"""Provider-neutral run_later scheduler behavior."""
from __future__ import annotations

import logging

from d810.ir.maturity import IRMaturity
from d810.passes.scheduler import (
    PassScheduler,
    PendingRun,
    RunLater,
    RunLaterDomain,
)


def test_run_later_stores_ir_maturity():
    request = RunLater(at=IRMaturity.GLOBAL_ANALYZED, reason="needs global facts")
    assert request.at is IRMaturity.GLOBAL_ANALYZED
    assert request.reason == "needs global facts"


def test_scheduler_accepts_later_maturity_request():
    scheduler = PassScheduler()
    assert scheduler.request(
        func_ea=0x1000,
        pass_id="recover",
        current_maturity=IRMaturity.CANONICAL,
        run_later=RunLater(IRMaturity.GLOBAL_ANALYZED),
    ) is True


def test_scheduler_rejects_same_maturity_request():
    scheduler = PassScheduler()
    assert scheduler.request(
        func_ea=0x1000,
        pass_id="recover",
        current_maturity=IRMaturity.GLOBAL_ANALYZED,
        run_later=RunLater(IRMaturity.GLOBAL_ANALYZED),
    ) is False


def test_scheduler_rejects_earlier_maturity_request():
    scheduler = PassScheduler()
    assert scheduler.request(
        func_ea=0x1000,
        pass_id="recover",
        current_maturity=IRMaturity.VARIABLE_RECOVERED,
        run_later=RunLater(IRMaturity.GLOBAL_ANALYZED),
    ) is False


def test_scheduler_accepts_next_optimized_ir_maturity():
    scheduler = PassScheduler()
    assert scheduler.request(
        func_ea=0x1000,
        pass_id="recover",
        current_maturity=IRMaturity.GLOBAL_ANALYZED,
        run_later=RunLater(IRMaturity.GLOBAL_OPTIMIZED),
    ) is True


def test_scheduler_dedupes_by_function_pass_and_maturity():
    scheduler = PassScheduler()
    request = RunLater(IRMaturity.GLOBAL_ANALYZED, reason="first")
    assert scheduler.request(
        func_ea=0x1000,
        pass_id="recover",
        current_maturity=IRMaturity.CANONICAL,
        run_later=request,
    ) is True
    assert scheduler.request(
        func_ea=0x1000,
        pass_id="recover",
        current_maturity=IRMaturity.CANONICAL,
        run_later=RunLater(IRMaturity.GLOBAL_ANALYZED, reason="duplicate"),
    ) is True

    drained = scheduler.drain(
        func_ea=0x1000, current_maturity=IRMaturity.GLOBAL_ANALYZED
    )
    assert drained == (
        PendingRun(
            func_ea=0x1000,
            pass_id="recover",
            at=IRMaturity.GLOBAL_ANALYZED,
            reason="first",
        ),
    )


def test_scheduler_domains_keep_pipeline_passes_out_of_optimizer_rule_drain():
    scheduler = PassScheduler()
    assert scheduler.request(
        func_ea=0x1000,
        pass_id="same_name",
        current_maturity=IRMaturity.CANONICAL,
        run_later=RunLater(IRMaturity.GLOBAL_ANALYZED, reason="pipeline"),
        domain=RunLaterDomain.PIPELINE_PASS,
    ) is True

    assert scheduler.drain(
        func_ea=0x1000,
        current_maturity=IRMaturity.GLOBAL_ANALYZED,
    ) == ()
    assert scheduler.drain(
        func_ea=0x1000,
        current_maturity=IRMaturity.GLOBAL_ANALYZED,
        domain=RunLaterDomain.PIPELINE_PASS,
    ) == (
        PendingRun(
            func_ea=0x1000,
            pass_id="same_name",
            at=IRMaturity.GLOBAL_ANALYZED,
            domain=RunLaterDomain.PIPELINE_PASS,
            reason="pipeline",
        ),
    )


def test_scheduler_drains_at_or_after_requested_maturity_and_removes_entries():
    scheduler = PassScheduler()
    scheduler.request(
        func_ea=0x1000,
        pass_id="recover",
        current_maturity=IRMaturity.CANONICAL,
        run_later=RunLater(IRMaturity.VARIABLE_RECOVERED),
    )

    assert scheduler.drain(
        func_ea=0x1000, current_maturity=IRMaturity.GLOBAL_ANALYZED
    ) == ()
    drained = scheduler.drain(
        func_ea=0x1000, current_maturity=IRMaturity.VARIABLE_RECOVERED
    )
    assert len(drained) == 1
    assert drained[0].at is IRMaturity.VARIABLE_RECOVERED
    assert scheduler.drain(
        func_ea=0x1000, current_maturity=IRMaturity.VARIABLE_RECOVERED
    ) == ()


def test_scheduler_reset_func_clears_only_one_function():
    scheduler = PassScheduler()
    scheduler.request(
        func_ea=0x1000,
        pass_id="recover",
        current_maturity=IRMaturity.CANONICAL,
        run_later=RunLater(IRMaturity.GLOBAL_ANALYZED),
    )
    scheduler.request(
        func_ea=0x2000,
        pass_id="recover",
        current_maturity=IRMaturity.CANONICAL,
        run_later=RunLater(IRMaturity.GLOBAL_ANALYZED),
    )

    scheduler.reset_func(0x1000)

    assert scheduler.drain(
        func_ea=0x1000, current_maturity=IRMaturity.GLOBAL_ANALYZED
    ) == ()
    drained = scheduler.drain(
        func_ea=0x2000, current_maturity=IRMaturity.GLOBAL_ANALYZED
    )
    assert len(drained) == 1


def test_scheduler_reset_all_clears_everything():
    scheduler = PassScheduler()
    scheduler.request(
        func_ea=0x1000,
        pass_id="recover",
        current_maturity=IRMaturity.CANONICAL,
        run_later=RunLater(IRMaturity.GLOBAL_ANALYZED),
    )
    scheduler.request(
        func_ea=0x2000,
        pass_id="recover",
        current_maturity=IRMaturity.CANONICAL,
        run_later=RunLater(IRMaturity.GLOBAL_ANALYZED),
    )

    scheduler.reset_all()

    assert scheduler.drain(
        func_ea=0x1000, current_maturity=IRMaturity.GLOBAL_ANALYZED
    ) == ()
    assert scheduler.drain(
        func_ea=0x2000, current_maturity=IRMaturity.GLOBAL_ANALYZED
    ) == ()


def test_scheduler_rejects_requests_after_per_function_budget(caplog):
    scheduler = PassScheduler(per_func_request_budget=1)
    scheduler.request(
        func_ea=0x1000,
        pass_id="first",
        current_maturity=IRMaturity.CANONICAL,
        run_later=RunLater(IRMaturity.GLOBAL_ANALYZED),
    )

    with caplog.at_level(logging.WARNING):
        accepted = scheduler.request(
            func_ea=0x1000,
            pass_id="second",
            current_maturity=IRMaturity.CANONICAL,
            run_later=RunLater(IRMaturity.VARIABLE_RECOVERED),
        )

    assert accepted is False
    assert "per-function budget 1 exceeded" in caplog.text
