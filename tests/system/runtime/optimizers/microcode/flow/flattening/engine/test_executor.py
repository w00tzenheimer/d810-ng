"""Runtime tests for the shared engine executor surface."""
from __future__ import annotations

import sys
import types

if "ida_hexrays" not in sys.modules:
    ida_hexrays_stub = types.ModuleType("ida_hexrays")
    ida_hexrays_stub.mop_z = 0
    sys.modules["ida_hexrays"] = ida_hexrays_stub

from d810.optimizers.microcode.flow.flattening.engine import executor as engine_executor
from d810.optimizers.microcode.flow.flattening.engine.executor import (
    TransactionalExecutor as EngineTransactionalExecutor,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.optimizers.microcode.flow.flattening.hodur import executor as hodur_executor


def _fragment() -> PlanFragment:
    return PlanFragment(
        strategy_name="profile_probe",
        family="direct",
        ownership=OwnershipScope(
            blocks=frozenset(),
            edges=frozenset(),
            transitions=frozenset(),
        ),
        prerequisites=[],
        expected_benefit=BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=0,
            blocks_freed=0,
            conflict_density=0.0,
        ),
        risk_score=0.0,
        modifications=[object()],
    )


def test_engine_executor_uses_configured_safeguard_profile(monkeypatch) -> None:
    seen: list[str] = []

    def _fake_should_apply(_num_edges, _total_handlers, context="", **_kwargs):
        seen.append(context)
        return False

    monkeypatch.setattr(
        engine_executor,
        "should_apply_bulk_cfg_modifications",
        _fake_should_apply,
    )

    executor = EngineTransactionalExecutor(
        mba=object(),
        safeguard_profile="generic_family",
    )
    [result] = executor.execute_pipeline([_fragment()], total_handlers=1)

    assert seen == ["generic_family"]
    assert result.failure_phase == "safeguard"


def test_hodur_executor_defaults_to_hodur_safeguard_profile(monkeypatch) -> None:
    seen: list[str] = []

    def _fake_should_apply(_num_edges, _total_handlers, context="", **_kwargs):
        seen.append(context)
        return False

    monkeypatch.setattr(
        hodur_executor,
        "should_apply_bulk_cfg_modifications",
        _fake_should_apply,
    )

    executor = hodur_executor.TransactionalExecutor(mba=object())
    [result] = executor.execute_pipeline([_fragment()], total_handlers=1)

    assert seen == ["hodur"]
    assert result.failure_phase == "safeguard"
