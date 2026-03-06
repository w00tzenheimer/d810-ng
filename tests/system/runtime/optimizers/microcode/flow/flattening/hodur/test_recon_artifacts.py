from __future__ import annotations

from types import SimpleNamespace

from d810.cfg.flow.return_frontier import ReturnSite
from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.optimizers.microcode.flow.flattening.hodur.recon_artifacts import (
    load_return_frontier_audit_from_store,
    load_transition_report_from_store,
    record_return_frontier_stage,
    save_transition_report_to_store,
    write_return_frontier_artifact_from_store,
)
from d810.optimizers.microcode.flow.flattening.hodur.unflattener import (
    HodurUnflattener,
)
from d810.recon.flow.transition_builder import StateHandler, TransitionResult
from d810.recon.flow.transition_report import build_dispatcher_transition_report_from_graph


def _make_report():
    flow_graph = FlowGraph(
        blocks={
            0: BlockSnapshot(0, 0, (3,), (), 0, 0, ()),
            3: BlockSnapshot(3, 0, (4,), (0,), 0, 0, ()),
            4: BlockSnapshot(4, 0, (), (3,), 0, 0, ()),
        },
        entry_serial=0,
        func_ea=0x401000,
    )
    transition_result = TransitionResult(
        handlers={
            0x30: StateHandler(
                state_value=0x30,
                check_block=3,
                handler_blocks=[3],
                transitions=[],
            )
        },
        initial_state=0x30,
        pre_header_serial=9,
        strategy_name="fixture",
        resolved_count=0,
    )
    return build_dispatcher_transition_report_from_graph(
        flow_graph=flow_graph,
        transition_result=transition_result,
        dispatcher_entry_serial=5,
    )


def test_transition_report_store_round_trip(tmp_path):
    report = _make_report()

    save_transition_report_to_store(
        func_ea=0x401000,
        maturity=7,
        report=report,
        log_dir=tmp_path,
    )
    loaded = load_transition_report_from_store(
        func_ea=0x401000,
        maturity=7,
        log_dir=tmp_path,
    )

    assert loaded is not None
    assert loaded.dispatcher_entry_serial == report.dispatcher_entry_serial
    assert loaded.summary.exit_count == 1


def test_audit_pre_plan_prefers_recon_store_transition_report(monkeypatch, tmp_path):
    report = _make_report()
    save_transition_report_to_store(
        func_ea=0x401000,
        maturity=7,
        report=report,
        log_dir=tmp_path,
    )

    unflattener = HodurUnflattener()
    unflattener.log_dir = tmp_path
    unflattener.mba = SimpleNamespace(entry_ea=0x401000)
    unflattener.cur_maturity = 7
    unflattener._build_successor_map = lambda: {0: [3], 3: [4], 4: []}
    unflattener._find_exit_blocks = lambda: frozenset({4})
    snapshot = SimpleNamespace(bst_dispatcher_serial=5, state_machine=None, mba=object())

    def fail_if_built(*_args, **_kwargs):
        raise AssertionError("direct transition report build should not run")

    monkeypatch.setattr(
        "d810.recon.flow.transition_report.build_dispatcher_transition_report",
        fail_if_built,
    )

    unflattener._audit_pre_plan(snapshot, handler_paths={})

    assert len(unflattener._audit_return_sites) == 1
    assert unflattener._audit_return_sites[0].origin_block == 3


def test_audit_pre_plan_persists_fallback_report_to_store(monkeypatch, tmp_path):
    report = _make_report()
    unflattener = HodurUnflattener()
    unflattener.log_dir = tmp_path
    unflattener.mba = SimpleNamespace(entry_ea=0x401000)
    unflattener.cur_maturity = 7
    unflattener._build_successor_map = lambda: {0: [3], 3: [4], 4: []}
    unflattener._find_exit_blocks = lambda: frozenset({4})
    snapshot = SimpleNamespace(bst_dispatcher_serial=5, state_machine=None, mba=object())

    monkeypatch.setattr(
        "d810.recon.flow.transition_report.build_dispatcher_transition_report",
        lambda *_args, **_kwargs: report,
    )

    unflattener._audit_pre_plan(snapshot, handler_paths={})
    loaded = load_transition_report_from_store(
        func_ea=0x401000,
        maturity=7,
        log_dir=tmp_path,
    )

    assert loaded is not None
    assert loaded.summary.exit_count == 1


def test_return_frontier_stage_round_trip(tmp_path):
    return_sites = (
        ReturnSite(
            site_id="site_3",
            origin_block=3,
            expected_terminal_kind="return",
            guard_hash="3",
            provenance="test",
        ),
    )

    pre_result = record_return_frontier_stage(
        func_ea=0x401000,
        maturity=7,
        log_dir=tmp_path,
        return_sites=return_sites,
        successors={0: [3], 3: [4], 4: []},
        entry=0,
        exits=frozenset({4}),
        stage_name="pre_plan",
    )
    post_result = record_return_frontier_stage(
        func_ea=0x401000,
        maturity=7,
        log_dir=tmp_path,
        return_sites=return_sites,
        successors={0: [4], 3: [4], 4: []},
        entry=0,
        exits=frozenset({4}),
        stage_name="post_apply",
    )
    audit = load_return_frontier_audit_from_store(
        func_ea=0x401000,
        maturity=7,
        log_dir=tmp_path,
    )

    assert pre_result.metrics["stages_audited"] == 1
    assert post_result.metrics["stages_audited"] == 2
    assert audit is not None
    report = audit.report()
    assert report["stages_audited"] == ["pre_plan", "post_apply"]
    assert report["broken_count"] == 1
    assert report["sites"][0]["first_break_stage"] == "post_apply"


def test_write_return_frontier_artifact_from_store(tmp_path):
    return_sites = (
        ReturnSite(
            site_id="site_3",
            origin_block=3,
            expected_terminal_kind="return",
            guard_hash="3",
            provenance="test",
        ),
    )
    record_return_frontier_stage(
        func_ea=0x401000,
        maturity=7,
        log_dir=tmp_path,
        return_sites=return_sites,
        successors={0: [3], 3: [4], 4: []},
        entry=0,
        exits=frozenset({4}),
        stage_name="pre_plan",
    )

    artifact = write_return_frontier_artifact_from_store(
        func_ea=0x401000,
        maturity=7,
        log_dir=tmp_path,
        artifact_dir=tmp_path / "artifacts",
    )

    assert artifact is not None
    assert artifact.exists()
    assert '"total_sites": 1' in artifact.read_text()
