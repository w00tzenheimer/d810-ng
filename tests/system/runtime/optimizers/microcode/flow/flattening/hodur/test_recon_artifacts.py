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
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
    StageResult,
)
from d810.optimizers.microcode.flow.flattening.engine.runtime import (
    ExecutedPipeline,
    PlannedPipeline,
)
from d810.optimizers.microcode.flow.flattening.engine.provenance import (
    PipelineProvenance,
)
from d810.optimizers.microcode.flow.flattening.hodur.family import (
    HodurDetection,
    HodurStrategyFamily,
)
from d810.optimizers.microcode.flow.flattening.hodur import family as hodur_family_module
from d810.optimizers.microcode.flow.flattening.hodur.unflattener import (
    HodurUnflattener,
)
from d810.optimizers.microcode.flow.flattening.hodur import unflattener as hodur_unflattener
from d810.optimizers.microcode.flow.flattening.strategies.fake_jump import (
    FAKE_JUMP_FIXES_METADATA_KEY,
    FakeJumpPredFix,
    FakeJumpStrategy,
)
from d810.optimizers.microcode.flow.flattening.strategies.bad_while_loop import (
    BAD_WHILE_LOOP_EDITS_METADATA_KEY,
    BAD_WHILE_LOOP_FOLLOW_UP_METADATA_KEY,
    BadWhileLoopAnalysis,
    BadWhileLoopFollowUp,
    BadWhileLoopGotoConversion,
    BadWhileLoopGotoRedirect,
    BadWhileLoopStrategy,
)
from d810.optimizers.microcode.flow.flattening.strategies.single_iteration import (
    SINGLE_ITERATION_FIXES_METADATA_KEY,
    SingleIterationPredFix,
    SingleIterationStrategy,
)
from d810.recon.flow.transition_builder import StateHandler, TransitionResult
from d810.recon.flow.transition_report import build_dispatcher_transition_report_from_graph
import ida_hexrays


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

    unflattener._audit_return_sites = unflattener._family.prepare_return_frontier_audit(
        snapshot,
        current_return_sites=tuple(),
        return_site_provider=unflattener._return_site_provider,
        func_ea=0x401000,
        maturity=7,
        log_dir=tmp_path,
        successors=unflattener._build_successor_map(),
        exits=unflattener._find_exit_blocks(),
        handler_paths={},
    )

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

    unflattener._audit_return_sites = unflattener._family.prepare_return_frontier_audit(
        snapshot,
        current_return_sites=tuple(),
        return_site_provider=unflattener._return_site_provider,
        func_ea=0x401000,
        maturity=7,
        log_dir=tmp_path,
        successors=unflattener._build_successor_map(),
        exits=unflattener._find_exit_blocks(),
        handler_paths={},
    )
    loaded = load_transition_report_from_store(
        func_ea=0x401000,
        maturity=7,
        log_dir=tmp_path,
    )

    assert loaded is not None
    assert loaded.summary.exit_count == 1


def test_hodur_unflattener_registers_live_fake_jump_strategy():
    unflattener = HodurUnflattener()

    assert any(isinstance(strategy, FakeJumpStrategy) for strategy in unflattener._strategies)


def test_hodur_unflattener_uses_hodur_strategy_family():
    unflattener = HodurUnflattener()

    assert isinstance(unflattener._family, HodurStrategyFamily)
    assert unflattener._strategies is unflattener._family.strategies


def test_hodur_unflattener_compatibility_accessors_read_through_family_state():
    unflattener = HodurUnflattener()
    state_machine = SimpleNamespace(transitions=["t0"])
    detector = object()
    switch_table_map = object()

    unflattener._family._state_machine = state_machine
    unflattener._family._detector = detector
    unflattener._family._switch_table_map = switch_table_map
    unflattener._family._resolved_transitions = {(1, 2)}
    unflattener._family._initial_transitions = ["initial"]

    assert unflattener.state_machine is state_machine
    assert unflattener._detector is detector
    assert unflattener._switch_table_map is switch_table_map
    assert unflattener._resolved_transitions == {(1, 2)}
    assert unflattener._initial_transitions == ["initial"]


def test_hodur_unflattener_registers_live_bad_while_loop_strategy():
    unflattener = HodurUnflattener()

    assert any(
        isinstance(strategy, BadWhileLoopStrategy)
        for strategy in unflattener._strategies
    )


def test_hodur_unflattener_registers_live_single_iteration_strategy():
    unflattener = HodurUnflattener()

    assert any(
        isinstance(strategy, SingleIterationStrategy)
        for strategy in unflattener._strategies
    )


def test_hodur_unflattener_optimize_routes_detection_and_snapshot_through_family(
    monkeypatch,
):
    unflattener = HodurUnflattener()
    unflattener.RETURN_FRONTIER_AUDIT_ENABLED = False
    unflattener.cur_maturity = ida_hexrays.MMAT_GLBOPT1

    mba = SimpleNamespace(
        maturity=ida_hexrays.MMAT_GLBOPT1,
        entry_ea=0x401000,
    )
    blk = SimpleNamespace(mba=mba)
    state_machine = SimpleNamespace(
        transitions=[],
        handlers={},
        state_constants=set(),
        state_var=None,
        initial_state=None,
    )
    detection = HodurDetection(
        state_machine=state_machine,
        detector=object(),
        detection_source="stub",
    )
    snapshot = SimpleNamespace(
        handler_count=0,
        bst_result=None,
        bst_dispatcher_serial=-1,
        state_machine=state_machine,
        mba=mba,
    )
    calls: list[object] = []

    monkeypatch.setattr(unflattener, "check_if_rule_should_be_used", lambda _blk: True)
    monkeypatch.setattr(unflattener, "_log_state_machine", lambda: calls.append("log"))
    monkeypatch.setattr(
        unflattener._family,
        "begin_pass",
        lambda pass_number: calls.append(("begin_pass", pass_number)),
    )
    monkeypatch.setattr(
        unflattener._family,
        "detect",
        lambda mba_arg: calls.append(("detect", mba_arg)) or detection,
    )
    monkeypatch.setattr(
        unflattener._family,
        "build_snapshot",
        lambda mba_arg, detection_arg: calls.append(
            ("build_snapshot", mba_arg, detection_arg)
        )
        or snapshot,
    )
    monkeypatch.setattr(
        hodur_unflattener,
        "load_transition_report_from_store",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        hodur_unflattener,
        "load_return_frontier_audit_from_store",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        hodur_unflattener,
        "load_terminal_return_audit_from_store",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        unflattener._planner,
        "plan",
        lambda snap, strategies, inputs=None: (
            calls.append(("plan", snap, strategies, inputs)) or [],
            object(),
        ),
    )

    assert unflattener.optimize(blk) == 0
    assert ("begin_pass", 0) in calls
    assert ("detect", mba) in calls
    assert ("build_snapshot", mba, detection) in calls
    plan_calls = [call for call in calls if isinstance(call, tuple) and call[0] == "plan"]
    assert len(plan_calls) == 1
    _, seen_snapshot, seen_strategies, _ = plan_calls[0]
    assert seen_snapshot is snapshot
    assert seen_strategies == unflattener._family.strategies_for_maturity(
        ida_hexrays.MMAT_GLBOPT1
    )


def test_hodur_unflattener_optimize_routes_planning_and_execution_through_engine_runtime(
    monkeypatch,
):
    unflattener = HodurUnflattener()
    unflattener.RETURN_FRONTIER_AUDIT_ENABLED = False
    unflattener.cur_maturity = ida_hexrays.MMAT_GLBOPT1

    mba = SimpleNamespace(
        maturity=ida_hexrays.MMAT_GLBOPT1,
        entry_ea=0x401000,
    )
    blk = SimpleNamespace(mba=mba)
    state_machine = SimpleNamespace(
        transitions=[],
        handlers={},
        state_constants=set(),
        state_var=None,
        initial_state=None,
    )
    detection = HodurDetection(
        state_machine=state_machine,
        detector=object(),
        detection_source="stub",
    )
    snapshot = SimpleNamespace(
        handler_count=0,
        bst_result=None,
        bst_dispatcher_serial=-1,
        state_machine=state_machine,
        mba=mba,
    )
    fragment = PlanFragment(
        strategy_name="runtime_probe",
        family="cleanup",
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
    calls: list[object] = []
    executor_factory_sentinel = object()

    monkeypatch.setattr(unflattener, "check_if_rule_should_be_used", lambda _blk: True)
    monkeypatch.setattr(unflattener, "_log_state_machine", lambda: None)
    monkeypatch.setattr(
        unflattener._family,
        "begin_pass",
        lambda pass_number: calls.append(("begin_pass", pass_number)),
    )
    monkeypatch.setattr(
        unflattener._family,
        "detect",
        lambda mba_arg: detection if mba_arg is mba else None,
    )
    monkeypatch.setattr(
        unflattener._family,
        "build_snapshot",
        lambda mba_arg, detection_arg: snapshot,
    )
    monkeypatch.setattr(
        hodur_unflattener,
        "load_transition_report_from_store",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        hodur_unflattener,
        "load_return_frontier_audit_from_store",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        hodur_unflattener,
        "load_terminal_return_audit_from_store",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        hodur_unflattener,
        "plan_family_pipeline",
        lambda snap, strategies, *, planner, inputs=None: (
            calls.append(("plan_runtime", snap, strategies, planner, inputs))
            or PlannedPipeline(
                pipeline=[fragment],
                provenance=PipelineProvenance(),
            )
        ),
    )
    monkeypatch.setattr(
        hodur_unflattener,
        "execute_family_pipeline",
        lambda snap, planned, *, executor_factory, flow_context=None: (
            calls.append(("execute_runtime", snap, planned, executor_factory, flow_context))
            or ExecutedPipeline(
                pipeline=planned.pipeline,
                results=[StageResult(strategy_name="runtime_probe")],
                provenance=planned.provenance,
                total_changes=0,
            )
        ),
    )
    monkeypatch.setattr(
        unflattener._family,
        "make_executor_factory",
        lambda *, gate, allow_legacy_block_creation: (
            calls.append(("make_executor_factory", gate, allow_legacy_block_creation))
            or executor_factory_sentinel
        ),
    )
    monkeypatch.setattr(
        unflattener._family,
        "record_execution_outcome",
        lambda pipeline, results, **kwargs: calls.append(
            ("record_execution_outcome", pipeline, results, kwargs)
        ),
    )
    monkeypatch.setattr(unflattener, "_log_pipeline_results", lambda *_args, **_kwargs: None)

    assert unflattener.optimize(blk) == 0

    plan_calls = [call for call in calls if isinstance(call, tuple) and call[0] == "plan_runtime"]
    execute_calls = [
        call for call in calls if isinstance(call, tuple) and call[0] == "execute_runtime"
    ]
    factory_calls = [
        call
        for call in calls
        if isinstance(call, tuple) and call[0] == "make_executor_factory"
    ]
    outcome_calls = [
        call
        for call in calls
        if isinstance(call, tuple) and call[0] == "record_execution_outcome"
    ]
    assert len(plan_calls) == 1
    assert len(execute_calls) == 1
    assert len(factory_calls) == 1
    assert len(outcome_calls) == 1
    _, seen_snapshot, seen_strategies, seen_planner, seen_inputs = plan_calls[0]
    assert seen_snapshot is snapshot
    assert seen_strategies == unflattener._family.strategies_for_maturity(
        ida_hexrays.MMAT_GLBOPT1
    )
    assert seen_planner is unflattener._planner
    assert seen_inputs.total_handlers == 0
    _, executed_snapshot, planned_pipeline, _executor_factory, seen_flow_context = execute_calls[0]
    assert executed_snapshot is snapshot
    assert planned_pipeline.pipeline == [fragment]
    assert seen_flow_context is unflattener.flow_context
    assert _executor_factory is executor_factory_sentinel
    _, seen_gate, seen_allow_legacy = factory_calls[0]
    assert seen_gate is unflattener._gate
    assert seen_allow_legacy is unflattener.allow_legacy_block_creation
    _, seen_pipeline, seen_results, seen_kwargs = outcome_calls[0]
    assert seen_pipeline == [fragment]
    assert len(seen_results) == 1
    assert seen_kwargs["func_ea"] == mba.entry_ea
    assert seen_kwargs["maturity"] == ida_hexrays.MMAT_GLBOPT1
    assert seen_kwargs["nb_changes"] == 0
    assert seen_kwargs["residual_dispatcher_preds_by_strategy"] == {}


def test_hodur_strategy_family_builds_cleanup_only_snapshot_without_state_machine(
    monkeypatch,
):
    family = HodurStrategyFamily()
    mba = SimpleNamespace(maturity=ida_hexrays.MMAT_GLBOPT1)
    reachability = SimpleNamespace(coverage=1.0)
    dispatcher_cache = object()
    base_flow_graph = FlowGraph(
        blocks={
            0: BlockSnapshot(0, 1, (1,), (), 0, 0, ()),
            1: BlockSnapshot(1, 0, (), (0,), 0, 0, ()),
        },
        entry_serial=0,
        func_ea=0x401000,
    )

    monkeypatch.setattr(
        family._cfg_translator,
        "lift",
        lambda _mba: base_flow_graph,
    )
    monkeypatch.setattr(
        hodur_family_module,
        "DispatcherCache",
        SimpleNamespace(get_or_create=lambda _mba: dispatcher_cache),
    )
    monkeypatch.setattr(
        family,
        "compute_reachability_info",
        lambda _mba: reachability,
    )
    monkeypatch.setattr(
        family,
        "attach_fake_jump_fixes_to_flow_graph",
        lambda _mba, flow_graph: FlowGraph(
            blocks=flow_graph.blocks,
            entry_serial=flow_graph.entry_serial,
            func_ea=flow_graph.func_ea,
            metadata={FAKE_JUMP_FIXES_METADATA_KEY: {1: {0: 1}}},
        ),
    )
    monkeypatch.setattr(
        family,
        "attach_bad_while_loop_edits_to_flow_graph",
        lambda _mba, flow_graph: flow_graph,
    )
    monkeypatch.setattr(
        family,
        "attach_single_iteration_fixes_to_flow_graph",
        lambda _mba, flow_graph: flow_graph,
    )

    snapshot = family.build_snapshot(
        mba,
        HodurDetection(
            state_machine=None,
            detector=object(),
            detection_source="none",
        ),
    )

    assert snapshot.state_machine is None
    assert snapshot.flow_graph is not None
    assert snapshot.flow_graph.metadata[FAKE_JUMP_FIXES_METADATA_KEY] == {1: {0: 1}}
    assert snapshot.dispatcher_cache is dispatcher_cache
    assert snapshot.reachability is reachability
    assert snapshot.maturity == ida_hexrays.MMAT_GLBOPT1
    assert snapshot.pass_number == 0


def test_hodur_unflattener_optimize_allows_cleanup_only_pipeline_without_state_machine(
    monkeypatch,
):
    unflattener = HodurUnflattener()
    unflattener.RETURN_FRONTIER_AUDIT_ENABLED = True
    unflattener.cur_maturity = ida_hexrays.MMAT_GLBOPT1
    unflattener._last_bst_serials = {8, 9}
    unflattener._last_dispatcher_serial = 7
    unflattener._last_func_ea = 0xDEADBEEF
    unflattener._last_bst_block_eas = {0x401200}
    unflattener._last_dispatcher_ea = 0x401180

    mba = SimpleNamespace(
        maturity=ida_hexrays.MMAT_GLBOPT1,
        entry_ea=0x401000,
    )
    blk = SimpleNamespace(mba=mba)
    detection = HodurDetection(
        state_machine=None,
        detector=object(),
        detection_source="none",
    )
    snapshot = SimpleNamespace(
        handler_count=0,
        bst_result=None,
        bst_dispatcher_serial=-1,
        state_machine=None,
        mba=mba,
        flow_graph=object(),
    )
    fragment = PlanFragment(
        strategy_name="fake_jump",
        family="cleanup",
        ownership=OwnershipScope(
            blocks=frozenset({1}),
            edges=frozenset({(1, 2)}),
            transitions=frozenset(),
        ),
        prerequisites=[],
        expected_benefit=BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=0,
            blocks_freed=1,
            conflict_density=0.0,
        ),
        risk_score=0.0,
        modifications=[object()],
    )
    calls: list[object] = []

    monkeypatch.setattr(unflattener, "check_if_rule_should_be_used", lambda _blk: True)
    monkeypatch.setattr(
        unflattener,
        "_log_state_machine",
        lambda: (_ for _ in ()).throw(AssertionError("should not log state machine")),
    )
    monkeypatch.setattr(
        unflattener._family,
        "begin_pass",
        lambda pass_number: calls.append(("begin_pass", pass_number)),
    )
    monkeypatch.setattr(
        unflattener._family,
        "detect",
        lambda mba_arg: calls.append(("detect", mba_arg)) or detection,
    )
    monkeypatch.setattr(
        unflattener._family,
        "build_snapshot",
        lambda mba_arg, detection_arg: calls.append(
            ("build_snapshot", mba_arg, detection_arg)
        )
        or snapshot,
    )
    monkeypatch.setattr(
        hodur_unflattener,
        "load_transition_report_from_store",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("cleanup-only path should not load transition report")
        ),
    )
    monkeypatch.setattr(
        hodur_unflattener,
        "load_return_frontier_audit_from_store",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("cleanup-only path should not load return frontier audit")
        ),
    )
    monkeypatch.setattr(
        hodur_unflattener,
        "load_terminal_return_audit_from_store",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("cleanup-only path should not load terminal return audit")
        ),
    )
    monkeypatch.setattr(
        unflattener._family,
        "prepare_return_frontier_audit",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("cleanup-only path should not prepare return-frontier audit")
        ),
    )
    monkeypatch.setattr(
        hodur_unflattener,
        "plan_family_pipeline",
        lambda snap, strategies, *, planner, inputs=None: (
            calls.append(("plan_runtime", snap, strategies, planner, inputs))
            or PlannedPipeline(
                pipeline=[fragment],
                provenance=PipelineProvenance(),
            )
        ),
    )
    monkeypatch.setattr(
        hodur_unflattener,
        "execute_family_pipeline",
        lambda snap, planned, *, executor_factory, flow_context=None: (
            calls.append(("execute_runtime", snap, planned, executor_factory, flow_context))
            or ExecutedPipeline(
                pipeline=planned.pipeline,
                results=[
                    StageResult(
                        strategy_name="fake_jump",
                        success=True,
                        edits_applied=1,
                    )
                ],
                provenance=planned.provenance,
                total_changes=1,
            )
        ),
    )
    monkeypatch.setattr(
        unflattener._family,
        "make_executor_factory",
        lambda *, gate, allow_legacy_block_creation: (
            calls.append(("make_executor_factory", gate, allow_legacy_block_creation))
            or object()
        ),
    )
    monkeypatch.setattr(
        unflattener._family,
        "record_execution_outcome",
        lambda pipeline, results, **kwargs: calls.append(
            ("record_execution_outcome", pipeline, results, kwargs)
        ),
    )
    monkeypatch.setattr(
        unflattener._family,
        "persist_terminal_return_audit",
        lambda results, **kwargs: calls.append(
            ("persist_terminal_return_audit", results, kwargs)
        ),
    )
    monkeypatch.setattr(
        unflattener._family,
        "collect_post_apply_bst_cleanup_blockers",
        lambda *args, **kwargs: {},
    )
    monkeypatch.setattr(
        unflattener._family,
        "finalize_return_frontier_audit",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("cleanup-only path should not finalize return-frontier audit")
        ),
    )
    monkeypatch.setattr(unflattener, "_log_pipeline_results", lambda *_args, **_kwargs: None)

    assert unflattener.optimize(blk) == 1
    assert unflattener._last_bst_serials is None
    assert unflattener._last_dispatcher_serial == -1
    assert unflattener._last_func_ea == 0
    assert unflattener._last_bst_block_eas == set()
    assert unflattener._last_dispatcher_ea == 0

    plan_calls = [call for call in calls if isinstance(call, tuple) and call[0] == "plan_runtime"]
    execute_calls = [
        call for call in calls if isinstance(call, tuple) and call[0] == "execute_runtime"
    ]
    assert ("detect", mba) in calls
    assert ("build_snapshot", mba, detection) in calls
    assert len(plan_calls) == 1
    assert len(execute_calls) == 1
    _, seen_snapshot, seen_strategies, seen_planner, seen_inputs = plan_calls[0]
    assert seen_snapshot is snapshot
    assert seen_strategies == unflattener._family.strategies_for_maturity(
        ida_hexrays.MMAT_GLBOPT1
    )
    assert seen_planner is unflattener._planner
    assert seen_inputs.total_handlers == 0
    assert seen_inputs.handler_transitions is None
    assert seen_inputs.return_frontier is None
    assert seen_inputs.terminal_return_audit is None


def test_hodur_strategy_family_records_execution_outcome():
    family = HodurStrategyFamily()
    strategy = SimpleNamespace(
        name="linearized_flow_graph",
        _applied=set(),
        _last_successful_residual_dispatcher_pred_counts={},
    )
    family._strategies = [strategy]
    family._state_machine = SimpleNamespace(
        transitions=[SimpleNamespace(from_state=0x10, to_state=0x20)]
    )
    fragment = PlanFragment(
        strategy_name="linearized_flow_graph",
        family="cleanup",
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
        metadata={"residual_dispatcher_preds": (4,)},
    )

    family.record_execution_outcome(
        [fragment],
        [StageResult(strategy_name="linearized_flow_graph", success=True, edits_applied=1)],
        func_ea=0x401000,
        maturity=ida_hexrays.MMAT_GLBOPT1,
        nb_changes=1,
        residual_dispatcher_preds_by_strategy={"linearized_flow_graph": (7, 8)},
    )

    assert strategy._applied == {(0x401000, ida_hexrays.MMAT_GLBOPT1)}
    assert strategy._last_successful_residual_dispatcher_pred_counts == {
        (0x401000, ida_hexrays.MMAT_GLBOPT1): 2
    }
    assert family.resolved_transitions == frozenset({(0x10, 0x20)})


def test_attach_fake_jump_fixes_to_flow_graph_metadata(monkeypatch):
    unflattener = HodurUnflattener()
    mba = SimpleNamespace(maturity=ida_hexrays.MMAT_GLBOPT1)
    flow_graph = FlowGraph(
        blocks={
            0: BlockSnapshot(0, 1, (5,), (), 0, 0, ()),
            5: BlockSnapshot(5, 1, (2,), (0,), 0, 0, ()),
            6: BlockSnapshot(6, 1, (2,), (), 0, 0, ()),
            2: BlockSnapshot(2, 4, (10, 20), (5, 6), 0, 0, ()),
            10: BlockSnapshot(10, 0, (), (2,), 0, 0, ()),
            20: BlockSnapshot(20, 0, (), (2,), 0, 0, ()),
        },
        entry_serial=0,
        func_ea=0x401000,
    )

    monkeypatch.setattr(
        hodur_family_module,
        "collect_live_fake_jump_fixes",
        lambda *_args, **_kwargs: (
            FakeJumpPredFix(fake_block=2, pred_block=5, new_target=10),
            FakeJumpPredFix(fake_block=2, pred_block=6, new_target=20),
        ),
    )

    updated = unflattener._family.attach_fake_jump_fixes_to_flow_graph(mba, flow_graph)

    assert updated is not flow_graph
    assert updated.metadata[FAKE_JUMP_FIXES_METADATA_KEY] == {2: {5: 10, 6: 20}}
    assert flow_graph.metadata == {}


def test_attach_fake_jump_fixes_skips_conditional_chain_dispatchers(monkeypatch):
    unflattener = HodurUnflattener()
    mba = SimpleNamespace(maturity=ida_hexrays.MMAT_GLBOPT1)
    flow_graph = FlowGraph(
        blocks={
            0: BlockSnapshot(0, 1, (5,), (), 0, 0, ()),
            5: BlockSnapshot(5, 1, (2,), (0,), 0, 0, ()),
            6: BlockSnapshot(6, 1, (2,), (), 0, 0, ()),
            2: BlockSnapshot(2, 4, (10, 20), (5, 6), 0, 0, ()),
            10: BlockSnapshot(10, 0, (), (2,), 0, 0, ()),
            20: BlockSnapshot(20, 0, (), (2,), 0, 0, ()),
        },
        entry_serial=0,
        func_ea=0x401000,
    )

    monkeypatch.setattr(
        hodur_family_module,
        "collect_live_fake_jump_fixes",
        lambda *_args, **_kwargs: (
            FakeJumpPredFix(fake_block=2, pred_block=5, new_target=10),
            FakeJumpPredFix(fake_block=2, pred_block=6, new_target=20),
        ),
    )
    monkeypatch.setattr(
        hodur_family_module,
        "DispatcherCache",
        SimpleNamespace(
            get_or_create=lambda _mba: SimpleNamespace(
                analyze=lambda: SimpleNamespace(is_conditional_chain=True),
                is_dispatcher=lambda serial: serial == 2,
            ),
        ),
    )

    updated = unflattener._family.attach_fake_jump_fixes_to_flow_graph(mba, flow_graph)

    assert updated is flow_graph
    assert updated.metadata == {}


def test_attach_bad_while_loop_edits_to_flow_graph_metadata(monkeypatch):
    unflattener = HodurUnflattener()
    mba = SimpleNamespace(maturity=ida_hexrays.MMAT_GLBOPT1)
    flow_graph = FlowGraph(
        blocks={
            0: BlockSnapshot(0, 1, (1,), (), 0, 0, ()),
            1: BlockSnapshot(1, 1, (2,), (0,), 0, 0, ()),
            2: BlockSnapshot(2, 4, (3, 4), (1, 5), 0, 0, ()),
            3: BlockSnapshot(3, 0, (), (2,), 0, 0, ()),
            4: BlockSnapshot(4, 0, (), (2,), 0, 0, ()),
            5: BlockSnapshot(5, 4, (2, 8), (), 0, 0, ()),
            8: BlockSnapshot(8, 0, (), (5,), 0, 0, ()),
        },
        entry_serial=0,
        func_ea=0x401000,
    )

    monkeypatch.setattr(
        hodur_family_module,
        "collect_live_bad_while_loop_analysis",
        lambda *_args, **_kwargs: BadWhileLoopAnalysis(
            edits=(
                BadWhileLoopGotoRedirect(
                    dispatcher_entry=2,
                    from_serial=1,
                    new_target=3,
                ),
                BadWhileLoopGotoConversion(
                    dispatcher_entry=2,
                    block_serial=5,
                    goto_target=4,
                ),
            ),
            follow_up=(
                BadWhileLoopFollowUp(
                    dispatcher_entry=2,
                    from_serial=5,
                    category="create_conditional_redirect",
                    reason="conditional_exit_with_loopback",
                    target_serial=3,
                    fallthrough_target=8,
                ),
            ),
        ),
    )

    updated = unflattener._family.attach_bad_while_loop_edits_to_flow_graph(
        mba, flow_graph
    )

    assert updated is not flow_graph
    assert updated.metadata[BAD_WHILE_LOOP_EDITS_METADATA_KEY] == [
        {
            "kind": "redirect_goto",
            "dispatcher_entry": 2,
            "from_serial": 1,
            "new_target": 3,
        },
        {
            "kind": "convert_to_goto",
            "dispatcher_entry": 2,
            "block_serial": 5,
            "goto_target": 4,
        },
    ]
    assert updated.metadata[BAD_WHILE_LOOP_FOLLOW_UP_METADATA_KEY] == [
        {
            "dispatcher_entry": 2,
            "from_serial": 5,
            "category": "create_conditional_redirect",
            "reason": "conditional_exit_with_loopback",
            "target_serial": 3,
            "fallthrough_target": 8,
        }
    ]
    assert flow_graph.metadata == {}


def test_attach_single_iteration_fixes_to_flow_graph_metadata(monkeypatch):
    unflattener = HodurUnflattener()
    mba = SimpleNamespace(maturity=ida_hexrays.MMAT_GLBOPT1)
    flow_graph = FlowGraph(
        blocks={
            0: BlockSnapshot(0, 1, (1,), (), 0, 0, ()),
            1: BlockSnapshot(1, 1, (2,), (0,), 0, 0, ()),
            2: BlockSnapshot(2, 4, (3, 4), (1, 3), 0, 0, ()),
            3: BlockSnapshot(3, 1, (2,), (2,), 0, 0, ()),
            4: BlockSnapshot(4, 0, (), (2,), 0, 0, ()),
        },
        entry_serial=0,
        func_ea=0x401000,
    )

    monkeypatch.setattr(
        hodur_family_module,
        "collect_live_single_iteration_fixes",
        lambda *_args, **_kwargs: (
            SingleIterationPredFix(loop_header=2, pred_block=1, new_target=3),
            SingleIterationPredFix(loop_header=2, pred_block=3, new_target=4),
        ),
    )

    updated = unflattener._family.attach_single_iteration_fixes_to_flow_graph(
        mba, flow_graph
    )

    assert updated is not flow_graph
    assert updated.metadata[SINGLE_ITERATION_FIXES_METADATA_KEY] == {2: {1: 3, 3: 4}}
    assert flow_graph.metadata == {}


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


def test_collect_post_apply_bst_cleanup_blockers_only_counts_applied_stages():
    fragment = PlanFragment(
        strategy_name="linearized_flow_graph",
        family="direct",
        ownership=OwnershipScope(
            blocks=frozenset(),
            edges=frozenset(),
            transitions=frozenset(),
        ),
        prerequisites=[],
        expected_benefit=BenefitMetrics(0, 0, 0, 0.0),
        risk_score=0.0,
        metadata={
            "allow_post_apply_bst_cleanup": False,
            "residual_dispatcher_preds": (95, 131),
        },
        modifications=[],
    )
    skipped_fragment = PlanFragment(
        strategy_name="other_stage",
        family="direct",
        ownership=OwnershipScope(
            blocks=frozenset(),
            edges=frozenset(),
            transitions=frozenset(),
        ),
        prerequisites=[],
        expected_benefit=BenefitMetrics(0, 0, 0, 0.0),
        risk_score=0.0,
        metadata={
            "allow_post_apply_bst_cleanup": False,
            "residual_dispatcher_preds": (17,),
        },
        modifications=[],
    )

    blockers = HodurStrategyFamily.collect_post_apply_bst_cleanup_blockers(
        [fragment, skipped_fragment],
        [
            StageResult(
                strategy_name="linearized_flow_graph",
                success=True,
                edits_applied=3,
            ),
            StageResult(
                strategy_name="other_stage",
                success=False,
                edits_applied=0,
            ),
        ],
    )

    assert blockers == {"linearized_flow_graph": (95, 131)}


def test_collect_post_apply_bst_cleanup_blockers_ignores_empty_residual_pred_sets():
    fragment = PlanFragment(
        strategy_name="linearized_flow_graph",
        family="direct",
        ownership=OwnershipScope(
            blocks=frozenset(),
            edges=frozenset(),
            transitions=frozenset(),
        ),
        prerequisites=[],
        expected_benefit=BenefitMetrics(0, 0, 0, 0.0),
        risk_score=0.0,
        metadata={
            "allow_post_apply_bst_cleanup": False,
            "residual_dispatcher_preds": (),
        },
        modifications=[],
    )

    blockers = HodurStrategyFamily.collect_post_apply_bst_cleanup_blockers(
        [fragment],
        [
            StageResult(
                strategy_name="linearized_flow_graph",
                success=True,
                edits_applied=7,
            ),
        ],
    )

    assert blockers == {}


def test_collect_post_apply_bst_cleanup_blockers_prefers_live_residual_pred_sets():
    fragment = PlanFragment(
        strategy_name="linearized_flow_graph",
        family="direct",
        ownership=OwnershipScope(
            blocks=frozenset(),
            edges=frozenset(),
            transitions=frozenset(),
        ),
        prerequisites=[],
        expected_benefit=BenefitMetrics(0, 0, 0, 0.0),
        risk_score=0.0,
        metadata={
            "allow_post_apply_bst_cleanup": False,
            "residual_dispatcher_preds": (),
        },
        modifications=[],
    )

    blockers = HodurStrategyFamily.collect_post_apply_bst_cleanup_blockers(
        [fragment],
        [
            StageResult(
                strategy_name="linearized_flow_graph",
                success=True,
                edits_applied=7,
            ),
        ],
        live_residual_dispatcher_preds_by_strategy={
            "linearized_flow_graph": (10, 45, 69, 192),
        },
    )

    assert blockers == {"linearized_flow_graph": (10, 45, 69, 192)}
