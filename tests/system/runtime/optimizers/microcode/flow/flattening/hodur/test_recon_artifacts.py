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
from d810.optimizers.microcode.flow.flattening.hodur.audit_runtime import (
    prepare_return_frontier_audit,
)
from d810.optimizers.microcode.flow.flattening.hodur.post_apply_runtime import (
    collect_live_residual_dispatcher_preds,
    collect_post_apply_bst_cleanup_blockers,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
    StageResult,
)
from d810.optimizers.microcode.flow.flattening.engine.runtime import (
    ExecutedPipeline,
    ExecutorPolicy,
    FamilyRunState,
    PlannedPipeline,
)
from d810.optimizers.microcode.flow.flattening.engine.state_machine_snapshot_builder import (
    StateMachineSnapshotBuilder,
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
from d810.optimizers.microcode.flow.flattening.hodur import (
    runtime_services as hodur_runtime_services,
)
from d810.optimizers.microcode.flow.flattening.hodur import (
    post_pipeline_hooks as hodur_post_pipeline_hooks,
)
from d810.optimizers.microcode.flow.flattening.hodur.post_pipeline_hooks import (
    HodurPostPipelineHooks,
)
from d810.optimizers.microcode.flow.flattening.hodur.runtime_services import (
    HodurRuntimeServices,
)
from d810.optimizers.microcode.flow.flattening.hodur.rule_services import (
    HodurRuleServices,
)
from d810.optimizers.microcode.flow.flattening.hodur.snapshot_builder import (
    HodurSnapshotPolicy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.semantic_exact_node import (
    SemanticExactNodeAllPlannableEdgesStrategy,
)
from d810.cfg.semantic_exact_selection import (
    parse_focus_edge_pairs,
    resolve_edge_window,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.linearized_flow_graph import (
    SemanticStructuredRegionStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.handler_chain_composer import (
    HandlerChainComposerStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.dispatcher_trampoline_skip import (
    DispatcherTrampolineSkipStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.counter_hoist import (
    CounterHoistStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.return_frontier_carrier_preserve import (
    ReturnFrontierCarrierPreserveStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_conditional_node import (
    ExactConditionalNodeLoweringStrategy,
    collect_exact_conditional_sites,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_conditional_alias import (
    ExactConditionalAliasNodeLoweringStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_conditional_fork import (
    ExactConditionalForkNodeLoweringStrategy,
    collect_exact_conditional_fork_sites,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_node_frontier_bypass import (
    ExactNodeFrontierBypassStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.prototypes import (
    ExactConditionalBridgeNodeLoweringStrategy,
)
from d810.optimizers.microcode.flow.flattening.strategies.fake_jump import (
    FAKE_JUMP_FIXES_METADATA_KEY,
    FakeJumpPredFix,
    FakeJumpStrategy,
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

    unflattener._audit_return_sites = prepare_return_frontier_audit(
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

    unflattener._audit_return_sites = prepare_return_frontier_audit(
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


def test_hodur_unflattener_does_not_register_fake_jump_in_live_hodur_stack():
    unflattener = HodurUnflattener()

    assert not any(
        isinstance(strategy, FakeJumpStrategy) for strategy in unflattener._strategies
    )


def test_hodur_unflattener_uses_hodur_strategy_family():
    unflattener = HodurUnflattener()

    assert isinstance(unflattener._family, HodurStrategyFamily)
    assert unflattener._strategies is unflattener._family.strategies


def test_hodur_unflattener_does_not_own_profile_hook_implementations():
    assert not [
        name
        for name in vars(HodurUnflattener)
        if name.startswith("_hook_") or name.startswith("_run_") and name.endswith("_hook")
    ]
    assert "bst_cleanup" in HodurPostPipelineHooks(object(), hook_runner=lambda *_a, **_k: None).handlers()


def test_hodur_unflattener_does_not_own_runtime_policy_callbacks():
    assert not {
        "_family_runtime_policy",
        "_build_family_planner_inputs",
        "_select_family_strategies",
        "_on_family_analysis",
        "_on_family_planned",
        "_on_family_executed",
    } & set(vars(HodurUnflattener))
    unflattener = HodurUnflattener()
    assert isinstance(unflattener._rule_services, HodurRuleServices)
    assert isinstance(unflattener._services, HodurRuntimeServices)
    assert unflattener._services.owner is unflattener._rule_services


def test_hodur_family_uses_generic_state_machine_snapshot_builder():
    family = HodurStrategyFamily()

    assert isinstance(family._snapshot_builder, StateMachineSnapshotBuilder)
    assert isinstance(family._snapshot_policy, HodurSnapshotPolicy)


def test_hodur_unflattener_compatibility_accessors_read_through_family_state():
    unflattener = HodurUnflattener()
    state_machine = SimpleNamespace(transitions=["t0"])
    detector = object()
    switch_table_map = object()

    unflattener._family._state_machine = state_machine
    unflattener._family._detector = detector
    unflattener._family._switch_table_map = switch_table_map
    unflattener._family._run_state = FamilyRunState(
        resolved_transitions=frozenset({(1, 2)}),
        initial_transitions=("initial",),
    )

    assert unflattener.state_machine is state_machine
    assert unflattener._detector is detector
    assert unflattener._switch_table_map is switch_table_map
    assert unflattener._resolved_transitions == {(1, 2)}
    assert unflattener._initial_transitions == ["initial"]


def test_semantic_structured_region_strategy_only_runs_at_glbopt1():
    strategy = SemanticStructuredRegionStrategy()
    state_machine = SimpleNamespace(handlers={0x10: object()}, initial_state=0x10)
    bst_result = SimpleNamespace(handler_state_map={0x10: 7})

    glbopt1_snapshot = SimpleNamespace(
        mba=SimpleNamespace(entry_ea=0x401000, maturity=ida_hexrays.MMAT_GLBOPT1),
        state_machine=state_machine,
        bst_result=bst_result,
    )
    glbopt2_snapshot = SimpleNamespace(
        mba=SimpleNamespace(entry_ea=0x401000, maturity=ida_hexrays.MMAT_GLBOPT2),
        state_machine=state_machine,
        bst_result=bst_result,
    )

    assert strategy.is_applicable(glbopt1_snapshot)
    assert not strategy.is_applicable(glbopt2_snapshot)


def test_hodur_strategy_family_defaults_to_live_strategies():
    family = HodurStrategyFamily()

    assert any(isinstance(strategy, HandlerChainComposerStrategy) for strategy in family.strategies)
    assert any(isinstance(strategy, DispatcherTrampolineSkipStrategy) for strategy in family.strategies)
    assert any(isinstance(strategy, CounterHoistStrategy) for strategy in family.strategies)


def test_hodur_strategy_family_accepts_explicit_strategy_override():
    family = HodurStrategyFamily(
        strategy_classes=[SemanticExactNodeAllPlannableEdgesStrategy]
    )

    assert len(family.strategies) == 1
    assert isinstance(
        family.strategies[0],
        SemanticExactNodeAllPlannableEdgesStrategy,
    )


def test_semantic_exact_node_bulk_window_defaults(monkeypatch):
    monkeypatch.delenv("D810_EXACT_NODE_EDGE_START", raising=False)
    monkeypatch.delenv("D810_EXACT_NODE_EDGE_STOP", raising=False)

    assert resolve_edge_window(10) == (0, 10)


def test_semantic_exact_node_bulk_window_clamps_and_orders(monkeypatch):
    monkeypatch.setenv("D810_EXACT_NODE_EDGE_START", "7")
    monkeypatch.setenv("D810_EXACT_NODE_EDGE_STOP", "3")
    assert resolve_edge_window(
        10,
        start_value="7",
        stop_value="3",
    ) == (7, 7)

    monkeypatch.setenv("D810_EXACT_NODE_EDGE_START", "0x2")
    monkeypatch.setenv("D810_EXACT_NODE_EDGE_STOP", "99")
    assert resolve_edge_window(
        10,
        start_value="0x2",
        stop_value="99",
    ) == (2, 10)


def test_semantic_exact_node_bulk_selection_skips_conditional_edges():
    strategy = SemanticExactNodeAllPlannableEdgesStrategy()
    transition_edge = SimpleNamespace(
        source_key=SimpleNamespace(state_const=0x10),
        target_state=0x20,
        kind=SimpleNamespace(name="TRANSITION"),
    )
    conditional_edge = SimpleNamespace(
        source_key=SimpleNamespace(state_const=0x30),
        target_state=0x40,
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
    )
    round_summary = SimpleNamespace(
        plannable_edges=(
            SimpleNamespace(edge=transition_edge),
            SimpleNamespace(edge=conditional_edge),
        )
    )

    selected = strategy._select_edges(round_summary)

    assert selected == [
        (round_summary.plannable_edges[0], (0x10, 0x20))
    ]


def test_parse_focus_edge_pairs_handles_hex_specs():
    assert parse_focus_edge_pairs(None) is None
    assert parse_focus_edge_pairs("") is None
    assert parse_focus_edge_pairs("   ") is None
    assert parse_focus_edge_pairs("5d0aebd3,606dc166") == ((0x5D0AEBD3, 0x606DC166),)
    assert parse_focus_edge_pairs(
        "5d0aebd3,606dc166;606dc166,139f2922"
    ) == (
        (0x5D0AEBD3, 0x606DC166),
        (0x606DC166, 0x139F2922),
    )
    assert parse_focus_edge_pairs("0x10,0x20") == ((0x10, 0x20),)
    # Malformed entries are silently skipped; valid ones survive.
    assert parse_focus_edge_pairs("garbage;0x10,0x20") == ((0x10, 0x20),)


def test_semantic_exact_node_focus_pairs_constructor_arg(monkeypatch):
    monkeypatch.delenv("D810_EXACT_NODE_FOCUS_EDGES", raising=False)
    strategy = SemanticExactNodeAllPlannableEdgesStrategy(
        focus_edge_pairs=((0x5D0AEBD3, 0x606DC166),)
    )
    pinned_edge = SimpleNamespace(
        source_key=SimpleNamespace(state_const=0x5D0AEBD3),
        target_state=0x606DC166,
        kind=SimpleNamespace(name="TRANSITION"),
    )
    other_edge = SimpleNamespace(
        source_key=SimpleNamespace(state_const=0x606DC166),
        target_state=0x139F2922,
        kind=SimpleNamespace(name="TRANSITION"),
    )
    round_summary = SimpleNamespace(
        plannable_edges=(
            SimpleNamespace(edge=pinned_edge),
            SimpleNamespace(edge=other_edge),
        )
    )
    selected = strategy._select_edges(round_summary)
    assert len(selected) == 1
    assert selected[0][1] == (0x5D0AEBD3, 0x606DC166)


def test_semantic_exact_node_focus_env_var_overrides_constructor(monkeypatch):
    monkeypatch.setenv(
        "D810_EXACT_NODE_FOCUS_EDGES", "606dc166,139f2922"
    )
    strategy = SemanticExactNodeAllPlannableEdgesStrategy(
        focus_edge_pairs=((0x5D0AEBD3, 0x606DC166),)
    )
    pinned_edge = SimpleNamespace(
        source_key=SimpleNamespace(state_const=0x5D0AEBD3),
        target_state=0x606DC166,
        kind=SimpleNamespace(name="TRANSITION"),
    )
    other_edge = SimpleNamespace(
        source_key=SimpleNamespace(state_const=0x606DC166),
        target_state=0x139F2922,
        kind=SimpleNamespace(name="TRANSITION"),
    )
    round_summary = SimpleNamespace(
        plannable_edges=(
            SimpleNamespace(edge=pinned_edge),
            SimpleNamespace(edge=other_edge),
        )
    )
    selected = strategy._select_edges(round_summary)
    assert len(selected) == 1
    assert selected[0][1] == (0x606DC166, 0x139F2922)


def test_collect_exact_conditional_sites_uses_physical_site_and_fallback_shape():
    flow_graph = FlowGraph(
        blocks={
            10: BlockSnapshot(10, 2, (11, 12), (0,), 0, 0, ()),
            11: BlockSnapshot(11, 1, (13,), (10,), 0, 0, ()),
            12: BlockSnapshot(12, 1, (14,), (10,), 0, 0, ()),
            13: BlockSnapshot(13, 1, (16,), (11,), 0, 0, ()),
            14: BlockSnapshot(14, 1, (30,), (12,), 0, 0, ()),
            16: BlockSnapshot(16, 1, (40,), (13,), 0, 0, ()),
            40: BlockSnapshot(40, 1, (21,), (16,), 0, 0, ()),
            21: BlockSnapshot(21, 0, (), (40,), 0, 0, ()),
            30: BlockSnapshot(30, 0, (), (14,), 0, 0, ()),
            0: BlockSnapshot(0, 1, (10,), (), 0, 0, ()),
        },
        entry_serial=0,
        func_ea=0x401000,
    )
    transition_edge = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x11111111),
        source_anchor=SimpleNamespace(block_serial=10),
        target_state=0x22222222,
        target_entry_anchor=40,
        ordered_path=(10, 11, 13),
    )
    alias_transition_edge = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0xAAAAAAAA),
        source_anchor=SimpleNamespace(block_serial=10),
        target_state=0x22222222,
        target_entry_anchor=40,
        ordered_path=(10, 11, 13),
    )
    return_edge = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_RETURN"),
        source_key=SimpleNamespace(state_const=0x11111111),
        source_anchor=SimpleNamespace(block_serial=10),
        ordered_path=(10, 12, 14, 30),
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(edges=(transition_edge, alias_transition_edge, return_edge)),
        plannable_edges=(
            SimpleNamespace(edge=transition_edge),
            SimpleNamespace(edge=alias_transition_edge),
        ),
    )

    sites = collect_exact_conditional_sites(round_summary, flow_graph)

    assert len(sites) == 1
    site = sites[0]
    assert site.source_block == 10
    assert site.target_entry == 40
    assert site.shape.taken_successor == 11
    assert site.shape.fallback_successor == 12
    assert site.shape.fallback_return_distance == 0
    assert site.shape.taken_return_distance == 0


def test_collect_exact_conditional_sites_rejects_when_taken_arm_is_closer_to_return():
    flow_graph = FlowGraph(
        blocks={
            10: BlockSnapshot(10, 2, (11, 12), (0,), 0, 0, ()),
            11: BlockSnapshot(11, 0, (), (10,), 0, 0, ()),
            12: BlockSnapshot(12, 2, (14, 16), (10,), 0, 0, ()),
            14: BlockSnapshot(14, 1, (15,), (12,), 0, 0, ()),
            15: BlockSnapshot(15, 0, (), (14,), 0, 0, ()),
            16: BlockSnapshot(16, 0, (), (12,), 0, 0, ()),
            0: BlockSnapshot(0, 1, (10,), (), 0, 0, ()),
        },
        entry_serial=0,
        func_ea=0x401000,
    )
    transition_edge = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x11111111),
        source_anchor=SimpleNamespace(block_serial=10),
        target_state=0x22222222,
        target_entry_anchor=40,
        ordered_path=(10, 11),
    )
    return_edge = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_RETURN"),
        source_key=SimpleNamespace(state_const=0x11111111),
        source_anchor=SimpleNamespace(block_serial=10),
        ordered_path=(10, 12, 14, 15),
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(edges=(transition_edge, return_edge)),
        plannable_edges=(SimpleNamespace(edge=transition_edge),),
    )

    sites = collect_exact_conditional_sites(round_summary, flow_graph)

    assert sites == ()


def test_collect_exact_conditional_fork_sites_selects_two_way_semantic_site():
    flow_graph = FlowGraph(
        blocks={
            10: BlockSnapshot(10, 2, (11, 12), (0,), 0, 0, ()),
            11: BlockSnapshot(11, 1, (13,), (10,), 0, 0, ()),
            12: BlockSnapshot(12, 1, (14,), (10,), 0, 0, ()),
            13: BlockSnapshot(13, 1, (40,), (11,), 0, 0, ()),
            14: BlockSnapshot(14, 1, (50,), (12,), 0, 0, ()),
            40: BlockSnapshot(40, 1, (21,), (13,), 0, 0, ()),
            50: BlockSnapshot(50, 1, (22,), (14,), 0, 0, ()),
            21: BlockSnapshot(21, 0, (), (40,), 0, 0, ()),
            22: BlockSnapshot(22, 0, (), (50,), 0, 0, ()),
            0: BlockSnapshot(0, 1, (10,), (), 0, 0, ()),
        },
        entry_serial=0,
        func_ea=0x401000,
    )
    edge_a = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x11111111),
        source_anchor=SimpleNamespace(block_serial=10),
        target_state=0x22222222,
        target_entry_anchor=40,
        ordered_path=(10, 11, 13),
    )
    edge_b = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x11111111),
        source_anchor=SimpleNamespace(block_serial=10),
        target_state=0x33333333,
        target_entry_anchor=50,
        ordered_path=(10, 12, 14),
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(edges=(edge_a, edge_b)),
        plannable_edges=(SimpleNamespace(edge=edge_a), SimpleNamespace(edge=edge_b)),
    )

    sites = collect_exact_conditional_fork_sites(round_summary, flow_graph)

    assert len(sites) == 1
    site = sites[0]
    assert site.source_block == 10
    assert {arm.first_hop for arm in site.arms} == {11, 12}
    assert {arm.target_entry for arm in site.arms} == {40, 50}


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
    monkeypatch.setattr(
        unflattener._rule_services,
        "_log_state_machine",
        lambda: calls.append("log"),
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
        hodur_runtime_services,
        "load_transition_report_from_store",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        hodur_runtime_services,
        "load_return_frontier_audit_from_store",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        hodur_runtime_services,
        "load_terminal_return_audit_from_store",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        unflattener._planner,
        "plan",
        lambda snap, strategies, inputs=None: (
            calls.append(("plan", snap, strategies, inputs)) or [],
            PipelineProvenance(),
        ),
    )
    monkeypatch.setattr(
        unflattener._rule_services,
        "_capture_post_pipeline_diagnostic_snapshot",
        lambda: calls.append("post_pipeline_snapshot"),
    )
    monkeypatch.setattr(
        unflattener._rule_services,
        "_stabilize_sub7ffd_post_pipeline_bundle",
        lambda: (_ for _ in ()).throw(
            AssertionError("recon-only no-plan path should not run bundle stabilization")
        ),
    )

    assert unflattener.optimize(blk) == 0
    assert ("begin_pass", 0) in calls
    assert ("detect", mba) in calls
    assert ("build_snapshot", mba, detection) in calls
    assert "post_pipeline_snapshot" in calls
    plan_calls = [call for call in calls if isinstance(call, tuple) and call[0] == "plan"]
    assert len(plan_calls) == 1
    _, seen_snapshot, seen_strategies, _ = plan_calls[0]
    assert seen_snapshot is snapshot
    assert seen_strategies == unflattener._family.strategies_for_maturity(
        ida_hexrays.MMAT_GLBOPT1
    )


def test_hodur_unflattener_ignores_configured_max_passes():
    unflattener = HodurUnflattener()

    unflattener.configure({"max_passes": 7})

    assert unflattener.max_passes == 1


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
    monkeypatch.setattr(unflattener._rule_services, "_log_state_machine", lambda: None)
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
        hodur_runtime_services,
        "load_transition_report_from_store",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        hodur_runtime_services,
        "load_return_frontier_audit_from_store",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        hodur_runtime_services,
        "load_terminal_return_audit_from_store",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        hodur_runtime_services,
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
        hodur_runtime_services,
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
        hodur_runtime_services,
        "make_transactional_executor_factory",
        lambda policy: (
            calls.append(("make_transactional_executor_factory", policy))
            or executor_factory_sentinel
        ),
    )
    monkeypatch.setattr(
        hodur_runtime_services,
        "run_ordered_family_hooks",
        lambda hook_names, hook_handlers, hook_context, **_kwargs: (
            calls.append(
                (
                    "post_pipeline_hooks",
                    hook_names,
                    tuple(hook_handlers),
                    hook_context,
                )
            )
            or hook_context
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
        unflattener._rule_services,
        "_log_pipeline_results",
        lambda *_args, **_kwargs: None,
    )

    assert unflattener.optimize(blk) == 0

    plan_calls = [call for call in calls if isinstance(call, tuple) and call[0] == "plan_runtime"]
    execute_calls = [
        call for call in calls if isinstance(call, tuple) and call[0] == "execute_runtime"
    ]
    factory_calls = [
        call
        for call in calls
        if isinstance(call, tuple) and call[0] == "make_transactional_executor_factory"
    ]
    outcome_calls = [
        call
        for call in calls
        if isinstance(call, tuple) and call[0] == "record_execution_outcome"
    ]
    hook_calls = [
        call
        for call in calls
        if isinstance(call, tuple) and call[0] == "post_pipeline_hooks"
    ]
    assert len(plan_calls) == 1
    assert len(execute_calls) == 1
    assert len(factory_calls) == 1
    assert len(outcome_calls) == 1
    assert len(hook_calls) == 1
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
    _, seen_policy = factory_calls[0]
    assert isinstance(seen_policy, ExecutorPolicy)
    assert seen_policy.gate is unflattener._gate
    assert seen_policy.safeguard_profile == "hodur"
    assert seen_policy.allow_legacy_block_creation is unflattener.allow_legacy_block_creation
    _, seen_pipeline, seen_results, seen_kwargs = outcome_calls[0]
    assert seen_pipeline == [fragment]
    assert len(seen_results) == 1
    assert seen_kwargs["func_ea"] == mba.entry_ea
    assert seen_kwargs["maturity"] == ida_hexrays.MMAT_GLBOPT1
    assert seen_kwargs["nb_changes"] == 0
    assert seen_kwargs["residual_dispatcher_preds_by_strategy"] == {}
    _, seen_hook_names, seen_hook_handlers, seen_hook_context = hook_calls[0]
    assert seen_hook_names == unflattener._profile.post_apply_hooks
    assert "bst_cleanup" in seen_hook_handlers
    assert "pipeline_summary" in seen_hook_handlers
    assert "post_pipeline_audit" in seen_hook_handlers
    assert seen_hook_context.pipeline == [fragment]
    assert seen_hook_context.total_changes == 0


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


def test_hodur_strategy_family_uses_constant_fixpoint_backend_for_discovery(
    monkeypatch,
):
    family = HodurStrategyFamily(strategy_classes=())
    constant_fixpoint = object()
    discovery = object()
    transition_result = object()
    dispatcher = object()
    dispatcher_cache = object()
    reachability = SimpleNamespace(entry_serial=0)
    base_flow_graph = FlowGraph(
        blocks={
            0: BlockSnapshot(0, 1, (2,), (), 0, 0, ()),
            2: BlockSnapshot(2, 0, (), (0,), 0, 0, ()),
        },
        entry_serial=0,
        func_ea=0x401000,
    )

    class _FakeConstantFixpointBackend:
        def compute(self, flow_graph: object, state_var_stkoff: int) -> object:
            assert flow_graph is base_flow_graph
            assert state_var_stkoff == 0x7BC
            return constant_fixpoint

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
        lambda _mba, flow_graph: flow_graph,
    )
    monkeypatch.setattr(
        family,
        "attach_single_iteration_fixes_to_flow_graph",
        lambda _mba, flow_graph: flow_graph,
    )
    monkeypatch.setattr(
        hodur_family_module,
        "build_transition_result_from_state_machine",
        lambda *args, **kwargs: transition_result,
    )

    def _fake_build_round_discovery_context(**kwargs):
        assert kwargs["flow_graph"] is base_flow_graph
        assert kwargs["transition_result"] is transition_result
        assert kwargs["dispatcher_entry_serial"] == 2
        assert kwargs["state_var_stkoff"] == 0x7BC
        assert kwargs["constant_fixpoint"] is constant_fixpoint
        assert kwargs["dispatcher"] is None
        return discovery

    monkeypatch.setattr(
        hodur_family_module,
        "build_round_discovery_context",
        _fake_build_round_discovery_context,
    )
    family._constant_fixpoint_backend = _FakeConstantFixpointBackend()
    from d810.recon.flow.dispatcher_detection import DispatcherType
    from d810.recon.flow.dispatcher_map import (
        StateDispatcherMap,
        StateDispatcherRow,
    )

    family._switch_table_map = StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=0x10,
                target_block=2,
                dispatcher_block=2,
                compare_block=2,
                branch_kind="switch_case",
                source=DispatcherType.SWITCH_TABLE,
                row_kind="handler",
            ),
        ),
        dispatcher_entry_block=2,
        dispatcher_blocks=frozenset({2}),
        state_var_stkoff=0x7BC,
        state_var_lvar_idx=None,
        source=DispatcherType.SWITCH_TABLE,
    )
    mba = SimpleNamespace(
        entry_ea=0x401000,
        maturity=ida_hexrays.MMAT_GLBOPT1,
    )
    state_machine = SimpleNamespace(
        handlers={0x10: SimpleNamespace(check_block=2)},
        initial_state=0x10,
        transitions=(),
        state_var=SimpleNamespace(
            t=ida_hexrays.mop_S,
            s=SimpleNamespace(off=0x7BC),
        ),
    )

    snapshot = family.build_snapshot(
        mba,
        HodurDetection(
            state_machine=state_machine,
            detector=object(),
            detection_source="test",
        ),
    )

    assert snapshot.discovery is discovery


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
        unflattener._rule_services,
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
        hodur_runtime_services,
        "load_transition_report_from_store",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("cleanup-only path should not load transition report")
        ),
    )
    monkeypatch.setattr(
        hodur_runtime_services,
        "load_return_frontier_audit_from_store",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("cleanup-only path should not load return frontier audit")
        ),
    )
    monkeypatch.setattr(
        hodur_runtime_services,
        "load_terminal_return_audit_from_store",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("cleanup-only path should not load terminal return audit")
        ),
    )
    monkeypatch.setattr(
        hodur_runtime_services,
        "prepare_return_frontier_audit",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("cleanup-only path should not prepare return-frontier audit")
        ),
    )
    monkeypatch.setattr(
        hodur_runtime_services,
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
        hodur_runtime_services,
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
        hodur_runtime_services,
        "make_transactional_executor_factory",
        lambda policy: calls.append(("make_transactional_executor_factory", policy))
        or object(),
    )
    monkeypatch.setattr(
        unflattener._family,
        "record_execution_outcome",
        lambda pipeline, results, **kwargs: calls.append(
            ("record_execution_outcome", pipeline, results, kwargs)
        ),
    )
    monkeypatch.setattr(
        hodur_runtime_services,
        "persist_terminal_return_audit",
        lambda results, **kwargs: calls.append(
            ("persist_terminal_return_audit", results, kwargs)
        ),
    )
    monkeypatch.setattr(
        hodur_post_pipeline_hooks,
        "collect_post_apply_bst_cleanup_blockers",
        lambda *args, **kwargs: {},
    )
    monkeypatch.setattr(
        hodur_post_pipeline_hooks,
        "finalize_return_frontier_audit",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("cleanup-only path should not finalize return-frontier audit")
        ),
    )
    monkeypatch.setattr(
        unflattener._rule_services,
        "_log_pipeline_results",
        lambda *_args, **_kwargs: None,
    )

    assert unflattener.optimize(blk) == 1
    assert unflattener._last_bst_serials == set()
    assert unflattener._last_dispatcher_serial == -1
    assert unflattener._last_func_ea == 0x401000
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


def test_attach_fake_jump_fixes_skips_cleanup_only_emulated_dispatcher_candidates(
    monkeypatch,
):
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
                analyze=lambda: SimpleNamespace(
                    is_conditional_chain=False,
                    dispatchers=(2,),
                ),
                is_dispatcher=lambda _serial: False,
            ),
        ),
    )

    updated = unflattener._family.attach_fake_jump_fixes_to_flow_graph(mba, flow_graph)

    assert updated is flow_graph
    assert updated.metadata == {}


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

    blockers = collect_post_apply_bst_cleanup_blockers(
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


def test_collect_live_residual_dispatcher_preds_uses_strategy_collector():
    calls: list[object] = []
    strategy = SimpleNamespace(
        name="linearized_flow_graph",
        _collect_dispatcher_predecessors=lambda flow_graph, dispatcher, **kwargs: (
            calls.append((flow_graph, dispatcher, kwargs)) or (95, 131)
        ),
    )
    cfg_translator = SimpleNamespace(lift=lambda mba: "live_flow_graph")
    snapshot = SimpleNamespace(
        bst_result=SimpleNamespace(bst_node_blocks={5, 6}),
        bst_dispatcher_serial=42,
    )

    residual_preds = collect_live_residual_dispatcher_preds(
        "mba",
        snapshot,
        strategies=[strategy],
        strategy_name="linearized_flow_graph",
        cfg_translator=cfg_translator,
    )

    assert residual_preds == (95, 131)
    assert calls == [
        ("live_flow_graph", 42, {"bst_node_blocks": {5, 6}}),
    ]


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

    blockers = collect_post_apply_bst_cleanup_blockers(
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


def test_collect_post_apply_bst_cleanup_blockers_preserves_reason_without_preds():
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
            "post_apply_bst_cleanup_reason": "residual_dispatcher_redirects",
        },
        modifications=[],
    )

    blockers = collect_post_apply_bst_cleanup_blockers(
        [fragment],
        [
            StageResult(
                strategy_name="linearized_flow_graph",
                success=True,
                edits_applied=7,
            ),
        ],
    )

    assert blockers == {"linearized_flow_graph": ()}


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

    blockers = collect_post_apply_bst_cleanup_blockers(
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
