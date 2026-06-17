from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

from d810.transforms.graph_modification import RedirectBranch
from d810.transforms.linearized_flow_graph_fragment_planning import (
    LinearizedDagPlannableEdge,
    LinearizedDagRoundSummary,
    LinearizedFlowGraphPlanningCallbacks,
    LinearizedFlowGraphPlanningContext,
    LinearizedFlowGraphStructuredRegionResult,
    LinearizedDagStructuredRegion,
    _regions_reachable_from_states,
    adapt_linearized_dag_round_summary,
    _synthesize_exact_node_regions,
    execute_linearized_flow_graph_planning,
    prepare_linearized_flow_graph_plan_setup,
)
from d810.analyses.control_flow.linearized_dag_round_discovery import (
    ResolvedDagStructuredRegion,
    discover_structured_dag_regions,
)
from d810.analyses.control_flow.linearized_state_dag import (
    LinearizedStateDag,
    RenderedProgramLine,
    RenderedProgramNode,
    RenderedProgramSnapshot,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
    StateDagNodeKey,
    StateNodeKind,
    StateRedirectAnchor,
    RedirectSourceKind,
)


@dataclass(frozen=True)
class _FakeEdge:
    name: str


class _FakeBuilder:
    def goto_redirect(self, *, source_block: int, target_block: int):
        return ("goto", int(source_block), int(target_block))


class _FakeStateMachine:
    def __init__(self):
        self.handlers = {}


class _FakeFlowGraph:
    def __init__(self, blocks):
        self.blocks = blocks

    def get_block(self, serial):
        return self.blocks.get(serial)


def _base_context(**overrides):
    base = dict(
        flow_graph=object(),
        builder=_FakeBuilder(),
        mba=None,
        state_machine=_FakeStateMachine(),
        dispatcher_serial=2,
        condition_chain_blocks=frozenset({2}),
        dispatcher_region=frozenset({2}),
        state_var_stkoff=None,
        dispatcher_lookup=None,
        dispatcher=None,
        pre_header_serial=None,
        original_blocks=frozenset({1, 10, 11, 20, 21}),
        same_maturity_rerun=False,
        projectable=False,
        round_limit=1,
        initial_state=0x1111,
        blocked_sources=frozenset(),
    )
    base.update(overrides)
    return LinearizedFlowGraphPlanningContext(**base)


def _summary(*edges: LinearizedDagPlannableEdge) -> LinearizedDagRoundSummary:
    return LinearizedDagRoundSummary(
        dag="dag",
        semantic_reference_program=None,
        structured_regions=(),
        plannable_edges=tuple(edges),
        report_exit_handlers=frozenset(),
        report_exit_owned_blocks=frozenset(),
        terminal_source_keys=frozenset(),
        terminal_source_handlers=frozenset(),
        terminal_source_owned_blocks=frozenset(),
        terminal_protected_blocks=frozenset(),
        terminal_skipped=0,
        unknown_skipped=0,
    )


def _summary_with_dag(dag, *edges: LinearizedDagPlannableEdge) -> LinearizedDagRoundSummary:
    return LinearizedDagRoundSummary(
        dag=dag,
        semantic_reference_program=None,
        structured_regions=(),
        plannable_edges=tuple(edges),
        report_exit_handlers=frozenset(),
        report_exit_owned_blocks=frozenset(),
        terminal_source_keys=frozenset(),
        terminal_source_handlers=frozenset(),
        terminal_source_owned_blocks=frozenset(),
        terminal_protected_blocks=frozenset(),
        terminal_skipped=0,
        unknown_skipped=0,
    )


def test_synthesize_exact_node_regions_adds_uncovered_exact_successors():
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        condition_chain_blocks=(2,),
        nodes=(
            StateDagNode(
                key=StateDagNodeKey(handler_serial=15, state_const=0x6107F8EC),
                kind=StateNodeKind.EXACT,
                state_label="0x6107F8EC",
                handler_serial=15,
                entry_anchor=15,
                owned_blocks=(15, 16, 17),
                exclusive_blocks=(15, 16, 17),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=StateDagNodeKey(handler_serial=66, state_const=0x4C77464F),
                kind=StateNodeKind.EXACT,
                state_label="0x4C77464F",
                handler_serial=66,
                entry_anchor=66,
                owned_blocks=(66, 67, 68, 69),
                exclusive_blocks=(66, 67, 68),
                shared_suffix_blocks=(69,),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=StateDagNodeKey(handler_serial=15, state_const=0x6107F8EC),
                target_key=StateDagNodeKey(handler_serial=66, state_const=0x4C77464F),
                target_state=0x4C77464F,
                target_entry_anchor=66,
                target_label="0x4C77464F",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=15,
                    branch_arm=0,
                ),
                ordered_path=(15, 16),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=StateDagNodeKey(handler_serial=66, state_const=0x4C77464F),
                target_key=StateDagNodeKey(handler_serial=189, state_const=0x32FCD904),
                target_state=0x32FCD904,
                target_entry_anchor=189,
                target_label="0x32FCD904",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=66,
                    branch_arm=0,
                ),
                ordered_path=(66, 67),
            ),
        ),
    )

    synthetic = _synthesize_exact_node_regions(
        dag,
        (
            LinearizedDagStructuredRegion(
                region_name="root",
                entry_state=0x6107F8EC,
                state_values=(0x6107F8EC,),
                state_labels=("0x6107F8EC",),
                internal_state_edges=(),
                exit_state_values=(0x4C77464F,),
            ),
        ),
    )

    assert synthetic == (
        LinearizedDagStructuredRegion(
            region_name="synthetic_exact_region_0x4C77464F",
            entry_state=0x4C77464F,
            state_values=(0x4C77464F,),
            state_labels=("0x4C77464F",),
            internal_state_edges=(),
            exit_state_values=(0x32FCD904,),
        ),
    )


def test_adapt_round_summary_can_disable_synthetic_exact_regions():
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        condition_chain_blocks=(2,),
        nodes=(
            StateDagNode(
                key=StateDagNodeKey(handler_serial=15, state_const=0x6107F8EC),
                kind=StateNodeKind.EXACT,
                state_label="0x6107F8EC",
                handler_serial=15,
                entry_anchor=15,
                owned_blocks=(15, 16, 17),
                exclusive_blocks=(15, 16, 17),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=StateDagNodeKey(handler_serial=66, state_const=0x4C77464F),
                kind=StateNodeKind.EXACT,
                state_label="0x4C77464F",
                handler_serial=66,
                entry_anchor=66,
                owned_blocks=(66, 67, 68),
                exclusive_blocks=(66, 67, 68),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=StateDagNodeKey(handler_serial=15, state_const=0x6107F8EC),
                target_key=StateDagNodeKey(handler_serial=66, state_const=0x4C77464F),
                target_state=0x4C77464F,
                target_entry_anchor=66,
                target_label="0x4C77464F",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=15,
                    branch_arm=0,
                ),
                ordered_path=(15, 16),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=StateDagNodeKey(handler_serial=66, state_const=0x4C77464F),
                target_key=StateDagNodeKey(handler_serial=189, state_const=0x32FCD904),
                target_state=0x32FCD904,
                target_entry_anchor=189,
                target_label="0x32FCD904",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=66,
                    branch_arm=0,
                ),
                ordered_path=(66, 67),
            ),
        ),
    )
    resolved_summary = SimpleNamespace(
        dag=dag,
        semantic_reference_program=None,
        structured_regions=(
            SimpleNamespace(
                region_name="root",
                entry_state=0x6107F8EC,
                state_values=(0x6107F8EC,),
                state_labels=("0x6107F8EC",),
                internal_state_edges=(),
                exit_state_values=(0x4C77464F,),
            ),
        ),
        plannable_edges=(),
        report_exit_handlers=frozenset(),
        report_exit_owned_blocks=frozenset(),
        terminal_source_keys=frozenset(),
        terminal_source_handlers=frozenset(),
        terminal_source_owned_blocks=frozenset(),
        terminal_protected_blocks=frozenset(),
        terminal_skipped=0,
        unknown_skipped=0,
    )

    without_synthetic = adapt_linearized_dag_round_summary(
        state_machine=SimpleNamespace(initial_state=0x6107F8EC, handlers={}),
        range_evidence=SimpleNamespace(),
        transition_result=SimpleNamespace(),
        current_flow_graph=object(),
        dag_round_mba=None,
        dispatcher_serial=2,
        state_var_stkoff=None,
        pre_header_serial=None,
        condition_chain_blocks=frozenset({2}),
        build_round_summary=lambda **kwargs: resolved_summary,
        build_live_dag=lambda *args, **kwargs: dag,
        build_transition_report=lambda *args, **kwargs: SimpleNamespace(rows=()),
        select_plannable_edges=lambda dag: (),
        include_synthetic_exact_regions=False,
    )
    with_synthetic = adapt_linearized_dag_round_summary(
        state_machine=SimpleNamespace(initial_state=0x6107F8EC, handlers={}),
        range_evidence=SimpleNamespace(),
        transition_result=SimpleNamespace(),
        current_flow_graph=object(),
        dag_round_mba=None,
        dispatcher_serial=2,
        state_var_stkoff=None,
        pre_header_serial=None,
        condition_chain_blocks=frozenset({2}),
        build_round_summary=lambda **kwargs: resolved_summary,
        build_live_dag=lambda *args, **kwargs: dag,
        build_transition_report=lambda *args, **kwargs: SimpleNamespace(rows=()),
        select_plannable_edges=lambda dag: (),
        include_synthetic_exact_regions=True,
    )

    assert tuple(region.region_name for region in without_synthetic.structured_regions) == ("root",)
    assert tuple(region.region_name for region in with_synthetic.structured_regions) == (
        "root",
        "synthetic_exact_region_0x4C77464F",
    )


def test_regions_reachable_from_states_does_not_include_transitive_exit_descendants():
    regions = (
        LinearizedDagStructuredRegion(
            region_name="root",
            entry_state=0x10743C4C,
            state_values=(0x10743C4C, 0x6107F8EC),
            state_labels=("0x10743C4C", "0x6107F8EC"),
            internal_state_edges=((0x10743C4C, 0x6107F8EC),),
            exit_state_values=(0x474EEEBB,),
        ),
        LinearizedDagStructuredRegion(
            region_name="child",
            entry_state=0x474EEEBB,
            state_values=(0x474EEEBB,),
            state_labels=("0x474EEEBB",),
            internal_state_edges=(),
            exit_state_values=(0x139F2922,),
        ),
        LinearizedDagStructuredRegion(
            region_name="grandchild",
            entry_state=0x139F2922,
            state_values=(0x139F2922,),
            state_labels=("0x139F2922",),
            internal_state_edges=(),
            exit_state_values=(),
        ),
    )

    root_only = _regions_reachable_from_states(
        regions,
        seeded_states=frozenset({0x10743C4C}),
        attempted_region_names=frozenset(),
    )
    child_only = _regions_reachable_from_states(
        regions,
        seeded_states=frozenset({0x474EEEBB}),
        attempted_region_names=frozenset({"root"}),
    )

    assert tuple(region.region_name for region in root_only) == ("root",)
    assert tuple(region.region_name for region in child_only) == ("child",)


class TestExecuteLinearizedFlowGraphPlanning:
    def test_accepts_edge_and_preheader_redirect(self):
        edge = LinearizedDagPlannableEdge(
            edge=_FakeEdge("e1"),
            source_anchor_block=10,
            ordered_path=(10,),
            target_entry_anchor=None,
            is_conditional_transition=False,
            requires_safe_target_resolution=False,
        )

        def emit_dag_redirect(**kwargs):
            state = kwargs["state"]
            state.modifications.append(("edge", kwargs["edge"].name))
            state.owned_blocks.add(10)
            state.owned_edges.add((10, 20))
            state.owned_transitions.add((1, 2))
            return True

        result = execute_linearized_flow_graph_planning(
            _base_context(pre_header_serial=1),
            callbacks=LinearizedFlowGraphPlanningCallbacks(
                build_round_summary=lambda current_flow_graph, dag_round_mba: _summary(edge),
                build_projected_mba=lambda flow_graph: flow_graph,
                project_flow_graph=lambda flow_graph, modifications: flow_graph,
                resolve_redirect_safe_target_entry=lambda dag, planned_edge, condition_chain_blocks: None,
                resolve_initial_entry=lambda dag, initial_state, condition_chain_blocks: 11,
                emit_dag_redirect=emit_dag_redirect,
                collect_residual_dispatcher_predecessors=lambda flow_graph, dispatcher_serial, condition_chain_blocks, reachable_from_serial: (),
                emit_structured_region=lambda **kwargs: LinearizedFlowGraphStructuredRegionResult(accepted=False),
                emit_residual_dispatcher_handoffs=lambda **kwargs: 0,
                disconnect_condition_chain_nodes=lambda condition_chain_blocks, dispatcher_serial, state: 2,
            ),
        )

        assert result.accepted
        assert result.modifications == (("edge", "e1"), ("goto", 1, 11))
        assert result.transition_count == 2
        assert result.conditional_count == 0
        assert result.disconnect_count == 2
        assert result.cleanup_gate_reason is None

    def test_reports_unresolved_safe_target_when_everything_is_skipped(self):
        edge = LinearizedDagPlannableEdge(
            edge=_FakeEdge("e1"),
            source_anchor_block=10,
            ordered_path=(10,),
            target_entry_anchor=20,
            is_conditional_transition=False,
            requires_safe_target_resolution=True,
        )

        result = execute_linearized_flow_graph_planning(
            _base_context(initial_state=None),
            callbacks=LinearizedFlowGraphPlanningCallbacks(
                build_round_summary=lambda current_flow_graph, dag_round_mba: _summary(edge),
                build_projected_mba=lambda flow_graph: flow_graph,
                project_flow_graph=lambda flow_graph, modifications: flow_graph,
                resolve_redirect_safe_target_entry=lambda dag, planned_edge, condition_chain_blocks: None,
                resolve_initial_entry=lambda dag, initial_state, condition_chain_blocks: None,
                emit_dag_redirect=lambda **kwargs: False,
                collect_residual_dispatcher_predecessors=lambda flow_graph, dispatcher_serial, condition_chain_blocks, reachable_from_serial: (),
                emit_structured_region=lambda **kwargs: LinearizedFlowGraphStructuredRegionResult(accepted=False),
                emit_residual_dispatcher_handoffs=lambda **kwargs: 0,
                disconnect_condition_chain_nodes=lambda condition_chain_blocks, dispatcher_serial, state: 0,
            ),
        )

        assert not result.accepted
        assert result.modifications == ()
        assert result.unresolved_condition_chain_targets == 1
        assert result.skipped_count == 1

    def test_preserves_cleanup_gate_when_residual_dispatcher_preds_remain(self):
        edge = LinearizedDagPlannableEdge(
            edge=_FakeEdge("e1"),
            source_anchor_block=10,
            ordered_path=(10,),
            target_entry_anchor=None,
            is_conditional_transition=False,
            requires_safe_target_resolution=False,
        )
        disconnect_calls: list[int] = []
        residual_calls = {"count": 0}
        residual_calls = {"count": 0}

        def collect_residual(flow_graph, dispatcher_serial, condition_chain_blocks, reachable_from_serial):
            residual_calls["count"] += 1
            return (21,)

        def emit_dag_redirect(**kwargs):
            state = kwargs["state"]
            state.modifications.append(("edge", kwargs["edge"].name))
            return True

        result = execute_linearized_flow_graph_planning(
            _base_context(initial_state=None),
            callbacks=LinearizedFlowGraphPlanningCallbacks(
                build_round_summary=lambda current_flow_graph, dag_round_mba: _summary(edge),
                build_projected_mba=lambda flow_graph: flow_graph,
                project_flow_graph=lambda flow_graph, modifications: flow_graph,
                resolve_redirect_safe_target_entry=lambda dag, planned_edge, condition_chain_blocks: None,
                resolve_initial_entry=lambda dag, initial_state, condition_chain_blocks: None,
                emit_dag_redirect=emit_dag_redirect,
                collect_residual_dispatcher_predecessors=collect_residual,
                emit_structured_region=lambda **kwargs: LinearizedFlowGraphStructuredRegionResult(accepted=False),
                emit_residual_dispatcher_handoffs=lambda **kwargs: 1,
                disconnect_condition_chain_nodes=lambda condition_chain_blocks, dispatcher_serial, state: disconnect_calls.append(1) or 7,
            ),
        )

        assert result.accepted
        assert result.cleanup_gate_reason == "residual_dispatcher_predecessors"
        assert result.residual_dispatcher_preds == (21,)
        assert result.residual_dispatcher_redirect_count == 1
        assert result.disconnect_count == 0
        assert disconnect_calls == []

    def test_preserves_cleanup_gate_when_residual_handoff_rejections_remain(self):
        edge = LinearizedDagPlannableEdge(
            edge=_FakeEdge("e1"),
            source_anchor_block=10,
            ordered_path=(10,),
            target_entry_anchor=None,
            is_conditional_transition=False,
            requires_safe_target_resolution=False,
        )
        disconnect_calls: list[int] = []
        residual_calls = {"count": 0}

        def emit_residual_dispatcher_handoffs(**kwargs):
            kwargs["state"].modifications.append(("residual", 41))
            kwargs["rejected_sources"].add(41)
            return 1

        def collect_residual_dispatcher_predecessors(
            flow_graph,
            dispatcher_serial,
            condition_chain_blocks,
            reachable_from_serial,
        ):
            if residual_calls["count"] == 0:
                residual_calls["count"] += 1
                return (41,)
            return ()

        result = execute_linearized_flow_graph_planning(
            _base_context(initial_state=None),
            callbacks=LinearizedFlowGraphPlanningCallbacks(
                build_round_summary=lambda current_flow_graph, dag_round_mba: _summary(edge),
                build_projected_mba=lambda flow_graph: flow_graph,
                project_flow_graph=lambda flow_graph, modifications: flow_graph,
                resolve_redirect_safe_target_entry=lambda dag, planned_edge, condition_chain_blocks: None,
                resolve_initial_entry=lambda dag, initial_state, condition_chain_blocks: None,
                emit_dag_redirect=lambda **kwargs: kwargs["state"].modifications.append(("edge", "e1")) or True,
                collect_residual_dispatcher_predecessors=collect_residual_dispatcher_predecessors,
                emit_structured_region=lambda **kwargs: LinearizedFlowGraphStructuredRegionResult(accepted=False),
                emit_residual_dispatcher_handoffs=emit_residual_dispatcher_handoffs,
                disconnect_condition_chain_nodes=lambda condition_chain_blocks, dispatcher_serial, state: disconnect_calls.append(1) or 7,
            ),
        )

        assert result.accepted
        assert result.cleanup_gate_reason == "residual_dispatcher_rejections"
        assert result.residual_dispatcher_preds == (41,)
        assert result.residual_dispatcher_redirect_count == 1
        assert result.disconnect_count == 0
        assert disconnect_calls == []

    def test_residual_redirects_still_block_cleanup_without_live_reprojection(self):
        edge = LinearizedDagPlannableEdge(
            edge=_FakeEdge("e1"),
            source_anchor_block=10,
            ordered_path=(10,),
            target_entry_anchor=None,
            is_conditional_transition=False,
            requires_safe_target_resolution=False,
        )
        disconnect_calls: list[int] = []
        residual_calls = {"count": 0}

        def collect_residual_dispatcher_predecessors(
            flow_graph,
            dispatcher_serial,
            condition_chain_blocks,
            reachable_from_serial,
        ):
            if residual_calls["count"] == 0:
                residual_calls["count"] += 1
                return (41,)
            return ()

        result = execute_linearized_flow_graph_planning(
            _base_context(initial_state=None),
            callbacks=LinearizedFlowGraphPlanningCallbacks(
                build_round_summary=lambda current_flow_graph, dag_round_mba: _summary(edge),
                build_projected_mba=lambda flow_graph: flow_graph,
                project_flow_graph=lambda flow_graph, modifications: flow_graph,
                resolve_redirect_safe_target_entry=lambda dag, planned_edge, condition_chain_blocks: None,
                resolve_initial_entry=lambda dag, initial_state, condition_chain_blocks: None,
                emit_dag_redirect=lambda **kwargs: kwargs["state"].modifications.append(("edge", "e1")) or True,
                collect_residual_dispatcher_predecessors=collect_residual_dispatcher_predecessors,
                emit_structured_region=lambda **kwargs: LinearizedFlowGraphStructuredRegionResult(accepted=False),
                emit_residual_dispatcher_handoffs=lambda **kwargs: 1,
                disconnect_condition_chain_nodes=lambda condition_chain_blocks, dispatcher_serial, state: disconnect_calls.append(1) or 7,
            ),
        )

        assert result.accepted
        assert result.cleanup_gate_reason in {
            "residual_dispatcher_redirects",
            "residual_dispatcher_predecessors",
        }
        assert result.residual_dispatcher_redirect_count == 1
        assert result.disconnect_count == 0
        assert disconnect_calls == []

    def test_structured_region_can_claim_edges_before_edge_loop(self):
        edge = LinearizedDagPlannableEdge(
            edge=SimpleNamespace(
                source_key=SimpleNamespace(state_const=0x5D0AEBD3),
                target_state=0x606DC166,
            ),
            source_anchor_block=10,
            ordered_path=(10,),
            target_entry_anchor=None,
            is_conditional_transition=False,
            requires_safe_target_resolution=False,
        )
        region = LinearizedDagStructuredRegion(
            region_name="sub7ffd_initial_semantic_region",
            entry_state=0x5D0AEBD3,
            state_values=(0x5D0AEBD3, 0x606DC166),
            state_labels=("STATE_5D0AEBD3", "STATE_606DC166"),
            internal_state_edges=((0x5D0AEBD3, 0x606DC166),),
        )
        emit_edge_calls: list[str] = []

        def emit_structured_region(**kwargs):
            state = kwargs["state"]
            state.modifications.append(("structured", "region"))
            return LinearizedFlowGraphStructuredRegionResult(
                accepted=True,
                consumed_state_edges=frozenset({(0x5D0AEBD3, 0x606DC166)}),
                transition_count=1,
                conditional_count=0,
            )

        result = execute_linearized_flow_graph_planning(
            _base_context(initial_state=None),
            callbacks=LinearizedFlowGraphPlanningCallbacks(
                build_round_summary=lambda current_flow_graph, dag_round_mba: LinearizedDagRoundSummary(
                    dag="dag",
                    semantic_reference_program=None,
                    structured_regions=(region,),
                    plannable_edges=(edge,),
                    report_exit_handlers=frozenset(),
                    report_exit_owned_blocks=frozenset(),
                    terminal_source_keys=frozenset(),
                    terminal_source_handlers=frozenset(),
                    terminal_source_owned_blocks=frozenset(),
                    terminal_protected_blocks=frozenset(),
                    terminal_skipped=0,
                    unknown_skipped=0,
                ),
                build_projected_mba=lambda flow_graph: flow_graph,
                project_flow_graph=lambda flow_graph, modifications: flow_graph,
                resolve_redirect_safe_target_entry=lambda dag, planned_edge, condition_chain_blocks: None,
                resolve_initial_entry=lambda dag, initial_state, condition_chain_blocks: None,
                emit_dag_redirect=lambda **kwargs: emit_edge_calls.append("edge") or True,
                collect_residual_dispatcher_predecessors=lambda flow_graph, dispatcher_serial, condition_chain_blocks, reachable_from_serial: (),
                emit_structured_region=emit_structured_region,
                emit_residual_dispatcher_handoffs=lambda **kwargs: 0,
                disconnect_condition_chain_nodes=lambda condition_chain_blocks, dispatcher_serial, state: 0,
            ),
        )

        assert result.accepted
        assert result.modifications == (("structured", "region"),)
        assert result.transition_count == 1
        assert emit_edge_calls == []

    def test_keeps_projected_conditional_redirects_without_contextual_owner_proof(self):
        source_key = StateDagNodeKey(handler_serial=15, state_const=0x6107F8EC)
        raw_taken_key = StateDagNodeKey(handler_serial=66, state_const=0x4C77464F)
        raw_not_taken_key = StateDagNodeKey(handler_serial=202, state_const=0x296F2452)
        semantic_taken_key = StateDagNodeKey(handler_serial=14, state_const=0x4C77464F)
        semantic_not_taken_key = StateDagNodeKey(handler_serial=201, state_const=0x296F2452)
        dag = LinearizedStateDag(
            dispatcher_entry_serial=2,
            state_var_stkoff=None,
            pre_header_serial=None,
            initial_state=0x6107F8EC,
            condition_chain_blocks=(2,),
            nodes=(
                StateDagNode(
                    key=StateDagNodeKey(handler_serial=15, state_const=0x6107F8EC),
                    kind=StateNodeKind.EXACT,
                    state_label="0x6107F8EC",
                    handler_serial=15,
                    entry_anchor=15,
                    owned_blocks=(15,),
                    exclusive_blocks=(15,),
                    shared_suffix_blocks=(),
                    local_segments=(),
                    local_edges=(),
                ),
                StateDagNode(
                    key=semantic_taken_key,
                    kind=StateNodeKind.EXACT,
                    state_label="0x4C77464F",
                    handler_serial=14,
                    entry_anchor=14,
                    owned_blocks=(14,),
                    exclusive_blocks=(14,),
                    shared_suffix_blocks=(),
                    local_segments=(),
                    local_edges=(),
                ),
                StateDagNode(
                    key=semantic_not_taken_key,
                    kind=StateNodeKind.EXACT,
                    state_label="0x296F2452",
                    handler_serial=201,
                    entry_anchor=201,
                    owned_blocks=(201,),
                    exclusive_blocks=(201,),
                    shared_suffix_blocks=(),
                    local_segments=(),
                    local_edges=(),
                ),
            ),
            edges=(
                StateDagEdge(
                    kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                    source_key=source_key,
                    target_key=raw_taken_key,
                    target_state=0x4C77464F,
                    target_entry_anchor=66,
                    target_label="0x4C77464F",
                    source_anchor=StateRedirectAnchor(
                        kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                        block_serial=15,
                        branch_arm=0,
                    ),
                    ordered_path=(15, 16),
                ),
                StateDagEdge(
                    kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                    source_key=source_key,
                    target_key=raw_not_taken_key,
                    target_state=0x296F2452,
                    target_entry_anchor=202,
                    target_label="0x296F2452",
                    source_anchor=StateRedirectAnchor(
                        kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                        block_serial=15,
                        branch_arm=1,
                    ),
                    ordered_path=(15, 17),
                ),
            ),
        )
        plannable_taken = LinearizedDagPlannableEdge(
            edge=_FakeEdge("taken"),
            source_anchor_block=15,
            ordered_path=(15, 16),
            target_entry_anchor=66,
            is_conditional_transition=True,
            requires_safe_target_resolution=False,
        )
        plannable_not_taken = LinearizedDagPlannableEdge(
            edge=_FakeEdge("not_taken"),
            source_anchor_block=15,
            ordered_path=(15, 17),
            target_entry_anchor=202,
            is_conditional_transition=True,
            requires_safe_target_resolution=False,
        )

        def emit_dag_redirect(**kwargs):
            state = kwargs["state"]
            edge_name = kwargs["edge"].name
            if edge_name == "taken":
                state.modifications.append(
                    RedirectBranch(from_serial=15, old_target=16, new_target=66)
                )
                state.claimed_2way[(15, 16)] = 66
                state.owned_edges.add((15, 66))
                state.emitted.add((15, 66))
            elif edge_name == "not_taken":
                state.modifications.append(
                    RedirectBranch(from_serial=15, old_target=17, new_target=202)
                )
                state.claimed_2way[(15, 17)] = 202
                state.owned_edges.add((15, 202))
                state.emitted.add((15, 202))
            state.owned_blocks.add(15)
            return True

        result = execute_linearized_flow_graph_planning(
            _base_context(
                initial_state=None,
                original_blocks=frozenset({14, 15, 16, 17, 201}),
            ),
            callbacks=LinearizedFlowGraphPlanningCallbacks(
                build_round_summary=lambda current_flow_graph, dag_round_mba: _summary_with_dag(
                    dag,
                    plannable_taken,
                    plannable_not_taken,
                ),
                build_projected_mba=lambda flow_graph: flow_graph,
                project_flow_graph=lambda flow_graph, modifications: flow_graph,
                resolve_redirect_safe_target_entry=lambda dag, planned_edge, condition_chain_blocks: None,
                resolve_initial_entry=lambda dag, initial_state, condition_chain_blocks: None,
                emit_dag_redirect=emit_dag_redirect,
                collect_residual_dispatcher_predecessors=lambda flow_graph, dispatcher_serial, condition_chain_blocks, reachable_from_serial: (),
                emit_structured_region=lambda **kwargs: LinearizedFlowGraphStructuredRegionResult(accepted=False),
                emit_residual_dispatcher_handoffs=lambda **kwargs: 0,
                disconnect_condition_chain_nodes=lambda condition_chain_blocks, dispatcher_serial, state: 0,
            ),
        )

        assert result.accepted
        assert result.modifications == (
            RedirectBranch(from_serial=15, old_target=16, new_target=66),
            RedirectBranch(from_serial=15, old_target=17, new_target=202),
        )
        assert result.residual_dispatcher_normalized_count == 0

def test_structured_regions_follow_successor_worklist_from_initial_state():
    region_a = LinearizedDagStructuredRegion(
        region_name="initial_region",
        entry_state=0x1111,
        state_values=(0x1111, 0x2222),
        state_labels=("STATE_1111", "STATE_2222"),
        internal_state_edges=((0x1111, 0x2222),),
        exit_state_values=(0x3333,),
    )
    region_b = LinearizedDagStructuredRegion(
        region_name="child_region",
        entry_state=0x4444,
        state_values=(0x4444, 0x3333),
        state_labels=("STATE_4444", "STATE_3333"),
        internal_state_edges=((0x4444, 0x3333),),
        exit_state_values=(),
    )
    region_c = LinearizedDagStructuredRegion(
        region_name="unrelated_region",
        entry_state=0x9999,
        state_values=(0x9999,),
        state_labels=("STATE_9999",),
        internal_state_edges=(),
        exit_state_values=(),
    )
    emitted_regions: list[str] = []

    def emit_structured_region(**kwargs):
        region = kwargs["region"]
        state = kwargs["state"]
        emitted_regions.append(region.region_name)
        if region.region_name == "initial_region":
            state.modifications.append(("structured", "initial_region"))
            return LinearizedFlowGraphStructuredRegionResult(
                accepted=True,
                consumed_state_edges=frozenset({(0x1111, 0x2222)}),
                successor_state_values=frozenset({0x3333}),
                transition_count=1,
                conditional_count=0,
            )
        if region.region_name == "child_region":
            state.modifications.append(("structured", "child_region"))
            return LinearizedFlowGraphStructuredRegionResult(
                accepted=True,
                consumed_state_edges=frozenset({(0x4444, 0x3333)}),
                transition_count=1,
                conditional_count=0,
            )
        return LinearizedFlowGraphStructuredRegionResult(accepted=False)

    result = execute_linearized_flow_graph_planning(
        _base_context(
            initial_state=0x1111,
            projectable=True,
            round_limit=2,
        ),
        callbacks=LinearizedFlowGraphPlanningCallbacks(
            build_round_summary=lambda current_flow_graph, dag_round_mba: LinearizedDagRoundSummary(
                dag="dag",
                semantic_reference_program=None,
                structured_regions=(region_a, region_b, region_c),
                plannable_edges=(),
                report_exit_handlers=frozenset(),
                report_exit_owned_blocks=frozenset(),
                terminal_source_keys=frozenset(),
                terminal_source_handlers=frozenset(),
                terminal_source_owned_blocks=frozenset(),
                terminal_protected_blocks=frozenset(),
                terminal_skipped=0,
                unknown_skipped=0,
            ),
            build_projected_mba=lambda flow_graph: flow_graph,
            project_flow_graph=lambda flow_graph, modifications: flow_graph,
            resolve_redirect_safe_target_entry=lambda dag, planned_edge, condition_chain_blocks: None,
            resolve_initial_entry=lambda dag, initial_state, condition_chain_blocks: None,
            emit_dag_redirect=lambda **kwargs: False,
            collect_residual_dispatcher_predecessors=lambda flow_graph, dispatcher_serial, condition_chain_blocks, reachable_from_serial: (),
            emit_structured_region=emit_structured_region,
            emit_residual_dispatcher_handoffs=lambda **kwargs: 0,
            disconnect_condition_chain_nodes=lambda condition_chain_blocks, dispatcher_serial, state: 0,
        ),
    )

    assert result.accepted
    assert emitted_regions == ["initial_region", "child_region"]
    assert result.transition_count == 2


def test_structured_regions_follow_transitive_region_graph_from_initial_state():
    region_a = LinearizedDagStructuredRegion(
        region_name="initial_region",
        entry_state=0x1111,
        state_values=(0x1111,),
        state_labels=("STATE_1111",),
        internal_state_edges=(),
        exit_state_values=(0x2222,),
    )
    region_b = LinearizedDagStructuredRegion(
        region_name="synthetic_mid_region",
        entry_state=0x2222,
        state_values=(0x2222,),
        state_labels=("STATE_2222",),
        internal_state_edges=(),
        exit_state_values=(0x3333,),
    )
    region_c = LinearizedDagStructuredRegion(
        region_name="downstream_region",
        entry_state=0x3333,
        state_values=(0x3333,),
        state_labels=("STATE_3333",),
        internal_state_edges=(),
        exit_state_values=(),
    )
    emitted_regions: list[str] = []

    def emit_structured_region(**kwargs):
        region = kwargs["region"]
        state = kwargs["state"]
        emitted_regions.append(region.region_name)
        state.modifications.append(("structured", region.region_name))
        successor_states = {
            "initial_region": frozenset({0x2222}),
            "synthetic_mid_region": frozenset({0x3333}),
        }.get(region.region_name, frozenset())
        return LinearizedFlowGraphStructuredRegionResult(
            accepted=True,
            successor_state_values=successor_states,
            transition_count=1,
            conditional_count=0,
        )

    result = execute_linearized_flow_graph_planning(
        _base_context(
            initial_state=0x1111,
            projectable=True,
            round_limit=3,
        ),
        callbacks=LinearizedFlowGraphPlanningCallbacks(
            build_round_summary=lambda current_flow_graph, dag_round_mba: LinearizedDagRoundSummary(
                dag="dag",
                semantic_reference_program=None,
                structured_regions=(region_a, region_b, region_c),
                plannable_edges=(),
                report_exit_handlers=frozenset(),
                report_exit_owned_blocks=frozenset(),
                terminal_source_keys=frozenset(),
                terminal_source_handlers=frozenset(),
                terminal_source_owned_blocks=frozenset(),
                terminal_protected_blocks=frozenset(),
                terminal_skipped=0,
                unknown_skipped=0,
            ),
            build_projected_mba=lambda flow_graph: flow_graph,
            project_flow_graph=lambda flow_graph, modifications: flow_graph,
            resolve_redirect_safe_target_entry=lambda dag, planned_edge, condition_chain_blocks: None,
            resolve_initial_entry=lambda dag, initial_state, condition_chain_blocks: None,
            emit_dag_redirect=lambda **kwargs: False,
            collect_residual_dispatcher_predecessors=lambda flow_graph, dispatcher_serial, condition_chain_blocks, reachable_from_serial: (),
            emit_structured_region=emit_structured_region,
            emit_residual_dispatcher_handoffs=lambda **kwargs: 0,
            disconnect_condition_chain_nodes=lambda condition_chain_blocks, dispatcher_serial, state: 0,
        ),
    )

    assert result.accepted
    assert emitted_regions == ["initial_region", "synthetic_mid_region", "downstream_region"]
    assert result.transition_count == 3


def test_structured_regions_requeue_unresolved_source_states_from_accepted_region():
    region_a = LinearizedDagStructuredRegion(
        region_name="initial_region",
        entry_state=0x1111,
        state_values=(0x1111, 0x2222),
        state_labels=("STATE_1111", "STATE_2222"),
        internal_state_edges=((0x1111, 0x2222),),
        exit_state_values=(),
    )
    region_b = LinearizedDagStructuredRegion(
        region_name="child_region",
        entry_state=0x2222,
        state_values=(0x2222,),
        state_labels=("STATE_2222",),
        internal_state_edges=(),
        exit_state_values=(),
    )
    emitted_regions: list[str] = []

    def emit_structured_region(**kwargs):
        region = kwargs["region"]
        state = kwargs["state"]
        emitted_regions.append(region.region_name)
        state.modifications.append(("structured", region.region_name))
        if region.region_name == "initial_region":
            return LinearizedFlowGraphStructuredRegionResult(
                accepted=True,
                unresolved_state_values=frozenset({0x2222}),
                transition_count=1,
                conditional_count=0,
            )
        return LinearizedFlowGraphStructuredRegionResult(
            accepted=True,
            transition_count=1,
            conditional_count=0,
        )

    result = execute_linearized_flow_graph_planning(
        _base_context(
            initial_state=0x1111,
            projectable=True,
            round_limit=2,
        ),
        callbacks=LinearizedFlowGraphPlanningCallbacks(
            build_round_summary=lambda current_flow_graph, dag_round_mba: LinearizedDagRoundSummary(
                dag="dag",
                semantic_reference_program=None,
                structured_regions=(region_a, region_b),
                plannable_edges=(),
                report_exit_handlers=frozenset(),
                report_exit_owned_blocks=frozenset(),
                terminal_source_keys=frozenset(),
                terminal_source_handlers=frozenset(),
                terminal_source_owned_blocks=frozenset(),
                terminal_protected_blocks=frozenset(),
                terminal_skipped=0,
                unknown_skipped=0,
            ),
            build_projected_mba=lambda flow_graph: flow_graph,
            project_flow_graph=lambda flow_graph, modifications: flow_graph,
            resolve_redirect_safe_target_entry=lambda dag, planned_edge, condition_chain_blocks: None,
            resolve_initial_entry=lambda dag, initial_state, condition_chain_blocks: None,
            emit_dag_redirect=lambda **kwargs: False,
            collect_residual_dispatcher_predecessors=lambda flow_graph, dispatcher_serial, condition_chain_blocks, reachable_from_serial: (),
            emit_structured_region=emit_structured_region,
            emit_residual_dispatcher_handoffs=lambda **kwargs: 0,
            disconnect_condition_chain_nodes=lambda condition_chain_blocks, dispatcher_serial, state: 0,
        ),
    )

    assert result.accepted
    assert emitted_regions == ["initial_region", "child_region"]
    assert result.transition_count == 2


def test_discover_structured_dag_regions_finds_sub7ffd_initial_region():
    dag = LinearizedStateDag(
        dispatcher_entry_serial=20,
        state_var_stkoff=0x7BC,
        pre_header_serial=78,
        initial_state=0x5D0AEBD3,
        condition_chain_blocks=(20,),
        nodes=(
            StateDagNode(
                key=StateDagNodeKey(handler_serial=78, state_const=0x5D0AEBD3),
                kind=StateNodeKind.EXACT,
                state_label="0x5D0AEBD3",
                handler_serial=78,
                entry_anchor=78,
                owned_blocks=(78,),
                exclusive_blocks=(78,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=StateDagNodeKey(handler_serial=14, state_const=0x606DC166),
                kind=StateNodeKind.EXACT,
                state_label="0x606DC166",
                handler_serial=14,
                entry_anchor=14,
                owned_blocks=(14,),
                exclusive_blocks=(14,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=StateDagNodeKey(handler_serial=136, state_const=0x139F2922),
                kind=StateNodeKind.EXACT,
                state_label="0x139F2922",
                handler_serial=136,
                entry_anchor=136,
                owned_blocks=(136,),
                exclusive_blocks=(136,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=StateDagNodeKey(handler_serial=143, state_const=0x63F502FA),
                kind=StateNodeKind.EXACT,
                state_label="0x63F502FA",
                handler_serial=143,
                entry_anchor=143,
                owned_blocks=(143,),
                exclusive_blocks=(143,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=StateDagNodeKey(handler_serial=150, state_const=0x2A5E29F6),
                kind=StateNodeKind.EXACT,
                state_label="0x2A5E29F6",
                handler_serial=150,
                entry_anchor=150,
                owned_blocks=(150,),
                exclusive_blocks=(150,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=StateDagNodeKey(handler_serial=78, state_const=0x5D0AEBD3),
                target_key=StateDagNodeKey(handler_serial=14, state_const=0x606DC166),
                target_state=0x606DC166,
                target_entry_anchor=14,
                target_label="0x606DC166",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=78,
                ),
                ordered_path=(78,),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=StateDagNodeKey(handler_serial=14, state_const=0x606DC166),
                target_key=StateDagNodeKey(handler_serial=136, state_const=0x139F2922),
                target_state=0x139F2922,
                target_entry_anchor=136,
                target_label="0x139F2922",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=14,
                ),
                ordered_path=(14,),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=StateDagNodeKey(handler_serial=136, state_const=0x139F2922),
                target_key=StateDagNodeKey(handler_serial=143, state_const=0x63F502FA),
                target_state=0x63F502FA,
                target_entry_anchor=143,
                target_label="0x63F502FA",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=136,
                ),
                ordered_path=(136, 137, 139, 140),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=StateDagNodeKey(handler_serial=143, state_const=0x63F502FA),
                target_key=StateDagNodeKey(handler_serial=150, state_const=0x2A5E29F6),
                target_state=0x2A5E29F6,
                target_entry_anchor=150,
                target_label="0x2A5E29F6",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=143,
                ),
                ordered_path=(143,),
            ),
        ),
        diagnostics=(),
    )
    program = RenderedProgramSnapshot(
        variant_name="semantic_reference_like",
        order_strategy="semantic",
        program_strategy="local_boundary_selective",
        label_render_mode="state_family",
        boundary_inline_mode="inline_single_level",
        comment_mode="minimal",
        nodes=tuple(
            RenderedProgramNode(
                node_index=index,
                label_text=label,
                node_kind="state",
                line_start=index * 2 + 1,
                line_end=index * 2 + 2,
            )
            for index, label in enumerate(
                (
                    "STATE_5D0AEBD3",
                    "STATE_606DC166",
                    "STATE_139F2922",
                )
            )
        ),
        lines=(
            RenderedProgramLine(1, "STATE_5D0AEBD3:", 0, 0, "label"),
        ),
    )

    regions = discover_structured_dag_regions(
        dag,
        semantic_reference_program=program,
    )

    assert regions == (
        ResolvedDagStructuredRegion(
            region_name="sub7ffd_initial_semantic_region",
            entry_state=0x5D0AEBD3,
            state_values=(
                0x5D0AEBD3,
                0x606DC166,
                0x139F2922,
            ),
            state_labels=(
                "STATE_5D0AEBD3",
                "STATE_606DC166",
                "STATE_139F2922",
            ),
            internal_state_edges=(
                (0x5D0AEBD3, 0x606DC166),
                (0x606DC166, 0x139F2922),
            ),
            exit_state_values=(0x16F7FF74, 0x2315233C, 0x63F502FA, 0x1031EAF4),
        ),
    )


def test_execute_planning_revisits_structured_regions_after_residual_handoffs():
    region_a = LinearizedDagStructuredRegion(
        region_name="initial_region",
        entry_state=0x1111,
        state_values=(0x1111,),
        state_labels=("STATE_00001111",),
        internal_state_edges=(),
        exit_state_values=(0x2222,),
    )
    region_b = LinearizedDagStructuredRegion(
        region_name="child_region",
        entry_state=0x2222,
        state_values=(0x2222,),
        state_labels=("STATE_00002222",),
        internal_state_edges=(),
        exit_state_values=(),
    )
    emitted_regions: list[str] = []
    accepted_regions: set[str] = set()
    summary_calls = {"count": 0}
    residual_calls = {"count": 0}

    def build_round_summary(current_flow_graph, dag_round_mba):
        summary_calls["count"] += 1
        regions = (region_a,) if summary_calls["count"] == 1 else (region_a, region_b)
        return LinearizedDagRoundSummary(
            dag="dag",
            semantic_reference_program=None,
            structured_regions=regions,
            plannable_edges=(),
            report_exit_handlers=frozenset(),
            report_exit_owned_blocks=frozenset(),
            terminal_source_keys=frozenset(),
            terminal_source_handlers=frozenset(),
            terminal_source_owned_blocks=frozenset(),
            terminal_protected_blocks=frozenset(),
            terminal_skipped=0,
            unknown_skipped=0,
        )

    def emit_structured_region(*, region, dag, flow_graph, semantic_reference_program, structured_regions, state):
        if region.region_name in accepted_regions:
            return LinearizedFlowGraphStructuredRegionResult(accepted=False)
        accepted_regions.add(region.region_name)
        emitted_regions.append(region.region_name)
        state.modifications.append(("structured", region.region_name))
        return LinearizedFlowGraphStructuredRegionResult(
            accepted=True,
            successor_state_values=frozenset(getattr(region, "exit_state_values", ())),
            transition_count=1,
            conditional_count=0,
        )

    def emit_residual_dispatcher_handoffs(**kwargs):
        if residual_calls["count"] > 0:
            return 0
        residual_calls["count"] += 1
        kwargs["state"].modifications.append(("residual", 99))
        return 1

    result = execute_linearized_flow_graph_planning(
        _base_context(
            initial_state=0x1111,
            projectable=True,
            round_limit=1,
        ),
        callbacks=LinearizedFlowGraphPlanningCallbacks(
            build_round_summary=build_round_summary,
            build_projected_mba=lambda flow_graph: flow_graph,
            project_flow_graph=lambda flow_graph, modifications: flow_graph,
            resolve_redirect_safe_target_entry=lambda dag, planned_edge, condition_chain_blocks: None,
            resolve_initial_entry=lambda dag, initial_state, condition_chain_blocks: None,
            emit_dag_redirect=lambda **kwargs: False,
            collect_residual_dispatcher_predecessors=lambda flow_graph, dispatcher_serial, condition_chain_blocks, reachable_from_serial: (99,) if residual_calls["count"] == 0 else (),
            emit_structured_region=emit_structured_region,
            emit_residual_dispatcher_handoffs=emit_residual_dispatcher_handoffs,
            disconnect_condition_chain_nodes=lambda condition_chain_blocks, dispatcher_serial, state: 0,
        ),
    )

    assert result.accepted
    assert emitted_regions == ["initial_region", "child_region"]
    assert result.transition_count == 2


def test_execute_planning_revisits_structured_regions_until_new_child_region_is_discovered():
    region_a = LinearizedDagStructuredRegion(
        region_name="initial_region",
        entry_state=0x1111,
        state_values=(0x1111,),
        state_labels=("STATE_00001111",),
        internal_state_edges=(),
        exit_state_values=(0x2222,),
    )
    region_b = LinearizedDagStructuredRegion(
        region_name="child_region",
        entry_state=0x2222,
        state_values=(0x2222,),
        state_labels=("STATE_00002222",),
        internal_state_edges=(),
        exit_state_values=(0x3333,),
    )
    region_c = LinearizedDagStructuredRegion(
        region_name="grandchild_region",
        entry_state=0x3333,
        state_values=(0x3333,),
        state_labels=("STATE_00003333",),
        internal_state_edges=(),
        exit_state_values=(),
    )
    emitted_regions: list[str] = []
    accepted_regions: set[str] = set()
    summary_calls = {"count": 0}
    residual_calls = {"count": 0}

    def build_round_summary(current_flow_graph, dag_round_mba):
        summary_calls["count"] += 1
        if summary_calls["count"] == 1:
            regions = (region_a,)
        elif summary_calls["count"] == 2:
            regions = (region_a, region_b)
        else:
            regions = (region_a, region_b, region_c)
        return LinearizedDagRoundSummary(
            dag="dag",
            semantic_reference_program=None,
            structured_regions=regions,
            plannable_edges=(),
            report_exit_handlers=frozenset(),
            report_exit_owned_blocks=frozenset(),
            terminal_source_keys=frozenset(),
            terminal_source_handlers=frozenset(),
            terminal_source_owned_blocks=frozenset(),
            terminal_protected_blocks=frozenset(),
            terminal_skipped=0,
            unknown_skipped=0,
        )

    def emit_structured_region(*, region, dag, flow_graph, semantic_reference_program, structured_regions, state):
        if region.region_name in accepted_regions:
            return LinearizedFlowGraphStructuredRegionResult(accepted=False)
        accepted_regions.add(region.region_name)
        emitted_regions.append(region.region_name)
        state.modifications.append(("structured", region.region_name))
        successor_states = frozenset(getattr(region, "exit_state_values", ()))
        return LinearizedFlowGraphStructuredRegionResult(
            accepted=True,
            successor_state_values=successor_states,
            transition_count=1,
            conditional_count=0,
        )

    def emit_residual_dispatcher_handoffs(**kwargs):
        if residual_calls["count"] > 0:
            return 0
        residual_calls["count"] += 1
        kwargs["state"].modifications.append(("residual", 99))
        return 1

    result = execute_linearized_flow_graph_planning(
        _base_context(
            initial_state=0x1111,
            projectable=True,
            round_limit=1,
        ),
        callbacks=LinearizedFlowGraphPlanningCallbacks(
            build_round_summary=build_round_summary,
            build_projected_mba=lambda flow_graph: flow_graph,
            project_flow_graph=lambda flow_graph, modifications: flow_graph,
            resolve_redirect_safe_target_entry=lambda dag, planned_edge, condition_chain_blocks: None,
            resolve_initial_entry=lambda dag, initial_state, condition_chain_blocks: None,
            emit_dag_redirect=lambda **kwargs: False,
            collect_residual_dispatcher_predecessors=lambda flow_graph, dispatcher_serial, condition_chain_blocks, reachable_from_serial: (99,) if residual_calls["count"] == 0 else (),
            emit_structured_region=emit_structured_region,
            emit_residual_dispatcher_handoffs=emit_residual_dispatcher_handoffs,
            disconnect_condition_chain_nodes=lambda condition_chain_blocks, dispatcher_serial, state: 0,
        ),
    )

    assert result.accepted
    assert emitted_regions == ["initial_region", "child_region", "grandchild_region"]
    assert result.transition_count == 3
    assert summary_calls["count"] >= 3


def test_execute_planning_revisits_structured_regions_before_raw_dag_phase_when_children_are_pending():
    region_a = LinearizedDagStructuredRegion(
        region_name="initial_region",
        entry_state=0x1111,
        state_values=(0x1111,),
        state_labels=("STATE_00001111",),
        internal_state_edges=(),
        exit_state_values=(0x2222,),
    )
    region_b = LinearizedDagStructuredRegion(
        region_name="child_region",
        entry_state=0x2222,
        state_values=(0x2222,),
        state_labels=("STATE_00002222",),
        internal_state_edges=(),
        exit_state_values=(),
    )
    emitted_regions: list[str] = []
    accepted_regions: set[str] = set()
    summary_calls = {"count": 0}

    def build_round_summary(current_flow_graph, dag_round_mba):
        summary_calls["count"] += 1
        return LinearizedDagRoundSummary(
            dag="dag",
            semantic_reference_program=None,
            structured_regions=(region_a, region_b),
            plannable_edges=(),
            report_exit_handlers=frozenset(),
            report_exit_owned_blocks=frozenset(),
            terminal_source_keys=frozenset(),
            terminal_source_handlers=frozenset(),
            terminal_source_owned_blocks=frozenset(),
            terminal_protected_blocks=frozenset(),
            terminal_skipped=0,
            unknown_skipped=0,
        )

    def emit_structured_region(*, region, dag, flow_graph, semantic_reference_program, structured_regions, state):
        if region.region_name in accepted_regions:
            return LinearizedFlowGraphStructuredRegionResult(accepted=False)
        accepted_regions.add(region.region_name)
        emitted_regions.append(region.region_name)
        state.modifications.append(("structured", region.region_name))
        return LinearizedFlowGraphStructuredRegionResult(
            accepted=True,
            successor_state_values=frozenset(getattr(region, "exit_state_values", ())),
            transition_count=1,
            conditional_count=0,
        )

    result = execute_linearized_flow_graph_planning(
        _base_context(
            initial_state=0x1111,
            projectable=True,
            round_limit=1,
        ),
        callbacks=LinearizedFlowGraphPlanningCallbacks(
            build_round_summary=build_round_summary,
            build_projected_mba=lambda flow_graph: flow_graph,
            project_flow_graph=lambda flow_graph, modifications: flow_graph,
            resolve_redirect_safe_target_entry=lambda dag, planned_edge, condition_chain_blocks: None,
            resolve_initial_entry=lambda dag, initial_state, condition_chain_blocks: None,
            emit_dag_redirect=lambda **kwargs: False,
            collect_residual_dispatcher_predecessors=lambda flow_graph, dispatcher_serial, condition_chain_blocks, reachable_from_serial: (),
            emit_structured_region=emit_structured_region,
            emit_residual_dispatcher_handoffs=lambda **kwargs: 0,
            disconnect_condition_chain_nodes=lambda condition_chain_blocks, dispatcher_serial, state: 0,
        ),
    )

    assert result.accepted
    assert emitted_regions == ["initial_region", "child_region"]
    assert result.transition_count == 2
    assert summary_calls["count"] >= 2


def test_execute_planning_revisits_partially_lowered_region_after_residual_handoff():
    region_a = LinearizedDagStructuredRegion(
        region_name="initial_region",
        entry_state=0x1111,
        state_values=(0x1111,),
        state_labels=("STATE_00001111",),
        internal_state_edges=(),
        exit_state_values=(0x2222,),
    )
    region_b = LinearizedDagStructuredRegion(
        region_name="child_region",
        entry_state=0x2222,
        state_values=(0x2222,),
        state_labels=("STATE_00002222",),
        internal_state_edges=(),
        exit_state_values=(),
    )
    emitted_regions: list[str] = []
    region_attempts = {"initial_region": 0, "child_region": 0}
    summary_calls = {"count": 0}
    residual_calls = {"count": 0}

    def build_round_summary(current_flow_graph, dag_round_mba):
        summary_calls["count"] += 1
        return LinearizedDagRoundSummary(
            dag="dag",
            semantic_reference_program=None,
            structured_regions=(region_a, region_b),
            plannable_edges=(),
            report_exit_handlers=frozenset(),
            report_exit_owned_blocks=frozenset(),
            terminal_source_keys=frozenset(),
            terminal_source_handlers=frozenset(),
            terminal_source_owned_blocks=frozenset(),
            terminal_protected_blocks=frozenset(),
            terminal_skipped=0,
            unknown_skipped=0,
        )

    def emit_structured_region(*, region, dag, flow_graph, semantic_reference_program, structured_regions, state):
        region_attempts[region.region_name] += 1
        emitted_regions.append(region.region_name)
        state.modifications.append(("structured", region.region_name, region_attempts[region.region_name]))
        if region.region_name == "initial_region" and region_attempts[region.region_name] == 1:
            return LinearizedFlowGraphStructuredRegionResult(
                accepted=True,
                unresolved_state_values=frozenset({0x1111}),
                transition_count=1,
                conditional_count=0,
            )
        if region.region_name == "initial_region":
            return LinearizedFlowGraphStructuredRegionResult(
                accepted=True,
                successor_state_values=frozenset({0x2222}),
                transition_count=1,
                conditional_count=0,
            )
        return LinearizedFlowGraphStructuredRegionResult(
            accepted=True,
            transition_count=1,
            conditional_count=0,
        )

    def emit_residual_dispatcher_handoffs(**kwargs):
        if residual_calls["count"] > 0:
            return 0
        residual_calls["count"] += 1
        kwargs["state"].modifications.append(("residual", 99))
        return 1

    result = execute_linearized_flow_graph_planning(
        _base_context(
            initial_state=0x1111,
            projectable=True,
            round_limit=1,
        ),
        callbacks=LinearizedFlowGraphPlanningCallbacks(
            build_round_summary=build_round_summary,
            build_projected_mba=lambda flow_graph: flow_graph,
            project_flow_graph=lambda flow_graph, modifications: flow_graph,
            resolve_redirect_safe_target_entry=lambda dag, planned_edge, condition_chain_blocks: None,
            resolve_initial_entry=lambda dag, initial_state, condition_chain_blocks: None,
            emit_dag_redirect=lambda **kwargs: False,
            collect_residual_dispatcher_predecessors=lambda flow_graph, dispatcher_serial, condition_chain_blocks, reachable_from_serial: (99,) if residual_calls["count"] == 0 else (),
            emit_structured_region=emit_structured_region,
            emit_residual_dispatcher_handoffs=emit_residual_dispatcher_handoffs,
            disconnect_condition_chain_nodes=lambda condition_chain_blocks, dispatcher_serial, state: 0,
        ),
    )

    assert result.accepted
    assert emitted_regions == ["initial_region", "initial_region", "child_region"]
    assert region_attempts["initial_region"] == 2
    assert result.transition_count == 3


def test_prepare_plan_setup_uses_three_rounds_for_first_pass_projectable_flow():
    snapshot = SimpleNamespace(lfg_redirected_blocks=())
    range_evidence = SimpleNamespace(
        dispatcher=None,
        pre_header_serial=None,
    )
    flow_graph = _FakeFlowGraph(
        {
            1: SimpleNamespace(succs=(2,)),
            2: SimpleNamespace(succs=()),
        }
    )

    setup = prepare_linearized_flow_graph_plan_setup(
        snapshot=snapshot,
        state_machine=_FakeStateMachine(),
        range_evidence=range_evidence,
        flow_graph=flow_graph,
        same_maturity_rerun=False,
        build_builder=lambda snapshot: _FakeBuilder(),
        resolve_state_var_stkoff=lambda snapshot, state_machine: None,
        supports_projected_replanning=lambda flow_graph: True,
        label_block=lambda serial: f"blk[{serial}]",
        transition_result=object(),
    )

    assert setup.round_limit == 3
