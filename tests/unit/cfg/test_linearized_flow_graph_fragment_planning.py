from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.linearized_flow_graph_fragment_planning import (
    LinearizedDagPlannableEdge,
    LinearizedDagRoundSummary,
    LinearizedFlowGraphPlanningCallbacks,
    LinearizedFlowGraphPlanningContext,
    execute_linearized_flow_graph_planning,
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


def _base_context(**overrides):
    base = dict(
        flow_graph=object(),
        builder=_FakeBuilder(),
        mba=None,
        state_machine=_FakeStateMachine(),
        dispatcher_serial=2,
        bst_node_blocks=frozenset({2}),
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
                resolve_redirect_safe_target_entry=lambda dag, planned_edge, bst_blocks: None,
                resolve_initial_entry=lambda dag, initial_state, bst_blocks: 11,
                emit_dag_redirect=emit_dag_redirect,
                collect_residual_dispatcher_predecessors=lambda flow_graph, dispatcher_serial, bst_blocks, reachable_from_serial: (),
                emit_residual_dispatcher_handoffs=lambda **kwargs: 0,
                disconnect_bst_comparison_nodes=lambda bst_blocks, dispatcher_serial, state: 2,
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
                resolve_redirect_safe_target_entry=lambda dag, planned_edge, bst_blocks: None,
                resolve_initial_entry=lambda dag, initial_state, bst_blocks: None,
                emit_dag_redirect=lambda **kwargs: False,
                collect_residual_dispatcher_predecessors=lambda flow_graph, dispatcher_serial, bst_blocks, reachable_from_serial: (),
                emit_residual_dispatcher_handoffs=lambda **kwargs: 0,
                disconnect_bst_comparison_nodes=lambda bst_blocks, dispatcher_serial, state: 0,
            ),
        )

        assert not result.accepted
        assert result.modifications == ()
        assert result.unresolved_bst_targets == 1
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

        def collect_residual(flow_graph, dispatcher_serial, bst_blocks, reachable_from_serial):
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
                resolve_redirect_safe_target_entry=lambda dag, planned_edge, bst_blocks: None,
                resolve_initial_entry=lambda dag, initial_state, bst_blocks: None,
                emit_dag_redirect=emit_dag_redirect,
                collect_residual_dispatcher_predecessors=collect_residual,
                emit_residual_dispatcher_handoffs=lambda **kwargs: 1,
                disconnect_bst_comparison_nodes=lambda bst_blocks, dispatcher_serial, state: disconnect_calls.append(1) or 7,
            ),
        )

        assert result.accepted
        assert result.cleanup_gate_reason == "residual_dispatcher_predecessors"
        assert result.residual_dispatcher_preds == (21,)
        assert result.residual_dispatcher_redirect_count == 1
        assert result.disconnect_count == 0
        assert disconnect_calls == []
