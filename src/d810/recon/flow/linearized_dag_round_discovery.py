from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Callable

from d810.recon.flow.dag_redirect_discovery import select_plannable_dag_edges
from d810.recon.flow.linearized_state_dag import (
    SemanticEdgeKind,
    build_live_linearized_state_dag_from_graph,
)
from d810.recon.flow.transition_report import (
    TransitionKind,
    build_dispatcher_transition_report_from_graph,
)


@dataclass(frozen=True, slots=True)
class ResolvedDagPlannableEdge:
    """Pure discovery summary for one DAG edge that may be planned."""

    edge: object
    source_anchor_block: int
    ordered_path: tuple[int, ...]
    target_entry_anchor: int | None
    is_conditional_transition: bool
    requires_safe_target_resolution: bool


@dataclass(frozen=True, slots=True)
class ResolvedDagRoundSummary:
    """Discovery summary for one projected DAG round."""

    dag: object
    plannable_edges: tuple[ResolvedDagPlannableEdge, ...]
    report_exit_handlers: frozenset[int]
    report_exit_owned_blocks: frozenset[int]
    terminal_source_keys: frozenset[object]
    terminal_source_handlers: frozenset[int]
    terminal_source_owned_blocks: frozenset[int]
    terminal_protected_blocks: frozenset[int]
    terminal_skipped: int
    unknown_skipped: int


def build_linearized_dag_round_summary(
    *,
    current_flow_graph: object,
    transition_result: object,
    dispatcher_serial: int,
    state_var_stkoff: int | None,
    pre_header_serial: int | None,
    initial_state: int | None,
    handler_range_map: dict | None,
    bst_node_blocks: tuple[int, ...],
    diagnostics: tuple[object, ...],
    dispatcher: object | None,
    mba: object | None,
    handlers: dict,
    build_live_dag: Callable[..., object] | None = None,
    build_transition_report: Callable[..., object] | None = None,
    select_plannable_edges: Callable[[object], tuple[object, ...]] | None = None,
) -> ResolvedDagRoundSummary:
    """Build all DAG/report facts needed by the cfg main-plan contract."""

    if build_live_dag is None:
        build_live_dag = build_live_linearized_state_dag_from_graph
    if build_transition_report is None:
        build_transition_report = build_dispatcher_transition_report_from_graph
    if select_plannable_edges is None:
        select_plannable_edges = select_plannable_dag_edges

    dag = build_live_dag(
        current_flow_graph,
        transition_result,
        dispatcher_entry_serial=dispatcher_serial,
        state_var_stkoff=state_var_stkoff,
        pre_header_serial=pre_header_serial,
        initial_state=initial_state,
        handler_range_map=handler_range_map or {},
        bst_node_blocks=tuple(sorted(int(block) for block in bst_node_blocks)),
        diagnostics=tuple(diagnostics or ()),
        dispatcher=dispatcher,
        mba=mba,
        prefer_local_corridors=True,
    )
    dag_report = build_transition_report(
        current_flow_graph,
        transition_result,
        dispatcher_entry_serial=dispatcher_serial,
        state_var_stkoff=state_var_stkoff,
        pre_header_serial=pre_header_serial,
        initial_state=initial_state,
        handler_range_map=handler_range_map or {},
        bst_node_blocks=tuple(sorted(int(block) for block in bst_node_blocks)),
        diagnostics=tuple(diagnostics or ()),
    )
    report_exit_handlers = {
        row.handler_serial
        for row in dag_report.rows
        if row.kind == TransitionKind.EXIT
    }
    nonterminal_source_handlers = {
        edge.source_key.handler_serial
        for edge in dag.edges
        if edge.kind
        in (
            SemanticEdgeKind.TRANSITION,
            SemanticEdgeKind.CONDITIONAL_TRANSITION,
        )
    }
    report_exit_handlers -= nonterminal_source_handlers
    report_exit_owned_blocks = {
        block_serial
        for handler in handlers.values()
        if handler.check_block in report_exit_handlers
        for block_serial in {handler.check_block, *handler.handler_blocks}
    }
    terminal_source_keys = {
        edge.source_key
        for edge in dag.edges
        if edge.kind
        in (
            SemanticEdgeKind.CONDITIONAL_RETURN,
            SemanticEdgeKind.EXIT_ROUTINE,
            SemanticEdgeKind.UNKNOWN,
        )
    }
    terminal_source_handlers = {
        edge.source_key.handler_serial
        for edge in dag.edges
        if edge.kind
        in (
            SemanticEdgeKind.CONDITIONAL_RETURN,
            SemanticEdgeKind.EXIT_ROUTINE,
            SemanticEdgeKind.UNKNOWN,
        )
    }
    terminal_source_owned_blocks = {
        block_serial
        for node in dag.nodes
        if node.handler_serial in terminal_source_handlers
        for block_serial in node.owned_blocks
    }
    terminal_protected_blocks = {
        block_serial
        for edge in dag.edges
        if edge.kind
        in (
            SemanticEdgeKind.CONDITIONAL_RETURN,
            SemanticEdgeKind.EXIT_ROUTINE,
            SemanticEdgeKind.UNKNOWN,
        )
        for block_serial in edge.ordered_path
    }
    terminal_skipped = sum(
        1
        for edge in dag.edges
        if edge.kind
        in (SemanticEdgeKind.CONDITIONAL_RETURN, SemanticEdgeKind.EXIT_ROUTINE)
    )
    unknown_skipped = sum(
        1 for edge in dag.edges if edge.kind == SemanticEdgeKind.UNKNOWN
    )
    plannable_edges = tuple(
        ResolvedDagPlannableEdge(
            edge=edge,
            source_anchor_block=int(edge.source_anchor.block_serial),
            ordered_path=tuple(int(node) for node in edge.ordered_path),
            target_entry_anchor=(
                int(edge.target_entry_anchor)
                if edge.target_entry_anchor is not None
                else None
            ),
            is_conditional_transition=(
                edge.kind == SemanticEdgeKind.CONDITIONAL_TRANSITION
            ),
            requires_safe_target_resolution=edge.target_entry_anchor is not None,
        )
        for edge in select_plannable_edges(dag)
    )
    return ResolvedDagRoundSummary(
        dag=dag,
        plannable_edges=plannable_edges,
        report_exit_handlers=frozenset(int(handler) for handler in report_exit_handlers),
        report_exit_owned_blocks=frozenset(
            int(block) for block in report_exit_owned_blocks
        ),
        terminal_source_keys=frozenset(terminal_source_keys),
        terminal_source_handlers=frozenset(
            int(handler) for handler in terminal_source_handlers
        ),
        terminal_source_owned_blocks=frozenset(
            int(block) for block in terminal_source_owned_blocks
        ),
        terminal_protected_blocks=frozenset(
            int(block) for block in terminal_protected_blocks
        ),
        terminal_skipped=int(terminal_skipped),
        unknown_skipped=int(unknown_skipped),
    )


__all__ = [
    "ResolvedDagPlannableEdge",
    "ResolvedDagRoundSummary",
    "build_linearized_dag_round_summary",
]
