from __future__ import annotations

from dataclasses import dataclass

from d810.core import logging
from d810.core.typing import Callable

logger = logging.getLogger(
    "D810.cfg.linearized_flow_graph_fragment_planning",
    logging.DEBUG,
)


@dataclass(frozen=True, slots=True)
class LinearizedDagPlannableEdge:
    """Opaque DAG edge plus cfg-owned metadata for orchestration."""

    edge: object
    source_anchor_block: int
    ordered_path: tuple[int, ...]
    target_entry_anchor: int | None
    is_conditional_transition: bool
    requires_safe_target_resolution: bool


@dataclass(frozen=True, slots=True)
class LinearizedDagRoundSummary:
    """Discovery summary for one projected DAG-planning round."""

    dag: object
    plannable_edges: tuple[LinearizedDagPlannableEdge, ...]
    report_exit_handlers: frozenset[int]
    report_exit_owned_blocks: frozenset[int]
    terminal_source_keys: frozenset[object]
    terminal_source_handlers: frozenset[int]
    terminal_source_owned_blocks: frozenset[int]
    terminal_protected_blocks: frozenset[int]
    terminal_skipped: int
    unknown_skipped: int


@dataclass(frozen=True, slots=True)
class LinearizedFlowGraphPlanningContext:
    """Structured request for main LFG fragment planning."""

    flow_graph: object
    builder: object
    mba: object | None
    state_machine: object
    dispatcher_serial: int
    bst_node_blocks: frozenset[int]
    dispatcher_region: frozenset[int]
    state_var_stkoff: int | None
    dispatcher_lookup: object | None
    dispatcher: object | None
    pre_header_serial: int | None
    original_blocks: frozenset[int]
    same_maturity_rerun: bool
    projectable: bool
    round_limit: int
    initial_state: int | None
    blocked_sources: frozenset[int]


@dataclass(frozen=True, slots=True)
class LinearizedFlowGraphPlanningCallbacks:
    """LFG-owned callbacks injected into cfg orchestration."""

    build_round_summary: Callable[[object, object | None], LinearizedDagRoundSummary]
    build_projected_mba: Callable[[object], object]
    project_flow_graph: Callable[[object, list], object]
    resolve_redirect_safe_target_entry: Callable[[object, object, frozenset[int]], int | None]
    resolve_initial_entry: Callable[[object, int, frozenset[int]], int | None]
    emit_dag_redirect: Callable[..., bool]
    collect_residual_dispatcher_predecessors: Callable[
        [object, int, frozenset[int], int | None],
        tuple[int, ...],
    ]
    emit_residual_dispatcher_handoffs: Callable[..., int]
    disconnect_bst_comparison_nodes: Callable[..., int]


@dataclass(slots=True)
class LinearizedFlowGraphPlanningState:
    """Mutable planner state carried across projected rounds."""

    modifications: list
    owned_blocks: set[int]
    owned_edges: set[tuple[int, int]]
    owned_transitions: set[tuple[int, int]]
    emitted: set[tuple[int, int]]
    claimed_1way: dict[int, int]
    claimed_2way: dict[tuple[int, int], int]
    claimed_exits: dict[int, int]
    claimed_path_edges: dict[tuple[int, int], int]
    blocked_sources: set[int]


@dataclass(frozen=True, slots=True)
class LinearizedFlowGraphPlanningResult:
    """Main LFG fragment plan result returned back to Hodur."""

    accepted: bool
    modifications: tuple[object, ...]
    owned_blocks: frozenset[int]
    owned_edges: frozenset[tuple[int, int]]
    owned_transitions: frozenset[tuple[int, int]]
    transition_count: int
    conditional_count: int
    terminal_skipped: int
    unknown_skipped: int
    skipped_count: int
    disconnect_count: int
    cleanup_gate_reason: str | None
    residual_dispatcher_preds: tuple[int, ...]
    residual_dispatcher_redirect_count: int
    residual_dispatcher_normalized_count: int
    dead_island_cleanup_count: int
    unresolved_bst_targets: int

def execute_linearized_flow_graph_planning(
    context: LinearizedFlowGraphPlanningContext,
    *,
    callbacks: LinearizedFlowGraphPlanningCallbacks,
) -> LinearizedFlowGraphPlanningResult:
    """Execute the main projected DAG planning loop for LFG."""

    state = LinearizedFlowGraphPlanningState(
        modifications=[],
        owned_blocks=set(),
        owned_edges=set(),
        owned_transitions=set(),
        emitted=set(),
        claimed_1way={},
        claimed_2way={},
        claimed_exits={},
        claimed_path_edges={},
        blocked_sources=set(int(serial) for serial in context.blocked_sources),
    )
    if state.blocked_sources:
        logger.info(
            "LFG DAG: starting with %d externally-claimed source blocks",
            len(state.blocked_sources),
        )

    current_flow_graph = context.flow_graph
    latest_summary: LinearizedDagRoundSummary | None = None
    transition_count = 0
    conditional_count = 0
    terminal_skipped = 0
    unknown_skipped = 0
    skipped_count = 0
    unresolved_bst_targets = 0

    for round_index in range(max(int(context.round_limit), 1)):
        round_mba = (
            context.mba
            if round_index == 0 or not context.projectable
            else callbacks.build_projected_mba(current_flow_graph)
        )
        latest_summary = callbacks.build_round_summary(current_flow_graph, round_mba)
        terminal_skipped = int(latest_summary.terminal_skipped)
        unknown_skipped = int(latest_summary.unknown_skipped)

        round_unresolved_bst_targets = 0
        round_start = len(state.modifications)
        if not context.same_maturity_rerun:
            for plannable_edge in latest_summary.plannable_edges:
                safe_target_entry = None
                if plannable_edge.requires_safe_target_resolution:
                    safe_target_entry = callbacks.resolve_redirect_safe_target_entry(
                        latest_summary.dag,
                        plannable_edge.edge,
                        context.bst_node_blocks,
                    )
                    if safe_target_entry is None:
                        round_unresolved_bst_targets += 1
                if plannable_edge.source_anchor_block not in context.original_blocks:
                    continue
                if any(
                    block_serial not in context.original_blocks
                    for block_serial in plannable_edge.ordered_path
                ):
                    continue
                if (
                    safe_target_entry is not None
                    and safe_target_entry not in context.original_blocks
                ):
                    continue
                accepted = callbacks.emit_dag_redirect(
                    edge=plannable_edge.edge,
                    dag=latest_summary.dag,
                    flow_graph=current_flow_graph,
                    state=state,
                    report_exit_handlers=latest_summary.report_exit_handlers,
                    report_exit_owned_blocks=latest_summary.report_exit_owned_blocks,
                    terminal_source_keys=latest_summary.terminal_source_keys,
                    terminal_source_handlers=latest_summary.terminal_source_handlers,
                    terminal_source_owned_blocks=latest_summary.terminal_source_owned_blocks,
                    terminal_protected_blocks=latest_summary.terminal_protected_blocks,
                )
                if accepted:
                    if plannable_edge.is_conditional_transition:
                        conditional_count += 1
                    else:
                        transition_count += 1
                else:
                    skipped_count += 1

        initial_entry = (
            callbacks.resolve_initial_entry(
                latest_summary.dag,
                int(context.initial_state),
                context.bst_node_blocks,
            )
            if context.initial_state is not None
            else None
        )
        if (
            context.pre_header_serial is not None
            and initial_entry is not None
            and context.pre_header_serial in context.original_blocks
            and initial_entry in context.original_blocks
            and context.pre_header_serial not in state.claimed_1way
        ):
            state.modifications.append(
                context.builder.goto_redirect(
                    source_block=int(context.pre_header_serial),
                    target_block=int(initial_entry),
                )
            )
            state.owned_blocks.add(int(context.pre_header_serial))
            state.owned_edges.add((int(context.pre_header_serial), int(initial_entry)))
            state.claimed_1way[int(context.pre_header_serial)] = int(initial_entry)
            transition_count += 1

        unresolved_bst_targets = round_unresolved_bst_targets
        round_added = len(state.modifications) - round_start
        if round_added <= 0:
            break
        if not context.projectable or round_index + 1 >= context.round_limit:
            break
        try:
            current_flow_graph = callbacks.project_flow_graph(
                context.flow_graph,
                state.modifications,
            )
            logger.info(
                "LFG DAG: projected planning round %d -> %d blocks",
                round_index + 1,
                len(getattr(current_flow_graph, "blocks", {})),
            )
        except Exception:
            logger.warning(
                "LFG DAG: projected replanning failed after round %d",
                round_index + 1,
                exc_info=True,
            )
            break

    if not state.modifications or latest_summary is None:
        return LinearizedFlowGraphPlanningResult(
            accepted=False,
            modifications=(),
            owned_blocks=frozenset(),
            owned_edges=frozenset(),
            owned_transitions=frozenset(),
            transition_count=0,
            conditional_count=0,
            terminal_skipped=terminal_skipped,
            unknown_skipped=unknown_skipped,
            skipped_count=skipped_count,
            disconnect_count=0,
            cleanup_gate_reason=None,
            residual_dispatcher_preds=(),
            residual_dispatcher_redirect_count=0,
            residual_dispatcher_normalized_count=0,
            dead_island_cleanup_count=0,
            unresolved_bst_targets=unresolved_bst_targets,
        )

    cleanup_gate_reason: str | None = None
    residual_dispatcher_preds: tuple[int, ...] = ()
    residual_dispatcher_redirect_count = 0
    residual_dispatcher_normalized_count = 0
    normalizable_redirect_blocks: set[int] = set()

    if context.projectable and state.modifications:
        try:
            final_flow_graph = callbacks.project_flow_graph(
                context.flow_graph,
                state.modifications,
            )
        except Exception:
            final_flow_graph = current_flow_graph
    else:
        final_flow_graph = current_flow_graph

    if final_flow_graph is not None:
        residual_dispatcher_preds = callbacks.collect_residual_dispatcher_predecessors(
            final_flow_graph,
            int(context.dispatcher_serial),
            context.bst_node_blocks,
            getattr(final_flow_graph, "entry_serial", None),
        )
        if residual_dispatcher_preds:
            residual_dispatcher_redirect_count = callbacks.emit_residual_dispatcher_handoffs(
                dag=latest_summary.dag,
                projected_flow_graph=final_flow_graph,
                state=state,
                redirected_blocks=normalizable_redirect_blocks,
            )
            if residual_dispatcher_redirect_count:
                final_flow_graph = callbacks.project_flow_graph(
                    context.flow_graph,
                    state.modifications,
                )
            residual_dispatcher_preds = callbacks.collect_residual_dispatcher_predecessors(
                final_flow_graph,
                int(context.dispatcher_serial),
                context.bst_node_blocks,
                getattr(final_flow_graph, "entry_serial", None),
            )
            if residual_dispatcher_preds:
                cleanup_gate_reason = "residual_dispatcher_predecessors"

    if unresolved_bst_targets or cleanup_gate_reason is not None:
        disconnect_count = 0
        if unresolved_bst_targets and cleanup_gate_reason is None:
            cleanup_gate_reason = "unresolved_bst_targets"
    else:
        disconnect_count = callbacks.disconnect_bst_comparison_nodes(
            context.bst_node_blocks,
            int(context.dispatcher_serial),
            state=state,
        )

    return LinearizedFlowGraphPlanningResult(
        accepted=True,
        modifications=tuple(state.modifications),
        owned_blocks=frozenset(state.owned_blocks),
        owned_edges=frozenset(state.owned_edges),
        owned_transitions=frozenset(state.owned_transitions),
        transition_count=int(transition_count),
        conditional_count=int(conditional_count),
        terminal_skipped=int(terminal_skipped),
        unknown_skipped=int(unknown_skipped),
        skipped_count=int(skipped_count),
        disconnect_count=int(disconnect_count),
        cleanup_gate_reason=cleanup_gate_reason,
        residual_dispatcher_preds=tuple(int(serial) for serial in residual_dispatcher_preds),
        residual_dispatcher_redirect_count=int(residual_dispatcher_redirect_count),
        residual_dispatcher_normalized_count=int(residual_dispatcher_normalized_count),
        dead_island_cleanup_count=0,
        unresolved_bst_targets=int(unresolved_bst_targets),
    )


__all__ = [
    "LinearizedDagPlannableEdge",
    "LinearizedDagRoundSummary",
    "LinearizedFlowGraphPlanningCallbacks",
    "LinearizedFlowGraphPlanningContext",
    "LinearizedFlowGraphPlanningResult",
    "LinearizedFlowGraphPlanningState",
    "execute_linearized_flow_graph_planning",
]
