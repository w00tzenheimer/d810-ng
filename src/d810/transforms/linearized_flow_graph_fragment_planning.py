from __future__ import annotations

from dataclasses import dataclass

from d810.core.algorithm_metadata import algorithm_metadata
from d810.core import logging
from d810.core.round_context import RoundFrame
from d810.core.typing import Callable
from d810.analyses.control_flow.dag_index import build_dag_node_maps
from d810.transforms.reconstruction_redirect_log import log_redirect_attempt
from d810.transforms.graph_modification import RedirectBranch
from d810.transforms.target_entry_resolution import resolve_edge_target_entry

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
    semantic_reference_program: object | None
    structured_regions: tuple["LinearizedDagStructuredRegion", ...]
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
class LinearizedDagStructuredRegion:
    """Structured semantic region passed into experimental Hodur lowering."""

    region_name: str
    entry_state: int
    state_values: tuple[int, ...]
    state_labels: tuple[str, ...]
    internal_state_edges: tuple[tuple[int, int], ...]
    exit_state_values: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class LinearizedFlowGraphPlanSetup:
    """Precomputed strategy-owned inputs for cfg planning."""

    builder: object
    state_var_stkoff: int | None
    dispatcher: object | None
    blocked_sources: frozenset[int]
    dispatcher_region: frozenset[int]
    bst_node_blocks: frozenset[int]
    original_blocks: frozenset[int]
    transition_result: object
    pre_header_serial: int | None
    projectable: bool
    round_limit: int


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
    # Pass-entry ``AnalysisSnapshot``. Carried so the internal round loop can
    # push :class:`RoundFrame`-based scope info onto the log stream (and in
    # future: into sub-callbacks via ``dataclasses.replace``) without
    # rewiring every caller. Defaults to ``None`` for back-compat with
    # callers that haven't migrated yet; round-aware logging is a no-op
    # when absent.
    snapshot: object | None = None


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
    emit_structured_region: Callable[..., "LinearizedFlowGraphStructuredRegionResult"]
    emit_residual_dispatcher_handoffs: Callable[..., int]
    disconnect_bst_comparison_nodes: Callable[..., int]
    resolve_effective_target_entry: Callable[..., int | None] | None = None


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


@dataclass(frozen=True, slots=True)
class LinearizedFlowGraphStructuredRegionResult:
    """Outcome from one experimental structured-region lowering attempt."""

    accepted: bool
    consumed_state_edges: frozenset[tuple[int, int]] = frozenset()
    successor_state_values: frozenset[int] = frozenset()
    unresolved_state_values: frozenset[int] = frozenset()
    transition_count: int = 0
    conditional_count: int = 0
    rejection_reason: str | None = None


def _regions_reachable_from_states(
    structured_regions: tuple[LinearizedDagStructuredRegion, ...],
    *,
    seeded_states: frozenset[int],
    attempted_region_names: frozenset[str],
) -> tuple[LinearizedDagStructuredRegion, ...]:
    if not structured_regions:
        return ()
    if not seeded_states:
        return tuple(
            region
            for region in structured_regions
            if str(region.region_name) not in attempted_region_names
        )

    normalized_seeded_states = {int(state) & 0xFFFFFFFF for state in seeded_states}
    return tuple(
        region
        for region in structured_regions
        if str(region.region_name) not in attempted_region_names
        and (
            (int(region.entry_state) & 0xFFFFFFFF) in normalized_seeded_states
            or {
                int(state) & 0xFFFFFFFF
                for state in getattr(region, "state_values", ())
            }.intersection(normalized_seeded_states)
        )
    )


def _synthesize_exact_node_regions(
    dag: object,
    structured_regions: tuple[LinearizedDagStructuredRegion, ...],
) -> tuple[LinearizedDagStructuredRegion, ...]:
    covered_states = {
        int(state) & 0xFFFFFFFF
        for region in structured_regions
        for state in getattr(region, "state_values", ())
    }
    exit_states_by_source: dict[int, set[int]] = {}
    for edge in getattr(dag, "edges", ()) or ():
        source_state = getattr(getattr(edge, "source_key", None), "state_const", None)
        target_state = getattr(edge, "target_state", None)
        if source_state is None or target_state is None:
            continue
        source_value = int(source_state) & 0xFFFFFFFF
        target_value = int(target_state) & 0xFFFFFFFF
        if source_value == target_value:
            continue
        exit_states_by_source.setdefault(source_value, set()).add(target_value)

    synthetic_regions: list[LinearizedDagStructuredRegion] = []
    for node in getattr(dag, "nodes", ()) or ():
        node_kind = getattr(node, "kind", None)
        if getattr(node_kind, "name", None) != "EXACT":
            continue
        state_value = getattr(getattr(node, "key", None), "state_const", None)
        if state_value is None:
            continue
        state_value = int(state_value) & 0xFFFFFFFF
        if state_value in covered_states:
            continue
        exit_states = tuple(sorted(exit_states_by_source.get(state_value, set())))
        if not exit_states:
            continue
        synthetic_regions.append(
            LinearizedDagStructuredRegion(
                region_name=f"synthetic_exact_region_0x{state_value:08X}",
                entry_state=state_value,
                state_values=(state_value,),
                state_labels=(str(getattr(node, "state_label", "") or ""),),
                internal_state_edges=(),
                exit_state_values=exit_states,
            )
        )

    synthetic_regions.sort(key=lambda region: (region.entry_state, region.region_name))
    return tuple(synthetic_regions)


def _apply_reachable_structured_regions(
    *,
    state: LinearizedFlowGraphPlanningState,
    current_flow_graph: object,
    latest_summary: LinearizedDagRoundSummary,
    known_structured_regions: dict[str, LinearizedDagStructuredRegion],
    accepted_region_names: set[str],
    attempted_region_names: set[str] | None,
    pending_region_states: set[int],
    consumed_structured_state_edges: set[tuple[int, int]],
    callbacks: LinearizedFlowGraphPlanningCallbacks,
) -> tuple[int, int, bool]:
    transition_delta = 0
    conditional_delta = 0
    start_modification_count = len(state.modifications)
    normalized_pending_states = {
        int(state_value) & 0xFFFFFFFF
        for state_value in pending_region_states
    }
    pending_region_states.clear()
    reachable_regions = _regions_reachable_from_states(
        tuple(known_structured_regions.values()),
        seeded_states=(
            frozenset(normalized_pending_states)
            if normalized_pending_states
            else frozenset()
        ),
        attempted_region_names=frozenset(
            set(accepted_region_names).union(attempted_region_names or set())
        ),
    )
    if not reachable_regions:
        pending_region_states.update(normalized_pending_states)
        return (
            int(transition_delta),
            int(conditional_delta),
            len(state.modifications) > start_modification_count,
        )

    next_round_frontier: set[int] = set()
    for structured_region in reachable_regions:
        if attempted_region_names is not None:
            attempted_region_names.add(str(structured_region.region_name))
        structured_result = callbacks.emit_structured_region(
            region=structured_region,
            dag=latest_summary.dag,
            semantic_reference_program=latest_summary.semantic_reference_program,
            structured_regions=tuple(known_structured_regions.values()),
            flow_graph=current_flow_graph,
            state=state,
        )
        if not structured_result.accepted:
            logger.info(
                "LFG DAG: structured region %s rejected reason=%s pending_state=0x%08X",
                structured_region.region_name,
                structured_result.rejection_reason,
                int(getattr(structured_region, "entry_state", 0)) & 0xFFFFFFFF,
            )
            next_round_frontier.add(
                int(getattr(structured_region, "entry_state", 0)) & 0xFFFFFFFF
            )
            continue
        if not structured_result.unresolved_state_values:
            accepted_region_names.add(str(structured_region.region_name))
        consumed_structured_state_edges.update(
            structured_result.consumed_state_edges
        )
        next_round_frontier.update(
            int(state_value) & 0xFFFFFFFF
            for state_value in structured_result.successor_state_values
        )
        next_round_frontier.update(
            int(state_value) & 0xFFFFFFFF
            for state_value in structured_result.unresolved_state_values
        )
        transition_delta += int(structured_result.transition_count)
        conditional_delta += int(structured_result.conditional_count)
    pending_region_states.update(next_round_frontier)

    return (
        int(transition_delta),
        int(conditional_delta),
        len(state.modifications) > start_modification_count,
    )


def _normalize_projected_conditional_redirects(
    *,
    dag: object,
    dispatcher_region: frozenset[int],
    original_blocks: frozenset[int],
    state_var_stkoff: int | None,
    dispatcher_lookup: object | None,
    dispatcher: object | None,
    mba: object | None,
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    emitted: set[tuple[int, int]],
    claimed_2way: dict[tuple[int, int], int],
    resolve_effective_target_entry=None,
) -> int:
    """Retarget queued conditional redirects against the latest projected DAG.

    Earlier planning rounds can emit branch redirects against transient corridor
    entries. Once the projected DAG is rebuilt, the same arm may resolve to a
    semantic head entry instead. Normalize those queued RedirectBranch edits
    here before residual cleanup so later stages consume the corrected targets.
    """

    if not hasattr(dag, "nodes") or not hasattr(dag, "edges"):
        return 0

    dag_node_maps = build_dag_node_maps(dag)
    normalized_count = 0

    for index, modification in enumerate(tuple(modifications)):
        if not isinstance(modification, RedirectBranch):
            continue
        source_block = int(modification.from_serial)
        old_target = int(modification.old_target)
        current_target = int(modification.new_target)

        matching_edges = []
        for edge in getattr(dag, "edges", ()) or ():
            source_anchor = getattr(edge, "source_anchor", None)
            if source_anchor is None:
                continue
            if int(getattr(source_anchor, "block_serial", -1)) != source_block:
                continue
            ordered_path = tuple(
                int(block_serial)
                for block_serial in (getattr(edge, "ordered_path", ()) or ())
            )
            if len(ordered_path) < 2:
                continue
            if ordered_path[0] != source_block or ordered_path[1] != old_target:
                continue
            matching_edges.append(edge)

        if not matching_edges:
            continue

        normalized_target: int | None = None
        for edge in matching_edges:
            effective_target = (
                resolve_effective_target_entry(
                    dag,
                    edge,
                    bst_node_blocks=set(int(block) for block in dispatcher_region),
                    state_var_stkoff=state_var_stkoff,
                    dispatcher_lookup=dispatcher_lookup,
                    dispatcher=dispatcher,
                    mba=mba,
                )
                if mba is not None and callable(resolve_effective_target_entry)
                else None
            )
            if effective_target is not None:
                candidate = int(effective_target)
                if (
                    candidate != source_block
                    and candidate != current_target
                    and candidate in original_blocks
                ):
                    normalized_target = candidate
                    break
            resolution = resolve_edge_target_entry(
                edge,
                node_by_key=dag_node_maps.node_by_key,
                dispatcher_region=set(int(block) for block in dispatcher_region),
            )
            if resolution.target_entry is None:
                continue
            candidate = int(resolution.target_entry)
            if candidate == source_block or candidate == current_target:
                continue
            if candidate not in original_blocks:
                continue
            normalized_target = candidate
            break

        if normalized_target is None:
            continue

        modifications[index] = RedirectBranch(
            from_serial=source_block,
            old_target=old_target,
            new_target=normalized_target,
        )
        claimed_2way[(source_block, old_target)] = normalized_target
        owned_blocks.add(source_block)
        owned_edges.discard((source_block, current_target))
        owned_edges.add((source_block, normalized_target))
        emitted.discard((source_block, current_target))
        emitted.add((source_block, normalized_target))
        normalized_count += 1

    return normalized_count


def flow_graph_block_serials(flow_graph: object) -> set[int]:
    blocks = getattr(flow_graph, "blocks", None)
    if blocks is None:
        return set()
    try:
        return set(blocks.keys())
    except Exception:
        return set()


def is_original_pre_header_candidate(
    flow_graph: object | None,
    *,
    pre_header_serial: int | None,
    entry_serial: int | None,
) -> bool:
    if flow_graph is None or pre_header_serial is None or entry_serial is None:
        return False
    if pre_header_serial == entry_serial:
        return True
    try:
        entry_block = flow_graph.get_block(entry_serial)
    except Exception:
        return False
    if entry_block is None:
        return False
    succs = tuple(getattr(entry_block, "succs", ()))
    return len(succs) == 1 and succs[0] == pre_header_serial


def prepare_linearized_flow_graph_plan_setup(
    *,
    snapshot: object,
    state_machine: object,
    bst_result: object,
    flow_graph: object,
    same_maturity_rerun: bool,
    build_builder: Callable[[object], object],
    resolve_state_var_stkoff: Callable[[object, object], int | None],
    supports_projected_replanning: Callable[[object], bool],
    label_block: Callable[[int | None], str],
    transition_result: object,
) -> LinearizedFlowGraphPlanSetup:
    bst_node_blocks = frozenset(
        int(block)
        for block in (getattr(bst_result, "condition_chain_blocks", set()) or set())
    )
    builder = build_builder(snapshot)
    state_var_stkoff = resolve_state_var_stkoff(snapshot, state_machine)
    dispatcher = getattr(bst_result, "dispatcher", None)
    blocked_sources = frozenset(
        int(serial)
        for serial in (getattr(snapshot, "lfg_redirected_blocks", ()) or ())
    )
    dispatcher_region = bst_node_blocks
    original_blocks = frozenset(
        int(block) for block in flow_graph_block_serials(flow_graph)
    )
    raw_pre_header = (
        None if same_maturity_rerun else getattr(bst_result, "pre_header_serial", None)
    )
    entry_serial = getattr(getattr(snapshot, "reachability", None), "entry_serial", None)
    pre_header_serial = (
        raw_pre_header
        if is_original_pre_header_candidate(
            flow_graph,
            pre_header_serial=raw_pre_header,
            entry_serial=entry_serial,
        )
        else None
    )
    if raw_pre_header is not None and pre_header_serial is None:
        logger.info(
            "LFG DAG: suppressing non-entry pre-header candidate %s (entry=%s)",
            label_block(raw_pre_header),
            label_block(entry_serial) if entry_serial is not None else "<none>",
        )

    projectable = bool(supports_projected_replanning(flow_graph))
    round_limit = 1 if same_maturity_rerun else 3
    return LinearizedFlowGraphPlanSetup(
        builder=builder,
        state_var_stkoff=state_var_stkoff,
        dispatcher=dispatcher,
        blocked_sources=blocked_sources,
        dispatcher_region=dispatcher_region,
        bst_node_blocks=bst_node_blocks,
        original_blocks=original_blocks,
        transition_result=transition_result,
        pre_header_serial=pre_header_serial,
        projectable=projectable,
        round_limit=round_limit,
    )


def build_linearized_flow_graph_planning_context(
    *,
    flow_graph: object,
    mba: object | None,
    state_machine: object,
    dispatcher_serial: int,
    setup: LinearizedFlowGraphPlanSetup,
    snapshot: object | None = None,
) -> LinearizedFlowGraphPlanningContext:
    dispatcher = setup.dispatcher
    return LinearizedFlowGraphPlanningContext(
        flow_graph=flow_graph,
        builder=setup.builder,
        mba=mba,
        state_machine=state_machine,
        dispatcher_serial=int(dispatcher_serial),
        bst_node_blocks=setup.bst_node_blocks,
        dispatcher_region=setup.dispatcher_region,
        state_var_stkoff=setup.state_var_stkoff,
        dispatcher_lookup=(dispatcher.lookup if dispatcher is not None else None),
        dispatcher=dispatcher,
        pre_header_serial=setup.pre_header_serial,
        original_blocks=setup.original_blocks,
        same_maturity_rerun=bool(setup.round_limit == 1),
        projectable=bool(setup.projectable),
        round_limit=int(setup.round_limit),
        initial_state=(
            int(state_machine.initial_state)
            if state_machine.initial_state is not None
            else None
        ),
        blocked_sources=setup.blocked_sources,
        snapshot=snapshot,
    )


def adapt_linearized_dag_round_summary(
    *,
    state_machine: object,
    bst_result: object,
    transition_result: object,
    current_flow_graph: object,
    dag_round_mba: object | None,
    dispatcher_serial: int,
    state_var_stkoff: int | None,
    pre_header_serial: int | None,
    bst_node_blocks: frozenset[int],
    build_round_summary: object,
    build_live_dag: object,
    build_transition_report: object,
    select_plannable_edges: object,
    include_synthetic_exact_regions: bool = True,
) -> LinearizedDagRoundSummary:
    resolved_summary = build_round_summary(
        current_flow_graph=current_flow_graph,
        transition_result=transition_result,
        dispatcher_serial=dispatcher_serial,
        state_var_stkoff=state_var_stkoff,
        pre_header_serial=pre_header_serial,
        initial_state=state_machine.initial_state,
        handler_range_map=getattr(bst_result, "handler_range_map", {}) or {},
        bst_node_blocks=tuple(sorted(bst_node_blocks)),
        diagnostics=tuple(getattr(bst_result, "diagnostics", ()) or ()),
        dispatcher=getattr(bst_result, "dispatcher", None),
        mba=dag_round_mba,
        handlers=state_machine.handlers,
        build_live_dag=build_live_dag,
        build_transition_report=build_transition_report,
        select_plannable_edges=select_plannable_edges,
    )
    plannable_edges = tuple(
        LinearizedDagPlannableEdge(
            edge=entry.edge,
            source_anchor_block=int(entry.source_anchor_block),
            ordered_path=tuple(int(node) for node in entry.ordered_path),
            target_entry_anchor=(
                int(entry.target_entry_anchor)
                if entry.target_entry_anchor is not None
                else None
            ),
            is_conditional_transition=bool(entry.is_conditional_transition),
            requires_safe_target_resolution=bool(
                entry.requires_safe_target_resolution
            ),
        )
        for entry in resolved_summary.plannable_edges
    )
    structured_regions = tuple(
        LinearizedDagStructuredRegion(
            region_name=str(region.region_name),
            entry_state=int(region.entry_state),
            state_values=tuple(int(state) for state in region.state_values),
            state_labels=tuple(str(label) for label in region.state_labels),
            internal_state_edges=tuple(
                (int(source), int(target))
                for source, target in region.internal_state_edges
            ),
            exit_state_values=tuple(
                int(state) for state in region.exit_state_values
            ),
        )
        for region in resolved_summary.structured_regions
    )
    synthetic_exact_regions = (
        _synthesize_exact_node_regions(
            resolved_summary.dag,
            structured_regions,
        )
        if include_synthetic_exact_regions
        else ()
    )
    return LinearizedDagRoundSummary(
        dag=resolved_summary.dag,
        semantic_reference_program=resolved_summary.semantic_reference_program,
        structured_regions=tuple((*structured_regions, *synthetic_exact_regions)),
        plannable_edges=plannable_edges,
        report_exit_handlers=frozenset(
            int(handler) for handler in resolved_summary.report_exit_handlers
        ),
        report_exit_owned_blocks=frozenset(
            int(block) for block in resolved_summary.report_exit_owned_blocks
        ),
        terminal_source_keys=frozenset(resolved_summary.terminal_source_keys),
        terminal_source_handlers=frozenset(
            int(handler) for handler in resolved_summary.terminal_source_handlers
        ),
        terminal_source_owned_blocks=frozenset(
            int(block) for block in resolved_summary.terminal_source_owned_blocks
        ),
        terminal_protected_blocks=frozenset(
            int(block) for block in resolved_summary.terminal_protected_blocks
        ),
        terminal_skipped=int(resolved_summary.terminal_skipped),
        unknown_skipped=int(resolved_summary.unknown_skipped),
    )


def build_linearized_flow_graph_planning_callbacks(
    *,
    snapshot: object,
    state_machine: object,
    bst_result: object,
    mba: object | None,
    setup: LinearizedFlowGraphPlanSetup,
    discover_round_summary: object,
    build_projected_mba: object,
    project_flow_graph: object,
    resolve_redirect_safe_target_entry: object,
    resolve_initial_entry: object,
    emit_dag_redirect: object,
    collect_residual_dispatcher_predecessors: object,
    emit_structured_region: object,
    emit_residual_dispatcher_handoffs: object,
    disconnect_bst_comparison_nodes: object,
    resolve_effective_target_entry: object | None,
    build_live_dag: object,
    build_transition_report: object,
    select_plannable_edges: object,
    include_synthetic_exact_regions: bool = True,
) -> LinearizedFlowGraphPlanningCallbacks:
    return LinearizedFlowGraphPlanningCallbacks(
        build_round_summary=lambda current_flow_graph, dag_round_mba: adapt_linearized_dag_round_summary(
            state_machine=state_machine,
            bst_result=bst_result,
            transition_result=setup.transition_result,
            current_flow_graph=current_flow_graph,
            dag_round_mba=dag_round_mba,
            dispatcher_serial=int(snapshot.bst_dispatcher_serial),
            state_var_stkoff=setup.state_var_stkoff,
            pre_header_serial=setup.pre_header_serial,
            bst_node_blocks=setup.bst_node_blocks,
            build_round_summary=discover_round_summary,
            build_live_dag=build_live_dag,
            build_transition_report=build_transition_report,
            select_plannable_edges=select_plannable_edges,
            include_synthetic_exact_regions=include_synthetic_exact_regions,
        ),
        build_projected_mba=build_projected_mba,
        project_flow_graph=project_flow_graph,
        resolve_redirect_safe_target_entry=lambda dag, edge, bst_node_blocks: resolve_redirect_safe_target_entry(
            dag,
            edge,
            bst_node_blocks=set(int(block) for block in bst_node_blocks),
        ),
        resolve_initial_entry=lambda dag, initial_state, bst_node_blocks: resolve_initial_entry(
            dag,
            initial_state,
            bst_node_blocks=set(int(block) for block in bst_node_blocks),
        ),
        emit_dag_redirect=lambda *,
            edge,
            dag,
            flow_graph,
            state,
            report_exit_handlers,
            report_exit_owned_blocks,
            terminal_source_keys,
            terminal_source_handlers,
            terminal_source_owned_blocks,
            terminal_protected_blocks: emit_dag_redirect(
                edge=edge,
                dag=dag,
                builder=setup.builder,
                modifications=state.modifications,
                owned_blocks=state.owned_blocks,
                owned_edges=state.owned_edges,
                owned_transitions=state.owned_transitions,
                emitted=state.emitted,
                claimed_1way=state.claimed_1way,
                claimed_2way=state.claimed_2way,
                claimed_exits=state.claimed_exits,
                claimed_path_edges=state.claimed_path_edges,
                blocked_sources=state.blocked_sources,
                terminal_source_keys=set(terminal_source_keys),
                terminal_source_handlers=set(terminal_source_handlers),
                terminal_source_owned_blocks=set(terminal_source_owned_blocks),
                terminal_protected_blocks=set(terminal_protected_blocks),
                report_exit_handlers=set(report_exit_handlers),
                report_exit_owned_blocks=set(report_exit_owned_blocks),
                bst_node_blocks=set(int(block) for block in setup.bst_node_blocks),
                dispatcher_region=set(int(block) for block in setup.dispatcher_region),
                flow_graph=flow_graph,
                state_var_stkoff=setup.state_var_stkoff,
                dispatcher_lookup=(
                    setup.dispatcher.lookup if setup.dispatcher is not None else None
                ),
                dispatcher=setup.dispatcher,
                mba=mba,
            ),
        collect_residual_dispatcher_predecessors=lambda current_flow_graph, dispatcher_serial, bst_node_blocks, reachable_from_serial: collect_residual_dispatcher_predecessors(
            current_flow_graph,
            dispatcher_serial,
            bst_node_blocks=set(int(block) for block in bst_node_blocks),
            reachable_from_serial=reachable_from_serial,
        ),
        emit_structured_region=lambda *,
            region,
            dag,
            flow_graph,
            semantic_reference_program,
            structured_regions,
            state: emit_structured_region(
                region=region,
                dag=dag,
                flow_graph=flow_graph,
                semantic_reference_program=semantic_reference_program,
                structured_regions=structured_regions,
                state=state,
            ),
        emit_residual_dispatcher_handoffs=lambda *,
            dag,
            projected_flow_graph,
            state,
            redirected_blocks,
            rejected_sources=None: emit_residual_dispatcher_handoffs(
                dag=dag,
                state_machine=state_machine,
                projected_flow_graph=projected_flow_graph,
                dispatcher_serial=int(snapshot.bst_dispatcher_serial),
                bst_node_blocks=set(int(block) for block in setup.bst_node_blocks),
                builder=setup.builder,
                modifications=state.modifications,
                owned_blocks=state.owned_blocks,
                owned_edges=state.owned_edges,
                owned_transitions=state.owned_transitions,
                emitted=state.emitted,
                claimed_1way=state.claimed_1way,
                claimed_2way=state.claimed_2way,
                state_var_stkoff=setup.state_var_stkoff,
                dispatcher_lookup=(
                    setup.dispatcher.lookup if setup.dispatcher is not None else None
                ),
                dispatcher=setup.dispatcher,
                mba=mba,
                redirected_blocks=redirected_blocks,
                rejected_sources=rejected_sources,
            ),
        disconnect_bst_comparison_nodes=lambda bst_node_blocks, dispatcher_serial, state: disconnect_bst_comparison_nodes(
            set(int(block) for block in bst_node_blocks),
            dispatcher_serial,
            setup.builder,
            state.modifications,
            state.emitted,
            mba=mba,
        ),
        resolve_effective_target_entry=resolve_effective_target_entry,
    )


@algorithm_metadata(
    algorithm_id="cfg.execute_linearized_flow_graph_planning",
    family="structured_semantic_region_lowering",
    summary="Executes projected semantic-DAG planning rounds into CFG modification bundles.",
    use_cases=(
        "Lower exact semantic corridors and structured regions into planner-owned CFG edits.",
        "Project candidate DAG rewrites through multiple planning rounds without mutating the live MBA directly.",
    ),
    examples=(
        "Emit structured-region overrides before residual handoff redirects in the linearized flow-graph planner.",
        "Accumulate transition, conditional, and terminal lowering decisions into one planning result.",
    ),
    tags=("structured-region", "semantic-dag", "planning", "lowering"),
    related_paths=(
        "src/d810/cfg/linearized_flow_graph_fragment_planning.py",
        "src/d810/optimizers/microcode/flow/flattening/hodur/strategies/reconstruction.py",
    ),
)
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
    consumed_structured_state_edges: set[tuple[int, int]] = set()
    pending_region_states: set[int] = (
        {int(context.initial_state) & 0xFFFFFFFF}
        if context.initial_state is not None
        else set()
    )
    accepted_structured_region_names: set[str] = set()
    known_structured_regions: dict[str, LinearizedDagStructuredRegion] = {}
    for round_index in range(max(int(context.round_limit), 1)):
        round_attempted_region_names: set[str] = set()
        # Publish the round scope on the snapshot's round_context stack for
        # log correlation. This is read-only breadcrumb at the moment — no
        # sub-callback currently consumes the pushed frame. When strategies
        # opt in to ``snapshot.round_context.in_round`` checks, the frame
        # will already be materialised here.
        if context.snapshot is not None and round_index >= 0:
            ctx = getattr(context.snapshot, "round_context", None)
            if ctx is not None:
                trace = ctx.push(
                    RoundFrame(
                        scope="round",
                        index=int(round_index),
                        name="projected_replan",
                    )
                ).as_trace()
                logger.info("LFG round enter: %s", trace)
        round_mba = (
            context.mba
            if round_index == 0 or not context.projectable
            else callbacks.build_projected_mba(current_flow_graph)
        )
        latest_summary = callbacks.build_round_summary(current_flow_graph, round_mba)
        for structured_region in latest_summary.structured_regions:
            known_structured_regions[str(structured_region.region_name)] = structured_region
        terminal_skipped = int(latest_summary.terminal_skipped)
        unknown_skipped = int(latest_summary.unknown_skipped)
        structured_round_start = len(state.modifications)
        (
            round_transition_delta,
            round_conditional_delta,
            _,
        ) = _apply_reachable_structured_regions(
            state=state,
            current_flow_graph=current_flow_graph,
            latest_summary=latest_summary,
            known_structured_regions=known_structured_regions,
            accepted_region_names=accepted_structured_region_names,
            attempted_region_names=round_attempted_region_names,
            pending_region_states=pending_region_states,
            consumed_structured_state_edges=consumed_structured_state_edges,
            callbacks=callbacks,
        )
        transition_count += round_transition_delta
        conditional_count += round_conditional_delta

        if (
            context.projectable
            and pending_region_states
            and len(state.modifications) > structured_round_start
        ):
            seen_structured_revisit_states: set[
                tuple[tuple[str, ...], tuple[int, ...], int]
            ] = set()
            structured_revisit_limit = max(
                len(known_structured_regions) + len(pending_region_states) + 1,
                1,
            )
            for iteration in range(structured_revisit_limit):
                if not pending_region_states:
                    break
                revisit_state = (
                    tuple(sorted(str(name) for name in known_structured_regions)),
                    tuple(sorted(int(state_value) for state_value in pending_region_states)),
                    len(state.modifications),
                )
                if revisit_state in seen_structured_revisit_states:
                    break
                seen_structured_revisit_states.add(revisit_state)
                try:
                    current_flow_graph = callbacks.project_flow_graph(
                        context.flow_graph,
                        state.modifications,
                    )
                    revisit_mba = callbacks.build_projected_mba(current_flow_graph)
                    revisit_summary = callbacks.build_round_summary(
                        current_flow_graph,
                        revisit_mba,
                    )
                except Exception:
                    logger.warning(
                        "LFG DAG: projected structured-region revisit[%d] failed",
                        int(iteration),
                        exc_info=True,
                    )
                    break
                for structured_region in revisit_summary.structured_regions:
                    known_structured_regions[str(structured_region.region_name)] = structured_region
                logger.info(
                    "LFG DAG: projected structured-region revisit[%d] with pending_states=%s",
                    int(iteration),
                    tuple(sorted(int(state_value) for state_value in pending_region_states)),
                )
                (
                    revisit_transition_delta,
                    revisit_conditional_delta,
                    revisit_added_modifications,
                ) = _apply_reachable_structured_regions(
                    state=state,
                    current_flow_graph=current_flow_graph,
                    latest_summary=revisit_summary,
                    known_structured_regions=known_structured_regions,
                    accepted_region_names=accepted_structured_region_names,
                    attempted_region_names=round_attempted_region_names,
                    pending_region_states=pending_region_states,
                    consumed_structured_state_edges=consumed_structured_state_edges,
                    callbacks=callbacks,
                )
                transition_count += revisit_transition_delta
                conditional_count += revisit_conditional_delta
                latest_summary = revisit_summary
                if not revisit_added_modifications:
                    break

        round_unresolved_bst_targets = 0
        round_start = len(state.modifications)
        if not context.same_maturity_rerun:
            for plannable_edge in latest_summary.plannable_edges:
                edge_obj = plannable_edge.edge
                edge_source_key = getattr(edge_obj, "source_key", None)
                source_state = (
                    int(getattr(edge_source_key, "state_const", None)) & 0xFFFFFFFF
                    if getattr(edge_source_key, "state_const", None) is not None
                    else None
                )
                target_state = (
                    int(getattr(edge_obj, "target_state", None)) & 0xFFFFFFFF
                    if getattr(edge_obj, "target_state", None) is not None
                    else None
                )
                if (
                    source_state is not None
                    and target_state is not None
                    and (source_state, target_state) in consumed_structured_state_edges
                ):
                    continue
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
            log_redirect_attempt(
                phase="lfg_preheader",
                src=int(context.pre_header_serial),
                old_target=int(context.dispatcher_serial),
                new_target=int(initial_entry),
                dag=latest_summary.dag,
                state_const=(
                    int(context.initial_state)
                    if context.initial_state is not None
                    else None
                ),
            )
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

    normalization_summary = latest_summary
    normalization_mba = context.mba
    if final_flow_graph is not None and latest_summary is not None:
        try:
            normalization_mba = (
                callbacks.build_projected_mba(final_flow_graph)
                if context.projectable
                else context.mba
            )
            normalization_summary = callbacks.build_round_summary(
                final_flow_graph,
                normalization_mba,
            )
        except Exception:
            logger.warning(
                "LFG DAG: projected normalization summary rebuild failed",
                exc_info=True,
            )
            normalization_summary = latest_summary
            normalization_mba = context.mba

    if final_flow_graph is not None and normalization_summary is not None:
        residual_dispatcher_normalized_count += _normalize_projected_conditional_redirects(
            dag=normalization_summary.dag,
            dispatcher_region=context.dispatcher_region,
            original_blocks=context.original_blocks,
            state_var_stkoff=context.state_var_stkoff,
            dispatcher_lookup=context.dispatcher_lookup,
            dispatcher=context.dispatcher,
            mba=normalization_mba,
            modifications=state.modifications,
            owned_blocks=state.owned_blocks,
            owned_edges=state.owned_edges,
            emitted=state.emitted,
            claimed_2way=state.claimed_2way,
            resolve_effective_target_entry=callbacks.resolve_effective_target_entry,
        )
        if residual_dispatcher_normalized_count:
            try:
                final_flow_graph = callbacks.project_flow_graph(
                    context.flow_graph,
                    state.modifications,
                )
            except Exception:
                logger.warning(
                    "LFG DAG: projected branch-target normalization failed",
                    exc_info=True,
                )

    if final_flow_graph is not None:
        residual_dispatcher_preds = callbacks.collect_residual_dispatcher_predecessors(
            final_flow_graph,
            int(context.dispatcher_serial),
            context.bst_node_blocks,
            getattr(final_flow_graph, "entry_serial", None),
        )
        if residual_dispatcher_preds:
            residual_iteration_limit = max(1, len(tuple(residual_dispatcher_preds)) + 2)
            seen_residual_states: set[tuple[tuple[int, ...], int]] = set()
            for _ in range(residual_iteration_limit):
                residual_key = tuple(int(serial) for serial in residual_dispatcher_preds)
                residual_state = (residual_key, len(state.modifications))
                if residual_state in seen_residual_states:
                    break
                seen_residual_states.add(residual_state)

                round_start_modifications = len(state.modifications)
                rejected_residual_sources: set[int] = set()
                redirected = callbacks.emit_residual_dispatcher_handoffs(
                    dag=latest_summary.dag,
                    projected_flow_graph=final_flow_graph,
                    state=state,
                    redirected_blocks=normalizable_redirect_blocks,
                    rejected_sources=rejected_residual_sources,
                )
                residual_dispatcher_redirect_count += int(redirected)
                if rejected_residual_sources:
                    residual_dispatcher_preds = tuple(
                        sorted(int(source_block) for source_block in rejected_residual_sources)
                    )
                    cleanup_gate_reason = "residual_dispatcher_rejections"
                    break
                if len(state.modifications) == round_start_modifications:
                    break

                final_flow_graph = callbacks.project_flow_graph(
                    context.flow_graph,
                    state.modifications,
                )
                next_residual_dispatcher_preds = callbacks.collect_residual_dispatcher_predecessors(
                    final_flow_graph,
                    int(context.dispatcher_serial),
                    context.bst_node_blocks,
                    getattr(final_flow_graph, "entry_serial", None),
                )
                residual_dispatcher_preds = next_residual_dispatcher_preds
                if not residual_dispatcher_preds:
                    break
            if residual_dispatcher_preds and cleanup_gate_reason != "residual_dispatcher_rejections":
                cleanup_gate_reason = "residual_dispatcher_predecessors"
            elif (
                residual_dispatcher_redirect_count > 0
                and cleanup_gate_reason is None
            ):
                cleanup_gate_reason = "residual_dispatcher_redirects"

    if (
        final_flow_graph is not None
        and context.projectable
        and (
            residual_dispatcher_preds
            or residual_dispatcher_redirect_count > 0
            or residual_dispatcher_normalized_count > 0
        )
    ):
        try:
            post_residual_iteration_limit = max(
                1,
                len(known_structured_regions) + len(pending_region_states) + 3,
            )
            seen_post_residual_states: set[
                tuple[tuple[str, ...], tuple[int, ...], int]
            ] = set()
            post_residual_attempted_region_names: set[str] = set()
            for iteration in range(post_residual_iteration_limit):
                revisit_state = (
                    tuple(sorted(str(name) for name in known_structured_regions)),
                    tuple(sorted(int(state_value) for state_value in pending_region_states)),
                    len(state.modifications),
                )
                if revisit_state in seen_post_residual_states:
                    break
                seen_post_residual_states.add(revisit_state)

                post_residual_mba = callbacks.build_projected_mba(final_flow_graph)
                post_residual_summary = callbacks.build_round_summary(
                    final_flow_graph,
                    post_residual_mba,
                )
                logger.info(
                    "LFG DAG: post-residual structured-region revisit[%d] with %d known regions",
                    int(iteration),
                    len(post_residual_summary.structured_regions),
                )
                for structured_region in post_residual_summary.structured_regions:
                    known_structured_regions[str(structured_region.region_name)] = structured_region
                (
                    post_transition_delta,
                    post_conditional_delta,
                    post_region_added_modifications,
                ) = _apply_reachable_structured_regions(
                    state=state,
                    current_flow_graph=final_flow_graph,
                    latest_summary=post_residual_summary,
                    known_structured_regions=known_structured_regions,
                    accepted_region_names=accepted_structured_region_names,
                    attempted_region_names=post_residual_attempted_region_names,
                    pending_region_states=pending_region_states,
                    consumed_structured_state_edges=consumed_structured_state_edges,
                    callbacks=callbacks,
                )
                logger.info(
                    "LFG DAG: post-residual revisit[%d] added_modifications=%s transitions=%d conditionals=%d pending_states=%s",
                    int(iteration),
                    post_region_added_modifications,
                    int(post_transition_delta),
                    int(post_conditional_delta),
                    tuple(sorted(int(state_value) for state_value in pending_region_states)),
                )
                transition_count += post_transition_delta
                conditional_count += post_conditional_delta
                if not post_region_added_modifications:
                    break

                final_flow_graph = callbacks.project_flow_graph(
                    context.flow_graph,
                    state.modifications,
                )
                if cleanup_gate_reason != "residual_dispatcher_rejections":
                    residual_dispatcher_preds = callbacks.collect_residual_dispatcher_predecessors(
                        final_flow_graph,
                        int(context.dispatcher_serial),
                        context.bst_node_blocks,
                        getattr(final_flow_graph, "entry_serial", None),
                    )
                    if residual_dispatcher_preds:
                        cleanup_gate_reason = "residual_dispatcher_predecessors"
                    elif residual_dispatcher_redirect_count > 0:
                        cleanup_gate_reason = "residual_dispatcher_redirects"
                    else:
                        cleanup_gate_reason = None
        except Exception:
            logger.warning(
                "LFG DAG: post-residual structured-region revisit failed",
                exc_info=True,
            )

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
    "LinearizedDagStructuredRegion",
    "LinearizedFlowGraphPlanSetup",
    "LinearizedFlowGraphPlanningCallbacks",
    "LinearizedFlowGraphPlanningContext",
    "LinearizedFlowGraphPlanningResult",
    "LinearizedFlowGraphPlanningState",
    "LinearizedFlowGraphStructuredRegionResult",
    "adapt_linearized_dag_round_summary",
    "build_linearized_flow_graph_planning_callbacks",
    "build_linearized_flow_graph_planning_context",
    "execute_linearized_flow_graph_planning",
    "flow_graph_block_serials",
    "is_original_pre_header_candidate",
    "prepare_linearized_flow_graph_plan_setup",
]
