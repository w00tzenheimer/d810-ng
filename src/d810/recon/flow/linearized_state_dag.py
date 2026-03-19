"""State-level DAG artifact for Hodur topology visualization."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from enum import Enum, auto

from d810.cfg.flowgraph import FlowGraph
from d810.core.typing import Callable, Mapping
from d810.recon.flow.interval_map import IntervalDispatcher
from d810.recon.flow.state_machine_analysis import (
    ConditionalTransition,
    HandlerPathResult,
    detect_conditional_transitions,
    evaluate_handler_paths,
)
from d810.recon.flow.transition_builder import TransitionResult
from d810.recon.flow.transition_report import (
    DispatcherTransitionReport,
    TransitionKind,
    TransitionPath,
    TransitionRow,
    TransitionSummary,
    build_dispatcher_transition_report_from_graph,
)


class StateNodeKind(Enum):
    """Identity class for one state-level DAG node."""

    EXACT = auto()
    RANGE_BACKED = auto()


class LocalSegmentKind(Enum):
    """Kind of local segment carried by a state node."""

    STRAIGHT_LINE = auto()
    BRANCH = auto()
    GOTO_LABEL = auto()
    JOIN = auto()
    SHARED_SUFFIX = auto()
    TERMINAL_SUFFIX = auto()


class LocalEdgeKind(Enum):
    """Kind of local CFG edge between segments in one state node."""

    FALLTHROUGH = auto()
    TAKEN = auto()
    GOTO = auto()
    JOIN = auto()
    SHARED_SUFFIX = auto()
    TERMINAL = auto()


class RedirectSourceKind(Enum):
    """How a semantic edge identifies its redirect source."""

    UNCONDITIONAL = auto()
    CONDITIONAL_BRANCH = auto()
    EXIT_BLOCK = auto()


class SemanticEdgeKind(Enum):
    """Outer DAG edge kinds."""

    TRANSITION = auto()
    CONDITIONAL_TRANSITION = auto()
    CONDITIONAL_RETURN = auto()
    EXIT_ROUTINE = auto()
    UNKNOWN = auto()


@dataclass(frozen=True, slots=True)
class StateDagNodeKey:
    """Stable identity for a state node."""

    handler_serial: int
    state_const: int | None = None
    range_lo: int | None = None
    range_hi: int | None = None


@dataclass(frozen=True, slots=True)
class StateRedirectAnchor:
    """Concrete source anchor for one redirectable semantic edge."""

    kind: RedirectSourceKind
    block_serial: int
    branch_arm: int | None = None


@dataclass(frozen=True, slots=True)
class StateLocalSegment:
    """One local CFG segment inside a state node."""

    segment_id: str
    kind: LocalSegmentKind
    blocks: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class StateLocalEdge:
    """One local CFG edge inside a state node."""

    source_segment_id: str
    target_segment_id: str
    kind: LocalEdgeKind
    branch_arm: int | None = None


@dataclass(frozen=True, slots=True)
class StateDagNode:
    """A semantic state node with its local CFG/segment graph."""

    key: StateDagNodeKey
    kind: StateNodeKind
    state_label: str
    handler_serial: int
    entry_anchor: int
    owned_blocks: tuple[int, ...]
    exclusive_blocks: tuple[int, ...]
    shared_suffix_blocks: tuple[int, ...]
    local_segments: tuple[StateLocalSegment, ...]
    local_edges: tuple[StateLocalEdge, ...]


@dataclass(frozen=True, slots=True)
class StateDagEdge:
    """One semantic edge in the outer state-level DAG."""

    kind: SemanticEdgeKind
    source_key: StateDagNodeKey
    target_key: StateDagNodeKey | None
    target_state: int | None
    target_entry_anchor: int | None
    target_label: str
    source_anchor: StateRedirectAnchor
    ordered_path: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class LinearizedStateDag:
    """Unified state-level DAG with local CFG details."""

    dispatcher_entry_serial: int
    state_var_stkoff: int | None
    pre_header_serial: int | None
    initial_state: int | None
    bst_node_blocks: tuple[int, ...]
    nodes: tuple[StateDagNode, ...]
    edges: tuple[StateDagEdge, ...]
    diagnostics: tuple[str, ...] = ()

    def node_by_handler(self) -> dict[int, StateDagNode]:
        return {node.handler_serial: node for node in self.nodes}


def _summarize_rows(rows: tuple[TransitionRow, ...]) -> TransitionSummary:
    known_count = sum(1 for row in rows if row.kind == TransitionKind.TRANSITION)
    conditional_count = sum(
        1 for row in rows if row.kind == TransitionKind.CONDITIONAL
    )
    exit_count = sum(1 for row in rows if row.kind == TransitionKind.EXIT)
    unknown_count = sum(1 for row in rows if row.kind == TransitionKind.UNKNOWN)
    return TransitionSummary(
        handlers_total=len(rows),
        known_count=known_count,
        conditional_count=conditional_count,
        exit_count=exit_count,
        unknown_count=unknown_count,
    )


def _resolve_range_backed_anchor(
    state_value: int,
    handler_range_map: Mapping[int, tuple[int | None, int | None]],
    *,
    known_entry_anchors: set[int],
) -> int | None:
    matching_ranges: list[tuple[int, int]] = []
    for handler_serial, (range_lo, range_hi) in handler_range_map.items():
        if range_lo is None or range_hi is None:
            continue
        if not (range_lo <= state_value <= range_hi):
            continue
        matching_ranges.append((range_hi - range_lo, handler_serial))

    if not matching_ranges:
        return None

    matching_ranges.sort()
    for _, handler_serial in matching_ranges:
        if handler_serial not in known_entry_anchors:
            return handler_serial
    return matching_ranges[0][1]


def _resolve_fallback_anchor_from_exact_cover(
    state_value: int,
    report: DispatcherTransitionReport,
    flow_graph: FlowGraph,
) -> int | None:
    exact_rows = sorted(
        (row for row in report.rows if row.state_const is not None),
        key=lambda row: row.state_const if row.state_const is not None else -1,
    )
    covering_row = None
    for row in exact_rows:
        if row.state_const is None or row.state_const > state_value:
            break
        covering_row = row
    if covering_row is None:
        return None

    handler_snapshot = flow_graph.get_block(covering_row.handler_serial)
    if handler_snapshot is None or len(handler_snapshot.preds) != 1:
        return None
    pred_serial = handler_snapshot.preds[0]
    if pred_serial not in set(report.bst_node_blocks):
        return None

    pred_snapshot = flow_graph.get_block(pred_serial)
    if pred_snapshot is None or len(pred_snapshot.succs) != 2:
        return None

    sibling_succs = [
        succ for succ in pred_snapshot.succs if succ != covering_row.handler_serial
    ]
    if len(sibling_succs) != 1:
        return None
    return sibling_succs[0]


def _ordered_unique(values: list[int] | tuple[int, ...]) -> tuple[int, ...]:
    seen: set[int] = set()
    ordered: list[int] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return tuple(ordered)


def _segment_id(block_serial: int) -> str:
    return f"blk[{block_serial}]"


def _format_state_label(
    state_const: int | None,
    range_lo: int | None,
    range_hi: int | None,
    kind: StateNodeKind,
) -> str:
    if (
        kind == StateNodeKind.RANGE_BACKED
        and range_lo is not None
        and range_hi is not None
    ):
        if state_const is not None:
            return f"[0x{range_lo:08X}..0x{range_hi:08X}] (repr 0x{state_const:08X})"
        return f"[0x{range_lo:08X}..0x{range_hi:08X}]"
    if state_const is not None:
        return f"0x{state_const:08X}"
    return "STATE<?>"


def _node_kind_for_handler(
    report: DispatcherTransitionReport,
    handler_serial: int,
) -> StateNodeKind:
    if (
        handler_serial not in report.handler_state_map
        and handler_serial in report.handler_range_map
    ):
        return StateNodeKind.RANGE_BACKED
    return StateNodeKind.EXACT


def _build_state_resolver(
    report: DispatcherTransitionReport,
    transition_result: TransitionResult,
    dispatcher: IntervalDispatcher | None,
) -> tuple[dict[int, int], Callable[[int], int | None]]:
    exact_state_to_handler = {
        row.state_const: row.handler_serial
        for row in report.rows
        if row.state_const is not None
    }
    valid_handler_serials = {row.handler_serial for row in report.rows}

    def resolve_handler(state_value: int) -> int | None:
        handler_serial = exact_state_to_handler.get(state_value)
        if handler_serial is not None:
            return handler_serial
        for handler_serial_inner, (lo, hi) in report.handler_range_map.items():
            if lo is None or hi is None:
                continue
            if lo <= state_value <= hi:
                return handler_serial_inner
        handler = transition_result.handlers.get(state_value)
        if handler is not None and handler.check_block in valid_handler_serials:
            return handler.check_block
        if dispatcher is not None:
            resolved = dispatcher.lookup(state_value)
            if resolved in valid_handler_serials:
                return resolved
        return None

    return exact_state_to_handler, resolve_handler


def _collect_local_block_order(
    handler_serial: int,
    transition_result: TransitionResult,
    row_state_const: int | None,
    paths: tuple[HandlerPathResult, ...],
    conditional_transitions: tuple[ConditionalTransition, ...],
) -> tuple[int, ...]:
    ordered: list[int] = [handler_serial]

    if row_state_const is not None:
        handler = transition_result.handlers.get(row_state_const)
        if handler is not None:
            ordered.extend(handler.handler_blocks)

    for path in paths:
        ordered.extend(path.ordered_path)

    for cond in conditional_transitions:
        ordered.append(cond.branch_block)
        if cond.state_write_block is not None:
            ordered.append(cond.state_write_block)

    return _ordered_unique(ordered)


def _compute_shared_blocks(
    handler_paths_by_handler: dict[int, tuple[HandlerPathResult, ...]],
) -> set[int]:
    counts: Counter[int] = Counter()
    for paths in handler_paths_by_handler.values():
        seen_for_handler: set[int] = set()
        for path in paths:
            for block_serial in path.ordered_path:
                if block_serial in seen_for_handler:
                    continue
                seen_for_handler.add(block_serial)
                counts[block_serial] += 1
    return {block_serial for block_serial, count in counts.items() if count > 1}


def _classify_segment_kind(
    block_serial: int,
    flow_graph: FlowGraph,
    *,
    branch_blocks: set[int],
    shared_blocks: set[int],
    terminal_exit_blocks: set[int],
    join_blocks: set[int],
    goto_targets: set[int],
) -> LocalSegmentKind:
    if block_serial in shared_blocks:
        return LocalSegmentKind.SHARED_SUFFIX
    if block_serial in terminal_exit_blocks:
        return LocalSegmentKind.TERMINAL_SUFFIX
    if block_serial in branch_blocks:
        return LocalSegmentKind.BRANCH
    if block_serial in goto_targets:
        return LocalSegmentKind.GOTO_LABEL
    if block_serial in join_blocks:
        return LocalSegmentKind.JOIN
    blk = flow_graph.get_block(block_serial)
    if blk is not None and len(blk.succs) == 2:
        return LocalSegmentKind.BRANCH
    if blk is not None and len(blk.preds) > 1:
        return LocalSegmentKind.JOIN
    return LocalSegmentKind.STRAIGHT_LINE


def _classify_local_edge_kind(
    source_block: int,
    target_block: int,
    flow_graph: FlowGraph,
    *,
    shared_blocks: set[int],
    terminal_exit_blocks: set[int],
) -> tuple[LocalEdgeKind, int | None]:
    if target_block in terminal_exit_blocks:
        return LocalEdgeKind.TERMINAL, None
    if target_block in shared_blocks:
        return LocalEdgeKind.SHARED_SUFFIX, None

    blk = flow_graph.get_block(source_block)
    if blk is not None and len(blk.succs) == 2:
        if target_block == blk.succs[0]:
            return LocalEdgeKind.FALLTHROUGH, 0
        if target_block == blk.succs[1]:
            return LocalEdgeKind.TAKEN, 1

    target_snapshot = flow_graph.get_block(target_block)
    if target_snapshot is not None and len(target_snapshot.preds) > 1:
        return LocalEdgeKind.JOIN, None
    return LocalEdgeKind.GOTO, None


def _build_local_edges(
    local_blocks: tuple[int, ...],
    paths: tuple[HandlerPathResult, ...],
    flow_graph: FlowGraph,
    *,
    shared_blocks: set[int],
    terminal_exit_blocks: set[int],
) -> tuple[StateLocalEdge, ...]:
    seen_edges: set[tuple[int, int, LocalEdgeKind, int | None]] = set()
    edges: list[StateLocalEdge] = []
    local_block_set = set(local_blocks)

    for path in paths:
        for source_block, target_block in zip(path.ordered_path, path.ordered_path[1:]):
            if (
                source_block not in local_block_set
                or target_block not in local_block_set
            ):
                continue
            edge_kind, branch_arm = _classify_local_edge_kind(
                source_block,
                target_block,
                flow_graph,
                shared_blocks=shared_blocks,
                terminal_exit_blocks=terminal_exit_blocks,
            )
            signature = (source_block, target_block, edge_kind, branch_arm)
            if signature in seen_edges:
                continue
            seen_edges.add(signature)
            edges.append(
                StateLocalEdge(
                    source_segment_id=_segment_id(source_block),
                    target_segment_id=_segment_id(target_block),
                    kind=edge_kind,
                    branch_arm=branch_arm,
                )
            )

    return tuple(edges)


def _infer_terminal_edge_kind(
    path: HandlerPathResult,
    flow_graph: FlowGraph,
    branch_anchor: StateRedirectAnchor | None,
) -> SemanticEdgeKind:
    if branch_anchor is not None:
        return SemanticEdgeKind.CONDITIONAL_RETURN
    blk = flow_graph.get_block(path.exit_block)
    if blk is not None and not blk.succs:
        return SemanticEdgeKind.CONDITIONAL_RETURN
    if len(path.ordered_path) > 1:
        return SemanticEdgeKind.EXIT_ROUTINE
    return SemanticEdgeKind.UNKNOWN


def _select_path_for_state(
    paths: tuple[HandlerPathResult, ...],
    state_value: int,
) -> HandlerPathResult | None:
    for path in paths:
        if path.final_state is None:
            continue
        if (path.final_state & 0xFFFFFFFF) == (state_value & 0xFFFFFFFF):
            return path
    return None


def _find_path_branch_anchor(
    path: HandlerPathResult,
    paths: tuple[HandlerPathResult, ...],
    flow_graph: FlowGraph,
) -> StateRedirectAnchor | None:
    if len(paths) < 2 or len(path.ordered_path) < 2:
        return None

    this_path = tuple(path.ordered_path)
    other_paths = [tuple(other.ordered_path) for other in paths if other is not path]
    if not other_paths:
        return None

    max_prefix_len = 0
    for other_path in other_paths:
        prefix_len = 0
        for idx in range(min(len(this_path), len(other_path))):
            if this_path[idx] != other_path[idx]:
                break
            prefix_len += 1
        if prefix_len > max_prefix_len:
            max_prefix_len = prefix_len

    if max_prefix_len < 1:
        return None

    for candidate_len in range(max_prefix_len, 0, -1):
        if candidate_len >= len(this_path):
            continue

        branch_block = this_path[candidate_len - 1]
        next_block = this_path[candidate_len]
        branch_snapshot = flow_graph.get_block(branch_block)
        if branch_snapshot is None or len(branch_snapshot.succs) != 2:
            continue

        if next_block == branch_snapshot.succs[0]:
            branch_arm = 0
        elif next_block == branch_snapshot.succs[1]:
            branch_arm = 1
        else:
            continue

        has_diverging_sibling = False
        for other_path in other_paths:
            if (
                candidate_len - 1 < len(other_path)
                and other_path[candidate_len - 1] == branch_block
            ):
                if (
                    candidate_len < len(other_path)
                    and other_path[candidate_len] != next_block
                ):
                    has_diverging_sibling = True
                    break
            elif candidate_len - 1 >= len(other_path):
                has_diverging_sibling = True
                break

        if has_diverging_sibling:
            return StateRedirectAnchor(
                kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                block_serial=branch_block,
                branch_arm=branch_arm,
            )

    return None


def _path_has_state_write_at_or_after_block(
    path: HandlerPathResult,
    block_serial: int,
) -> bool:
    positions = {serial: idx for idx, serial in enumerate(path.ordered_path)}
    anchor_index = positions.get(block_serial)

    for write_block, _ in path.state_writes:
        if write_block == block_serial:
            return True
        write_index = positions.get(write_block)
        if (
            anchor_index is not None
            and write_index is not None
            and write_index > anchor_index
        ):
            return True

    return False


def _infer_path_branch_anchor(
    path: HandlerPathResult,
    flow_graph: FlowGraph,
) -> StateRedirectAnchor | None:
    if len(path.ordered_path) < 2:
        return None

    for source_block, next_block in zip(
        reversed(path.ordered_path[:-1]),
        reversed(path.ordered_path[1:]),
    ):
        branch_snapshot = flow_graph.get_block(source_block)
        if branch_snapshot is None or len(branch_snapshot.succs) != 2:
            continue
        if next_block == branch_snapshot.succs[0]:
            return StateRedirectAnchor(
                kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                block_serial=source_block,
                branch_arm=0,
            )
        if next_block == branch_snapshot.succs[1]:
            return StateRedirectAnchor(
                kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                block_serial=source_block,
                branch_arm=1,
            )

    return None


def _find_sibling_branch_handoff_path(
    handler_serial: int,
    paths: tuple[HandlerPathResult, ...],
    flow_graph: FlowGraph,
    *,
    known_state_by_entry: Mapping[int, int],
) -> HandlerPathResult | None:
    """Synthesize a non-terminal sibling path that lands in another handler's join.

    This preserves local goto-label chains like:
    source handler -> local branch arm -> local goto blocks -> join block
    where the join's other predecessor is an exact handler entry for the first
    semantic continuation state.
    """

    for path in paths:
        if path.final_state is not None:
            continue

        branch_anchor = _find_path_branch_anchor(path, paths, flow_graph)
        if branch_anchor is None:
            branch_anchor = _infer_path_branch_anchor(path, flow_graph)
        if (
            branch_anchor is None
            or branch_anchor.kind != RedirectSourceKind.CONDITIONAL_BRANCH
            or branch_anchor.branch_arm is None
        ):
            continue

        branch_block = flow_graph.get_block(branch_anchor.block_serial)
        if branch_block is None or len(branch_block.succs) != 2:
            continue

        sibling_arm = 1 - branch_anchor.branch_arm
        if sibling_arm >= len(branch_block.succs):
            continue

        sibling_next = branch_block.succs[sibling_arm]
        try:
            branch_index = path.ordered_path.index(branch_anchor.block_serial)
        except ValueError:
            continue

        prefix = list(path.ordered_path[: branch_index + 1])
        chain = list(prefix)
        current = sibling_next
        previous = branch_anchor.block_serial
        visited = {branch_anchor.block_serial}

        while current not in visited:
            visited.add(current)
            chain.append(current)

            if current in known_state_by_entry and current != handler_serial:
                return HandlerPathResult(
                    exit_block=current,
                    final_state=known_state_by_entry[current],
                    state_writes=[],
                    ordered_path=chain,
                )

            current_snapshot = flow_graph.get_block(current)
            if current_snapshot is None:
                break

            if len(current_snapshot.preds) > 1:
                alternate_entries = [
                    pred
                    for pred in current_snapshot.preds
                    if pred != previous
                    and pred in known_state_by_entry
                    and pred != handler_serial
                ]
                if len(alternate_entries) == 1:
                    entry_serial = alternate_entries[0]
                    return HandlerPathResult(
                        exit_block=current,
                        final_state=known_state_by_entry[entry_serial],
                        state_writes=[],
                        ordered_path=chain,
                    )
                break

            if len(current_snapshot.succs) != 1:
                break

            previous, current = current, current_snapshot.succs[0]

    return None


def _discover_supplemental_states(
    report: DispatcherTransitionReport,
    transition_result: TransitionResult,
    paths_by_handler: Mapping[int, tuple[HandlerPathResult, ...]],
    conds_by_handler: Mapping[int, tuple[ConditionalTransition, ...]],
    dag: LinearizedStateDag,
    flow_graph: FlowGraph,
) -> tuple[set[int], dict[int, set[int]]]:
    existing_states = {
        row.state_const & 0xFFFFFFFF
        for row in report.rows
        if row.state_const is not None
    }
    supplemental_states: set[int] = set()
    collapsed_target_anchors: dict[int, set[int]] = {}

    for transition in transition_result.transitions:
        state_value = transition.to_state & 0xFFFFFFFF
        if state_value not in existing_states:
            supplemental_states.add(state_value)

    for paths in paths_by_handler.values():
        for path in paths:
            if path.final_state is None:
                continue
            state_value = path.final_state & 0xFFFFFFFF
            if state_value not in existing_states:
                supplemental_states.add(state_value)

    for conds in conds_by_handler.values():
        for cond in conds:
            if cond.is_terminal_no_write:
                continue
            state_value = cond.target_state & 0xFFFFFFFF
            if state_value not in existing_states:
                supplemental_states.add(state_value)

    for edge in dag.edges:
        if edge.target_state is None:
            continue
        state_value = edge.target_state & 0xFFFFFFFF
        if state_value in existing_states:
            continue
        if edge.target_key is not None and edge.target_key.state_const == state_value:
            continue
        supplemental_states.add(state_value)

        candidate_anchor: int | None = None
        if (
            edge.source_anchor.kind == RedirectSourceKind.CONDITIONAL_BRANCH
            and edge.source_anchor.branch_arm is not None
        ):
            branch_block = flow_graph.get_block(edge.source_anchor.block_serial)
            if (
                branch_block is not None
                and edge.source_anchor.branch_arm < len(branch_block.succs)
            ):
                candidate_anchor = branch_block.succs[edge.source_anchor.branch_arm]
        if candidate_anchor is None:
            tail_block = (
                edge.ordered_path[-1]
                if edge.ordered_path
                else edge.source_anchor.block_serial
            )
            tail_snapshot = flow_graph.get_block(tail_block)
            if tail_snapshot is not None:
                succ_candidates = [
                    succ
                    for succ in tail_snapshot.succs
                    if succ not in edge.ordered_path
                ]
                if len(succ_candidates) == 1:
                    candidate_anchor = succ_candidates[0]
                elif len(tail_snapshot.succs) == 1:
                    candidate_anchor = tail_snapshot.succs[0]
        if candidate_anchor is not None:
            collapsed_target_anchors.setdefault(state_value, set()).add(
                candidate_anchor
            )

    return supplemental_states, collapsed_target_anchors


def build_live_linearized_state_dag_from_graph(
    flow_graph: FlowGraph,
    transition_result: TransitionResult,
    *,
    dispatcher_entry_serial: int,
    state_var_stkoff: int | None = None,
    state_var_lvar_idx: int | None = None,
    pre_header_serial: int | None = None,
    initial_state: int | None = None,
    handler_range_map: Mapping[int, tuple[int | None, int | None]] | None = None,
    bst_node_blocks: tuple[int, ...] = (),
    diagnostics: tuple[str, ...] = (),
    dispatcher: IntervalDispatcher | None = None,
    mba: object | None = None,
) -> LinearizedStateDag:
    """Build a live DAG from graph-backed analysis inputs.

    This is the shared semantic-graph builder for both recon dumping and
    strategy planning. When ``mba`` and ``state_var_stkoff`` are available,
    it enriches the base transition report with path-evaluated conditional and
    fallback states before materializing the DAG.
    """

    report = build_dispatcher_transition_report_from_graph(
        flow_graph=flow_graph,
        transition_result=transition_result,
        dispatcher_entry_serial=dispatcher_entry_serial,
        state_var_stkoff=state_var_stkoff,
        state_var_lvar_idx=state_var_lvar_idx,
        pre_header_serial=pre_header_serial,
        initial_state=initial_state,
        handler_range_map=handler_range_map,
        bst_node_blocks=bst_node_blocks,
        diagnostics=diagnostics,
    )

    handler_paths_by_handler: dict[int, tuple[HandlerPathResult, ...]] = {}
    conditional_transitions_by_handler: dict[
        int, tuple[ConditionalTransition, ...]
    ] = {}

    if state_var_stkoff is None or mba is None:
        return build_linearized_state_dag_from_graph(
            flow_graph,
            report,
            transition_result,
            dispatcher=dispatcher,
            handler_paths_by_handler=handler_paths_by_handler,
            conditional_transitions_by_handler=conditional_transitions_by_handler,
        )

    handler_entry_blocks = {
        handler.check_block for handler in transition_result.handlers.values()
    }
    state_constants = set(transition_result.handlers.keys())

    for row in report.rows:
        incoming_state = row.state_const
        if incoming_state is None:
            incoming_state = row.state_range_lo
        if incoming_state is None:
            continue

        paths = tuple(
            evaluate_handler_paths(
                mba,
                row.handler_serial,
                incoming_state,
                set(report.bst_node_blocks),
                state_var_stkoff,
                handler_entry_blocks,
            )
        )
        handler_paths_by_handler[row.handler_serial] = paths
        conds = tuple(
            detect_conditional_transitions(
                row.handler_serial,
                list(paths),
                state_constants,
                flow_graph,
                incoming_state=incoming_state,
            )
        )
        if conds:
            conditional_transitions_by_handler[row.handler_serial] = conds

    report_with_supplemental = report
    dag = build_linearized_state_dag_from_graph(
        flow_graph,
        report_with_supplemental,
        transition_result,
        dispatcher=dispatcher,
        handler_paths_by_handler=handler_paths_by_handler,
        conditional_transitions_by_handler=conditional_transitions_by_handler,
    )

    while True:
        existing_states = {
            row.state_const & 0xFFFFFFFF
            for row in report_with_supplemental.rows
            if row.state_const is not None
        }
        known_entry_anchors = {
            row.handler_serial for row in report_with_supplemental.rows
        }
        existing_rows_by_handler = {
            row.handler_serial: row for row in report_with_supplemental.rows
        }
        supplemental_states, collapsed_target_anchors = _discover_supplemental_states(
            report_with_supplemental,
            transition_result,
            handler_paths_by_handler,
            conditional_transitions_by_handler,
            dag,
            flow_graph,
        )
        pending_states = sorted(state for state in supplemental_states if state not in existing_states)
        if not pending_states:
            return dag

        supplemental_rows: list[TransitionRow] = []
        for state_value in pending_states:
            anchor_candidates = collapsed_target_anchors.get(state_value, set())
            preferred_anchor: int | None = None
            preferred_paths: tuple[HandlerPathResult, ...] = ()
            preferred_conds: tuple[ConditionalTransition, ...] = ()
            if len(anchor_candidates) == 1:
                candidate_anchor = next(iter(anchor_candidates))
                if candidate_anchor not in set(report_with_supplemental.bst_node_blocks):
                    candidate_paths = tuple(
                        evaluate_handler_paths(
                            mba,
                            candidate_anchor,
                            state_value,
                            set(report_with_supplemental.bst_node_blocks),
                            state_var_stkoff,
                            handler_entry_blocks,
                        )
                    )
                    candidate_normalized_states = {
                        path.final_state & 0xFFFFFFFF
                        for path in candidate_paths
                        if path.final_state is not None
                    }
                    candidate_normalized_states.update(
                        value & 0xFFFFFFFF
                        for path in candidate_paths
                        for _, value in path.state_writes
                    )
                    if candidate_paths and candidate_normalized_states & existing_states:
                        preferred_anchor = candidate_anchor
                        preferred_paths = candidate_paths
                        preferred_conds = tuple(
                            detect_conditional_transitions(
                                candidate_anchor,
                                list(candidate_paths),
                                state_constants
                                | existing_states
                                | set(pending_states),
                                flow_graph,
                                incoming_state=state_value,
                            )
                        )

            anchor = _resolve_fallback_anchor_from_exact_cover(
                state_value,
                report_with_supplemental,
                flow_graph,
            )
            if anchor is None:
                anchor = _resolve_range_backed_anchor(
                    state_value,
                    dict(report_with_supplemental.handler_range_map),
                    known_entry_anchors=known_entry_anchors,
                )
            if anchor is None and len(anchor_candidates) == 1:
                anchor = next(iter(anchor_candidates))
            if anchor is None and dispatcher is not None:
                row = dispatcher.lookup_row(state_value)
                anchor = row.target if row is not None else None
            if preferred_anchor is not None:
                anchor = preferred_anchor
            if anchor is None:
                continue

            if preferred_anchor is not None:
                paths = preferred_paths
                conds = preferred_conds
                handler_paths_by_handler[anchor] = paths
                if conds:
                    conditional_transitions_by_handler[anchor] = conds
                elif anchor in conditional_transitions_by_handler:
                    del conditional_transitions_by_handler[anchor]

                synthetic_kind = TransitionKind.UNKNOWN
                transition_label = "synthetic fallback"
                if any(not cond.is_terminal_no_write for cond in conds):
                    synthetic_kind = TransitionKind.CONDITIONAL
                    transition_label = "conditional fallback"
                elif any(path.final_state is not None for path in paths):
                    synthetic_kind = TransitionKind.TRANSITION
                    transition_label = "resolved fallback"
                elif any(path.final_state is None for path in paths):
                    synthetic_kind = TransitionKind.EXIT
                    transition_label = "fallback exit"

                conditional_states = tuple(
                    sorted(
                        {
                            cond.target_state
                            for cond in conds
                            if not cond.is_terminal_no_write
                        }
                    )
                )
                next_state = next(
                    (
                        path.final_state
                        for path in paths
                        if path.final_state is not None and not conditional_states
                    ),
                    None,
                )
                chain = tuple(paths[0].ordered_path[:4]) if paths else (anchor,)
            elif anchor in known_entry_anchors:
                base_row = existing_rows_by_handler.get(anchor)
                paths = handler_paths_by_handler.get(anchor, ())
                conds = conditional_transitions_by_handler.get(anchor, ())
                synthetic_kind = (
                    base_row.kind if base_row is not None else TransitionKind.UNKNOWN
                )
                transition_label = (
                    f"range alias of {base_row.state_label}"
                    if base_row is not None
                    else "range alias"
                )
                conditional_states = (
                    base_row.conditional_states if base_row is not None else ()
                )
                next_state = base_row.next_state if base_row is not None else None
                chain = base_row.chain_preview if base_row is not None else (anchor,)
            else:
                paths = tuple(
                    evaluate_handler_paths(
                        mba,
                        anchor,
                        state_value,
                        set(report_with_supplemental.bst_node_blocks),
                        state_var_stkoff,
                        handler_entry_blocks,
                    )
                )
                handler_paths_by_handler[anchor] = paths
                conds = tuple(
                    detect_conditional_transitions(
                        anchor,
                        list(paths),
                        state_constants | existing_states | set(pending_states),
                        flow_graph,
                        incoming_state=state_value,
                    )
                )
                if conds:
                    conditional_transitions_by_handler[anchor] = conds

                synthetic_kind = TransitionKind.UNKNOWN
                transition_label = "synthetic fallback"
                if any(not cond.is_terminal_no_write for cond in conds):
                    synthetic_kind = TransitionKind.CONDITIONAL
                    transition_label = "conditional fallback"
                elif any(path.final_state is not None for path in paths):
                    synthetic_kind = TransitionKind.TRANSITION
                    transition_label = "resolved fallback"
                elif any(path.final_state is None for path in paths):
                    synthetic_kind = TransitionKind.EXIT
                    transition_label = "fallback exit"

                conditional_states = tuple(
                    sorted(
                        {
                            cond.target_state
                            for cond in conds
                            if not cond.is_terminal_no_write
                        }
                    )
                )
                next_state = next(
                    (
                        path.final_state
                        for path in paths
                        if path.final_state is not None and not conditional_states
                    ),
                    None,
                )
                chain = tuple(paths[0].ordered_path[:4]) if paths else (anchor,)

            supplemental_rows.append(
                TransitionRow(
                    state_const=state_value,
                    state_range_lo=None,
                    state_range_hi=None,
                    handler_serial=anchor,
                    kind=synthetic_kind,
                    next_state=next_state,
                    conditional_states=conditional_states,
                    state_label=f"State 0x{state_value:08x}",
                    transition_label=transition_label,
                    chain_preview=chain,
                    path=TransitionPath(
                        handler_serial=anchor,
                        chain=chain,
                        next_state=next_state,
                        conditional_states=conditional_states,
                        back_edge=bool(next_state is not None or conditional_states),
                        reaches_exit_block=any(
                            path.final_state is None for path in paths
                        ),
                        classified_exit=synthetic_kind == TransitionKind.EXIT,
                        unresolved=synthetic_kind == TransitionKind.UNKNOWN,
                    ),
                )
            )

        if not supplemental_rows:
            return dag

        rows = tuple(
            sorted(
                (*report_with_supplemental.rows, *supplemental_rows),
                key=lambda row: (
                    row.state_const is None,
                    row.state_const if row.state_const is not None else 0xFFFFFFFF,
                    row.handler_serial,
                ),
            )
        )
        report_with_supplemental = DispatcherTransitionReport(
            dispatcher_entry_serial=report_with_supplemental.dispatcher_entry_serial,
            state_var_stkoff=report_with_supplemental.state_var_stkoff,
            state_var_lvar_idx=report_with_supplemental.state_var_lvar_idx,
            pre_header_serial=report_with_supplemental.pre_header_serial,
            initial_state=report_with_supplemental.initial_state,
            handler_state_map=report_with_supplemental.handler_state_map,
            handler_range_map=report_with_supplemental.handler_range_map,
            bst_node_blocks=report_with_supplemental.bst_node_blocks,
            rows=rows,
            summary=_summarize_rows(rows),
            diagnostics=report_with_supplemental.diagnostics,
        )
        dag = build_linearized_state_dag_from_graph(
            flow_graph,
            report_with_supplemental,
            transition_result,
            dispatcher=dispatcher,
            handler_paths_by_handler=handler_paths_by_handler,
            conditional_transitions_by_handler=conditional_transitions_by_handler,
        )


def build_linearized_state_dag_from_graph(
    flow_graph: FlowGraph,
    report: DispatcherTransitionReport,
    transition_result: TransitionResult,
    *,
    dispatcher: IntervalDispatcher | None = None,
    handler_paths_by_handler: dict[int, tuple[HandlerPathResult, ...]] | None = None,
    conditional_transitions_by_handler: dict[
        int, tuple[ConditionalTransition, ...]
    ]
    | None = None,
) -> LinearizedStateDag:
    """Build a state-level DAG from structured graph-backed inputs."""
    paths_by_handler = {
        serial: tuple(paths)
        for serial, paths in (handler_paths_by_handler or {}).items()
    }
    conds_by_handler = {
        serial: tuple(conds)
        for serial, conds in (conditional_transitions_by_handler or {}).items()
    }
    known_state_by_entry = {
        row.handler_serial: row.state_const
        for row in report.rows
        if row.state_const is not None
    }
    for handler_serial, paths in list(paths_by_handler.items()):
        synthetic_path = _find_sibling_branch_handoff_path(
            handler_serial,
            paths,
            flow_graph,
            known_state_by_entry=known_state_by_entry,
        )
        if synthetic_path is None:
            continue
        existing_signatures = {
            (path.exit_block, path.final_state, tuple(path.ordered_path))
            for path in paths
        }
        synthetic_signature = (
            synthetic_path.exit_block,
            synthetic_path.final_state,
            tuple(synthetic_path.ordered_path),
        )
        if synthetic_signature in existing_signatures:
            continue
        paths_by_handler[handler_serial] = (*paths, synthetic_path)

    shared_blocks = _compute_shared_blocks(paths_by_handler)
    _, resolve_handler = _build_state_resolver(report, transition_result, dispatcher)

    nodes: list[StateDagNode] = []
    primary_node_by_handler: dict[int, StateDagNode] = {}
    node_by_state: dict[int, StateDagNode] = {}

    for row in report.rows:
        node_kind = _node_kind_for_handler(report, row.handler_serial)
        paths = paths_by_handler.get(row.handler_serial, ())
        conds = conds_by_handler.get(row.handler_serial, ())
        local_blocks = _collect_local_block_order(
            row.handler_serial,
            transition_result,
            row.state_const,
            paths,
            conds,
        )

        terminal_exit_blocks = {
            path.exit_block for path in paths if path.final_state is None
        }
        branch_blocks = {cond.branch_block for cond in conds}
        goto_targets: set[int] = set()
        join_blocks: set[int] = set()
        for path in paths:
            for source_block, target_block in zip(
                path.ordered_path, path.ordered_path[1:]
            ):
                blk = flow_graph.get_block(source_block)
                if blk is None:
                    continue
                if len(blk.succs) == 1:
                    goto_targets.add(target_block)
                target_snapshot = flow_graph.get_block(target_block)
                if target_snapshot is not None and len(target_snapshot.preds) > 1:
                    join_blocks.add(target_block)

        local_segments = tuple(
            StateLocalSegment(
                segment_id=_segment_id(block_serial),
                kind=_classify_segment_kind(
                    block_serial,
                    flow_graph,
                    branch_blocks=branch_blocks,
                    shared_blocks=shared_blocks,
                    terminal_exit_blocks=terminal_exit_blocks,
                    join_blocks=join_blocks,
                    goto_targets=goto_targets,
                ),
                blocks=(block_serial,),
            )
            for block_serial in local_blocks
        )
        local_edges = _build_local_edges(
            local_blocks,
            paths,
            flow_graph,
            shared_blocks=shared_blocks,
            terminal_exit_blocks=terminal_exit_blocks,
        )

        shared_suffix_blocks = tuple(
            block_serial
            for block_serial in local_blocks
            if block_serial in shared_blocks and block_serial != row.handler_serial
        )
        exclusive_blocks = tuple(
            block_serial
            for block_serial in local_blocks
            if block_serial not in shared_blocks
        )

        node = StateDagNode(
            key=StateDagNodeKey(
                handler_serial=row.handler_serial,
                state_const=row.state_const,
                range_lo=row.state_range_lo,
                range_hi=row.state_range_hi,
            ),
            kind=node_kind,
            state_label=_format_state_label(
                row.state_const,
                row.state_range_lo,
                row.state_range_hi,
                node_kind,
            ),
            handler_serial=row.handler_serial,
            entry_anchor=row.handler_serial,
            owned_blocks=local_blocks,
            exclusive_blocks=exclusive_blocks,
            shared_suffix_blocks=shared_suffix_blocks,
            local_segments=local_segments,
            local_edges=local_edges,
        )
        nodes.append(node)
        primary_node_by_handler.setdefault(row.handler_serial, node)
        if row.state_const is not None:
            node_by_state[row.state_const] = node

    def resolve_target_node(
        target_handler_serial: int | None,
        target_state: int | None,
    ) -> StateDagNode | None:
        if target_state is not None:
            direct_node = node_by_state.get(target_state & 0xFFFFFFFF)
            if direct_node is not None:
                return direct_node
        if target_handler_serial is None:
            return None
        return primary_node_by_handler.get(target_handler_serial)

    edges: list[StateDagEdge] = []
    seen_edge_keys: set[
        tuple[
            SemanticEdgeKind,
            StateDagNodeKey,
            StateDagNodeKey | None,
            int | None,
            int | None,
            RedirectSourceKind,
            int,
            int | None,
        ]
    ] = set()
    terminal_paths_consumed: defaultdict[int, set[tuple[int, tuple[int, ...]]]] = (
        defaultdict(set)
    )

    for state_const, handler in transition_result.handlers.items():
        source_node = primary_node_by_handler.get(handler.check_block)
        if source_node is None:
            continue
        paths = paths_by_handler.get(handler.check_block, ())
        synthesized_targets = {
            path.final_state & 0xFFFFFFFF
            for path in paths
            if path.final_state is not None and not path.state_writes
        }

        for transition in handler.transitions:
            if transition.is_conditional:
                continue
            target_handler_serial = resolve_handler(transition.to_state)
            target_node = resolve_target_node(target_handler_serial, transition.to_state)
            matched_path = _select_path_for_state(paths, transition.to_state)
            if matched_path is None and synthesized_targets:
                continue
            ordered_path = (
                tuple(matched_path.ordered_path) if matched_path is not None else ()
            )
            source_anchor = StateRedirectAnchor(
                kind=RedirectSourceKind.UNCONDITIONAL,
                block_serial=transition.from_block,
            )
            edge = StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_node.key,
                target_key=target_node.key if target_node is not None else None,
                target_state=transition.to_state,
                target_entry_anchor=(
                    target_node.entry_anchor
                    if target_node is not None
                    else target_handler_serial
                ),
                target_label=(
                    target_node.state_label
                    if target_node is not None
                    else (
                        f"blk[{target_handler_serial}]"
                        if target_handler_serial is not None
                        else f"0x{transition.to_state:08X}"
                    )
                ),
                source_anchor=source_anchor,
                ordered_path=ordered_path,
            )
            edge_key = (
                edge.kind,
                edge.source_key,
                edge.target_key,
                edge.target_state,
                edge.target_entry_anchor,
                edge.source_anchor.kind,
                edge.source_anchor.block_serial,
                edge.source_anchor.branch_arm,
            )
            if edge_key in seen_edge_keys:
                continue
            seen_edge_keys.add(edge_key)
            edges.append(edge)
            if matched_path is not None:
                terminal_paths_consumed[handler.check_block].add(
                    (matched_path.exit_block, tuple(matched_path.ordered_path))
                )

    for handler_serial, conds in conds_by_handler.items():
        source_node = primary_node_by_handler.get(handler_serial)
        if source_node is None:
            continue
        paths = paths_by_handler.get(handler_serial, ())
        for cond in conds:
            kind = (
                SemanticEdgeKind.CONDITIONAL_RETURN
                if cond.is_terminal_no_write
                else SemanticEdgeKind.CONDITIONAL_TRANSITION
            )
            target_handler_serial = (
                resolve_handler(cond.target_state)
                if not cond.is_terminal_no_write
                else None
            )
            target_node = (
                resolve_target_node(target_handler_serial, cond.target_state)
                if not cond.is_terminal_no_write
                else None
            )
            matched_path = _select_path_for_state(paths, cond.target_state)
            ordered_path = (
                tuple(matched_path.ordered_path) if matched_path is not None else ()
            )
            source_anchor = StateRedirectAnchor(
                kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                block_serial=cond.branch_block,
                branch_arm=cond.branch_arm,
            )
            edge = StateDagEdge(
                kind=kind,
                source_key=source_node.key,
                target_key=target_node.key if target_node is not None else None,
                target_state=None if cond.is_terminal_no_write else cond.target_state,
                target_entry_anchor=(
                    target_node.entry_anchor
                    if target_node is not None
                    else target_handler_serial
                ),
                target_label=(
                    "RETURN"
                    if cond.is_terminal_no_write
                    else (
                        target_node.state_label
                        if target_node is not None
                        else (
                            f"blk[{target_handler_serial}]"
                            if target_handler_serial is not None
                            else f"0x{cond.target_state:08X}"
                        )
                    )
                ),
                source_anchor=source_anchor,
                ordered_path=ordered_path,
            )
            edge_key = (
                edge.kind,
                edge.source_key,
                edge.target_key,
                edge.target_state,
                edge.target_entry_anchor,
                edge.source_anchor.kind,
                edge.source_anchor.block_serial,
                edge.source_anchor.branch_arm,
            )
            if edge_key in seen_edge_keys:
                continue
            seen_edge_keys.add(edge_key)
            edges.append(edge)
            if matched_path is not None:
                terminal_paths_consumed[handler_serial].add(
                    (matched_path.exit_block, tuple(matched_path.ordered_path))
                )

    for handler_serial, paths in paths_by_handler.items():
        source_node = primary_node_by_handler.get(handler_serial)
        if source_node is None:
            continue
        for path in paths:
            path_signature = (path.exit_block, tuple(path.ordered_path))
            if path_signature in terminal_paths_consumed[handler_serial]:
                continue

            branch_anchor = _find_path_branch_anchor(path, paths, flow_graph)
            source_state = source_node.key.state_const

            if path.final_state is None:
                edge_kind = _infer_terminal_edge_kind(path, flow_graph, branch_anchor)
                target_label = (
                    "RETURN"
                    if edge_kind == SemanticEdgeKind.CONDITIONAL_RETURN
                    else "EXIT_ROUTINE"
                )
                if edge_kind == SemanticEdgeKind.UNKNOWN:
                    target_label = "UNKNOWN"
                edge = StateDagEdge(
                    kind=edge_kind,
                    source_key=source_node.key,
                    target_key=None,
                    target_state=None,
                    target_entry_anchor=None,
                    target_label=target_label,
                    source_anchor=(
                        branch_anchor
                        if branch_anchor is not None
                        else StateRedirectAnchor(
                            kind=RedirectSourceKind.EXIT_BLOCK,
                            block_serial=path.exit_block,
                        )
                    ),
                    ordered_path=tuple(path.ordered_path),
                )
            else:
                if (
                    branch_anchor is not None
                    and source_state is not None
                    and (path.final_state & 0xFFFFFFFF)
                    == (source_state & 0xFFFFFFFF)
                    and not _path_has_state_write_at_or_after_block(
                        path, branch_anchor.block_serial
                    )
                ):
                    continue
                target_handler_serial = resolve_handler(path.final_state)
                target_node = resolve_target_node(
                    target_handler_serial, path.final_state
                )
                source_anchor = (
                    branch_anchor
                    if branch_anchor is not None
                    else StateRedirectAnchor(
                        kind=RedirectSourceKind.EXIT_BLOCK,
                        block_serial=path.exit_block,
                    )
                )
                edge = StateDagEdge(
                    kind=(
                        SemanticEdgeKind.CONDITIONAL_TRANSITION
                        if branch_anchor is not None
                        and target_handler_serial is not None
                        else (
                            SemanticEdgeKind.TRANSITION
                            if target_handler_serial is not None
                            else SemanticEdgeKind.UNKNOWN
                        )
                    ),
                    source_key=source_node.key,
                    target_key=target_node.key if target_node is not None else None,
                    target_state=path.final_state,
                    target_entry_anchor=(
                        target_node.entry_anchor
                        if target_node is not None
                        else target_handler_serial
                    ),
                    target_label=(
                        target_node.state_label
                        if target_node is not None
                        else (
                            f"blk[{target_handler_serial}]"
                            if target_handler_serial is not None
                            else f"0x{path.final_state:08X}"
                        )
                    ),
                    source_anchor=source_anchor,
                    ordered_path=tuple(path.ordered_path),
                )

            edge_key = (
                edge.kind,
                edge.source_key,
                edge.target_key,
                edge.target_state,
                edge.target_entry_anchor,
                edge.source_anchor.kind,
                edge.source_anchor.block_serial,
                edge.source_anchor.branch_arm,
            )
            if edge_key in seen_edge_keys:
                continue
            seen_edge_keys.add(edge_key)
            edges.append(edge)

    primary_edges_by_source: dict[StateDagNodeKey, list[StateDagEdge]] = defaultdict(list)
    for edge in edges:
        primary_edges_by_source[edge.source_key].append(edge)

    for node in nodes:
        primary_node = primary_node_by_handler.get(node.handler_serial)
        if primary_node is None or primary_node.key == node.key:
            continue
        for edge in primary_edges_by_source.get(primary_node.key, ()):
            alias_edge = StateDagEdge(
                kind=edge.kind,
                source_key=node.key,
                target_key=edge.target_key,
                target_state=edge.target_state,
                target_entry_anchor=edge.target_entry_anchor,
                target_label=edge.target_label,
                source_anchor=edge.source_anchor,
                ordered_path=edge.ordered_path,
            )
            edge_key = (
                alias_edge.kind,
                alias_edge.source_key,
                alias_edge.target_key,
                alias_edge.target_state,
                alias_edge.target_entry_anchor,
                alias_edge.source_anchor.kind,
                alias_edge.source_anchor.block_serial,
                alias_edge.source_anchor.branch_arm,
            )
            if edge_key in seen_edge_keys:
                continue
            seen_edge_keys.add(edge_key)
            edges.append(alias_edge)

    return LinearizedStateDag(
        dispatcher_entry_serial=report.dispatcher_entry_serial,
        state_var_stkoff=report.state_var_stkoff,
        pre_header_serial=report.pre_header_serial,
        initial_state=report.initial_state,
        bst_node_blocks=report.bst_node_blocks,
        nodes=tuple(nodes),
        edges=tuple(edges),
        diagnostics=report.diagnostics,
    )


def _format_anchor(anchor: StateRedirectAnchor) -> str:
    if (
        anchor.kind == RedirectSourceKind.CONDITIONAL_BRANCH
        and anchor.branch_arm is not None
    ):
        arm = "fallthrough" if anchor.branch_arm == 0 else "taken"
        return f"blk[{anchor.block_serial}].{arm}"
    return f"blk[{anchor.block_serial}]"


def _format_local_edge(edge: StateLocalEdge) -> str:
    label = edge.kind.name.lower()
    return f"{edge.source_segment_id} -{label}-> {edge.target_segment_id}"


def _format_edge_target(edge: StateDagEdge) -> str:
    if edge.target_state is None:
        return edge.target_label
    raw_target = f"0x{edge.target_state:08X}"
    if edge.target_label == raw_target:
        return raw_target
    return f"{raw_target} via {edge.target_label}"


def _node_sort_key(node: StateDagNode) -> tuple[int, int, int]:
    state_rank = (
        node.key.state_const if node.key.state_const is not None else 0xFFFFFFFF
    )
    range_rank = node.key.range_lo if node.key.range_lo is not None else 0xFFFFFFFF
    return (state_rank, range_rank, node.handler_serial)


def _dot_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _dot_state_id(key: StateDagNodeKey) -> str:
    if key.state_const is not None:
        return f"state_{key.state_const:08X}_{key.handler_serial}"
    if key.range_lo is not None and key.range_hi is not None:
        return f"state_range_{key.range_lo:08X}_{key.range_hi:08X}_{key.handler_serial}"
    return f"state_unknown_{key.handler_serial}"


def _dot_segment_id(key: StateDagNodeKey, block_serial: int) -> str:
    return f"{_dot_state_id(key)}_blk_{block_serial}"


def _dot_terminal_id(kind: SemanticEdgeKind) -> str:
    return f"terminal_{kind.name.lower()}"


def _dot_edge_attributes(edge: StateDagEdge) -> list[str]:
    label_lines = [edge.kind.name.lower(), f"src={_format_anchor(edge.source_anchor)}"]
    if edge.ordered_path:
        path_text = ", ".join(str(block) for block in edge.ordered_path)
        label_lines.append(f"path=[{path_text}]")
    attrs = [f'label="{_dot_escape(chr(10).join(label_lines))}"']
    if edge.kind == SemanticEdgeKind.CONDITIONAL_TRANSITION:
        attrs.append("color=blue")
    elif edge.kind == SemanticEdgeKind.CONDITIONAL_RETURN:
        attrs.append("color=darkgreen")
    elif edge.kind == SemanticEdgeKind.EXIT_ROUTINE:
        attrs.append("color=orange")
    elif edge.kind == SemanticEdgeKind.UNKNOWN:
        attrs.append("style=dashed")
        attrs.append("color=red")
    return attrs


def render_linearized_state_dag_dot(
    dag: LinearizedStateDag,
    *,
    expanded: bool = False,
) -> str:
    """Render the DAG as a Graphviz DOT graph."""
    lines: list[str] = ["digraph linearized_state_dag {"]
    lines.append("    rankdir=LR;")
    lines.append("    graph [compound=true];")
    lines.append("    node [shape=record];")
    lines.append("")

    node_by_key = {node.key: node for node in dag.nodes}
    sorted_nodes = sorted(dag.nodes, key=_node_sort_key)
    terminal_nodes_needed: dict[SemanticEdgeKind, str] = {}
    raw_target_nodes: dict[tuple[int, str], str] = {}

    if dag.initial_state is not None:
        start_id = None
        for node in sorted_nodes:
            if node.key.state_const == dag.initial_state:
                start_id = _dot_state_id(node.key)
                break
        if start_id is None:
            for node in sorted_nodes:
                lo = node.key.range_lo
                hi = node.key.range_hi
                if lo is None or hi is None:
                    continue
                if lo <= dag.initial_state <= hi:
                    start_id = _dot_state_id(node.key)
                    break
        if start_id is not None:
            lines.append("    START [shape=point];")
            lines.append(f"    START -> {start_id};")
            lines.append("")

    if not expanded:
        for node in sorted_nodes:
            attrs = [
                f'label="{_dot_escape(f"{node.state_label}\\nblk[{node.entry_anchor}]")}"'
            ]
            if node.kind == StateNodeKind.RANGE_BACKED:
                attrs.extend(["style=filled", "fillcolor=lightblue"])
            lines.append(f"    {_dot_state_id(node.key)} [{', '.join(attrs)}];")
        lines.append("")
    else:
        for node in sorted_nodes:
            cluster_id = f"cluster_{_dot_state_id(node.key)}"
            header_id = _dot_state_id(node.key)
            cluster_label = (
                f"{node.state_label}\\nentry blk[{node.entry_anchor}] [{node.kind.name.lower()}]"
            )
            lines.append(f"    subgraph {cluster_id} {{")
            lines.append(f'        label="{_dot_escape(cluster_label)}";')
            lines.append("        color=lightgrey;")
            header_attrs = [
                f'label="{_dot_escape(f"{node.state_label}\\nentry blk[{node.entry_anchor}]")}"'
            ]
            if node.kind == StateNodeKind.RANGE_BACKED:
                header_attrs.extend(["style=filled", "fillcolor=lightblue"])
            lines.append(f"        {header_id} [{', '.join(header_attrs)}];")
            for segment in node.local_segments:
                seg_id = _dot_segment_id(node.key, segment.blocks[0])
                seg_label = f"{segment.segment_id}\\n{segment.kind.name.lower()}"
                seg_attrs = [f'label="{_dot_escape(seg_label)}"', "shape=box"]
                if segment.kind == LocalSegmentKind.SHARED_SUFFIX:
                    seg_attrs.extend(["style=filled", "fillcolor=lightgrey"])
                elif segment.kind == LocalSegmentKind.TERMINAL_SUFFIX:
                    seg_attrs.extend(["style=filled", "fillcolor=lightgreen"])
                elif segment.kind == LocalSegmentKind.BRANCH:
                    seg_attrs.extend(["style=filled", "fillcolor=lightyellow"])
                lines.append(f"        {seg_id} [{', '.join(seg_attrs)}];")
            entry_segment_id = _dot_segment_id(node.key, node.entry_anchor)
            if any(segment.blocks[0] == node.entry_anchor for segment in node.local_segments):
                lines.append(
                    f"        {header_id} -> {entry_segment_id} [style=dotted, arrowhead=none];"
                )
            lines.append("    }")
        lines.append("")

        for node in sorted_nodes:
            for local_edge in node.local_edges:
                source_block = int(local_edge.source_segment_id[4:-1])
                target_block = int(local_edge.target_segment_id[4:-1])
                source_id = _dot_segment_id(node.key, source_block)
                target_id = _dot_segment_id(node.key, target_block)
                attrs = [f'label="{local_edge.kind.name.lower()}"', "color=gray50"]
                lines.append(f"    {source_id} -> {target_id} [{', '.join(attrs)}];")
        lines.append("")

    for edge in dag.edges:
        if edge.target_key is None:
            if edge.target_state is not None:
                raw_label = _format_edge_target(edge)
                raw_key = (edge.target_state, raw_label)
                target_id = raw_target_nodes.get(raw_key)
                if target_id is None:
                    target_id = f"raw_target_{edge.target_state:08X}"
                    raw_target_nodes[raw_key] = target_id
                    lines.append(
                        f'    {target_id} [label="{_dot_escape(raw_label)}", style=dashed];'
                    )
            else:
                target_id = terminal_nodes_needed.get(edge.kind)
                if target_id is None:
                    target_id = _dot_terminal_id(edge.kind)
                    terminal_nodes_needed[edge.kind] = target_id
                    term_label = edge.target_label
                    term_attrs = [f'label="{_dot_escape(term_label)}"']
                    if edge.kind == SemanticEdgeKind.CONDITIONAL_RETURN:
                        term_attrs.extend(["shape=oval", "style=filled", "fillcolor=lightgreen"])
                    elif edge.kind == SemanticEdgeKind.EXIT_ROUTINE:
                        term_attrs.extend(["shape=oval", "style=filled", "fillcolor=orange"])
                    else:
                        term_attrs.extend(["shape=oval", "style=filled", "fillcolor=lightyellow"])
                    lines.append(f"    {target_id} [{', '.join(term_attrs)}];")
        else:
            target_id = _dot_state_id(edge.target_key)

        if expanded:
            source_node = node_by_key[edge.source_key]
            if any(
                segment.blocks[0] == edge.source_anchor.block_serial
                for segment in source_node.local_segments
            ):
                source_id = _dot_segment_id(
                    edge.source_key, edge.source_anchor.block_serial
                )
            else:
                source_id = _dot_state_id(edge.source_key)
        else:
            source_id = _dot_state_id(edge.source_key)

        lines.append(
            f"    {source_id} -> {target_id} [{', '.join(_dot_edge_attributes(edge))}];"
        )

    lines.append("}")
    return "\n".join(lines)


def render_linearized_state_dag(dag: LinearizedStateDag) -> str:
    """Render a human-readable dump of a state-level DAG."""
    lines: list[str] = []
    node_by_key = {node.key: node for node in dag.nodes}
    edges_by_source: dict[StateDagNodeKey, list[StateDagEdge]] = defaultdict(list)
    for edge in dag.edges:
        edges_by_source[edge.source_key].append(edge)

    start_key: StateDagNodeKey | None = None
    if dag.initial_state is not None:
        for node in dag.nodes:
            if node.key.state_const == dag.initial_state:
                start_key = node.key
                break
        if start_key is None:
            for node in dag.nodes:
                lo = node.key.range_lo
                hi = node.key.range_hi
                if lo is None or hi is None:
                    continue
                if lo <= dag.initial_state <= hi:
                    start_key = node.key
                    break

    queue: deque[StateDagNodeKey] = deque()
    visited: set[StateDagNodeKey] = set()
    if start_key is not None:
        queue.append(start_key)
        visited.add(start_key)

    for node in sorted(dag.nodes, key=_node_sort_key):
        if node.key not in visited:
            queue.append(node.key)
            visited.add(node.key)

    lines.append(
        "=== LINEARIZED STATE DAG ==="
        if dag.initial_state is None
        else f"=== LINEARIZED STATE DAG (starting from 0x{dag.initial_state:08X}) ==="
    )
    lines.append("")

    step_index = 0
    rendered: set[StateDagNodeKey] = set()
    edge_counts: Counter[SemanticEdgeKind] = Counter()

    while queue:
        node_key = queue.popleft()
        if node_key in rendered:
            continue
        rendered.add(node_key)
        node = node_by_key[node_key]
        lines.append(
            f"[{step_index}] {node.state_label} -> entry blk[{node.entry_anchor}] "
            f"[{node.kind.name.lower()}]"
        )
        if node.shared_suffix_blocks:
            shared = ", ".join(f"blk[{blk}]" for blk in node.shared_suffix_blocks)
            lines.append(f"    shared-suffix: {shared}")
        if node.local_edges:
            local_cfg = ", ".join(_format_local_edge(edge) for edge in node.local_edges)
            lines.append(f"    local-cfg: {local_cfg}")

        outgoing = sorted(
            edges_by_source.get(node_key, ()),
            key=lambda edge: (
                edge.kind.value,
                edge.target_state if edge.target_state is not None else 0xFFFFFFFF,
                (
                    edge.target_entry_anchor
                    if edge.target_entry_anchor is not None
                    else 0xFFFFFFFF
                ),
            ),
        )
        if not outgoing:
            lines.append("    edge: <none>")
        for edge in outgoing:
            edge_counts[edge.kind] += 1
            path_suffix = (
                f" path={list(edge.ordered_path)}" if edge.ordered_path else ""
            )
            target_entry = (
                f" entry=blk[{edge.target_entry_anchor}]"
                if edge.target_entry_anchor is not None
                else ""
            )
            lines.append(
                f"    edge {edge.kind.name.lower()} src={_format_anchor(edge.source_anchor)}"
                f" -> {_format_edge_target(edge)}{target_entry}{path_suffix}"
            )
            if edge.target_key is not None and edge.target_key not in rendered:
                queue.append(edge.target_key)
        lines.append("")
        step_index += 1

    lines.append(
        "Summary: "
        f"{len(dag.nodes)} nodes, "
        f"{len(dag.edges)} semantic edges, "
        f"{edge_counts[SemanticEdgeKind.TRANSITION]} transitions, "
        f"{edge_counts[SemanticEdgeKind.CONDITIONAL_TRANSITION]} conditional transitions, "
        f"{edge_counts[SemanticEdgeKind.CONDITIONAL_RETURN]} conditional returns, "
        f"{edge_counts[SemanticEdgeKind.EXIT_ROUTINE]} exit routines, "
        f"{edge_counts[SemanticEdgeKind.UNKNOWN]} unknown"
    )

    return "\n".join(lines)


__all__ = [
    "LinearizedStateDag",
    "LocalEdgeKind",
    "LocalSegmentKind",
    "RedirectSourceKind",
    "SemanticEdgeKind",
    "StateDagEdge",
    "StateDagNode",
    "StateDagNodeKey",
    "StateLocalEdge",
    "StateLocalSegment",
    "StateNodeKind",
    "StateRedirectAnchor",
    "build_live_linearized_state_dag_from_graph",
    "build_linearized_state_dag_from_graph",
    "render_linearized_state_dag",
    "render_linearized_state_dag_dot",
]
