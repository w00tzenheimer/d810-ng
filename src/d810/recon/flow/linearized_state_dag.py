"""State-level DAG artifact for Hodur topology visualization."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from enum import Enum, auto

from d810.cfg.flowgraph import FlowGraph
from d810.recon.flow.interval_map import IntervalDispatcher
from d810.recon.flow.state_machine_analysis import (
    ConditionalTransition,
    HandlerPathResult,
)
from d810.recon.flow.transition_builder import TransitionResult
from d810.recon.flow.transition_report import DispatcherTransitionReport
from d810.core.typing import Callable


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
    shared_blocks = _compute_shared_blocks(paths_by_handler)
    _, resolve_handler = _build_state_resolver(report, transition_result, dispatcher)

    nodes: list[StateDagNode] = []
    node_by_handler: dict[int, StateDagNode] = {}

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
        node_by_handler[row.handler_serial] = node

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
        source_node = node_by_handler.get(handler.check_block)
        if source_node is None:
            continue
        paths = paths_by_handler.get(handler.check_block, ())

        for transition in handler.transitions:
            if transition.is_conditional:
                continue
            target_handler_serial = resolve_handler(transition.to_state)
            target_node = (
                node_by_handler.get(target_handler_serial)
                if target_handler_serial is not None
                else None
            )
            matched_path = _select_path_for_state(paths, transition.to_state)
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
        source_node = node_by_handler.get(handler_serial)
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
                node_by_handler.get(target_handler_serial)
                if target_handler_serial is not None
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
        source_node = node_by_handler.get(handler_serial)
        if source_node is None:
            continue
        for path in paths:
            path_signature = (path.exit_block, tuple(path.ordered_path))
            if path_signature in terminal_paths_consumed[handler_serial]:
                continue

            branch_anchor = _find_path_branch_anchor(path, paths, flow_graph)

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
                target_handler_serial = resolve_handler(path.final_state)
                target_node = (
                    node_by_handler.get(target_handler_serial)
                    if target_handler_serial is not None
                    else None
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


def render_linearized_state_dag(dag: LinearizedStateDag) -> str:
    """Render a human-readable dump of a state-level DAG."""
    lines: list[str] = []
    node_by_key = {node.key: node for node in dag.nodes}
    edges_by_source: dict[StateDagNodeKey, list[StateDagEdge]] = defaultdict(list)
    for edge in dag.edges:
        edges_by_source[edge.source_key].append(edge)

    def node_sort_key(node: StateDagNode) -> tuple[int, int, int]:
        state_rank = (
            node.key.state_const if node.key.state_const is not None else 0xFFFFFFFF
        )
        range_rank = node.key.range_lo if node.key.range_lo is not None else 0xFFFFFFFF
        return (state_rank, range_rank, node.handler_serial)

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

    for node in sorted(dag.nodes, key=node_sort_key):
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
                f" -> {edge.target_label}{target_entry}{path_suffix}"
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
    "build_linearized_state_dag_from_graph",
    "render_linearized_state_dag",
]
