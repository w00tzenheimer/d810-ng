"""State-level DAG artifact for Hodur topology visualization."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, replace
from enum import Enum, auto
import re

from d810.cfg.flowgraph import FlowGraph
from d810.core import logging
from d810.core.typing import Callable, Mapping
from d810.recon.flow.interval_map import IntervalDispatcher
from d810.recon.flow.dispatch_region import DispatchRegionDetector
from d810.recon.flow.state_machine_analysis import (
    ConditionalTransition,
    ExitStateKind,
    HandlerPathResult,
    classify_exit_state,
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

logger = logging.getLogger("D810.recon.flow.linearized_state_dag", logging.INFO)

_SIMPLE_CONST_ASSIGN_RE = re.compile(r"^\s*.+?=\s*(0x[0-9A-F]+)\s*$")
_SIMPLE_COMPARE_RE = re.compile(
    r"^\s*(?P<lhs>.+?)\s+"
    r"(?P<op>==|!=|>=u|<=u|>u|<u|>=s|<=s|>s|<s)\s+"
    r"(?P<rhs>.+?)\s*$"
)
_PROGRAM_LABEL_RE = re.compile(r"^(?P<label>[A-Za-z_][A-Za-z0-9_]*)\:$")
_PROGRAM_GOTO_RE = re.compile(r"\bgoto\s+(?P<label>[A-Za-z_][A-Za-z0-9_]*)\s*;")


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


class RenderOrderStrategy(str, Enum):
    """Textual rendering order for state-family dumps."""

    CATALOG = "catalog"
    SEMANTIC = "semantic"


class ProgramRenderStrategy(str, Enum):
    """How much local segment structure to preserve in program rendering."""

    LOCAL_SEGMENT_COLLAPSING = "local_segment_collapsing"
    LOCAL_SEGMENT_EXPLICIT = "local_segment_explicit"
    LOCAL_BOUNDARY_SELECTIVE = "local_boundary_selective"


class ProgramCommentMode(Enum):
    """How much renderer metadata is emitted alongside program text."""

    DEBUG_METADATA = auto()
    MINIMAL = auto()


class LabelRenderMode(Enum):
    """How top-level program labels are rendered."""

    STATE_FAMILY = auto()
    IDA_BLOCK_SERIAL = auto()


class BoundaryInlineMode(Enum):
    """How aggressively visible local boundary nodes are inlined."""

    LABELS_ONLY = auto()
    INLINE_SINGLE_LEVEL = auto()


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
    last_write_site: tuple[int, int] | None = None


@dataclass(frozen=True, slots=True)
class ProgramLabel:
    """Rendered label metadata for one state-family node."""

    rendered: str
    base: str
    entry_anchor: int
    label_num: int | None = None


@dataclass(frozen=True, slots=True)
class RenderedProgramNode:
    """One rendered label block in the linearized program."""

    node_index: int
    label_text: str
    node_kind: str
    line_start: int
    line_end: int
    state_label: str | None = None
    handler_serial: int | None = None
    entry_anchor: int | None = None
    label_num: int | None = None


@dataclass(frozen=True, slots=True)
class RenderedProgramLine:
    """One rendered output line with lightweight query metadata."""

    line_no: int
    text: str
    node_index: int | None
    indent_level: int
    line_kind: str
    target_label: str | None = None


@dataclass(frozen=True, slots=True)
class RenderedProgramSnapshot:
    """Structured snapshot of one rendered linearized program variant."""

    variant_name: str
    order_strategy: str
    program_strategy: str
    label_render_mode: str
    boundary_inline_mode: str
    comment_mode: str
    nodes: tuple[RenderedProgramNode, ...]
    lines: tuple[RenderedProgramLine, ...]


class _RenderedProgramBuilder:
    """Collect rendered program lines and node spans directly during emission."""

    def __init__(self) -> None:
        self._nodes: list[RenderedProgramNode] = []
        self._lines: list[RenderedProgramLine] = []
        self._current_node_index: int | None = None

    def __len__(self) -> int:
        return len(self._lines)

    def __iter__(self):
        for line in self._lines:
            yield line.text

    def _finalize_open_node(self) -> None:
        if self._current_node_index is None:
            return
        node = self._nodes[self._current_node_index]
        self._nodes[self._current_node_index] = RenderedProgramNode(
            node_index=node.node_index,
            label_text=node.label_text,
            node_kind=node.node_kind,
            line_start=node.line_start,
            line_end=len(self._lines),
            state_label=node.state_label,
            handler_serial=node.handler_serial,
            entry_anchor=node.entry_anchor,
            label_num=node.label_num,
        )

    def begin_node(
        self,
        label_text: str,
        *,
        node_kind: str,
        state_label: str | None = None,
        handler_serial: int | None = None,
        entry_anchor: int | None = None,
        label_num: int | None = None,
    ) -> None:
        self._finalize_open_node()
        node_index = len(self._nodes)
        self._nodes.append(
            RenderedProgramNode(
                node_index=node_index,
                label_text=label_text,
                node_kind=node_kind,
                line_start=len(self._lines) + 1,
                line_end=len(self._lines) + 1,
                state_label=state_label,
                handler_serial=handler_serial,
                entry_anchor=entry_anchor,
                label_num=label_num,
            )
        )
        self._current_node_index = node_index
        self.append(f"{label_text}:")

    def append(self, text: str) -> None:
        stripped = text.strip()
        if not stripped:
            line_kind = "blank"
        elif _PROGRAM_LABEL_RE.match(text):
            line_kind = "label"
        elif stripped.startswith("//"):
            line_kind = "comment"
        elif stripped.startswith("goto "):
            line_kind = "goto"
        elif stripped.startswith("if "):
            line_kind = "if"
        elif stripped.startswith("return "):
            line_kind = "return"
        else:
            line_kind = "statement"
        goto_match = _PROGRAM_GOTO_RE.search(text)
        indent_level = max(0, (len(text) - len(text.lstrip(" "))) // 4)
        self._lines.append(
            RenderedProgramLine(
                line_no=len(self._lines) + 1,
                text=text,
                node_index=self._current_node_index,
                indent_level=indent_level,
                line_kind=line_kind,
                target_label=goto_match.group("label") if goto_match else None,
            )
        )

    def build_snapshot(
        self,
        *,
        variant_name: str,
        order_strategy: str,
        program_strategy: str,
        label_render_mode: str,
        boundary_inline_mode: str,
        comment_mode: str,
    ) -> RenderedProgramSnapshot:
        self._finalize_open_node()
        return RenderedProgramSnapshot(
            variant_name=variant_name,
            order_strategy=order_strategy,
            program_strategy=program_strategy,
            label_render_mode=label_render_mode,
            boundary_inline_mode=boundary_inline_mode,
            comment_mode=comment_mode,
            nodes=tuple(self._nodes),
            lines=tuple(self._lines),
        )


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
    covering_row = _find_exact_cover_row(
        state_value,
        report,
        exact_handler_state_map=report.handler_state_map,
    )
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


def _find_exact_cover_row(
    state_value: int,
    report: DispatcherTransitionReport,
    *,
    exact_handler_state_map: Mapping[int, int] | None = None,
) -> TransitionRow | None:
    allowed_pairs = None
    if exact_handler_state_map is not None:
        allowed_pairs = {
            (handler_serial, state_const)
            for handler_serial, state_const in exact_handler_state_map.items()
        }
    exact_rows = sorted(
        (
            row
            for row in report.rows
            if row.state_const is not None
            and (
                allowed_pairs is None
                or (row.handler_serial, row.state_const) in allowed_pairs
            )
        ),
        key=lambda row: row.state_const if row.state_const is not None else -1,
    )
    covering_row = None
    for row in exact_rows:
        if row.state_const is None or row.state_const > state_value:
            break
        covering_row = row
    return covering_row


def _ordered_unique(values: list[int] | tuple[int, ...]) -> tuple[int, ...]:
    seen: set[int] = set()
    ordered: list[int] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return tuple(ordered)


def _resolve_owner_family_fallback(
    anchor_candidates: set[int] | tuple[int, ...],
    dag: LinearizedStateDag,
    flow_graph: FlowGraph,
) -> tuple[int, str] | None:
    """Map a synthetic alias onto the local exact handler's fallback sibling.

    Some supplemental states are not real dispatcher values. They are local
    branch artifacts inside an exact handler family, and the correct semantic
    continuation is that family's existing ``*_fallback`` node rather than a
    shared interval prelude or the dispatcher root.
    """

    if not anchor_candidates:
        return None

    def _owns_candidate(node: StateDagNode, block_serial: int) -> bool:
        if block_serial == node.entry_anchor or block_serial in node.owned_blocks:
            return True
        return any(block_serial in segment.blocks for segment in node.local_segments)

    owner_nodes: list[StateDagNode] = []
    for node in dag.nodes:
        if node.kind != StateNodeKind.EXACT or node.key.state_const is None:
            continue
        if any(_owns_candidate(node, block_serial) for block_serial in anchor_candidates):
            owner_nodes.append(node)

    if not owner_nodes:
        return None

    owner_nodes.sort(
        key=lambda node: (
            0 if any(block in node.exclusive_blocks for block in anchor_candidates) else 1,
            0 if any(block == node.entry_anchor for block in anchor_candidates) else 1,
            abs(node.entry_anchor - min(anchor_candidates)),
        )
    )
    owner = owner_nodes[0]
    base_state = owner.key.state_const & 0xFFFFFFFF
    fallback_label = f"0x{base_state:08X}_fallback"

    fallback_nodes = [
        node
        for node in dag.nodes
        if node.state_label == fallback_label and node.entry_anchor != owner.entry_anchor
    ]
    max_candidate = max(anchor_candidates)
    if fallback_nodes:
        fallback_nodes.sort(
            key=lambda node: (
                0 if node.entry_anchor > max_candidate else 1,
                abs(node.entry_anchor - max_candidate),
            )
        )
        chosen = fallback_nodes[0]
        return chosen.entry_anchor, chosen.state_label

    owner_snapshot = flow_graph.get_block(owner.entry_anchor)
    if owner_snapshot is None:
        return None
    sibling_candidates: list[int] = []
    for pred_serial in owner_snapshot.preds:
        pred_snapshot = flow_graph.get_block(pred_serial)
        if pred_snapshot is None or len(pred_snapshot.succs) != 2:
            continue
        sibling_succs = [
            succ for succ in pred_snapshot.succs if succ != owner.entry_anchor
        ]
        if len(sibling_succs) != 1:
            continue
        sibling_candidates.append(sibling_succs[0])
    if not sibling_candidates:
        return None
    sibling_candidates.sort(
        key=lambda block_serial: (
            0 if block_serial > max_candidate else 1,
            abs(block_serial - max_candidate),
        )
    )
    return sibling_candidates[0], fallback_label


def _suppress_bst_extension_alias_edges(
    edges: tuple[StateDagEdge, ...] | list[StateDagEdge],
    *,
    bst_node_blocks: tuple[int, ...] | set[int],
) -> list[StateDagEdge]:
    """Drop alias edges that only extend a resolved path back into the BST.

    These show up as a second semantic edge whose ordered path is exactly the
    same as a concrete transition, plus one trailing dispatcher-root hop. They
    are useful for explanation, but they keep synthetic supplemental states like
    0x27EEEA11 alive and in turn preserve dispatcher-root loops in the planner.
    """

    bst_block_set = set(bst_node_blocks)
    if not bst_block_set:
        return list(edges)

    concrete_prefixes: set[tuple[StateDagNodeKey, tuple[int, ...]]] = set()
    for edge in edges:
        if (
            edge.kind not in (SemanticEdgeKind.TRANSITION, SemanticEdgeKind.CONDITIONAL_TRANSITION)
            or edge.target_entry_anchor is None
            or edge.target_entry_anchor in bst_block_set
            or not edge.ordered_path
        ):
            continue
        concrete_prefixes.add((edge.source_key, tuple(edge.ordered_path)))

    filtered: list[StateDagEdge] = []
    for edge in edges:
        if (
            edge.kind in (SemanticEdgeKind.TRANSITION, SemanticEdgeKind.CONDITIONAL_TRANSITION)
            and edge.target_entry_anchor is not None
            and edge.target_entry_anchor in bst_block_set
            and len(edge.ordered_path) >= 2
            and edge.ordered_path[-1] in bst_block_set
            and (edge.source_key, tuple(edge.ordered_path[:-1])) in concrete_prefixes
        ):
            continue
        filtered.append(edge)
    return filtered


def _segment_id(block_serial: int) -> str:
    return f"blk[{block_serial}]"


def _is_canonical_exact_row(
    row: TransitionRow,
    *,
    real_handler_states: set[int],
) -> bool:
    if (
        row.state_const is None
        or row.state_range_lo is not None
        or row.state_range_hi is not None
    ):
        return False
    if row.state_const not in real_handler_states:
        return False
    label = row.transition_label.lower()
    return "fallback" not in label and not label.startswith("range alias")


def _find_unique_exact_bridge_row(
    state_value: int,
    report: DispatcherTransitionReport,
    *,
    real_handler_states: set[int],
) -> TransitionRow | None:
    canonical_rows = [
        row
        for row in report.rows
        if _is_canonical_exact_row(
            row, real_handler_states=real_handler_states
        )
    ]
    canonical_states = {
        row.state_const for row in canonical_rows if row.state_const is not None
    }
    candidates = [
        row
        for row in canonical_rows
        if row.state_const is not None
        and row.state_const < state_value
        and row.kind == TransitionKind.TRANSITION
        and row.next_state is not None
        and row.next_state in canonical_states
        and row.next_state > state_value
        and not row.conditional_states
    ]
    if not candidates:
        return None
    candidates.sort(
        key=lambda row: (
            (row.next_state or 0) - state_value,
            state_value - (row.state_const or 0),
            row.handler_serial,
        )
    )
    best = candidates[0]
    if len(candidates) > 1:
        second = candidates[1]
        best_key = (
            (best.next_state or 0) - state_value,
            state_value - (best.state_const or 0),
        )
        second_key = (
            (second.next_state or 0) - state_value,
            state_value - (second.state_const or 0),
        )
        if second_key == best_key:
            return None
    return best


def _resolve_bridge_anchor(
    bridge_row: TransitionRow,
    edges_by_source_state: Mapping[int, tuple[StateDagEdge, ...]],
) -> int:
    bridge_state = bridge_row.state_const
    bridge_next = bridge_row.next_state
    if bridge_state is not None and bridge_next is not None:
        candidate_edges = tuple(
            edge
            for edge in edges_by_source_state.get(bridge_state, ())
            if edge.kind == SemanticEdgeKind.TRANSITION
            and edge.target_state == bridge_next
        )
        if len(candidate_edges) == 1:
            return candidate_edges[0].source_anchor.block_serial
    return bridge_row.handler_serial


def _find_exact_bridge_edge(
    state_value: int,
    edges_by_source_state: Mapping[int, tuple[StateDagEdge, ...]],
    *,
    real_handler_states: set[int],
) -> StateDagEdge | None:
    candidates: list[StateDagEdge] = []
    for source_state, state_edges in edges_by_source_state.items():
        if source_state not in real_handler_states or source_state >= state_value:
            continue
        for edge in state_edges:
            if (
                edge.kind != SemanticEdgeKind.TRANSITION
                or edge.target_state is None
                or edge.target_state not in real_handler_states
                or edge.target_state <= state_value
            ):
                continue
            candidates.append(edge)

    if not candidates:
        return None

    candidates.sort(
        key=lambda edge: (
            (edge.target_state or 0) - state_value,
            state_value - (edge.source_key.state_const or 0),
            edge.source_anchor.block_serial,
        )
    )
    best = candidates[0]
    if len(candidates) > 1:
        second = candidates[1]
        best_key = (
            (best.target_state or 0) - state_value,
            state_value - (best.source_key.state_const or 0),
        )
        second_key = (
            (second.target_state or 0) - state_value,
            state_value - (second.source_key.state_const or 0),
        )
        if second_key == best_key:
            return None
    return best


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
    flow_graph: object | None = None,
) -> tuple[dict[int, int], Callable[[int], int | None]]:
    exact_state_to_handler = {
        row.state_const: row.handler_serial
        for row in report.rows
        if row.state_const is not None
    }
    valid_handler_serials = {row.handler_serial for row in report.rows}

    bst_block_set = set(report.bst_node_blocks)

    def resolve_handler(state_value: int) -> int | None:
        handler_serial = exact_state_to_handler.get(state_value)
        if handler_serial is not None:
            # Validate: if the IntervalDispatcher routes this state to a
            # different non-BST block, the exact match is stale — the BST
            # intercepts at a higher level before reaching the exact handler.
            if dispatcher is not None:
                dispatcher_target = dispatcher.lookup(state_value)
                if (
                    dispatcher_target is not None
                    and int(dispatcher_target) != handler_serial
                    and int(dispatcher_target) != report.dispatcher_entry_serial
                    and int(dispatcher_target) not in bst_block_set
                ):
                    # Guard: if the exact handler is a direct predecessor
                    # of the dispatcher target (adjacent BST check → body),
                    # the disagreement is normal — don't override.
                    # Only override when they're in different subtrees
                    # (the BST intercepts the state at a higher level).
                    adjacent = False
                    if flow_graph is not None:
                        exact_blk = flow_graph.get_block(handler_serial)
                        if exact_blk is not None:
                            exact_succs = {
                                int(s) for s in getattr(exact_blk, "succs", ())
                            }
                            adjacent = int(dispatcher_target) in exact_succs
                    if not adjacent:
                        logger.info(
                            "DAG: exact-vs-dispatcher override: state 0x%X "
                            "exact=blk[%d] dispatcher=blk[%d], "
                            "preferring dispatcher",
                            state_value & 0xFFFFFFFF,
                            handler_serial,
                            int(dispatcher_target),
                        )
                        return int(dispatcher_target)
            return handler_serial
        handler = transition_result.handlers.get(state_value)
        if handler is not None and handler.check_block in valid_handler_serials:
            return handler.check_block
        if dispatcher is not None:
            resolved = dispatcher.lookup(state_value)
            if resolved is not None:
                resolved_int = int(resolved)
                # Skip dispatcher serial — it's a routing trampoline, not a handler
                if resolved_int != report.dispatcher_entry_serial:
                    return resolved_int
        for handler_serial_inner, (lo, hi) in report.handler_range_map.items():
            if lo is None or hi is None:
                continue
            if lo <= state_value <= hi:
                if handler_serial_inner == report.dispatcher_entry_serial:
                    continue
                return handler_serial_inner
        return None

    return exact_state_to_handler, resolve_handler


def _canonical_exact_handler_states(
    report: DispatcherTransitionReport,
    transition_result: TransitionResult,
) -> set[int]:
    canonical_states = {
        state_const & 0xFFFFFFFF
        for state_const in report.handler_state_map.values()
        if state_const is not None
    }
    if transition_result.initial_state is not None:
        canonical_states.add(transition_result.initial_state & 0xFFFFFFFF)
    return canonical_states


def _protected_exact_point_keys(
    report: DispatcherTransitionReport,
) -> set[StateDagNodeKey]:
    protected: set[StateDagNodeKey] = set()
    for row in report.rows:
        if (
            row.state_const is None
            or row.state_range_lo is not None
            or row.state_range_hi is not None
        ):
            continue
        expected_label = f"0x{row.state_const:08X}"
        if row.state_label != expected_label:
            continue
        protected.add(
            StateDagNodeKey(
                handler_serial=row.handler_serial,
                state_const=row.state_const & 0xFFFFFFFF,
            )
        )
    return protected


def _compute_alias_label_override(
    node: StateDagNode,
    incoming_edges: tuple[StateDagEdge, ...],
    outgoing_edges: tuple[StateDagEdge, ...],
    report: DispatcherTransitionReport,
    flow_graph: FlowGraph,
    edges_by_source_block: Mapping[int, tuple[StateDagEdge, ...]],
    edges_by_source_state: Mapping[int, tuple[StateDagEdge, ...]],
    real_handler_states: set[int],
    *,
    prefer_local_corridors: bool = False,
) -> tuple[str, int, bool] | None:
    state_value = node.key.state_const
    if state_value is None or len(outgoing_edges) != 1:
        if state_value in {0x2A5E29F6, 0x6CAA9521}:
            logger.info(
                "DAG alias override skip state=0x%08X outgoing=%d incoming=%d entry=%s label=%s",
                state_value,
                len(outgoing_edges),
                len(incoming_edges),
                node.entry_anchor,
                node.state_label,
            )
        return None

    terminal_kinds = {
        SemanticEdgeKind.CONDITIONAL_RETURN,
        SemanticEdgeKind.EXIT_ROUTINE,
        SemanticEdgeKind.UNKNOWN,
    }
    outgoing_edge = outgoing_edges[0]
    if (
        outgoing_edge.kind in terminal_kinds
        and len(incoming_edges) == 1
        and incoming_edges[0].source_key.state_const is not None
    ):
        bst_blocks = set(report.bst_node_blocks)
        incoming_edge = incoming_edges[0]
        source_state = incoming_edge.source_key.state_const & 0xFFFFFFFF
        source_terminal_edges = tuple(
            edge
            for edge in edges_by_source_state.get(source_state, ())
            if edge.kind in terminal_kinds and edge.ordered_path
        )
        alias_terminal_path = tuple(outgoing_edge.ordered_path)
        alias_exit_block = alias_terminal_path[-1] if alias_terminal_path else None
        for terminal_edge in source_terminal_edges:
            terminal_path = tuple(terminal_edge.ordered_path)
            if (
                alias_exit_block is not None
                and terminal_path
                and terminal_path[-1] != alias_exit_block
            ):
                continue

            common_len = 0
            for lhs, rhs in zip(incoming_edge.ordered_path, terminal_path):
                if lhs != rhs:
                    break
                common_len += 1
            if (
                common_len == 0
                and terminal_path
                and terminal_path[0] == incoming_edge.source_key.handler_serial
            ):
                common_len = 1

            candidate_anchor = next(
                (
                    block_serial
                    for block_serial in terminal_path[common_len:]
                    if block_serial not in bst_blocks
                ),
                None,
            )
            if candidate_anchor is None:
                candidate_anchor = next(
                    (
                        block_serial
                        for block_serial in terminal_path
                        if block_serial not in bst_blocks
                    ),
                    None,
                )
            if candidate_anchor is None or candidate_anchor == node.entry_anchor:
                continue
            if state_value in {0x2A5E29F6, 0x6CAA9521}:
                logger.info(
                    "DAG alias override terminal collapse state=0x%08X -> anchor=%s",
                    state_value,
                    candidate_anchor,
                )
            return (node.state_label, candidate_anchor, True)

    for incoming_edge in incoming_edges:
        source_snapshot = flow_graph.get_block(incoming_edge.source_anchor.block_serial)
        if source_snapshot is None or len(source_snapshot.succs) != 1:
            continue
        prelude_anchor = source_snapshot.succs[0]
        if prelude_anchor == node.entry_anchor:
            continue
        exact_preludes = tuple(
            candidate
            for candidate in edges_by_source_block.get(prelude_anchor, ())
            if candidate.kind == SemanticEdgeKind.TRANSITION
            and candidate.target_state is not None
            and candidate.target_state in real_handler_states
        )
        exact_targets = {
            candidate.target_state
            for candidate in exact_preludes
            if candidate.target_state is not None
        }
        if len(exact_targets) != 1:
            continue
        exact_target = next(iter(exact_targets))
        if exact_target is None:
            continue
        if state_value in {0x2A5E29F6, 0x6CAA9521}:
            logger.info(
                "DAG alias override prelude collapse state=0x%08X -> fallback=%s anchor=%s",
                state_value,
                exact_target,
                prelude_anchor,
            )
        return (f"0x{exact_target:08X}_fallback", prelude_anchor, True)

    cover_row = _find_exact_cover_row(
        state_value,
        report,
        exact_handler_state_map=report.handler_state_map,
    )
    edge = outgoing_edges[0]
    if (
        prefer_local_corridors
        and edge.kind == SemanticEdgeKind.TRANSITION
        and edge.target_state is not None
    ):
        lower_gap = (
            state_value - cover_row.state_const
            if cover_row is not None and cover_row.state_const is not None
            else None
        )
        upper_candidates: list[tuple[int, str, int, bool]] = []
        if (
            edge.target_state in real_handler_states
            and edge.target_state > state_value
        ):
            upper_candidates.append(
                (
                    edge.target_state - state_value,
                    f"0x{edge.target_state:08X}_fallback",
                    node.entry_anchor,
                    False,
                )
            )
        bridge_edge = _find_exact_bridge_edge(
            state_value,
            edges_by_source_state,
            real_handler_states=real_handler_states,
        )
        if (
            bridge_edge is not None
            and bridge_edge.target_state is not None
            and bridge_edge.target_state > state_value
            and bridge_edge.source_anchor.block_serial < node.entry_anchor
        ):
            upper_candidates.append(
                (
                    bridge_edge.target_state - state_value,
                    f"0x{bridge_edge.target_state:08X}_fallback",
                    bridge_edge.source_anchor.block_serial,
                    True,
                )
            )
        if upper_candidates:
            upper_candidates.sort(key=lambda item: item[0])
            best_gap, best_label, best_anchor, best_local = upper_candidates[0]
            if lower_gap is None or best_gap < lower_gap:
                if state_value in {0x2A5E29F6, 0x6CAA9521}:
                    logger.info(
                        "DAG alias override upper-gap collapse state=0x%08X -> label=%s anchor=%s local=%s lower_gap=%s best_gap=%s",
                        state_value,
                        best_label,
                        best_anchor,
                        best_local,
                        lower_gap,
                        best_gap,
                    )
                return (best_label, best_anchor, best_local)
        if (
            cover_row is not None
            and cover_row.state_const is not None
            and cover_row.state_const != state_value
            and node.entry_anchor != cover_row.handler_serial
        ):
            if state_value in {0x2A5E29F6, 0x6CAA9521}:
                logger.info(
                    "DAG alias override cover collapse state=0x%08X -> cover=0x%08X anchor=%s",
                    state_value,
                    cover_row.state_const,
                    node.entry_anchor,
                )
            return (
                f"0x{cover_row.state_const:08X}_fallback",
                node.entry_anchor,
                False,
            )

    if prefer_local_corridors:
        return None

    if edge.kind != SemanticEdgeKind.TRANSITION or edge.target_state is None:
        return None

    bridge_edge = _find_exact_bridge_edge(
        state_value,
        edges_by_source_state,
        real_handler_states=real_handler_states,
    )
    if bridge_edge is not None and bridge_edge.target_state is not None:
        return (
            f"0x{bridge_edge.target_state:08X}_fallback",
            bridge_edge.source_anchor.block_serial,
            True,
        )

    bridge_row = _find_unique_exact_bridge_row(
        state_value,
        report,
        real_handler_states=real_handler_states,
    )
    if bridge_row is not None and bridge_row.next_state is not None:
        return (
            f"0x{bridge_row.next_state:08X}_fallback",
            _resolve_bridge_anchor(bridge_row, edges_by_source_state),
            True,
        )
    if edge.target_state in real_handler_states:
        return (
            f"0x{edge.target_state:08X}_fallback",
            edge.source_anchor.block_serial,
            True,
        )
    if cover_row is None or cover_row.state_const == state_value:
        return None
    return (f"0x{cover_row.state_const:08X}_fallback", node.entry_anchor, False)


def _normalize_alias_nodes(
    nodes: list[StateDagNode],
    edges: list[StateDagEdge],
    report: DispatcherTransitionReport,
    transition_result: TransitionResult,
    flow_graph: FlowGraph,
    *,
    prefer_local_corridors: bool = False,
    bst_node_blocks: tuple[int, ...] = (),
    dispatcher: IntervalDispatcher | None = None,
) -> tuple[list[StateDagNode], list[StateDagEdge]]:
    real_handler_states = _canonical_exact_handler_states(
        report,
        transition_result,
    )
    protected_exact_keys = _protected_exact_point_keys(report)
    incoming_by_state: defaultdict[int, list[StateDagEdge]] = defaultdict(list)
    outgoing_by_state_key: defaultdict[StateDagNodeKey, list[StateDagEdge]] = defaultdict(list)
    edges_by_source_block: defaultdict[int, list[StateDagEdge]] = defaultdict(list)
    edges_by_source_state: defaultdict[int, list[StateDagEdge]] = defaultdict(list)
    for edge in edges:
        if edge.target_state is not None:
            incoming_by_state[edge.target_state & 0xFFFFFFFF].append(edge)
        outgoing_by_state_key[edge.source_key].append(edge)
        edges_by_source_block[edge.source_anchor.block_serial].append(edge)
        if edge.source_key.state_const is not None:
            edges_by_source_state[edge.source_key.state_const & 0xFFFFFFFF].append(edge)

    normalized_nodes: list[StateDagNode] = []
    key_updates: dict[StateDagNodeKey, StateDagNode] = {}
    for node in nodes:
        state_value = node.key.state_const
        if (
            state_value is None
            or state_value in real_handler_states
            or node.key in protected_exact_keys
        ):
            normalized_nodes.append(node)
            key_updates[node.key] = node
            continue

        embedded_owner_override = _resolve_embedded_exact_owner_override(
            node,
            nodes,
            tuple(outgoing_by_state_key.get(node.key, ())),
            {
                state_key: tuple(state_edges)
                for state_key, state_edges in outgoing_by_state_key.items()
            },
            canonical_handler_states=real_handler_states,
        )
        if embedded_owner_override is not None:
            state_label, entry_anchor, use_anchor_as_local_entry = embedded_owner_override
            if state_value in {0x2A5E29F6, 0x6CAA9521}:
                logger.info(
                    "DAG alias normalize embedded-owner state=0x%08X handler=%s -> label=%s anchor=%s local=%s",
                    state_value,
                    node.handler_serial,
                    state_label,
                    entry_anchor,
                    use_anchor_as_local_entry,
                )

            owned_blocks = node.owned_blocks
            exclusive_blocks = node.exclusive_blocks
            shared_suffix_blocks = node.shared_suffix_blocks
            local_segments = node.local_segments
            local_edges = node.local_edges
            if use_anchor_as_local_entry and entry_anchor != node.entry_anchor:
                owned_blocks = (entry_anchor,)
                exclusive_blocks = (entry_anchor,)
                shared_suffix_blocks = ()
                local_segments = (
                    StateLocalSegment(
                        segment_id=_segment_id(entry_anchor),
                        kind=LocalSegmentKind.STRAIGHT_LINE,
                        blocks=(entry_anchor,),
                    ),
                )
                local_edges = ()

            normalized = StateDagNode(
                key=node.key,
                kind=node.kind,
                state_label=state_label,
                handler_serial=node.handler_serial,
                entry_anchor=entry_anchor,
                owned_blocks=owned_blocks,
                exclusive_blocks=exclusive_blocks,
                shared_suffix_blocks=shared_suffix_blocks,
                local_segments=local_segments,
                local_edges=local_edges,
            )
            normalized_nodes.append(normalized)
            key_updates[node.key] = normalized
            continue

        override = _compute_alias_label_override(
            node,
            tuple(incoming_by_state.get(state_value, ())),
            tuple(outgoing_by_state_key.get(node.key, ())),
            report,
            flow_graph,
            {
                block_serial: tuple(block_edges)
                for block_serial, block_edges in edges_by_source_block.items()
            },
            {
                state_value: tuple(state_edges)
                for state_value, state_edges in edges_by_source_state.items()
            },
            real_handler_states,
            prefer_local_corridors=prefer_local_corridors,
        )
        if override is None:
            normalized_nodes.append(node)
            key_updates[node.key] = node
            continue

        state_label, entry_anchor, use_anchor_as_local_entry = override
        if override is not None:
            state_label, entry_anchor, use_anchor_as_local_entry = override

        owned_blocks = node.owned_blocks
        exclusive_blocks = node.exclusive_blocks
        shared_suffix_blocks = node.shared_suffix_blocks
        local_segments = node.local_segments
        local_edges = node.local_edges
        if use_anchor_as_local_entry and entry_anchor != node.entry_anchor:
            owned_blocks = (entry_anchor,)
            exclusive_blocks = (entry_anchor,)
            shared_suffix_blocks = ()
            local_segments = (
                StateLocalSegment(
                    segment_id=_segment_id(entry_anchor),
                    kind=LocalSegmentKind.STRAIGHT_LINE,
                    blocks=(entry_anchor,),
                ),
            )
            local_edges = ()

        normalized = StateDagNode(
            key=node.key,
            kind=node.kind,
            state_label=state_label,
            handler_serial=node.handler_serial,
            entry_anchor=entry_anchor,
            owned_blocks=owned_blocks,
            exclusive_blocks=exclusive_blocks,
            shared_suffix_blocks=shared_suffix_blocks,
            local_segments=local_segments,
            local_edges=local_edges,
        )
        normalized_nodes.append(normalized)
        key_updates[node.key] = normalized

    normalized_edges: list[StateDagEdge] = []
    _bst_set = set(bst_node_blocks)
    for edge in edges:
        target_node = key_updates.get(edge.target_key) if edge.target_key is not None else None
        _resolved_anchor = (
            target_node.entry_anchor
            if target_node is not None
            else edge.target_entry_anchor
        )
        if (
            _resolved_anchor is not None
            and int(_resolved_anchor) in _bst_set
            and edge.target_state is not None
            and dispatcher is not None
        ):
            _lookup = dispatcher.lookup(edge.target_state)
            if _lookup is not None and int(_lookup) not in _bst_set:
                _resolved_anchor = int(_lookup)
            else:
                _resolved_anchor = None  # No valid target
        normalized_edges.append(
            StateDagEdge(
                kind=edge.kind,
                source_key=edge.source_key,
                target_key=edge.target_key,
                target_state=edge.target_state,
                target_entry_anchor=_resolved_anchor,
                target_label=(
                    target_node.state_label
                    if target_node is not None
                    else edge.target_label
                ),
                source_anchor=edge.source_anchor,
                ordered_path=edge.ordered_path,
                last_write_site=edge.last_write_site,
            )
        )

    return normalized_nodes, normalized_edges


def _normalize_nonhandler_exact_nodes(
    nodes: list[StateDagNode],
    edges: list[StateDagEdge],
    report: DispatcherTransitionReport,
    transition_result: TransitionResult,
    flow_graph: FlowGraph,
    *,
    prefer_local_corridors: bool = False,
    bst_node_blocks: tuple[int, ...] = (),
    dispatcher: IntervalDispatcher | None = None,
) -> tuple[list[StateDagNode], list[StateDagEdge]]:
    canonical_handler_states = _canonical_exact_handler_states(
        report,
        transition_result,
    )
    protected_exact_keys = _protected_exact_point_keys(report)
    initial_state = (
        transition_result.initial_state & 0xFFFFFFFF
        if transition_result.initial_state is not None
        else None
    )
    incoming_by_state: defaultdict[int, list[StateDagEdge]] = defaultdict(list)
    outgoing_by_state_key: defaultdict[StateDagNodeKey, list[StateDagEdge]] = defaultdict(list)
    edges_by_source_block: defaultdict[int, list[StateDagEdge]] = defaultdict(list)
    edges_by_source_state: defaultdict[int, list[StateDagEdge]] = defaultdict(list)
    for edge in edges:
        if edge.target_state is not None:
            incoming_by_state[edge.target_state & 0xFFFFFFFF].append(edge)
        outgoing_by_state_key[edge.source_key].append(edge)
        edges_by_source_block[edge.source_anchor.block_serial].append(edge)
        if edge.source_key.state_const is not None:
            edges_by_source_state[edge.source_key.state_const & 0xFFFFFFFF].append(edge)

    normalized_nodes: list[StateDagNode] = []
    key_updates: dict[StateDagNodeKey, StateDagNode] = {}
    for node in nodes:
        state_value = node.key.state_const
        if (
            state_value is None
            or node.kind != StateNodeKind.EXACT
            or state_value == initial_state
            or node.key in protected_exact_keys
        ):
            normalized_nodes.append(node)
            key_updates[node.key] = node
            continue

        if state_value in {0x2A5E29F6, 0x6CAA9521}:
            logger.info(
                "DAG nonhandler normalize inspect state=0x%08X canonical=%s handler=%s entry=%s label=%s",
                state_value,
                state_value in canonical_handler_states,
                node.handler_serial,
                node.entry_anchor,
                node.state_label,
            )

        embedded_owner_override = _resolve_embedded_exact_owner_override(
            node,
            nodes,
            tuple(outgoing_by_state_key.get(node.key, ())),
            {
                state_key: tuple(state_edges)
                for state_key, state_edges in outgoing_by_state_key.items()
            },
            canonical_handler_states=canonical_handler_states,
        )
        if embedded_owner_override is not None:
            state_label, entry_anchor, use_anchor_as_local_entry = embedded_owner_override
            if state_value in {0x2A5E29F6, 0x6CAA9521}:
                logger.info(
                    "DAG nonhandler normalize embedded-owner state=0x%08X handler=%s -> label=%s anchor=%s local=%s",
                    state_value,
                    node.handler_serial,
                    state_label,
                    entry_anchor,
                    use_anchor_as_local_entry,
                )

            owned_blocks = node.owned_blocks
            exclusive_blocks = node.exclusive_blocks
            shared_suffix_blocks = node.shared_suffix_blocks
            local_segments = node.local_segments
            local_edges = node.local_edges
            if use_anchor_as_local_entry and entry_anchor != node.entry_anchor:
                owned_blocks = (entry_anchor,)
                exclusive_blocks = (entry_anchor,)
                shared_suffix_blocks = ()
                local_segments = (
                    StateLocalSegment(
                        segment_id=_segment_id(entry_anchor),
                        kind=LocalSegmentKind.STRAIGHT_LINE,
                        blocks=(entry_anchor,),
                    ),
                )
                local_edges = ()

            normalized = StateDagNode(
                key=node.key,
                kind=node.kind,
                state_label=state_label,
                handler_serial=node.handler_serial,
                entry_anchor=entry_anchor,
                owned_blocks=owned_blocks,
                exclusive_blocks=exclusive_blocks,
                shared_suffix_blocks=shared_suffix_blocks,
                local_segments=local_segments,
                local_edges=local_edges,
            )
            normalized_nodes.append(normalized)
            key_updates[node.key] = normalized
            continue

        override = _compute_alias_label_override(
            node,
            tuple(incoming_by_state.get(state_value, ())),
            tuple(outgoing_by_state_key.get(node.key, ())),
            report,
            flow_graph,
            {
                block_serial: tuple(block_edges)
                for block_serial, block_edges in edges_by_source_block.items()
            },
            {
                source_state: tuple(state_edges)
                for source_state, state_edges in edges_by_source_state.items()
            },
            canonical_handler_states,
            prefer_local_corridors=prefer_local_corridors,
        )
        if override is None:
            if state_value in {0x2A5E29F6, 0x6CAA9521}:
                logger.info(
                    "DAG nonhandler normalize no-override state=0x%08X handler=%s entry=%s",
                    state_value,
                    node.handler_serial,
                    node.entry_anchor,
                )
            normalized_nodes.append(node)
            key_updates[node.key] = node
            continue

        state_label, entry_anchor, use_anchor_as_local_entry = override
        if state_value in {0x2A5E29F6, 0x6CAA9521}:
            logger.info(
                "DAG nonhandler normalize apply state=0x%08X handler=%s -> label=%s anchor=%s local=%s",
                state_value,
                node.handler_serial,
                state_label,
                entry_anchor,
                use_anchor_as_local_entry,
            )
        owned_blocks = node.owned_blocks
        exclusive_blocks = node.exclusive_blocks
        shared_suffix_blocks = node.shared_suffix_blocks
        local_segments = node.local_segments
        local_edges = node.local_edges
        if use_anchor_as_local_entry and entry_anchor != node.entry_anchor:
            owned_blocks = (entry_anchor,)
            exclusive_blocks = (entry_anchor,)
            shared_suffix_blocks = ()
            local_segments = (
                StateLocalSegment(
                    segment_id=_segment_id(entry_anchor),
                    kind=LocalSegmentKind.STRAIGHT_LINE,
                    blocks=(entry_anchor,),
                ),
            )
            local_edges = ()

        normalized = StateDagNode(
            key=node.key,
            kind=node.kind,
            state_label=state_label,
            handler_serial=node.handler_serial,
            entry_anchor=entry_anchor,
            owned_blocks=owned_blocks,
            exclusive_blocks=exclusive_blocks,
            shared_suffix_blocks=shared_suffix_blocks,
            local_segments=local_segments,
            local_edges=local_edges,
        )
        normalized_nodes.append(normalized)
        key_updates[node.key] = normalized

    normalized_edges: list[StateDagEdge] = []
    _bst_set = set(bst_node_blocks)
    for edge in edges:
        target_node = key_updates.get(edge.target_key) if edge.target_key is not None else None
        _resolved_anchor = (
            target_node.entry_anchor
            if target_node is not None
            else edge.target_entry_anchor
        )
        if (
            _resolved_anchor is not None
            and int(_resolved_anchor) in _bst_set
            and edge.target_state is not None
            and dispatcher is not None
        ):
            _lookup = dispatcher.lookup(edge.target_state)
            if _lookup is not None and int(_lookup) not in _bst_set:
                _resolved_anchor = int(_lookup)
            else:
                _resolved_anchor = None  # No valid target
        normalized_edges.append(
            StateDagEdge(
                kind=edge.kind,
                source_key=edge.source_key,
                target_key=edge.target_key,
                target_state=edge.target_state,
                target_entry_anchor=_resolved_anchor,
                target_label=(
                    target_node.state_label
                    if target_node is not None
                    else edge.target_label
                ),
                source_anchor=edge.source_anchor,
                ordered_path=edge.ordered_path,
                last_write_site=edge.last_write_site,
            )
        )

    return normalized_nodes, normalized_edges


def _resolve_embedded_exact_owner_override(
    node: StateDagNode,
    nodes: list[StateDagNode],
    outgoing_edges: tuple[StateDagEdge, ...],
    outgoing_edges_by_key: Mapping[StateDagNodeKey, tuple[StateDagEdge, ...]],
    *,
    canonical_handler_states: set[int],
) -> tuple[str, int, bool] | None:
    state_value = node.key.state_const
    if state_value is None or state_value in canonical_handler_states:
        return None

    alias_targets = {
        edge.target_state & 0xFFFFFFFF
        for edge in outgoing_edges
        if edge.kind in (SemanticEdgeKind.TRANSITION, SemanticEdgeKind.CONDITIONAL_TRANSITION)
        and edge.target_state is not None
    }
    if not alias_targets:
        return None

    owner_candidates: list[tuple[tuple[int, int, int], StateDagNode]] = []
    for owner in nodes:
        owner_state = owner.key.state_const
        if (
            owner.key == node.key
            or owner.kind != StateNodeKind.EXACT
            or owner_state is None
            or owner_state not in canonical_handler_states
        ):
            continue
        owns_entry = (
            node.entry_anchor == owner.entry_anchor
            or node.entry_anchor in owner.owned_blocks
            or any(node.entry_anchor in segment.blocks for segment in owner.local_segments)
        )
        if not owns_entry:
            continue

        owner_targets = {
            edge.target_state & 0xFFFFFFFF
            for edge in outgoing_edges_by_key.get(owner.key, ())
            if edge.kind in (SemanticEdgeKind.TRANSITION, SemanticEdgeKind.CONDITIONAL_TRANSITION)
            and edge.target_state is not None
        }
        if not owner_targets or not alias_targets.issubset(owner_targets):
            continue

        score = (
            1 if node.entry_anchor in owner.exclusive_blocks else 0,
            len(owner_targets),
            -abs(owner.entry_anchor - node.entry_anchor),
        )
        owner_candidates.append((score, owner))

    if not owner_candidates:
        return None

    owner_candidates.sort(key=lambda item: item[0], reverse=True)
    owner = owner_candidates[0][1]
    if owner.entry_anchor == node.entry_anchor:
        return None
    return (node.state_label, owner.entry_anchor, False)


def _promote_range_backed_nodes_to_dispatcher_bodies(
    nodes: list[StateDagNode],
    edges: list[StateDagEdge],
    dispatcher: IntervalDispatcher | None,
    *,
    bst_node_blocks: tuple[int, ...],
) -> tuple[list[StateDagNode], list[StateDagEdge]]:
    if dispatcher is None:
        return nodes, edges

    bst_blocks = set(bst_node_blocks)
    promoted_by_key: dict[StateDagNodeKey, StateDagNode] = {}
    promoted_nodes: list[StateDagNode] = []

    for node in nodes:
        promoted = node
        if (
            node.kind == StateNodeKind.RANGE_BACKED
            and node.key.state_const is not None
            and node.entry_anchor in bst_blocks
        ):
            try:
                dispatcher_row = dispatcher.lookup_row(node.key.state_const)
            except Exception:
                dispatcher_row = None
            promoted_anchor = (
                int(dispatcher_row.target)
                if dispatcher_row is not None and dispatcher_row.target not in bst_blocks
                else None
            )
            if promoted_anchor is not None and promoted_anchor != node.entry_anchor:
                promoted = StateDagNode(
                    key=node.key,
                    kind=node.kind,
                    state_label=node.state_label,
                    handler_serial=node.handler_serial,
                    entry_anchor=promoted_anchor,
                    owned_blocks=(promoted_anchor,),
                    exclusive_blocks=(promoted_anchor,),
                    shared_suffix_blocks=(),
                    local_segments=(
                        StateLocalSegment(
                            segment_id=_segment_id(promoted_anchor),
                            kind=LocalSegmentKind.STRAIGHT_LINE,
                            blocks=(promoted_anchor,),
                        ),
                    ),
                    local_edges=(),
                )
        promoted_nodes.append(promoted)
        promoted_by_key[promoted.key] = promoted

    promoted_edges: list[StateDagEdge] = []
    _bst_set = set(bst_node_blocks)
    for edge in edges:
        target_node = (
            promoted_by_key.get(edge.target_key)
            if edge.target_key is not None
            else None
        )
        _resolved_anchor = (
            target_node.entry_anchor
            if target_node is not None
            else edge.target_entry_anchor
        )
        if (
            _resolved_anchor is not None
            and int(_resolved_anchor) in _bst_set
            and edge.target_state is not None
            and dispatcher is not None
        ):
            _lookup = dispatcher.lookup(edge.target_state)
            if _lookup is not None and int(_lookup) not in _bst_set:
                _resolved_anchor = int(_lookup)
            else:
                _resolved_anchor = None  # No valid target
        promoted_edges.append(
            StateDagEdge(
                kind=edge.kind,
                source_key=edge.source_key,
                target_key=edge.target_key,
                target_state=edge.target_state,
                target_entry_anchor=_resolved_anchor,
                target_label=(
                    target_node.state_label
                    if target_node is not None
                    else edge.target_label
                ),
                source_anchor=edge.source_anchor,
                ordered_path=edge.ordered_path,
                last_write_site=edge.last_write_site,
            )
        )

    return promoted_nodes, promoted_edges


def _normalize_entry_anchors_to_unique_path_starts(
    nodes: list[StateDagNode],
    edges: list[StateDagEdge],
    *,
    bst_node_blocks: tuple[int, ...],
    dispatcher: IntervalDispatcher | None = None,
) -> tuple[list[StateDagNode], list[StateDagEdge]]:
    bst_blocks = set(bst_node_blocks)
    outgoing_by_key: defaultdict[StateDagNodeKey, list[StateDagEdge]] = defaultdict(list)
    for edge in edges:
        outgoing_by_key[edge.source_key].append(edge)

    normalized_nodes: list[StateDagNode] = []
    normalized_by_key: dict[StateDagNodeKey, StateDagNode] = {}

    for node in nodes:
        if node.local_segments:
            normalized_nodes.append(node)
            normalized_by_key[node.key] = node
            continue

        outgoing_paths = tuple(
            edge.ordered_path
            for edge in outgoing_by_key.get(node.key, ())
            if edge.ordered_path
        )
        if not outgoing_paths:
            normalized_nodes.append(node)
            normalized_by_key[node.key] = node
            continue

        blocks_on_paths = {
            block_serial
            for path in outgoing_paths
            for block_serial in path
        }
        if node.entry_anchor in blocks_on_paths:
            normalized_nodes.append(node)
            normalized_by_key[node.key] = node
            continue

        path_starts = _ordered_unique(
            [
                path[0]
                for path in outgoing_paths
                if path and path[0] not in bst_blocks
            ]
        )
        if len(path_starts) != 1:
            normalized_nodes.append(node)
            normalized_by_key[node.key] = node
            continue

        entry_anchor = path_starts[0]
        if entry_anchor == node.entry_anchor:
            normalized_nodes.append(node)
            normalized_by_key[node.key] = node
            continue

        owned_blocks = node.owned_blocks
        if entry_anchor not in owned_blocks:
            owned_blocks = _ordered_unique((entry_anchor, *owned_blocks))

        exclusive_blocks = node.exclusive_blocks
        if entry_anchor not in exclusive_blocks:
            exclusive_blocks = _ordered_unique((entry_anchor, *exclusive_blocks))

        local_segments = node.local_segments
        if not any(entry_anchor in segment.blocks for segment in local_segments):
            local_segments = (
                StateLocalSegment(
                    segment_id=_segment_id(entry_anchor),
                    kind=LocalSegmentKind.STRAIGHT_LINE,
                    blocks=(entry_anchor,),
                ),
                *local_segments,
            )

        normalized = StateDagNode(
            key=node.key,
            kind=node.kind,
            state_label=node.state_label,
            handler_serial=node.handler_serial,
            entry_anchor=entry_anchor,
            owned_blocks=owned_blocks,
            exclusive_blocks=exclusive_blocks,
            shared_suffix_blocks=node.shared_suffix_blocks,
            local_segments=local_segments,
            local_edges=node.local_edges,
        )
        normalized_nodes.append(normalized)
        normalized_by_key[node.key] = normalized

    normalized_edges: list[StateDagEdge] = []
    for edge in edges:
        target_node = (
            normalized_by_key.get(edge.target_key)
            if edge.target_key is not None
            else None
        )
        _resolved_anchor = (
            target_node.entry_anchor
            if target_node is not None
            else edge.target_entry_anchor
        )
        if (
            _resolved_anchor is not None
            and int(_resolved_anchor) in bst_blocks
            and edge.target_state is not None
            and dispatcher is not None
        ):
            _lookup = dispatcher.lookup(edge.target_state)
            if _lookup is not None and int(_lookup) not in bst_blocks:
                _resolved_anchor = int(_lookup)
            else:
                _resolved_anchor = None  # No valid target
        normalized_edges.append(
            StateDagEdge(
                kind=edge.kind,
                source_key=edge.source_key,
                target_key=edge.target_key,
                target_state=edge.target_state,
                target_entry_anchor=_resolved_anchor,
                target_label=(
                    target_node.state_label
                    if target_node is not None
                    else edge.target_label
                ),
                source_anchor=edge.source_anchor,
                ordered_path=edge.ordered_path,
                last_write_site=edge.last_write_site,
            )
        )

    return normalized_nodes, normalized_edges


def _collect_local_block_order(
    handler_serial: int,
    transition_result: TransitionResult,
    row_state_const: int | None,
    paths: tuple[HandlerPathResult, ...],
    conditional_transitions: tuple[ConditionalTransition, ...],
    *,
    path_root_override: int | None = None,
) -> tuple[int, ...]:
    ordered: list[int]
    if path_root_override is not None and path_root_override != handler_serial:
        ordered = [path_root_override]
    else:
        ordered = [handler_serial]

    if row_state_const is not None and path_root_override is None:
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


def _resolve_semantic_entry_anchor(
    handler_serial: int,
    local_blocks: tuple[int, ...],
    paths: tuple[HandlerPathResult, ...],
    *,
    bst_node_blocks: tuple[int, ...],
) -> int:
    path_roots = _ordered_unique(
        [path.ordered_path[0] for path in paths if path.ordered_path]
    )
    if len(path_roots) == 1 and path_roots[0] != handler_serial:
        return path_roots[0]

    bst_blocks = set(bst_node_blocks)
    if handler_serial not in bst_blocks:
        return handler_serial

    path_candidates: list[int] = []
    for path in paths:
        try:
            start_idx = path.ordered_path.index(handler_serial)
        except ValueError:
            continue
        candidate = next(
            (
                block_serial
                for block_serial in path.ordered_path[start_idx + 1 :]
                if block_serial not in bst_blocks
            ),
            None,
        )
        if candidate is not None:
            path_candidates.append(candidate)

    ordered_path_candidates = _ordered_unique(path_candidates)
    if len(ordered_path_candidates) == 1:
        return ordered_path_candidates[0]

    local_candidate = next(
        (
            block_serial
            for block_serial in local_blocks
            if block_serial != handler_serial and block_serial not in bst_blocks
        ),
        None,
    )
    if local_candidate is not None:
        return local_candidate

    return handler_serial


def _is_self_handoff_only_candidate(
    paths: tuple[HandlerPathResult, ...],
    state_value: int,
) -> bool:
    if not paths:
        return False

    saw_path = False
    normalized_state = state_value & 0xFFFFFFFF
    for path in paths:
        if path.final_state is None:
            return False
        saw_path = True
        if (path.final_state & 0xFFFFFFFF) != normalized_state:
            return False
        if path.state_writes:
            normalized_writes = {
                value & 0xFFFFFFFF for _, value in path.state_writes
            }
            if normalized_writes != {normalized_state}:
                return False

    return saw_path


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
    dispatcher: "IntervalDispatcher | None" = None,
    mba: object | None = None,
    state_var_stkoff: int | None = None,
) -> tuple[set[int], dict[int, set[int]]]:
    existing_states = {
        row.state_const & 0xFFFFFFFF
        for row in report.rows
        if row.state_const is not None
    }
    exact_state_to_handler = {
        row.state_const: row.handler_serial
        for row in report.rows
        if row.state_const is not None
    }
    handler_entry_blocks = {row.handler_serial for row in report.rows}
    bst_block_set = set(report.bst_node_blocks)
    # Map handler serial → incoming state for classification.
    handler_incoming_state = {
        row.handler_serial: row.state_const
        for row in report.rows
        if row.state_const is not None
    }

    supplemental_states: set[int] = set()
    collapsed_target_anchors: dict[int, set[int]] = {}
    # Denylist: states whose handler entry is a transient corridor
    # (state var overwritten before side effects in the entry's body).
    # Built by scanning handler entries independently of the DFS, so it
    # works even when DFS continuation consumes transient exits early.
    transient_entry_blocks: set[int] = set()
    if mba is not None and state_var_stkoff is not None:
        for entry in handler_entry_blocks:
            if entry in bst_block_set:
                continue
            kind = classify_exit_state(
                mba=mba,
                final_state=1,  # dummy non-None to skip TERMINAL check
                incoming_state=None,
                successor_serial=entry,
                state_var_stkoff=state_var_stkoff,
                bst_node_blocks=bst_block_set,
            )
            if kind == ExitStateKind.TRANSIENT_CORRIDOR:
                transient_entry_blocks.add(entry)
    transient_states: set[int] = set()
    if transient_entry_blocks and dispatcher is not None:
        # A state value is transient if the stale exact-match handler
        # is a transient corridor entry.  Build the set by scanning
        # all known exact-match state→handler mappings.
        for row in report.rows:
            if row.state_const is None:
                continue
            if row.handler_serial in transient_entry_blocks:
                transient_states.add(row.state_const & 0xFFFFFFFF)
        # Also check transition targets whose dispatcher resolution
        # points to a transient entry.
        for transition in transition_result.transitions:
            sv = transition.to_state & 0xFFFFFFFF
            if sv in existing_states:
                continue
            disp = dispatcher.lookup(sv)
            if disp is not None and int(disp) in transient_entry_blocks:
                transient_states.add(sv)
    if transient_entry_blocks:
        logger.info(
            "transient corridor entries: %d blocks: %s",
            len(transient_entry_blocks),
            ", ".join("blk[%d]" % b for b in sorted(transient_entry_blocks)),
        )
    if transient_states:
        logger.info(
            "transient denylist: %d states: %s",
            len(transient_states),
            ", ".join("0x%X" % s for s in sorted(transient_states)),
        )

    for handler_serial, paths in paths_by_handler.items():
        incoming = handler_incoming_state.get(handler_serial)
        for path in paths:
            if path.final_state is None:
                continue
            state_value = path.final_state & 0xFFFFFFFF
            if state_value not in existing_states:
                # Identify the successor to classify.  Prefer handler
                # entry blocks (the DFS terminated there), but fall back
                # to any non-BST, non-visited successor.
                exit_blk = flow_graph.get_block(path.exit_block)
                path_set = set(path.ordered_path) if path.ordered_path else set()
                succ_serial: int | None = None
                if exit_blk is not None:
                    for s in exit_blk.succs:
                        if s in handler_entry_blocks and s not in path_set:
                            succ_serial = s
                            break
                    if succ_serial is None:
                        for s in exit_blk.succs:
                            if s not in bst_block_set and s not in path_set:
                                succ_serial = s
                                break
                kind = ExitStateKind.UNCLASSIFIED
                if mba is not None and state_var_stkoff is not None and succ_serial is not None:
                    kind = classify_exit_state(
                        mba=mba,
                        final_state=path.final_state,
                        incoming_state=incoming,
                        successor_serial=succ_serial,
                        state_var_stkoff=state_var_stkoff,
                        bst_node_blocks=bst_block_set,
                    )
                logger.info(
                    "supplemental classification: state 0x%X from handler blk[%d] "
                    "exit_block=%d succ=%s → %s",
                    state_value,
                    handler_serial,
                    path.exit_block,
                    "blk[%d]" % succ_serial if succ_serial is not None else "None",
                    kind.value,
                )
                if kind == ExitStateKind.TRANSIENT_CORRIDOR or state_value in transient_states:
                    continue  # Do not promote transient states.
                supplemental_states.add(state_value)

    if transient_states:
        logger.info(
            "transient denylist: %d states: %s",
            len(transient_states),
            ", ".join("0x%X" % s for s in sorted(transient_states)),
        )

    # --- Phase 2: promote from transitions (filtered by denylist) ---
    for transition in transition_result.transitions:
        state_value = transition.to_state & 0xFFFFFFFF
        if state_value not in existing_states and state_value not in transient_states:
            supplemental_states.add(state_value)

    for conds in conds_by_handler.values():
        for cond in conds:
            if cond.is_terminal_no_write:
                continue
            state_value = cond.target_state & 0xFFFFFFFF
            if state_value not in existing_states and state_value not in transient_states:
                supplemental_states.add(state_value)

    for edge in dag.edges:
        if edge.target_state is None:
            continue
        state_value = edge.target_state & 0xFFFFFFFF
        if state_value in existing_states:
            continue
        if state_value in transient_states:
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


def _discover_shadowed_range_handlers(
    dag: LinearizedStateDag,
    dispatcher: IntervalDispatcher | None,
    bst_node_blocks: set[int],
    flow_graph: FlowGraph,
    existing_states: set[int],
    handler_paths_by_handler: dict[int, tuple] | None = None,
    exact_state_to_handler: dict[int, int] | None = None,
) -> set[int]:
    """Find IntervalDispatcher range targets that are live but not in the DAG.

    When exact resolution picks a more specific handler for every concrete
    state in a range, the range-backed handler block is never materialized
    as a DAG node.  If the range block has real handler semantics (non-BST,
    has outgoing dispatcher feeder), its range-start state should be
    injected so the supplemental machinery can wire it.

    Additionally, scans handler path evaluations for exit states that fall
    in shadowed ranges but are NOT claimed by narrower exact families.
    These become incoming-edge candidates for the range-backed node.
    """
    if dispatcher is None:
        return set()

    dag_entry_anchors = {int(node.entry_anchor) for node in dag.nodes}
    shadowed_states: set[int] = set()

    # Phase 1: identify shadowed range targets (nodes without DAG presence).
    shadowed_ranges: list[tuple[int, int, int]] = []  # (lo, hi, target)
    for row in getattr(dispatcher, "_rows", ()):
        target = int(row.target)
        if target in bst_node_blocks:
            continue
        if target in dag_entry_anchors:
            continue
        block = flow_graph.get_block(target)
        if block is None:
            continue
        if block.nsucc < 1:
            continue
        shadowed_ranges.append((int(row.lo), int(row.hi), target))
        synthetic_state = int(row.lo)
        if synthetic_state not in existing_states:
            shadowed_states.add(synthetic_state)
            logger.info(
                "DAG: shadowed range-backed handler blk[%d] "
                "range=[0x%X..0x%X) not in DAG, injecting state 0x%X",
                target,
                int(row.lo),
                int(row.hi),
                synthetic_state,
            )

    if not shadowed_ranges:
        return shadowed_states

    # Phase 2: scan handler path evaluations for exit states that land in
    # shadowed ranges but are NOT claimed by a narrower exact family.
    # These states become incoming-edge candidates for the range node.
    exact_map = exact_state_to_handler or {}
    paths_map = handler_paths_by_handler or {}
    for _handler_serial, paths in paths_map.items():
        for path in paths:
            final = getattr(path, "final_state", None)
            if final is None:
                continue
            normalized = int(final) & 0xFFFFFFFF
            if normalized in existing_states:
                continue
            if normalized in exact_map:
                continue
            # Check if this state falls in any shadowed range.
            for lo, hi, target in shadowed_ranges:
                if lo <= normalized < hi:
                    shadowed_states.add(normalized)
                    logger.info(
                        "DAG: shadowed range incoming edge: "
                        "exit state 0x%X -> blk[%d] "
                        "range=[0x%X..0x%X) (not exact-claimed)",
                        normalized,
                        target,
                        lo,
                        hi,
                    )
                    break

    return shadowed_states


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
    prefer_local_corridors: bool = False,
    corrected_dag_out: list | None = None,
) -> LinearizedStateDag:
    """Build a live DAG from graph-backed analysis inputs.

    When *corrected_dag_out* is a list, a second DAG is built after the
    supplemental loop with dispatcher-validated supplemental anchors and
    appended to it.  The returned DAG uses the original (possibly stale)
    supplemental anchors — callers can use it for phase-1 corridor emission
    (preserving baseline redirect targets) and switch to the corrected DAG
    for late phases only.

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

    # Validate report rows: when a row's handler_serial disagrees with the
    # IntervalDispatcher AND the exact handler is not a direct predecessor
    # of the dispatcher target, the exact handler is stale (the BST
    # intercepts the state at a higher level).  Replace with the dispatcher
    # target so downstream DAG edges use the correct handler.
    if dispatcher is not None:
        bst_set = set(bst_node_blocks)
        patched_rows: list[TransitionRow] = []
        for row in report.rows:
            if row.state_const is None:
                patched_rows.append(row)
                continue
            disp_target = dispatcher.lookup(row.state_const)
            if (
                disp_target is not None
                and int(disp_target) != row.handler_serial
                and int(disp_target) != dispatcher_entry_serial
                and int(disp_target) not in bst_set
            ):
                exact_blk = flow_graph.get_block(row.handler_serial)
                adjacent = False
                if exact_blk is not None:
                    exact_succs = {
                        int(s) for s in getattr(exact_blk, "succs", ())
                    }
                    adjacent = int(disp_target) in exact_succs
                if not adjacent:
                    logger.info(
                        "DAG: row handler override: state 0x%X "
                        "exact=blk[%d] dispatcher=blk[%d]",
                        row.state_const & 0xFFFFFFFF,
                        row.handler_serial,
                        int(disp_target),
                    )
                    patched_rows.append(
                        replace(row, handler_serial=int(disp_target))
                    )
                    continue
            patched_rows.append(row)
        if len(patched_rows) == len(report.rows):
            report = replace(report, rows=tuple(patched_rows))

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
            prefer_local_corridors=prefer_local_corridors,
        )

    handler_entry_blocks = {
        handler.check_block for handler in transition_result.handlers.values()
    }
    if dispatcher is not None:
        for state_value in transition_result.handlers:
            try:
                dispatcher_row = dispatcher.lookup_row(state_value)
            except Exception:
                dispatcher_row = None
            if (
                dispatcher_row is not None
                and getattr(dispatcher_row, "lo", None) == state_value
            ):
                handler_entry_blocks.add(int(dispatcher_row.target))
    state_constants = set(transition_result.handlers.keys())
    real_handler_states = state_constants | set(report.handler_state_map.values())

    for row in report.rows:
        incoming_state = row.state_const
        if incoming_state is None:
            incoming_state = row.state_range_lo
        if incoming_state is None:
            continue

        analysis_anchor = row.handler_serial
        if (
            dispatcher is not None
            and row.state_const is not None
            and row.state_range_lo is None
            and row.state_range_hi is None
        ):
            try:
                dispatcher_row = dispatcher.lookup_row(row.state_const)
            except Exception:
                dispatcher_row = None
            exact_anchor = (
                int(dispatcher_row.target)
                if dispatcher_row is not None
                and getattr(dispatcher_row, "lo", None) == row.state_const
                and int(dispatcher_row.target) not in set(report.bst_node_blocks)
                else None
            )
            if exact_anchor is not None and exact_anchor != row.handler_serial:
                exact_paths = tuple(
                    evaluate_handler_paths(
                        mba,
                        exact_anchor,
                        incoming_state,
                        set(report.bst_node_blocks),
                        state_var_stkoff,
                        handler_entry_blocks,
                    )
                )
                if exact_paths:
                    analysis_anchor = exact_anchor

        paths = tuple(
            evaluate_handler_paths(
                mba,
                analysis_anchor,
                incoming_state,
                set(report.bst_node_blocks),
                state_var_stkoff,
                handler_entry_blocks,
            )
        )
        handler_paths_by_handler[row.handler_serial] = paths
        conds = tuple(
            detect_conditional_transitions(
                analysis_anchor,
                list(paths),
                state_constants,
                flow_graph,
                incoming_state=incoming_state,
            )
        )
        if conds:
            conditional_transitions_by_handler[row.handler_serial] = conds

    def _maybe_build_corrected_dag(
        rpt: DispatcherTransitionReport,
    ) -> None:
        """If corrected_dag_out is requested, rebuild DAG with dispatcher-
        validated supplemental anchors and append to the output list."""
        if corrected_dag_out is None or dispatcher is None:
            logger.info(
                "corrected_dag: skipped (corrected_dag_out=%s dispatcher=%s)",
                "None" if corrected_dag_out is None else "list",
                "None" if dispatcher is None else type(dispatcher).__name__,
            )
            return
        bst_set = set(rpt.bst_node_blocks)
        n_corrections = 0
        corrected_rows: list[TransitionRow] = []
        for row in rpt.rows:
            if row.state_const is None:
                corrected_rows.append(row)
                continue
            disp_target = dispatcher.lookup(row.state_const)
            if (
                disp_target is not None
                and int(disp_target) != row.handler_serial
                and int(disp_target) != rpt.dispatcher_entry_serial
                and int(disp_target) not in bst_set
            ):
                exact_blk = flow_graph.get_block(row.handler_serial)
                adjacent = False
                if exact_blk is not None:
                    exact_succs = {
                        int(s) for s in getattr(exact_blk, "succs", ())
                    }
                    adjacent = int(disp_target) in exact_succs
                if not adjacent:
                    corrected_rows.append(
                        replace(row, handler_serial=int(disp_target))
                    )
                    n_corrections += 1
                    continue
            corrected_rows.append(row)
        logger.info(
            "corrected_dag: checked %d rows, %d corrections",
            len(rpt.rows), n_corrections,
        )
        if len(corrected_rows) != len(rpt.rows):
            return  # safety — row count mismatch
        if n_corrections == 0:
            return
        corrected_rpt = DispatcherTransitionReport(
            dispatcher_entry_serial=rpt.dispatcher_entry_serial,
            state_var_stkoff=rpt.state_var_stkoff,
            state_var_lvar_idx=rpt.state_var_lvar_idx,
            pre_header_serial=rpt.pre_header_serial,
            initial_state=rpt.initial_state,
            handler_state_map=rpt.handler_state_map,
            handler_range_map=rpt.handler_range_map,
            bst_node_blocks=rpt.bst_node_blocks,
            rows=tuple(corrected_rows),
            summary=_summarize_rows(tuple(corrected_rows)),
            diagnostics=rpt.diagnostics,
        )
        corrected_dag_out.append(
            build_linearized_state_dag_from_graph(
                flow_graph,
                corrected_rpt,
                transition_result,
                dispatcher=dispatcher,
                handler_paths_by_handler=handler_paths_by_handler,
                conditional_transitions_by_handler=conditional_transitions_by_handler,
                prefer_local_corridors=prefer_local_corridors,
            )
        )

    report_with_supplemental = report
    dag = build_linearized_state_dag_from_graph(
        flow_graph,
        report_with_supplemental,
        transition_result,
        dispatcher=dispatcher,
        handler_paths_by_handler=handler_paths_by_handler,
        conditional_transitions_by_handler=conditional_transitions_by_handler,
        prefer_local_corridors=prefer_local_corridors,
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
            dispatcher=dispatcher,
            mba=mba,
            state_var_stkoff=state_var_stkoff,
        )
        pending_states = sorted(state for state in supplemental_states if state not in existing_states)
        if not pending_states:
            # --- Shadowed range-backed handler retention ---
            # Some IntervalDispatcher range targets are real handler bodies
            # that exact resolution never visits (exact picks a more specific
            # handler for every concrete state).  If such a target has a
            # non-trivial body, inject its range-start state so the
            # supplemental machinery materializes a DAG node for it.
            exact_map = {
                int(row.state_const) & 0xFFFFFFFF: row.handler_serial
                for row in report_with_supplemental.rows
                if row.state_const is not None
            }
            shadowed = _discover_shadowed_range_handlers(
                dag,
                dispatcher,
                set(report_with_supplemental.bst_node_blocks),
                flow_graph,
                existing_states,
                handler_paths_by_handler=handler_paths_by_handler,
                exact_state_to_handler=exact_map,
            )
            if shadowed:
                pending_states = sorted(shadowed - existing_states)
            if not pending_states:
                _maybe_build_corrected_dag(report_with_supplemental)
                return dag

        supplemental_rows: list[TransitionRow] = []
        for state_value in pending_states:
            anchor_candidates = collapsed_target_anchors.get(state_value, set())
            bst_block_set = set(report_with_supplemental.bst_node_blocks)
            cover_anchor = _resolve_fallback_anchor_from_exact_cover(
                state_value,
                report_with_supplemental,
                flow_graph,
            )
            dispatcher_row = (
                dispatcher.lookup_row(state_value) if dispatcher is not None else None
            )
            dispatcher_anchor = (
                dispatcher_row.target
                if dispatcher_row is not None and dispatcher_row.target not in bst_block_set
                else None
            )
            dispatcher_exact_anchor = (
                dispatcher_row.target
                if dispatcher_row is not None
                and getattr(dispatcher_row, "lo", None) == state_value
                and dispatcher_row.target not in bst_block_set
                else None
            )
            bridge_row = _find_unique_exact_bridge_row(
                state_value,
                report_with_supplemental,
                real_handler_states=real_handler_states,
            )
            range_anchor = _resolve_range_backed_anchor(
                state_value,
                dict(report_with_supplemental.handler_range_map),
                known_entry_anchors=known_entry_anchors,
            )
            preferred_anchor: int | None = None
            preferred_paths: tuple[HandlerPathResult, ...] = ()
            preferred_conds: tuple[ConditionalTransition, ...] = ()
            family_fallback = (
                _resolve_owner_family_fallback(anchor_candidates, dag, flow_graph)
                if prefer_local_corridors and anchor_candidates
                else None
            )
            family_fallback_anchor = family_fallback[0] if family_fallback is not None else None
            if prefer_local_corridors:
                candidate_anchor_set: set[int] = {
                    candidate_anchor
                    for candidate_anchor in anchor_candidates
                    if candidate_anchor not in bst_block_set
                }
                for candidate_anchor in (
                    family_fallback_anchor,
                    dispatcher_exact_anchor,
                    cover_anchor,
                    dispatcher_anchor,
                    range_anchor,
                    bridge_row.handler_serial if bridge_row is not None else None,
                ):
                    if (
                        candidate_anchor is not None
                        and candidate_anchor not in bst_block_set
                    ):
                        candidate_anchor_set.add(candidate_anchor)

                best_candidate: tuple[
                    int,
                    int,
                    int,
                    int,
                    int,
                    int,
                    int,
                    int,
                    tuple[HandlerPathResult, ...],
                    tuple[ConditionalTransition, ...],
                ] | None = None
                for candidate_anchor in sorted(candidate_anchor_set):
                    candidate_paths = tuple(
                        evaluate_handler_paths(
                            mba,
                            candidate_anchor,
                            state_value,
                            bst_block_set,
                            state_var_stkoff,
                            handler_entry_blocks,
                        )
                    )
                    if not candidate_paths:
                        continue
                    if _is_self_handoff_only_candidate(
                        candidate_paths,
                        state_value,
                    ):
                        continue
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
                    candidate_conds = tuple(
                        detect_conditional_transitions(
                            candidate_anchor,
                            list(candidate_paths),
                            state_constants | existing_states | set(pending_states),
                            flow_graph,
                            incoming_state=state_value,
                        )
                    )
                    score = (
                        len(candidate_normalized_states & (existing_states | set(pending_states))),
                        max(len(path.ordered_path) for path in candidate_paths),
                        sum(1 for path in candidate_paths if path.final_state is not None),
                        len(candidate_normalized_states - existing_states),
                        1 if candidate_anchor in anchor_candidates else 0,
                        1 if candidate_anchor == cover_anchor else 0,
                        -candidate_anchor,
                    )
                    if best_candidate is None or score > best_candidate[:7]:
                        best_candidate = (
                            *score,
                            candidate_anchor,
                            candidate_paths,
                            candidate_conds,
                        )
                if best_candidate is not None:
                    preferred_anchor = best_candidate[7]
                    preferred_paths = best_candidate[8]
                    preferred_conds = best_candidate[9]
            elif len(anchor_candidates) == 1:
                candidate_anchor = next(iter(anchor_candidates))
                if candidate_anchor not in bst_block_set:
                    candidate_paths = tuple(
                        evaluate_handler_paths(
                            mba,
                            candidate_anchor,
                            state_value,
                            bst_block_set,
                            state_var_stkoff,
                            handler_entry_blocks,
                        )
                    )
                    if _is_self_handoff_only_candidate(
                        candidate_paths,
                        state_value,
                    ):
                        candidate_paths = ()
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
                    if candidate_paths and (
                        bridge_row is None
                        or candidate_normalized_states & existing_states
                    ):
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

            anchor = None
            if preferred_anchor is not None:
                anchor = preferred_anchor
            if anchor is None:
                anchor = family_fallback_anchor
            if anchor is None:
                anchor = dispatcher_exact_anchor
            cover_conflicts_with_dispatcher = (
                cover_anchor is not None
                and dispatcher_anchor is not None
                and range_anchor is not None
                and dispatcher_anchor == range_anchor
                and cover_anchor != dispatcher_anchor
            )
            if anchor is None and not cover_conflicts_with_dispatcher:
                anchor = cover_anchor
            # Prefer a concrete dispatcher-resolved body entry over a
            # range-backed BST family anchor. This keeps supplemental alias
            # states off dispatcher-root compare nodes like blk[2] when the
            # interval lookup already points at the first semantic body block.
            if anchor is None:
                anchor = dispatcher_anchor
            if anchor is None and cover_conflicts_with_dispatcher:
                anchor = cover_anchor
            if anchor is None:
                anchor = range_anchor
            if anchor is None and len(anchor_candidates) == 1:
                only_candidate = next(iter(anchor_candidates))
                if only_candidate not in bst_block_set:
                    anchor = only_candidate
            if anchor is None and bridge_row is not None:
                anchor = bridge_row.handler_serial
            if anchor is None:
                continue

            if state_value == 0x27EEEA11:
                logger.info(
                    "DAG supplemental 0x27EEEA11: preferred=%s family=%s cover=%s dispatcher=%s range=%s selected=%s candidates=%s",
                    preferred_anchor,
                    family_fallback_anchor,
                    cover_anchor,
                    dispatcher_anchor,
                    range_anchor,
                    anchor,
                    sorted(anchor_candidates),
                )

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
            _maybe_build_corrected_dag(report_with_supplemental)
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
            prefer_local_corridors=prefer_local_corridors,
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
    prefer_local_corridors: bool = False,
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
    _, resolve_handler = _build_state_resolver(
        report, transition_result, dispatcher, flow_graph=flow_graph,
    )

    nodes: list[StateDagNode] = []
    primary_node_by_handler: dict[int, StateDagNode] = {}
    node_by_state: dict[int, StateDagNode] = {}

    for row in report.rows:
        node_kind = _node_kind_for_handler(report, row.handler_serial)
        paths = paths_by_handler.get(row.handler_serial, ())
        conds = conds_by_handler.get(row.handler_serial, ())
        path_root_override = None
        path_roots = _ordered_unique(
            [path.ordered_path[0] for path in paths if path.ordered_path]
        )
        if len(path_roots) == 1 and path_roots[0] != row.handler_serial:
            path_root_override = path_roots[0]
        local_blocks = _collect_local_block_order(
            row.handler_serial,
            transition_result,
            row.state_const,
            paths,
            conds,
            path_root_override=path_root_override,
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
        entry_anchor = _resolve_semantic_entry_anchor(
            row.handler_serial,
            local_blocks,
            paths,
            bst_node_blocks=report.bst_node_blocks,
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
            entry_anchor=entry_anchor,
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
            _writes = getattr(matched_path, 'state_writes', []) if matched_path is not None else []
            _last_write = _writes[-1] if _writes else None
            # Fix 1: resolve target_entry_anchor past BST region
            _target_entry: int | None = (
                target_node.entry_anchor if target_node is not None else target_handler_serial
            )
            _bst_set = set(report.bst_node_blocks)
            if _target_entry is not None and int(_target_entry) in _bst_set:
                if dispatcher is not None and transition.to_state is not None:
                    _resolved = dispatcher.lookup(transition.to_state)
                    if _resolved is not None and int(_resolved) not in _bst_set:
                        _target_entry = int(_resolved)
                    else:
                        _target_entry = None
                else:
                    _target_entry = None
            # Fix 2: downgrade edges with no state writes to UNKNOWN
            _edge_kind = SemanticEdgeKind.TRANSITION
            if matched_path is not None and not _writes:
                _edge_kind = SemanticEdgeKind.UNKNOWN
            edge = StateDagEdge(
                kind=_edge_kind,
                source_key=source_node.key,
                target_key=target_node.key if target_node is not None else None,
                target_state=transition.to_state,
                target_entry_anchor=_target_entry,
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
                last_write_site=_last_write,
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
            _cond_writes = getattr(matched_path, 'state_writes', []) if matched_path is not None else []
            _cond_last_write = _cond_writes[-1] if _cond_writes else None
            source_anchor = StateRedirectAnchor(
                kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                block_serial=cond.branch_block,
                branch_arm=cond.branch_arm,
            )
            # Fix 1: resolve target_entry_anchor past BST region
            _cond_target_entry: int | None = (
                target_node.entry_anchor if target_node is not None else target_handler_serial
            )
            _cond_bst_set = set(report.bst_node_blocks)
            if _cond_target_entry is not None and int(_cond_target_entry) in _cond_bst_set:
                if dispatcher is not None and cond.target_state is not None:
                    _cond_resolved = dispatcher.lookup(cond.target_state)
                    if _cond_resolved is not None and int(_cond_resolved) not in _cond_bst_set:
                        _cond_target_entry = int(_cond_resolved)
                    else:
                        _cond_target_entry = None
                else:
                    _cond_target_entry = None
            # Fix 2: downgrade edges with no state writes to UNKNOWN
            _cond_kind = kind
            if matched_path is not None and not _cond_writes and kind != SemanticEdgeKind.CONDITIONAL_RETURN:
                _cond_kind = SemanticEdgeKind.UNKNOWN
            edge = StateDagEdge(
                kind=_cond_kind,
                source_key=source_node.key,
                target_key=target_node.key if target_node is not None else None,
                target_state=None if cond.is_terminal_no_write else cond.target_state,
                target_entry_anchor=_cond_target_entry,
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
                last_write_site=_cond_last_write,
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

            _leftover_writes = getattr(path, 'state_writes', [])
            _leftover_last_write = _leftover_writes[-1] if _leftover_writes else None

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
                    last_write_site=_leftover_last_write,
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
                # Fix 1: resolve target_entry_anchor past BST region
                _lo_target_entry: int | None = (
                    target_node.entry_anchor if target_node is not None else target_handler_serial
                )
                _lo_bst_set = set(report.bst_node_blocks)
                if _lo_target_entry is not None and int(_lo_target_entry) in _lo_bst_set:
                    if dispatcher is not None and path.final_state is not None:
                        _lo_resolved = dispatcher.lookup(path.final_state)
                        if _lo_resolved is not None and int(_lo_resolved) not in _lo_bst_set:
                            _lo_target_entry = int(_lo_resolved)
                        else:
                            _lo_target_entry = None
                    else:
                        _lo_target_entry = None
                # Fix 2: downgrade edges with no state writes to UNKNOWN
                _lo_kind = (
                    SemanticEdgeKind.CONDITIONAL_TRANSITION
                    if branch_anchor is not None
                    and target_handler_serial is not None
                    else (
                        SemanticEdgeKind.TRANSITION
                        if target_handler_serial is not None
                        else SemanticEdgeKind.UNKNOWN
                    )
                )
                if not _leftover_writes and _lo_kind == SemanticEdgeKind.TRANSITION:
                    _lo_kind = SemanticEdgeKind.UNKNOWN
                edge = StateDagEdge(
                    kind=_lo_kind,
                    source_key=source_node.key,
                    target_key=target_node.key if target_node is not None else None,
                    target_state=path.final_state,
                    target_entry_anchor=_lo_target_entry,
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
                    last_write_site=_leftover_last_write,
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
                last_write_site=edge.last_write_site,
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

    nodes, edges = _normalize_alias_nodes(
        nodes,
        edges,
        report,
        transition_result,
        flow_graph,
        prefer_local_corridors=prefer_local_corridors,
        bst_node_blocks=report.bst_node_blocks,
        dispatcher=dispatcher,
    )
    nodes, edges = _normalize_nonhandler_exact_nodes(
        nodes,
        edges,
        report,
        transition_result,
        flow_graph,
        prefer_local_corridors=prefer_local_corridors,
        bst_node_blocks=report.bst_node_blocks,
        dispatcher=dispatcher,
    )
    nodes, edges = _promote_range_backed_nodes_to_dispatcher_bodies(
        nodes,
        edges,
        dispatcher,
        bst_node_blocks=report.bst_node_blocks,
    )
    nodes, edges = _normalize_entry_anchors_to_unique_path_starts(
        nodes,
        edges,
        bst_node_blocks=report.bst_node_blocks,
        dispatcher=dispatcher,
    )
    edges = _suppress_bst_extension_alias_edges(
        edges,
        bst_node_blocks=report.bst_node_blocks,
    )

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


def _resolve_start_key(dag: LinearizedStateDag) -> StateDagNodeKey | None:
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
    return start_key


def _catalog_render_order(dag: LinearizedStateDag) -> tuple[StateDagNodeKey, ...]:
    """Return the existing catalog-style textual order.

    This is not a semantic traversal order. It seeds the initial-state node
    first, then appends every remaining node in hex/range-sorted order, and
    only uses edge discovery to avoid duplicates while draining that queue.
    The result is useful as a stable inventory, but it does not resemble the
    original linearized program order.
    """
    start_key = _resolve_start_key(dag)

    queue: deque[StateDagNodeKey] = deque()
    visited: set[StateDagNodeKey] = set()
    if start_key is not None:
        queue.append(start_key)
        visited.add(start_key)

    for node in sorted(dag.nodes, key=_node_sort_key):
        if node.key not in visited:
            queue.append(node.key)
            visited.add(node.key)

    ordered: list[StateDagNodeKey] = []
    rendered: set[StateDagNodeKey] = set()
    edges_by_source: dict[StateDagNodeKey, list[StateDagEdge]] = defaultdict(list)
    for edge in dag.edges:
        edges_by_source[edge.source_key].append(edge)

    while queue:
        node_key = queue.popleft()
        if node_key in rendered:
            continue
        rendered.add(node_key)
        ordered.append(node_key)
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
        for edge in outgoing:
            if edge.target_key is not None and edge.target_key not in rendered:
                queue.append(edge.target_key)

    return tuple(ordered)


def _is_fallback_state_label(label: str) -> bool:
    return "_fallback" in label


def _semantic_node_sort_key(
    key: StateDagNodeKey,
    node_by_key: Mapping[StateDagNodeKey, StateDagNode],
) -> tuple[int, int, int]:
    node = node_by_key[key]
    fallback_rank = 1 if _is_fallback_state_label(node.state_label) else 0
    return (fallback_rank, *_node_sort_key(node))


def _semantic_edge_sort_key(
    edge: StateDagEdge,
    *,
    node_by_key: Mapping[StateDagNodeKey, StateDagNode],
    component_by_key: Mapping[StateDagNodeKey, int],
) -> tuple[int, int, int, int, int, int]:
    same_component = (
        0
        if edge.target_key is not None
        and component_by_key.get(edge.target_key) == component_by_key.get(edge.source_key)
        else 1
    )
    kind_rank = {
        SemanticEdgeKind.TRANSITION: 0,
        SemanticEdgeKind.CONDITIONAL_TRANSITION: 1,
        SemanticEdgeKind.CONDITIONAL_RETURN: 2,
        SemanticEdgeKind.EXIT_ROUTINE: 3,
        SemanticEdgeKind.UNKNOWN: 4,
    }[edge.kind]
    source_kind_rank = {
        RedirectSourceKind.UNCONDITIONAL: 0,
        RedirectSourceKind.CONDITIONAL_BRANCH: 1,
        RedirectSourceKind.EXIT_BLOCK: 2,
    }[edge.source_anchor.kind]
    branch_rank = (
        edge.source_anchor.branch_arm
        if edge.source_anchor.branch_arm is not None
        else -1
    )
    target_label = edge.target_label
    if edge.target_key is not None and edge.target_key in node_by_key:
        target_label = node_by_key[edge.target_key].state_label
    fallback_rank = 1 if target_label and _is_fallback_state_label(target_label) else 0
    target_state_rank = edge.target_state if edge.target_state is not None else 0xFFFFFFFF
    entry_rank = edge.target_entry_anchor if edge.target_entry_anchor is not None else 0xFFFFFFFF
    return (
        same_component,
        kind_rank,
        source_kind_rank,
        branch_rank,
        fallback_rank,
        min(target_state_rank, entry_rank),
    )


def _semantic_render_order(dag: LinearizedStateDag) -> tuple[StateDagNodeKey, ...]:
    """Return a program-like semantic traversal order.

    This traversal starts from the initial state, condenses strongly-connected
    components so loop regions stay contiguous, then walks the condensed graph
    depth-first using edge-local priority: primary/non-fallback transitions
    first, fallback siblings later, and unreachable leftovers last.
    """
    node_by_key = {node.key: node for node in dag.nodes}
    edges_by_source: dict[StateDagNodeKey, list[StateDagEdge]] = defaultdict(list)
    for edge in dag.edges:
        edges_by_source[edge.source_key].append(edge)

    key_to_idx = {key: idx for idx, key in enumerate(node_by_key)}
    idx_to_key = {idx: key for key, idx in key_to_idx.items()}
    adj: dict[int, tuple[int, ...]] = {}
    for key in node_by_key:
        succs = tuple(
            key_to_idx[edge.target_key]
            for edge in edges_by_source.get(key, ())
            if edge.target_key is not None
        )
        adj[key_to_idx[key]] = succs

    sccs = DispatchRegionDetector.tarjan_scc(adj)
    component_by_key: dict[StateDagNodeKey, int] = {}
    nodes_by_component: dict[int, list[StateDagNodeKey]] = defaultdict(list)
    for comp_idx, scc in enumerate(sccs):
        for idx in scc:
            key = idx_to_key[idx]
            component_by_key[key] = comp_idx
            nodes_by_component[comp_idx].append(key)

    start_key = _resolve_start_key(dag)
    start_component = (
        component_by_key[start_key]
        if start_key is not None and start_key in component_by_key
        else None
    )

    ordered: list[StateDagNodeKey] = []
    visited_nodes: set[StateDagNodeKey] = set()
    visited_components: set[int] = set()

    def visit_component(comp_idx: int, seed_key: StateDagNodeKey | None = None) -> None:
        if comp_idx in visited_components:
            return
        visited_components.add(comp_idx)

        component_nodes = nodes_by_component.get(comp_idx, [])
        if not component_nodes:
            return

        next_components: list[int] = []
        cross_component_seed: dict[int, StateDagNodeKey] = {}

        def record_next_component(edge: StateDagEdge) -> None:
            if edge.target_key is None:
                return
            target_comp = component_by_key[edge.target_key]
            if target_comp == comp_idx:
                return
            if target_comp not in cross_component_seed:
                cross_component_seed[target_comp] = edge.target_key
            if target_comp not in next_components:
                next_components.append(target_comp)

        def visit_node(node_key: StateDagNodeKey) -> None:
            if node_key in visited_nodes:
                return
            visited_nodes.add(node_key)
            ordered.append(node_key)
            outgoing = sorted(
                edges_by_source.get(node_key, ()),
                key=lambda edge: _semantic_edge_sort_key(
                    edge,
                    node_by_key=node_by_key,
                    component_by_key=component_by_key,
                ),
            )
            for edge in outgoing:
                if edge.target_key is None:
                    continue
                target_comp = component_by_key[edge.target_key]
                if target_comp == comp_idx:
                    visit_node(edge.target_key)
                else:
                    record_next_component(edge)

        seed_order: list[StateDagNodeKey] = []
        if seed_key is not None and seed_key in component_nodes:
            seed_order.append(seed_key)
        for key in sorted(
            component_nodes,
            key=lambda item: _semantic_node_sort_key(item, node_by_key),
        ):
            if key not in seed_order:
                seed_order.append(key)

        for key in seed_order:
            visit_node(key)

        remaining_successors = sorted(
            (
                succ
                for succ in {
                    component_by_key[edge.target_key]
                    for key in component_nodes
                    for edge in edges_by_source.get(key, ())
                    if edge.target_key is not None
                    and component_by_key[edge.target_key] != comp_idx
                }
                if succ not in next_components
            ),
            key=lambda succ: _semantic_node_sort_key(
                cross_component_seed.get(
                    succ,
                    min(
                        nodes_by_component[succ],
                        key=lambda item: _semantic_node_sort_key(item, node_by_key),
                    ),
                ),
                node_by_key,
            ),
        )
        for succ in remaining_successors:
            next_components.append(succ)

        for succ in next_components:
            visit_component(succ, cross_component_seed.get(succ))

    if start_component is not None:
        visit_component(start_component, start_key)

    for comp_idx in sorted(
        nodes_by_component,
        key=lambda comp: _semantic_node_sort_key(
            min(
                nodes_by_component[comp],
                key=lambda item: _semantic_node_sort_key(item, node_by_key),
            ),
            node_by_key,
        ),
    ):
        if comp_idx in visited_components:
            continue
        seed = min(
            nodes_by_component[comp_idx],
            key=lambda item: _semantic_node_sort_key(item, node_by_key),
        )
        visit_component(comp_idx, seed)

    return tuple(ordered)


def _render_order(
    dag: LinearizedStateDag,
    *,
    strategy: RenderOrderStrategy = RenderOrderStrategy.CATALOG,
) -> tuple[StateDagNodeKey, ...]:
    if strategy == RenderOrderStrategy.SEMANTIC:
        return _semantic_render_order(dag)
    return _catalog_render_order(dag)


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


def render_linearized_state_dag(
    dag: LinearizedStateDag,
    *,
    order_strategy: RenderOrderStrategy = RenderOrderStrategy.CATALOG,
) -> str:
    """Render a human-readable dump of a state-level DAG."""
    lines: list[str] = []
    node_by_key = {node.key: node for node in dag.nodes}
    edges_by_source: dict[StateDagNodeKey, list[StateDagEdge]] = defaultdict(list)
    for edge in dag.edges:
        edges_by_source[edge.source_key].append(edge)

    lines.append(
        "=== LINEARIZED STATE DAG ==="
        if dag.initial_state is None
        else f"=== LINEARIZED STATE DAG (starting from 0x{dag.initial_state:08X}) ==="
    )
    lines.append("")

    step_index = 0
    edge_counts: Counter[SemanticEdgeKind] = Counter()

    for node_key in _unique_render_keys(_render_order(dag, strategy=order_strategy)):
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


def _unique_render_keys(
    ordered_keys: tuple[StateDagNodeKey, ...],
) -> tuple[StateDagNodeKey, ...]:
    seen: set[StateDagNodeKey] = set()
    unique: list[StateDagNodeKey] = []
    for key in ordered_keys:
        if key in seen:
            continue
        seen.add(key)
        unique.append(key)
    return tuple(unique)


def _state_family_program_base_label(raw_label: str) -> str:
    if raw_label == "EXIT_ROUTINE":
        return raw_label
    if raw_label.startswith("0x"):
        if "_fallback" in raw_label:
            base, suffix = raw_label.split("_", 1)
            return f"STATE_{base[2:]}_{suffix}"
        return f"STATE_{raw_label[2:]}"
    return raw_label.replace(" ", "_")


def _program_label_base_for_node(
    node: StateDagNode,
    label_render_mode: LabelRenderMode,
) -> str:
    if label_render_mode == LabelRenderMode.IDA_BLOCK_SERIAL:
        return f"LABEL_{node.entry_anchor}"
    return _state_family_program_base_label(node.state_label)


def _program_label_base_for_edge(
    edge: StateDagEdge,
    label_render_mode: LabelRenderMode,
) -> str:
    if edge.kind == SemanticEdgeKind.EXIT_ROUTINE:
        return "EXIT_ROUTINE"
    if label_render_mode == LabelRenderMode.IDA_BLOCK_SERIAL:
        if edge.target_entry_anchor is not None:
            return f"LABEL_{edge.target_entry_anchor}"
        if edge.target_key is not None:
            return f"LABEL_{edge.target_key.handler_serial}"
    if edge.target_label:
        return _state_family_program_base_label(edge.target_label)
    if edge.target_state is not None:
        return _state_family_program_base_label(f"0x{edge.target_state:08X}")
    return "EXIT_ROUTINE"


def _state_family_annotation(node: StateDagNode) -> str:
    return _state_family_program_base_label(node.state_label)


def _program_node_collision_sort_key(
    node: StateDagNode,
) -> tuple[int, int, int, int, int]:
    return (
        node.entry_anchor,
        node.handler_serial,
        node.key.state_const if node.key.state_const is not None else 0xFFFFFFFF,
        node.key.range_lo if node.key.range_lo is not None else 0xFFFFFFFF,
        node.key.range_hi if node.key.range_hi is not None else 0xFFFFFFFF,
    )


def _program_node_disambiguator(node: StateDagNode) -> str:
    parts = [f"blk{node.entry_anchor}", f"h{node.handler_serial}"]
    if node.key.state_const is not None:
        parts.append(f"s{node.key.state_const:08X}")
    if node.key.range_lo is not None or node.key.range_hi is not None:
        lo = node.key.range_lo if node.key.range_lo is not None else 0
        hi = node.key.range_hi if node.key.range_hi is not None else 0
        parts.append(f"r{lo:08X}_{hi:08X}")
    return "__" + "_".join(parts)


def _build_program_labels(
    dag: LinearizedStateDag,
    label_render_mode: LabelRenderMode = LabelRenderMode.STATE_FAMILY,
) -> tuple[
    dict[StateDagNodeKey, ProgramLabel],
    dict[str, tuple[ProgramLabel, ...]],
    dict[tuple[str, int], tuple[ProgramLabel, ...]],
]:
    node_by_key = {node.key: node for node in dag.nodes}
    keys_by_base: dict[str, list[StateDagNodeKey]] = defaultdict(list)
    for node in dag.nodes:
        keys_by_base[_program_label_base_for_node(node, label_render_mode)].append(
            node.key
        )

    label_by_key: dict[StateDagNodeKey, ProgramLabel] = {}
    labels_by_base: dict[str, tuple[ProgramLabel, ...]] = {}
    labels_by_base_and_entry: dict[tuple[str, int], tuple[ProgramLabel, ...]] = {}

    for base, keys in keys_by_base.items():
        ordered_keys = sorted(
            keys,
            key=lambda key: _program_node_collision_sort_key(node_by_key[key]),
        )
        labels_for_base: list[ProgramLabel] = []
        labels_for_entry: defaultdict[int, list[ProgramLabel]] = defaultdict(list)
        for index, key in enumerate(ordered_keys, start=1):
            node = node_by_key[key]
            rendered = base
            if len(ordered_keys) > 1:
                if label_render_mode == LabelRenderMode.IDA_BLOCK_SERIAL:
                    rendered = f"{base}__{index}"
                else:
                    rendered = f"{base}{_program_node_disambiguator(node)}"
            label = ProgramLabel(
                rendered=rendered,
                base=base,
                entry_anchor=node.entry_anchor,
                label_num=(
                    node.entry_anchor
                    if label_render_mode == LabelRenderMode.IDA_BLOCK_SERIAL
                    else None
                ),
            )
            label_by_key[key] = label
            labels_for_base.append(label)
            labels_for_entry[node.entry_anchor].append(label)
        labels_by_base[base] = tuple(labels_for_base)
        for entry_anchor, labels in labels_for_entry.items():
            labels_by_base_and_entry[(base, entry_anchor)] = tuple(labels)

    return label_by_key, labels_by_base, labels_by_base_and_entry


def _program_target_label(
    edge: StateDagEdge,
    node_by_key: Mapping[StateDagNodeKey, StateDagNode],
    label_by_key: Mapping[StateDagNodeKey, ProgramLabel],
    labels_by_base: Mapping[str, tuple[ProgramLabel, ...]],
    labels_by_base_and_entry: Mapping[tuple[str, int], tuple[ProgramLabel, ...]],
    label_render_mode: LabelRenderMode,
) -> str:
    if edge.target_key is not None:
        target_label = label_by_key.get(edge.target_key)
        if target_label is not None:
            return target_label.rendered
        target_node = node_by_key.get(edge.target_key)
        if target_node is not None:
            base = _program_label_base_for_node(target_node, label_render_mode)
            labels = labels_by_base.get(base, ())
            if len(labels) == 1:
                return labels[0].rendered
    base = _program_label_base_for_edge(edge, label_render_mode)
    if edge.target_label or edge.target_state is not None:
        if edge.target_entry_anchor is not None:
            labels = labels_by_base_and_entry.get((base, edge.target_entry_anchor), ())
            if len(labels) == 1:
                return labels[0].rendered
        labels = labels_by_base.get(base, ())
        if len(labels) == 1:
            return labels[0].rendered
        return base
    return "EXIT_ROUTINE"


def _program_action(
    edge: StateDagEdge,
    node_by_key: Mapping[StateDagNodeKey, StateDagNode],
    label_by_key: Mapping[StateDagNodeKey, ProgramLabel],
    labels_by_base: Mapping[str, tuple[ProgramLabel, ...]],
    labels_by_base_and_entry: Mapping[tuple[str, int], tuple[ProgramLabel, ...]],
    label_render_mode: LabelRenderMode,
) -> str:
    if edge.kind == SemanticEdgeKind.CONDITIONAL_RETURN:
        return "return result;"
    if edge.kind == SemanticEdgeKind.EXIT_ROUTINE:
        return "goto EXIT_ROUTINE;"
    target = _program_target_label(
        edge,
        node_by_key,
        label_by_key,
        labels_by_base,
        labels_by_base_and_entry,
        label_render_mode,
    )
    if label_render_mode == LabelRenderMode.IDA_BLOCK_SERIAL:
        annotation = _program_label_base_for_edge(
            edge,
            LabelRenderMode.STATE_FAMILY,
        )
        return f"goto {target};  /* {annotation} */"
    return (
        "goto "
        f"{target};"
    )


def _emit_program_state_family_comment(
    lines: list[str],
    node: StateDagNode,
    *,
    label_render_mode: LabelRenderMode,
    comment_mode: ProgramCommentMode,
) -> None:
    if comment_mode == ProgramCommentMode.MINIMAL:
        return
    if label_render_mode != LabelRenderMode.IDA_BLOCK_SERIAL:
        return
    lines.append(f"    // state-family: {_state_family_annotation(node)}")


def _negate_condition_text(condition: str) -> str:
    match = _SIMPLE_COMPARE_RE.match(condition)
    if match is None:
        return f"!({condition})"
    op = match.group("op")
    negated_op = {
        "==": "!=",
        "!=": "==",
        "<u": ">=u",
        "<=u": ">u",
        ">u": "<=u",
        ">=u": "<u",
        "<s": ">=s",
        "<=s": ">s",
        ">s": "<=s",
        ">=s": "<s",
    }.get(op)
    if negated_op is None:
        return f"!({condition})"
    return f"{match.group('lhs')} {negated_op} {match.group('rhs')}"


def _is_terminal_control_rendered_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if stripped.startswith("/* assert */ "):
        stripped = stripped[len("/* assert */ ") :].lstrip()
    return (
        stripped.startswith("goto ")
        or stripped.startswith("if (")
        or stripped.startswith("return")
        or stripped.startswith("switch(")
    )


def _prune_terminal_control_lines(
    rendered_lines: tuple[str, ...],
) -> tuple[str, ...]:
    pruned = list(rendered_lines)
    while pruned and _is_terminal_control_rendered_line(pruned[-1]):
        pruned.pop()
    return tuple(pruned)


def _prune_transition_state_write_lines(
    rendered_lines: tuple[str, ...],
    *,
    transition_state_values: set[int],
) -> tuple[str, ...]:
    if not transition_state_values:
        return rendered_lines
    pruned = list(rendered_lines)
    while pruned:
        match = _SIMPLE_CONST_ASSIGN_RE.match(pruned[-1].strip())
        if match is None:
            break
        try:
            value = int(match.group(1), 16)
        except ValueError:
            break
        if value not in transition_state_values:
            break
        pruned.pop()
    return tuple(pruned)


def _emit_block_payload_lines(
    out_lines: list[str],
    *,
    blocks: tuple[int, ...],
    indent: str,
    block_payload_by_serial: Mapping[int, tuple[str, ...]] | None,
    transition_state_values: set[int] | None = None,
) -> None:
    if not block_payload_by_serial:
        return
    for block_serial in blocks:
        payload_lines = tuple(block_payload_by_serial.get(block_serial, ()))
        payload_lines = _prune_terminal_control_lines(payload_lines)
        payload_lines = _prune_transition_state_write_lines(
            payload_lines,
            transition_state_values=transition_state_values or set(),
        )
        for payload_line in payload_lines:
            if payload_line.strip():
                out_lines.append(f"{indent}{payload_line}")


def _sanitize_segment_suffix(segment_id: str) -> str:
    sanitized = []
    for char in segment_id:
        if char.isalnum():
            sanitized.append(char)
        else:
            sanitized.append("_")
    text = "".join(sanitized).strip("_")
    return text or "segment"


def _find_entry_segment_id(node: StateDagNode) -> str | None:
    for segment in node.local_segments:
        if node.entry_anchor in segment.blocks:
            return segment.segment_id
    if node.local_segments:
        return node.local_segments[0].segment_id
    return None


def _build_program_segment_labels(
    node: StateDagNode,
    node_label: str,
) -> dict[str, str]:
    return {
        segment.segment_id: f"{node_label}__{_sanitize_segment_suffix(segment.segment_id)}"
        for segment in node.local_segments
    }


def _local_segment_sort_key(segment: StateLocalSegment) -> tuple[int, int, str]:
    first_block = segment.blocks[0] if segment.blocks else 0xFFFFFFFF
    return (first_block, segment.kind.value, segment.segment_id)


def _local_segment_render_order(node: StateDagNode) -> tuple[str, ...]:
    if not node.local_segments:
        return ()

    segment_by_id = {segment.segment_id: segment for segment in node.local_segments}
    local_edges_by_source: dict[str, list[StateLocalEdge]] = defaultdict(list)
    for edge in node.local_edges:
        local_edges_by_source[edge.source_segment_id].append(edge)

    ordered: list[str] = []
    visited: set[str] = set()

    def visit(segment_id: str) -> None:
        if segment_id in visited or segment_id not in segment_by_id:
            return
        visited.add(segment_id)
        ordered.append(segment_id)
        outgoing = sorted(
            local_edges_by_source.get(segment_id, ()),
            key=lambda edge: (
                edge.branch_arm if edge.branch_arm is not None else -1,
                edge.kind.value,
                edge.target_segment_id,
            ),
        )
        for edge in outgoing:
            visit(edge.target_segment_id)

    entry_segment_id = _find_entry_segment_id(node)
    if entry_segment_id is not None:
        visit(entry_segment_id)

    for segment in sorted(node.local_segments, key=_local_segment_sort_key):
        visit(segment.segment_id)

    return tuple(ordered)


def _render_segment_edge_action(
    edge: StateDagEdge,
    *,
    node_by_key: Mapping[StateDagNodeKey, StateDagNode],
    label_by_key: Mapping[StateDagNodeKey, ProgramLabel],
    labels_by_base: Mapping[str, tuple[ProgramLabel, ...]],
    labels_by_base_and_entry: Mapping[tuple[str, int], tuple[ProgramLabel, ...]],
    label_render_mode: LabelRenderMode,
) -> str:
    return _program_action(
        edge,
        node_by_key,
        label_by_key,
        labels_by_base,
        labels_by_base_and_entry,
        label_render_mode,
    )


def _render_explicit_local_segment_program(
    dag: LinearizedStateDag,
    *,
    order_strategy: RenderOrderStrategy,
    label_render_mode: LabelRenderMode,
    block_payload_by_serial: Mapping[int, tuple[str, ...]] | None = None,
) -> _RenderedProgramBuilder:
    lines = _RenderedProgramBuilder()
    node_by_key = {node.key: node for node in dag.nodes}
    label_by_key, labels_by_base, labels_by_base_and_entry = _build_program_labels(
        dag,
        label_render_mode=label_render_mode,
    )
    edges_by_source: dict[StateDagNodeKey, list[StateDagEdge]] = defaultdict(list)
    for edge in dag.edges:
        edges_by_source[edge.source_key].append(edge)

    def _edge_target_states(edges: tuple[StateDagEdge, ...] | list[StateDagEdge]) -> set[int]:
        return {
            edge.target_state & 0xFFFFFFFF
            for edge in edges
            if edge.target_state is not None
        }

    ordered_keys = _unique_render_keys(_render_order(dag, strategy=order_strategy))
    lines.append(
        "=== LINEARIZED STATE PROGRAM ==="
        if dag.initial_state is None
        else f"=== LINEARIZED STATE PROGRAM (starting from 0x{dag.initial_state:08X}) ==="
    )
    lines.append("")

    emitted_exit_routine = False
    for node_key in ordered_keys:
        node = node_by_key[node_key]
        program_label = label_by_key[node_key]
        lines.begin_node(
            program_label.rendered,
            node_kind="state_family",
            state_label=node.state_label,
            handler_serial=node.handler_serial,
            entry_anchor=node.entry_anchor,
            label_num=program_label.label_num,
        )
        _emit_program_state_family_comment(
            lines,
            node,
            label_render_mode=label_render_mode,
            comment_mode=ProgramCommentMode.DEBUG_METADATA,
        )
        lines.append(f"    // entry blk[{node.entry_anchor}] [{node.kind.name.lower()}]")
        if node.owned_blocks:
            owned = ", ".join(f"blk[{blk}]" for blk in node.owned_blocks)
            lines.append(f"    // blocks: {owned}")
        if node.shared_suffix_blocks:
            shared = ", ".join(f"blk[{blk}]" for blk in node.shared_suffix_blocks)
            lines.append(f"    // shared-suffix: {shared}")

        if not node.local_segments:
            outgoing = sorted(
                edges_by_source.get(node_key, ()),
                key=lambda edge: (
                    edge.source_anchor.block_serial,
                    edge.source_anchor.kind.value,
                    (
                        edge.source_anchor.branch_arm
                        if edge.source_anchor.branch_arm is not None
                        else -1
                    ),
                    edge.kind.value,
                    edge.target_state if edge.target_state is not None else 0xFFFFFFFF,
                ),
            )
            _emit_block_payload_lines(
                lines,
                blocks=node.owned_blocks,
                indent="    ",
                block_payload_by_serial=block_payload_by_serial,
                transition_state_values=_edge_target_states(outgoing),
            )
            if not outgoing:
                lines.append("    // no outgoing semantic edges")
                lines.append("")
                continue
            for edge in outgoing:
                if edge.kind == SemanticEdgeKind.EXIT_ROUTINE:
                    emitted_exit_routine = True
                lines.append(
                    "    "
                    f"{_render_segment_edge_action(edge, node_by_key=node_by_key, label_by_key=label_by_key, labels_by_base=labels_by_base, labels_by_base_and_entry=labels_by_base_and_entry, label_render_mode=label_render_mode)}  "
                    f"// {_format_anchor(edge.source_anchor)} {edge.kind.name.lower()}"
                )
            lines.append("")
            continue

        segment_labels = _build_program_segment_labels(node, program_label.rendered)
        entry_segment_id = _find_entry_segment_id(node)
        if entry_segment_id is not None:
            lines.append(f"    goto {segment_labels[entry_segment_id]};")
        else:
            lines.append("    // no entry local segment")
        lines.append("")

        local_edges_by_source: dict[str, list[StateLocalEdge]] = defaultdict(list)
        for edge in node.local_edges:
            local_edges_by_source[edge.source_segment_id].append(edge)

        semantic_edges_by_segment: dict[str, list[StateDagEdge]] = defaultdict(list)
        for edge in edges_by_source.get(node_key, ()):
            for segment in node.local_segments:
                if edge.source_anchor.block_serial in segment.blocks:
                    semantic_edges_by_segment[segment.segment_id].append(edge)
                    break

        segment_by_id = {segment.segment_id: segment for segment in node.local_segments}
        for segment_id in _local_segment_render_order(node):
            segment = segment_by_id[segment_id]
            lines.begin_node(
                segment_labels[segment_id],
                node_kind="local_boundary",
            )
            blocks = ", ".join(f"blk[{blk}]" for blk in segment.blocks)
            lines.append(
                f"    // {segment.kind.name.lower()} segment: {segment.segment_id}"
                + (f" ({blocks})" if blocks else "")
            )

            semantic_edges = sorted(
                semantic_edges_by_segment.get(segment_id, ()),
                key=lambda edge: (
                    edge.source_anchor.block_serial,
                    edge.source_anchor.kind.value,
                    edge.source_anchor.branch_arm
                    if edge.source_anchor.branch_arm is not None
                    else -1,
                    edge.kind.value,
                ),
            )
            local_edges = sorted(
                local_edges_by_source.get(segment_id, ()),
                key=lambda edge: (
                    edge.branch_arm if edge.branch_arm is not None else -1,
                    edge.kind.value,
                    edge.target_segment_id,
                ),
            )
            _emit_block_payload_lines(
                lines,
                blocks=segment.blocks,
                indent="    ",
                block_payload_by_serial=block_payload_by_serial,
                transition_state_values=_edge_target_states(semantic_edges),
            )

            semantic_branch_by_arm: dict[int, StateDagEdge] = {}
            semantic_passthrough: list[StateDagEdge] = []
            for edge in semantic_edges:
                if (
                    edge.source_anchor.kind == RedirectSourceKind.CONDITIONAL_BRANCH
                    and edge.source_anchor.branch_arm is not None
                ):
                    semantic_branch_by_arm[edge.source_anchor.branch_arm] = edge
                else:
                    semantic_passthrough.append(edge)

            local_branch_by_arm: dict[int, StateLocalEdge] = {}
            local_passthrough: list[StateLocalEdge] = []
            for edge in local_edges:
                if edge.branch_arm is not None:
                    local_branch_by_arm[edge.branch_arm] = edge
                else:
                    local_passthrough.append(edge)

            if semantic_passthrough:
                local_passthrough = []

            taken_semantic = semantic_branch_by_arm.get(1)
            fallthrough_semantic = semantic_branch_by_arm.get(0)
            taken_local = local_branch_by_arm.get(1)
            fallthrough_local = local_branch_by_arm.get(0)

            if taken_semantic is not None or fallthrough_semantic is not None:
                if taken_semantic is not None:
                    if taken_semantic.kind == SemanticEdgeKind.EXIT_ROUTINE:
                        emitted_exit_routine = True
                    lines.append(
                        f"    if (/* blk[{taken_semantic.source_anchor.block_serial}].taken */)"
                    )
                    lines.append(
                        "        "
                        f"{_render_segment_edge_action(taken_semantic, node_by_key=node_by_key, label_by_key=label_by_key, labels_by_base=labels_by_base, labels_by_base_and_entry=labels_by_base_and_entry, label_render_mode=label_render_mode)}"
                    )
                elif taken_local is not None:
                    lines.append(f"    if (/* {segment.segment_id}.taken */)")
                    lines.append(
                        f"        goto {segment_labels[taken_local.target_segment_id]};"
                    )

                if fallthrough_semantic is not None:
                    if fallthrough_semantic.kind == SemanticEdgeKind.EXIT_ROUTINE:
                        emitted_exit_routine = True
                    lines.append(
                        "    "
                        f"{_render_segment_edge_action(fallthrough_semantic, node_by_key=node_by_key, label_by_key=label_by_key, labels_by_base=labels_by_base, labels_by_base_and_entry=labels_by_base_and_entry, label_render_mode=label_render_mode)}"
                        f"  // blk[{fallthrough_semantic.source_anchor.block_serial}].fallthrough"
                    )
                elif fallthrough_local is not None:
                    lines.append(
                        f"    goto {segment_labels[fallthrough_local.target_segment_id]};  // {segment.segment_id}.fallthrough"
                    )
            elif taken_local is not None and fallthrough_local is not None:
                lines.append(f"    if (/* {segment.segment_id}.taken */)")
                lines.append(
                    f"        goto {segment_labels[taken_local.target_segment_id]};"
                )
                lines.append(
                    f"    goto {segment_labels[fallthrough_local.target_segment_id]};  // {segment.segment_id}.fallthrough"
                )

            for edge in semantic_passthrough:
                if edge.kind == SemanticEdgeKind.EXIT_ROUTINE:
                    emitted_exit_routine = True
                lines.append(
                    "    "
                    f"{_render_segment_edge_action(edge, node_by_key=node_by_key, label_by_key=label_by_key, labels_by_base=labels_by_base, labels_by_base_and_entry=labels_by_base_and_entry, label_render_mode=label_render_mode)}  "
                    f"// {_format_anchor(edge.source_anchor)} {edge.kind.name.lower()}"
                )

            for edge in local_passthrough:
                lines.append(
                    f"    goto {segment_labels[edge.target_segment_id]};  "
                    f"// {edge.source_segment_id} {edge.kind.name.lower()}"
                )

            if not (
                taken_semantic
                or fallthrough_semantic
                or taken_local
                or fallthrough_local
                or semantic_passthrough
                or local_passthrough
            ):
                lines.append("    // no local or semantic exits")
            lines.append("")

    if emitted_exit_routine:
        lines.begin_node("EXIT_ROUTINE", node_kind="exit_routine")
        lines.append("    return result;")
        lines.append("")

    return lines


def _render_selective_local_boundary_program(
    dag: LinearizedStateDag,
    *,
    order_strategy: RenderOrderStrategy,
    boundary_inline_mode: BoundaryInlineMode,
    label_render_mode: LabelRenderMode,
    comment_mode: ProgramCommentMode,
    block_payload_by_serial: Mapping[int, tuple[str, ...]] | None = None,
) -> _RenderedProgramBuilder:
    lines = _RenderedProgramBuilder()
    node_by_key = {node.key: node for node in dag.nodes}
    label_by_key, labels_by_base, labels_by_base_and_entry = _build_program_labels(
        dag,
        label_render_mode=label_render_mode,
    )
    edges_by_source: dict[StateDagNodeKey, list[StateDagEdge]] = defaultdict(list)
    for edge in dag.edges:
        edges_by_source[edge.source_key].append(edge)

    def emit_debug_comment(indent: str, text: str) -> None:
        if comment_mode == ProgramCommentMode.DEBUG_METADATA:
            lines.append(f"{indent}{text}")

    def debug_suffix(text: str) -> str:
        return text if comment_mode == ProgramCommentMode.DEBUG_METADATA else ""

    def with_optional_comment(action: str, comment: str = "") -> str:
        return f"{action}  {comment}" if comment else action

    def _edge_target_states(edges: tuple[StateDagEdge, ...] | list[StateDagEdge]) -> set[int]:
        return {
            edge.target_state & 0xFFFFFFFF
            for edge in edges
            if edge.target_state is not None
        }

    ordered_keys = _unique_render_keys(_render_order(dag, strategy=order_strategy))
    lines.append(
        "=== LINEARIZED STATE PROGRAM ==="
        if dag.initial_state is None
        else f"=== LINEARIZED STATE PROGRAM (starting from 0x{dag.initial_state:08X}) ==="
    )
    lines.append("")

    emitted_exit_routine = False
    for node_key in ordered_keys:
        node = node_by_key[node_key]
        program_label = label_by_key[node_key]
        lines.begin_node(
            program_label.rendered,
            node_kind="state_family",
            state_label=node.state_label,
            handler_serial=node.handler_serial,
            entry_anchor=node.entry_anchor,
            label_num=program_label.label_num,
        )
        _emit_program_state_family_comment(
            lines,
            node,
            label_render_mode=label_render_mode,
            comment_mode=comment_mode,
        )
        emit_debug_comment("    ", f"// entry blk[{node.entry_anchor}] [{node.kind.name.lower()}]")
        if node.owned_blocks:
            owned = ", ".join(f"blk[{blk}]" for blk in node.owned_blocks)
            emit_debug_comment("    ", f"// blocks: {owned}")
        if node.shared_suffix_blocks:
            shared = ", ".join(f"blk[{blk}]" for blk in node.shared_suffix_blocks)
            emit_debug_comment("    ", f"// shared-suffix: {shared}")

        if not node.local_segments:
            outgoing = sorted(
                edges_by_source.get(node_key, ()),
                key=lambda edge: (
                    edge.source_anchor.block_serial,
                    edge.source_anchor.kind.value,
                    (
                        edge.source_anchor.branch_arm
                        if edge.source_anchor.branch_arm is not None
                        else -1
                    ),
                    edge.kind.value,
                    edge.target_state if edge.target_state is not None else 0xFFFFFFFF,
                ),
            )
            _emit_block_payload_lines(
                lines,
                blocks=node.owned_blocks,
                indent="    ",
                block_payload_by_serial=block_payload_by_serial,
                transition_state_values=_edge_target_states(outgoing),
            )
            if not outgoing:
                emit_debug_comment("    ", "// no outgoing semantic edges")
                lines.append("")
                continue
            for edge in outgoing:
                if edge.kind == SemanticEdgeKind.EXIT_ROUTINE:
                    emitted_exit_routine = True
                comment = (
                    f"{_format_anchor(edge.source_anchor)} {edge.kind.name.lower()}"
                    if comment_mode == ProgramCommentMode.DEBUG_METADATA
                    else ""
                )
                lines.append(
                    "    "
                    + with_optional_comment(
                        _render_segment_edge_action(
                            edge,
                            node_by_key=node_by_key,
                            label_by_key=label_by_key,
                            labels_by_base=labels_by_base,
                            labels_by_base_and_entry=labels_by_base_and_entry,
                            label_render_mode=label_render_mode,
                        ),
                        f"// {comment}" if comment else "",
                    )
                )
            lines.append("")
            continue

        segment_by_id = {segment.segment_id: segment for segment in node.local_segments}
        segment_labels = _build_program_segment_labels(node, program_label.rendered)
        segment_id_by_label = {label: segment_id for segment_id, label in segment_labels.items()}
        entry_segment_id = _find_entry_segment_id(node)

        local_edges_by_source: dict[str, list[StateLocalEdge]] = defaultdict(list)
        local_incoming_count: Counter[str] = Counter()
        local_incoming_by_target: dict[str, list[StateLocalEdge]] = defaultdict(list)
        for edge in node.local_edges:
            local_edges_by_source[edge.source_segment_id].append(edge)
            local_incoming_count[edge.target_segment_id] += 1
            local_incoming_by_target[edge.target_segment_id].append(edge)

        semantic_edges_by_segment: dict[str, list[StateDagEdge]] = defaultdict(list)
        for edge in edges_by_source.get(node_key, ()):
            for segment in node.local_segments:
                if edge.source_anchor.block_serial in segment.blocks:
                    semantic_edges_by_segment[segment.segment_id].append(edge)
                    break

        resolved_target_cache: dict[str, tuple[str, str | None, tuple[str, ...]]] = {}
        branch_meaning_cache: dict[str, bool] = {}

        def branch_arms(segment_id: str) -> dict[int, StateLocalEdge]:
            return {
                edge.branch_arm: edge
                for edge in local_edges_by_source.get(segment_id, ())
                if edge.branch_arm is not None
            }

        def _edge_signature(edge: StateDagEdge) -> tuple[str, str]:
            return (
                edge.kind.name,
                _render_segment_edge_action(
                    edge,
                    node_by_key=node_by_key,
                    label_by_key=label_by_key,
                    labels_by_base=labels_by_base,
                    labels_by_base_and_entry=labels_by_base_and_entry,
                    label_render_mode=label_render_mode,
                ),
            )

        def segment_is_meaningful(segment_id: str, stack: tuple[str, ...] = ()) -> bool:
            if segment_id in branch_meaning_cache:
                return branch_meaning_cache[segment_id]
            if segment_id in stack:
                return True
            segment = segment_by_id[segment_id]
            if semantic_edges_by_segment.get(segment_id):
                branch_meaning_cache[segment_id] = True
                return True
            if segment.kind in (
                LocalSegmentKind.JOIN,
                LocalSegmentKind.SHARED_SUFFIX,
                LocalSegmentKind.TERMINAL_SUFFIX,
            ):
                branch_meaning_cache[segment_id] = True
                return True
            if local_incoming_count.get(segment_id, 0) > 1:
                branch_meaning_cache[segment_id] = True
                return True

            arms = branch_arms(segment_id)
            if len(arms) >= 2:
                outcomes = {
                    arm: resolve_target(edge.target_segment_id, stack + (segment_id,))
                    for arm, edge in arms.items()
                }
                signatures = {
                    (outcome_kind, target_label)
                    for outcome_kind, target_label, _collapsed_chain in outcomes.values()
                }
                meaningful = len(signatures) > 1
                branch_meaning_cache[segment_id] = meaningful
                return meaningful

            branch_meaning_cache[segment_id] = False
            return False

        def resolve_target(
            segment_id: str,
            stack: tuple[str, ...] = (),
        ) -> tuple[str, str | None, tuple[str, ...]]:
            if segment_id in resolved_target_cache and not stack:
                return resolved_target_cache[segment_id]
            if segment_id in stack:
                result = ("segment", segment_labels.get(segment_id), (segment_id,))
                if not stack:
                    resolved_target_cache[segment_id] = result
                return result
            if segment_is_meaningful(segment_id, stack):
                result = ("segment", segment_labels[segment_id], ())
                if not stack:
                    resolved_target_cache[segment_id] = result
                return result

            semantic_edges = semantic_edges_by_segment.get(segment_id, ())
            if semantic_edges:
                edge = sorted(
                    semantic_edges,
                    key=lambda item: (
                        item.source_anchor.block_serial,
                        item.source_anchor.kind.value,
                        item.kind.value,
                    ),
                )[0]
                result = (
                    "semantic",
                    _render_segment_edge_action(
                        edge,
                        node_by_key=node_by_key,
                        label_by_key=label_by_key,
                        labels_by_base=labels_by_base,
                        labels_by_base_and_entry=labels_by_base_and_entry,
                        label_render_mode=label_render_mode,
                    ),
                    (),
                )
                if not stack:
                    resolved_target_cache[segment_id] = result
                return result

            local_edges = sorted(
                local_edges_by_source.get(segment_id, ()),
                key=lambda edge: (
                    edge.branch_arm if edge.branch_arm is not None else -1,
                    edge.kind.value,
                    edge.target_segment_id,
                ),
            )
            if not local_edges:
                result = ("deadend", None, (segment_id,))
                if not stack:
                    resolved_target_cache[segment_id] = result
                return result

            next_edge = local_edges[0]
            outcome_kind, target_label, collapsed_chain = resolve_target(
                next_edge.target_segment_id,
                stack + (segment_id,),
            )
            result = (outcome_kind, target_label, (segment_id,) + collapsed_chain)
            if not stack:
                resolved_target_cache[segment_id] = result
            return result

        def _collapse_comment(collapsed_chain: tuple[str, ...]) -> str:
            if comment_mode != ProgramCommentMode.DEBUG_METADATA:
                return ""
            if not collapsed_chain:
                return ""
            blocks: list[str] = []
            seen_blocks: set[int] = set()
            for collapsed_id in collapsed_chain:
                segment = segment_by_id.get(collapsed_id)
                if segment is None:
                    continue
                for block in segment.blocks:
                    if block in seen_blocks:
                        continue
                    seen_blocks.add(block)
                    blocks.append(f"blk[{block}]")
            if not blocks:
                return ""
            return "  // via " + ", ".join(blocks)

        def _emit_collapsed_chain_payload(
            collapsed_chain: tuple[str, ...],
            *,
            indent: str,
        ) -> bool:
            emitted = False
            if not block_payload_by_serial:
                return emitted
            for collapsed_id in collapsed_chain:
                segment = segment_by_id.get(collapsed_id)
                if segment is None:
                    continue
                before = len(lines)
                _emit_block_payload_lines(
                    lines,
                    blocks=segment.blocks,
                    indent=indent,
                    block_payload_by_serial=block_payload_by_serial,
                )
                emitted = emitted or len(lines) > before
            return emitted

        def _extract_terminal_if_condition(segment_id: str) -> str | None:
            if not block_payload_by_serial:
                return None
            segment = segment_by_id.get(segment_id)
            if segment is None:
                return None
            for block_serial in reversed(segment.blocks):
                for raw_line in reversed(tuple(block_payload_by_serial.get(block_serial, ()))):
                    stripped = raw_line.strip()
                    if not stripped:
                        continue
                    if stripped.startswith("/* assert */ "):
                        stripped = stripped[len("/* assert */ ") :].lstrip()
                    if stripped.startswith("if (") and ") goto " in stripped:
                        return stripped[len("if (") : stripped.index(") goto ")]
                    if not _is_terminal_control_rendered_line(stripped):
                        break
            return None

        def _emit_structured_collapsed_chain_to_boundary(
            collapsed_chain: tuple[str, ...],
            *,
            final_segment_id: str,
            indent: str,
        ) -> bool:
            if not collapsed_chain or not block_payload_by_serial:
                return False
            first_segment_id = collapsed_chain[0]
            remaining_chain = collapsed_chain[1:]
            if not remaining_chain:
                return False
            first_segment = segment_by_id.get(first_segment_id)
            if first_segment is None or first_segment.kind != LocalSegmentKind.BRANCH:
                return False

            arms = branch_arms(first_segment_id)
            taken_edge = arms.get(1)
            fallthrough_edge = arms.get(0)
            if taken_edge is None or fallthrough_edge is None:
                return False

            def _resolves_to_final(segment_id: str) -> bool:
                outcome_kind, target_label, _ = resolve_target(segment_id)
                if outcome_kind != "segment" or target_label is None:
                    return False
                return segment_id_by_label.get(target_label) == final_segment_id

            next_segment_id = remaining_chain[0]
            taken_is_next = taken_edge.target_segment_id == next_segment_id
            fallthrough_is_next = fallthrough_edge.target_segment_id == next_segment_id
            taken_is_final = _resolves_to_final(taken_edge.target_segment_id)
            fallthrough_is_final = _resolves_to_final(fallthrough_edge.target_segment_id)

            if not (
                (taken_is_next and fallthrough_is_final)
                or (fallthrough_is_next and taken_is_final)
            ):
                return False

            condition = _extract_terminal_if_condition(first_segment_id)
            if not condition:
                return False

            _emit_block_payload_lines(
                lines,
                blocks=first_segment.blocks,
                indent=indent,
                block_payload_by_serial=block_payload_by_serial,
                transition_state_values=set(),
            )

            if taken_is_next and fallthrough_is_final:
                guard = condition
            else:
                guard = _negate_condition_text(condition)

            lines.append(f"{indent}if ({guard})")
            lines.append(f"{indent}{{")
            _emit_collapsed_chain_payload(
                remaining_chain,
                indent=f"{indent}    ",
            )
            lines.append(f"{indent}}}")
            return True

        def _render_local_destination(
            segment_id: str,
        ) -> tuple[str, str, tuple[str, ...]]:
            outcome_kind, target_label, collapsed_chain = resolve_target(segment_id)
            comment = _collapse_comment(collapsed_chain)
            if outcome_kind in {"segment", "semantic"} and target_label is not None:
                return (f"goto {target_label};", comment, collapsed_chain)
            return ("// local dead-end", comment, collapsed_chain)

        owned_block_set = set(node.owned_blocks)

        def _semantic_edge_tail_blocks(
            edge: StateDagEdge,
            *,
            current_segment: StateLocalSegment,
        ) -> tuple[int, ...]:
            if not edge.ordered_path:
                return ()
            tail_blocks: list[int] = []
            saw_source = False
            seen_blocks: set[int] = set(current_segment.blocks)
            for block_serial in edge.ordered_path:
                if not saw_source:
                    if block_serial == edge.source_anchor.block_serial:
                        saw_source = True
                    continue
                if block_serial in seen_blocks:
                    continue
                if block_serial not in owned_block_set:
                    continue
                seen_blocks.add(block_serial)
                tail_blocks.append(block_serial)
            return tuple(tail_blocks)

        def _emit_semantic_edge_tail_payload(
            edge: StateDagEdge,
            *,
            current_segment: StateLocalSegment,
            indent: str,
        ) -> bool:
            tail_blocks = _semantic_edge_tail_blocks(edge, current_segment=current_segment)
            if not tail_blocks:
                return False
            before = len(lines)
            _emit_block_payload_lines(
                lines,
                blocks=tail_blocks,
                indent=indent,
                block_payload_by_serial=block_payload_by_serial,
                transition_state_values=_edge_target_states((edge,)),
            )
            return len(lines) > before

        def segment_is_trivial_leaf(segment_id: str) -> bool:
            if semantic_edges_by_segment.get(segment_id):
                return False
            if local_edges_by_source.get(segment_id):
                return False
            segment = segment_by_id[segment_id]
            return segment.kind in (
                LocalSegmentKind.SHARED_SUFFIX,
                LocalSegmentKind.TERMINAL_SUFFIX,
            )

        visible_segments = [
            segment_id
            for segment_id in _local_segment_render_order(node)
            if (
                segment_id != entry_segment_id
                and segment_is_meaningful(segment_id)
                and not segment_is_trivial_leaf(segment_id)
            )
        ]
        inlined_segments: set[str] = set()
        visible_parent_cache: dict[str, frozenset[str]] = {}

        def visible_parent_boundaries(
            segment_id: str,
            stack: tuple[str, ...] = (),
        ) -> frozenset[str]:
            if segment_id in visible_parent_cache and not stack:
                return visible_parent_cache[segment_id]
            if segment_id in stack:
                return frozenset({segment_id})

            visible_parents: set[str] = set()
            for edge in local_incoming_by_target.get(segment_id, ()):
                source_segment_id = edge.source_segment_id
                if (
                    source_segment_id == entry_segment_id
                    or segment_is_meaningful(source_segment_id)
                ):
                    visible_parents.add(source_segment_id)
                    continue
                visible_parents.update(
                    visible_parent_boundaries(
                        source_segment_id,
                        stack + (segment_id,),
                    )
                )

            result = frozenset(visible_parents)
            if not stack:
                visible_parent_cache[segment_id] = result
            return result

        def can_inline_boundary_target(segment_id: str) -> bool:
            if boundary_inline_mode != BoundaryInlineMode.INLINE_SINGLE_LEVEL:
                return False
            if segment_id == entry_segment_id or segment_id in inlined_segments:
                return False
            if segment_id not in visible_segments:
                return False
            if len(visible_parent_boundaries(segment_id)) > 1:
                return False
            return True

        def maybe_inline_boundary(
            target_segment_id: str,
            *,
            indent: str,
            collapsed_comment: str,
            allow_inline: bool,
        ) -> bool:
            if not allow_inline:
                return False
            outcome_kind, target_label, _collapsed_chain = resolve_target(target_segment_id)
            resolved_segment_id = (
                segment_id_by_label.get(target_label)
                if outcome_kind == "segment" and target_label is not None
                else None
            )
            if resolved_segment_id is None or not can_inline_boundary_target(
                resolved_segment_id
            ):
                return False
            inlined_segments.add(resolved_segment_id)
            emitted_payload = _emit_structured_collapsed_chain_to_boundary(
                _collapsed_chain,
                final_segment_id=resolved_segment_id,
                indent=indent,
            )
            if not emitted_payload:
                emitted_payload = _emit_collapsed_chain_payload(
                    _collapsed_chain,
                    indent=indent,
                )
            if collapsed_comment and not emitted_payload:
                lines.append(f"{indent}{collapsed_comment}")
            render_boundary_body(
                resolved_segment_id,
                indent=indent,
                allow_inline=False,
            )
            return True

        def render_boundary_body(
            segment_id: str,
            *,
            indent: str,
            allow_inline: bool,
        ) -> None:
            nonlocal emitted_exit_routine
            segment = segment_by_id[segment_id]
            blocks = ", ".join(f"blk[{blk}]" for blk in segment.blocks)
            if comment_mode == ProgramCommentMode.DEBUG_METADATA:
                lines.append(
                    f"{indent}// {segment.kind.name.lower()} segment: {segment.segment_id}"
                    + (f" ({blocks})" if blocks else "")
                )

            semantic_edges = sorted(
                semantic_edges_by_segment.get(segment_id, ()),
                key=lambda edge: (
                    edge.source_anchor.block_serial,
                    edge.source_anchor.kind.value,
                    edge.source_anchor.branch_arm
                    if edge.source_anchor.branch_arm is not None
                    else -1,
                    edge.kind.value,
                ),
            )
            local_edges = sorted(
                local_edges_by_source.get(segment_id, ()),
                key=lambda edge: (
                    edge.branch_arm if edge.branch_arm is not None else -1,
                    edge.kind.value,
                    edge.target_segment_id,
                ),
            )
            _emit_block_payload_lines(
                lines,
                blocks=segment.blocks,
                indent=indent,
                block_payload_by_serial=block_payload_by_serial,
                transition_state_values=_edge_target_states(semantic_edges),
            )
            segment_condition = _extract_terminal_if_condition(segment_id)

            semantic_branch_by_arm: dict[int, StateDagEdge] = {}
            semantic_passthrough: list[StateDagEdge] = []
            for edge in semantic_edges:
                if (
                    edge.source_anchor.kind == RedirectSourceKind.CONDITIONAL_BRANCH
                    and edge.source_anchor.branch_arm is not None
                ):
                    semantic_branch_by_arm[edge.source_anchor.branch_arm] = edge
                else:
                    semantic_passthrough.append(edge)

            local_branch_by_arm: dict[int, StateLocalEdge] = {}
            local_passthrough: list[StateLocalEdge] = []
            for edge in local_edges:
                if edge.branch_arm is not None:
                    local_branch_by_arm[edge.branch_arm] = edge
                else:
                    local_passthrough.append(edge)

            taken_semantic = semantic_branch_by_arm.get(1)
            fallthrough_semantic = semantic_branch_by_arm.get(0)
            taken_local = local_branch_by_arm.get(1)
            fallthrough_local = local_branch_by_arm.get(0)

            if semantic_passthrough:
                local_passthrough = []
            elif (
                taken_semantic is not None
                or fallthrough_semantic is not None
                or taken_local is not None
                or fallthrough_local is not None
            ):
                local_passthrough = [
                    edge
                    for edge in local_passthrough
                    if edge.kind not in (LocalEdgeKind.SHARED_SUFFIX, LocalEdgeKind.TERMINAL)
                ]

            if taken_semantic is not None or fallthrough_semantic is not None:
                if taken_semantic is not None:
                    if taken_semantic.kind == SemanticEdgeKind.EXIT_ROUTINE:
                        emitted_exit_routine = True
                    lines.append(
                        f"{indent}if ({segment_condition or f'/* blk[{taken_semantic.source_anchor.block_serial}].taken */'})"
                    )
                    _emit_semantic_edge_tail_payload(
                        taken_semantic,
                        current_segment=segment,
                        indent=f"{indent}    ",
                    )
                    lines.append(
                        f"{indent}    "
                        f"{_render_segment_edge_action(taken_semantic, node_by_key=node_by_key, label_by_key=label_by_key, labels_by_base=labels_by_base, labels_by_base_and_entry=labels_by_base_and_entry, label_render_mode=label_render_mode)}"
                    )
                elif taken_local is not None:
                    action, comment, _collapsed_chain = _render_local_destination(
                        taken_local.target_segment_id
                    )
                    lines.append(
                        f"{indent}if ({segment_condition or f'/* {segment.segment_id}.taken */'})"
                    )
                    if not maybe_inline_boundary(
                        taken_local.target_segment_id,
                        indent=f"{indent}    ",
                        collapsed_comment=comment,
                        allow_inline=allow_inline,
                    ):
                        emitted_payload = _emit_collapsed_chain_payload(
                            _collapsed_chain,
                            indent=f"{indent}    ",
                        )
                        lines.append(
                            f"{indent}    {action}{'' if emitted_payload else comment}"
                        )

                if fallthrough_semantic is not None:
                    if fallthrough_semantic.kind == SemanticEdgeKind.EXIT_ROUTINE:
                        emitted_exit_routine = True
                    _emit_semantic_edge_tail_payload(
                        fallthrough_semantic,
                        current_segment=segment,
                        indent=indent,
                    )
                    lines.append(
                        f"{indent}"
                        + with_optional_comment(
                            _render_segment_edge_action(
                                fallthrough_semantic,
                                node_by_key=node_by_key,
                                label_by_key=label_by_key,
                                labels_by_base=labels_by_base,
                                labels_by_base_and_entry=labels_by_base_and_entry,
                                label_render_mode=label_render_mode,
                            ),
                            debug_suffix(
                                f"// blk[{fallthrough_semantic.source_anchor.block_serial}].fallthrough"
                            ),
                        )
                    )
                elif fallthrough_local is not None:
                    action, comment, _collapsed_chain = _render_local_destination(
                        fallthrough_local.target_segment_id
                    )
                    inline_comment = comment or debug_suffix(
                        f"// {segment.segment_id}.fallthrough"
                    )
                    if not maybe_inline_boundary(
                        fallthrough_local.target_segment_id,
                        indent=indent,
                        collapsed_comment=inline_comment,
                        allow_inline=allow_inline,
                    ):
                        emitted_payload = _emit_collapsed_chain_payload(
                            _collapsed_chain,
                            indent=indent,
                        )
                        lines.append(
                            f"{indent}{action}{'' if emitted_payload else (comment or debug_suffix(f'  // {segment.segment_id}.fallthrough'))}"
                        )
            elif taken_local is not None and fallthrough_local is not None:
                taken_action, taken_comment, taken_chain = _render_local_destination(
                    taken_local.target_segment_id
                )
                fallthrough_action, fallthrough_comment, fallthrough_chain = _render_local_destination(
                    fallthrough_local.target_segment_id
                )
                lines.append(
                    f"{indent}if ({segment_condition or f'/* {segment.segment_id}.taken */'})"
                )
                if not maybe_inline_boundary(
                    taken_local.target_segment_id,
                    indent=f"{indent}    ",
                    collapsed_comment=taken_comment,
                    allow_inline=allow_inline,
                ):
                    taken_emitted_payload = _emit_collapsed_chain_payload(
                        taken_chain,
                        indent=f"{indent}    ",
                    )
                    lines.append(
                        f"{indent}    {taken_action}{'' if taken_emitted_payload else taken_comment}"
                    )
                if not maybe_inline_boundary(
                    fallthrough_local.target_segment_id,
                    indent=indent,
                    collapsed_comment=fallthrough_comment
                    or debug_suffix(f"// {segment.segment_id}.fallthrough"),
                    allow_inline=allow_inline,
                ):
                    fallthrough_emitted_payload = _emit_collapsed_chain_payload(
                        fallthrough_chain,
                        indent=indent,
                    )
                    lines.append(
                        f"{indent}{fallthrough_action}{'' if fallthrough_emitted_payload else (fallthrough_comment or debug_suffix(f'  // {segment.segment_id}.fallthrough'))}"
                    )

            for edge in semantic_passthrough:
                if edge.kind == SemanticEdgeKind.EXIT_ROUTINE:
                    emitted_exit_routine = True
                _emit_semantic_edge_tail_payload(
                    edge,
                    current_segment=segment,
                    indent=indent,
                )
                lines.append(
                    f"{indent}"
                    + with_optional_comment(
                        _render_segment_edge_action(
                            edge,
                            node_by_key=node_by_key,
                            label_by_key=label_by_key,
                            labels_by_base=labels_by_base,
                            labels_by_base_and_entry=labels_by_base_and_entry,
                            label_render_mode=label_render_mode,
                        ),
                        debug_suffix(
                            f"// {_format_anchor(edge.source_anchor)} {edge.kind.name.lower()}"
                        ),
                    )
                )

            for edge in local_passthrough:
                action, comment, _collapsed_chain = _render_local_destination(
                    edge.target_segment_id
                )
                if maybe_inline_boundary(
                    edge.target_segment_id,
                    indent=indent,
                    collapsed_comment=comment
                    or debug_suffix(
                        f"// {edge.source_segment_id} {edge.kind.name.lower()}"
                    ),
                    allow_inline=allow_inline,
                ):
                    continue
                emitted_payload = _emit_collapsed_chain_payload(
                    _collapsed_chain,
                    indent=indent,
                )
                lines.append(
                    f"{indent}{action}{'' if emitted_payload else (comment or debug_suffix(f'  // {edge.source_segment_id} {edge.kind.name.lower()}'))}"
                )

            if not (
                taken_semantic
                or fallthrough_semantic
                or taken_local
                or fallthrough_local
                or semantic_passthrough
                or local_passthrough
            ):
                emit_debug_comment(indent, "// no local or semantic exits")

        if entry_segment_id is None:
            emit_debug_comment("    ", "// no entry local segment")
            lines.append("")
            continue

        if segment_is_meaningful(entry_segment_id):
            render_boundary_body(
                entry_segment_id,
                indent="    ",
                allow_inline=True,
            )
        else:
            outcome_kind, target_label, collapsed_chain = resolve_target(entry_segment_id)
            entry_comment = _collapse_comment(collapsed_chain)
            target_segment_id = (
                segment_id_by_label.get(target_label)
                if outcome_kind == "segment" and target_label is not None
                else None
            )
            emitted_payload = False
            if (
                target_segment_id is not None
                and can_inline_boundary_target(target_segment_id)
            ):
                inlined_segments.add(target_segment_id)
                emitted_payload = _emit_structured_collapsed_chain_to_boundary(
                    collapsed_chain,
                    final_segment_id=target_segment_id,
                    indent="    ",
                )
                if not emitted_payload:
                    emitted_payload = _emit_collapsed_chain_payload(
                        collapsed_chain,
                        indent="    ",
                    )
                if entry_comment and not emitted_payload:
                    emit_debug_comment("    ", entry_comment)
                render_boundary_body(
                    target_segment_id,
                    indent="    ",
                    allow_inline=False,
                )
            elif outcome_kind in {"segment", "semantic"} and target_label is not None:
                emitted_payload = _emit_collapsed_chain_payload(
                    collapsed_chain,
                    indent="    ",
                )
                lines.append(f"    goto {target_label};{'' if emitted_payload else entry_comment}")
            else:
                emitted_payload = _emit_collapsed_chain_payload(
                    collapsed_chain,
                    indent="    ",
                )
                if not emitted_payload or comment_mode == ProgramCommentMode.DEBUG_METADATA:
                    lines.append(f"    // local dead-end{'' if emitted_payload else entry_comment}")
        lines.append("")

        for segment_id in visible_segments:
            if segment_id in inlined_segments:
                continue
            lines.begin_node(
                segment_labels[segment_id],
                node_kind="local_boundary",
            )
            render_boundary_body(
                segment_id,
                indent="    ",
                allow_inline=False,
            )
            lines.append("")

    if emitted_exit_routine:
        lines.begin_node("EXIT_ROUTINE", node_kind="exit_routine")
        lines.append("    return result;")
        lines.append("")

    return lines


def _render_collapsed_linearized_state_program(
    dag: LinearizedStateDag,
    *,
    order_strategy: RenderOrderStrategy = RenderOrderStrategy.CATALOG,
    label_render_mode: LabelRenderMode = LabelRenderMode.STATE_FAMILY,
    block_payload_by_serial: Mapping[int, tuple[str, ...]] | None = None,
) -> _RenderedProgramBuilder:
    """Render the state DAG as a label-preserving linearized program.

    This intentionally preserves explicit state-family labels and semantic
    redirects instead of asking Hex-Rays to rediscover a structured CFG from
    later graph rewrites.
    """
    lines = _RenderedProgramBuilder()
    node_by_key = {node.key: node for node in dag.nodes}
    label_by_key, labels_by_base, labels_by_base_and_entry = _build_program_labels(
        dag,
        label_render_mode=label_render_mode,
    )
    edges_by_source: dict[StateDagNodeKey, list[StateDagEdge]] = defaultdict(list)
    for edge in dag.edges:
        edges_by_source[edge.source_key].append(edge)

    def _edge_target_states(edges: tuple[StateDagEdge, ...] | list[StateDagEdge]) -> set[int]:
        return {
            edge.target_state & 0xFFFFFFFF
            for edge in edges
            if edge.target_state is not None
        }

    ordered_keys = _unique_render_keys(_render_order(dag, strategy=order_strategy))
    lines.append(
        "=== LINEARIZED STATE PROGRAM ==="
        if dag.initial_state is None
        else f"=== LINEARIZED STATE PROGRAM (starting from 0x{dag.initial_state:08X}) ==="
    )
    lines.append("")

    emitted_exit_routine = False
    for node_key in ordered_keys:
        node = node_by_key[node_key]
        node_label = label_by_key[node_key]
        lines.begin_node(
            node_label.rendered,
            node_kind="state_family",
            state_label=node.state_label,
            handler_serial=node.handler_serial,
            entry_anchor=node.entry_anchor,
            label_num=node_label.label_num,
        )
        _emit_program_state_family_comment(
            lines,
            node,
            label_render_mode=label_render_mode,
            comment_mode=ProgramCommentMode.DEBUG_METADATA,
        )
        lines.append(
            f"    // entry blk[{node.entry_anchor}] [{node.kind.name.lower()}]"
        )
        if node.owned_blocks:
            owned = ", ".join(f"blk[{blk}]" for blk in node.owned_blocks)
            lines.append(f"    // blocks: {owned}")
        if node.shared_suffix_blocks:
            shared = ", ".join(f"blk[{blk}]" for blk in node.shared_suffix_blocks)
            lines.append(f"    // shared-suffix: {shared}")
        if node.local_edges:
            local_cfg = ", ".join(_format_local_edge(edge) for edge in node.local_edges)
            lines.append(f"    // local-cfg: {local_cfg}")
        outgoing = sorted(
            edges_by_source.get(node_key, ()),
            key=lambda edge: (
                edge.source_anchor.block_serial,
                edge.source_anchor.kind.value,
                (
                    edge.source_anchor.branch_arm
                    if edge.source_anchor.branch_arm is not None
                    else -1
                ),
                edge.kind.value,
                edge.target_state if edge.target_state is not None else 0xFFFFFFFF,
            ),
        )
        _emit_block_payload_lines(
            lines,
            blocks=node.owned_blocks,
            indent="    ",
            block_payload_by_serial=block_payload_by_serial,
            transition_state_values=_edge_target_states(outgoing),
        )
        if not outgoing:
            lines.append("    // no outgoing semantic edges")
            lines.append("")
            continue

        branch_groups: dict[int, dict[int, StateDagEdge]] = defaultdict(dict)
        passthrough_edges: list[StateDagEdge] = []
        for edge in outgoing:
            anchor = edge.source_anchor
            if (
                anchor.kind == RedirectSourceKind.CONDITIONAL_BRANCH
                and anchor.branch_arm is not None
            ):
                branch_groups[anchor.block_serial][anchor.branch_arm] = edge
            else:
                passthrough_edges.append(edge)

        for edge in passthrough_edges:
            if edge.kind == SemanticEdgeKind.EXIT_ROUTINE:
                emitted_exit_routine = True
            lines.append(
                "    "
                f"{_program_action(edge, node_by_key, label_by_key, labels_by_base, labels_by_base_and_entry, label_render_mode)}  "
                f"// {_format_anchor(edge.source_anchor)} {edge.kind.name.lower()}"
            )

        for block_serial in sorted(branch_groups):
            arms = branch_groups[block_serial]
            taken_edge = arms.get(1)
            fallthrough_edge = arms.get(0)
            if taken_edge is not None and fallthrough_edge is not None:
                if taken_edge.kind == SemanticEdgeKind.EXIT_ROUTINE:
                    emitted_exit_routine = True
                if fallthrough_edge.kind == SemanticEdgeKind.EXIT_ROUTINE:
                    emitted_exit_routine = True
                lines.append(f"    if (/* blk[{block_serial}].taken */)")
                lines.append(
                    "        "
                    f"{_program_action(taken_edge, node_by_key, label_by_key, labels_by_base, labels_by_base_and_entry, label_render_mode)}"
                )
                lines.append(
                    "    "
                    f"{_program_action(fallthrough_edge, node_by_key, label_by_key, labels_by_base, labels_by_base_and_entry, label_render_mode)}  "
                    f"// blk[{block_serial}].fallthrough"
                )
                continue

            for arm, edge in sorted(arms.items()):
                if edge.kind == SemanticEdgeKind.EXIT_ROUTINE:
                    emitted_exit_routine = True
                arm_name = "fallthrough" if arm == 0 else "taken"
                lines.append(f"    if (/* blk[{block_serial}].{arm_name} */)")
                lines.append(
                    "        "
                    f"{_program_action(edge, node_by_key, label_by_key, labels_by_base, labels_by_base_and_entry, label_render_mode)}"
                )

        lines.append("")

    if emitted_exit_routine:
        lines.begin_node("EXIT_ROUTINE", node_kind="exit_routine")
        lines.append("    return result;")
        lines.append("")

    return lines


def linearized_program_variant_name(
    *,
    order_strategy: RenderOrderStrategy,
    program_strategy: ProgramRenderStrategy,
    label_render_mode: LabelRenderMode,
    boundary_inline_mode: BoundaryInlineMode,
    comment_mode: ProgramCommentMode,
) -> str:
    """Return a stable variant name for a rendered program configuration."""
    if (
        order_strategy == RenderOrderStrategy.SEMANTIC
        and program_strategy == ProgramRenderStrategy.LOCAL_BOUNDARY_SELECTIVE
        and label_render_mode == LabelRenderMode.STATE_FAMILY
        and boundary_inline_mode == BoundaryInlineMode.INLINE_SINGLE_LEVEL
        and comment_mode == ProgramCommentMode.MINIMAL
    ):
        return "semantic_reference_like"
    if (
        order_strategy == RenderOrderStrategy.SEMANTIC
        and program_strategy == ProgramRenderStrategy.LOCAL_BOUNDARY_SELECTIVE
        and label_render_mode == LabelRenderMode.STATE_FAMILY
        and boundary_inline_mode == BoundaryInlineMode.INLINE_SINGLE_LEVEL
        and comment_mode == ProgramCommentMode.DEBUG_METADATA
    ):
        return "semantic_local_boundaries"
    if (
        order_strategy == RenderOrderStrategy.SEMANTIC
        and program_strategy == ProgramRenderStrategy.LOCAL_BOUNDARY_SELECTIVE
        and label_render_mode == LabelRenderMode.IDA_BLOCK_SERIAL
        and boundary_inline_mode == BoundaryInlineMode.INLINE_SINGLE_LEVEL
        and comment_mode == ProgramCommentMode.DEBUG_METADATA
    ):
        return "semantic_local_boundaries_ida_labels"
    if (
        order_strategy == RenderOrderStrategy.SEMANTIC
        and program_strategy == ProgramRenderStrategy.LOCAL_SEGMENT_COLLAPSING
        and label_render_mode == LabelRenderMode.STATE_FAMILY
        and boundary_inline_mode == BoundaryInlineMode.LABELS_ONLY
        and comment_mode == ProgramCommentMode.DEBUG_METADATA
    ):
        return "semantic"
    if (
        order_strategy == RenderOrderStrategy.CATALOG
        and program_strategy == ProgramRenderStrategy.LOCAL_SEGMENT_COLLAPSING
        and label_render_mode == LabelRenderMode.STATE_FAMILY
        and boundary_inline_mode == BoundaryInlineMode.LABELS_ONLY
        and comment_mode == ProgramCommentMode.DEBUG_METADATA
    ):
        return "catalog"
    return "_".join(
        (
            order_strategy.value,
            program_strategy.value,
            label_render_mode.name.lower(),
            boundary_inline_mode.name.lower(),
            comment_mode.name.lower(),
        )
    )


def _rendered_program_line_kind(text: str) -> str:
    stripped = text.strip()
    if not stripped:
        return "blank"
    if _PROGRAM_LABEL_RE.match(text):
        return "label"
    if stripped.startswith("//"):
        return "comment"
    if stripped.startswith("goto "):
        return "goto"
    if stripped.startswith("if "):
        return "if"
    if stripped.startswith("return "):
        return "return"
    return "statement"


def build_rendered_program_snapshot(
    dag: LinearizedStateDag,
    rendered_program: str,
    *,
    order_strategy: RenderOrderStrategy,
    program_strategy: ProgramRenderStrategy,
    label_render_mode: LabelRenderMode,
    boundary_inline_mode: BoundaryInlineMode,
    comment_mode: ProgramCommentMode,
) -> RenderedProgramSnapshot:
    """Convert rendered text into a queryable program snapshot."""
    node_by_key = {node.key: node for node in dag.nodes}
    label_by_key, _labels_by_base, _labels_by_base_and_entry = _build_program_labels(
        dag,
        label_render_mode=label_render_mode,
    )
    top_level_meta = {
        label.rendered: (node_by_key[key], label)
        for key, label in label_by_key.items()
    }

    raw_lines = rendered_program.splitlines()
    node_spans: list[tuple[str, int, int]] = []
    current_label: str | None = None
    current_start: int | None = None
    for line_no, text in enumerate(raw_lines, 1):
        match = _PROGRAM_LABEL_RE.match(text)
        if match is None:
            continue
        label_text = match.group("label")
        if current_label is not None and current_start is not None:
            node_spans.append((current_label, current_start, line_no - 1))
        current_label = label_text
        current_start = line_no
    if current_label is not None and current_start is not None:
        node_spans.append((current_label, current_start, len(raw_lines)))

    nodes: list[RenderedProgramNode] = []
    label_to_index: dict[str, int] = {}
    for node_index, (label_text, line_start, line_end) in enumerate(node_spans):
        label_to_index[label_text] = node_index
        if label_text == "EXIT_ROUTINE":
            nodes.append(
                RenderedProgramNode(
                    node_index=node_index,
                    label_text=label_text,
                    node_kind="exit_routine",
                    line_start=line_start,
                    line_end=line_end,
                )
            )
            continue

        meta = top_level_meta.get(label_text)
        if meta is None:
            nodes.append(
                RenderedProgramNode(
                    node_index=node_index,
                    label_text=label_text,
                    node_kind="local_boundary",
                    line_start=line_start,
                    line_end=line_end,
                )
            )
            continue

        dag_node, program_label = meta
        nodes.append(
            RenderedProgramNode(
                node_index=node_index,
                label_text=label_text,
                node_kind="state_family",
                line_start=line_start,
                line_end=line_end,
                state_label=dag_node.state_label,
                handler_serial=dag_node.handler_serial,
                entry_anchor=dag_node.entry_anchor,
                label_num=program_label.label_num,
            )
        )

    lines: list[RenderedProgramLine] = []
    current_node_index: int | None = None
    for line_no, text in enumerate(raw_lines, 1):
        match = _PROGRAM_LABEL_RE.match(text)
        if match is not None:
            current_node_index = label_to_index.get(match.group("label"))
        goto_match = _PROGRAM_GOTO_RE.search(text)
        indent_level = max(0, (len(text) - len(text.lstrip(" "))) // 4)
        lines.append(
            RenderedProgramLine(
                line_no=line_no,
                text=text,
                node_index=current_node_index,
                indent_level=indent_level,
                line_kind=_rendered_program_line_kind(text),
                target_label=goto_match.group("label") if goto_match else None,
            )
        )

    return RenderedProgramSnapshot(
        variant_name=linearized_program_variant_name(
            order_strategy=order_strategy,
            program_strategy=program_strategy,
            label_render_mode=label_render_mode,
            boundary_inline_mode=boundary_inline_mode,
            comment_mode=comment_mode,
        ),
        order_strategy=order_strategy.value,
        program_strategy=program_strategy.value,
        label_render_mode=label_render_mode.name.lower(),
        boundary_inline_mode=boundary_inline_mode.name.lower(),
        comment_mode=comment_mode.name.lower(),
        nodes=tuple(nodes),
        lines=tuple(lines),
    )


def build_linearized_state_program(
    dag: LinearizedStateDag,
    *,
    order_strategy: RenderOrderStrategy = RenderOrderStrategy.CATALOG,
    program_strategy: ProgramRenderStrategy = ProgramRenderStrategy.LOCAL_SEGMENT_COLLAPSING,
    label_render_mode: LabelRenderMode = LabelRenderMode.STATE_FAMILY,
    boundary_inline_mode: BoundaryInlineMode = BoundaryInlineMode.LABELS_ONLY,
    comment_mode: ProgramCommentMode = ProgramCommentMode.DEBUG_METADATA,
    block_payload_by_serial: Mapping[int, tuple[str, ...]] | None = None,
) -> RenderedProgramSnapshot:
    """Build the structured linearized-program IR for one state DAG.

    ``LOCAL_SEGMENT_COLLAPSING`` preserves family labels and semantic exits while
    collapsing the intra-family local segment graph into comments.

    ``LOCAL_SEGMENT_EXPLICIT`` keeps the same family ordering but emits local
    segment sublabels and intra-family gotos so corridor structure remains
    visible for debugging.

    ``LOCAL_BOUNDARY_SELECTIVE`` keeps semantic family order but only emits
    local sublabels for meaningful local boundary points. Straight-line corridor
    chains are collapsed back into direct gotos.
    """
    builder: _RenderedProgramBuilder
    if program_strategy == ProgramRenderStrategy.LOCAL_BOUNDARY_SELECTIVE:
        builder = _render_selective_local_boundary_program(
            dag,
            order_strategy=order_strategy,
            boundary_inline_mode=boundary_inline_mode,
            label_render_mode=label_render_mode,
            comment_mode=comment_mode,
            block_payload_by_serial=block_payload_by_serial,
        )
    elif program_strategy == ProgramRenderStrategy.LOCAL_SEGMENT_EXPLICIT:
        builder = _render_explicit_local_segment_program(
            dag,
            order_strategy=order_strategy,
            label_render_mode=label_render_mode,
            block_payload_by_serial=block_payload_by_serial,
        )
    else:
        builder = _render_collapsed_linearized_state_program(
            dag,
            order_strategy=order_strategy,
            label_render_mode=label_render_mode,
            block_payload_by_serial=block_payload_by_serial,
        )
    return builder.build_snapshot(
        variant_name=linearized_program_variant_name(
            order_strategy=order_strategy,
            program_strategy=program_strategy,
            label_render_mode=label_render_mode,
            boundary_inline_mode=boundary_inline_mode,
            comment_mode=comment_mode,
        ),
        order_strategy=order_strategy.value,
        program_strategy=program_strategy.value,
        label_render_mode=label_render_mode.name.lower(),
        boundary_inline_mode=boundary_inline_mode.name.lower(),
        comment_mode=comment_mode.name.lower(),
    )


def render_linearized_state_program(
    program: RenderedProgramSnapshot,
) -> str:
    """Render a built linearized-program IR to text."""
    return "\n".join(line.text for line in program.lines)


__all__ = [
    "BoundaryInlineMode",
    "LinearizedStateDag",
    "LabelRenderMode",
    "LocalEdgeKind",
    "LocalSegmentKind",
    "ProgramCommentMode",
    "ProgramLabel",
    "RenderedProgramLine",
    "RenderedProgramNode",
    "RenderedProgramSnapshot",
    "ProgramRenderStrategy",
    "RenderOrderStrategy",
    "RedirectSourceKind",
    "SemanticEdgeKind",
    "StateDagEdge",
    "StateDagNode",
    "StateDagNodeKey",
    "StateLocalEdge",
    "StateLocalSegment",
    "StateNodeKind",
    "StateRedirectAnchor",
    "build_linearized_state_program",
    "build_rendered_program_snapshot",
    "build_live_linearized_state_dag_from_graph",
    "build_linearized_state_dag_from_graph",
    "linearized_program_variant_name",
    "render_linearized_state_program",
    "render_linearized_state_dag",
    "render_linearized_state_dag_dot",
]
