from __future__ import annotations

from dataclasses import dataclass, replace
import re

from d810.core import logging
from d810.core.typing import Callable

from d810.analyses.control_flow.dag_redirect_discovery import select_plannable_dag_edges
from d810.analyses.control_flow.linearized_state_dag import (
    BoundaryInlineMode,
    LabelRenderMode,
    SemanticEdgeKind,
    ProgramCommentMode,
    ProgramRenderStrategy,
    RenderOrderStrategy,
    RenderedProgramSnapshot,
    build_linearized_state_program,
    build_live_linearized_state_dag_from_graph,
)
from d810.analyses.control_flow.transition_report import (
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
    semantic_reference_program: RenderedProgramSnapshot | None
    structured_regions: tuple["ResolvedDagStructuredRegion", ...]
    plannable_edges: tuple[ResolvedDagPlannableEdge, ...]
    report_exit_handlers: frozenset[int]
    report_exit_owned_blocks: frozenset[int]
    terminal_source_keys: frozenset[object]
    terminal_source_handlers: frozenset[int]
    terminal_source_owned_blocks: frozenset[int]
    terminal_protected_blocks: frozenset[int]
    terminal_skipped: int
    unknown_skipped: int


@dataclass(frozen=True, slots=True)
class ResolvedDagStructuredRegion:
    """Trusted semantic region carried forward for structured lowering experiments."""

    region_name: str
    entry_state: int
    state_values: tuple[int, ...]
    state_labels: tuple[str, ...]
    internal_state_edges: tuple[tuple[int, int], ...]
    exit_state_values: tuple[int, ...] = ()


_SUB7FFD_INITIAL_REGION_NAME = "sub7ffd_initial_semantic_region"
_SUB7FFD_INITIAL_REGION_STATES = (
    0x5D0AEBD3,
    0x606DC166,
    0x139F2922,
)
_SUB7FFD_INITIAL_REGION_LABELS = tuple(
    f"STATE_{state:08X}" for state in _SUB7FFD_INITIAL_REGION_STATES
)
_SUB7FFD_INITIAL_REGION_EXITS = (
    0x16F7FF74,
    0x2315233C,
    0x63F502FA,
    0x1031EAF4,
)
_SUB7FFD_DOWNSTREAM_CHAIN_REGION_NAME = "sub7ffd_downstream_chain_region"
_SUB7FFD_DOWNSTREAM_CHAIN_REGION_STATES = (
    0x32FCD904,
    0x2E6C61F3,
    0x652D7A98,
)
_SUB7FFD_DOWNSTREAM_CHAIN_REGION_LABELS = tuple(
    f"STATE_{state:08X}" for state in _SUB7FFD_DOWNSTREAM_CHAIN_REGION_STATES
)
_SUB7FFD_RETRY_CHAIN_REGION_NAME = "sub7ffd_retry_chain_region"
_SUB7FFD_RETRY_CHAIN_REGION_STATES = (
    0x37B42A40,
    0x63D54755,
    0x57BE6FD0,
    0x03E42B03,
    0x610BB4D9,
)
_SUB7FFD_RETRY_CHAIN_REGION_LABELS = tuple(
    f"STATE_{state:08X}" for state in _SUB7FFD_RETRY_CHAIN_REGION_STATES
)
_SUB7FFD_RETRY_CHAIN_REGION_EXITS = (
    0x00C0C59F,
    0x3873BC54,
    0x1CCE40B3,
)
_SUB7FFD_6D207773_CORRIDOR_REGION_NAME = "sub7ffd_6d207773_corridor_region"
_SUB7FFD_6D207773_CORRIDOR_REGION_STATES = (
    0x6D207773,
    0x0B2FECE0,
    0x1031EAF4,
    0x2A5E29F6,
)
_SUB7FFD_6D207773_CORRIDOR_REGION_LABELS = tuple(
    f"STATE_{state:08X}" for state in _SUB7FFD_6D207773_CORRIDOR_REGION_STATES
)
_SUB7FFD_6D207773_CORRIDOR_REGION_EXITS = (
    0x16F7FF74,
    0x2315233C,
    0x63F502FA,
)
_SUB7FFD_7C2C0220_CORRIDOR_REGION_NAME = "sub7ffd_7c2c0220_corridor_region"
_SUB7FFD_7C2C0220_CORRIDOR_REGION_STATES = (
    0x2315233C,
    0x7D9C16EC,
    0x72AFE1BC,
    0x737189D5,
    0x71E22BF3,
    0x11CD1DA3,
)
_SUB7FFD_7C2C0220_CORRIDOR_REGION_LABELS = tuple(
    f"STATE_{state:08X}" for state in _SUB7FFD_7C2C0220_CORRIDOR_REGION_STATES
)
_SUB7FFD_7C2C0220_CORRIDOR_REGION_EXITS = (
    0x4E69F350,
)
_SUB7FFD_10743C4C_BRANCH_REGION_NAME = "sub7ffd_10743c4c_branch_region"
_SUB7FFD_10743C4C_BRANCH_REGION_STATES = (
    0x4E69F350,
    0x2A5ADB57,
    0x1AB9946F,
    0x7C2C0220,
    0x385BBE2D,
    0x10743C4C,
    0x6107F8EC,
)
_SUB7FFD_10743C4C_BRANCH_REGION_LABELS = tuple(
    f"STATE_{state:08X}" for state in _SUB7FFD_10743C4C_BRANCH_REGION_STATES
)
_SUB7FFD_10743C4C_BRANCH_REGION_EXITS = (
    0x4C77464F,
    0x296F2452,
)
_STATE_LABEL_HEX_RE = re.compile(r"STATE_([0-9A-Fa-f]{8})")
_STATE_SUFFIX_HEX_RE = re.compile(r"_s([0-9A-Fa-f]{8})(?:_|$)")
_STATE_LABEL_PREFIX_RE = re.compile(r"^STATE_([0-9A-Fa-f]{8})(?:(_fallback))?(?:__.+)?$")
_RAW_STATE_LABEL_PREFIX_RE = re.compile(
    r"^0x([0-9A-Fa-f]{8})(?:(_fallback))?(?:__.+)?$"
)
logger = logging.getLogger(__name__)


def _semantic_program_state_markers(
    semantic_reference_program: RenderedProgramSnapshot,
) -> frozenset[int]:
    state_markers: set[int] = set()
    for node in semantic_reference_program.nodes:
        label_text = str(node.label_text)
        for match in _STATE_LABEL_HEX_RE.finditer(label_text):
            state_markers.add(int(match.group(1), 16) & 0xFFFFFFFF)
        for match in _STATE_SUFFIX_HEX_RE.finditer(label_text):
            state_markers.add(int(match.group(1), 16) & 0xFFFFFFFF)
    for line in getattr(semantic_reference_program, "lines", ()) or ():
        target_label = getattr(line, "target_label", None)
        if target_label is None:
            continue
        target_label_text = str(target_label)
        for match in _STATE_LABEL_HEX_RE.finditer(target_label_text):
            state_markers.add(int(match.group(1), 16) & 0xFFFFFFFF)
        for match in _STATE_SUFFIX_HEX_RE.finditer(target_label_text):
            state_markers.add(int(match.group(1), 16) & 0xFFFFFFFF)
    return frozenset(state_markers)


def _semantic_program_successors_by_state(
    semantic_reference_program: RenderedProgramSnapshot,
) -> dict[int, tuple[int, ...]]:
    successors_by_state: dict[int, tuple[int, ...]] = {}
    lines = tuple(getattr(semantic_reference_program, "lines", ()) or ())
    for node in getattr(semantic_reference_program, "nodes", ()) or ():
        label_text = str(getattr(node, "label_text", "") or "")
        state_match = _STATE_LABEL_HEX_RE.search(label_text)
        if state_match is None:
            continue
        source_state = int(state_match.group(1), 16) & 0xFFFFFFFF
        line_start = int(getattr(node, "line_start", 0) or 0)
        line_end = int(getattr(node, "line_end", 0) or 0)
        if line_end < line_start:
            line_end = line_start
        targets: list[int] = []
        for line in lines:
            line_no = int(getattr(line, "line_no", 0) or 0)
            if line_no < line_start or line_no > line_end:
                continue
            target_label = getattr(line, "target_label", None)
            if target_label is None:
                continue
            target_text = str(target_label)
            target_match = _STATE_LABEL_HEX_RE.search(target_text)
            if target_match is None:
                target_match = _STATE_SUFFIX_HEX_RE.search(target_text)
            if target_match is None:
                continue
            targets.append(int(target_match.group(1), 16) & 0xFFFFFFFF)
        if targets:
            successors_by_state[source_state] = tuple(dict.fromkeys(targets))
    return successors_by_state


def _resolve_semantic_alias_state_for_selected_entry(
    dag: object,
    *,
    raw_state: int,
    selected_entry_anchor: int,
) -> int | None:
    normalized_raw_state = int(raw_state) & 0xFFFFFFFF

    def _node_owned_blocks(node: object) -> set[int]:
        blocks: set[int] = set()
        entry_anchor = getattr(node, "entry_anchor", None)
        if entry_anchor is not None:
            blocks.add(int(entry_anchor))
        blocks.update(int(block) for block in (getattr(node, "exclusive_blocks", ()) or ()))
        blocks.update(int(block) for block in (getattr(node, "owned_blocks", ()) or ()))
        blocks.update(
            int(block)
            for segment in (getattr(node, "local_segments", ()) or ())
            for block in (getattr(segment, "blocks", ()) or ())
        )
        return blocks

    best_match: tuple[int, int, int, int] | None = None
    best_state: int | None = None
    for node in getattr(dag, "nodes", ()) or ():
        key = getattr(node, "key", None)
        state_const = getattr(key, "state_const", None)
        if state_const is None:
            continue
        candidate_state = int(state_const) & 0xFFFFFFFF
        if candidate_state == normalized_raw_state:
            continue
        owned_blocks = _node_owned_blocks(node)
        if int(selected_entry_anchor) not in owned_blocks:
            continue
        state_label = str(getattr(node, "state_label", "") or "")
        outgoing_count = sum(
            1
            for edge in getattr(dag, "edges", ()) or ()
            if getattr(getattr(edge, "source_key", None), "state_const", None) is not None
            and (int(edge.source_key.state_const) & 0xFFFFFFFF) == candidate_state
            and getattr(edge, "target_state", None) is not None
        )
        score = (
            outgoing_count,
            1 if state_label.endswith("_fallback") else 0,
            1 if int(getattr(node, "entry_anchor", -1)) == int(selected_entry_anchor) else 0,
            -candidate_state,
        )
        if best_match is None or score > best_match:
            best_match = score
            best_state = candidate_state
    return best_state


def _rewrite_state_label_text(label_text: str, alias_map: dict[int, int]) -> str:
    rewritten = label_text
    for raw_state, semantic_state in alias_map.items():
        raw_hex = f"{int(raw_state) & 0xFFFFFFFF:08X}"
        semantic_hex = f"{int(semantic_state) & 0xFFFFFFFF:08X}"
        rewritten = rewritten.replace(f"STATE_{raw_hex}", f"STATE_{semantic_hex}")
        rewritten = rewritten.replace(f"0x{raw_hex}", f"STATE_{semantic_hex}")
        rewritten = rewritten.replace(f"0x{raw_hex.lower()}", f"STATE_{semantic_hex}")
    return rewritten


def _normalize_semantic_reference_program_aliases(
    dag: object,
    semantic_reference_program: RenderedProgramSnapshot,
) -> RenderedProgramSnapshot:
    alias_map: dict[int, int] = {}
    for state_value, anchor in getattr(dag, "supplemental_selected_entries", ()) or ():
        normalized_state = int(state_value) & 0xFFFFFFFF
        selected_anchor = int(anchor)
        semantic_state = _resolve_semantic_alias_state_for_selected_entry(
            dag,
            raw_state=normalized_state,
            selected_entry_anchor=selected_anchor,
        )
        if semantic_state is None or semantic_state == normalized_state:
            continue
        alias_map[normalized_state] = int(semantic_state) & 0xFFFFFFFF
    if not alias_map:
        return semantic_reference_program

    rewritten_nodes = tuple(
        replace(
            node,
            label_text=_rewrite_state_label_text(str(node.label_text), alias_map),
            state_label=(
                None
                if getattr(node, "state_label", None) is None
                else _rewrite_state_label_text(str(node.state_label), alias_map)
            ),
        )
        for node in semantic_reference_program.nodes
    )
    rewritten_lines = tuple(
        replace(
            line,
            text=_rewrite_state_label_text(str(line.text), alias_map),
            target_label=(
                None
                if getattr(line, "target_label", None) is None
                else _rewrite_state_label_text(str(line.target_label), alias_map)
            ),
        )
        for line in semantic_reference_program.lines
    )
    return replace(
        semantic_reference_program,
        nodes=rewritten_nodes,
        lines=rewritten_lines,
    )


def _normalize_region_exit_state_via_owned_entry(
    dag: object,
    state_value: int,
    *,
    semantic_reference_program: RenderedProgramSnapshot | None = None,
) -> int:
    normalized_state = int(state_value) & 0xFFFFFFFF
    raw_entry_candidates: set[int] = set()
    if semantic_reference_program is not None:
        semantic_state_markers = _semantic_program_state_markers(
            semantic_reference_program
        )
        if normalized_state not in semantic_state_markers:
            for raw_state, anchor in (
                getattr(dag, "supplemental_selected_entries", ()) or ()
            ):
                if (int(raw_state) & 0xFFFFFFFF) != normalized_state:
                    continue
                semantic_state = _resolve_semantic_alias_state_for_selected_entry(
                    dag,
                    raw_state=normalized_state,
                    selected_entry_anchor=int(anchor),
                )
                if (
                    semantic_state is not None
                    and semantic_state != normalized_state
                    and (int(semantic_state) & 0xFFFFFFFF) in semantic_state_markers
                ):
                    return int(semantic_state) & 0xFFFFFFFF
    source_outgoing_count = sum(
        1
        for edge in getattr(dag, "edges", ()) or ()
        if getattr(getattr(edge, "source_key", None), "state_const", None) is not None
        and (int(edge.source_key.state_const) & 0xFFFFFFFF) == normalized_state
        and getattr(edge, "target_state", None) is not None
    )
    if source_outgoing_count:
        return normalized_state

    def _node_owned_blocks(node: object) -> set[int]:
        blocks: set[int] = set()
        entry_anchor = getattr(node, "entry_anchor", None)
        if entry_anchor is not None:
            blocks.add(int(entry_anchor))
        blocks.update(
            int(block)
            for block in (getattr(node, "exclusive_blocks", ()) or ())
        )
        blocks.update(
            int(block)
            for block in (getattr(node, "owned_blocks", ()) or ())
        )
        blocks.update(
            int(block)
            for segment in (getattr(node, "local_segments", ()) or ())
            for block in (getattr(segment, "blocks", ()) or ())
        )
        return blocks

    for node in getattr(dag, "nodes", ()) or ():
        key = getattr(node, "key", None)
        state_const = getattr(key, "state_const", None)
        if state_const is None or (int(state_const) & 0xFFFFFFFF) != normalized_state:
            continue
        raw_entry_candidates.update(_node_owned_blocks(node))

    if not raw_entry_candidates:
        return normalized_state

    best_match: tuple[int, int, int, int] | None = None
    best_state: int | None = None
    for node in getattr(dag, "nodes", ()) or ():
        key = getattr(node, "key", None)
        state_const = getattr(key, "state_const", None)
        if state_const is None:
            continue
        candidate_state = int(state_const) & 0xFFFFFFFF
        if candidate_state == normalized_state:
            continue
        state_label = str(getattr(node, "state_label", "") or "")
        if not state_label:
            continue
        if (
            _STATE_LABEL_PREFIX_RE.match(state_label) is None
            and _RAW_STATE_LABEL_PREFIX_RE.match(state_label) is None
        ):
            continue
        owned_blocks = _node_owned_blocks(node)
        shared_blocks = raw_entry_candidates & owned_blocks
        if not shared_blocks:
            continue
        candidate_outgoing_count = sum(
            1
            for edge in getattr(dag, "edges", ()) or ()
            if getattr(getattr(edge, "source_key", None), "state_const", None) is not None
            and (int(edge.source_key.state_const) & 0xFFFFFFFF) == candidate_state
            and getattr(edge, "target_state", None) is not None
        )
        if candidate_outgoing_count <= 0:
            continue
        fallback_suffix = 1 if state_label.endswith("_fallback") else 0
        entry_anchor = getattr(node, "entry_anchor", None)
        exact_entry_shared = (
            1
            if entry_anchor is not None and int(entry_anchor) in raw_entry_candidates
            else 0
        )
        exclusive_shared = 1 if any(
            int(block) in raw_entry_candidates
            for block in (getattr(node, "exclusive_blocks", ()) or ())
        ) else 0
        score = (
            candidate_outgoing_count,
            fallback_suffix,
            exact_entry_shared,
            exclusive_shared,
            -candidate_state,
        )
        if best_match is None or score > best_match:
            best_match = score
            best_state = candidate_state

    if best_state is None:
        return normalized_state
    return int(best_state) & 0xFFFFFFFF


def _normalize_region_exit_state_values(
    dag: object,
    exit_state_values: tuple[int, ...],
    *,
    semantic_reference_program: RenderedProgramSnapshot | None = None,
) -> tuple[int, ...]:
    normalized: list[int] = []
    seen: set[int] = set()
    for state in exit_state_values:
        resolved = _normalize_region_exit_state_via_owned_entry(
            dag,
            int(state),
            semantic_reference_program=semantic_reference_program,
        )
        if resolved in seen:
            continue
        seen.add(resolved)
        normalized.append(resolved)
    return tuple(normalized)


def _canonicalize_alias_exit_regions(
    dag: object,
    regions: list[ResolvedDagStructuredRegion],
    *,
    semantic_reference_program: RenderedProgramSnapshot | None = None,
) -> tuple[ResolvedDagStructuredRegion, ...]:
    canonical_regions: list[ResolvedDagStructuredRegion] = []
    seen_single_exit_entries: set[int] = set()
    for region in regions:
        region_name = str(getattr(region, "region_name", ""))
        entry_state = int(getattr(region, "entry_state")) & 0xFFFFFFFF
        state_values = tuple(int(state) & 0xFFFFFFFF for state in region.state_values)
        state_labels = tuple(str(label) for label in region.state_labels)
        exit_state_values = _normalize_region_exit_state_values(
            dag,
            tuple(int(state) & 0xFFFFFFFF for state in region.exit_state_values),
            semantic_reference_program=semantic_reference_program,
        )
        if region_name.startswith("sub7ffd_exit_state_region_") and len(state_values) == 1:
            normalized_entry_state = _normalize_region_exit_state_via_owned_entry(
                dag,
                entry_state,
                semantic_reference_program=semantic_reference_program,
            )
            if normalized_entry_state != entry_state:
                entry_state = normalized_entry_state
                state_values = (normalized_entry_state,)
                state_labels = (f"STATE_{normalized_entry_state:08X}",)
                region_name = f"sub7ffd_exit_state_region_{normalized_entry_state:08x}"
            if entry_state in seen_single_exit_entries:
                continue
            seen_single_exit_entries.add(entry_state)
        canonical_regions.append(
            ResolvedDagStructuredRegion(
                region_name=region_name,
                entry_state=entry_state,
                state_values=state_values,
                state_labels=state_labels,
                internal_state_edges=tuple(region.internal_state_edges),
                exit_state_values=exit_state_values,
            )
        )
    return tuple(canonical_regions)


def _discover_sub7ffd_region(
    dag: object,
    *,
    semantic_reference_program: RenderedProgramSnapshot,
    region_name: str,
    region_states: tuple[int, ...],
    region_labels: tuple[str, ...],
    exit_state_values: tuple[int, ...] = (),
) -> ResolvedDagStructuredRegion | None:
    labels = {str(node.label_text) for node in semantic_reference_program.nodes}
    state_markers = _semantic_program_state_markers(semantic_reference_program)
    required_state_markers = {int(state) & 0xFFFFFFFF for state in region_states}
    region_state_set = {int(state) for state in region_states}
    dag_state_values = {
        int(value) & 0xFFFFFFFF
        for value in (
            *(int(getattr(node.key, "state_const", 0)) for node in getattr(dag, "nodes", ()) if getattr(getattr(node, "key", None), "state_const", None) is not None),
            *(int(getattr(edge.source_key, "state_const", 0)) for edge in getattr(dag, "edges", ()) if getattr(getattr(edge, "source_key", None), "state_const", None) is not None),
            *(int(getattr(edge, "target_state", 0)) for edge in getattr(dag, "edges", ()) if getattr(edge, "target_state", None) is not None),
        )
    }
    internal_state_edges = tuple(
        sorted(
            {
                (
                    int(edge.source_key.state_const) & 0xFFFFFFFF,
                    int(edge.target_state) & 0xFFFFFFFF,
                )
                for edge in getattr(dag, "edges", ())
                if edge.kind
                in (
                    SemanticEdgeKind.TRANSITION,
                    SemanticEdgeKind.CONDITIONAL_TRANSITION,
                )
                and edge.source_key.state_const is not None
                and edge.target_state is not None
                and (int(edge.source_key.state_const) & 0xFFFFFFFF) in region_state_set
                and (int(edge.target_state) & 0xFFFFFFFF) in region_state_set
            }
        )
    )
    if not internal_state_edges:
        semantic_successors = _semantic_program_successors_by_state(
            semantic_reference_program
        )
        derived_edges = []
        for source_state, target_state in zip(region_states, region_states[1:]):
            successor_states = semantic_successors.get(int(source_state) & 0xFFFFFFFF, ())
            if (int(target_state) & 0xFFFFFFFF) not in successor_states:
                continue
            derived_edges.append(
                (
                    int(source_state) & 0xFFFFFFFF,
                    int(target_state) & 0xFFFFFFFF,
                )
            )
        internal_state_edges = tuple(sorted(set(derived_edges)))
    if not internal_state_edges and len(region_states) >= 2:
        internal_state_edges = tuple(
            (
                int(source_state) & 0xFFFFFFFF,
                int(target_state) & 0xFFFFFFFF,
            )
            for source_state, target_state in zip(region_states, region_states[1:])
        )
    exact_labels_present = all(label in labels for label in region_labels)
    state_markers_present = required_state_markers.issubset(state_markers)
    dag_states_present = required_state_markers.issubset(dag_state_values)
    entry_state = int(region_states[0]) & 0xFFFFFFFF
    entry_label = region_labels[0] if region_labels else None
    entry_state_present = (
        (entry_label is not None and entry_label in labels)
        or entry_state in state_markers
        or entry_state in dag_state_values
    )
    if not (
        exact_labels_present
        or state_markers_present
        or dag_states_present
        or (entry_state_present and bool(internal_state_edges))
    ):
        logger.info(
            "RECON DAG discovery: region %s rejected labels exact=%s state_markers=%s dag_states=%s missing_labels=%s missing_states=%s missing_dag_states=%s internal_edges=%s",
            region_name,
            exact_labels_present,
            state_markers_present,
            dag_states_present,
            sorted(label for label in region_labels if label not in labels),
            [f"0x{state:08X}" for state in sorted(required_state_markers - state_markers)],
            [f"0x{state:08X}" for state in sorted(required_state_markers - dag_state_values)],
            [f"0x{src:08X}->0x{dst:08X}" for src, dst in internal_state_edges],
        )
        return None
    if not internal_state_edges:
        logger.info(
            "RECON DAG discovery: region %s rejected empty_internal_edges labels=%s state_markers=%s",
            region_name,
            exact_labels_present,
            state_markers_present,
        )
        return None

    return ResolvedDagStructuredRegion(
        region_name=region_name,
        entry_state=region_states[0],
        state_values=region_states,
        state_labels=region_labels,
        internal_state_edges=internal_state_edges,
        exit_state_values=_normalize_region_exit_state_values(
            dag,
            exit_state_values,
            semantic_reference_program=semantic_reference_program,
        ),
    )


def _discover_single_state_exit_region(
    dag: object,
    *,
    semantic_reference_program: RenderedProgramSnapshot,
    entry_state: int,
    region_name: str,
) -> ResolvedDagStructuredRegion | None:
    normalized_entry = int(entry_state) & 0xFFFFFFFF
    if normalized_entry == 0:
        return None
    semantic_successors = _semantic_program_successors_by_state(
        semantic_reference_program
    )
    exit_state_values = tuple(
        int(state) & 0xFFFFFFFF
        for state in semantic_successors.get(normalized_entry, ())
        if (int(state) & 0xFFFFFFFF) != normalized_entry
    )
    if not exit_state_values:
        return None

    labels = {str(node.label_text) for node in semantic_reference_program.nodes}
    state_markers = _semantic_program_state_markers(semantic_reference_program)
    dag_state_values = {
        int(value) & 0xFFFFFFFF
        for value in (
            *(
                int(getattr(node.key, "state_const", 0))
                for node in getattr(dag, "nodes", ())
                if getattr(getattr(node, "key", None), "state_const", None) is not None
            ),
            *(
                int(getattr(edge.source_key, "state_const", 0))
                for edge in getattr(dag, "edges", ())
                if getattr(getattr(edge, "source_key", None), "state_const", None) is not None
            ),
            *(
                int(getattr(edge, "target_state", 0))
                for edge in getattr(dag, "edges", ())
                if getattr(edge, "target_state", None) is not None
            ),
        )
    }
    label = f"STATE_{normalized_entry:08X}"
    if not (
        label in labels
        or normalized_entry in state_markers
        or normalized_entry in dag_state_values
    ):
        return None

    return ResolvedDagStructuredRegion(
        region_name=region_name,
        entry_state=normalized_entry,
        state_values=(normalized_entry,),
        state_labels=(label,),
        internal_state_edges=(),
        exit_state_values=_normalize_region_exit_state_values(
            dag,
            exit_state_values,
            semantic_reference_program=semantic_reference_program,
        ),
    )


def discover_structured_dag_regions(
    dag: object,
    *,
    semantic_reference_program: RenderedProgramSnapshot | None,
) -> tuple[ResolvedDagStructuredRegion, ...]:
    """Return experimental structured regions inferred from the trusted semantic program.

    This stays deliberately narrow for the current `sub_7FFD` exploration. The
    goal is to surface one trusted region as a first-class lowering input before
    widening the contract.
    """
    if semantic_reference_program is None:
        return ()
    initial_state = getattr(dag, "initial_state", None)
    if initial_state is None or int(initial_state) != _SUB7FFD_INITIAL_REGION_STATES[0]:
        return ()
    regions: list[ResolvedDagStructuredRegion] = []
    initial_region = _discover_sub7ffd_region(
        dag,
        semantic_reference_program=semantic_reference_program,
        region_name=_SUB7FFD_INITIAL_REGION_NAME,
        region_states=_SUB7FFD_INITIAL_REGION_STATES,
        region_labels=_SUB7FFD_INITIAL_REGION_LABELS,
        exit_state_values=_SUB7FFD_INITIAL_REGION_EXITS,
    )
    if initial_region is not None:
        regions.append(initial_region)

    downstream_region = _discover_sub7ffd_region(
        dag,
        semantic_reference_program=semantic_reference_program,
        region_name=_SUB7FFD_DOWNSTREAM_CHAIN_REGION_NAME,
        region_states=_SUB7FFD_DOWNSTREAM_CHAIN_REGION_STATES,
        region_labels=_SUB7FFD_DOWNSTREAM_CHAIN_REGION_LABELS,
    )
    if downstream_region is not None:
        regions.append(downstream_region)

    retry_region = _discover_sub7ffd_region(
        dag,
        semantic_reference_program=semantic_reference_program,
        region_name=_SUB7FFD_RETRY_CHAIN_REGION_NAME,
        region_states=_SUB7FFD_RETRY_CHAIN_REGION_STATES,
        region_labels=_SUB7FFD_RETRY_CHAIN_REGION_LABELS,
        exit_state_values=_SUB7FFD_RETRY_CHAIN_REGION_EXITS,
    )
    if retry_region is not None:
        regions.append(retry_region)

    exact_corridor_region = _discover_sub7ffd_region(
        dag,
        semantic_reference_program=semantic_reference_program,
        region_name=_SUB7FFD_6D207773_CORRIDOR_REGION_NAME,
        region_states=_SUB7FFD_6D207773_CORRIDOR_REGION_STATES,
        region_labels=_SUB7FFD_6D207773_CORRIDOR_REGION_LABELS,
        exit_state_values=_SUB7FFD_6D207773_CORRIDOR_REGION_EXITS,
    )
    if exact_corridor_region is not None:
        regions.append(exact_corridor_region)

    exact_follow_region = _discover_sub7ffd_region(
        dag,
        semantic_reference_program=semantic_reference_program,
        region_name=_SUB7FFD_7C2C0220_CORRIDOR_REGION_NAME,
        region_states=_SUB7FFD_7C2C0220_CORRIDOR_REGION_STATES,
        region_labels=_SUB7FFD_7C2C0220_CORRIDOR_REGION_LABELS,
        exit_state_values=_SUB7FFD_7C2C0220_CORRIDOR_REGION_EXITS,
    )
    if exact_follow_region is not None:
        regions.append(exact_follow_region)

    branch_follow_region = _discover_sub7ffd_region(
        dag,
        semantic_reference_program=semantic_reference_program,
        region_name=_SUB7FFD_10743C4C_BRANCH_REGION_NAME,
        region_states=_SUB7FFD_10743C4C_BRANCH_REGION_STATES,
        region_labels=_SUB7FFD_10743C4C_BRANCH_REGION_LABELS,
        exit_state_values=_SUB7FFD_10743C4C_BRANCH_REGION_EXITS,
    )
    if branch_follow_region is not None:
        regions.append(branch_follow_region)

    discovered_entry_states = {
        int(region.entry_state) & 0xFFFFFFFF
        for region in regions
    }
    covered_region_states = {
        int(state) & 0xFFFFFFFF
        for region in regions
        for state in getattr(region, "state_values", ())
    }
    pending_exit_states = [
        int(state) & 0xFFFFFFFF
        for region in regions
        for state in getattr(region, "exit_state_values", ())
    ]
    while pending_exit_states:
        exit_state = int(pending_exit_states.pop(0)) & 0xFFFFFFFF
        if exit_state == 0:
            continue
        if exit_state in discovered_entry_states or exit_state in covered_region_states:
            continue
        synthesized_region = _discover_single_state_exit_region(
            dag,
            semantic_reference_program=semantic_reference_program,
            entry_state=exit_state,
            region_name=f"sub7ffd_exit_state_region_{exit_state:08x}",
        )
        if synthesized_region is None:
            continue
        regions.append(synthesized_region)
        discovered_entry_states.add(exit_state)
        covered_region_states.update(
            int(state) & 0xFFFFFFFF
            for state in getattr(synthesized_region, "state_values", ())
        )
        pending_exit_states.extend(
            int(state) & 0xFFFFFFFF
            for state in getattr(synthesized_region, "exit_state_values", ())
            if (int(state) & 0xFFFFFFFF) not in discovered_entry_states
            and (int(state) & 0xFFFFFFFF) not in covered_region_states
            and (int(state) & 0xFFFFFFFF) != 0
        )

    canonical_regions = _canonicalize_alias_exit_regions(
        dag,
        regions,
        semantic_reference_program=semantic_reference_program,
    )
    logger.info(
        "RECON DAG discovery: structured regions=%s",
        tuple(str(region.region_name) for region in canonical_regions),
    )
    return canonical_regions


def build_linearized_dag_round_summary(
    *,
    current_flow_graph: object,
    transition_result: object,
    dispatcher_serial: int,
    state_var_stkoff: int | None,
    pre_header_serial: int | None,
    initial_state: int | None,
    handler_range_map: dict | None,
    condition_chain_blocks: tuple[int, ...],
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
        condition_chain_blocks=tuple(sorted(int(block) for block in condition_chain_blocks)),
        diagnostics=tuple(diagnostics or ()),
        dispatcher=dispatcher,
        mba=mba,
        prefer_local_corridors=True,
    )
    semantic_reference_program = build_linearized_state_program(
        dag,
        order_strategy=RenderOrderStrategy.SEMANTIC,
        program_strategy=ProgramRenderStrategy.LOCAL_SEGMENT_COLLAPSING,
        label_render_mode=LabelRenderMode.STATE_FAMILY,
        boundary_inline_mode=BoundaryInlineMode.LABELS_ONLY,
        comment_mode=ProgramCommentMode.MINIMAL,
    )
    semantic_reference_program = _normalize_semantic_reference_program_aliases(
        dag,
        semantic_reference_program,
    )
    dag_report = build_transition_report(
        current_flow_graph,
        transition_result,
        dispatcher_entry_serial=dispatcher_serial,
        state_var_stkoff=state_var_stkoff,
        pre_header_serial=pre_header_serial,
        initial_state=initial_state,
        handler_range_map=handler_range_map or {},
        condition_chain_blocks=tuple(sorted(int(block) for block in condition_chain_blocks)),
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
    structured_regions = discover_structured_dag_regions(
        dag,
        semantic_reference_program=semantic_reference_program,
    )
    return ResolvedDagRoundSummary(
        dag=dag,
        semantic_reference_program=semantic_reference_program,
        structured_regions=structured_regions,
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
    "ResolvedDagStructuredRegion",
    "build_linearized_dag_round_summary",
    "discover_structured_dag_regions",
]
