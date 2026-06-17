"""Helpers for resolving semantic target entries from DAG edges."""

from __future__ import annotations

from dataclasses import dataclass
import re


_STATE_LABEL_RE = re.compile(r"^STATE_([0-9A-Fa-f]{8})(?:(_fallback))?$")
_RAW_STATE_LABEL_RE = re.compile(r"^0x([0-9A-Fa-f]{8})(?:(_fallback))?$")


@dataclass(frozen=True, slots=True)
class EdgeTargetEntryResolution:
    """Resolved semantic entry for one DAG edge."""

    target_entry: int | None
    rejection_reason: str | None = None
    original_dispatcher_entry: int | None = None


def resolve_semantic_reference_entry_for_state(
    state_value: int,
    *,
    semantic_reference_program: object | None,
    dispatcher_region: set[int] | frozenset[int] = (),
    allow_dispatcher_exact_head: bool = False,
) -> int | None:
    """Return the semantic-reference entry for ``state_value`` when available."""
    if semantic_reference_program is None:
        return None

    normalized_state = int(state_value) & 0xFFFFFFFF
    dispatcher_blocks = {int(block) for block in dispatcher_region}
    target_labels = (
        f"STATE_{normalized_state:08X}",
        f"0x{normalized_state:08X}",
    )

    for node in getattr(semantic_reference_program, "nodes", ()) or ():
        label_text = str(getattr(node, "label_text", "") or "")
        if label_text not in target_labels:
            raw_match = _RAW_STATE_LABEL_RE.match(label_text)
            if raw_match is not None:
                normalized_label = f"STATE_{raw_match.group(1).upper()}{raw_match.group(2) or ''}"
                if normalized_label not in target_labels:
                    continue
            else:
                state_match = _STATE_LABEL_RE.match(label_text)
                if state_match is None:
                    continue
                normalized_label = f"0x{state_match.group(1).upper()}{state_match.group(2) or ''}"
                if normalized_label not in target_labels:
                    continue
        entry_anchor = getattr(node, "entry_anchor", None)
        if entry_anchor is None:
            continue
        entry_value = int(entry_anchor)
        node_kind = str(getattr(node, "node_kind", "") or "")
        label_is_state_family = (
            _STATE_LABEL_RE.match(label_text) is not None
            or _RAW_STATE_LABEL_RE.match(label_text) is not None
        )
        if (
            entry_value in dispatcher_blocks
            and not (
                allow_dispatcher_exact_head
                and (node_kind == "state_family" or label_is_state_family)
            )
        ):
            continue
        return entry_value
    return None


def resolve_exact_dag_entry_for_state(
    dag: object,
    state_value: int,
    *,
    dispatcher_region: set[int] | frozenset[int] = (),
    allow_dispatcher_exact_head: bool = False,
) -> int | None:
    """Return the best non-dispatcher exact DAG entry for ``state_value``."""
    normalized_state = int(state_value) & 0xFFFFFFFF
    dispatcher_blocks = {int(block) for block in dispatcher_region}
    candidates: list[tuple[int, int, int]] = []
    for node in getattr(dag, "nodes", ()) or ():
        node_key = getattr(node, "key", None)
        node_state = getattr(node_key, "state_const", None)
        if node_state is None or (int(node_state) & 0xFFFFFFFF) != normalized_state:
            continue
        entry_anchor = getattr(node, "entry_anchor", None)
        if entry_anchor is None:
            continue
        entry_value = int(entry_anchor)
        kind_name = str(getattr(getattr(node, "kind", None), "name", "") or "")
        if (
            entry_value in dispatcher_blocks
            and not (
                allow_dispatcher_exact_head
                and kind_name == "EXACT"
            )
        ):
            continue
        exact_rank = 0 if kind_name == "EXACT" else 1
        handler_serial = int(getattr(node_key, "handler_serial", entry_value))
        candidates.append((exact_rank, entry_value, handler_serial))
    if not candidates:
        return None
    candidates.sort()
    return int(candidates[0][1])


def resolve_edge_target_entry(
    edge: object,
    *,
    node_by_key: dict[object, object],
    dispatcher_region: set[int],
) -> EdgeTargetEntryResolution:
    """Resolve a non-dispatcher semantic entry for one DAG edge."""
    target_entry = edge.target_entry_anchor
    if target_entry is None:
        return EdgeTargetEntryResolution(
            target_entry=None,
            rejection_reason="missing_target_entry",
        )
    target_entry = int(target_entry)

    target_node = node_by_key.get(edge.target_key)
    resolved_non_condition_chain: int | None = None

    def _node_local_blocks(node: object | None) -> set[int]:
        if node is None:
            return set()
        blocks = {int(getattr(node, "entry_anchor"))}
        blocks.update(int(b) for b in getattr(node, "exclusive_blocks", ()) or ())
        blocks.update(int(b) for b in getattr(node, "owned_blocks", ()) or ())
        blocks.update(int(b) for b in getattr(node, "shared_suffix_blocks", ()) or ())
        return blocks

    # ``target_entry_anchor`` is already the DAG builder's concrete routing
    # decision.  If it names a non-dispatcher block outside the target node's
    # own local corridor, honor it before same-state exact-node lookup.  This
    # preserves dispatcher overrides for transient exact aliases such as
    # state 0x1864829A (edge routes to blk[152], stale exact node is blk[147]).
    # When the edge merely points into the target node's local corridor, keep
    # the older head-first behavior below.
    if target_entry not in dispatcher_region:
        target_node_blocks = _node_local_blocks(target_node)
        target_node_key = getattr(target_node, "key", None)
        target_node_state = (
            getattr(target_node_key, "state_const", None)
            if target_node_key is not None
            else None
        )
        edge_target_state = getattr(edge, "target_state", None)
        if (
            target_node_state is not None
            and edge_target_state is not None
            and int(target_node_state) != int(edge_target_state)
        ):
            return EdgeTargetEntryResolution(target_entry=target_entry)
        if not target_node_blocks or target_entry not in target_node_blocks:
            return EdgeTargetEntryResolution(target_entry=target_entry)

    def _iter_same_state_nodes() -> list[tuple[object | None, object]]:
        if edge.target_state is None:
            return []
        matches: list[tuple[StateDagNodeKey | None, StateDagNode]] = []
        for key, node in node_by_key.items():
            if key.state_const == edge.target_state:
                matches.append((key, node))
        matches.sort(
            key=lambda item: (
                0 if str(getattr(getattr(item[1], "kind", None), "name", "") or "") == "EXACT" else 1,
                int(item[1].entry_anchor),
                int(getattr(item[1], "handler_serial", item[1].entry_anchor)),
            )
        )
        return matches

    same_state_nodes = _iter_same_state_nodes()

    for _, node in same_state_nodes:
        candidate = int(node.entry_anchor)
        if candidate not in dispatcher_region:
            resolved_non_condition_chain = candidate
            break

    if resolved_non_condition_chain is not None:
        return EdgeTargetEntryResolution(
            target_entry=resolved_non_condition_chain,
            original_dispatcher_entry=(
                target_entry if target_entry in dispatcher_region else None
            ),
        )

    if target_entry not in dispatcher_region:
        return EdgeTargetEntryResolution(target_entry=target_entry)

    if resolved_non_condition_chain is None and target_node is not None:
        candidate_blocks: list[int] = []
        candidate_blocks.extend(int(b) for b in target_node.exclusive_blocks)
        candidate_blocks.extend(int(b) for b in target_node.owned_blocks)
        candidate_blocks.extend(int(b) for b in target_node.shared_suffix_blocks)
        for candidate in candidate_blocks:
            if candidate not in dispatcher_region:
                resolved_non_condition_chain = candidate
                break

    if resolved_non_condition_chain is None:
        for _, node in same_state_nodes:
            candidate_blocks: list[int] = []
            candidate_blocks.extend(int(b) for b in node.exclusive_blocks)
            candidate_blocks.extend(int(b) for b in node.owned_blocks)
            candidate_blocks.extend(int(b) for b in node.shared_suffix_blocks)
            for candidate in candidate_blocks:
                if candidate not in dispatcher_region:
                    resolved_non_condition_chain = candidate
                    break
            if resolved_non_condition_chain is not None:
                break

    if resolved_non_condition_chain is None:
        return EdgeTargetEntryResolution(
            target_entry=None,
            rejection_reason="dispatcher_target_entry",
        )
    return EdgeTargetEntryResolution(
        target_entry=resolved_non_condition_chain,
        original_dispatcher_entry=target_entry,
    )


__all__ = [
    "EdgeTargetEntryResolution",
    "resolve_edge_target_entry",
    "resolve_exact_dag_entry_for_state",
    "resolve_semantic_reference_entry_for_state",
]
