"""Helpers for resolving semantic target entries from DAG edges."""

from __future__ import annotations

from dataclasses import dataclass

from d810.recon.flow.linearized_state_dag import (
    StateDagEdge,
    StateDagNode,
    StateDagNodeKey,
)


@dataclass(frozen=True, slots=True)
class EdgeTargetEntryResolution:
    """Resolved semantic entry for one DAG edge."""

    target_entry: int | None
    rejection_reason: str | None = None
    original_dispatcher_entry: int | None = None


def resolve_edge_target_entry(
    edge: StateDagEdge,
    *,
    node_by_key: dict[StateDagNodeKey, StateDagNode],
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
    if target_entry not in dispatcher_region:
        return EdgeTargetEntryResolution(target_entry=target_entry)

    target_node = node_by_key.get(edge.target_key)
    resolved_non_bst: int | None = None

    if target_node is not None:
        candidate_blocks: list[int] = [int(target_node.entry_anchor)]
        candidate_blocks.extend(int(b) for b in target_node.exclusive_blocks)
        candidate_blocks.extend(int(b) for b in target_node.owned_blocks)
        candidate_blocks.extend(int(b) for b in target_node.shared_suffix_blocks)
        for candidate in candidate_blocks:
            if candidate not in dispatcher_region:
                resolved_non_bst = candidate
                break

    if resolved_non_bst is None and edge.target_state is not None:
        for key, node in node_by_key.items():
            if (
                key.state_const == edge.target_state
                and int(node.entry_anchor) not in dispatcher_region
            ):
                resolved_non_bst = int(node.entry_anchor)
                break

    if resolved_non_bst is None:
        return EdgeTargetEntryResolution(
            target_entry=None,
            rejection_reason="dispatcher_target_entry",
        )
    return EdgeTargetEntryResolution(
        target_entry=resolved_non_bst,
        original_dispatcher_entry=target_entry,
    )


__all__ = [
    "EdgeTargetEntryResolution",
    "resolve_edge_target_entry",
]
