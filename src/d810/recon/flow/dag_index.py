"""Indexes and small query helpers over :mod:`linearized_state_dag`."""

from __future__ import annotations

from collections import defaultdict

from d810.recon.flow.linearized_state_dag import LinearizedStateDag, StateDagEdge


def semantic_entry_anchors(dag: LinearizedStateDag) -> set[int]:
    """Return entry anchors owned by semantic DAG nodes."""
    return {int(node.entry_anchor) for node in dag.nodes}


def incoming_edges_by_target_entry(
    dag: LinearizedStateDag,
) -> dict[int, tuple[StateDagEdge, ...]]:
    """Group DAG edges by target entry anchor."""
    incoming: defaultdict[int, list[StateDagEdge]] = defaultdict(list)
    for edge in dag.edges:
        if edge.target_entry_anchor is None:
            continue
        incoming[int(edge.target_entry_anchor)].append(edge)
    return {entry: tuple(edges) for entry, edges in incoming.items()}


__all__ = [
    "incoming_edges_by_target_entry",
    "semantic_entry_anchors",
]
