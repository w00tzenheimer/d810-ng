"""Indexes and small query helpers over :mod:`linearized_state_dag`."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DagNodeMaps:
    """Lookup tables derived from one :class:`LinearizedStateDag`."""

    node_by_key: dict[object, object]
    outgoing_by_key: dict[object, tuple[object, ...]]
    nodes_by_entry_anchor: dict[int, tuple[object, ...]]


def semantic_entry_anchors(dag: object) -> set[int]:
    """Return entry anchors owned by semantic DAG nodes."""
    return {int(node.entry_anchor) for node in dag.nodes}


def incoming_edges_by_target_entry(
    dag: object,
) -> dict[int, tuple[object, ...]]:
    """Group DAG edges by target entry anchor."""
    incoming: defaultdict[int, list[object]] = defaultdict(list)
    for edge in dag.edges:
        if edge.target_entry_anchor is None:
            continue
        incoming[int(edge.target_entry_anchor)].append(edge)
    return {entry: tuple(edges) for entry, edges in incoming.items()}


def build_dag_node_maps(dag: object) -> DagNodeMaps:
    """Build stable node/edge lookup tables for one DAG snapshot."""
    node_by_key = {node.key: node for node in dag.nodes}
    outgoing_by_key: defaultdict[object, list[object]] = defaultdict(list)
    nodes_by_entry_anchor: defaultdict[int, list[object]] = defaultdict(list)
    for node in dag.nodes:
        nodes_by_entry_anchor[int(node.entry_anchor)].append(node)
    for dag_edge in dag.edges:
        outgoing_by_key[dag_edge.source_key].append(dag_edge)
    return DagNodeMaps(
        node_by_key=node_by_key,
        outgoing_by_key={key: tuple(edges) for key, edges in outgoing_by_key.items()},
        nodes_by_entry_anchor={
            anchor: tuple(nodes) for anchor, nodes in nodes_by_entry_anchor.items()
        },
    )


def resolve_target_node(
    edge: object,
    *,
    node_by_key: dict[object, object],
    nodes_by_entry_anchor: dict[int, tuple[object, ...]],
) -> object | None:
    """Resolve the semantic target node for one DAG edge."""
    if edge.target_key is not None:
        return node_by_key.get(edge.target_key)
    if edge.target_entry_anchor is None:
        return None
    candidates = nodes_by_entry_anchor.get(int(edge.target_entry_anchor), ())
    if len(candidates) != 1:
        return None
    return candidates[0]


__all__ = [
    "DagNodeMaps",
    "build_dag_node_maps",
    "incoming_edges_by_target_entry",
    "resolve_target_node",
    "semantic_entry_anchors",
]
