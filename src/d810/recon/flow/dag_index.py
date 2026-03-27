"""Indexes and small query helpers over :mod:`linearized_state_dag`."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from d810.recon.flow.linearized_state_dag import (
    LinearizedStateDag,
    StateDagEdge,
    StateDagNode,
    StateDagNodeKey,
)


@dataclass(frozen=True, slots=True)
class DagNodeMaps:
    """Lookup tables derived from one :class:`LinearizedStateDag`."""

    node_by_key: dict[StateDagNodeKey, StateDagNode]
    outgoing_by_key: dict[StateDagNodeKey, tuple[StateDagEdge, ...]]
    nodes_by_entry_anchor: dict[int, tuple[StateDagNode, ...]]


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


def build_dag_node_maps(dag: LinearizedStateDag) -> DagNodeMaps:
    """Build stable node/edge lookup tables for one DAG snapshot."""
    node_by_key = {node.key: node for node in dag.nodes}
    outgoing_by_key: defaultdict[StateDagNodeKey, list[StateDagEdge]] = defaultdict(list)
    nodes_by_entry_anchor: defaultdict[int, list[StateDagNode]] = defaultdict(list)
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
    edge: StateDagEdge,
    *,
    node_by_key: dict[StateDagNodeKey, StateDagNode],
    nodes_by_entry_anchor: dict[int, tuple[StateDagNode, ...]],
) -> StateDagNode | None:
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
