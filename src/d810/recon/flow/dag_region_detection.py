"""Semantic DAG region detection helpers.

These helpers operate on the reconstructed semantic DAG, not on live Hex-Rays
microblocks. They belong in ``recon.flow`` because they identify analysis
regions; strategy code can then decide whether and how to lower them.
"""
from __future__ import annotations

from collections import defaultdict

from d810.recon.flow.linearized_state_dag import (
    LinearizedStateDag,
    SemanticEdgeKind,
    StateDagNode,
)

__all__ = ["detect_linear_transition_regions"]


def detect_linear_transition_regions(
    dag: LinearizedStateDag,
) -> tuple[tuple[StateDagNode, ...], ...]:
    """Return maximal linear regions connected by ``TRANSITION`` edges.

    A region starts at every node whose number of incoming transition edges is
    not exactly one. The region then walks forward while the current node has
    exactly one outgoing transition edge and the target node has exactly one
    incoming transition edge.

    Branching states, joins, terminal states, and cycles close the current
    region. The output order is deterministic by ``entry_anchor`` and
    ``state_label``.
    """
    node_by_key = {node.key: node for node in dag.nodes}

    out_by_src: dict[object, list[StateDagNode]] = defaultdict(list)
    in_count: dict[object, int] = defaultdict(int)
    for edge in dag.edges:
        if edge.kind is not SemanticEdgeKind.TRANSITION:
            continue
        target_node: StateDagNode | None = None
        if edge.target_key is not None:
            target_node = node_by_key.get(edge.target_key)
        if target_node is None:
            continue
        out_by_src[edge.source_key].append(target_node)
        in_count[edge.target_key] = in_count.get(edge.target_key, 0) + 1

    is_region_start: set[object] = set()
    for node in dag.nodes:
        n_in = in_count.get(node.key, 0)
        if n_in != 1:
            is_region_start.add(node.key)

    visited: set[object] = set()
    regions: list[tuple[StateDagNode, ...]] = []

    ordered_nodes = sorted(
        dag.nodes,
        key=lambda n: (int(n.entry_anchor), str(n.state_label)),
    )

    for node in ordered_nodes:
        if node.key in visited:
            continue
        if node.key not in is_region_start:
            continue
        path = [node]
        visited.add(node.key)
        cur = node
        depth = 0
        while depth < 4096:
            outs = out_by_src.get(cur.key, [])
            if len(outs) != 1:
                break
            nxt = outs[0]
            if in_count.get(nxt.key, 0) != 1:
                break
            if nxt.key in visited:
                break
            path.append(nxt)
            visited.add(nxt.key)
            cur = nxt
            depth += 1
        regions.append(tuple(path))

    return tuple(regions)
