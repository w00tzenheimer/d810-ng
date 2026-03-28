"""Pure residual handoff discovery helpers.

These helpers answer semantic target-resolution questions for residual
dispatcher handoffs without choosing or applying any lowering policy.
"""

from __future__ import annotations

from d810.recon.flow.dag_index import build_dag_node_maps
from d810.recon.flow.linearized_state_dag import (
    LinearizedStateDag,
    StateDagEdge,
    StateDagNode,
)


def dispatcher_has_exact_state_row(
    state_value: int | None,
    *,
    dispatcher: object | None = None,
) -> bool:
    """Return whether ``dispatcher`` has an exact one-state row for ``state_value``."""
    if state_value is None or dispatcher is None:
        return False

    rows = getattr(dispatcher, "_rows", None)
    if not rows:
        return False

    for row in rows:
        lo = getattr(row, "lo", None)
        hi = getattr(row, "hi", None)
        if lo is None or hi is None:
            continue
        lo = int(lo) & 0xFFFFFFFF
        hi = int(hi) & 0xFFFFFFFF
        if lo > state_value:
            break
        if lo == state_value and hi - lo == 1:
            return True
    return False


def dispatcher_exact_state_target(
    state_value: int | None,
    *,
    dispatcher: object | None = None,
) -> int | None:
    """Return the dispatch target for an exact one-state row, if any."""
    if state_value is None or dispatcher is None:
        return None

    rows = getattr(dispatcher, "_rows", None)
    if not rows:
        return None

    for row in rows:
        lo = getattr(row, "lo", None)
        hi = getattr(row, "hi", None)
        if lo is None or hi is None:
            continue
        lo = int(lo) & 0xFFFFFFFF
        hi = int(hi) & 0xFFFFFFFF
        if lo > state_value:
            break
        if lo == state_value and hi - lo == 1:
            return int(getattr(row, "target", 0))
    return None


def resolve_path_lead_entry_from_node(
    dag: LinearizedStateDag,
    node: StateDagNode,
    *,
    bst_node_blocks: set[int],
) -> int | None:
    """Return a unique non-BST path lead for ``node``, if one exists."""
    outgoing_paths = tuple(
        edge.ordered_path
        for edge in dag.edges
        if edge.source_key == node.key and edge.ordered_path
    )
    if not outgoing_paths:
        return None

    blocks_on_outgoing_paths = {
        block_serial
        for path in outgoing_paths
        for block_serial in path
    }
    if node.entry_anchor in blocks_on_outgoing_paths:
        return None

    path_starts = sorted(
        {
            path[0]
            for path in outgoing_paths
            if path[0] not in bst_node_blocks
        }
    )
    if len(path_starts) != 1:
        return None
    return path_starts[0]


def resolve_redirect_safe_entry_from_node(
    node: StateDagNode,
    *,
    dag: LinearizedStateDag | None = None,
    bst_node_blocks: set[int],
) -> int | None:
    """Return a non-BST entry representative for ``node``."""
    if dag is not None:
        path_lead_entry = resolve_path_lead_entry_from_node(
            dag,
            node,
            bst_node_blocks=bst_node_blocks,
        )
        if path_lead_entry is not None:
            return path_lead_entry
    candidates = (
        node.entry_anchor,
        *node.exclusive_blocks,
        *node.owned_blocks,
    )
    for block_serial in candidates:
        if block_serial not in bst_node_blocks:
            return block_serial
    return node.entry_anchor if node.entry_anchor not in bst_node_blocks else None


def resolve_redirect_safe_target_entry(
    dag: LinearizedStateDag,
    edge: StateDagEdge,
    *,
    bst_node_blocks: set[int],
) -> int | None:
    """Return the semantic redirect-safe entry for one residual handoff edge."""
    target_entry = edge.target_entry_anchor
    explicit_target_entry = (
        target_entry
        if target_entry is not None and target_entry not in bst_node_blocks
        else None
    )
    target_node = (
        build_dag_node_maps(dag).node_by_key.get(edge.target_key)
        if edge.target_key is not None
        else None
    )
    labeled_entry = None
    if edge.target_label:
        labeled_matches = [
            node for node in dag.nodes if node.state_label == edge.target_label
        ]
        if len(labeled_matches) == 1:
            labeled_entry = resolve_redirect_safe_entry_from_node(
                labeled_matches[0],
                dag=dag,
                bst_node_blocks=bst_node_blocks,
            )
    if (
        labeled_entry is not None
        and edge.target_label
        and edge.target_label.endswith("_fallback")
    ):
        return labeled_entry
    if target_node is not None:
        safe_target_entry = resolve_redirect_safe_entry_from_node(
            target_node,
            dag=dag,
            bst_node_blocks=bst_node_blocks,
        )
        if (
            explicit_target_entry is not None
            and safe_target_entry is not None
            and explicit_target_entry != safe_target_entry
        ):
            if explicit_target_entry in edge.ordered_path:
                return safe_target_entry
            return explicit_target_entry
        if safe_target_entry is not None:
            return safe_target_entry
    if labeled_entry is not None:
        return labeled_entry
    if explicit_target_entry is None:
        return None
    return explicit_target_entry


__all__ = [
    "dispatcher_exact_state_target",
    "dispatcher_has_exact_state_row",
    "resolve_path_lead_entry_from_node",
    "resolve_redirect_safe_entry_from_node",
    "resolve_redirect_safe_target_entry",
]
