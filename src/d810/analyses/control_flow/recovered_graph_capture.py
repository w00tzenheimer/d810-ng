"""Stash the unflatten recovered (projected post-edit) FlowGraph for diagnostics.

The unflatten reconstruction projects the lifted FlowGraph through its spine
modifications (``project_post_state``) to obtain the recovered topology -- the
dispatcher edges replaced by the reconstructed handler chain. This module keeps
the most recent projection so the **diagnostic** structurer
(``D810_USE_STRUCTURER``) can structure the *recovered* CFG instead of the raw
flattened ``lift(mba)``.

Diagnostics only: it never drives planning or mutation. A module-level slot is
acceptable because it is read solely by the dump path, immediately after the
live unflatten run that set it, for the same function.
"""
from __future__ import annotations

_LAST_RECOVERED_FLOW_GRAPH: object | None = None
_LAST_RECOVERED_STATE_DAG: object | None = None
_LAST_EXPLORE_RESOLVED_EDGES: tuple[object, ...] = ()
_LAST_EXPLORE_MATERIALIZE_BLOCKS: frozenset[int] = frozenset()

__all__ = [
    "record_recovered_flow_graph",
    "get_recovered_flow_graph",
    "record_recovered_state_dag",
    "get_recovered_state_dag",
    "record_explore_resolved_edges",
    "get_explore_resolved_edges",
    "record_explore_materialize_blocks",
    "get_explore_materialize_blocks",
]


def record_recovered_flow_graph(flow_graph: object) -> None:
    """Stash the unflatten projected/recovered FlowGraph (called from the unflatten lower)."""
    global _LAST_RECOVERED_FLOW_GRAPH
    _LAST_RECOVERED_FLOW_GRAPH = flow_graph


def get_recovered_flow_graph() -> object | None:
    """Return the most recently recorded recovered FlowGraph, or ``None``."""
    return _LAST_RECOVERED_FLOW_GRAPH


def record_recovered_state_dag(dag: object) -> None:
    """Stash the unflatten recovered ``LinearizedStateDag`` (the clean handler graph).

    Read by the ``D810_USE_STRUCTURER`` diagnostic structurer so it structures
    the recovered state graph (dispatcher-free) instead of the lifted/projected
    FlowGraph (which retains the BST comparison blocks).
    """
    global _LAST_RECOVERED_STATE_DAG
    _LAST_RECOVERED_STATE_DAG = dag


def get_recovered_state_dag() -> object | None:
    """Return the most recently recorded recovered state-DAG, or ``None``."""
    return _LAST_RECOVERED_STATE_DAG


def record_explore_resolved_edges(edges: object) -> None:
    """Stash ``explore()``'s resolved transition edges (``view.resolved``).

    The dag-level injection can only attach edges between
    :class:`LinearizedStateDag` handler nodes; adapter-only blocks (range-backed
    / producer blocks) that exist only in the projected block CFG drop their
    enumerated edges. The ``D810_USE_EXPLORE`` structurer reads this stash to
    re-attach those edges at the block-CFG level (where both endpoints exist).
    Set fresh on every live state-DAG rebuild; read immediately after by the
    same dump path for the same function (diagnostics only).
    """
    global _LAST_EXPLORE_RESOLVED_EDGES
    _LAST_EXPLORE_RESOLVED_EDGES = tuple(edges or ())


def get_explore_resolved_edges() -> tuple[object, ...]:
    """Return the most recently stashed ``explore()`` resolved edges (or ``()``)."""
    return _LAST_EXPLORE_RESOLVED_EDGES


def record_explore_materialize_blocks(blocks: object) -> None:
    """Stash blocks the projection must materialise as state-graph nodes.

    A dispatcher/BST-region block that ``explore()`` routed to AND that writes
    the state var directly (e.g. the ``!= 0x7D9C16EC`` BST else-leaf ``blk57``,
    which re-dispatches ``0x307BF0E5`` -> ``186``).  Absent from the projected
    handler CFG, such a block severs the routed chain and orphans the block it
    re-dispatches to.  The ``D810_USE_EXPLORE`` structurer reads this set and
    materialises those blocks before attaching the explore edges.  Computed at
    the microcode layer because the state-var-write check needs the ``mba``; a
    shared-*temp* writer (``blk194`` writes ``var_70``) is deliberately excluded.
    """
    global _LAST_EXPLORE_MATERIALIZE_BLOCKS
    _LAST_EXPLORE_MATERIALIZE_BLOCKS = frozenset(int(b) for b in (blocks or ()))


def get_explore_materialize_blocks() -> frozenset[int]:
    """Return the most recently stashed materialise set (or empty)."""
    return _LAST_EXPLORE_MATERIALIZE_BLOCKS
