"""Stash the §1a recovered (projected post-edit) FlowGraph for diagnostics.

The §1a reconstruction projects the lifted FlowGraph through its spine
modifications (``project_post_state``) to obtain the recovered topology -- the
dispatcher edges replaced by the reconstructed handler chain. This module keeps
the most recent projection so the **diagnostic** structurer
(``D810_USE_STRUCTURER``) can structure the *recovered* CFG instead of the raw
flattened ``lift(mba)``.

Diagnostics only: it never drives planning or mutation. A module-level slot is
acceptable because it is read solely by the dump path, immediately after the
live §1a run that set it, for the same function.
"""
from __future__ import annotations

_LAST_RECOVERED_FLOW_GRAPH: object | None = None

__all__ = ["record_recovered_flow_graph", "get_recovered_flow_graph"]


def record_recovered_flow_graph(flow_graph: object) -> None:
    """Stash the §1a projected/recovered FlowGraph (called from the §1a lower)."""
    global _LAST_RECOVERED_FLOW_GRAPH
    _LAST_RECOVERED_FLOW_GRAPH = flow_graph


def get_recovered_flow_graph() -> object | None:
    """Return the most recently recorded recovered FlowGraph, or ``None``."""
    return _LAST_RECOVERED_FLOW_GRAPH
