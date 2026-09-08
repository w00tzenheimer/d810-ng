"""Read-only access to the graph owned by the SDK microcode lifecycle.

The SDK permits build_graph only once, before LOCOPT. Analysis does not own
that transition: optimize_local prepares the graph at LOCOPT. Calling the
builder again can restore instructions even on an already mature MBA.
"""
from __future__ import annotations

import ida_hexrays


class GraphReadinessUnavailable(RuntimeError):
    """The current MBA cannot supply an already prepared analysis graph."""


def require_graph_ready(mba: object) -> object:
    """Observe a mature MBA's existing graph, without a build fallback."""
    try:
        maturity = int(mba.maturity)
        if maturity < int(ida_hexrays.MMAT_LOCOPT):
            raise GraphReadinessUnavailable(
                f"read-only graph access requires LOCOPT or later: {maturity}"
            )
        graph = mba.get_graph()
        if graph is None:
            raise GraphReadinessUnavailable("SDK graph is unavailable")
        return graph
    except GraphReadinessUnavailable:
        raise
    except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
        raise GraphReadinessUnavailable("SDK graph observation failed") from exc


def ensure_graph_and_lists_ready(mba: object) -> None:
    """Observe the graph and prepare use/def lists, or report unavailability."""
    require_graph_ready(mba)
    try:
        for serial in range(int(mba.qty)):
            block = mba.get_mblock(serial)
            if block is None:
                raise GraphReadinessUnavailable(f"SDK block {serial} is unavailable")
            block.make_lists_ready()
    except GraphReadinessUnavailable:
        raise
    except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
        raise GraphReadinessUnavailable("SDK use/def list preparation failed") from exc
