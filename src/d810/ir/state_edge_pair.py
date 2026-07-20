"Shared state-edge-pair helpers used by reconstruction producers + emitters.\n\n``state_edge_pair(edge)`` extracts the ``(source_state, target_state)`` unsigned\n32-bit tuple that identifies a DAG edge in region-accept bookkeeping. Previously\nduplicated across four producer modules via the copy-local pattern; consolidated\nhere so every Option-C producer/emitter imports from one canonical definition.\n\nLives in the cfg layer because it is pure tuple manipulation on duck-typed\nedge attributes (no preanalysis-specific types), and both cfg emitters and preanalysis\nproducers need it.\n"
from __future__ import annotations


def state_edge_pair(edge) -> tuple[int, int] | None:
    """Return ``(source_state & 0xFFFFFFFF, target_state & 0xFFFFFFFF)``.

    Returns ``None`` when either endpoint's state is unset. Duck-typed on
    ``edge.source_key.state_const`` and ``edge.target_state`` so it accepts
    both live ``StateDagEdge`` instances and test doubles.
    """
    source_key = getattr(edge, "source_key", None)
    source_state = getattr(source_key, "state_const", None)
    target_state = getattr(edge, "target_state", None)
    if source_state is None or target_state is None:
        return None
    return (
        int(source_state) & 0xFFFFFFFF,
        int(target_state) & 0xFFFFFFFF,
    )


def format_state_pair(pair: tuple[int, int] | None) -> str:
    """Format a state-edge-pair for log lines.

    ``None`` is rendered as ``"?->?"`` to match the original helpers.
    """
    if pair is None:
        return "?->?"
    return "0x%08X->0x%08X" % pair


__all__ = ("state_edge_pair", "format_state_pair")
