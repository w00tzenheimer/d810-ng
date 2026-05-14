"""Backend-neutral exact semantic edge selection helpers."""
from __future__ import annotations

from collections.abc import Iterable

from d810.cfg.semantic_conditional_lowering import is_straight_line_handoff

__all__ = [
    "parse_focus_edge_pairs",
    "resolve_edge_window",
    "select_focused_semantic_exact_edges",
    "select_windowed_semantic_exact_edges",
    "semantic_edge_state_pair",
]


def semantic_edge_state_pair(edge: object) -> tuple[int, int] | None:
    source_key = getattr(edge, "source_key", None)
    source_state = getattr(source_key, "state_const", None)
    target_state = getattr(edge, "target_state", None)
    if source_state is None or target_state is None:
        return None
    return (
        int(source_state) & 0xFFFFFFFF,
        int(target_state) & 0xFFFFFFFF,
    )


def _parse_nonnegative_int(value: str | int | None, *, default: int) -> int:
    if value is None or value == "":
        return default
    try:
        parsed = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return default
    return max(0, parsed)


def resolve_edge_window(
    total_edges: int,
    *,
    start_value: str | int | None = None,
    stop_value: str | int | None = None,
) -> tuple[int, int]:
    start = _parse_nonnegative_int(start_value, default=0)
    stop = _parse_nonnegative_int(stop_value, default=total_edges)
    if start > total_edges:
        start = total_edges
    if stop > total_edges:
        stop = total_edges
    if stop < start:
        stop = start
    return start, stop


def _parse_state_value(raw: str) -> int:
    value = raw.strip()
    if value.lower().startswith("0x"):
        return int(value, 0)
    return int(value, 16)


def parse_focus_edge_pairs(
    raw: str | None,
) -> tuple[tuple[int, int], ...] | None:
    """Parse a ``src,dst[;src,dst]*`` exact-edge focus spec.

    Bare values are interpreted as hexadecimal for compatibility with the
    existing ``D810_EXACT_NODE_FOCUS_EDGES`` convention.
    """
    if raw is None:
        return None
    cleaned = raw.strip()
    if not cleaned:
        return None
    pairs: list[tuple[int, int]] = []
    for chunk in cleaned.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = [part.strip() for part in chunk.split(",")]
        if len(parts) != 2:
            continue
        try:
            src = _parse_state_value(parts[0])
            dst = _parse_state_value(parts[1])
        except ValueError:
            continue
        pairs.append((src & 0xFFFFFFFF, dst & 0xFFFFFFFF))
    return tuple(pairs) if pairs else None


def select_focused_semantic_exact_edges(
    plannable_edges: Iterable[object],
    focus_pairs: Iterable[tuple[int, int]] | None,
) -> list[tuple[object, tuple[int, int]]]:
    if not focus_pairs:
        return []
    by_pair: dict[tuple[int, int], object] = {}
    for plannable in plannable_edges:
        pair = semantic_edge_state_pair(getattr(plannable, "edge", None))
        if pair is not None and pair not in by_pair:
            by_pair[pair] = plannable
    selected: list[tuple[object, tuple[int, int]]] = []
    for src, dst in focus_pairs:
        pair = (int(src) & 0xFFFFFFFF, int(dst) & 0xFFFFFFFF)
        plannable = by_pair.get(pair)
        if plannable is not None:
            selected.append((plannable, pair))
    return selected


def select_windowed_semantic_exact_edges(
    plannable_edges: Iterable[object],
    *,
    start_value: str | int | None = None,
    stop_value: str | int | None = None,
) -> tuple[list[tuple[object, tuple[int, int]]], tuple[int, int], int]:
    ordered_edges: list[tuple[object, tuple[int, int]]] = []
    seen_pairs: set[tuple[int, int]] = set()
    for plannable in plannable_edges:
        edge = getattr(plannable, "edge", None)
        if edge is None or not is_straight_line_handoff(edge):
            continue
        pair = semantic_edge_state_pair(edge)
        if pair is None or pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        ordered_edges.append((plannable, pair))

    start, stop = resolve_edge_window(
        len(ordered_edges),
        start_value=start_value,
        stop_value=stop_value,
    )
    return ordered_edges[start:stop], (start, stop), len(ordered_edges)
