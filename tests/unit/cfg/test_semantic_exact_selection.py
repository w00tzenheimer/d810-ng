from __future__ import annotations

from types import SimpleNamespace

from d810.transforms.semantic_exact_selection import (
    parse_focus_edge_pairs,
    resolve_edge_window,
    select_focused_semantic_exact_edges,
    select_windowed_semantic_exact_edges,
    semantic_edge_state_pair,
)


def _edge(src: int | None, dst: int | None, *, kind: str = "TRANSITION"):
    return SimpleNamespace(
        source_key=SimpleNamespace(state_const=src) if src is not None else None,
        target_state=dst,
        kind=SimpleNamespace(name=kind),
    )


def _plannable(edge: object):
    return SimpleNamespace(edge=edge)


def test_semantic_edge_state_pair_normalizes_to_u32() -> None:
    assert semantic_edge_state_pair(_edge(0x1_0000_0001, -1)) == (
        1,
        0xFFFFFFFF,
    )
    assert semantic_edge_state_pair(_edge(None, 1)) is None
    assert semantic_edge_state_pair(_edge(1, None)) is None


def test_resolve_edge_window_clamps_and_orders() -> None:
    assert resolve_edge_window(10) == (0, 10)
    assert resolve_edge_window(10, start_value="7", stop_value="3") == (7, 7)
    assert resolve_edge_window(10, start_value="0x2", stop_value="99") == (2, 10)
    assert resolve_edge_window(10, start_value="bad", stop_value="bad") == (0, 10)


def test_parse_focus_edge_pairs_handles_hex_specs() -> None:
    assert parse_focus_edge_pairs(None) is None
    assert parse_focus_edge_pairs("") is None
    assert parse_focus_edge_pairs("   ") is None
    assert parse_focus_edge_pairs("5d0aebd3,606dc166") == (
        (0x5D0AEBD3, 0x606DC166),
    )
    assert parse_focus_edge_pairs(
        "5d0aebd3,606dc166;606dc166,139f2922"
    ) == (
        (0x5D0AEBD3, 0x606DC166),
        (0x606DC166, 0x139F2922),
    )
    assert parse_focus_edge_pairs("0x10,0x20") == ((0x10, 0x20),)
    assert parse_focus_edge_pairs("garbage;0x10,0x20") == ((0x10, 0x20),)


def test_select_focused_semantic_exact_edges_preserves_focus_order() -> None:
    first = _plannable(_edge(0x10, 0x20))
    second = _plannable(_edge(0x30, 0x40))

    selected = select_focused_semantic_exact_edges(
        (first, second),
        ((0x30, 0x40), (0x10, 0x20)),
    )

    assert selected == [(second, (0x30, 0x40)), (first, (0x10, 0x20))]


def test_select_windowed_semantic_exact_edges_skips_conditionals_and_duplicates() -> None:
    first = _plannable(_edge(0x10, 0x20))
    duplicate = _plannable(_edge(0x10, 0x20))
    conditional = _plannable(_edge(0x30, 0x40, kind="CONDITIONAL_TRANSITION"))
    second = _plannable(_edge(0x50, 0x60))

    selected, window, total = select_windowed_semantic_exact_edges(
        (first, duplicate, conditional, second),
        start_value="1",
        stop_value="2",
    )

    assert total == 2
    assert window == (1, 2)
    assert selected == [(second, (0x50, 0x60))]
