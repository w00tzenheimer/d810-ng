from __future__ import annotations

from types import SimpleNamespace

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.cfg.semantic_conditional_lowering import (
    analyze_exact_conditional_sites,
    collect_conditional_node_scope,
)


def _graph(blocks: dict[int, tuple[tuple[int, ...], tuple[int, ...]]], entry: int) -> FlowGraph:
    return FlowGraph(
        blocks={
            serial: BlockSnapshot(
                serial,
                0,
                succs,
                preds,
                0,
                0,
                (),
            )
            for serial, (succs, preds) in blocks.items()
        },
        entry_serial=entry,
        func_ea=0x401000,
    )


class _FakeEdge:
    def __init__(
        self,
        *,
        source_state: int,
        source_block: int,
        target_state: int,
        target_entry_anchor: int,
        ordered_path: tuple[int, ...],
        kind_name: str = "CONDITIONAL_TRANSITION",
    ) -> None:
        self.kind = SimpleNamespace(name=kind_name)
        self.source_key = SimpleNamespace(state_const=source_state)
        self.target_state = target_state
        self.target_entry_anchor = target_entry_anchor
        self.source_anchor = SimpleNamespace(block_serial=source_block)
        self.ordered_path = ordered_path


def _round_summary(edges: list[_FakeEdge]) -> SimpleNamespace:
    return SimpleNamespace(
        dag=SimpleNamespace(edges=tuple(edges)),
        plannable_edges=tuple(
            SimpleNamespace(edge=edge)
            for edge in edges
            if getattr(edge.kind, "name", "") == "CONDITIONAL_TRANSITION"
        ),
    )


def _local_hammock_graph() -> FlowGraph:
    return _graph(
        {
            10: ((11, 12), ()),
            11: ((14,), (10,)),
            12: ((21,), (10,)),
            14: ((21,), (11,)),
            21: ((), (12, 14)),
        },
        entry=10,
    )


def test_analyze_exact_conditional_sites_selects_local_hammock() -> None:
    transition = _FakeEdge(
        source_state=0x11111111,
        source_block=10,
        target_state=0x22222222,
        target_entry_anchor=99,
        ordered_path=(10, 11, 14, 21),
    )
    return_edge = _FakeEdge(
        source_state=0x11111111,
        source_block=10,
        target_state=0,
        target_entry_anchor=21,
        ordered_path=(10, 12, 21),
        kind_name="CONDITIONAL_RETURN",
    )

    sites, inventory = analyze_exact_conditional_sites(
        _round_summary([transition, return_edge]),
        _local_hammock_graph(),
    )

    assert inventory.selected_count == 1
    assert inventory.multi_transition_blocks == ()
    assert inventory.missing_return_blocks == ()
    assert inventory.shape_rejected_blocks == ()
    assert len(sites) == 1
    assert sites[0].source_state == 0x11111111
    assert sites[0].source_block == 10
    assert sites[0].target_state == 0x22222222
    assert sites[0].target_entry == 99
    assert sites[0].taken_tail == 21


def test_analyze_exact_conditional_sites_reports_missing_return_edge() -> None:
    transition = _FakeEdge(
        source_state=0x11111111,
        source_block=10,
        target_state=0x22222222,
        target_entry_anchor=99,
        ordered_path=(10, 11, 14, 21),
    )

    sites, inventory = analyze_exact_conditional_sites(
        _round_summary([transition]),
        _local_hammock_graph(),
    )

    assert sites == ()
    assert inventory.missing_return_blocks == (10,)


def test_analyze_exact_conditional_sites_reports_multi_transition_source() -> None:
    transition_a = _FakeEdge(
        source_state=0x11111111,
        source_block=10,
        target_state=0x22222222,
        target_entry_anchor=99,
        ordered_path=(10, 11, 14, 21),
    )
    transition_b = _FakeEdge(
        source_state=0x11111111,
        source_block=10,
        target_state=0x33333333,
        target_entry_anchor=100,
        ordered_path=(10, 11, 14),
    )
    return_edge = _FakeEdge(
        source_state=0x11111111,
        source_block=10,
        target_state=0,
        target_entry_anchor=21,
        ordered_path=(10, 12, 21),
        kind_name="CONDITIONAL_RETURN",
    )

    sites, inventory = analyze_exact_conditional_sites(
        _round_summary([transition_a, transition_b, return_edge]),
        _local_hammock_graph(),
    )

    assert sites == ()
    assert inventory.multi_transition_blocks == ((10, 2, 1),)


def test_collect_conditional_node_scope_includes_sibling_return_path() -> None:
    transition = _FakeEdge(
        source_state=0x11111111,
        source_block=10,
        target_state=0x22222222,
        target_entry_anchor=99,
        ordered_path=(10, 11, 14, 21),
    )
    return_edge = _FakeEdge(
        source_state=0x11111111,
        source_block=10,
        target_state=0,
        target_entry_anchor=21,
        ordered_path=(10, 12, 21),
        kind_name="CONDITIONAL_RETURN",
    )
    dag = SimpleNamespace(edges=(transition, return_edge))

    blocks, edges = collect_conditional_node_scope(
        dag,
        transition,
        source_state=0x11111111,
        source_block=10,
    )

    assert blocks == {10, 11, 12, 14, 21}
    assert edges == {(10, 11), (11, 14), (14, 21), (10, 12), (12, 21)}
