from __future__ import annotations

from types import SimpleNamespace

import pytest

import d810.cfg.semantic_conditional_lowering as semantic_conditional_lowering
from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.cfg.semantic_conditional_lowering import (
    ConditionalForkExactNodeArm,
    analyze_exact_conditional_alias_sites,
    analyze_exact_conditional_sites,
    collect_exact_conditional_alias_sites,
    collect_conditional_fork_scope,
    collect_conditional_node_scope,
    conditional_fork_path_from_source,
    normalize_clean_conditional_fork_arms,
    ordered_path_first_hop,
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
        source_branch_arm: int | None = None,
        kind_name: str = "CONDITIONAL_TRANSITION",
    ) -> None:
        self.kind = SimpleNamespace(name=kind_name)
        self.source_key = SimpleNamespace(state_const=source_state)
        self.target_state = target_state
        self.target_entry_anchor = target_entry_anchor
        self.source_anchor = SimpleNamespace(
            block_serial=source_block,
            branch_arm=source_branch_arm,
        )
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


def _fork_arm(
    *,
    first_hop: int,
    tail: int,
    ordered_path: tuple[int, ...],
) -> ConditionalForkExactNodeArm:
    return ConditionalForkExactNodeArm(
        target_state=0x22222222,
        target_entry=99,
        first_hop=first_hop,
        tail=tail,
        ordered_path=ordered_path,
        transition_edge=object(),
        return_distance=None,
    )


def test_analyze_exact_conditional_alias_sites_reports_inventory(monkeypatch) -> None:
    sites = (
        SimpleNamespace(source_block=30),
        SimpleNamespace(source_block=10),
        SimpleNamespace(source_block=30),
    )

    def _fake_alias_sites(round_summary, flow_graph):
        assert round_summary == "round"
        assert flow_graph == "graph"
        return sites

    monkeypatch.setattr(
        semantic_conditional_lowering,
        "analyze_duplicate_alias_conditional_sites",
        _fake_alias_sites,
    )

    result, inventory = analyze_exact_conditional_alias_sites("round", "graph")

    assert result == sites
    assert inventory.selected_count == 3
    assert inventory.alias_blocks == (10, 30, 30)
    assert collect_exact_conditional_alias_sites("round", "graph") == sites


def test_collect_conditional_fork_scope_uses_transition_arms_only() -> None:
    source_state = 0x11111111
    transition_a = _FakeEdge(
        source_state=source_state,
        source_block=10,
        target_state=0x22222222,
        target_entry_anchor=20,
        ordered_path=(10, 11, 12),
    )
    transition_b = _FakeEdge(
        source_state=source_state,
        source_block=10,
        target_state=0x33333333,
        target_entry_anchor=30,
        ordered_path=(10, 13, 14),
    )
    return_edge = _FakeEdge(
        source_state=source_state,
        source_block=10,
        target_state=0,
        target_entry_anchor=40,
        ordered_path=(10, 15, 16),
        kind_name="CONDITIONAL_RETURN",
    )
    unrelated_transition = _FakeEdge(
        source_state=source_state,
        source_block=99,
        target_state=0x44444444,
        target_entry_anchor=50,
        ordered_path=(99, 100),
    )
    dag = _round_summary([
        transition_a,
        transition_b,
        return_edge,
        unrelated_transition,
    ]).dag

    blocks, edges = collect_conditional_fork_scope(dag, source_block=10)

    assert blocks == {10, 11, 12, 13, 14}
    assert edges == {(10, 11), (11, 12), (10, 13), (13, 14)}


@pytest.mark.parametrize(
    ("path", "source", "expected"),
    [
        ((10, 11, 12), 10, 11),
        ((8, 10, 12), 10, 12),
        ((8, 9, 10), 10, None),
        ((8, 9, 10), 7, 9),
        ((), 7, None),
    ],
)
def test_ordered_path_first_hop(path: tuple[int, ...], source: int, expected: int | None) -> None:
    assert ordered_path_first_hop(path, source_block=source) == expected


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


@pytest.mark.parametrize("source_block", [28, 98, 136, 181])
def test_analyze_exact_conditional_sites_accepts_alias_duplicated_multi_transition_sites(
    source_block: int,
) -> None:
    taken_successor = source_block + 1
    fallback_successor = source_block + 10
    taken_tail_a = source_block + 20
    taken_tail_b = source_block + 21

    source_state = 0x10000000 + source_block
    transition_a = _FakeEdge(
        source_state=source_state,
        source_block=source_block,
        target_state=0x20000000 + source_block,
        target_entry_anchor=source_block + 100,
        source_branch_arm=0,
        ordered_path=(source_block, taken_successor, taken_tail_a),
    )
    transition_b = _FakeEdge(
        source_state=source_state,
        source_block=source_block,
        target_state=0x30000000 + source_block,
        target_entry_anchor=source_block + 200,
        source_branch_arm=1,
        ordered_path=(source_block, taken_successor, taken_tail_b),
    )
    return_edge = _FakeEdge(
        source_state=source_state,
        source_block=source_block,
        target_state=0x40000000 + source_block,
        target_entry_anchor=source_block + 300,
        source_branch_arm=1,
        ordered_path=(source_block, fallback_successor, fallback_successor + 1),
        kind_name="CONDITIONAL_RETURN",
    )
    flow_graph = _graph(
        {
            source_block: ((taken_successor, fallback_successor), ()),
            taken_successor: ((taken_tail_a, taken_tail_b), (source_block,)),
            taken_tail_a: ((2,), (taken_successor,)),
            taken_tail_b: ((2,), (taken_successor,)),
            fallback_successor: ((fallback_successor + 1,), (source_block,)),
            fallback_successor + 1: ((), (fallback_successor,)),
            2: ((), (taken_tail_a, taken_tail_b)),
        },
        entry=source_block,
    )

    sites, inventory = analyze_exact_conditional_sites(
        _round_summary([transition_a, transition_b, return_edge]),
        flow_graph,
    )

    assert inventory.selected_count >= 1
    assert any(item[0] == source_block for item in inventory.multi_transition_blocks)
    assert source_block not in inventory.shape_rejected_blocks
    assert any(site.source_block == source_block for site in sites)


def test_analyze_exact_conditional_sites_accepts_mixed_shape_multi_transition_site() -> None:
    source_block = 163
    taken_successor = 164
    fallback_successor = 170
    source_state = 0x50000000

    valid_transition = _FakeEdge(
        source_state=source_state,
        source_block=source_block,
        target_state=0x6CAA9521,
        target_entry_anchor=98,
        source_branch_arm=0,
        ordered_path=(source_block, taken_successor, 69),
    )
    mixed_transition = _FakeEdge(
        source_state=source_state,
        source_block=source_block,
        target_state=0x6E958F9A,
        target_entry_anchor=160,
        source_branch_arm=1,
        ordered_path=(source_block, fallback_successor, fallback_successor + 1),
    )
    return_edge = _FakeEdge(
        source_state=source_state,
        source_block=source_block,
        target_state=0x6AAAAAAA,
        target_entry_anchor=161,
        source_branch_arm=1,
        ordered_path=(source_block, fallback_successor, fallback_successor + 1),
        kind_name="CONDITIONAL_RETURN",
    )
    flow_graph = _graph(
        {
            source_block: ((taken_successor, fallback_successor), ()),
            taken_successor: ((69,), (source_block,)),
            69: ((2,), (taken_successor,)),
            fallback_successor: ((fallback_successor + 1,), (source_block,)),
            fallback_successor + 1: ((), (fallback_successor,)),
            2: ((), (69,)),
        },
        entry=source_block,
    )

    sites, inventory = analyze_exact_conditional_sites(
        _round_summary([valid_transition, mixed_transition, return_edge]),
        flow_graph,
    )

    assert inventory.selected_count >= 1
    assert any(item[0] == 163 for item in inventory.multi_transition_blocks)
    assert any(site.target_entry == 98 for site in sites)


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


def test_conditional_fork_path_from_source_requires_source_and_first_hop() -> None:
    assert conditional_fork_path_from_source(
        source_block=10,
        first_hop=11,
        ordered_path=(9, 10, 11, 20),
    ) == (10, 11, 20)
    assert conditional_fork_path_from_source(
        source_block=10,
        first_hop=12,
        ordered_path=(9, 10, 11, 20),
    ) is None
    assert conditional_fork_path_from_source(
        source_block=99,
        first_hop=11,
        ordered_path=(9, 10, 11, 20),
    ) is None


def test_normalize_clean_conditional_fork_arms_accepts_independent_single_pred_arms() -> None:
    flow_graph = _graph(
        {
            10: ((11, 12), ()),
            11: ((21,), (10,)),
            12: ((22,), (10,)),
            21: ((30,), (11,)),
            22: ((31,), (12,)),
            30: ((), (21,)),
            31: ((), (22,)),
        },
        entry=10,
    )
    arms = (
        _fork_arm(first_hop=11, tail=30, ordered_path=(10, 11, 21, 30)),
        _fork_arm(first_hop=12, tail=31, ordered_path=(10, 12, 22, 31)),
    )

    assert normalize_clean_conditional_fork_arms(
        flow_graph,
        source_block=10,
        arms=arms,
        dispatcher_region=set(),
    ) == arms


def test_normalize_clean_conditional_fork_arms_rewrites_empty_shared_join_tails() -> None:
    flow_graph = _graph(
        {
            10: ((11, 12), ()),
            11: ((21,), (10,)),
            12: ((22,), (10,)),
            21: ((40,), (11,)),
            22: ((40,), (12,)),
            40: ((50,), (21, 22)),
            50: ((), (40,)),
        },
        entry=10,
    )
    arms = (
        _fork_arm(first_hop=11, tail=40, ordered_path=(10, 11, 21, 40)),
        _fork_arm(first_hop=12, tail=40, ordered_path=(10, 12, 22, 40)),
    )

    normalized = normalize_clean_conditional_fork_arms(
        flow_graph,
        source_block=10,
        arms=arms,
        dispatcher_region=set(),
    )

    assert normalized is not None
    assert tuple(arm.tail for arm in normalized) == (21, 22)


def test_normalize_clean_conditional_fork_arms_rejects_join_to_dispatcher() -> None:
    flow_graph = _graph(
        {
            10: ((11, 12), ()),
            11: ((21,), (10,)),
            12: ((22,), (10,)),
            21: ((40,), (11,)),
            22: ((40,), (12,)),
            40: ((2,), (21, 22)),
            2: ((), (40,)),
        },
        entry=10,
    )
    arms = (
        _fork_arm(first_hop=11, tail=40, ordered_path=(10, 11, 21, 40)),
        _fork_arm(first_hop=12, tail=40, ordered_path=(10, 12, 22, 40)),
    )

    assert normalize_clean_conditional_fork_arms(
        flow_graph,
        source_block=10,
        arms=arms,
        dispatcher_region={2},
    ) is None
