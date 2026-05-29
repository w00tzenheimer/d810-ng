"""Tests for the portable loop / SCC analysis (LS8 S2). Pure-Python, no IDA."""
from __future__ import annotations

import dataclasses

import pytest

from d810.analyses.control_flow.loops import (
    LoopInfo,
    LoopRef,
    Region,
    loop_sccs,
    strongly_connected_components,
)


def _components_as_sets(succs):
    return {frozenset(c) for c in strongly_connected_components(succs)}


def test_scc_dag_each_node_singleton() -> None:
    # 0 -> 1 -> 2 (acyclic): three singleton components.
    succs = {0: (1,), 1: (2,), 2: ()}
    assert _components_as_sets(succs) == {frozenset({0}), frozenset({1}), frozenset({2})}


def test_scc_full_cycle_is_one_component() -> None:
    succs = {0: (1,), 1: (2,), 2: (0,)}
    assert _components_as_sets(succs) == {frozenset({0, 1, 2})}


def test_scc_nested_cycle_separates_tail() -> None:
    # 0 -> 1 -> 2 -> 1 : {1,2} loop, {0} separate.
    succs = {0: (1,), 1: (2,), 2: (1,)}
    assert _components_as_sets(succs) == {frozenset({0}), frozenset({1, 2})}


def test_scc_components_are_internally_sorted() -> None:
    succs = {2: (0,), 0: (1,), 1: (2,)}
    (comp,) = strongly_connected_components(succs)
    assert comp == (0, 1, 2)


def test_loop_sccs_filters_acyclic() -> None:
    assert loop_sccs({0: (1,), 1: ()}) == ()


def test_loop_sccs_keeps_multiblock_cycle() -> None:
    assert {frozenset(c) for c in loop_sccs({0: (1,), 1: (0,)})} == {frozenset({0, 1})}


def test_loop_sccs_keeps_self_loop_but_not_plain_singleton() -> None:
    assert loop_sccs({0: (0,)}) == ((0,),)  # self-edge => loop
    assert loop_sccs({0: ()}) == ()  # no self-edge => not a loop


def test_region_and_refs_construct_and_freeze() -> None:
    region = Region(blocks=frozenset({1, 2, 3}))
    ref = LoopRef(header=1)
    info = LoopInfo(header=1, blocks=frozenset({1, 2}), back_edges=((2, 1),))
    assert 2 in region.blocks and ref.header == 1
    assert info.back_edges == ((2, 1),)
    with pytest.raises(dataclasses.FrozenInstanceError):
        ref.header = 9  # type: ignore[misc]


def test_loop_info_default_back_edges_empty() -> None:
    assert LoopInfo(header=0, blocks=frozenset({0})).back_edges == ()
