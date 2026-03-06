"""Tests for graph-map dominator tree computation."""
from __future__ import annotations

from d810.cfg.dominator import compute_dom_tree
from d810.cfg.postdominator import compute_postdom_tree


class TestDominatorTree:
    def test_linear_chain(self) -> None:
        succs = {0: [1], 1: [2], 2: [3], 3: []}
        tree = compute_dom_tree(succs, entry=0)

        assert tree.dominates(0, 3)
        assert tree.dominates(2, 3)
        assert tree.dominators_of(2) == frozenset({0, 1, 2})
        assert tree.idom[0] is None
        assert tree.idom[3] == 2

    def test_diamond(self) -> None:
        succs = {0: [1, 2], 1: [3], 2: [3], 3: []}
        tree = compute_dom_tree(succs, entry=0)

        assert tree.dominates(0, 3)
        assert not tree.dominates(1, 3)
        assert not tree.dominates(2, 3)
        assert tree.idom[3] == 0

    def test_unreachable_nodes_are_excluded_from_tree(self) -> None:
        succs = {0: [1], 1: [], 2: [3], 3: []}
        tree = compute_dom_tree(succs, entry=0)

        assert 2 not in tree.idom
        assert 3 not in tree.idom
        assert tree.dominators_of(2) == frozenset({2})


class TestDominanceFixtures:
    def test_flattened_fixture_matches_expected_dom_and_postdom(self) -> None:
        # entry -> preheader -> dispatcher -> handlers -> shared return
        succs = {
            0: [1],
            1: [2],
            2: [3, 4],
            3: [5],
            4: [5],
            5: [6],
            6: [],
        }
        dom_tree = compute_dom_tree(succs, entry=0)
        pdom_tree = compute_postdom_tree(succs, entry=0, exits=frozenset({6}))

        assert dom_tree.dominates(2, 5)
        assert not dom_tree.dominates(3, 5)
        assert pdom_tree.postdominates(5, 2)
        assert pdom_tree.postdominates(6, 5)

    def test_reconstructed_fixture_matches_expected_dom_and_postdom(self) -> None:
        # dispatcher removed; handlers branch directly to shared return
        succs = {
            0: [3, 4],
            3: [6],
            4: [6],
            6: [],
        }
        dom_tree = compute_dom_tree(succs, entry=0)
        pdom_tree = compute_postdom_tree(succs, entry=0, exits=frozenset({6}))

        assert dom_tree.dominates(0, 6)
        assert not dom_tree.dominates(3, 6)
        assert not dom_tree.dominates(4, 6)
        assert pdom_tree.postdominates(6, 0)
