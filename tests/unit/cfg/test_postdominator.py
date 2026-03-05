"""Tests for postdominator tree computation."""
from __future__ import annotations

import pytest

from d810.cfg.postdominator import (
    PostdomTree,
    compute_postdom_tree,
    is_postdominated_by_any_exit,
)


class TestPostdomTree:
    def test_linear_chain(self):
        # 0 -> 1 -> 2 -> 3(exit)
        succs = {0: [1], 1: [2], 2: [3], 3: []}
        tree = compute_postdom_tree(succs, entry=0, exits=frozenset({3}))
        assert tree.postdominates(3, 0)
        assert tree.postdominates(3, 1)
        assert tree.postdominates(2, 1)

    def test_diamond(self):
        # 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3, 3(exit)
        succs = {0: [1, 2], 1: [3], 2: [3], 3: []}
        tree = compute_postdom_tree(succs, entry=0, exits=frozenset({3}))
        assert tree.postdominates(3, 0)
        assert not tree.postdominates(1, 0)
        assert not tree.postdominates(2, 0)

    def test_multiple_exits(self):
        # 0 -> 1, 0 -> 2, 1 -> 3(exit), 2 -> 4(exit)
        succs = {0: [1, 2], 1: [3], 2: [4], 3: [], 4: []}
        tree = compute_postdom_tree(succs, entry=0, exits=frozenset({3, 4}))
        assert not tree.postdominates(3, 0)  # neither exit postdominates entry alone
        assert not tree.postdominates(4, 0)

    def test_loop(self):
        # 0 -> 1, 1 -> 2, 2 -> 1 (back edge), 2 -> 3(exit)
        succs = {0: [1], 1: [2], 2: [1, 3], 3: []}
        tree = compute_postdom_tree(succs, entry=0, exits=frozenset({3}))
        assert tree.postdominates(3, 0)

    def test_postdominators_of(self):
        succs = {0: [1], 1: [2], 2: [3], 3: []}
        tree = compute_postdom_tree(succs, entry=0, exits=frozenset({3}))
        pdoms = tree.postdominators_of(1)
        assert 1 in pdoms  # self
        assert 2 in pdoms
        assert 3 in pdoms

    def test_self_postdomination(self):
        succs = {0: [1], 1: []}
        tree = compute_postdom_tree(succs, entry=0, exits=frozenset({1}))
        assert tree.postdominates(1, 1)
        assert tree.postdominates(0, 0)

    def test_single_node_exit(self):
        succs = {0: []}
        tree = compute_postdom_tree(succs, entry=0, exits=frozenset({0}))
        assert tree.postdominates(0, 0)

    def test_exit_node_idom_is_none(self):
        succs = {0: [1], 1: []}
        tree = compute_postdom_tree(succs, entry=0, exits=frozenset({1}))
        # Exit node has no postdominator (idom is None)
        assert tree.idom.get(1) is None

    def test_is_postdominated_by_any_exit_true(self):
        succs = {0: [1], 1: [2], 2: [3], 3: []}
        tree = compute_postdom_tree(succs, entry=0, exits=frozenset({3}))
        assert is_postdominated_by_any_exit(0, frozenset({3}), tree)

    def test_is_postdominated_by_any_exit_false(self):
        # 0 -> 1(exit), 0 -> 2(exit) — neither exit postdominates 0
        succs = {0: [1, 2], 1: [], 2: []}
        tree = compute_postdom_tree(succs, entry=0, exits=frozenset({1, 2}))
        assert not is_postdominated_by_any_exit(0, frozenset({1}), tree)
        assert not is_postdominated_by_any_exit(0, frozenset({2}), tree)
