"""Unit tests for d810.cfg.dominators."""
from __future__ import annotations

import pytest

from d810.cfg.dominators import compute_dominators, dominates


class MockBlock:
    def __init__(self, predset: list[int]) -> None:
        self.predset = predset


class MockMba:
    def __init__(self, blocks: list[list[int]]) -> None:
        self._blocks = [MockBlock(preds) for preds in blocks]
        self.qty = len(blocks)

    def get_mblock(self, i: int) -> MockBlock:
        return self._blocks[i]


class TestComputeDominators:
    def test_single_block(self) -> None:
        mba = MockMba([[]])
        dom = compute_dominators(mba)
        assert len(dom) == 1
        assert dom[0] == {0}

    def test_empty_mba(self) -> None:
        mba = MockMba([])
        mba.qty = 0
        dom = compute_dominators(mba)
        assert dom == []

    def test_linear_chain(self) -> None:
        # 0 -> 1 -> 2 -> 3
        mba = MockMba([[], [0], [1], [2]])
        dom = compute_dominators(mba)
        assert dom[0] == {0}
        assert dom[1] == {0, 1}
        assert dom[2] == {0, 1, 2}
        assert dom[3] == {0, 1, 2, 3}

    def test_diamond_cfg(self) -> None:
        # 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3
        mba = MockMba([[], [0], [0], [1, 2]])
        dom = compute_dominators(mba)
        assert dom[0] == {0}
        assert dom[1] == {0, 1}
        assert dom[2] == {0, 2}
        # block 3 is dominated only by 0 and itself (1 and 2 don't both dominate)
        assert dom[3] == {0, 3}

    def test_diamond_dominates_entry_dominates_all(self) -> None:
        # 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3
        mba = MockMba([[], [0], [0], [1, 2]])
        dom = compute_dominators(mba)
        assert dominates(dom, 0, 0)
        assert dominates(dom, 0, 1)
        assert dominates(dom, 0, 2)
        assert dominates(dom, 0, 3)

    def test_diamond_branch_does_not_dominate_exit(self) -> None:
        # 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3
        mba = MockMba([[], [0], [0], [1, 2]])
        dom = compute_dominators(mba)
        assert not dominates(dom, 1, 3)
        assert not dominates(dom, 2, 3)

    def test_dominates_out_of_range_returns_false(self) -> None:
        mba = MockMba([[], [0]])
        dom = compute_dominators(mba)
        assert not dominates(dom, 0, 99)

    def test_block_dominates_itself(self) -> None:
        mba = MockMba([[], [0], [1]])
        dom = compute_dominators(mba)
        for i in range(3):
            assert dominates(dom, i, i)
