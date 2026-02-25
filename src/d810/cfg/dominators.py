"""Dominator tree computation for microcode CFGs.

Implements the classic iterative dominator algorithm using Python sets
instead of IDA's bitset_t, making it testable without IDA.
"""
from __future__ import annotations

from d810.core import getLogger
from d810.core.typing import Any

logger = getLogger(__name__)


def compute_dominators(mba: Any) -> list[set[int]]:
    """Compute dominator sets for each block in the MBA.

    Args:
        mba: Object with .qty (int) and .get_mblock(i) returning blocks
             with .predset (list[int]).

    Returns:
        List where dom[i] is the set of block serials that dominate block i.
    """
    num_blocks = mba.qty
    if num_blocks == 0:
        return []

    all_blocks = set(range(num_blocks))

    # Initialize: entry dominated only by itself, all others by everything
    dom: list[set[int]] = [all_blocks.copy() for _ in range(num_blocks)]
    dom[0] = {0}

    # Iterate until fixpoint
    changed = True
    while changed:
        changed = False
        for i in range(1, num_blocks):
            blk = mba.get_mblock(i)
            preds = [p for p in blk.predset if 0 <= p < num_blocks]
            if not preds:
                new_dom = {i}
            else:
                new_dom = dom[preds[0]].copy()
                for p in preds[1:]:
                    new_dom &= dom[p]
                new_dom.add(i)
            if new_dom != dom[i]:
                dom[i] = new_dom
                changed = True

    return dom


def dominates(dom: list[set[int]], a: int, b: int) -> bool:
    """Check if block a dominates block b."""
    if b >= len(dom):
        return False
    return a in dom[b]
