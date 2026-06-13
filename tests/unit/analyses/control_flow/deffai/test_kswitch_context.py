"""Unit tests for :class:`KContext` + :class:`ContextPolicy` (DEFFAI Step 2).

Asserts the sliding-window extend/truncate, ``is_full``, the k<=0 collapse, and
context-count finiteness.  No IDA.
"""
from __future__ import annotations

import pytest

from d810.analyses.control_flow.deffai.context import ContextPolicy, KContext


def test_empty_context():
    assert KContext.empty() == KContext(())
    assert KContext.empty().depth == 0
    assert KContext.empty().last is None


def test_extend_grows_then_slides_at_k():
    # k=2: window grows to 2, then slides dropping the oldest.
    c = KContext(())
    c = c.extend(1, 2)
    assert c == KContext((1,))
    c = c.extend(2, 2)
    assert c == KContext((1, 2))
    c = c.extend(3, 2)  # full -> slide: drop 1
    assert c == KContext((2, 3))
    c = c.extend(4, 2)
    assert c == KContext((3, 4))


def test_is_full():
    assert not KContext(()).is_full(2)
    assert not KContext((1,)).is_full(2)
    assert KContext((1, 2)).is_full(2)
    assert KContext((1, 2, 3)).is_full(2)


def test_extend_masks_to_u32():
    c = KContext(()).extend(0x1_0000_0001, 4)
    assert c == KContext((1,))  # upper bits dropped by the u32 mask


def test_k_zero_collapses_to_empty():
    # k<=0 is the sound k=0 baseline: every context collapses to ().
    c = KContext((1, 2)).extend(3, 0)
    assert c == KContext(())


def test_extend_k6_three_layer_growth():
    c = KContext(())
    for case in (1, 2, 3, 4, 5, 6):
        c = c.extend(case, 6)
    assert c == KContext((1, 2, 3, 4, 5, 6))
    c = c.extend(7, 6)  # slide
    assert c == KContext((2, 3, 4, 5, 6, 7))


def test_last_and_depth():
    c = KContext((5, 9))
    assert c.last == 9
    assert c.depth == 2


def test_hashable_and_distinct_by_history():
    a = KContext((1, 2))
    b = KContext((1, 2))
    c = KContext((2, 1))
    d = {a: "x"}
    assert d[b] == "x"  # structural equality
    assert a != c  # order matters -> distinct contexts


def test_context_count_bounded_by_states_pow_k():
    # The reachable contexts from a finite state set are bounded by |states|^k.
    states = [10, 20, 30]
    k = 2
    seen = set()
    frontier = {KContext(())}
    for _ in range(10):  # iterate well past saturation
        nxt = set()
        for ctx in frontier:
            for s in states:
                nxt.add(ctx.extend(s, k))
        seen |= nxt
        frontier = nxt
    # full-length windows: |states|^k = 9; plus the shorter transient windows.
    assert len(seen) <= len(states) ** k + len(states) + 1
    full = {c for c in seen if c.depth == k}
    assert len(full) == len(states) ** k


def test_policy_defaults_and_validation():
    p = ContextPolicy()
    assert p.k == 2
    assert p.max_contexts == 4096
    with pytest.raises(ValueError):
        ContextPolicy(k=-1)
    with pytest.raises(ValueError):
        ContextPolicy(max_contexts=0)
