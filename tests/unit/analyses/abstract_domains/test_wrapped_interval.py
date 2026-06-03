"""Tests for the wrapped (modular) interval domain — esp. word-correctness."""
from __future__ import annotations

from d810.analyses.abstract_domains import AbstractDomain, WrappedInterval as WI


def test_satisfies_protocol_and_const():
    assert isinstance(WI.of(3, 8), AbstractDomain)
    assert WI.of(3, 8).to_const() == 3
    assert WI.top(8).to_const() is None


def test_wraparound_add_keeps_zero_THE_pasted_code_bug():
    # The whole point: [254,255] + [1,1] over u8 must include 0 (wrap), not drop it.
    res = WI(8, 254, 255).add(WI.of(1, 8))
    assert res.contains(0)        # pasted float-interval clamped this away
    assert res.contains(255)
    assert not res.contains(128)  # but it is NOT all of u8


def test_sub_wraps():
    # [0,0] - [1,1] over u8 = {255}
    res = WI.of(0, 8).sub(WI.of(1, 8))
    assert res.to_const() == 255


def test_contains_wrapping_arc():
    arc = WI(4, 14, 2)            # {14,15,0,1,2} over u4
    assert arc.contains(15) and arc.contains(0) and arc.contains(2)
    assert not arc.contains(7)
    assert arc.cardinality() == 5


def test_leq_and_join_upper_bound():
    a, b = WI.of(2, 8), WI.of(5, 8)
    j = a.join(b)
    assert a.leq(j) and b.leq(j)
    assert j.contains(2) and j.contains(5)
    # tightest non-wrapping hull is [2,5]
    assert j.cardinality() == 4


def test_join_picks_smaller_wrap():
    # joining {0} and {15} over u4 should wrap [15,0] (size 2), not [0,15] (size 16)
    j = WI.of(0, 4).join(WI.of(15, 4))
    assert j.cardinality() == 2
    assert j.contains(0) and j.contains(15) and not j.contains(7)


def test_meet_disjoint_is_bottom():
    assert WI.of(1, 8).meet(WI.of(2, 8)).is_bottom()


def test_meet_containment():
    big = WI(8, 0, 100)
    small = WI(8, 10, 20)
    assert small.leq(big)
    assert big.meet(small).leq(small) and small.leq(big.meet(small))


def test_meet_is_sound_overapprox_never_drops_feasible():
    # overlapping arcs: meet must ⊇ the true intersection (soundness for assume)
    a = WI(8, 0, 50)
    b = WI(8, 40, 200)
    m = a.meet(b)
    for v in (40, 45, 50):       # the true intersection {40..50}
        assert m.contains(v)


def test_widen_terminates_to_top_on_growth():
    a = WI.of(0, 8)
    b = WI(8, 0, 1)
    w = a.widen(b)
    assert w.is_top()            # grew -> jump to ⊤ (terminating)
    assert a.widen(a) == a       # stable -> no change
