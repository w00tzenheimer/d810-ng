"""AbstractEvidence = reduced product KnownBits x WrappedInterval (ticket llr-xvkt)."""
from __future__ import annotations

from d810.analyses.abstract_domains.known_bits import KnownBits
from d810.analyses.abstract_domains.wrapped_interval import WrappedInterval
from d810.analyses.data_flow.concolic.abstract_evidence import AbstractEvidence

W = 8


def test_constructors_and_queries() -> None:
    assert AbstractEvidence.top(W).is_top()
    assert AbstractEvidence.bottom(W).is_bottom()
    s = AbstractEvidence.singleton(5, W)
    assert s.to_const() == 5
    assert not s.is_top() and not s.is_bottom()


def test_contains_uses_both_components() -> None:
    # join of {2} and {4}: bits = {0,2,4,6} (bit0 known-0), interval = [2,4].
    # 3 is in the interval but bits reject it (odd); 6 satisfies the bits but the
    # interval rejects it (>4) -> contains must consult BOTH components.
    e = AbstractEvidence.singleton(2, W).join(AbstractEvidence.singleton(4, W))
    assert e.contains(2) and e.contains(4)
    assert not e.contains(3)      # bits reject: 3 is odd, bit0 is known-0
    assert not e.contains(6)      # interval rejects: 6 > 4 (bits alone allow it)
    assert not e.contains(8)      # outside both


def test_meet_of_distinct_singletons_is_bottom() -> None:
    m = AbstractEvidence.singleton(1, W).meet(AbstractEvidence.singleton(2, W))
    assert m.is_bottom()


def test_join_of_distinct_singletons_is_not_constant() -> None:
    j = AbstractEvidence.singleton(1, W).join(AbstractEvidence.singleton(2, W))
    assert j.to_const() is None
    assert not j.is_bottom() and not j.is_top()
    assert AbstractEvidence.singleton(1, W).leq(j)   # 1 <= join
    assert AbstractEvidence.singleton(2, W).leq(j)   # 2 <= join


def test_leq_order() -> None:
    assert AbstractEvidence.singleton(5, W).leq(AbstractEvidence.top(W))
    assert not AbstractEvidence.top(W).leq(AbstractEvidence.singleton(5, W))


def test_reduction_propagates_known_bits_into_interval() -> None:
    # bits prove the constant, interval is wide-open -> reduce tightens interval
    raw = AbstractEvidence(W, KnownBits.of(5, W), WrappedInterval.top(W))
    reduced = raw._reduce()
    assert reduced.interval.to_const() == 5


def test_reduction_propagates_interval_into_known_bits() -> None:
    raw = AbstractEvidence(W, KnownBits.top(W), WrappedInterval.of(7, W))
    reduced = raw._reduce()
    assert reduced.bits.to_const() == 7


def test_reduction_canonicalises_bottom() -> None:
    # one component infeasible -> whole element is bottom (both components)
    raw = AbstractEvidence(W, KnownBits.bottom(W), WrappedInterval.of(3, W))
    reduced = raw._reduce()
    assert reduced.is_bottom()
    assert reduced.bits.is_bottom() and reduced.interval.is_bottom()


def test_widen_never_renarrows() -> None:
    a = AbstractEvidence.singleton(1, W)
    b = AbstractEvidence.singleton(200, W)
    w = a.widen(b)
    assert a.leq(w) and b.leq(w)
    # stable: widening again does not move it further down
    assert w.leq(w.widen(b))
