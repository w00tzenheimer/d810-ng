"""ConcolicValue reduced-product + reduce() (ticket llr-xvkt, S1 acceptance)."""
from __future__ import annotations

import pytest

from d810.analyses.data_flow.concolic.abstract_evidence import AbstractEvidence
from d810.analyses.data_flow.concolic.values import (
    ConcolicValue,
    PrecisionStatus,
    reduce,
)

W = 8


def test_constructors_set_status_and_keep_symbolic_none() -> None:
    assert ConcolicValue.of(5, W).status is PrecisionStatus.CONCRETE
    assert ConcolicValue.top(W).status is PrecisionStatus.TOP
    assert ConcolicValue.bottom(W).status is PrecisionStatus.BOTTOM
    # S1: symbolic is ALWAYS None (field present so the shape is final)
    for v in (ConcolicValue.of(5, W), ConcolicValue.top(W), ConcolicValue.bottom(W)):
        assert v.symbolic is None


def test_of_reflects_concrete_into_abstract() -> None:
    v = ConcolicValue.of(5, W)
    assert v.concrete == 5
    assert v.abstract.to_const() == 5


def test_reduce_with_concrete_meets_singleton_into_abstract() -> None:
    # raw value whose abstract is wide-open but concrete is known
    raw = ConcolicValue(5, None, AbstractEvidence.top(W), W, PrecisionStatus.TOP)
    r = reduce(raw)
    assert r.abstract.to_const() == 5            # abstract = abstract.meet(singleton)
    assert r.status is PrecisionStatus.CONCRETE


def test_reduce_bottom_abstract_drops_everything() -> None:
    raw = ConcolicValue(None, None, AbstractEvidence.bottom(W), W, PrecisionStatus.TOP)
    r = reduce(raw)
    assert r.status is PrecisionStatus.BOTTOM
    assert r.concrete is None and r.symbolic is None


def test_join_equal_concretes_stays_concrete() -> None:
    j = ConcolicValue.of(5, W).join(ConcolicValue.of(5, W))
    assert j.concrete == 5
    assert j.status is PrecisionStatus.CONCRETE


def test_join_distinct_concretes_drops_to_abstract() -> None:
    j = ConcolicValue.of(1, W).join(ConcolicValue.of(2, W))
    assert j.concrete is None
    assert j.status is PrecisionStatus.ABSTRACT
    # equals the abstract join of the two singletons
    expected = AbstractEvidence.singleton(1, W).join(AbstractEvidence.singleton(2, W))
    assert j.abstract == expected


def test_meet_distinct_concretes_is_bottom() -> None:
    m = ConcolicValue.of(1, W).meet(ConcolicValue.of(2, W))
    assert m.status is PrecisionStatus.BOTTOM
    assert m.concrete is None


def test_meet_top_with_concrete_is_assume() -> None:
    # assume(s == 5) from no information -> the concrete is recovered
    m = ConcolicValue.top(W).meet(ConcolicValue.of(5, W))
    assert m.concrete == 5
    assert m.status is PrecisionStatus.CONCRETE


def test_widen_widens_abstract_and_never_renarrows() -> None:
    a = ConcolicValue.of(1, W)
    b = ConcolicValue.of(200, W)
    w = a.widen(b)
    assert w.concrete is None                    # concretes differ -> dropped
    assert w.abstract.contains(1) and w.abstract.contains(200)
    assert a.abstract.leq(w.abstract) and b.abstract.leq(w.abstract)
    # re-widening does not move further down (stable)
    assert w.leq(w.widen(b))


def test_leq_via_abstract_floor() -> None:
    assert ConcolicValue.of(5, W).leq(ConcolicValue.top(W))
    assert not ConcolicValue.top(W).leq(ConcolicValue.of(5, W))


def test_width_mismatch_rejected() -> None:
    with pytest.raises(ValueError):
        ConcolicValue.of(1, 8).join(ConcolicValue.of(1, 16))
