"""ConcolicStore: LocationRef -> ConcolicValue, missing key => TOP (ticket llr-xvkt)."""
from __future__ import annotations

from d810.analyses.data_flow.concolic.refs import LocationRef
from d810.analyses.data_flow.concolic.store import ConcolicStore
from d810.analyses.data_flow.concolic.values import ConcolicValue, PrecisionStatus

W = 8
LOC_A = LocationRef.stack(0x7F0, W)
LOC_B = LocationRef.reg(0, W)


def test_missing_cell_is_top() -> None:
    v = ConcolicStore().eval(LOC_A)
    assert v.status is PrecisionStatus.TOP


def test_assign_then_eval() -> None:
    s = ConcolicStore().assign(LOC_A, ConcolicValue.of(5, W))
    assert s.eval(LOC_A).concrete == 5


def test_assign_is_copy_on_write() -> None:
    base = ConcolicStore()
    s = base.assign(LOC_A, ConcolicValue.of(5, W))
    assert base.eval(LOC_A).status is PrecisionStatus.TOP   # original untouched
    assert s.eval(LOC_A).concrete == 5


def test_is_concrete_enough() -> None:
    s = ConcolicStore().assign(LOC_A, ConcolicValue.of(5, W))
    assert s.is_concrete_enough([LOC_A])
    assert not s.is_concrete_enough([LOC_B])           # unset cell -> TOP
    assert not s.is_concrete_enough([LOC_A, LOC_B])


def test_join_same_concrete_stays_concrete() -> None:
    s1 = ConcolicStore().assign(LOC_A, ConcolicValue.of(5, W))
    s2 = ConcolicStore().assign(LOC_A, ConcolicValue.of(5, W))
    assert s1.join(s2).eval(LOC_A).concrete == 5


def test_join_distinct_concrete_drops_to_abstract() -> None:
    s1 = ConcolicStore().assign(LOC_A, ConcolicValue.of(5, W))
    s2 = ConcolicStore().assign(LOC_A, ConcolicValue.of(6, W))
    merged = s1.join(s2).eval(LOC_A)
    assert merged.status is PrecisionStatus.ABSTRACT
    assert merged.concrete is None


def test_join_key_on_only_one_side_is_top() -> None:
    s1 = ConcolicStore().assign(LOC_A, ConcolicValue.of(5, W))
    s2 = ConcolicStore().assign(LOC_B, ConcolicValue.of(9, W))
    merged = s1.join(s2)
    assert merged.eval(LOC_A).status is PrecisionStatus.TOP   # only in s1
    assert merged.eval(LOC_B).status is PrecisionStatus.TOP   # only in s2
    assert not merged.is_concrete_enough([LOC_A])


def test_widen_key_on_only_one_side_is_top() -> None:
    s1 = ConcolicStore().assign(LOC_A, ConcolicValue.of(5, W))
    s2 = ConcolicStore().assign(LOC_B, ConcolicValue.of(9, W))
    merged = s1.widen(s2)
    assert merged.eval(LOC_A).status is PrecisionStatus.TOP
    assert merged.eval(LOC_B).status is PrecisionStatus.TOP
