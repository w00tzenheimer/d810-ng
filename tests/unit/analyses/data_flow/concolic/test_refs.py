"""LocationRef / ValueRef portable references (ticket llr-xvkt)."""
from __future__ import annotations

from d810.analyses.data_flow.concolic.refs import (
    LocationKind,
    LocationRef,
    ValueRef,
)


def test_stack_and_reg_factories() -> None:
    s = LocationRef.stack(0x7F0, 8)
    r = LocationRef.reg(3, 4)
    assert s.kind is LocationKind.STACK and s.key == 0x7F0 and s.width == 8
    assert r.kind is LocationKind.REGISTER and r.key == 3 and r.width == 4


def test_structural_equality_and_hashable() -> None:
    assert LocationRef.stack(0x10, 8) == LocationRef.stack(0x10, 8)
    assert LocationRef.stack(0x10, 8) != LocationRef.reg(0x10, 8)   # kind differs
    assert LocationRef.stack(0x10, 8) != LocationRef.stack(0x10, 4)  # width differs
    # usable as a dict/set key (the store keys on it)
    keyed = {LocationRef.stack(0x10, 8): 1}
    assert keyed[LocationRef.stack(0x10, 8)] == 1


def test_repr_is_readable() -> None:
    assert repr(LocationRef.stack(0x7F0, 8)) == "stack[0x7f0]:8"
    assert repr(LocationRef.reg(3, 4)) == "reg(3):4"


def test_value_ref_stub_defaults() -> None:
    loc = LocationRef.stack(0x10, 8)
    vr = ValueRef(loc)
    assert vr.location is loc
    assert vr.def_site is None
    assert ValueRef(loc, 42).def_site == 42
