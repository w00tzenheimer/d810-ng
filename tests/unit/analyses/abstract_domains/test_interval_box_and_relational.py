"""Tests for the non-relational IntervalBox + the RelationalDomain seam."""
from __future__ import annotations

from d810.analyses.abstract_domains import (
    AbstractDomain,
    IntervalBox,
    LinearConstraint,
    NullRelational,
    RelationalDomain,
    Satisfiability,
    WrappedInterval as WI,
)


def test_box_protocol_and_pointwise():
    box = IntervalBox.top(8).assign("x", WI.of(3, 8)).assign("y", WI.of(7, 8))
    assert isinstance(box, AbstractDomain)
    assert box.get("x").to_const() == 3
    assert box.get("z").is_top()          # absent var = ⊤


def test_box_join_is_pointwise_upper_bound():
    a = IntervalBox.top(8).assign("x", WI.of(1, 8))
    b = IntervalBox.top(8).assign("x", WI.of(2, 8))
    j = a.join(b)
    assert a.leq(j) and b.leq(j)
    assert j.get("x").contains(1) and j.get("x").contains(2)


def test_box_meet_bottom_on_conflicting_var():
    a = IntervalBox.top(8).assign("x", WI.of(1, 8))
    b = IntervalBox.top(8).assign("x", WI.of(2, 8))
    assert a.meet(b).is_bottom()          # x can't be both 1 and 2


def test_null_relational_is_sound_noop():
    r = NullRelational()
    assert isinstance(r, RelationalDomain)
    c = LinearConstraint(coeffs=(("x", 1), ("y", -1)), rhs=0)
    # refutes nothing, asserts nothing -> always UNKNOWN, stays ⊤
    assert r.classify(c) is Satisfiability.UNKNOWN
    assert r.assume(c).is_top()
