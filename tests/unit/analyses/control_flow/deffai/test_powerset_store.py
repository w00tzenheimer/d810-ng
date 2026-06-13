"""Unit tests for :class:`PowersetStore` (DEFFAI Step 1).

Asserts the multi-cell store lattice: union join (``{3} ⊔ {4} = {3,4}``), cell cap
-> ⊤, ⊥ identity, the ``leq`` order, idempotent join, and meet/widen.  No IDA.
"""
from __future__ import annotations

import pytest

from d810.analyses.control_flow.state_transition_domain import StateValue
from d810.analyses.data_flow.concolic.refs import LocationRef

from d810.analyses.control_flow.deffai.powerset_store import PowersetStore

S = LocationRef.stack(0x10, 8)
T = LocationRef.stack(0x20, 8)
R = LocationRef.reg(5, 8)


def test_bottom_is_empty_store():
    b = PowersetStore.bottom()
    assert b.is_bottom()
    assert b.cell_refs() == frozenset()
    assert b.get(S).is_bottom


def test_get_absent_cell_is_bottom():
    store = PowersetStore.singleton(S, 3)
    assert store.get(T).is_bottom
    assert store.get(S) == StateValue.of(3)


def test_set_is_functional_and_immutable():
    a = PowersetStore.singleton(S, 3)
    b = a.set(T, StateValue.of(7))
    assert a.get(T).is_bottom  # original unchanged
    assert b.get(S) == StateValue.of(3)
    assert b.get(T) == StateValue.of(7)


def test_set_bottom_removes_cell():
    a = PowersetStore.singleton(S, 3)
    b = a.set(S, StateValue.bottom())
    assert b.is_bottom()
    assert not b.has(S)


def test_join_is_per_cell_union():
    a = PowersetStore.singleton(S, 3)
    b = PowersetStore.singleton(S, 4)
    joined = a.join(b)
    assert joined.get(S) == StateValue.of_many([3, 4])


def test_join_keeps_disjoint_cells():
    a = PowersetStore.singleton(S, 3)
    b = PowersetStore.singleton(T, 7)
    joined = a.join(b)
    assert joined.get(S) == StateValue.of(3)
    assert joined.get(T) == StateValue.of(7)


def test_join_with_bottom_is_identity():
    a = PowersetStore.singleton(S, 3)
    assert a.join(PowersetStore.bottom()) == a
    assert PowersetStore.bottom().join(a) == a


def test_join_is_idempotent():
    a = PowersetStore.of({S: StateValue.of_many([3, 4]), T: StateValue.of(7)})
    assert a.join(a) == a


def test_join_saturates_cell_to_top_past_cap():
    # Per-cell StateValue.join caps to ⊤ past MAX_CONSTS (256).
    big = StateValue.of_many(range(StateValue.MAX_CONSTS))
    a = PowersetStore.of({S: big})
    b = PowersetStore.of({S: StateValue.of(10_000)})
    joined = a.join(b)
    assert joined.get(S).is_top


def test_meet_is_per_cell_intersection_on_shared_cells():
    a = PowersetStore.of({S: StateValue.of_many([3, 4, 5])})
    b = PowersetStore.of({S: StateValue.of_many([4, 5, 6])})
    met = a.meet(b)
    assert met.get(S) == StateValue.of_many([4, 5])


def test_meet_drops_unshared_cells():
    a = PowersetStore.of({S: StateValue.of(3), T: StateValue.of(7)})
    b = PowersetStore.of({S: StateValue.of(3)})
    met = a.meet(b)
    assert met.get(S) == StateValue.of(3)
    assert met.get(T).is_bottom  # T absent in b -> bottom -> dropped


def test_widen_equals_join_finite_height():
    a = PowersetStore.singleton(S, 3)
    b = PowersetStore.singleton(S, 4)
    assert a.widen(b) == a.join(b)


def test_leq_order():
    small = PowersetStore.singleton(S, 3)
    big = PowersetStore.of({S: StateValue.of_many([3, 4])})
    assert small.leq(big)
    assert not big.leq(small)


def test_leq_bottom_below_all():
    b = PowersetStore.bottom()
    a = PowersetStore.singleton(S, 3)
    assert b.leq(a)
    assert not a.leq(b)


def test_leq_top_cell_above_all():
    top_cell = PowersetStore.of({S: StateValue.top()})
    a = PowersetStore.of({S: StateValue.of_many([3, 4])})
    assert a.leq(top_cell)
    assert not top_cell.leq(a)


def test_canonicalization_equality_drops_bottom_cells():
    # Explicit bottom cell vs absent cell compare equal.
    a = PowersetStore.of({S: StateValue.of(3), T: StateValue.bottom()})
    b = PowersetStore.of({S: StateValue.of(3)})
    assert a == b
    assert hash(a) == hash(b)


def test_max_cells_cap_refuses_new_cells():
    store = PowersetStore.bottom()
    # Fill exactly to the cap with distinct cells.
    for i in range(PowersetStore.MAX_CELLS):
        store = store.set(LocationRef.stack(i * 8, 8), StateValue.of(i))
    assert len(store.cell_refs()) == PowersetStore.MAX_CELLS
    # One more new cell is refused (store unchanged).
    overflow = store.set(LocationRef.stack(10_000_000, 8), StateValue.of(1))
    assert overflow == store
    # But updating an EXISTING cell still applies.
    existing = LocationRef.stack(0, 8)
    updated = store.set(existing, StateValue.of(999))
    assert updated.get(existing) == StateValue.of(999)


def test_hashable_as_dict_key():
    a = PowersetStore.singleton(S, 3)
    b = PowersetStore.singleton(S, 3)
    d = {a: "x"}
    assert d[b] == "x"  # structural equality -> same key


def test_singleton_and_of_constructors():
    assert PowersetStore.singleton(S, 5).get(S) == StateValue.of(5)
    assert PowersetStore.of({R: StateValue.of(9)}).get(R) == StateValue.of(9)
