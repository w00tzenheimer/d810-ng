"""S0 unit tests: AbstractValue / RouteResult ADTs + ``.project()`` projections.

Pure-type tests (no IDA): the value-side seam (``AbstractValue``), the
router-side seam (``RouteResult``), and the projection of each lattice element
(``KnownBits`` / ``WrappedInterval`` / ``StateValue``) into ``AbstractValue``.
"""
from __future__ import annotations

from d810.analyses.abstract_domains import KnownBits, WrappedInterval
from d810.analyses.control_flow.state_transition_domain import StateValue
from d810.analyses.data_flow import (
    AbstractValue,
    Block,
    Const,
    EntersDispatcher,
    Guarded,
    OneOf,
    RouteOneOf,
    RouteResult,
    TOP,
    Top,
    Unknown,
)
from d810.ir.lattice import Const as LatticeConst


# --- Const reuse (no third Const) ------------------------------------------


def test_const_variant_is_ir_lattice_const():
    # S0 contract: the ``Const`` ADT variant IS ir.lattice.Const, not a new type.
    assert Const is LatticeConst
    c = Const(0x79F598F7, 4)
    assert c.value == 0x79F598F7 and c.size == 4


# --- AbstractValue shapes ---------------------------------------------------


def test_abstractvalue_union_members_are_distinct():
    members = {Const, Guarded, OneOf, Top}
    assert len(members) == 4
    # TOP is the singleton ⊤ instance.
    assert isinstance(TOP, Top)
    assert AbstractValue is not None  # union alias is importable


def test_oneof_of_masks_and_single():
    o = OneOf.of([0x10, 0x20, 0x10])
    assert o.values == frozenset({0x10, 0x20})
    assert o.single() is None
    assert OneOf.of([0x55]).single() == 0x55
    assert OneOf.of([]).single() is None


def test_guarded_carries_choices():
    g = Guarded((("g0", Const(1, 4)), ("g1", OneOf.of([2, 3]))))
    assert len(g.choices) == 2
    assert g.choices[0][1] == Const(1, 4)


# --- RouteResult shapes (EA carried alongside serial) ----------------------


def test_block_repr_carries_ea():
    assert repr(Block(52, 0x18001450D)) == "Block(52@0x18001450d)"
    assert repr(Block(52)) == "Block(52)"


def test_enters_dispatcher_repr_carries_ea():
    model = object()
    rr = EntersDispatcher(model, entry_serial=2, entry_ea=0x180001000)
    assert "2@0x180001000" in repr(rr)
    assert rr.model is model


def test_route_oneof_targets_are_blocks_with_ea():
    rr = RouteOneOf((Block(1, 0x1000), Block(2, 0x2000)))
    assert all(isinstance(t, Block) and t.ea is not None for t in rr.targets)


def test_unknown_surfaces_reason():
    u = Unknown("state_not_in_dispatcher_map")
    assert u.reason == "state_not_in_dispatcher_map"
    assert RouteResult is not None


# --- KnownBits.project() ----------------------------------------------------


def test_known_bits_project_const_when_fully_known():
    p = KnownBits.of(0xA5, 8).project()
    assert p == Const(0xA5, 1)  # 8 bits -> 1 byte


def test_known_bits_project_top_when_unknown_or_partial():
    assert KnownBits.top(32).project() is TOP
    # partially known -> still TOP (no finite powerset for known-bits)
    partial = KnownBits(8, zero=0b0000_0001, one=0b0000_0000)
    assert partial.project() is TOP


def test_known_bits_project_width_to_byte_size():
    assert KnownBits.of(7, 32).project() == Const(7, 4)


# --- WrappedInterval.project() ---------------------------------------------


def test_wrapped_interval_project_singleton_is_const():
    p = WrappedInterval.of(0x79F598F7, 32).project()
    assert p == Const(0x79F598F7, 4)


def test_wrapped_interval_project_bounded_is_oneof():
    wi = WrappedInterval(8, lo=3, hi=6, kind="range")  # {3,4,5,6}
    p = wi.project()
    assert isinstance(p, OneOf)
    assert p.values == frozenset({3, 4, 5, 6})


def test_wrapped_interval_project_top_when_unbounded():
    assert WrappedInterval.top(32).project() is TOP
    # a wide arc beyond the enumeration cap projects to TOP, not a huge OneOf.
    wide = WrappedInterval(32, lo=0, hi=0x10000, kind="range")
    assert wide.project() is TOP


# --- StateValue.project() <-> OneOf.from_state_value -----------------------


def test_state_value_project_singleton_is_const():
    assert StateValue.of(0x79F598F7).project() == Const(0x79F598F7, 8)


def test_state_value_project_set_is_oneof():
    p = StateValue.of_many([0x10, 0x20]).project()
    assert isinstance(p, OneOf)
    assert p.values == frozenset({0x10, 0x20})


def test_state_value_project_top():
    assert StateValue.top().project() is TOP


def test_oneof_from_state_value_unifies():
    sv = StateValue.of_many([0x10, 0x20])
    lifted = OneOf.from_state_value(sv)
    assert isinstance(lifted, OneOf)
    assert lifted.values == frozenset({0x10, 0x20})
    # ⊤ StateValue lifts to TOP
    assert OneOf.from_state_value(StateValue.top()) is TOP
    # round-trip: project then from_state_value of the same powerset agree
    assert OneOf.from_state_value(sv) == StateValue.of_many([0x10, 0x20]).project()
