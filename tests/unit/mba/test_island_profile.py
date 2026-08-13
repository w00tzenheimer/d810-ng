from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from d810.mba.island_profile import (
    IslandBlocker,
    MbaIslandClass,
    profile_typed_term,
)
from d810.mba.typed_term import TypedBvTerm


def _leaf(name: str) -> TypedBvTerm:
    return TypedBvTerm(operation=None, width=32, leaf_key=("register", name))


def _constant(value: int) -> TypedBvTerm:
    return TypedBvTerm(operation=None, width=32, value=value)


def _node(
    operation: str,
    left: TypedBvTerm,
    right: TypedBvTerm | None = None,
) -> TypedBvTerm:
    children = (left,) if right is None else (left, right)
    return TypedBvTerm(operation=operation, width=32, children=children)


def test_profile_counts_operations_and_repeated_leaf_identity():
    x = _leaf("x")
    term = _node("add", _node("and", x, _leaf("y")), x)

    profile = profile_typed_term(term)

    assert profile.width_bits == 32
    assert profile.operator_count == 2
    assert profile.total_node_count == 5
    assert profile.distinct_leaf_count == 2
    assert profile.constant_count == 0
    assert profile.operations == (("add", 1), ("and", 1))
    assert profile.has_boolean is True
    assert profile.has_arithmetic is True
    assert profile.nonlinear_product_count == 0
    assert profile.island_class is MbaIslandClass.LINEAR_MBA


def test_constant_scaling_is_linear_but_symbolic_product_is_nonlinear():
    linear = _node("mul", _constant(7), _leaf("x"))
    nonlinear = _node("mul", _leaf("x"), _node("add", _leaf("y"), _constant(1)))

    assert profile_typed_term(linear).nonlinear_product_count == 0
    assert profile_typed_term(linear).island_class is MbaIslandClass.NOT_MBA
    assert profile_typed_term(nonlinear).nonlinear_product_count == 1
    assert profile_typed_term(nonlinear).island_class is MbaIslandClass.NONLINEAR_MBA


def test_blockers_are_immutable_sorted_and_force_unsupported():
    profile = profile_typed_term(
        _node("and", _leaf("x"), _leaf("y")),
        blockers=(IslandBlocker.CALL, IslandBlocker.CAST, IslandBlocker.CALL),
    )

    assert profile.blockers == (IslandBlocker.CALL, IslandBlocker.CAST)
    assert profile.island_class is MbaIslandClass.UNSUPPORTED
    with pytest.raises(FrozenInstanceError):
        profile.width_bits = 64  # type: ignore[misc]


def test_profiles_have_a_stable_fingerprint_for_equivalent_terms():
    first = _node("or", _leaf("x"), _leaf("y"))
    second = _node("or", _leaf("x"), _leaf("y"))

    assert profile_typed_term(first).fingerprint == profile_typed_term(second).fingerprint
