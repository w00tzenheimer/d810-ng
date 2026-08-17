from __future__ import annotations

from dataclasses import fields

import pytest

from d810.mba.semantic_canonicalization import canonicalize_mba_term
from d810.mba.typed_term import (
    FIXED_SHIFT_OPERATIONS,
    TypedBvTerm,
    canonicalize_ac_term,
    fixed_shift_term,
    term_cost,
    term_fingerprint,
)


def _leaf(name: str, *, width: int = 32) -> TypedBvTerm:
    return TypedBvTerm(operation=None, width=width, leaf_key=("register", name))


def _constant(value: int, *, width: int = 32) -> TypedBvTerm:
    return TypedBvTerm(operation=None, width=width, value=value)


def _node(
    operation: str,
    left: TypedBvTerm,
    right: TypedBvTerm | None = None,
) -> TypedBvTerm:
    children = (left,) if right is None else (left, right)
    return TypedBvTerm(operation=operation, width=left.width, children=children)


def test_constants_mask_to_their_fixed_width_and_fingerprint_stably():
    masked = _constant(0x1FF, width=8)
    equivalent = _constant(0xFF, width=8)

    assert masked.value == 0xFF
    assert term_fingerprint(masked) == term_fingerprint(equivalent)
    assert term_fingerprint(masked) == term_fingerprint(masked)


def test_same_width_ac_terms_canonicalize_across_order_and_association():
    a = _leaf("a")
    b = _leaf("b")
    c = _leaf("c")

    left_associated = _node("add", _node("add", a, b), c)
    right_associated = _node("add", a, _node("add", c, b))

    assert canonicalize_ac_term(left_associated) == canonicalize_ac_term(
        right_associated
    )


def test_leaf_identity_participates_in_the_persisted_fingerprint():
    register = _leaf("same")
    stack = TypedBvTerm(operation=None, width=32, leaf_key=("stack", "same"))

    assert term_fingerprint(register) != term_fingerprint(stack)


def test_term_cost_counts_operator_and_total_nodes():
    term = _node("add", _leaf("x"), _constant(1))

    assert term_cost(term) == (1, 3)


def test_mixed_width_children_fail_closed():
    with pytest.raises(ValueError, match="same width"):
        TypedBvTerm(
            operation="add",
            width=32,
            children=(_leaf("wide", width=32), _leaf("narrow", width=16)),
        )


def test_typed_term_cost_and_fingerprint_are_suitable_for_canonical_views():
    term = _node("add", _leaf("x"), _constant(-2))
    view = canonicalize_mba_term(term)

    assert term_cost(term) == (1, 3)
    assert view.raw_term is term
    assert view.raw_cost == term_cost(term)
    assert view.canonical_term == canonicalize_ac_term(term)
    assert view.canonical_cost == term_cost(view.canonical_term)
    assert term_fingerprint(view.canonical_term)


def test_fixed_shift_metadata_is_last_and_requires_one_same_width_child():
    assert fields(TypedBvTerm)[-1].name == "shift_count"
    x = _leaf("x", width=32)
    term = fixed_shift_term("shl", 32, x, 7)

    assert FIXED_SHIFT_OPERATIONS == frozenset({"shl", "lshr", "rol", "ror"})
    assert term.children == (x,)
    assert term.shift_count == 7
    assert term_cost(term) == (1, 2)

    with pytest.raises(ValueError, match="same width"):
        fixed_shift_term("shl", 32, _leaf("narrow", width=16), 7)
    with pytest.raises(ValueError, match="exactly one child"):
        TypedBvTerm(
            "shl",
            32,
            children=(x, _leaf("y", width=32)),
            shift_count=7,
        )


@pytest.mark.parametrize("count", [-1, 32, True])
def test_fixed_shift_rejects_invalid_literal_count(count):
    x = _leaf("x", width=32)

    with pytest.raises(ValueError, match="shift_count"):
        fixed_shift_term("shl", 32, x, count)


def test_non_shift_operator_rejects_shift_metadata():
    x = _leaf("x", width=32)
    y = _leaf("y", width=32)

    with pytest.raises(ValueError, match="shift_count"):
        TypedBvTerm("add", 32, children=(x, y), shift_count=1)


@pytest.mark.parametrize("operation", sorted(FIXED_SHIFT_OPERATIONS))
def test_fixed_shift_fingerprint_includes_direction_and_count(operation):
    x = _leaf("x", width=32)
    first = fixed_shift_term(operation, 32, x, 1)
    second = fixed_shift_term(operation, 32, x, 2)

    assert term_fingerprint(first) != term_fingerprint(second)
    assert term_cost(first) == term_cost(second) == (1, 2)


def test_fixed_shift_terms_are_not_ac_reassociated_or_flattened():
    x = _leaf("x", width=32)
    nested = fixed_shift_term("shl", 32, fixed_shift_term("shl", 32, x, 1), 2)

    assert canonicalize_ac_term(nested) == nested


@pytest.mark.parametrize("operation", ["rol", "ror"])
def test_rotate_rejects_unsupported_width(operation):
    x = _leaf("x", width=24)

    with pytest.raises(ValueError, match="rotate"):
        fixed_shift_term(operation, 24, x, 1)
