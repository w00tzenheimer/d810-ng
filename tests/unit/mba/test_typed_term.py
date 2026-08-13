from __future__ import annotations

import pytest

from d810.mba.typed_term import (
    TypedBvTerm,
    canonicalize_ac_term,
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
