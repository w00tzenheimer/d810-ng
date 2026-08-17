from __future__ import annotations

import json
from pathlib import Path

import pytest

from d810.backends.mba.native_z3_proof_template import (
    _lower_validated_term as lower_typed_term_to_z3,
)
from d810.mba.semantic_canonicalization import (
    CanonicalizationKind,
    CanonicalMbaTermView,
    CanonicalizationStep,
    canonicalize_mba_term,
)
from d810.mba.typed_term import (
    TypedBvTerm,
    canonicalize_ac_term,
    fixed_shift_term,
    term_cost,
    term_fingerprint,
)


def leaf(name: str, width: int) -> TypedBvTerm:
    return TypedBvTerm(None, width, leaf_key=("register", name))


def const(value: int, width: int) -> TypedBvTerm:
    return TypedBvTerm(None, width, value=value)


def node(operation: str, width: int, *children: TypedBvTerm) -> TypedBvTerm:
    return TypedBvTerm(operation, width, children=children)


def neg(term: TypedBvTerm) -> TypedBvTerm:
    return node("neg", term.width, term)


@pytest.mark.parametrize("width", [8, 16, 32, 64])
def test_subtraction_and_modular_negative_coefficient_share_one_form(width: int):
    x = leaf("x", width)
    y = leaf("y", width)
    xy = node("and", width, x, y)
    subtraction = node(
        "sub",
        width,
        node("add", width, x, y),
        node("mul", width, const(2, width), xy),
    )
    coefficient = node(
        "add",
        width,
        node("add", width, x, y),
        node("mul", width, const(-2, width), xy),
    )

    left = canonicalize_mba_term(subtraction)
    right = canonicalize_mba_term(coefficient)

    assert left.canonical_term == right.canonical_term
    assert left.canonical_term.operation == "sub"
    assert left.raw_cost == term_cost(subtraction)
    assert right.raw_cost == term_cost(coefficient)


@pytest.mark.parametrize("width", [8, 16, 32, 64])
def test_negating_a_constant_is_modular(width: int):
    source = neg(const(3, width))

    result = canonicalize_mba_term(source)

    assert result.canonical_term == const((-3) & ((1 << width) - 1), width)


def test_double_negation_and_subtraction_of_a_negation_are_local_rewrites():
    x = leaf("x", 32)
    y = leaf("y", 32)

    assert canonicalize_mba_term(neg(neg(x))).canonical_term == x
    assert canonicalize_mba_term(node("sub", 32, x, neg(y))).canonical_term == node(
        "add", 32, x, y
    )


def test_deterministic_ac_order_after_local_normalization():
    width = 32
    x = leaf("x", width)
    z = leaf("z", width)
    source = node("add", width, z, x)

    first = canonicalize_mba_term(source)
    second = canonicalize_mba_term(source)

    assert first.canonical_term == second.canonical_term
    assert first.canonical_term == node("add", width, x, z)
    assert any(step.kind is CanonicalizationKind.AC_REORDER for step in first.steps)


def test_signed_addition_is_association_invariant_and_trace_stable():
    width = 32
    x = leaf("x", width)
    y = leaf("y", width)
    z = leaf("z", width)
    left_associated = node("add", width, neg(x), node("add", width, z, neg(y)))
    right_associated = node(
        "add", width, node("add", width, neg(x), z), neg(y)
    )

    left = canonicalize_mba_term(left_associated)
    right = canonicalize_mba_term(right_associated)

    assert left.canonical_term == right.canonical_term
    assert left.steps == right.steps
    assert left.canonical_term == node(
        "sub", width, node("sub", width, z, x), y
    )


def test_canonicalization_api_uses_the_planned_enum_and_slot_contract():
    assert CanonicalizationKind.NEGATE_CONSTANT.value == "negate_constant"
    assert CanonicalizationKind.DOUBLE_NEGATION.value == "double_negation"
    assert CanonicalizationKind.NEGATIVE_COEFFICIENT.value == "negative_coefficient"
    assert CanonicalizationKind.ADD_NEG_TO_SUB.value == "add_neg_to_sub"
    assert CanonicalizationKind.SUB_NEG_TO_ADD.value == "sub_neg_to_add"
    assert CanonicalizationKind.AC_REORDER.value == "ac_reorder"
    assert not hasattr(CanonicalizationKind, "ADD_NEGATED_OPERANDS")
    assert not hasattr(CanonicalizationKind, "SUB_NEGATION_TO_ADD")
    assert "__slots__" in CanonicalizationStep.__dict__
    assert "__slots__" in CanonicalMbaTermView.__dict__


def test_raw_and_canonical_costs_remain_separate_for_negative_coefficients():
    width = 16
    source = node("mul", width, const(-2, width), leaf("x", width))

    result = canonicalize_mba_term(source)

    assert result.raw_term is source
    assert result.raw_cost == (1, 3)
    assert result.canonical_cost == (2, 4)
    assert result.raw_cost != result.canonical_cost


@pytest.mark.parametrize("width", [8, 16, 32, 64])
def test_local_normalizations_are_modular_and_idempotent(width: int):
    x = leaf("x", width)
    minimum = 1 << (width - 1)
    samples = (
        neg(const(3, width)),
        neg(neg(x)),
        node("sub", width, x, neg(const(7, width))),
        node("mul", width, const(minimum, width), x),
    )
    for source in samples:
        first = canonicalize_mba_term(source)
        second = canonicalize_mba_term(first.canonical_term)
        assert second.canonical_term == first.canonical_term
        assert json.loads(term_fingerprint(first.canonical_term))
    assert canonicalize_mba_term(node("mul", width, const(minimum, width), x)).canonical_term == (
        canonicalize_ac_term(node("mul", width, const(minimum, width), x))
    )


def test_signed_minimum_coefficient_is_not_rewritten():
    width = 8
    x = leaf("x", width)
    source = node("mul", width, const(1 << (width - 1), width), x)

    result = canonicalize_mba_term(source)

    assert result.canonical_term == canonicalize_ac_term(source)
    assert all(
        step.kind is not CanonicalizationKind.NEGATIVE_COEFFICIENT
        for step in result.steps
    )


def test_no_distribution_boolean_expansion_or_arbitrary_constant_algebra():
    width = 32
    x = leaf("x", width)
    y = leaf("y", width)
    z = leaf("z", width)
    source = node(
        "mul",
        width,
        node("add", width, x, y),
        node("or", width, y, z),
    )

    result = canonicalize_mba_term(source)

    assert result.canonical_term.operation == "mul"
    assert result.canonical_term.children[0].operation == "add"
    assert result.canonical_term.children[1].operation == "or"
    constant_add = canonicalize_mba_term(
        node("add", width, const(1, width), const(2, width))
    )
    assert constant_add.canonical_term.operation == "add"


def test_step_trace_and_fingerprints_are_deterministic_and_json_safe():
    width = 16
    x = leaf("x", width)
    y = leaf("y", width)
    source = node("add", width, node("mul", width, const(-2, width), y), x)

    first = canonicalize_mba_term(source)
    second = canonicalize_mba_term(source)

    assert first.steps == second.steps
    assert first.raw_term is source
    for step in first.steps:
        assert json.loads(step.source_fingerprint)
        assert json.loads(step.result_fingerprint)
    assert any(
        step.kind is CanonicalizationKind.NEGATIVE_COEFFICIENT
        for step in first.steps
    )


def test_canonicalizer_does_not_import_provider_backends():
    source = Path("src/d810/mba/semantic_canonicalization.py").read_text()
    assert "d810.backends" not in source
    assert "egglog" not in source
    assert "z3" not in source


def _generated_terms(width: int) -> tuple[TypedBvTerm, ...]:
    """Build a reproducible operation/depth matrix without random state."""

    x = leaf("x", width)
    y = leaf("y", width)
    levels: list[tuple[TypedBvTerm, ...]] = [
        (x, y, const(1, width), const(-2, width), neg(x))
    ]
    operations = ("add", "and", "mul", "or", "sub", "xor", "neg", "bnot")
    for depth in range(1, 4):
        previous = levels[-1]
        generated: list[TypedBvTerm] = []
        for index, operation in enumerate(operations):
            if operation in {"neg", "bnot"}:
                generated.append(node(operation, width, previous[index % len(previous)]))
            else:
                generated.append(
                    node(
                        operation,
                        width,
                        previous[index % len(previous)],
                        previous[(index + depth) % len(previous)],
                    )
                )
        levels.append(tuple(generated))
    return tuple(term for level in levels for term in level)


@pytest.mark.parametrize("width", [8, 16])
def test_deterministic_generated_terms_preserve_fixed_width_semantics(width: int):
    import z3

    # `_lower_validated_term` is the repository's existing pure
    # TypedBvTerm-to-Z3 seam; it does not require a live native object.
    for source in _generated_terms(width):
        canonical = canonicalize_mba_term(source).canonical_term
        variables: dict[tuple[object, ...], object] = {}
        solver = z3.Solver()
        solver.add(
            lower_typed_term_to_z3(source, variables=variables, z3=z3)
            != lower_typed_term_to_z3(canonical, variables=variables, z3=z3)
        )
        assert solver.check() == z3.unsat


def test_rejects_non_typed_terms():
    with pytest.raises(TypeError, match="TypedBvTerm"):
        canonicalize_mba_term(object())


@pytest.mark.parametrize("operation", ["shl", "lshr", "rol", "ror"])
@pytest.mark.parametrize("width", [8, 16, 32, 64])
def test_canonicalizer_preserves_fixed_shift_metadata_without_rotate_rewrite(
    operation: str, width: int
):
    source = fixed_shift_term(operation, width, leaf("x", width), width - 1)

    result = canonicalize_mba_term(source)

    assert result.canonical_term.operation == operation
    assert result.canonical_term.shift_count == width - 1
    assert result.canonical_term.children == source.children
    assert result.canonical_term == canonicalize_ac_term(source)
    assert all(
        step.kind is not CanonicalizationKind.NEGATIVE_COEFFICIENT
        for step in result.steps
    )
