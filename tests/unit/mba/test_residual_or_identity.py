"""Admission and consumer coverage for the mined repeated-term OR identity."""

from __future__ import annotations

import pytest

from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue
from d810.backends.mba.native_z3_proof_template import NativeZ3ProofTemplate
from d810.mba.certified_rule_compiler import (
    RuleCompilationStatus,
    apply_compiled_rule_to_term,
    compile_mba_rule_catalogue,
    compiled_rules_for_families,
)
from d810.mba.subterm_atomization import atomize_repeated_subterms
from d810.mba.typed_term import TypedBvTerm, canonicalize_ac_term


RULE_NAME = "MbaResidualRule_2aa7de9f2ef4"
MASK = 0xFFFFFBFB


def _leaf(name: str, width: int = 32) -> TypedBvTerm:
    return TypedBvTerm(None, width, leaf_key=("register", name))


def _constant(value: int, width: int = 32) -> TypedBvTerm:
    return TypedBvTerm(None, width, value=value)


def _node(operation: str, *children: TypedBvTerm, width: int = 32) -> TypedBvTerm:
    return canonicalize_ac_term(
        TypedBvTerm(operation, width, children=tuple(children))
    )


def _raw_node(operation: str, *children: TypedBvTerm, width: int = 32) -> TypedBvTerm:
    return TypedBvTerm(operation, width, children=tuple(children))


def _candidate(*, coefficient: int = 2, width: int = 32) -> TypedBvTerm:
    v17 = _leaf("v17", width)
    masked = _leaf("masked", width)
    return _raw_node(
        "add",
        _raw_node(
            "sub",
            _raw_node("xor", masked, v17),
            _raw_node(
                "add",
                _raw_node("and", masked, v17),
                _raw_node(
                    "mul",
                    _constant(coefficient, width),
                    _raw_node("and", masked, _raw_node("bnot", v17)),
                ),
            ),
        ),
        _raw_node("mul", _constant(2, width), masked),
        width=width,
    )


def test_mined_rule_is_explicitly_admitted_in_the_or_family() -> None:
    from d810.mba.rules.or_ import MbaResidualRule_2aa7de9f2ef4
    from d810.mba.rules.catalogue import MBA_RULE_FAMILIES

    assert MbaResidualRule_2aa7de9f2ef4.__name__ == RULE_NAME
    assert MbaResidualRule_2aa7de9f2ef4 in MBA_RULE_FAMILIES["or"]


def test_mined_rule_compiles_with_all_four_certificate_widths() -> None:
    receipt = compile_mba_rule_catalogue().receipt_for("or", RULE_NAME)

    assert receipt.status is RuleCompilationStatus.COMPILED
    assert receipt.canonical_name == RULE_NAME
    assert receipt.compiled_rule is not None
    assert receipt.compiled_rule.proof_widths == (8, 16, 32, 64)


def test_mined_rule_matches_full_concrete_expression_and_restores_masked_or() -> None:
    rule = compile_mba_rule_catalogue().receipt_for("or", RULE_NAME).compiled_rule
    assert rule is not None
    replacement = apply_compiled_rule_to_term(rule, _candidate())

    assert replacement == _raw_node("or", _leaf("masked"), _leaf("v17"))


def test_mined_rule_restores_the_concrete_masked_subterm_after_atomized_match() -> None:
    rule = compile_mba_rule_catalogue().receipt_for("or", RULE_NAME).compiled_rule
    assert rule is not None
    v17 = _leaf("v17")
    masked = _raw_node("and", _leaf("v135"), _constant(MASK))
    concrete = _raw_node(
        "add",
        _raw_node(
            "sub",
            _raw_node("xor", masked, v17),
            _raw_node(
                "add",
                _raw_node("and", masked, v17),
                _raw_node(
                    "mul",
                    _constant(2),
                    _raw_node("and", masked, _raw_node("bnot", v17)),
                ),
            ),
        ),
        _raw_node("mul", _constant(2), masked),
    )
    atomized = atomize_repeated_subterms(concrete)
    atomized_replacement = apply_compiled_rule_to_term(rule, atomized.atomized_term)

    assert atomized_replacement is not None
    assert atomized.restore(atomized_replacement) == _raw_node("or", masked, v17)


def test_mined_rule_rejects_one_coefficient_near_miss() -> None:
    rule = compile_mba_rule_catalogue().receipt_for("or", RULE_NAME).compiled_rule
    assert rule is not None

    assert apply_compiled_rule_to_term(rule, _candidate(coefficient=3)) is None


@pytest.mark.parametrize("width", (8, 16, 32, 64))
def test_mined_rule_native_proof_template_succeeds_at_each_width(width: int) -> None:
    rule = compile_mba_rule_catalogue().receipt_for("or", RULE_NAME).compiled_rule
    assert rule is not None
    template = NativeZ3ProofTemplate.from_compiled_rule(rule, width=width)
    assert template is not None
    left = _leaf("left", width)
    right = _leaf("right", width)
    original = _raw_node(
        "add",
        _raw_node(
            "sub",
            _raw_node("xor", right, left, width=width),
            _raw_node(
                "add",
                _raw_node("and", right, left, width=width),
                _raw_node(
                    "mul",
                    _constant(2, width),
                    _raw_node("and", left, _raw_node("bnot", right, width=width), width=width),
                    width=width,
                ),
                width=width,
            ),
            width=width,
        ),
        _raw_node("mul", _constant(2, width), left, width=width),
        width=width,
    )
    replacement = _raw_node("or", left, right, width=width)
    validation = template.validate_terms(original, replacement)

    assert validation is not None
    assert validation.width == width


def test_egraph_closed_catalogue_exposes_mined_rule_source_name() -> None:
    rules = compiled_rules_for_families(("or",))
    assert RULE_NAME in {rule.source_name for rule in rules}
    catalogue = CompiledPatternCatalogue.from_rules(rules)
    assert RULE_NAME in {
        item.rule.source_name
        for item in catalogue.rules
    }
