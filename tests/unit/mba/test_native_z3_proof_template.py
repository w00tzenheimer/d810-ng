"""Portable admission and shape-validation tests for native Z3 templates."""

from __future__ import annotations

from dataclasses import replace

from d810.backends.mba.egglog_add_rule_compiler import compile_add_rule_catalogue
from d810.backends.mba.native_z3_proof_template import (
    NativeZ3ProofTemplate,
    native_z3_proof_templates_for_rules,
)
from d810.mba.typed_term import TypedBvTerm, canonicalize_ac_term


def _rule(name: str):
    return next(
        rule
        for rule in compile_add_rule_catalogue().compiled_rules
        if rule.source_name == name
    )


def _term(operation: str, *children: TypedBvTerm) -> TypedBvTerm:
    return canonicalize_ac_term(
        TypedBvTerm(operation=operation, width=32, children=children)
    )


def _valid_terms() -> tuple[TypedBvTerm, TypedBvTerm]:
    x = TypedBvTerm(None, 32, leaf_key=("mop", "x"))
    y = TypedBvTerm(None, 32, leaf_key=("mop", "y"))
    two = TypedBvTerm(None, 32, value=2)
    original = _term("add", _term("xor", x, y), _term("mul", two, _term("and", x, y)))
    return original, _term("add", x, y)


def test_template_accepts_only_enrolled_width_preserving_rule_shapes() -> None:
    rule = _rule("Add_HackersDelightRule_2")

    assert NativeZ3ProofTemplate.from_compiled_rule(rule, width=32) is not None
    assert NativeZ3ProofTemplate.from_compiled_rule(rule, width=24) is None
    assert (
        NativeZ3ProofTemplate.from_compiled_rule(
            replace(rule, source_name="not_enrolled"), width=32
        )
        is None
    )


def test_template_validates_exact_constants_and_repeated_live_leaf_identity() -> None:
    template = NativeZ3ProofTemplate.from_compiled_rule(
        _rule("Add_HackersDelightRule_2"), width=32
    )
    assert template is not None
    original, replacement = _valid_terms()

    validation = template.validate_terms(original, replacement)
    assert validation is not None
    assert validation.width == 32
    assert validation.leaf_keys == (("mop", "x"), ("mop", "y"))

    x = TypedBvTerm(None, 32, leaf_key=("mop", "x"))
    y = TypedBvTerm(None, 32, leaf_key=("mop", "y"))
    z = TypedBvTerm(None, 32, leaf_key=("mop", "z"))
    two = TypedBvTerm(None, 32, value=2)
    repeated_leaf_mismatch = _term(
        "add", _term("xor", x, y), _term("mul", two, _term("and", x, z))
    )
    assert template.validate_terms(repeated_leaf_mismatch, replacement) is None
    assert template.validate_terms(original, _term("add", x, z)) is None


def test_templates_are_immutable_and_keyed_by_exact_admitted_rule_identity() -> None:
    rule = _rule("Add_HackersDelightRule_2")
    templates = native_z3_proof_templates_for_rules((rule,))

    assert templates[(id(rule), 8)].width == 8
    assert templates[(id(rule), 64)].source_name == rule.source_name
    try:
        templates[(id(rule), 32)] = templates[(id(rule), 32)]
    except TypeError:
        pass
    else:  # pragma: no cover - documents the immutable cache contract.
        raise AssertionError("template catalogue must be immutable")
