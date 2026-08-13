import pytest

from d810.backends.mba import egglog_add_rule_compiler
from d810.backends.mba.egglog_add_rule_compiler import (
    RuleCompilationStatus,
    compile_add_rule_catalogue,
)
from d810.backends.mba.z3 import verify_rule
from d810.mba.constraints import ComparisonConstraint
from d810.mba.dsl import Const, Var
from d810.mba.rules._base import VerifiableRule


@pytest.mark.parametrize("malformed_attribute", ("PATTERN", "REPLACEMENT"))
def test_add_catalogue_rejects_non_dsl_pattern_or_replacement(
    monkeypatch, malformed_attribute
):
    attributes = {"PATTERN": Var("x"), "REPLACEMENT": Var("x")}
    attributes[malformed_attribute] = object()
    malformed_rule = type("MalformedRule", (VerifiableRule,), attributes)
    monkeypatch.setattr(
        egglog_add_rule_compiler, "ADD_RULE_CLASSES", (malformed_rule,)
    )

    catalogue = compile_add_rule_catalogue()

    receipt = catalogue.receipt_for("MalformedRule")
    assert receipt.status is RuleCompilationStatus.REJECTED
    assert receipt.compiled_rule is None
    assert receipt.canonical_name is None


def test_add_catalogue_rejects_unknown_comparison_constraint_operation(monkeypatch):
    malformed_rule = type(
        "UnknownComparisonRule",
        (VerifiableRule,),
        {
            "PATTERN": Var("x"),
            "REPLACEMENT": Var("x"),
            "CONSTRAINTS": [
                ComparisonConstraint(Var("x"), Var("y"), "bogus", "bogus")
            ],
        },
    )
    monkeypatch.setattr(
        egglog_add_rule_compiler, "ADD_RULE_CLASSES", (malformed_rule,)
    )

    receipt = compile_add_rule_catalogue().receipt_for("UnknownComparisonRule")

    assert receipt.status is RuleCompilationStatus.REJECTED
    assert receipt.compiled_rule is None
    assert receipt.canonical_name is None


def test_add_catalogue_rejects_logical_constraint_the_verifier_cannot_convert(
    monkeypatch,
):
    x, y = Var("x"), Var("y")
    malformed_rule = type(
        "ContradictoryAndRule",
        (VerifiableRule,),
        {
            "PATTERN": x,
            "REPLACEMENT": x,
            "CONSTRAINTS": [(x == y) & (x != y)],
        },
    )
    monkeypatch.setattr(
        egglog_add_rule_compiler, "ADD_RULE_CLASSES", (malformed_rule,)
    )

    receipt = compile_add_rule_catalogue().receipt_for("ContradictoryAndRule")

    assert receipt.status is RuleCompilationStatus.REJECTED
    assert receipt.compiled_rule is None
    assert receipt.canonical_name is None


def test_add_catalogue_rejects_hidden_get_constraints_override(monkeypatch):
    x = Var("x")

    def contradictory_constraint(_self, z3_vars):
        return [z3_vars["x"] != z3_vars["x"]]

    malformed_rule = type(
        "HiddenConstraintRule",
        (VerifiableRule,),
        {
            "PATTERN": x,
            "REPLACEMENT": x + Const("ONE", 1),
            "get_constraints": contradictory_constraint,
        },
    )
    monkeypatch.setattr(
        egglog_add_rule_compiler, "ADD_RULE_CLASSES", (malformed_rule,)
    )

    receipt = compile_add_rule_catalogue().receipt_for("HiddenConstraintRule")

    assert receipt.status is RuleCompilationStatus.REJECTED
    assert receipt.compiled_rule is None
    assert receipt.canonical_name is None


def test_add_catalogue_certifies_all_native_widths_and_preserves_aliases():
    catalogue = compile_add_rule_catalogue()

    assert len(catalogue.receipts) == 15
    assert len(catalogue.compiled_rules) == 13
    assert catalogue.entries == catalogue.receipts
    assert catalogue.receipt_for("Add_OllvmRule_3").status is RuleCompilationStatus.DUPLICATE
    assert (
        catalogue.receipt_for("Add_OllvmRule_3").canonical_name
        == "Add_HackersDelightRule_2"
    )
    assert (
        catalogue.receipt_for("Add_OllvmRule_DynamicConst").canonical_name
        == "Add_OllvmRule_1"
    )
    assert all(rule.proof_widths == (8, 16, 32, 64) for rule in catalogue.compiled_rules)


@pytest.mark.parametrize("bit_width", (8, 16, 32, 64))
@pytest.mark.parametrize(
    "rule_type",
    (
        pytest.param(
            type(
                "MaskedEqualityRule",
                (VerifiableRule,),
                {
                    "PATTERN": Var("x") + (Var("masked") & Const("mask", 0xFF)),
                    "REPLACEMENT": Var("x") + Var("constant"),
                    "CONSTRAINTS": [
                        (Var("masked") & Const("constraint_mask", 0xFF))
                        == Var("constant")
                    ],
                },
            ),
            id="masked-equality",
        ),
        pytest.param(
            type(
                "ComplementDerivedConstantRule",
                (VerifiableRule,),
                {
                    "PATTERN": Var("x") + Var("complement"),
                    "REPLACEMENT": Var("x") + ~Var("source"),
                    "CONSTRAINTS": [Var("complement") == ~Var("source")],
                },
            ),
            id="complement-derived-constant",
        ),
        pytest.param(
            type(
                "NegativeTwoRule",
                (VerifiableRule,),
                {
                    "PATTERN": Var("x") - Var("c"),
                    "REPLACEMENT": Var("x") + Const("TWO", 2),
                    "CONSTRAINTS": [Var("c") == Const("NEGATIVE_TWO", -2)],
                },
            ),
            id="negative-two",
        ),
    ),
)
def test_verify_rule_honors_constraint_width_and_constraint_only_symbols(
    bit_width, rule_type
):
    assert verify_rule(rule_type(), bit_width=bit_width)
