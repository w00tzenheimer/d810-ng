from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

from d810.backends.mba.egglog_add_rule_compiler import (
    CERTIFICATE_WIDTHS,
    RuleCompilationStatus,
    compile_add_rule_catalogue,
    compile_mba_rule_catalogue,
)
from d810.mba.dsl import Var
from d810.mba.rules._base import VerifiableRule
from d810.mba.rules.catalogue import (
    FAMILY_REJECTION_REASONS,
    MBA_RULE_FAMILIES,
)


_RULE_MODULE_BY_FAMILY = {
    "add": "add",
    "and": "and_",
    "bnot": "bnot",
    "cst": "cst",
    "division": "division",
    "hodur": "hodur",
    "misc": "misc",
    "mov": "mov",
    "mul": "mul",
    "neg": "neg",
    "or": "or_",
    "predicates": "predicates",
    "sub": "sub",
    "tigress": "tigress",
    "xor": "xor",
}
_CLOSED_FAMILIES = frozenset(
    {"add", "xor", "sub", "and", "or", "bnot", "neg", "mul"}
)


@pytest.fixture(scope="module")
def mba_catalogue():
    return compile_mba_rule_catalogue()


def _declared_rule_names(module_name: str) -> tuple[str, ...]:
    module = importlib.import_module(f"d810.mba.rules.{module_name}")
    module_path = Path(module.__file__)
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    return tuple(
        statement.name
        for statement in tree.body
        if isinstance(statement, ast.ClassDef)
        and any(
            isinstance(base, ast.Name) and base.id == "VerifiableRule"
            for base in statement.bases
        )
    )


def test_family_manifest_covers_every_rule_declaration_in_source_order():
    discovered_keys: list[tuple[str, str]] = []
    manifest_keys: list[tuple[str, str]] = []

    assert tuple(MBA_RULE_FAMILIES) == tuple(_RULE_MODULE_BY_FAMILY)
    for family, module_name in _RULE_MODULE_BY_FAMILY.items():
        declared_names = _declared_rule_names(module_name)
        manifest_names = tuple(
            rule_type.__name__ for rule_type in MBA_RULE_FAMILIES[family]
        )
        assert manifest_names == declared_names
        discovered_keys.extend((family, name) for name in declared_names)
        manifest_keys.extend((family, name) for name in manifest_names)

    assert manifest_keys == discovered_keys
    assert len(discovered_keys) == 187
    assert (
        sum(
            len(MBA_RULE_FAMILIES[family])
            for family in _CLOSED_FAMILIES
        )
        == 118
    )


def test_whole_corpus_has_one_family_qualified_receipt_per_declaration(
    mba_catalogue,
):
    catalogue = mba_catalogue
    expected_keys = {
        (family, rule_type.__name__)
        for family, rule_types in MBA_RULE_FAMILIES.items()
        for rule_type in rule_types
    }

    assert len(catalogue.receipts) == 187
    assert set(catalogue.receipts_by_key) == expected_keys
    assert len(catalogue.receipts_by_key) == len(catalogue.receipts)
    assert sum(
        receipt.family not in _CLOSED_FAMILIES
        and receipt.status is RuleCompilationStatus.REJECTED
        for receipt in catalogue.receipts
    ) == 69


def test_unsupported_family_and_custom_guard_reasons_are_stable(mba_catalogue):
    catalogue = mba_catalogue

    assert (
        catalogue.receipt_for("predicates", "PredSetnzRule1").reason
        == "predicate semantics are not portable"
    )
    assert (
        catalogue.receipt_for("hodur", "Xor_Hodur_2").reason
        == "custom get_constraints is not portable"
    )
    assert (
        FAMILY_REJECTION_REASONS["division"]
        == "division and cast semantics are not portable"
    )


def test_compiled_rules_are_family_qualified_and_cross_width_certified(
    mba_catalogue,
):
    catalogue = mba_catalogue

    assert catalogue.compiled_rules
    assert all(
        rule.family in _CLOSED_FAMILIES for rule in catalogue.compiled_rules
    )
    assert all(
        rule.proof_widths == CERTIFICATE_WIDTHS
        for rule in catalogue.compiled_rules
    )
    assert all(
        receipt.compiled_rule is None
        or receipt.compiled_rule.family == receipt.family
        for receipt in catalogue.receipts
    )
    assert all(
        receipt.compiled_rule is not None
        for receipt in catalogue.receipts
        if receipt.status
        in {RuleCompilationStatus.COMPILED, RuleCompilationStatus.DUPLICATE}
    )


def test_add_catalogue_remains_a_source_name_compatible_view(mba_catalogue):
    add_catalogue = compile_add_rule_catalogue()
    whole_catalogue = mba_catalogue
    whole_add_receipts = tuple(
        receipt for receipt in whole_catalogue.receipts if receipt.family == "add"
    )

    assert add_catalogue.receipts == whole_add_receipts
    assert add_catalogue.receipt_for("Add_HackersDelightRule_1") == (
        whole_catalogue.receipt_for("add", "Add_HackersDelightRule_1")
    )
    assert len(add_catalogue.receipts) == 15


def test_family_manifest_does_not_follow_the_mutable_rule_registry(monkeypatch):
    fake_rule = type(
        "RegistryOnlyRule",
        (VerifiableRule,),
        {"PATTERN": Var("x"), "REPLACEMENT": Var("x")},
    )
    before = tuple(MBA_RULE_FAMILIES["add"])
    monkeypatch.setitem(VerifiableRule.registry, fake_rule.__name__, fake_rule)

    assert MBA_RULE_FAMILIES["add"] == before
    assert fake_rule not in MBA_RULE_FAMILIES["add"]
