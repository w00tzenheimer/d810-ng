from __future__ import annotations

import importlib

import pytest

from d810.backends.mba import egglog_add_rule_compiler
from d810.backends.mba.egglog_add_rule_compiler import (
    CERTIFICATE_WIDTHS,
    MbaRuleCatalogue,
    RuleCompilationStatus,
    compile_add_rule_catalogue,
    compile_mba_rule_catalogue,
)
from d810.mba.dsl import Var
from d810.mba.rules._base import VerifiableRule
from d810.mba.rules.catalogue import MBA_RULE_FAMILIES


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


def _module_owned_rule_types(
    module_name: str,
) -> tuple[type[VerifiableRule], ...]:
    module = importlib.import_module(f"d810.mba.rules.{module_name}")
    return tuple(
        value
        for value in vars(module).values()
        if isinstance(value, type)
        and value is not VerifiableRule
        and issubclass(value, VerifiableRule)
        and value.__module__ == module.__name__
    )


def test_family_manifest_covers_every_module_owned_rule_in_source_order():
    discovered_keys: list[tuple[str, str]] = []
    manifest_keys: list[tuple[str, str]] = []

    assert tuple(MBA_RULE_FAMILIES) == tuple(_RULE_MODULE_BY_FAMILY)
    for family, module_name in _RULE_MODULE_BY_FAMILY.items():
        discovered_rule_types = _module_owned_rule_types(module_name)
        manifest_rule_types = MBA_RULE_FAMILIES[family]
        assert manifest_rule_types == discovered_rule_types
        discovered_keys.extend(
            (family, rule_type.__name__) for rule_type in discovered_rule_types
        )
        manifest_keys.extend(
            (family, rule_type.__name__) for rule_type in manifest_rule_types
        )

    assert manifest_keys == discovered_keys
    assert len(discovered_keys) == 188
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

    assert len(catalogue.receipts) == 188
    assert set(catalogue.receipts_by_key) == expected_keys
    assert len(catalogue.receipts_by_key) == len(catalogue.receipts)
    assert sum(
        receipt.family not in _CLOSED_FAMILIES
        and receipt.status is RuleCompilationStatus.REJECTED
        for receipt in catalogue.receipts
    ) == 70


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
        catalogue.receipt_for("division", "UnsignedMagicModulo3Rule").reason
        == "division and cast semantics are not portable"
    )


def test_catalogue_rejects_unclassified_families(monkeypatch):
    monkeypatch.setattr(
        egglog_add_rule_compiler,
        "MBA_RULE_FAMILIES",
        {"unclassified": ()},
    )

    with pytest.raises(
        ValueError,
        match="unclassified MBA rule families: unclassified",
    ):
        compile_mba_rule_catalogue()


@pytest.mark.parametrize("exception_type", (AssertionError, TypeError, ValueError))
def test_catalogue_turns_constructor_failures_into_rejected_receipts(
    monkeypatch,
    exception_type,
):
    def fail_construction(_self):
        raise exception_type("constructor failed")

    malformed_rule = type(
        f"{exception_type.__name__}ConstructorRule",
        (VerifiableRule,),
        {
            "PATTERN": Var("x"),
            "REPLACEMENT": Var("x"),
            "__init__": fail_construction,
        },
    )
    monkeypatch.setattr(
        egglog_add_rule_compiler,
        "ADD_RULE_CLASSES",
        (malformed_rule,),
    )

    receipt = compile_add_rule_catalogue().receipt_for(malformed_rule.__name__)

    assert receipt.status is RuleCompilationStatus.REJECTED
    assert receipt.reason == "constructor failed"
    assert receipt.compiled_rule is None


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


def test_live_family_selector_preserves_catalogue_order_and_add_compatibility(
    mba_catalogue,
):
    requested_families = ("xor", "add", "mul", "add")

    selected = egglog_add_rule_compiler.compiled_rules_for_families(requested_families)
    expected = tuple(
        rule
        for rule in mba_catalogue.compiled_rules
        if rule.family in set(requested_families)
    )

    assert selected == expected
    repeated = egglog_add_rule_compiler.compiled_rules_for_families(
        requested_families
    )
    assert all(left is right for left, right in zip(selected, repeated, strict=True))
    assert egglog_add_rule_compiler.compiled_rules_for_families(("add",)) == (
        compile_add_rule_catalogue().compiled_rules
    )


def test_add_only_live_selection_does_not_compile_the_whole_corpus(monkeypatch):
    def reject_whole_corpus_compile():
        raise AssertionError("ADD selection must not certify unrelated families")

    monkeypatch.setattr(
        egglog_add_rule_compiler,
        "compile_mba_rule_catalogue",
        reject_whole_corpus_compile,
    )

    selected = egglog_add_rule_compiler.compiled_rules_for_families(("add",))

    assert selected == compile_add_rule_catalogue().compiled_rules


def test_live_selection_cache_reuses_only_the_same_declaration_version(monkeypatch):
    egglog_add_rule_compiler._compile_selected_rule_catalogue.cache_clear()
    calls = []

    def observe(rule_families):
        calls.append(tuple(rule_families.items()))
        return MbaRuleCatalogue(())

    monkeypatch.setattr(egglog_add_rule_compiler, "_compile_rule_families", observe)
    monkeypatch.setattr(
        egglog_add_rule_compiler,
        "MBA_RULE_FAMILIES",
        {"add": ()},
    )

    with pytest.raises(ValueError, match="no compiled rules"):
        egglog_add_rule_compiler.compiled_rules_for_families(("add",))
    with pytest.raises(ValueError, match="no compiled rules"):
        egglog_add_rule_compiler.compiled_rules_for_families(("add",))
    assert len(calls) == 1

    fake_rule = type(
        "ChangedDeclarationRule",
        (VerifiableRule,),
        {"PATTERN": Var("x"), "REPLACEMENT": Var("x")},
    )
    monkeypatch.setattr(
        egglog_add_rule_compiler,
        "MBA_RULE_FAMILIES",
        {"add": (fake_rule,)},
    )
    with pytest.raises(ValueError, match="no compiled rules"):
        egglog_add_rule_compiler.compiled_rules_for_families(("add",))
    assert len(calls) == 2


@pytest.mark.parametrize(
    ("families", "message"),
    [
        (("imaginary",), "unknown MBA rule families: imaginary"),
        (("predicates",), "MBA rule families have no compiled rules: predicates"),
    ],
)
def test_live_family_selector_rejects_unknown_and_receipts_only_families(
    families,
    message,
):
    with pytest.raises(ValueError, match=message):
        egglog_add_rule_compiler.compiled_rules_for_families(families)


def test_live_family_selector_keeps_aliases_as_provenance_not_executable_rules():
    selected = egglog_add_rule_compiler.compiled_rules_for_families(("add", "xor"))
    aliases_by_canonical = {
        rule.source_name: rule.aliases for rule in selected if rule.aliases
    }

    assert aliases_by_canonical == {
        "Add_HackersDelightRule_2": ("Add_OllvmRule_3",),
        "Add_OllvmRule_1": ("Add_OllvmRule_DynamicConst",),
        "Xor_HackersDelightRule_5": ("Xor_MbaRule_2",),
        "Xor_FactorRule_1": ("Xor_Rule_4",),
    }
    executable_names = {rule.source_name for rule in selected}
    assert not executable_names.intersection(
        alias for aliases in aliases_by_canonical.values() for alias in aliases
    )


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
