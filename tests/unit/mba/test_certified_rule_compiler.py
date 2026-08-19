"""Provider-neutral admission and typed-term application contracts."""

from __future__ import annotations

import builtins
import inspect
from collections import Counter
from dataclasses import fields

import pytest

from d810.mba.rules.catalogue import MBA_RULE_FAMILIES
from d810.mba.typed_term import TypedBvTerm, canonicalize_ac_term


def _leaf(name: str, width: int = 32) -> TypedBvTerm:
    return TypedBvTerm(None, width, leaf_key=("mop", name))


def _constant(value: int, width: int = 32) -> TypedBvTerm:
    return TypedBvTerm(None, width, value=value)


def _node(
    operation: str,
    *children: TypedBvTerm,
    width: int = 32,
) -> TypedBvTerm:
    return canonicalize_ac_term(
        TypedBvTerm(operation, width, children=tuple(children))
    )


def test_catalogue_receipts_keep_exact_declaration_order_and_counts() -> None:
    from d810.mba.certified_rule_compiler import (
        RuleCompilationStatus,
        compile_mba_rule_catalogue,
    )

    catalogue = compile_mba_rule_catalogue()
    expected_keys = tuple(
        (family, rule_type.__name__)
        for family, rule_types in MBA_RULE_FAMILIES.items()
        for rule_type in rule_types
    )

    assert len(catalogue.receipts) == 192
    assert len(catalogue.compiled_rules) == 112
    assert tuple(receipt.key for receipt in catalogue.receipts) == expected_keys
    assert Counter(receipt.status for receipt in catalogue.receipts) == Counter(
        {
            RuleCompilationStatus.COMPILED: 112,
            RuleCompilationStatus.DUPLICATE: 4,
            RuleCompilationStatus.REJECTED: 76,
        }
    )


def test_catalogue_preserves_aliases_proof_widths_and_guard_metadata() -> None:
    from d810.mba.certified_rule_compiler import compile_mba_rule_catalogue

    catalogue = compile_mba_rule_catalogue()
    aliases = {
        (rule.family, rule.source_name): rule.aliases
        for rule in catalogue.compiled_rules
        if rule.aliases
    }

    assert aliases == {
        ("add", "Add_HackersDelightRule_2"): ("Add_OllvmRule_3",),
        ("add", "Add_OllvmRule_1"): ("Add_OllvmRule_DynamicConst",),
        ("xor", "Xor_HackersDelightRule_5"): ("Xor_MbaRule_2",),
        ("xor", "Xor_FactorRule_1"): ("Xor_Rule_4",),
    }
    assert all(rule.proof_widths == (8, 16, 32, 64) for rule in catalogue.compiled_rules)
    assert catalogue.receipt_for("xor", "Xor_FactorRule_1").compiled_rule.guarded


def test_duplicate_and_rejected_receipts_retain_exact_provenance() -> None:
    from d810.mba.certified_rule_compiler import (
        RuleCompilationStatus,
        compile_mba_rule_catalogue,
    )

    catalogue = compile_mba_rule_catalogue()
    assert [
        (receipt.family, receipt.source_name, receipt.canonical_name)
        for receipt in catalogue.receipts
        if receipt.status is RuleCompilationStatus.DUPLICATE
    ] == [
        ("add", "Add_OllvmRule_3", "Add_HackersDelightRule_2"),
        ("add", "Add_OllvmRule_DynamicConst", "Add_OllvmRule_1"),
        ("xor", "Xor_MbaRule_2", "Xor_HackersDelightRule_5"),
        ("xor", "Xor_Rule_4", "Xor_FactorRule_1"),
    ]
    assert catalogue.receipt_for(
        "predicates", "PredSetnzRule1"
    ).reason == "predicate semantics are not portable"
    assert catalogue.receipt_for(
        "hodur", "Xor_Hodur_2"
    ).reason == "custom get_constraints is not portable"


def test_compiled_rule_fields_are_portable_descriptors_only() -> None:
    from d810.mba.certified_rule_compiler import CompiledMbaRule, compile_mba_rule_catalogue

    assert tuple(field.name for field in fields(CompiledMbaRule)) == (
        "source_name",
        "aliases",
        "rule_type",
        "proof_widths",
        "guarded",
        "family",
    )
    for rule in compile_mba_rule_catalogue().compiled_rules:
        assert type(rule) is CompiledMbaRule
        assert all(
            "astnode" not in type(value).__name__.lower()
            and "egglog" not in type(value).__module__.lower()
            for value in (
                rule.source_name,
                rule.aliases,
                rule.rule_type,
                rule.proof_widths,
                rule.guarded,
                rule.family,
            )
        )


def test_guarded_typed_term_application_matches_and_rejects_exact_constants() -> None:
    from d810.mba.certified_rule_compiler import (
        apply_compiled_rule_to_term,
        compile_mba_rule_catalogue,
    )

    rule = compile_mba_rule_catalogue().receipt_for(
        "add", "Add_SpecialConstantRule_1"
    ).compiled_rule
    assert rule is not None and rule.guarded
    x = _leaf("x")
    accepted = _node(
        "add",
        _node("xor", x, _constant(0x55)),
        _node("mul", _constant(2), _node("and", x, _constant(0x55))),
    )
    rejected = _node(
        "add",
        _node("xor", x, _constant(0x55)),
        _node("mul", _constant(2), _node("and", x, _constant(0xAA))),
    )

    assert apply_compiled_rule_to_term(rule, accepted) == _node("add", x, _constant(0x55))
    assert apply_compiled_rule_to_term(rule, rejected) is None


def test_compilation_does_not_load_provider_or_native_runtime_modules(monkeypatch) -> None:
    from d810.mba.certified_rule_compiler import compile_mba_rule_catalogue

    blocked = {
        "egglog",
        "d810_egglog",
        "ida_hexrays",
        "d810.hexrays",
        "d810.speedups",
    }
    real_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name in blocked or any(name.startswith(prefix + ".") for prefix in blocked):
            raise AssertionError(f"provider/native import during compilation: {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    catalogue = compile_mba_rule_catalogue()
    assert len(catalogue.compiled_rules) == 112


@pytest.mark.parametrize(
    "module_name",
    [
        "d810.mba.canonical_pattern",
        "d810.backends.mba.compiled_pattern_catalogue",
        "d810.backends.mba.native_z3_proof_template",
    ],
)
def test_native_core_consumers_import_the_portable_compiler(module_name: str) -> None:
    module = __import__(module_name, fromlist=["*"])
    source = inspect.getsource(module)
    assert "d810.backends.mba.egglog_add_rule_compiler" not in source
    assert "CompiledMbaRule" in source
