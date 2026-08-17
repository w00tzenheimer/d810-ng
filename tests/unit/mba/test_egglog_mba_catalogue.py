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
from d810.mba.typed_term import TypedBvTerm, fixed_shift_term


def test_fixed_rotate_structural_catalogue_certifies_every_nonzero_count():
    from d810.backends.mba.egglog_structural_rules import (
        StructuralRuleStatus,
        compile_fixed_rotate_rules,
    )

    for width in (8, 16, 32, 64):
        for direction in ("rol", "ror"):
            receipts = compile_fixed_rotate_rules(width=width, direction=direction)
            assert len(receipts) == width - 1
            assert all(
                receipt.status is StructuralRuleStatus.COMPILED
                for receipt in receipts
            )
            assert all(receipt.proof_verdict is True for receipt in receipts)
            assert tuple(receipt.count for receipt in receipts) == tuple(
                range(1, width)
            )


def test_fixed_rotate_structural_receipts_are_frozen_and_wire_stable():
    from dataclasses import FrozenInstanceError

    from d810.backends.mba.egglog_structural_rules import (
        StructuralRuleCompilationReceipt,
        StructuralRuleStatus,
        compile_fixed_rotate_rules,
    )

    receipt = compile_fixed_rotate_rules(width=8, direction="rol")[0]
    assert isinstance(receipt, StructuralRuleCompilationReceipt)
    assert receipt.to_dict() == {
        "source_name": "rol_8_1",
        "status": StructuralRuleStatus.COMPILED.value,
        "width": 8,
        "direction": "rol",
        "count": 1,
        "proof_verdict": True,
        "refusal_reason": None,
    }
    with pytest.raises(FrozenInstanceError):
        receipt.count = 2  # type: ignore[misc]


def test_failed_fixed_rotate_certification_omits_only_that_rule(monkeypatch):
    from d810.backends.mba import egglog_structural_rules
    from d810.backends.mba.egglog_structural_rules import StructuralRuleStatus

    original = egglog_structural_rules.prove_typed_term_equivalence

    def reject_count_three(pattern, replacement):
        return not (
            replacement.operation == "rol" and replacement.shift_count == 3
        )

    monkeypatch.setattr(
        egglog_structural_rules,
        "prove_typed_term_equivalence",
        reject_count_three,
    )
    try:
        receipts = egglog_structural_rules.compile_fixed_rotate_rules(
            width=8, direction="rol"
        )
    finally:
        monkeypatch.setattr(
            egglog_structural_rules,
            "prove_typed_term_equivalence",
            original,
        )

    rejected = receipts[2]
    assert rejected.count == 3
    assert rejected.status is StructuralRuleStatus.REJECTED
    assert rejected.compiled_rule is None
    assert rejected.refusal_reason == "typed_z3_proof_failed"
    assert sum(item.compiled_rule is not None for item in receipts) == 6


@pytest.mark.parametrize("direction", ["rol", "ror"])
def test_fixed_rotate_rejects_invalid_width_direction_and_count(direction):
    from d810.backends.mba.egglog_structural_rules import (
        build_rotate_identity,
        compile_fixed_rotate_rules,
    )

    with pytest.raises(ValueError, match="width"):
        compile_fixed_rotate_rules(width=24, direction=direction)
    with pytest.raises(ValueError, match="direction"):
        compile_fixed_rotate_rules(width=8, direction="bad")
    with pytest.raises(ValueError, match="count"):
        build_rotate_identity(8, direction, 0)
    with pytest.raises(ValueError, match="count"):
        build_rotate_identity(8, direction, 8)


def test_fixed_rotate_rejects_signed_mixed_width_and_extra_operand_shapes():
    from d810.backends.mba.egglog_structural_rules import (
        compile_fixed_rotate_rules,
        structural_catalogue_for_rules,
    )

    rule = compile_fixed_rotate_rules(width=32, direction="rol")[4].compiled_rule
    assert rule is not None
    catalogue = structural_catalogue_for_rules((rule,))
    x32 = TypedBvTerm(None, 32, leaf_key=("register", "x"))

    # Arithmetic shifts are deliberately outside the typed fixed-shift
    # vocabulary, so they cannot enter the structural catalogue at all.
    with pytest.raises(ValueError, match="shift_count"):
        fixed_shift_term("sar", 32, x32, 5)

    # A source at another width cannot match a 32-bit certified rule.
    x16 = TypedBvTerm(None, 16, leaf_key=("register", "x"))
    mixed_width_candidate = TypedBvTerm(
        "or",
        16,
        children=(
            fixed_shift_term("shl", 16, x16, 5),
            fixed_shift_term("lshr", 16, x16, 11),
        ),
    )
    assert catalogue.canonical_applications(mixed_width_candidate) == ()
    with pytest.raises(ValueError, match="same width"):
        TypedBvTerm(
            "or",
            32,
            children=(
                fixed_shift_term("shl", 32, x32, 5),
                fixed_shift_term("lshr", 16, x16, 11),
            ),
        )

    # An enclosing operand changes the root shape and must not be searched
    # through by the candidate-root-only structural route.
    source = TypedBvTerm(
        "or",
        32,
        children=(
            fixed_shift_term("shl", 32, x32, 5),
            fixed_shift_term("lshr", 32, x32, 27),
        ),
    )
    extra_operand = TypedBvTerm(
        "add",
        32,
        children=(TypedBvTerm(None, 32, value=0), source),
    )
    assert catalogue.canonical_applications(extra_operand) == ()


def test_snapshot_fingerprint_binds_admitted_structural_rotate_inventory():
    from d810.backends.mba.egglog_structural_rules import compile_fixed_rotate_rules
    from d810.mba.certified_catalogue import build_certified_catalogue_snapshot

    receipts = compile_fixed_rotate_rules(width=8, direction="rol")
    structural_rules = tuple(
        receipt.compiled_rule
        for receipt in receipts
        if receipt.compiled_rule is not None
    )
    complete = build_certified_catalogue_snapshot(
        (),
        compiler_version="structural-v1",
        widths=(8,),
        structural_rules=structural_rules,
    )
    incomplete = build_certified_catalogue_snapshot(
        (),
        compiler_version="structural-v1",
        widths=(8,),
        structural_rules=structural_rules[:-1],
    )

    assert complete.structural_rule_fingerprints
    assert complete.structural_rule_digest
    assert complete.fingerprint != incomplete.fingerprint
    assert complete.structural_rule_digest != incomplete.structural_rule_digest


def test_snapshot_rejects_forged_structural_rule_with_imported_token():
    from d810.mba.certified_catalogue import (
        _STRUCTURAL_RULE_ADMISSION_TOKEN,
        build_certified_catalogue_snapshot,
    )

    class ForgedStructuralRule:
        source_name = "rol_32_5"
        width = 32
        direction = "rol"
        count = 5
        proof_verdict = True
        family = "fixed_rotate"
        semantic_fingerprint = "forged-rotate-fingerprint"

    forged = ForgedStructuralRule()
    forged._admission_token = _STRUCTURAL_RULE_ADMISSION_TOKEN
    unmarked = ForgedStructuralRule()
    forged_snapshot = build_certified_catalogue_snapshot(
        (),
        compiler_version="structural-v1",
        structural_rules=(forged,),
    )
    unavailable_snapshot = build_certified_catalogue_snapshot(
        (),
        compiler_version="structural-v1",
        structural_rules=(unmarked,),
    )

    assert forged_snapshot.structural_authorizable is False
    assert forged_snapshot.structural_rule_fingerprints == ()
    assert (
        forged_snapshot.structural_rule_digest
        == unavailable_snapshot.structural_rule_digest
    )


def test_fixed_rotate_inventory_reuses_certification_across_live_requests(monkeypatch):
    from d810.backends.mba import egglog_structural_rules

    compile_all = egglog_structural_rules.compile_all_fixed_rotate_rules
    compile_all.cache_clear()
    first = compile_all()
    calls = 0

    def unexpected_reproof(pattern, replacement):
        nonlocal calls
        calls += 1
        raise AssertionError("cached fixed-rotate inventory re-entered proof gate")

    monkeypatch.setattr(
        egglog_structural_rules,
        "prove_typed_term_equivalence",
        unexpected_reproof,
    )
    try:
        second = compile_all()
    finally:
        compile_all.cache_clear()

    assert second is first
    assert calls == 0


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
_RULE_MODULES_BY_FAMILY = {
    **_RULE_MODULE_BY_FAMILY,
    # These two certified Eidolon identities are intentionally interleaved in
    # the explicit XOR declaration order, so the manifest is not a one-module
    # inventory for this family.
    "xor": ("xor", "eidolon"),
}
_CLOSED_FAMILIES = frozenset({"add", "xor", "sub", "and", "or", "bnot", "neg", "mul"})


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

    assert tuple(MBA_RULE_FAMILIES) == tuple(_RULE_MODULES_BY_FAMILY)
    for family, module_names in _RULE_MODULES_BY_FAMILY.items():
        if isinstance(module_names, str):
            module_names = (module_names,)
        manifest_rule_types = MBA_RULE_FAMILIES[family]
        manifest_modules = {rule_type.__module__.rsplit(".", 1)[-1] for rule_type in manifest_rule_types}
        assert manifest_modules == set(module_names)
        for module_name in module_names:
            discovered_rule_types = _module_owned_rule_types(module_name)
            assert tuple(
                rule_type
                for rule_type in manifest_rule_types
                if rule_type.__module__.rsplit(".", 1)[-1] == module_name
            ) == discovered_rule_types
            discovered_keys.extend(
                (family, rule_type.__name__) for rule_type in discovered_rule_types
            )
        manifest_keys.extend(
            (family, rule_type.__name__) for rule_type in manifest_rule_types
        )

    assert set(manifest_keys) == set(discovered_keys)
    assert len(manifest_keys) == 192
    assert sum(len(MBA_RULE_FAMILIES[family]) for family in _CLOSED_FAMILIES) == 122


def test_whole_corpus_has_one_family_qualified_receipt_per_declaration(
    mba_catalogue,
):
    catalogue = mba_catalogue
    expected_keys = {
        (family, rule_type.__name__)
        for family, rule_types in MBA_RULE_FAMILIES.items()
        for rule_type in rule_types
    }

    assert len(catalogue.receipts) == 192
    assert set(catalogue.receipts_by_key) == expected_keys
    assert len(catalogue.receipts_by_key) == len(catalogue.receipts)
    assert (
        sum(
            receipt.family not in _CLOSED_FAMILIES
            and receipt.status is RuleCompilationStatus.REJECTED
            for receipt in catalogue.receipts
        )
        == 70
    )


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
    assert all(rule.family in _CLOSED_FAMILIES for rule in catalogue.compiled_rules)
    assert all(
        rule.proof_widths == CERTIFICATE_WIDTHS for rule in catalogue.compiled_rules
    )
    assert all(
        receipt.compiled_rule is None or receipt.compiled_rule.family == receipt.family
        for receipt in catalogue.receipts
    )
    assert all(
        receipt.compiled_rule is not None
        for receipt in catalogue.receipts
        if receipt.status
        in {RuleCompilationStatus.COMPILED, RuleCompilationStatus.DUPLICATE}
    )


def test_canonical_template_projection_consumes_existing_admitted_rules_only(
    monkeypatch,
):
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue

    rule = compile_add_rule_catalogue().receipt_for(
        "Add_HackersDelightRule_2"
    ).compiled_rule
    assert rule is not None
    monkeypatch.setattr(
        egglog_add_rule_compiler,
        "verify_rule",
        lambda *_args, **_kwargs: pytest.fail("canonical projection recompiled proof"),
    )

    catalogue = CompiledPatternCatalogue.from_rules((rule,))
    assert catalogue.rules[0].canonical_by_width[32].semantic_fingerprint


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


def test_public_catalogue_compilers_reuse_immutable_certificates():
    egglog_add_rule_compiler._compile_selected_rule_catalogue.cache_clear()

    mba_catalogue = compile_mba_rule_catalogue()
    add_catalogue = compile_add_rule_catalogue()

    assert compile_mba_rule_catalogue() is mba_catalogue
    assert compile_add_rule_catalogue() is add_catalogue


def test_public_catalogue_cache_misses_changed_family_declarations(monkeypatch):
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
    monkeypatch.setattr(egglog_add_rule_compiler, "ADD_RULE_CLASSES", ())

    mba_catalogue = compile_mba_rule_catalogue()
    add_catalogue = compile_add_rule_catalogue()
    assert compile_mba_rule_catalogue() is mba_catalogue
    assert compile_add_rule_catalogue() is add_catalogue
    assert len(calls) == 1

    changed_rule = type(
        "ChangedDeclarationRule",
        (VerifiableRule,),
        {"PATTERN": Var("x"), "REPLACEMENT": Var("x")},
    )
    monkeypatch.setattr(
        egglog_add_rule_compiler,
        "MBA_RULE_FAMILIES",
        {"add": (changed_rule,)},
    )
    monkeypatch.setattr(
        egglog_add_rule_compiler,
        "ADD_RULE_CLASSES",
        (changed_rule,),
    )

    changed_mba_catalogue = compile_mba_rule_catalogue()
    changed_add_catalogue = compile_add_rule_catalogue()

    assert changed_mba_catalogue is not mba_catalogue
    assert changed_add_catalogue is not add_catalogue
    assert changed_add_catalogue is changed_mba_catalogue
    assert len(calls) == 2


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
    repeated = egglog_add_rule_compiler.compiled_rules_for_families(requested_families)
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
