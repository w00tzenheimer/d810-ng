"""Provider-neutral admission and typed-term application contracts."""

from __future__ import annotations

import builtins
import inspect
import os
import subprocess
import sys
import textwrap
from collections import Counter
from dataclasses import fields
from types import SimpleNamespace

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


def test_fresh_process_compilation_does_not_scan_provider_tree() -> None:
    source_root = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "..")
    )
    source_path = os.path.join(source_root, "src")
    script = textwrap.dedent(
        """
        import builtins

        attempted = []
        real_import = builtins.__import__

        def guarded_import(name, *args, **kwargs):
            lowered = name.lower()
            blocked = (
                "egglog" in lowered
                or lowered.startswith("ida_")
                or lowered in {"idaapi", "idc", "idautils", "d810_egglog"}
                or "d810.hexrays" in lowered
                or (
                    lowered.startswith("d810.speedups.")
                    and lowered != "d810.speedups.bootstrap"
                )
            )
            if blocked:
                attempted.append(name)
                raise AssertionError(f"forbidden provider/native import: {name}")
            return real_import(name, *args, **kwargs)

        builtins.__import__ = guarded_import
        from d810.mba.certified_rule_compiler import compile_mba_rule_catalogue

        catalogue = compile_mba_rule_catalogue()
        assert len(catalogue.receipts) == 192
        assert len(catalogue.compiled_rules) == 112
        assert not attempted, attempted
        """
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = source_path
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=source_root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_unknown_verification_backend_fails_closed() -> None:
    from d810.mba.backend_registry import get_verification_engine

    with pytest.raises(ImportError, match="not available"):
        get_verification_engine("missing")


def _guard_rule(
    name: str,
    constraint,
):
    from d810.mba.certified_rule_compiler import (
        CompiledMbaRule,
        _enroll_admitted_rule,
    )
    from d810.mba.dsl import Const, Var
    from d810.mba.rules._base import VerifiableRule

    x, c1, c2 = Var("x"), Const("c1"), Const("c2")

    class GuardRule(VerifiableRule):
        PATTERN = (x + (c1 * Const("one", 1))) + c2
        REPLACEMENT = x
        CONSTRAINTS = [constraint]

    GuardRule.__name__ = name
    return _enroll_admitted_rule(
        CompiledMbaRule(
            source_name=name,
            aliases=(),
            rule_type=GuardRule,
            proof_widths=(32,),
            guarded=True,
            family="add",
        )
    )


def test_comparison_and_logical_guards_distinguish_identical_bindings() -> None:
    from d810.mba.certified_rule_compiler import apply_compiled_rule_to_term
    from d810.mba.dsl import Const

    c1, c2 = Const("c1"), Const("c2")
    eq_rule = _guard_rule("EqualityGuardRule", c1 == c2)
    ne_rule = _guard_rule("InequalityGuardRule", c1 != c2)
    logical_rule = _guard_rule("LogicalGuardRule", (c1 < c2) | (c1 == c2))

    candidate = _node(
        "add",
        _node("add", _leaf("x"), _node("mul", _constant(1), _constant(1))),
        _constant(1),
    )
    assert apply_compiled_rule_to_term(eq_rule, candidate) == _leaf("x")
    assert apply_compiled_rule_to_term(ne_rule, candidate) is None
    assert apply_compiled_rule_to_term(logical_rule, candidate) == _leaf("x")


@pytest.mark.parametrize(
    ("operation", "constraint_factory", "expected"),
    [
        ("ne", lambda left, right: left != right, True),
        ("lt", lambda left, right: left < right, False),
        ("le", lambda left, right: left <= right, False),
        ("gt", lambda left, right: left > right, True),
        ("ge", lambda left, right: left >= right, True),
    ],
)
def test_comparison_guards_use_unsigned_fixed_width_values(
    operation,
    constraint_factory,
    expected,
) -> None:
    from d810.mba.certified_rule_compiler import apply_compiled_rule_to_term
    from d810.mba.dsl import Const

    c1, c2 = Const("c1"), Const("c2")
    rule = _guard_rule(
        f"Unsigned{operation.title()}GuardRule",
        constraint_factory(c1, c2),
    )
    candidate = _node(
        "add",
        _node(
            "add",
            _leaf("x"),
            _node("mul", _constant(-1), _constant(1)),
        ),
        _constant(0),
    )
    result = apply_compiled_rule_to_term(rule, candidate)
    assert (result == _leaf("x")) is expected


def test_canonical_constraints_preserve_operator_semantics_and_fingerprints() -> None:
    from d810.mba.canonical_pattern import (
        compile_canonical_pattern,
        evaluate_frozen_constraints,
    )
    from d810.mba.dsl import Const, Var
    from d810.mba.rules._base import VerifiableRule

    x, c1, c2 = Var("x"), Const("c1"), Const("c2")

    def descriptor(constraint):
        return SimpleNamespace(
            pattern=(x + c1) + c2,
            replacement=x,
            constraints=(constraint,),
            rule_type=VerifiableRule,
            source_name="same-rule",
            aliases=(),
            family="add",
            proof_widths=(32,),
            guarded=True,
        )

    equality = compile_canonical_pattern(
        descriptor(c1 == c2), width=32, declaration_index=0
    )
    inequality = compile_canonical_pattern(
        descriptor(c1 != c2), width=32, declaration_index=0
    )
    logical = compile_canonical_pattern(
        descriptor((c1 < c2) | (c1 == c2)), width=32, declaration_index=0
    )
    logical_and = compile_canonical_pattern(
        descriptor((c1 == c2) & (c1 <= c2)), width=32, declaration_index=0
    )
    logical_not = compile_canonical_pattern(
        descriptor(~(c1 != c2)), width=32, declaration_index=0
    )
    unsigned_less = compile_canonical_pattern(
        descriptor(c1 < c2), width=32, declaration_index=0
    )
    unsigned_greater = compile_canonical_pattern(
        descriptor(c1 > c2), width=32, declaration_index=0
    )
    equal_bindings = {
        "x": _leaf("x"),
        "c1": _constant(1),
        "c2": _constant(1),
    }
    unsigned_bindings = {
        "x": _leaf("x"),
        "c1": _constant(-1),
        "c2": _constant(0),
    }

    assert equality.constraints[0].operation == "eq"
    assert inequality.constraints[0].operation == "ne"
    assert logical.constraints[0].operation == "or"
    assert logical_and.constraints[0].operation == "and"
    assert logical_not.constraints[0].operation == "not"
    assert evaluate_frozen_constraints(
        equality.constraints, dict(equal_bindings), width=32
    )
    assert not evaluate_frozen_constraints(
        inequality.constraints, dict(equal_bindings), width=32
    )
    assert evaluate_frozen_constraints(
        logical.constraints, dict(equal_bindings), width=32
    )
    assert evaluate_frozen_constraints(
        logical_and.constraints, dict(equal_bindings), width=32
    )
    assert evaluate_frozen_constraints(
        logical_not.constraints, dict(equal_bindings), width=32
    )
    assert not evaluate_frozen_constraints(
        unsigned_less.constraints, dict(unsigned_bindings), width=32
    )
    assert evaluate_frozen_constraints(
        unsigned_greater.constraints, dict(unsigned_bindings), width=32
    )
    assert equality.semantic_fingerprint != inequality.semantic_fingerprint


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
