"""Portable admission and shape-validation tests for native Z3 templates."""

from __future__ import annotations

from dataclasses import replace

import pytest

from d810.backends.mba.egglog_add_rule_compiler import compile_add_rule_catalogue
from d810.backends.mba.native_z3 import _prove_generic_native_terms
from d810.backends.mba.native_z3_proof_template import (
    NativeZ3ProofTemplate,
    TemplateValidation,
    _lower_validated_term,
    native_z3_proof_templates_for_rules,
)
from d810.mba.typed_term import TypedBvTerm, canonicalize_ac_term, fixed_shift_term


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


def test_template_validates_exact_constants_and_repeated_live_leaf_identity(
    monkeypatch,
) -> None:
    import d810.backends.mba.native_z3_proof_template as template_module

    template = NativeZ3ProofTemplate.from_compiled_rule(
        _rule("Add_HackersDelightRule_2"), width=32
    )
    assert template is not None
    original, replacement = _valid_terms()

    def forbidden_generic_rematch(*_args, **_kwargs):
        raise AssertionError("template validation must use its compiled shapes")

    monkeypatch.setattr(
        template_module,
        "apply_compiled_rule_to_term_by_identity",
        forbidden_generic_rematch,
    )

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


def test_template_proves_validated_terms_with_its_own_fresh_solver() -> None:
    template = NativeZ3ProofTemplate.from_compiled_rule(
        _rule("Add_HackersDelightRule_2"), width=32
    )
    assert template is not None
    original, replacement = _valid_terms()
    validation = template.validate_terms(original, replacement)

    assert validation is not None
    assert template.prove_validation(validation) is True


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


@pytest.mark.parametrize("operation", ["shl", "lshr", "rol", "ror"])
@pytest.mark.parametrize("width", [8, 16, 32, 64])
@pytest.mark.parametrize("count_selector", [0, 1, -1])
def test_fixed_shift_z3_lowering_matches_concrete_bitvector_semantics(
    operation: str, width: int, count_selector: int
) -> None:
    import z3

    count = (width - 1) if count_selector == -1 else count_selector
    key = ("mop", "x")
    term = fixed_shift_term(
        operation,
        width,
        TypedBvTerm(None, width, leaf_key=key),
        count,
    )
    variable = z3.BitVec("fixed_shift_x", width)
    expression = _lower_validated_term(
        term,
        variables={key: variable},
        z3=z3,
    )

    expected = {
        "shl": variable << count,
        "lshr": z3.LShR(variable, count),
        "rol": z3.RotateLeft(variable, count),
        "ror": z3.RotateRight(variable, count),
    }[operation]
    solver = z3.Solver()
    solver.add(expression != expected)
    assert solver.check() == z3.unsat

    for value in (0, 1, (1 << (width - 1)), (1 << width) - 1):
        concrete = z3.Solver()
        concrete.add(variable == value)
        assert concrete.check() == z3.sat
        model = concrete.model()
        assert model.eval(expression).as_long() == model.eval(expected).as_long()


@pytest.mark.parametrize("operation", ["shl", "lshr", "rol", "ror"])
@pytest.mark.parametrize("width", [8, 16, 32, 64])
def test_native_z3_proof_template_proves_fixed_shift_terms(
    operation: str, width: int
) -> None:
    template = NativeZ3ProofTemplate.from_compiled_rule(
        _rule("Add_HackersDelightRule_2"), width=width
    )
    assert template is not None
    term = fixed_shift_term(
        operation,
        width,
        TypedBvTerm(None, width, leaf_key=("mop", "x")),
        width - 1,
    )
    validation = TemplateValidation(
        width=width,
        original=term,
        replacement=term,
        leaf_keys=(("mop", "x"),),
    )

    assert template.prove_validation(validation)


@pytest.mark.parametrize("operation", ["shl", "lshr", "rol", "ror"])
@pytest.mark.parametrize("width", [8, 16, 32, 64])
def test_native_z3_generic_proof_uses_exact_fixed_shift_semantics(
    operation: str, width: int
) -> None:
    count = 1
    source_value = (1 << (width - 1)) | 1
    expected_value = {
        "shl": 1 << count,
        "lshr": 1 << (width - 2),
        "rol": (1 << count) | 1,
        "ror": (1 << (width - 1)) | (1 << (width - 2)),
    }[operation]
    source = fixed_shift_term(
        operation,
        width,
        TypedBvTerm(None, width, value=source_value),
        count,
    )
    expected = TypedBvTerm(None, width, value=expected_value)

    assert _prove_generic_native_terms(
        source,
        expected,
        width=width,
        assumptions={},
    ) is True


def test_proof_template_rejects_root_width_mismatch_without_raising() -> None:
    template = NativeZ3ProofTemplate.from_compiled_rule(
        _rule("Add_HackersDelightRule_2"), width=32
    )
    assert template is not None
    term = TypedBvTerm(None, 8, value=1)
    validation = TemplateValidation(
        width=32,
        original=term,
        replacement=term,
        leaf_keys=(),
    )

    assert template.prove_validation(validation) is False


@pytest.mark.parametrize(
    "malformed",
    [
        object(),
        {"width": 32, "operation": "add", "children": ()},
    ],
)
def test_proof_template_rejects_non_typed_validation_roots_without_raising(
    malformed: object,
) -> None:
    template = NativeZ3ProofTemplate.from_compiled_rule(
        _rule("Add_HackersDelightRule_2"), width=32
    )
    assert template is not None
    validation = TemplateValidation(
        width=32,
        original=malformed,  # type: ignore[arg-type]
        replacement=malformed,  # type: ignore[arg-type]
        leaf_keys=(),
    )

    assert template.prove_validation(validation) is False
    assert template.prove_validation(object()) is False  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("forged_field", "forged_value"),
    [
        ("shift_count", 1),
        ("value", 1),
        ("leaf_key", ("forged",)),
    ],
)
def test_proof_template_rejects_forged_forbidden_term_state_before_solver(
    monkeypatch,
    forged_field: str,
    forged_value: object,
) -> None:
    import z3

    template = NativeZ3ProofTemplate.from_compiled_rule(
        _rule("Add_HackersDelightRule_2"), width=32
    )
    assert template is not None
    if forged_field == "shift_count":
        forged = TypedBvTerm(None, 32, value=1)
    else:
        x = TypedBvTerm(None, 32, leaf_key=("mop", "x"))
        y = TypedBvTerm(None, 32, leaf_key=("mop", "y"))
        forged = _term("add", x, y)
    object.__setattr__(forged, forged_field, forged_value)
    validation = TemplateValidation(
        width=32,
        original=forged,
        replacement=forged,
        leaf_keys=(),
    )

    def forbidden_solver() -> None:
        raise AssertionError("forged term state must be rejected before solving")

    monkeypatch.setattr(z3, "Solver", forbidden_solver)
    assert template.prove_validation(validation) is False


def test_proof_template_does_not_swallow_solver_value_error(monkeypatch) -> None:
    import z3

    template = NativeZ3ProofTemplate.from_compiled_rule(
        _rule("Add_HackersDelightRule_2"), width=32
    )
    assert template is not None
    original, replacement = _valid_terms()
    validation = template.validate_terms(original, replacement)
    assert validation is not None

    def solver_value_error() -> None:
        raise ValueError("unexpected solver failure")

    monkeypatch.setattr(z3, "Solver", solver_value_error)
    with pytest.raises(ValueError, match="unexpected solver failure"):
        template.prove_validation(validation)
