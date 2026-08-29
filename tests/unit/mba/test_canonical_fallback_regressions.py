"""Task 6 coverage for canonical MBA matcher selection and refusal paths.

These tests use the callback-local native view, so they exercise the same
catalogue boundary as the IDA adapter without inventing a second matcher or
evaluator.  The motivating Eid identity is covered by its admitted repeated
masked-operand rule with unknown ``x`` and ``y`` leaves.
"""

from __future__ import annotations

import pytest

from d810.backends.mba.compiled_pattern_catalogue import (
    CompiledPatternCatalogue,
    NativeMatchSelection,
    NativeMatchStopReason,
)
from d810.backends.mba.native_mba_term_view import NativeMbaTermView
from d810.mba.ac_matching import AcMatchStopReason
from d810.mba.certified_rule_compiler import CompiledMbaRule, _enroll_admitted_rule
from d810.mba.dsl import Const, SymbolicExpression, Var
from d810.mba.rules._base import VerifiableRule
from d810.mba.rules.catalogue import MBA_RULE_FAMILIES
from d810.mba.typed_term import TypedBvTerm
from tests.unit.mba._compiled_rule_fixture import admitted_rule


def _leaf(name: str, width: int = 32) -> NativeMbaTermView:
    return NativeMbaTermView(None, width, leaf_key=("task6", name))


def _constant(value: int, width: int = 32) -> NativeMbaTermView:
    return NativeMbaTermView(None, width, constant_value=value)


def _node(
    operation: str,
    *children: NativeMbaTermView,
    width: int = 32,
    shift_count: int | None = None,
) -> NativeMbaTermView:
    return NativeMbaTermView(
        operation,
        width,
        children=children,
        shift_count=shift_count,
    )


def _certified_descriptor_fixture(
    name: str,
    pattern: SymbolicExpression,
    replacement: SymbolicExpression | None = None,
    *,
    proof_widths: tuple[int, ...] = (32,),
) -> CompiledMbaRule:
    """Enroll a controlled certified descriptor for matcher-only coverage."""
    rule_type = type(
        name,
        (VerifiableRule,),
        {
            "PATTERN": pattern,
            "REPLACEMENT": replacement if replacement is not None else Var("x"),
            "CONSTRAINTS": (),
        },
    )
    return _enroll_admitted_rule(
        CompiledMbaRule(name, (), rule_type, proof_widths, False)
    )


def _catalogue_rule(family: str, name: str) -> CompiledMbaRule:
    rule_type = next(
        rule for rule in MBA_RULE_FAMILIES[family] if rule.__name__ == name
    )
    return admitted_rule(rule_type, family=family)


def _typed_leaf(name: str, width: int = 32) -> TypedBvTerm:
    return TypedBvTerm(None, width, leaf_key=("task6", name))


def _typed_node(
    operation: str, *children: TypedBvTerm, width: int = 32
) -> TypedBvTerm:
    return TypedBvTerm(operation, width, children=children)


def _eid_repeated_mask_candidate() -> NativeMbaTermView:
    """Build the Eid algebra with a repeated compound operand substitution."""
    masked_y = _node("and", _leaf("y"), _constant(0xFFFFFBFB))
    return _node(
        "add",
        _node(
            "sub",
            _node("xor", _leaf("x"), masked_y),
            _node(
                "add",
                _node("and", _leaf("x"), masked_y),
                _node(
                    "mul",
                    _constant(2),
                    _node("and", masked_y, _node("bnot", _leaf("x"))),
                ),
            ),
        ),
        _node("mul", _constant(2), masked_y),
    )


def test_motivating_identity_uses_the_admitted_repeated_mask_rule() -> None:
    names = {
        rule.__name__
        for family in MBA_RULE_FAMILIES.values()
        for rule in family
    }
    assert "Or_EidRepeatedMaskedOperand_1" in names


def test_motivating_unknown_xy_shape_uses_canonical_fallback() -> None:
    from d810.mba.rules.eid import (
        Or_EidRepeatedMaskedOperand_1,
        REPEATED_OPERAND_MASK,
    )

    rule = admitted_rule(Or_EidRepeatedMaskedOperand_1, family="eid")
    catalogue = CompiledPatternCatalogue.from_rules((rule,))
    x, y = _leaf("x"), _leaf("y")
    masked_y = _node("and", y, _constant(REPEATED_OPERAND_MASK.value))
    source = _node(
        "sub",
        _node("xor", x, masked_y),
        _node(
            "add",
            _node("and", x, masked_y),
            _node("mul", _constant(2), _node("and", masked_y, _node("bnot", x))),
        ),
    )
    # Double-negating the final coefficient is a structurally different but
    # canonical-equivalent spelling.  It keeps x/y unknown and does not rely
    # on constant propagation or repeated-subtree atomization.
    candidate = _node(
        "add",
        source,
        _node(
            "neg",
            _node("neg", _node("mul", _constant(2), masked_y)),
        ),
    )

    result = catalogue.match_root(candidate)

    assert result.selection is NativeMatchSelection.CANONICAL_FALLBACK
    assert result.stop_reason is NativeMatchStopReason.MATCHED
    assert bool(result.matches) is True
    assert tuple(match.rule.source_name for match in result.matches) == (
        "Or_EidRepeatedMaskedOperand_1",
    )
    assert result.matches[0].bindings.native["x_0"] is x
    assert result.matches[0].bindings.native["x_1"] is y
    assert result.fallback_comparisons > 0


@pytest.mark.parametrize(
    ("case", "rule", "candidate", "selection", "stop_reason", "proof"),
    (
        (
            "ac_commute",
            _catalogue_rule("add", "Add_HackersDelightRule_2"),
            _node(
                "add",
                _node("mul", _constant(2), _node("and", _leaf("y"), _leaf("x"))),
                _node("xor", _leaf("y"), _leaf("x")),
            ),
            NativeMatchSelection.RAW_POD,
            NativeMatchStopReason.MATCHED,
            True,
        ),
        (
            "ac_associate_equal_arity",
            _certified_descriptor_fixture("AcThree", Var("x") + Var("y") + Var("z")),
            _node("add", _leaf("x"), _node("add", _leaf("y"), _leaf("z"))),
            NativeMatchSelection.RAW_POD,
            NativeMatchStopReason.MATCHED,
            True,
        ),
        (
            "add_neg_to_sub_root_change",
            _certified_descriptor_fixture("AddNegToSub", Var("x") + -Var("y"), Var("x") - Var("y")),
            _node("sub", _leaf("x"), _leaf("y")),
            NativeMatchSelection.CANONICAL_FALLBACK,
            NativeMatchStopReason.MATCHED,
            True,
        ),
        (
            "double_negation",
            _certified_descriptor_fixture(
                "DoubleNegation", (-(-Var("x"))) + Var("y"), Var("x") + Var("y")
            ),
            _node("add", _leaf("x"), _leaf("y")),
            NativeMatchSelection.CANONICAL_FALLBACK,
            NativeMatchStopReason.MATCHED,
            True,
        ),
        (
            "negative_modular_coefficient",
            _catalogue_rule("xor", "Xor_HackersDelightRule_3"),
            _node(
                "add",
                _node("add", _leaf("x"), _leaf("y")),
                _node("mul", _constant(-2), _node("and", _leaf("x"), _leaf("y"))),
            ),
            NativeMatchSelection.CANONICAL_FALLBACK,
            NativeMatchStopReason.MATCHED,
            True,
        ),
    ),
)
def test_positive_canonical_shapes_have_stable_selection_receipts(
    case: str,
    rule: CompiledMbaRule,
    candidate: NativeMbaTermView,
    selection: NativeMatchSelection,
    stop_reason: NativeMatchStopReason,
    proof: bool,
) -> None:
    result = CompiledPatternCatalogue.from_rules((rule,)).match_root(candidate)

    assert case
    assert result.selection is selection
    assert result.stop_reason is stop_reason
    assert bool(result.matches) is proof
    assert result.matches
    assert tuple(match.rule for match in result.matches) == (rule,) * len(result.matches)
    assert result.fallback_comparisons == (
        0 if selection is NativeMatchSelection.RAW_POD else result.fallback_comparisons
    )
    if selection is NativeMatchSelection.CANONICAL_FALLBACK:
        assert result.comparisons == 0
        assert result.fallback_comparisons > 0


def test_fallback_replacement_is_materialized_from_exact_source_bindings() -> None:
    x, y = _leaf("x"), _leaf("y")
    rule = _certified_descriptor_fixture("ExactBindings", Var("x") + -Var("y"), Var("x") - Var("y"))
    result = CompiledPatternCatalogue.from_rules((rule,)).match_root(_node("sub", x, y))

    assert result.selection is NativeMatchSelection.CANONICAL_FALLBACK
    match = result.matches[0]
    assert match.bindings.native["x"] is x
    assert match.bindings.native["y"] is y
    assert match.bindings.materialize_replacement(rule) == _typed_node(
        "sub", _typed_leaf("x"), _typed_leaf("y")
    )


@pytest.mark.parametrize(
    ("case", "rule", "candidate", "stop_reason", "proof"),
    (
        (
            "wildcard_absorbing_ac_submultiset",
            _certified_descriptor_fixture("TwoOperandWildcard", Var("left") + Var("right")),
            _node("add", _node("add", _leaf("x"), _leaf("y")), _leaf("z")),
            NativeMatchStopReason.CANONICAL_MISS,
            False,
        ),
        (
            "repeated_masked_subtree_requires_atomization",
            _certified_descriptor_fixture(
                "GeneralEidAtomicOperand",
                (Var("x") ^ Var("y"))
                - (
                    (Var("x") & Var("y"))
                    + Const("two", 2) * (Var("y") & ~Var("x"))
                )
                + Const("two", 2) * Var("y"),
                Var("x") | Var("y"),
            ),
            _eid_repeated_mask_candidate(),
            NativeMatchStopReason.CANONICAL_MISS,
            False,
        ),
        (
            "unsupported_call",
            _certified_descriptor_fixture("CallBlocker", Var("x") + Var("y")),
            _node("call", _leaf("x"), _leaf("y")),
            NativeMatchStopReason.RAW_UNSUPPORTED,
            False,
        ),
        (
            "unsupported_load",
            _certified_descriptor_fixture("LoadBlocker", Var("x") + Var("y")),
            _node("load", _leaf("x"), _leaf("y")),
            NativeMatchStopReason.RAW_UNSUPPORTED,
            False,
        ),
        (
            "unsupported_store",
            _certified_descriptor_fixture("StoreBlocker", Var("x") + Var("y")),
            _node("store", _leaf("x"), _leaf("y")),
            NativeMatchStopReason.RAW_UNSUPPORTED,
            False,
        ),
        (
            "unsupported_cast",
            _certified_descriptor_fixture("CastBlocker", Var("x") + Var("y")),
            _node("cast", _leaf("x"), _leaf("y")),
            NativeMatchStopReason.RAW_UNSUPPORTED,
            False,
        ),
        (
            "unsupported_shift",
            _certified_descriptor_fixture("ShiftBlocker", Var("x") + Var("y")),
            _node("shl", _leaf("x"), width=32, shift_count=5),
            NativeMatchStopReason.CANONICAL_MISS,
            False,
        ),
    ),
)
def test_negative_shapes_are_explicit_no_match_receipts(
    case: str,
    rule: CompiledMbaRule,
    candidate: NativeMbaTermView,
    stop_reason: NativeMatchStopReason,
    proof: bool,
) -> None:
    result = CompiledPatternCatalogue.from_rules((rule,)).match_root(candidate)

    assert case
    assert bool(result.matches) is proof
    assert proof is False
    assert result.matches == ()
    assert result.selection is NativeMatchSelection.NONE
    assert result.stop_reason is stop_reason


def test_mixed_width_native_view_is_rejected_before_canonical_fallback() -> None:
    with pytest.raises(ValueError, match="same width"):
        _node("add", _leaf("x", 32), _leaf("y", 16), width=32)


def test_ambiguous_shift_is_rejected_before_matching() -> None:
    with pytest.raises(ValueError, match="shift_count"):
        _node("shl", _leaf("x"), shift_count=None)


def test_synthetic_binding_path_is_provenance_rejected() -> None:
    captured = Const("captured")
    value = Var("value")
    rule = _certified_descriptor_fixture("SyntheticBinding", value + captured, captured)
    candidate = _node("add", _leaf("x"), _node("neg", _constant(-5)))

    result = CompiledPatternCatalogue.from_rules((rule,)).match_root(candidate)

    assert result.matches == ()
    assert result.selection is NativeMatchSelection.NONE
    assert result.stop_reason is NativeMatchStopReason.PROVENANCE_REJECTED


def test_fallback_budget_exhaustion_has_no_match_and_no_proof_candidate(monkeypatch) -> None:
    from d810.mba.canonical_pattern import CanonicalPatternMatchReport

    rule = _catalogue_rule("add", "Add_HackersDelightRule_2")
    catalogue = CompiledPatternCatalogue.from_rules((rule,))
    candidate = _node("sub", _leaf("x"), _leaf("y"))

    def exhausted(_self, _candidate, *, comparison_budget):
        assert comparison_budget == 64
        return CanonicalPatternMatchReport(
            (), 64, 0, 0, AcMatchStopReason.COMPARISON_BUDGET
        )

    monkeypatch.setattr(CompiledPatternCatalogue, "match_canonical_root", exhausted)
    result = catalogue.match_root(candidate)

    assert result.matches == ()
    assert result.selection is NativeMatchSelection.NONE
    assert result.stop_reason is NativeMatchStopReason.CANONICAL_BUDGET
    assert result.canonical_budget_exceeded is True
    assert result.candidate_term is not None
