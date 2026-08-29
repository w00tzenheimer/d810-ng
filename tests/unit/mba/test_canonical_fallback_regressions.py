"""Task 6 coverage for canonical MBA matcher selection and refusal paths.

These tests use the callback-local native view, so they exercise the same
catalogue boundary as the IDA adapter without inventing a second matcher or
evaluator.  The motivating Eid identity is covered by its admitted repeated
masked-operand rule with unknown ``x`` and ``y`` leaves.
"""

from __future__ import annotations

import json
from itertools import count
from dataclasses import replace
from pathlib import Path

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
from d810.mba.native_corpus_capture import (
    NativeProviderHistorySnapshot,
    _is_raw_native_identity_outcome,
    raw_identity_payload_fingerprint,
    capture_native_provider_case,
    profiles_from_native_provider_histories,
)
from d810.mba.provider_outcome import (
    MatcherOutcomeMetadata,
    MatcherSelection,
    MbaProviderKind,
    MbaProviderOutcome,
    ProviderOutcomeStatus,
)
from d810.mba.rules._base import VerifiableRule
from d810.mba.rules.catalogue import MBA_RULE_FAMILIES
from d810.mba.typed_term import TypedBvTerm


_RECEIPT_MANIFEST = Path(__file__).resolve().parents[2] / "fixtures/mba/certification_receipts.json"
_FIXTURE_RULE_IDS = count()


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


def _matcher_only_descriptor_fixture(
    name: str,
    pattern: SymbolicExpression,
    replacement: SymbolicExpression | None = None,
    *,
    proof_widths: tuple[int, ...] = (32,),
) -> CompiledMbaRule:
    """Bypass verification for a controlled descriptor used only mechanically."""
    rule_type = type(
        f"_MatcherOnlyFixture_{next(_FIXTURE_RULE_IDS)}_{name}",
        (VerifiableRule,),
        {
            "PATTERN": pattern,
            "REPLACEMENT": replacement if replacement is not None else pattern,
            "CONSTRAINTS": (),
        },
    )
    return _enroll_admitted_rule(
        CompiledMbaRule(name, (), rule_type, proof_widths, False)
    )


def test_matcher_fixture_identity_does_not_replace_production_registry_entry() -> None:
    """Mechanical descriptors retain source names without shadowing production rules."""

    production = VerifiableRule.registry["add_hackersdelightrule_2"]
    descriptor = _matcher_only_descriptor_fixture(
        "Add_HackersDelightRule_2", Var("x") + Var("y")
    )

    assert descriptor.source_name == "Add_HackersDelightRule_2"
    assert descriptor.rule_type.__name__ != descriptor.source_name
    assert VerifiableRule.registry["add_hackersdelightrule_2"] is production


def _authoritative_descriptor_fixture(family: str, name: str) -> CompiledMbaRule:
    """Use the checked-in production certificate and its source descriptor.

    The default matcher gate deliberately does not rerun the full Z3 catalogue
    compilation.  The receipt manifest is checked by the certification tests;
    this fixture binds that certified source descriptor to the matcher-only
    mechanics without presenting the fixture as a new production admission.
    """
    manifest = json.loads(_RECEIPT_MANIFEST.read_text(encoding="ascii"))
    receipt = next(
        item
        for item in manifest["receipts"]
        if item["family"] == family and item["source_name"] == name
    )
    assert receipt["status"] == "compiled"
    assert receipt["canonical_name"] == name
    rule_type = next(
        candidate
        for candidate in MBA_RULE_FAMILIES[family]
        if candidate.__name__ == name
    )
    from tools.scripts.render_mba_certification_receipts import _fingerprint

    assert receipt["semantic_fingerprint"] == _fingerprint(rule_type)
    return _matcher_only_descriptor_fixture(
        name,
        rule_type().pattern,
        rule_type().replacement,
        proof_widths=(8, 16, 32, 64),
    )


@pytest.mark.slow
def test_motivating_rule_is_currently_admitted_by_production_catalogue() -> None:
    """Keep the motivating corpus row tied to the live admission gate."""
    from d810.mba.certified_rule_compiler import (
        RuleCompilationStatus,
        compile_mba_rule_catalogue,
    )

    receipt = compile_mba_rule_catalogue().receipt_for(
        "or", "Or_EidRepeatedMaskedOperand_1"
    )
    assert receipt.status is RuleCompilationStatus.COMPILED
    assert receipt.compiled_rule is not None
    assert receipt.compiled_rule.proof_widths == (8, 16, 32, 64)


def _valid_raw_identity_payload() -> dict[str, object]:
    operand = {"type": 0, "oprops": 0, "size": 4, "valnum": 0}
    payload = {
        "opcode": 1,
        "ea": 0x401000,
        "iprops": 0,
        "l": operand,
        "r": operand.copy(),
        "d": operand.copy(),
    }
    payload.update(
        {
            "left": payload["l"],
            "right": payload["r"],
            "destination": payload["d"],
            "size": 4,
        }
    )
    return payload


def _valid_raw_outcome(
    *, payload: dict[str, object] | None = None, fingerprint: str | None = None
) -> MbaProviderOutcome:
    identity = payload or _valid_raw_identity_payload()
    return MbaProviderOutcome(
        provider=MbaProviderKind.CATALOGUE,
        status=ProviderOutcomeStatus.APPLIED,
        fingerprint=fingerprint or raw_identity_payload_fingerprint(identity),
        source_provenance=("Task6Rule",),
        metadata={"raw_native_identity": identity, "mutation_outcome": "accepted"},
        matcher=MatcherOutcomeMetadata(
            comparisons=1,
            lazy_swaps=0,
            flattened_arity=0,
            stop_reason="matched",
            selection=MatcherSelection.RAW,
            raw_comparisons=1,
            raw_lazy_swaps=0,
            backend="legacy_ast",
            fallback_comparisons=0,
            terminal_stop_reason="matched",
            native_equivalence_verdict=None,
            mutation_outcome="accepted",
        ),
    )


def _raw_payload_without(field: str) -> dict[str, object]:
    payload = _valid_raw_identity_payload()
    payload.pop(field)
    return payload


def test_raw_native_identity_is_not_a_semantic_profile_candidate() -> None:
    raw = _valid_raw_outcome()

    assert _is_raw_native_identity_outcome(raw)
    assert profiles_from_native_provider_histories((_HistoryProvider(raw),)) == ()


@pytest.mark.parametrize(
    "outcome",
    (
        _valid_raw_outcome(payload={"opcode": 1}, fingerprint="raw:" + "0" * 64),
        _valid_raw_outcome(
            payload={"opcode": 1, "unexpected": 2}, fingerprint="raw:" + "0" * 64
        ),
        _valid_raw_outcome(
            payload=_raw_payload_without("left"), fingerprint="raw:" + "0" * 64
        ),
        _valid_raw_outcome(
            payload={
                **_valid_raw_identity_payload(),
                "l": {"type": 0, "oprops": 0, "unknown": 1},
            },
            fingerprint="raw:" + "0" * 64,
        ),
        _valid_raw_outcome(fingerprint="raw:" + "0" * 64),
    ),
)
def test_malformed_or_spoofed_raw_identity_is_not_skipped(outcome) -> None:
    assert not _is_raw_native_identity_outcome(outcome)
    with pytest.raises(ValueError):
        profiles_from_native_provider_histories((_HistoryProvider(outcome),))


def _raw_contract_mutations() -> tuple[tuple[str, MbaProviderOutcome], ...]:
    valid = _valid_raw_outcome()
    assert valid.matcher is not None

    def metadata_update(**updates: object) -> MbaProviderOutcome:
        metadata = dict(valid.metadata)
        metadata.update(updates)
        return replace(valid, metadata=metadata)

    def matcher_update(**updates: object) -> MbaProviderOutcome:
        return replace(valid, matcher=replace(valid.matcher, **updates))

    return (
        ("wrong provider", replace(valid, provider=MbaProviderKind.EGRAPH)),
        ("wrong status", replace(valid, status=ProviderOutcomeStatus.UNCHANGED)),
        ("missing raw metadata", metadata_update(raw_native_identity=None)),
        ("spoofed fingerprint", replace(valid, fingerprint="raw:" + "0" * 64)),
        ("wrong matcher selection", matcher_update(selection=MatcherSelection.CANONICAL_FALLBACK)),
        ("non-matched stop", matcher_update(stop_reason="miss")),
        ("non-matched terminal stop", matcher_update(terminal_stop_reason="miss")),
        ("fallback work", matcher_update(fallback_comparisons=1)),
        ("proof present", replace(valid, proof_verdict=True)),
        ("mutation metadata missing", metadata_update(mutation_outcome=None)),
        ("mutation receipt rejected", matcher_update(mutation_outcome="rejected")),
        ("provenance missing", replace(valid, source_provenance=())),
    )


@pytest.mark.parametrize("label,outcome", _raw_contract_mutations())
def test_raw_identity_contract_rejects_each_spoofed_dimension(
    label: str, outcome: MbaProviderOutcome
) -> None:
    assert not _is_raw_native_identity_outcome(outcome), label
    with pytest.raises(ValueError):
        profiles_from_native_provider_histories((_HistoryProvider(outcome),))


def test_raw_identity_unavailable_requires_valid_scoped_history() -> None:
    missing = _HistoryProvider()
    with pytest.raises(ValueError, match="requires a validated raw outcome"):
        capture_native_provider_case(
            case_id="missing-raw",
            stratum="catalogue",
            profile=None,
            rules=(missing,),
            expected_providers=(MbaProviderKind.CATALOGUE,),
            unavailable_reason="raw_identity_profile_unavailable",
        )

    observed = _HistoryProvider(_valid_raw_outcome())
    captured = capture_native_provider_case(
        case_id="observed-raw",
        stratum="catalogue",
        profile=None,
        rules=(observed,),
        expected_providers=(MbaProviderKind.CATALOGUE,),
        unavailable_reason="raw_identity_profile_unavailable",
    )
    assert captured.outcomes[0].status is ProviderOutcomeStatus.UNAVAILABLE

    excluded_snapshot = NativeProviderHistorySnapshot({id(observed): 1})
    with pytest.raises(ValueError, match="requires a validated raw outcome"):
        capture_native_provider_case(
            case_id="excluded-raw",
            stratum="catalogue",
            profile=None,
            rules=(observed,),
            history_snapshot=excluded_snapshot,
            expected_providers=(MbaProviderKind.CATALOGUE,),
            unavailable_reason="raw_identity_profile_unavailable",
        )


def _typed_leaf(name: str, width: int = 32) -> TypedBvTerm:
    return TypedBvTerm(None, width, leaf_key=("task6", name))


def _typed_node(
    operation: str, *children: TypedBvTerm, width: int = 32
) -> TypedBvTerm:
    return TypedBvTerm(operation, width, children=children)


class _HistoryProvider:
    def __init__(self, *outcomes):
        self._outcomes = outcomes

    def provider_outcomes(self):
        return self._outcomes


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

    rule = _authoritative_descriptor_fixture("or", Or_EidRepeatedMaskedOperand_1.__name__)
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
    ("case", "rule", "candidate", "selection", "stop_reason", "expected_match"),
    (
        (
            "ac_commute",
            _authoritative_descriptor_fixture("add", "Add_HackersDelightRule_2"),
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
            _matcher_only_descriptor_fixture("AcThree", Var("x") + Var("y") + Var("z")),
            _node("add", _leaf("x"), _node("add", _leaf("y"), _leaf("z"))),
            NativeMatchSelection.RAW_POD,
            NativeMatchStopReason.MATCHED,
            True,
        ),
        (
            "add_neg_to_sub_root_change",
            _matcher_only_descriptor_fixture("AddNegToSub", Var("x") + -Var("y"), Var("x") - Var("y")),
            _node("sub", _leaf("x"), _leaf("y")),
            NativeMatchSelection.CANONICAL_FALLBACK,
            NativeMatchStopReason.MATCHED,
            True,
        ),
        (
            "double_negation",
            _matcher_only_descriptor_fixture(
                "DoubleNegation", (-(-Var("x"))) + Var("y"), Var("x") + Var("y")
            ),
            _node("add", _leaf("x"), _leaf("y")),
            NativeMatchSelection.CANONICAL_FALLBACK,
            NativeMatchStopReason.MATCHED,
            True,
        ),
        (
            "negative_modular_coefficient",
            _authoritative_descriptor_fixture("xor", "Xor_HackersDelightRule_3"),
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
    expected_match: bool,
) -> None:
    result = CompiledPatternCatalogue.from_rules((rule,)).match_root(candidate)

    assert case
    assert result.selection is selection
    assert result.stop_reason is stop_reason
    assert bool(result.matches) is expected_match
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
    rule = _matcher_only_descriptor_fixture("ExactBindings", Var("x") + -Var("y"), Var("x") - Var("y"))
    result = CompiledPatternCatalogue.from_rules((rule,)).match_root(_node("sub", x, y))

    assert result.selection is NativeMatchSelection.CANONICAL_FALLBACK
    match = result.matches[0]
    assert match.bindings.native["x"] is x
    assert match.bindings.native["y"] is y
    assert match.bindings.materialize_replacement(rule) == _typed_node(
        "sub", _typed_leaf("x"), _typed_leaf("y")
    )


@pytest.mark.parametrize(
    ("case", "rule", "candidate", "stop_reason", "expected_match"),
    (
        (
            "wildcard_absorbing_ac_submultiset",
            _matcher_only_descriptor_fixture("TwoOperandWildcard", Var("left") + Var("right")),
            _node("add", _node("add", _leaf("x"), _leaf("y")), _leaf("z")),
            NativeMatchStopReason.CANONICAL_MISS,
            False,
        ),
        (
            "repeated_masked_subtree_requires_atomization",
            _matcher_only_descriptor_fixture(
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
            _matcher_only_descriptor_fixture("CallBlocker", Var("x") + Var("y")),
            _node("call", _leaf("x"), _leaf("y")),
            NativeMatchStopReason.RAW_UNSUPPORTED,
            False,
        ),
        (
            "unsupported_load",
            _matcher_only_descriptor_fixture("LoadBlocker", Var("x") + Var("y")),
            _node("load", _leaf("x"), _leaf("y")),
            NativeMatchStopReason.RAW_UNSUPPORTED,
            False,
        ),
        (
            "unsupported_store",
            _matcher_only_descriptor_fixture("StoreBlocker", Var("x") + Var("y")),
            _node("store", _leaf("x"), _leaf("y")),
            NativeMatchStopReason.RAW_UNSUPPORTED,
            False,
        ),
        (
            "unsupported_cast",
            _matcher_only_descriptor_fixture("CastBlocker", Var("x") + Var("y")),
            _node("cast", _leaf("x"), _leaf("y")),
            NativeMatchStopReason.RAW_UNSUPPORTED,
            False,
        ),
        (
            "unsupported_shift",
            _matcher_only_descriptor_fixture("ShiftBlocker", Var("x") + Var("y")),
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
    expected_match: bool,
) -> None:
    result = CompiledPatternCatalogue.from_rules((rule,)).match_root(candidate)

    assert case
    assert bool(result.matches) is expected_match
    assert expected_match is False
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
    rule = _matcher_only_descriptor_fixture("SyntheticBinding", value + captured)
    candidate = _node("add", _leaf("x"), _node("neg", _constant(-5)))

    result = CompiledPatternCatalogue.from_rules((rule,)).match_root(candidate)

    assert result.matches == ()
    assert result.selection is NativeMatchSelection.NONE
    assert result.stop_reason is NativeMatchStopReason.PROVENANCE_REJECTED


def test_fallback_budget_exhaustion_has_no_match_and_no_proof_candidate(monkeypatch) -> None:
    from d810.mba.canonical_pattern import CanonicalPatternMatchReport

    rule = _authoritative_descriptor_fixture("add", "Add_HackersDelightRule_2")
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
