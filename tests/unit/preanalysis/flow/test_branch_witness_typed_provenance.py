"""Typed provenance on the branch-witness model (d81-9q6e, audit section 5.2).

Three free-form string fields carried proof state through this module:

* ``predicate``, documented only by an inline ``# "eq" or "ne"`` comment;
* ``evidence``, whose default ``"validated_against_current_cfg"`` is a *claim*
  that validation happened;
* ``BranchWitnessAbstain.reason``, a 22-value vocabulary that at least one
  consumer branches on by string equality
  (``minimal_unflatten_emit.py:956`` unlocks a multi-entry fallback when the
  reason is exactly ``"selected_successor_not_dispatcher_endpoint"``).

The last one is why this matters: a typo in an undeclared 22-value string
vocabulary was a silent behaviour change, not a type error.

These tests pin the enums *and* the compatibility contract that makes the
change safe -- ``str``-valued members compare and serialize exactly like the
literals they replace, so every existing consumer, including the ones in files
this change may not touch, is unaffected.
"""

from __future__ import annotations

import dataclasses

import pytest

from d810.analyses.control_flow.branch_witness import (
    BranchPredicateKind,
    BranchWitnessAbstain,
    BranchWitnessAbstainReason,
    BranchWitnessEvidenceKind,
    BranchWitnessProofKind,
    BranchWitnessRow,
    ExactBranchWitness,
    _is_known_predicate,
)

#: The exact literal ``minimal_unflatten_emit.py:956`` tests for. Hard-coded
#: here on purpose: this test must fail if the member's value ever drifts.
_MULTI_ENTRY_FALLBACK_LITERAL = "selected_successor_not_dispatcher_endpoint"


def _row(**overrides) -> BranchWitnessRow:
    base = {
        "state": 0x1234,
        "compare_block": 10,
        "predicate": BranchPredicateKind.EQ,
        "compare_const": 0x1234,
        "selected_successor": 11,
        "rejected_successors": (12,),
    }
    base.update(overrides)
    return BranchWitnessRow(**base)


def _witness(**overrides) -> ExactBranchWitness:
    base = {
        "state": 0x1234,
        "compare_block": 10,
        "predicate": BranchPredicateKind.EQ,
        "selected_successor": 11,
        "rejected_successors": (12,),
        "target_block": 11,
        "proof_kind": BranchWitnessProofKind.STATIC_EQUALITY_CHAIN,
    }
    base.update(overrides)
    return ExactBranchWitness(**base)


class TestAbstainReasonIsTyped:
    def test_default_is_a_member(self) -> None:
        assert BranchWitnessAbstain().reason is BranchWitnessAbstainReason.ABSTAIN

    def test_multi_entry_fallback_literal_is_preserved(self) -> None:
        """The one abstain reason a consumer branches on by string equality.

        ``minimal_unflatten_emit.py:956`` is outside this change's scope, so
        the member's *value* is the contract, not its name.
        """
        member = BranchWitnessAbstainReason.SELECTED_SUCCESSOR_NOT_DISPATCHER_ENDPOINT
        assert member.value == _MULTI_ENTRY_FALLBACK_LITERAL
        assert member == _MULTI_ENTRY_FALLBACK_LITERAL
        abstain = BranchWitnessAbstain(member)
        assert abstain.reason == _MULTI_ENTRY_FALLBACK_LITERAL

    def test_a_dynamic_string_reason_still_constructs(self) -> None:
        """External callers build abstains from strings they compute."""
        abstain = BranchWitnessAbstain("some_caller_specific_reason")
        assert abstain.reason == "some_caller_specific_reason"
        assert abstain.reason_name == "some_caller_specific_reason"

    def test_reason_name_is_a_plain_string(self) -> None:
        """``str(member)`` would render ``"BranchWitnessAbstainReason.X"``."""
        abstain = BranchWitnessAbstain(BranchWitnessAbstainReason.COMPARE_CHAIN_CYCLE)
        assert abstain.reason_name == "compare_chain_cycle"
        assert type(abstain.reason_name) is str

    @pytest.mark.parametrize("member", list(BranchWitnessAbstainReason))
    def test_every_member_value_is_a_lowercase_identifier(self, member) -> None:
        assert member.value.islower()
        assert member.value.isidentifier()

    def test_member_values_are_unique(self) -> None:
        values = [m.value for m in BranchWitnessAbstainReason]
        assert len(values) == len(set(values))


class TestPredicateIsTyped:
    def test_members_match_the_historical_literals(self) -> None:
        assert BranchPredicateKind.EQ == "eq"
        assert BranchPredicateKind.NE == "ne"

    @pytest.mark.parametrize("value", ["eq", "ne"])
    def test_known_predicates_are_accepted_as_strings(self, value) -> None:
        assert _is_known_predicate(value) is True

    @pytest.mark.parametrize("member", list(BranchPredicateKind))
    def test_known_predicates_are_accepted_as_members(self, member) -> None:
        assert _is_known_predicate(member) is True

    @pytest.mark.parametrize("value", ["sgt", "ult", "", "EQ", "jz"])
    def test_unknown_predicates_are_rejected(self, value) -> None:
        assert _is_known_predicate(value) is False

    def test_predicate_name_is_a_plain_string(self) -> None:
        assert _row(predicate=BranchPredicateKind.NE).predicate_name == "ne"
        assert type(_row().predicate_name) is str

    def test_a_raw_string_predicate_still_works(self) -> None:
        assert _row(predicate="ne").predicate_name == "ne"
        assert _witness(predicate="ne").predicate_name == "ne"


class TestEvidenceIsTyped:
    def test_default_is_a_member_matching_the_historical_literal(self) -> None:
        assert _row().evidence is (
            BranchWitnessEvidenceKind.VALIDATED_AGAINST_CURRENT_CFG
        )
        assert _row().evidence == "validated_against_current_cfg"
        assert _witness().evidence == "validated_against_current_cfg"

    def test_provider_corroboration_is_enumerated(self) -> None:
        """``branch_witness_provider.py:260`` uses this second literal."""
        assert (
            BranchWitnessEvidenceKind.LOCAL_INDIRECT_STATE_STORE_COMPARE
            == "local_indirect_state_store_compare"
        )

    def test_evidence_name_is_a_plain_string(self) -> None:
        assert _row().evidence_name == "validated_against_current_cfg"
        assert type(_row().evidence_name) is str

    def test_a_raw_string_evidence_still_works(self) -> None:
        assert _row(evidence="hand_written").evidence_name == "hand_written"


class TestFieldTypingIsBackwardsCompatible:
    """The union-with-``str`` contract every out-of-scope consumer relies on."""

    @pytest.mark.parametrize(
        "cls,field,members",
        [
            (BranchWitnessRow, "predicate", BranchPredicateKind),
            (BranchWitnessRow, "evidence", BranchWitnessEvidenceKind),
            (ExactBranchWitness, "predicate", BranchPredicateKind),
            (ExactBranchWitness, "evidence", BranchWitnessEvidenceKind),
            (BranchWitnessAbstain, "reason", BranchWitnessAbstainReason),
        ],
    )
    def test_field_accepts_both_a_member_and_a_bare_string(
        self, cls, field, members
    ) -> None:
        annotation = {
            f.name: f.type for f in dataclasses.fields(cls)
        }[field]
        assert "str" in str(annotation), (
            f"{cls.__name__}.{field} must stay assignable from a bare str"
        )
        assert members.__name__ in str(annotation)

    @pytest.mark.parametrize(
        "members",
        [BranchPredicateKind, BranchWitnessEvidenceKind, BranchWitnessAbstainReason],
    )
    def test_members_are_str_subclasses(self, members) -> None:
        """Non-negotiable: consumers compare these against bare strings."""
        assert issubclass(members, str)
        for member in members:
            assert member == member.value
            assert member in {member.value}
            assert {member.value: 1}[member] == 1
