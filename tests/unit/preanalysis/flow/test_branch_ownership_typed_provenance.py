"""Typed provenance on BranchOwnershipProof (d81-9q6e, audit section 5.1).

``oracle_kind`` was a free-form string whose default,
``"preanalysis_branch_ownership"``, is also the name of a real producer. An
unrecognised or absent producer therefore presented itself as a known one, and
nothing could tell the two apart. ``trusted`` was a bare bool that consumers had
to recompose with a ``proof_kind`` string to learn what a row permits -- and
that recomposition sits on the path to a semantic DAG bridge
(``transition_trust.py:216`` -> ``linearized_state_dag.py:5430``).

These tests pin the typed replacements *and* the compatibility guarantee that
makes them safe to land: ``str``-valued enums compare, hash, and serialize
exactly like the bare strings they replace, so no consumer changes behaviour.
"""

from __future__ import annotations

import json

import pytest

from d810.analyses.control_flow.branch_ownership import (
    UNSPECIFIED_BRANCH_OWNERSHIP_ORACLE,
    BranchOwnershipAuthority,
    BranchOwnershipEvidenceKey,
    BranchOwnershipOracleKind,
    BranchOwnershipProof,
    BranchOwnershipProofKind,
    branch_ownership_proof_from_any,
)


def _proof(**overrides) -> BranchOwnershipProof:
    base = {
        "proof_id": "p0",
        "proof_kind": BranchOwnershipProofKind.UNRESOLVED,
        "trusted": False,
        "reason": "test",
        # d81-9q6e review round 2: a grant needs a named producer, so the
        # helper names one.  The *absent* producer is pinned separately by
        # TestOracleKindIsTyped below and in the producer-registry file.
        "oracle_kind": BranchOwnershipOracleKind.PREANALYSIS_BRANCH_OWNERSHIP,
    }
    base.update(overrides)
    return BranchOwnershipProof(**base)


class TestOracleKindIsTyped:
    def test_a_named_producer_is_a_member_not_a_bare_string(self) -> None:
        assert _proof().oracle_kind is (
            BranchOwnershipOracleKind.PREANALYSIS_BRANCH_OWNERSHIP
        )

    def test_the_dataclass_default_is_the_unregistered_sentinel(self) -> None:
        """An omitted producer must not restore a real producer's name.

        The default used to be ``PREANALYSIS_BRANCH_OWNERSHIP`` -- an
        enumerated member -- so omission was indistinguishable from that
        producer's own rows and passed the registration gate (review round 2).
        """
        proof = BranchOwnershipProof(
            proof_id="p0",
            proof_kind=BranchOwnershipProofKind.UNRESOLVED,
            trusted=False,
            reason="test",
        )
        assert proof.oracle_kind == UNSPECIFIED_BRANCH_OWNERSHIP_ORACLE
        assert proof.is_known_oracle is False

    def test_member_compares_equal_to_the_bare_name(self) -> None:
        """The compatibility guarantee every existing consumer relies on."""
        proof = _proof(oracle_kind=BranchOwnershipOracleKind.MOPTRACKER)
        assert proof.oracle_kind == "moptracker_branch_ownership"
        assert proof.oracle_kind in {"moptracker_branch_ownership"}
        assert {"moptracker_branch_ownership": 1}[proof.oracle_kind] == 1

    def test_oracle_kind_name_is_a_plain_string(self) -> None:
        """``str(member)`` would render ``"BranchOwnershipOracleKind.X"``."""
        proof = _proof(oracle_kind=BranchOwnershipOracleKind.Z3_JUMPFIXER)
        assert proof.oracle_kind_name == "z3_jumpfixer_branch_ownership"
        assert type(proof.oracle_kind_name) is str

    def test_diag_row_oracle_kind_is_unchanged_by_typing(self) -> None:
        typed = _proof(oracle_kind=BranchOwnershipOracleKind.DAG_EDGE_EQUIVALENCE)
        literal = _proof(oracle_kind="dag_edge_equivalence")
        assert typed.to_diag_row() == literal.to_diag_row()
        assert typed.to_diag_row()["oracle_kind"] == "dag_edge_equivalence"
        assert json.dumps(typed.to_diag_row()) == json.dumps(literal.to_diag_row())

    def test_unknown_producer_round_trips_but_is_not_known(self) -> None:
        """A third-party oracle stays usable and stops masquerading."""
        proof = _proof(oracle_kind="some_third_party_oracle")
        assert proof.oracle_kind_name == "some_third_party_oracle"
        assert proof.is_known_oracle is False
        assert proof.to_diag_row()["oracle_kind"] == "some_third_party_oracle"

    @pytest.mark.parametrize("member", list(BranchOwnershipOracleKind))
    def test_every_enumerated_producer_is_known(self, member) -> None:
        assert _proof(oracle_kind=member).is_known_oracle is True

    def test_absent_producer_falls_back_visibly(self) -> None:
        """Absent is its own name, and it is not a registered producer."""
        coerced = branch_ownership_proof_from_any(
            {"proof_id": "p", "proof_kind": "UNRESOLVED", "trusted": False,
             "reason": "r"}
        )
        assert coerced is not None
        assert coerced.oracle_kind == UNSPECIFIED_BRANCH_OWNERSHIP_ORACLE
        assert coerced.is_known_oracle is False

    def test_coercion_normalizes_a_recognised_name(self) -> None:
        coerced = branch_ownership_proof_from_any(
            {"proof_id": "p", "proof_kind": "UNRESOLVED", "trusted": False,
             "reason": "r", "oracle_kind": "switch_case_branch_ownership"}
        )
        assert coerced is not None
        assert coerced.oracle_kind is (
            BranchOwnershipOracleKind.SWITCH_CASE_BRANCH_OWNERSHIP
        )

    def test_coercion_preserves_an_unrecognised_name(self) -> None:
        coerced = branch_ownership_proof_from_any(
            {"proof_id": "p", "proof_kind": "UNRESOLVED", "trusted": False,
             "reason": "r", "oracle_kind": "not_a_registered_oracle"}
        )
        assert coerced is not None
        assert coerced.oracle_kind == "not_a_registered_oracle"
        assert coerced.is_known_oracle is False


class TestAuthorityIsOneTypedVerdict:
    """``trusted`` + ``proof_kind`` are composed in exactly one place now."""

    @pytest.mark.parametrize(
        "kind,trusted,expected",
        [
            (BranchOwnershipProofKind.REAL_DATA_DEPENDENT, True,
             BranchOwnershipAuthority.SEMANTIC_BRIDGE),
            (BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM, True,
             BranchOwnershipAuthority.NONSEMANTIC_REWRITE),
            (BranchOwnershipProofKind.OPAQUE_ALWAYS_TRUE, True,
             BranchOwnershipAuthority.DIAGNOSTIC_ONLY),
            (BranchOwnershipProofKind.OPAQUE_ALWAYS_FALSE, True,
             BranchOwnershipAuthority.DIAGNOSTIC_ONLY),
            (BranchOwnershipProofKind.EQUIVALENT_STATE_ARMS, True,
             BranchOwnershipAuthority.DIAGNOSTIC_ONLY),
            (BranchOwnershipProofKind.TERMINAL_RETURN_FRONTIER, True,
             BranchOwnershipAuthority.DIAGNOSTIC_ONLY),
            (BranchOwnershipProofKind.UNRESOLVED, True,
             BranchOwnershipAuthority.DIAGNOSTIC_ONLY),
            # Untrusted rows authorize nothing, whatever they claim to be.
            (BranchOwnershipProofKind.REAL_DATA_DEPENDENT, False,
             BranchOwnershipAuthority.DIAGNOSTIC_ONLY),
            (BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM, False,
             BranchOwnershipAuthority.DIAGNOSTIC_ONLY),
        ],
    )
    def test_authority_matrix(self, kind, trusted, expected) -> None:
        assert _proof(proof_kind=kind, trusted=trusted).authority is expected

    @pytest.mark.parametrize("kind", list(BranchOwnershipProofKind))
    @pytest.mark.parametrize("trusted", [True, False])
    def test_authority_agrees_with_the_legacy_properties(self, kind, trusted) -> None:
        """Behaviour is identical to the pre-typing bool+string composition."""
        proof = _proof(proof_kind=kind, trusted=trusted)
        legacy_bridge = (
            bool(trusted)
            and proof.proof_kind_name
            == BranchOwnershipProofKind.REAL_DATA_DEPENDENT.value
        )
        legacy_rewrite = bool(trusted) and proof.proof_kind_name in {
            BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM.value,
        }
        assert proof.authorizes_semantic_branch_bridge is legacy_bridge
        assert proof.authorizes_nonsemantic_branch_rewrite is legacy_rewrite
        assert (
            proof.authority is BranchOwnershipAuthority.SEMANTIC_BRIDGE
        ) is legacy_bridge
        assert (
            proof.authority is BranchOwnershipAuthority.NONSEMANTIC_REWRITE
        ) is legacy_rewrite

    def test_a_row_never_carries_both_authorities(self) -> None:
        """Bridging and removing are mutually exclusive by construction."""
        for kind in BranchOwnershipProofKind:
            for trusted in (True, False):
                proof = _proof(proof_kind=kind, trusted=trusted)
                assert not (
                    proof.authorizes_semantic_branch_bridge
                    and proof.authorizes_nonsemantic_branch_rewrite
                )

    def test_a_raw_string_proof_kind_still_resolves(self) -> None:
        """The duck-typed coercion path keeps working."""
        assert (
            _proof(proof_kind="REAL_DATA_DEPENDENT", trusted=True).authority
            is BranchOwnershipAuthority.SEMANTIC_BRIDGE
        )

    def test_an_unrecognised_proof_kind_authorizes_nothing(self) -> None:
        assert (
            _proof(proof_kind="INVENTED_KIND", trusted=True).authority
            is BranchOwnershipAuthority.DIAGNOSTIC_ONLY
        )


class TestEvidenceKeyIsTyped:
    """The side-effect guard no longer hinges on an undeclared literal."""

    def test_veto_key_matches_the_historical_literal(self) -> None:
        assert (
            BranchOwnershipEvidenceKey.SIDE_EFFECT_GUARD_REASON
            == "side_effect_guard_reason"
        )

    def test_veto_fires_for_an_untrusted_unresolved_row(self) -> None:
        proof = _proof(
            proof_kind=BranchOwnershipProofKind.UNRESOLVED,
            trusted=False,
            evidence={
                BranchOwnershipEvidenceKey.SIDE_EFFECT_GUARD_REASON.value: "payload"
            },
        )
        assert proof.vetoes_fallback_refinement is True

    def test_veto_does_not_fire_without_the_key(self) -> None:
        assert _proof(evidence={"other": 1}).vetoes_fallback_refinement is False

    def test_veto_does_not_fire_for_a_trusted_row(self) -> None:
        """A trusted row is a verdict, not a sticky refusal to reclassify."""
        proof = _proof(
            trusted=True,
            evidence={
                BranchOwnershipEvidenceKey.SIDE_EFFECT_GUARD_REASON.value: "payload"
            },
        )
        assert proof.vetoes_fallback_refinement is False

    def test_veto_does_not_fire_for_a_resolved_kind(self) -> None:
        proof = _proof(
            proof_kind=BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM,
            trusted=False,
            evidence={
                BranchOwnershipEvidenceKey.SIDE_EFFECT_GUARD_REASON.value: "payload"
            },
        )
        assert proof.vetoes_fallback_refinement is False
