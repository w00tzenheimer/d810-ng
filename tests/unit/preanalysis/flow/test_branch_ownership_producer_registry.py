"""Producer registration and trust well-formedness gate semantic authority.

Review finding F1 on d81-9q6e: ``BranchOwnershipProof.is_known_oracle`` existed
but ``authority`` never consulted it, and the duck-typed adapter coerced
``trusted`` with ``bool(value)``.  An unregistered oracle carrying the *string*
``"false"`` therefore minted ``SEMANTIC_BRIDGE`` authority, and
``transition_trust`` promoted that row into live DAG authority
(``transition_trust.py:208``).

Two independent gates are pinned here:

* trust well-formedness -- a non-``bool`` trust value is malformed provenance,
  never a truthy trust decision;
* producer registration -- only a producer this codebase enumerates, or one a
  caller explicitly adapted at the boundary, can mint ``SEMANTIC_BRIDGE`` or
  ``NONSEMANTIC_REWRITE``.

Both fail closed: the row becomes ``UNRESOLVED_PROVENANCE``, which authorizes
nothing and which ``transition_trust`` must refuse to promote.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.branch_ownership import (
    BranchOwnershipAuthority,
    BranchOwnershipOracleKind,
    BranchOwnershipProducerRegistration,
    BranchOwnershipProof,
    BranchOwnershipProofKind,
    BranchOwnershipTrustProvenance,
    branch_ownership_proof_from_any,
)
from d810.analyses.control_flow.transition_trust import (
    classify_transition_trust_for_explicit_conditional_bridge,
)

_UNREGISTERED = "not_a_registered_oracle"


def _proof_dict(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "proof_id": "p0",
        "proof_kind": "REAL_DATA_DEPENDENT",
        "trusted": True,
        "reason": "test",
        "oracle_kind": BranchOwnershipOracleKind.MOPTRACKER.value,
    }
    base.update(overrides)
    return base


def _conditional_transition(**kwargs: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "is_conditional": True,
        "provenance_chain": [(1, 2)],
    }
    values.update(kwargs)
    return SimpleNamespace(**values)


class TestReviewerReproduction:
    """The exact row the reviewer used to mint a semantic bridge."""

    def test_unregistered_oracle_with_string_trust_does_not_authorize(self) -> None:
        row = _proof_dict(oracle_kind=_UNREGISTERED, trusted="false")

        proof = branch_ownership_proof_from_any(row)

        assert proof is not None
        assert proof.is_known_oracle is False
        assert proof.trusted is False
        assert proof.trust_provenance is BranchOwnershipTrustProvenance.MALFORMED
        assert proof.authority is BranchOwnershipAuthority.UNRESOLVED_PROVENANCE
        assert proof.authorizes_semantic_branch_bridge is False
        assert proof.authorizes_nonsemantic_branch_rewrite is False

    def test_transition_trust_does_not_promote_the_reproduction_row(self) -> None:
        transition = _conditional_transition(
            branch_ownership_proof=_proof_dict(
                oracle_kind=_UNREGISTERED, trusted="false"
            )
        )

        result = classify_transition_trust_for_explicit_conditional_bridge(transition)

        assert result.authorizes_explicit_conditional_bridge is False
        assert result.trusted is False
        assert result.reason.startswith("branch_ownership_unresolved_provenance")


class TestTrustValueMustBeBoolean:
    @pytest.mark.parametrize("trusted", [True, False])
    def test_real_booleans_are_accepted(self, trusted: bool) -> None:
        proof = branch_ownership_proof_from_any(_proof_dict(trusted=trusted))

        assert proof is not None
        assert proof.trusted is trusted
        assert proof.trust_provenance is BranchOwnershipTrustProvenance.WELL_FORMED

    @pytest.mark.parametrize("trusted", ["true", "false", "", 1, 0, None, 1.0, []])
    def test_non_boolean_trust_is_malformed_provenance(self, trusted: object) -> None:
        proof = branch_ownership_proof_from_any(_proof_dict(trusted=trusted))

        assert proof is not None
        assert proof.trusted is False
        assert proof.trust_provenance is BranchOwnershipTrustProvenance.MALFORMED
        assert proof.authority is BranchOwnershipAuthority.UNRESOLVED_PROVENANCE

    @pytest.mark.parametrize("trusted", ["true", "false", 1, 0, None])
    def test_direct_construction_rejects_non_boolean_trust(
        self, trusted: object
    ) -> None:
        with pytest.raises(TypeError):
            BranchOwnershipProof(
                proof_id="p0",
                proof_kind=BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
                trusted=trusted,  # type: ignore[arg-type]
                reason="test",
            )

    def test_malformed_trust_is_not_promoted_by_transition_trust(self) -> None:
        transition = _conditional_transition(
            branch_ownership_proof=_proof_dict(trusted=1),
        )

        result = classify_transition_trust_for_explicit_conditional_bridge(transition)

        assert result.authorizes_explicit_conditional_bridge is False


class TestProducerRegistrationGatesGrants:
    @pytest.mark.parametrize(
        "kind,expected",
        [
            (
                BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
                BranchOwnershipAuthority.SEMANTIC_BRIDGE,
            ),
            (
                BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM,
                BranchOwnershipAuthority.NONSEMANTIC_REWRITE,
            ),
        ],
    )
    def test_registered_producer_keeps_its_authority(
        self, kind: BranchOwnershipProofKind, expected: BranchOwnershipAuthority
    ) -> None:
        proof = branch_ownership_proof_from_any(
            _proof_dict(proof_kind=kind.value, trusted=True)
        )

        assert proof is not None
        assert proof.producer_registration is (
            BranchOwnershipProducerRegistration.REGISTERED
        )
        assert proof.authority is expected

    @pytest.mark.parametrize(
        "kind",
        [
            BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
            BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM,
        ],
    )
    def test_unregistered_producer_abstains_even_when_trusted(
        self, kind: BranchOwnershipProofKind
    ) -> None:
        proof = branch_ownership_proof_from_any(
            _proof_dict(oracle_kind=_UNREGISTERED, proof_kind=kind.value, trusted=True)
        )

        assert proof is not None
        assert proof.trusted is True
        assert proof.producer_registration is (
            BranchOwnershipProducerRegistration.UNKNOWN
        )
        assert proof.authority is BranchOwnershipAuthority.UNRESOLVED_PROVENANCE

    def test_explicitly_adapted_producer_may_mint_authority(self) -> None:
        proof = branch_ownership_proof_from_any(
            _proof_dict(oracle_kind=_UNREGISTERED, trusted=True),
            adapted_producers=frozenset({_UNREGISTERED}),
        )

        assert proof is not None
        assert proof.producer_registration is (
            BranchOwnershipProducerRegistration.EXPLICITLY_ADAPTED
        )
        assert proof.authority is BranchOwnershipAuthority.SEMANTIC_BRIDGE

    def test_adapting_one_producer_does_not_adapt_another(self) -> None:
        proof = branch_ownership_proof_from_any(
            _proof_dict(oracle_kind="some_other_oracle", trusted=True),
            adapted_producers=frozenset({_UNREGISTERED}),
        )

        assert proof is not None
        assert proof.authority is BranchOwnershipAuthority.UNRESOLVED_PROVENANCE

    def test_unregistered_diagnostic_row_stays_diagnostic_only(self) -> None:
        """Registration gates *grants*; it does not reclassify evidence rows."""
        proof = branch_ownership_proof_from_any(
            _proof_dict(
                oracle_kind=_UNREGISTERED,
                proof_kind=BranchOwnershipProofKind.OPAQUE_ALWAYS_TRUE.value,
                trusted=True,
            )
        )

        assert proof is not None
        assert proof.authority is BranchOwnershipAuthority.DIAGNOSTIC_ONLY

    def test_untrusted_unregistered_row_stays_diagnostic_only(self) -> None:
        proof = branch_ownership_proof_from_any(
            _proof_dict(oracle_kind=_UNREGISTERED, trusted=False)
        )

        assert proof is not None
        assert proof.authority is BranchOwnershipAuthority.DIAGNOSTIC_ONLY


class TestTransitionTrustNeverPromotesAbstainedRows:
    def test_registered_trusted_row_still_authorizes(self) -> None:
        transition = _conditional_transition(
            branch_ownership_proof=_proof_dict(trusted=True)
        )

        result = classify_transition_trust_for_explicit_conditional_bridge(transition)

        assert result.authorizes_explicit_conditional_bridge is True

    def test_unregistered_trusted_row_is_refused(self) -> None:
        transition = _conditional_transition(
            branch_ownership_proof=_proof_dict(
                oracle_kind=_UNREGISTERED, trusted=True
            )
        )

        result = classify_transition_trust_for_explicit_conditional_bridge(transition)

        assert result.authorizes_explicit_conditional_bridge is False
        assert result.reason.startswith("branch_ownership_unresolved_provenance")
        assert result.evidence["producer_registration"] == (
            BranchOwnershipProducerRegistration.UNKNOWN.value
        )

    def test_an_abstained_row_does_not_fall_through_to_provenance_tag_trust(
        self,
    ) -> None:
        """A malformed row must not be skipped in favour of weaker evidence."""
        transition = _conditional_transition(
            branch_ownership_proof=_proof_dict(
                oracle_kind=_UNREGISTERED, trusted="false"
            ),
            provenance_kind="global_or_state_write",
        )

        result = classify_transition_trust_for_explicit_conditional_bridge(transition)

        assert result.authorizes_explicit_conditional_bridge is False
