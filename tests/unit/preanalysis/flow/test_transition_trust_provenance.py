"""Provenance gates on transition trust evidence (d81-9q6e, review round 2).

``classify_transition_trust_for_explicit_conditional_bridge`` consults the
*typed* trust attribute before the hardened branch-ownership path, so every
weakness in the typed adapter is reachable from the production gate at
``linearized_state_dag.py:2612`` regardless of how well branch ownership is
guarded.  Before this file the typed adapter:

* coerced ``trusted`` with ``bool(...)``, so the string ``"false"`` was trusted;
* defaulted an absent ``trust_kind`` to ``EXPLICIT_PRODUCER_TRUST``, which is a
  bridge-authorising kind; and
* asked nothing at all about which producer minted the row.

The reviewer's reproduction is the first test below.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.branch_ownership import (
    BranchOwnershipOracleKind,
    BranchOwnershipProof,
    BranchOwnershipProofKind,
    branch_ownership_registration_authority,
)
from d810.analyses.control_flow.transition_trust import (
    UNSPECIFIED_TRANSITION_TRUST_PRODUCER,
    TransitionTrustAuthority,
    TransitionTrustKind,
    TransitionTrustProducerKind,
    TransitionTrustProducerRegistration,
    TransitionTrustProvenance,
    TransitionTrustResult,
    classify_transition_trust_for_explicit_conditional_bridge,
    transition_is_trusted_for_explicit_conditional_bridge,
    transition_trust_registration_authority,
    transition_trust_result_from_any,
)


def _registered_ownership_proof(**fields: object) -> BranchOwnershipProof:
    """An ownership proof its oracle registered, as an in-tree producer does."""
    registrar = branch_ownership_registration_authority()
    proof = BranchOwnershipProof(
        oracle_kind=BranchOwnershipOracleKind.MOPTRACKER, **fields
    )
    return registrar.bind(
        proof, registrar.producer(BranchOwnershipOracleKind.MOPTRACKER)
    )


def _conditional_transition(**kwargs: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "is_conditional": True,
        "provenance_chain": [(1, 2)],
    }
    values.update(kwargs)
    return SimpleNamespace(**values)


class TestReviewerReproduction:
    """The exact input the independent review reported as a bypass."""

    @staticmethod
    def _reported_transition() -> SimpleNamespace:
        return SimpleNamespace(
            is_conditional=True,
            provenance_chain=[(1, 2)],
            trust_result={"trusted": "false", "reason": "r"},
        )

    def test_string_false_trust_does_not_authorize_a_bridge(self) -> None:
        assert not transition_is_trusted_for_explicit_conditional_bridge(
            self._reported_transition()
        )

    def test_string_false_trust_is_refused_with_an_explicit_reason(self) -> None:
        result = classify_transition_trust_for_explicit_conditional_bridge(
            self._reported_transition()
        )

        assert result.trusted is False
        assert result.reason.startswith("transition_trust_unresolved_provenance:")
        assert result.evidence["trust_provenance"] == (
            TransitionTrustProvenance.MALFORMED.value
        )


class TestTrustWellFormedness:
    """``trusted`` must be a real boolean decision, never a truthy value."""

    @pytest.mark.parametrize(
        "trusted",
        ["true", "false", "", "0", 1, 0, 1.0, [], {}, object()],
    )
    def test_non_boolean_trust_is_malformed(self, trusted: object) -> None:
        result = transition_trust_result_from_any(
            {
                "trusted": trusted,
                "reason": "r",
                "trust_kind": TransitionTrustKind.EXPLICIT_PRODUCER_TRUST.value,
            }
        )

        assert result is not None
        assert result.trusted is False
        assert result.trust_provenance is TransitionTrustProvenance.MALFORMED
        assert result.authority is TransitionTrustAuthority.UNRESOLVED_PROVENANCE
        assert not result.authorizes_explicit_conditional_bridge

    @pytest.mark.parametrize("trusted", [True, False])
    def test_boolean_trust_is_well_formed(self, trusted: bool) -> None:
        result = transition_trust_result_from_any({"trusted": trusted, "reason": "r"})

        assert result is not None
        assert result.trusted is trusted
        assert result.trust_provenance is TransitionTrustProvenance.WELL_FORMED

    def test_typed_construction_refuses_a_non_boolean_trust_value(self) -> None:
        with pytest.raises(TypeError):
            TransitionTrustResult("false", "r")  # type: ignore[arg-type]


class TestAbsentTrustKindIsNotATrustingDefault:
    def test_absent_trust_kind_is_unsupported(self) -> None:
        result = transition_trust_result_from_any({"trusted": True, "reason": "r"})

        assert result is not None
        assert result.trust_kind is TransitionTrustKind.UNSUPPORTED
        assert not result.authorizes_explicit_conditional_bridge

    def test_absent_trust_kind_does_not_authorize_from_the_gate(self) -> None:
        transition = _conditional_transition(
            trust_result={"trusted": True, "reason": "r"}
        )

        assert not transition_is_trusted_for_explicit_conditional_bridge(transition)


class TestProducerRegistrationGatesGrants:
    """A grant needs a producer somebody vouches for."""

    @pytest.mark.parametrize(
        "trust_kind",
        [
            TransitionTrustKind.EXPLICIT_PRODUCER_TRUST,
            TransitionTrustKind.DYNAMIC_STATE_WRITE,
            TransitionTrustKind.BRANCH_OWNERSHIP_REAL_DATA_DEPENDENT,
        ],
    )
    def test_unregistered_producer_cannot_mint_bridge_authority(
        self, trust_kind: TransitionTrustKind
    ) -> None:
        result = transition_trust_result_from_any(
            {
                "trusted": True,
                "reason": "r",
                "trust_kind": trust_kind.value,
                "producer": "not_a_registered_producer",
            }
        )

        assert result is not None
        assert result.producer_registration is (
            TransitionTrustProducerRegistration.UNKNOWN
        )
        assert result.authority is TransitionTrustAuthority.UNRESOLVED_PROVENANCE
        assert not result.authorizes_explicit_conditional_bridge

    def test_absent_producer_is_unregistered(self) -> None:
        result = transition_trust_result_from_any(
            {
                "trusted": True,
                "reason": "r",
                "trust_kind": TransitionTrustKind.EXPLICIT_PRODUCER_TRUST.value,
            }
        )

        assert result is not None
        assert result.producer_name == UNSPECIFIED_TRANSITION_TRUST_PRODUCER
        assert result.producer_registration is (
            TransitionTrustProducerRegistration.UNKNOWN
        )
        assert not result.authorizes_explicit_conditional_bridge

    def test_explicitly_adapted_producer_may_grant(self) -> None:
        """Vouching binds a row through a binder; it is not a name argument.

        Review round 3: the classifier is no longer handed a list of names to
        trust alongside the evidence.  The owner of the binder vouches for an
        out-of-tree producer when it *builds* the binder, and binds the row
        before attaching it.
        """
        registrar = transition_trust_registration_authority(
            adapted_producers=("mop_tracker_oracle",)
        )
        transition = _conditional_transition(
            trust_result=registrar.bind(
                TransitionTrustResult(
                    True,
                    "mop_tracker_path_constant_state_write",
                    trust_kind=TransitionTrustKind.EXPLICIT_PRODUCER_TRUST,
                ),
                registrar.producer("mop_tracker_oracle"),
            )
        )

        result = classify_transition_trust_for_explicit_conditional_bridge(transition)

        assert result.producer_registration is (
            TransitionTrustProducerRegistration.EXPLICITLY_ADAPTED
        )
        assert result.authority is (
            TransitionTrustAuthority.EXPLICIT_CONDITIONAL_BRIDGE
        )
        assert result.authorizes_explicit_conditional_bridge

    def test_vouching_binds_one_row_not_a_producer_name(self) -> None:
        """Having vouched for a producer does not bless rows that claim it."""
        registrar = transition_trust_registration_authority(
            adapted_producers=("mop_tracker_oracle",)
        )
        registrar.bind(
            TransitionTrustResult(
                True,
                "r",
                trust_kind=TransitionTrustKind.EXPLICIT_PRODUCER_TRUST,
            ),
            registrar.producer("mop_tracker_oracle"),
        )
        transition = _conditional_transition(
            trust_result={
                "trusted": True,
                "reason": "r",
                "trust_kind": TransitionTrustKind.EXPLICIT_PRODUCER_TRUST.value,
                "producer": "mop_tracker_oracle",
            }
        )

        assert not transition_is_trusted_for_explicit_conditional_bridge(transition)

    def test_typed_result_instance_is_gated_too(self) -> None:
        transition = _conditional_transition(
            transition_trust=TransitionTrustResult(
                True,
                "r",
                trust_kind=TransitionTrustKind.EXPLICIT_PRODUCER_TRUST,
            )
        )

        assert not transition_is_trusted_for_explicit_conditional_bridge(transition)


class TestInTreeAdaptersNameTheirProducer:
    def test_provenance_tag_adapter_is_registered(self) -> None:
        result = classify_transition_trust_for_explicit_conditional_bridge(
            _conditional_transition(provenance_kind="global_or_state_write")
        )

        assert result.producer is TransitionTrustProducerKind.PROVENANCE_TAG_ADAPTER
        assert result.producer_registration is (
            TransitionTrustProducerRegistration.REGISTERED
        )
        assert result.authorizes_explicit_conditional_bridge

    def test_branch_ownership_adapter_is_registered(self) -> None:
        result = classify_transition_trust_for_explicit_conditional_bridge(
            _conditional_transition(
                branch_ownership_proof=_registered_ownership_proof(
                    proof_id="proof:real",
                    proof_kind=BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
                    trusted=True,
                    reason="mop_tracker_real_password_branch",
                )
            )
        )

        assert result.producer is TransitionTrustProducerKind.BRANCH_OWNERSHIP_ADAPTER
        assert result.authorizes_explicit_conditional_bridge


class TestMalformedTypedRowDoesNotFallThrough:
    """A malformed typed row is refused, not skipped.

    Skipping would let a weaker evidence source answer for a row that arrived
    malformed -- the same discipline ``branch_ownership`` uses.
    """

    def test_malformed_typed_row_blocks_a_valid_branch_ownership_proof(self) -> None:
        transition = _conditional_transition(
            trust_result={"trusted": "false", "reason": "r"},
            branch_ownership_proof=_registered_ownership_proof(
                proof_id="proof:real",
                proof_kind=BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
                trusted=True,
                reason="mop_tracker_real_password_branch",
            ),
        )

        result = classify_transition_trust_for_explicit_conditional_bridge(transition)

        assert not result.authorizes_explicit_conditional_bridge
        assert result.reason.startswith("transition_trust_unresolved_provenance:")
