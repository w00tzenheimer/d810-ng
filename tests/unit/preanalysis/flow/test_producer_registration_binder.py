"""Evidence may not authenticate its own producer (d81-9q6e review round 3).

Rounds 1 and 2 gated grants on *producer registration*, but registration was
still derived from the row itself:

* a raw dict/duck-typed row that merely **claimed** a recognized
  ``oracle_kind`` was normalised to an enumerated member and therefore
  reported ``REGISTERED`` -- so any foreign row could name
  ``moptracker_branch_ownership`` and mint ``SEMANTIC_BRIDGE``;
* a directly constructed proof/trust object could set the
  producer-controlled boolean ``adapted_producer=True`` and register itself;
* the ``unspecified_producer`` sentinel -- the name a row carries when it
  never named a producer at all -- could be vouched for after the fact.

The rule pinned here: a producer name on a row is a **claim**.  Registration
is *minted* by an authority-owned binder from a producer object the binder
itself recognizes, and is carried as an unforgeable token.  Rows, forged
tokens and direct constructions get no registration, so they cannot mint
bridge authority.
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.branch_ownership import (
    UNSPECIFIED_BRANCH_OWNERSHIP_ORACLE,
    BranchOwnershipAuthority,
    BranchOwnershipOracleKind,
    BranchOwnershipProducerRegistration,
    BranchOwnershipProof,
    BranchOwnershipProofKind,
    branch_ownership_proof_from_any,
    branch_ownership_registration_authority,
)
from d810.analyses.control_flow.producer_registration import (
    UNSPECIFIED_PRODUCER,
    ProducerIdentity,
    ProducerRegistration,
    ProducerRegistrationToken,
)
from d810.analyses.control_flow.transition_trust import (
    UNSPECIFIED_TRANSITION_TRUST_PRODUCER,
    TransitionTrustAuthority,
    TransitionTrustKind,
    TransitionTrustProducerKind,
    TransitionTrustProducerRegistration,
    TransitionTrustResult,
    classify_transition_trust_for_explicit_conditional_bridge,
    transition_trust_registration_authority,
    transition_trust_result_from_any,
)

_GRANT_PROOF_KINDS = (
    BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
    BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM,
)


def _spoofed_proof_dict(oracle_kind: object, **overrides: object) -> dict[str, object]:
    """A foreign row that claims ``oracle_kind`` produced it."""
    row: dict[str, object] = {
        "proof_id": "spoof",
        "proof_kind": BranchOwnershipProofKind.REAL_DATA_DEPENDENT.value,
        "trusted": True,
        "reason": "claims_a_producer_it_never_had",
        "oracle_kind": oracle_kind,
    }
    row.update(overrides)
    return row


def _spoofed_trust_dict(producer: object, **overrides: object) -> dict[str, object]:
    """A foreign trust row that claims ``producer`` minted it."""
    row: dict[str, object] = {
        "trusted": True,
        "reason": "claims_a_producer_it_never_had",
        "trust_kind": TransitionTrustKind.EXPLICIT_PRODUCER_TRUST.value,
        "producer": producer,
    }
    row.update(overrides)
    return row


def _conditional_transition(**kwargs: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "is_conditional": True,
        "provenance_chain": [(1, 2)],
    }
    values.update(kwargs)
    return SimpleNamespace(**values)


class TestRawRowMayNotAuthenticateItsProducer:
    """(a) A raw row that claims a recognized producer name is still a claim."""

    def test_reviewer_reproduction_claimed_name_does_not_mint_semantic_bridge(
        self,
    ) -> None:
        proof = branch_ownership_proof_from_any(
            _spoofed_proof_dict(BranchOwnershipOracleKind.MOPTRACKER.value)
        )

        assert proof is not None
        assert proof.trusted is True
        assert proof.producer_registration is (
            BranchOwnershipProducerRegistration.UNKNOWN
        )
        assert proof.authority is BranchOwnershipAuthority.UNRESOLVED_PROVENANCE
        assert proof.authorizes_semantic_branch_bridge is False

    def test_reviewer_reproduction_is_refused_by_transition_trust(self) -> None:
        transition = _conditional_transition(
            branch_ownership_proof=_spoofed_proof_dict(
                BranchOwnershipOracleKind.MOPTRACKER.value
            )
        )

        result = classify_transition_trust_for_explicit_conditional_bridge(transition)

        assert result.authorizes_explicit_conditional_bridge is False

    @pytest.mark.parametrize("kind", list(BranchOwnershipOracleKind))
    @pytest.mark.parametrize("proof_kind", _GRANT_PROOF_KINDS)
    def test_no_recognized_producer_name_can_be_spoofed_by_a_raw_row(
        self,
        kind: BranchOwnershipOracleKind,
        proof_kind: BranchOwnershipProofKind,
    ) -> None:
        proof = branch_ownership_proof_from_any(
            _spoofed_proof_dict(kind.value, proof_kind=proof_kind.value)
        )

        assert proof is not None
        assert proof.producer_registration is (
            BranchOwnershipProducerRegistration.UNKNOWN
        )
        assert proof.authority is BranchOwnershipAuthority.UNRESOLVED_PROVENANCE

    @pytest.mark.parametrize("kind", list(BranchOwnershipOracleKind))
    def test_a_duck_typed_object_cannot_spoof_a_producer_either(
        self, kind: BranchOwnershipOracleKind
    ) -> None:
        proof = branch_ownership_proof_from_any(
            SimpleNamespace(**_spoofed_proof_dict(kind.value))
        )

        assert proof is not None
        assert proof.authority is BranchOwnershipAuthority.UNRESOLVED_PROVENANCE

    @pytest.mark.parametrize("producer", list(TransitionTrustProducerKind))
    def test_no_recognized_trust_producer_can_be_spoofed_by_a_raw_row(
        self, producer: TransitionTrustProducerKind
    ) -> None:
        result = transition_trust_result_from_any(_spoofed_trust_dict(producer.value))

        assert result is not None
        assert result.producer_registration is (
            TransitionTrustProducerRegistration.UNKNOWN
        )
        assert result.authority is TransitionTrustAuthority.UNRESOLVED_PROVENANCE
        assert result.authorizes_explicit_conditional_bridge is False

    @pytest.mark.parametrize("producer", list(TransitionTrustProducerKind))
    def test_a_duck_typed_trust_row_cannot_spoof_a_producer_either(
        self, producer: TransitionTrustProducerKind
    ) -> None:
        result = transition_trust_result_from_any(
            SimpleNamespace(**_spoofed_trust_dict(producer.value))
        )

        assert result is not None
        assert result.authority is TransitionTrustAuthority.UNRESOLVED_PROVENANCE

    @pytest.mark.parametrize("producer", list(TransitionTrustProducerKind))
    def test_a_spoofing_trust_row_is_refused_by_the_production_gate(
        self, producer: TransitionTrustProducerKind
    ) -> None:
        transition = _conditional_transition(
            transition_trust=_spoofed_trust_dict(producer.value)
        )

        result = classify_transition_trust_for_explicit_conditional_bridge(transition)

        assert result.authorizes_explicit_conditional_bridge is False


class TestVouchingByNameIsGoneFromTheBoundary:
    """A coercion boundary may not be handed a list of names to trust.

    Round 2 accepted ``adapted_producers=`` on the *coercion* helpers and on
    the classifier, so a caller vouched for a name it had been handed
    alongside the evidence.  Vouching now happens where a binder is built,
    from a producer object that binder owns.
    """

    def test_branch_ownership_coercion_takes_no_adapted_producers(self) -> None:
        with pytest.raises(TypeError):
            branch_ownership_proof_from_any(  # type: ignore[call-arg]
                _spoofed_proof_dict("out_of_tree_oracle"),
                adapted_producers=("out_of_tree_oracle",),
            )

    def test_transition_trust_coercion_takes_no_adapted_producers(self) -> None:
        with pytest.raises(TypeError):
            transition_trust_result_from_any(  # type: ignore[call-arg]
                _spoofed_trust_dict("out_of_tree_oracle"),
                adapted_producers=("out_of_tree_oracle",),
            )

    def test_the_classifier_takes_no_adapted_producers(self) -> None:
        transition = _conditional_transition(
            transition_trust=_spoofed_trust_dict("out_of_tree_oracle")
        )

        classify = classify_transition_trust_for_explicit_conditional_bridge
        with pytest.raises(TypeError):
            classify(  # type: ignore[call-arg]
                transition,
                adapted_producers=("out_of_tree_oracle",),
            )


class TestDirectConstructionMayNotSelfRegister:
    """(b) A directly constructed object cannot vouch for itself."""

    @pytest.mark.parametrize("kind", list(BranchOwnershipOracleKind))
    def test_a_constructed_proof_naming_a_producer_does_not_grant(
        self, kind: BranchOwnershipOracleKind
    ) -> None:
        proof = BranchOwnershipProof(
            proof_id="direct",
            proof_kind=BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
            trusted=True,
            reason="constructed_by_hand",
            oracle_kind=kind,
        )

        assert proof.authority is BranchOwnershipAuthority.UNRESOLVED_PROVENANCE
        assert proof.authorizes_semantic_branch_bridge is False

    def test_reviewer_reproduction_a_constructed_proof_cannot_set_an_adapted_flag(
        self,
    ) -> None:
        """The producer-controlled boolean must not exist at all."""
        with pytest.raises(TypeError):
            BranchOwnershipProof(  # type: ignore[call-arg]
                proof_id="direct",
                proof_kind=BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
                trusted=True,
                reason="constructed_by_hand",
                oracle_kind="out_of_tree_oracle",
                adapted_producer=True,
            )

    @pytest.mark.parametrize("producer", list(TransitionTrustProducerKind))
    def test_a_constructed_trust_row_naming_an_adapter_does_not_grant(
        self, producer: TransitionTrustProducerKind
    ) -> None:
        row = TransitionTrustResult(
            True,
            "constructed_by_hand",
            trust_kind=TransitionTrustKind.EXPLICIT_PRODUCER_TRUST,
            producer=producer,
        )

        assert row.authority is TransitionTrustAuthority.UNRESOLVED_PROVENANCE
        assert row.authorizes_explicit_conditional_bridge is False

    def test_reviewer_reproduction_a_constructed_trust_row_cannot_set_an_adapted_flag(
        self,
    ) -> None:
        with pytest.raises(TypeError):
            TransitionTrustResult(  # type: ignore[call-arg]
                True,
                "constructed_by_hand",
                trust_kind=TransitionTrustKind.EXPLICIT_PRODUCER_TRUST,
                producer="out_of_tree_oracle",
                adapted_producer=True,
            )

    def test_a_constructed_trust_row_is_refused_by_the_production_gate(self) -> None:
        transition = _conditional_transition(
            transition_trust=TransitionTrustResult(
                True,
                "constructed_by_hand",
                trust_kind=TransitionTrustKind.EXPLICIT_PRODUCER_TRUST,
                producer=TransitionTrustProducerKind.PROVENANCE_TAG_ADAPTER,
            )
        )

        result = classify_transition_trust_for_explicit_conditional_bridge(transition)

        assert result.authorizes_explicit_conditional_bridge is False


class TestAHandBuiltRegistrationIsRefused:
    """(b, continued) The registration field only accepts a minted token."""

    @pytest.mark.parametrize(
        "forged",
        [
            True,
            1,
            "registered",
            {"producer_name": "moptracker_branch_ownership"},
            SimpleNamespace(
                producer_name="moptracker_branch_ownership",
                registration=ProducerRegistration.REGISTERED,
                domain="branch_ownership",
                nonce=object(),
            ),
        ],
    )
    def test_a_forged_branch_ownership_registration_is_refused(
        self, forged: object
    ) -> None:
        with pytest.raises(TypeError):
            BranchOwnershipProof(
                proof_id="direct",
                proof_kind=BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
                trusted=True,
                reason="constructed_by_hand",
                oracle_kind=BranchOwnershipOracleKind.MOPTRACKER,
                registration=forged,  # type: ignore[arg-type]
            )

    @pytest.mark.parametrize("forged", [True, 1, "registered", {"a": 1}])
    def test_a_forged_transition_trust_registration_is_refused(
        self, forged: object
    ) -> None:
        with pytest.raises(TypeError):
            TransitionTrustResult(
                True,
                "constructed_by_hand",
                trust_kind=TransitionTrustKind.EXPLICIT_PRODUCER_TRUST,
                producer=TransitionTrustProducerKind.BRANCH_OWNERSHIP_ADAPTER,
                registration=forged,  # type: ignore[arg-type]
            )

    def test_a_token_cannot_be_constructed_without_a_binder_nonce(self) -> None:
        with pytest.raises(TypeError):
            ProducerRegistrationToken(
                producer_name="moptracker_branch_ownership",
                registration=ProducerRegistration.REGISTERED,
                domain="branch_ownership",
                nonce=object(),  # type: ignore[arg-type]
            )


class TestATokenIsScopedToItsProducerAndRecordFamily:
    """A minted token vouches for one producer in one record family."""

    def test_rewriting_the_producer_field_drops_the_registration(self) -> None:
        registrar = branch_ownership_registration_authority()
        bound = registrar.bind(
            BranchOwnershipProof(
                proof_id="bound",
                proof_kind=BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
                trusted=True,
                reason="registered_by_its_oracle",
                oracle_kind=BranchOwnershipOracleKind.MOPTRACKER,
            ),
            registrar.producer(BranchOwnershipOracleKind.MOPTRACKER),
        )
        assert bound.authority is BranchOwnershipAuthority.SEMANTIC_BRIDGE

        stolen = replace(bound, oracle_kind=BranchOwnershipOracleKind.Z3_JUMPFIXER)

        assert stolen.producer_registration is (
            BranchOwnershipProducerRegistration.UNKNOWN
        )
        assert stolen.authority is BranchOwnershipAuthority.UNRESOLVED_PROVENANCE

    def test_a_token_from_another_record_family_does_not_carry_over(self) -> None:
        trust_registrar = transition_trust_registration_authority(
            adapted_producers=(BranchOwnershipOracleKind.MOPTRACKER.value,)
        )
        foreign_token = trust_registrar.mint(
            trust_registrar.producer(BranchOwnershipOracleKind.MOPTRACKER.value)
        )

        proof = BranchOwnershipProof(
            proof_id="cross_domain",
            proof_kind=BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
            trusted=True,
            reason="token_minted_for_another_record_family",
            oracle_kind=BranchOwnershipOracleKind.MOPTRACKER,
            registration=foreign_token,
        )

        assert proof.producer_registration is (
            BranchOwnershipProducerRegistration.UNKNOWN
        )
        assert proof.authority is BranchOwnershipAuthority.UNRESOLVED_PROVENANCE

    def test_a_look_alike_identity_built_outside_the_binder_is_refused(self) -> None:
        registrar = branch_ownership_registration_authority()
        look_alike = ProducerIdentity(
            name=BranchOwnershipOracleKind.MOPTRACKER.value,
            record_value=BranchOwnershipOracleKind.MOPTRACKER,
        )

        assert registrar.recognizes(look_alike) is False
        with pytest.raises(LookupError):
            registrar.mint(look_alike)

    def test_one_binder_does_not_honour_another_binders_producer(self) -> None:
        left = branch_ownership_registration_authority()
        right = branch_ownership_registration_authority()

        with pytest.raises(LookupError):
            left.mint(right.producer(BranchOwnershipOracleKind.MOPTRACKER))


class TestAbsenceIsNeverVouchedFor:
    """(c) The unspecified sentinel can never be adapted after the fact.

    Inverted in review round 3.  Round 2 let a caller vouch for the *sentinel*,
    so a row that named no producer at all could be adapted after the fact --
    exactly the shape this gate exists to refuse.
    """

    def test_no_identity_can_be_built_from_the_sentinel(self) -> None:
        with pytest.raises(ValueError):
            ProducerIdentity(name=UNSPECIFIED_PRODUCER)

    def test_a_branch_ownership_binder_refuses_to_adapt_the_sentinel(self) -> None:
        with pytest.raises(ValueError):
            branch_ownership_registration_authority(
                adapted_producers=(UNSPECIFIED_BRANCH_OWNERSHIP_ORACLE,)
            )

    def test_a_transition_trust_binder_refuses_to_adapt_the_sentinel(self) -> None:
        with pytest.raises(ValueError):
            transition_trust_registration_authority(
                adapted_producers=(UNSPECIFIED_TRANSITION_TRUST_PRODUCER,)
            )

    def test_no_binder_owns_an_identity_for_the_sentinel(self) -> None:
        registrar = branch_ownership_registration_authority()

        assert UNSPECIFIED_BRANCH_OWNERSHIP_ORACLE not in registrar.producer_names
        with pytest.raises(LookupError):
            registrar.producer(UNSPECIFIED_BRANCH_OWNERSHIP_ORACLE)

    def test_an_omitted_branch_ownership_producer_stays_unregistered(self) -> None:
        proof = branch_ownership_proof_from_any(_spoofed_proof_dict(None))

        assert proof is not None
        assert proof.oracle_kind_name == UNSPECIFIED_BRANCH_OWNERSHIP_ORACLE
        assert proof.producer_registration is (
            BranchOwnershipProducerRegistration.UNKNOWN
        )
        assert proof.authority is BranchOwnershipAuthority.UNRESOLVED_PROVENANCE

    def test_an_omitted_trust_producer_stays_unregistered(self) -> None:
        result = transition_trust_result_from_any(
            {
                "trusted": True,
                "reason": "no_producer",
                "trust_kind": TransitionTrustKind.EXPLICIT_PRODUCER_TRUST.value,
            }
        )

        assert result is not None
        assert result.producer_name == UNSPECIFIED_TRANSITION_TRUST_PRODUCER
        assert result.authority is TransitionTrustAuthority.UNRESOLVED_PROVENANCE
        assert result.authorizes_explicit_conditional_bridge is False


class TestACarriedTokenIsStrippedAtTheCoercionBoundary:
    """A row may not smuggle a registration in through the untyped boundary.

    The tokens above are unforgeable, but a *genuine* one could still leak into
    a serialized row.  Coercion therefore never reads a ``registration`` field
    off its input: the row it builds starts unregistered, whatever the input
    carried, so only code holding the binder can register anything.
    """

    def test_a_carried_branch_ownership_token_does_not_survive_coercion(self) -> None:
        registrar = branch_ownership_registration_authority()
        leaked = registrar.mint(
            registrar.producer(BranchOwnershipOracleKind.MOPTRACKER)
        )

        proof = branch_ownership_proof_from_any(
            _spoofed_proof_dict(
                BranchOwnershipOracleKind.MOPTRACKER.value,
                registration=leaked,
            )
        )

        assert proof is not None
        assert proof.registration is None
        assert proof.authority is BranchOwnershipAuthority.UNRESOLVED_PROVENANCE

    def test_a_carried_trust_token_does_not_survive_coercion(self) -> None:
        registrar = transition_trust_registration_authority()
        leaked = registrar.mint(
            registrar.producer(TransitionTrustProducerKind.BRANCH_OWNERSHIP_ADAPTER)
        )

        result = transition_trust_result_from_any(
            _spoofed_trust_dict(
                TransitionTrustProducerKind.BRANCH_OWNERSHIP_ADAPTER.value,
                registration=leaked,
            )
        )

        assert result is not None
        assert result.registration is None
        assert result.authority is TransitionTrustAuthority.UNRESOLVED_PROVENANCE

    def test_a_duck_typed_row_carrying_a_token_is_stripped_too(self) -> None:
        registrar = branch_ownership_registration_authority()
        leaked = registrar.mint(
            registrar.producer(BranchOwnershipOracleKind.MOPTRACKER)
        )
        row = SimpleNamespace(
            **_spoofed_proof_dict(
                BranchOwnershipOracleKind.MOPTRACKER.value,
                registration=leaked,
            )
        )

        proof = branch_ownership_proof_from_any(row)

        assert proof is not None
        assert proof.registration is None
        assert proof.authority is BranchOwnershipAuthority.UNRESOLVED_PROVENANCE
