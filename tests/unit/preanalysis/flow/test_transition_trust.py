from __future__ import annotations

from types import SimpleNamespace

from d810.analyses.control_flow.branch_ownership import (
    BranchOwnershipOracleKind,
    BranchOwnershipProof,
    BranchOwnershipProofKind,
    branch_ownership_registration_authority,
)
from d810.analyses.control_flow.dispatch_key import (
    DispatchKeyTransformKind,
)
from d810.analyses.control_flow.transition_trust import (
    TransitionTrustKind,
    TransitionTrustResult,
    classify_transition_trust_for_explicit_conditional_bridge,
    transition_trust_registration_authority,
)


def _registered_ownership_proof(**fields: object) -> BranchOwnershipProof:
    """An ownership proof its oracle registered, as an in-tree producer does.

    d81-9q6e review round 3: naming ``moptracker_branch_ownership`` on the row
    is a claim; the grant needs a registration minted by a binder.
    """
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


def test_typed_transition_trust_authorizes_explicit_conditional_bridge() -> None:
    """A typed producer still has to be *registered* by a binder (d81-9q6e).

    ``EXPLICIT_PRODUCER_TRUST`` is a grant, so it is gated on producer
    registration.  ``mop_tracker`` is not an in-tree adapter, so the owner of
    the binder vouches for it when it builds the binder and binds the row
    before attaching it -- review round 3: a row may not vouch for itself, and
    the classifier may not be handed a name to trust alongside the evidence.
    The unvouched variant is pinned in ``test_transition_trust_provenance.py``.
    """
    registrar = transition_trust_registration_authority(
        adapted_producers=("mop_tracker_oracle",)
    )
    transition = _conditional_transition(
        transition_trust=registrar.bind(
            TransitionTrustResult(
                True,
                "mop_tracker_path_constant_state_write",
                trust_kind=TransitionTrustKind.EXPLICIT_PRODUCER_TRUST,
                evidence={"oracle": "mop_tracker"},
            ),
            registrar.producer("mop_tracker_oracle"),
        )
    )

    result = classify_transition_trust_for_explicit_conditional_bridge(transition)

    assert result.authorizes_explicit_conditional_bridge
    assert result.reason == "mop_tracker_path_constant_state_write"
    assert result.trust_kind == TransitionTrustKind.EXPLICIT_PRODUCER_TRUST


def test_trusted_real_branch_ownership_authorizes_explicit_bridge() -> None:
    transition = _conditional_transition(
        branch_ownership_proof=_registered_ownership_proof(
            proof_id="proof:real",
            proof_kind=BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
            trusted=True,
            reason="mop_tracker_real_password_branch",
        )
    )

    result = classify_transition_trust_for_explicit_conditional_bridge(transition)

    assert result.authorizes_explicit_conditional_bridge
    assert result.trust_kind == TransitionTrustKind.BRANCH_OWNERSHIP_REAL_DATA_DEPENDENT


def test_nonsemantic_branch_ownership_does_not_authorize_bridge() -> None:
    transition = _conditional_transition(
        branch_ownership_proof=_registered_ownership_proof(
            proof_id="proof:junk",
            proof_kind=BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM,
            trusted=True,
            reason="opaque_selector_junk_arm",
        )
    )

    result = classify_transition_trust_for_explicit_conditional_bridge(transition)

    assert not result.authorizes_explicit_conditional_bridge
    assert (
        result.reason == "branch_ownership_not_bridge_authority:OBFUSCATION_RESIDUE_ARM"
    )


def test_provenance_tag_is_adapter_not_consumer_allowlist() -> None:
    transition = _conditional_transition(
        provenance_kind="global_or_state_write",
    )

    result = classify_transition_trust_for_explicit_conditional_bridge(transition)

    assert result.authorizes_explicit_conditional_bridge
    assert result.trust_kind == TransitionTrustKind.DYNAMIC_STATE_WRITE
    assert result.evidence == {"source": "provenance_tag_adapter"}


def test_dispatch_key_transform_shape_does_not_authorize_bridge() -> None:
    transition = _conditional_transition(
        provenance_kind="derived_xor_dispatch_key",
    )

    result = classify_transition_trust_for_explicit_conditional_bridge(transition)

    assert not result.authorizes_explicit_conditional_bridge
    assert result.reason == "dispatch_key_transform_not_authority"
    assert result.dispatch_key_transform_kind == DispatchKeyTransformKind.XOR
    assert result.evidence == {"source": "dispatch_key_transform_adapter"}


def test_unsupported_provenance_remains_diagnostic_only() -> None:
    transition = _conditional_transition(
        provenance_kind="shape_only_bcf_guess",
    )

    result = classify_transition_trust_for_explicit_conditional_bridge(transition)

    assert not result.authorizes_explicit_conditional_bridge
    assert result.reason == "unsupported_provenance"
