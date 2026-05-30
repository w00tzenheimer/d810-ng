from __future__ import annotations

from types import SimpleNamespace

from d810.analyses.control_flow.branch_ownership import (
    BranchOwnershipProof,
    BranchOwnershipProofKind,
)
from d810.recon.flow.transition_trust import (
    TransitionTrustKind,
    TransitionTrustResult,
    classify_transition_trust_for_explicit_conditional_bridge,
)


def _conditional_transition(**kwargs: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "is_conditional": True,
        "provenance_chain": [(1, 2)],
    }
    values.update(kwargs)
    return SimpleNamespace(**values)


def test_typed_transition_trust_authorizes_explicit_conditional_bridge() -> None:
    transition = _conditional_transition(
        transition_trust=TransitionTrustResult(
            True,
            "mop_tracker_path_constant_state_write",
            trust_kind=TransitionTrustKind.EXPLICIT_PRODUCER_TRUST,
            evidence={"oracle": "mop_tracker"},
        )
    )

    result = classify_transition_trust_for_explicit_conditional_bridge(
        transition
    )

    assert result.authorizes_explicit_conditional_bridge
    assert result.reason == "mop_tracker_path_constant_state_write"
    assert result.trust_kind == TransitionTrustKind.EXPLICIT_PRODUCER_TRUST


def test_trusted_real_branch_ownership_authorizes_explicit_bridge() -> None:
    transition = _conditional_transition(
        branch_ownership_proof=BranchOwnershipProof(
            proof_id="proof:real",
            proof_kind=BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
            trusted=True,
            reason="mop_tracker_real_password_branch",
        )
    )

    result = classify_transition_trust_for_explicit_conditional_bridge(
        transition
    )

    assert result.authorizes_explicit_conditional_bridge
    assert (
        result.trust_kind
        == TransitionTrustKind.BRANCH_OWNERSHIP_REAL_DATA_DEPENDENT
    )


def test_nonsemantic_branch_ownership_does_not_authorize_bridge() -> None:
    transition = _conditional_transition(
        branch_ownership_proof=BranchOwnershipProof(
            proof_id="proof:junk",
            proof_kind=BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM,
            trusted=True,
            reason="opaque_selector_junk_arm",
        )
    )

    result = classify_transition_trust_for_explicit_conditional_bridge(
        transition
    )

    assert not result.authorizes_explicit_conditional_bridge
    assert (
        result.reason
        == "branch_ownership_not_bridge_authority:OBFUSCATION_RESIDUE_ARM"
    )


def test_provenance_tag_is_adapter_not_consumer_allowlist() -> None:
    transition = _conditional_transition(
        provenance_kind="global_or_state_write",
    )

    result = classify_transition_trust_for_explicit_conditional_bridge(
        transition
    )

    assert result.authorizes_explicit_conditional_bridge
    assert result.trust_kind == TransitionTrustKind.DYNAMIC_STATE_WRITE
    assert result.evidence == {"source": "provenance_tag_adapter"}


def test_unsupported_provenance_remains_diagnostic_only() -> None:
    transition = _conditional_transition(
        provenance_kind="shape_only_bcf_guess",
    )

    result = classify_transition_trust_for_explicit_conditional_bridge(
        transition
    )

    assert not result.authorizes_explicit_conditional_bridge
    assert result.reason == "unsupported_provenance"
