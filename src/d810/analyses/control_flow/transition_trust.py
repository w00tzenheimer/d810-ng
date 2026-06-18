"""Trust decisions for state-machine transition evidence.

This module is the boundary between transition producers and consumers that
may turn evidence into concrete DAG/CFG authority.  Producers can attach typed
trust evidence directly; older producers that only expose provenance strings
are adapted here so consumers do not grow local allowlists.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from d810.analyses.control_flow.branch_ownership import (
    branch_ownership_proof_from_any,
)
from d810.analyses.control_flow.dispatch_key import (
    DispatchKeyTransformKind,
    dispatch_key_transform_kind_from_any,
)


class TransitionTrustKind(str, Enum):
    """Typed source of authority for promoting transition evidence.

    ``DYNAMIC_STATE_WRITE``
        A recon producer observed a conditional state write through the
        dispatcher state variable or a global/state alias with enough evidence
        to treat the written state as the branch target.  This can authorize an
        explicit conditional DAG bridge because it identifies real transition
        data, not merely graph shape.

    ``BRANCH_OWNERSHIP_REAL_DATA_DEPENDENT``
        Branch ownership proved the arm is real source-program control flow.
        This is the only branch-ownership proof kind that becomes semantic DAG
        bridge authority.  Nonsemantic ownership kinds remain rewrite evidence.

    ``EXPLICIT_PRODUCER_TRUST``
        A future oracle, for example MopTracker or Z3, attached a typed trust
        result directly.  Use this only when the producer already performed the
        semantic-vs-obfuscation distinction and can explain it in ``reason`` /
        ``evidence``.

    ``UNSUPPORTED``
        The transition is diagnostic-only for this consumer.  No explicit
        conditional bridge should be built from it.
    """

    DYNAMIC_STATE_WRITE = "DYNAMIC_STATE_WRITE"
    BRANCH_OWNERSHIP_REAL_DATA_DEPENDENT = (
        "BRANCH_OWNERSHIP_REAL_DATA_DEPENDENT"
    )
    EXPLICIT_PRODUCER_TRUST = "EXPLICIT_PRODUCER_TRUST"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True, slots=True)
class TransitionTrustResult:
    """Decision describing whether transition evidence can authorize a use."""

    trusted: bool
    reason: str
    trust_kind: TransitionTrustKind | str = TransitionTrustKind.UNSUPPORTED
    provenance_kind: str | None = None
    dispatch_key_transform_kind: DispatchKeyTransformKind | None = None
    evidence: dict[str, object] = field(default_factory=dict)

    @property
    def trust_kind_name(self) -> str:
        kind = self.trust_kind
        if isinstance(kind, TransitionTrustKind):
            return kind.value
        return str(kind)

    @property
    def authorizes_explicit_conditional_bridge(self) -> bool:
        """Whether this trust result can become explicit conditional DAG input."""

        return bool(self.trusted) and self.trust_kind_name in {
            TransitionTrustKind.DYNAMIC_STATE_WRITE.value,
            TransitionTrustKind.BRANCH_OWNERSHIP_REAL_DATA_DEPENDENT.value,
            TransitionTrustKind.EXPLICIT_PRODUCER_TRUST.value,
        }


_PROVENANCE_TAG_TRUST_KIND_BY_NAME = {
    "global_or_state_write": TransitionTrustKind.DYNAMIC_STATE_WRITE,
}

_PROVENANCE_TAG_REASON_BY_KIND = {
    TransitionTrustKind.DYNAMIC_STATE_WRITE: "dynamic_state_write",
}

_DISPATCH_KEY_TRANSFORM_BY_PROVENANCE_KIND = {
    "derived_xor_dispatch_key": DispatchKeyTransformKind.XOR,
}


def classify_transition_trust_for_explicit_conditional_bridge(
    transition: object,
) -> TransitionTrustResult:
    """Classify whether a conditional transition may form an explicit bridge.

    The result is intentionally conservative: diagnostic provenance is not
    enough.  A producer must either attach typed trust evidence, attach a
    trusted branch-ownership proof for real data-dependent control, or expose
    a recognized provenance tag adapted at this boundary.
    """

    if not bool(getattr(transition, "is_conditional", False)):
        return TransitionTrustResult(False, "not_conditional")
    if not bool(getattr(transition, "provenance_chain", ())):
        return TransitionTrustResult(False, "missing_provenance_chain")

    typed_result = _typed_transition_trust_result(transition)
    if typed_result is not None:
        return typed_result

    branch_result = _branch_ownership_transition_trust_result(transition)
    if branch_result is not None:
        return branch_result

    provenance_kind = _transition_provenance_kind(transition)
    dispatch_key_transform_kind = _transition_dispatch_key_transform_kind(
        transition,
        provenance_kind=provenance_kind,
    )
    provenance_trust_kind = _PROVENANCE_TAG_TRUST_KIND_BY_NAME.get(
        provenance_kind
    )
    if provenance_trust_kind is not None:
        return TransitionTrustResult(
            True,
            _PROVENANCE_TAG_REASON_BY_KIND[provenance_trust_kind],
            trust_kind=provenance_trust_kind,
            provenance_kind=provenance_kind,
            dispatch_key_transform_kind=dispatch_key_transform_kind,
            evidence={"source": "provenance_tag_adapter"},
        )

    if dispatch_key_transform_kind is not None:
        return TransitionTrustResult(
            False,
            "dispatch_key_transform_not_authority",
            provenance_kind=provenance_kind,
            dispatch_key_transform_kind=dispatch_key_transform_kind,
            evidence={"source": "dispatch_key_transform_adapter"},
        )

    return TransitionTrustResult(
        False,
        "unsupported_provenance",
        provenance_kind=provenance_kind,
    )


def transition_is_trusted_for_explicit_conditional_bridge(
    transition: object,
) -> bool:
    """Return whether transition evidence can authorize explicit bridging."""

    return (
        classify_transition_trust_for_explicit_conditional_bridge(
            transition
        ).authorizes_explicit_conditional_bridge
    )


def _typed_transition_trust_result(
    transition: object,
) -> TransitionTrustResult | None:
    for attr in ("transition_trust", "trust_result", "trust_evidence"):
        value = getattr(transition, attr, None)
        result = transition_trust_result_from_any(value)
        if result is not None:
            return result
    metadata = getattr(transition, "metadata", None)
    if isinstance(metadata, dict):
        for key in ("transition_trust", "trust_result", "trust_evidence"):
            result = transition_trust_result_from_any(metadata.get(key))
            if result is not None:
                return result
    return None


def transition_trust_result_from_any(
    value: object | None,
) -> TransitionTrustResult | None:
    """Coerce a typed trust object/dict into ``TransitionTrustResult``."""

    if value is None:
        return None
    if isinstance(value, TransitionTrustResult):
        return value
    if isinstance(value, dict):
        trusted = value.get("trusted")
        reason = value.get("reason")
        trust_kind = value.get("trust_kind")
        provenance_kind = value.get("provenance_kind")
        dispatch_key_transform_kind = value.get(
            "dispatch_key_transform_kind"
        )
        evidence = value.get("evidence") or {}
    else:
        trusted = getattr(value, "trusted", None)
        reason = getattr(value, "reason", None)
        trust_kind = getattr(value, "trust_kind", None)
        provenance_kind = getattr(value, "provenance_kind", None)
        dispatch_key_transform_kind = getattr(
            value,
            "dispatch_key_transform_kind",
            None,
        )
        evidence = getattr(value, "evidence", None) or {}
    if trusted is None or reason is None:
        return None
    if trust_kind is None:
        trust_kind = TransitionTrustKind.EXPLICIT_PRODUCER_TRUST
    try:
        normalized_kind = (
            trust_kind
            if isinstance(trust_kind, TransitionTrustKind)
            else TransitionTrustKind(str(trust_kind))
        )
    except ValueError:
        normalized_kind = str(trust_kind)
    return TransitionTrustResult(
        bool(trusted),
        str(reason),
        trust_kind=normalized_kind,
        provenance_kind=(
            None if provenance_kind is None else str(provenance_kind)
        ),
        dispatch_key_transform_kind=dispatch_key_transform_kind_from_any(
            dispatch_key_transform_kind
        ),
        evidence=dict(evidence),
    )


def _branch_ownership_transition_trust_result(
    transition: object,
) -> TransitionTrustResult | None:
    for value in _branch_ownership_candidates(transition):
        proof = branch_ownership_proof_from_any(value)
        if proof is None:
            continue
        proof_kind = proof.proof_kind_name
        if proof.authorizes_semantic_branch_bridge:
            return TransitionTrustResult(
                True,
                "branch_ownership_real_data_dependent",
                trust_kind=(
                    TransitionTrustKind
                    .BRANCH_OWNERSHIP_REAL_DATA_DEPENDENT
                ),
                evidence={
                    "proof_id": proof.proof_id,
                    "oracle_kind": proof.oracle_kind,
                },
            )
        return TransitionTrustResult(
            False,
            f"branch_ownership_not_bridge_authority:{proof_kind}",
            evidence={
                "proof_id": proof.proof_id,
                "trusted": bool(proof.trusted),
                "oracle_kind": proof.oracle_kind,
            },
        )
    return None


def _branch_ownership_candidates(transition: object) -> tuple[object, ...]:
    candidates: list[object] = []
    for attr in ("branch_ownership_proof", "branch_ownership"):
        value = getattr(transition, attr, None)
        if value is not None:
            candidates.append(value)
    metadata = getattr(transition, "metadata", None)
    if isinstance(metadata, dict):
        for key in ("branch_ownership_proof", "branch_ownership"):
            value = metadata.get(key)
            if value is not None:
                candidates.append(value)
    return tuple(candidates)


def _transition_provenance_kind(transition: object) -> str | None:
    provenance_kind = getattr(transition, "provenance_kind", None)
    if provenance_kind is None:
        metadata = getattr(transition, "metadata", None)
        if isinstance(metadata, dict):
            provenance_kind = metadata.get("provenance_kind")
    return None if provenance_kind is None else str(provenance_kind)


def _transition_dispatch_key_transform_kind(
    transition: object,
    *,
    provenance_kind: str | None,
) -> DispatchKeyTransformKind | None:
    for attr in (
        "dispatch_key_transform_kind",
        "key_transform_kind",
        "dispatch_key_transform",
    ):
        result = dispatch_key_transform_kind_from_any(
            getattr(transition, attr, None)
        )
        if result is not None:
            return result
    metadata = getattr(transition, "metadata", None)
    if isinstance(metadata, dict):
        for key in (
            "dispatch_key_transform_kind",
            "key_transform_kind",
            "dispatch_key_transform",
        ):
            result = dispatch_key_transform_kind_from_any(metadata.get(key))
            if result is not None:
                return result
    return _DISPATCH_KEY_TRANSFORM_BY_PROVENANCE_KIND.get(provenance_kind)


__all__ = [
    "TransitionTrustKind",
    "TransitionTrustResult",
    "classify_transition_trust_for_explicit_conditional_bridge",
    "transition_is_trusted_for_explicit_conditional_bridge",
    "transition_trust_result_from_any",
]
