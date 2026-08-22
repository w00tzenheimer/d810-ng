"""Validation helpers for the typed unflatten proposal channel.

This module validates the producer-owned value without evaluating it.  Route
selection belongs to :mod:`transaction_api`; the temporary legacy envelope is
transport only and is never converted into authority here.
"""

from __future__ import annotations

from dataclasses import dataclass
from d810.core.typing import TYPE_CHECKING, Literal, TypeAlias
from d810.transforms.plan import normalized_metadata_items

from .model import (
    LegacyUnflattenShadowEnvelope,
    ProposedUnflattenContract,
    UnflattenAuthorityNotApplicable,
    UnflattenAuthorityReason,
    UnflattenPlanRoute,
)
from .producer_api import build_unflatten_plan_input_catalog
from .ids import validate_canonical_roundtrip

if TYPE_CHECKING:
    from d810.transforms.plan import PatchPlan


def _current_reserved_keys() -> frozenset[str]:
    """Build the guard from the constants exported by their owning modules."""

    from d810.analyses.control_flow.effect_branch_exclusion import (
        EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA,
    )
    from d810.transforms.dispatcher_corridor_coverage import (
        DISPATCHER_CORRIDOR_COVERAGE_METADATA,
        DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA,
        FULL_UNFLATTENING_CLAIM_METADATA,
        USE_DEF_SEVERANCE_AUDIT_METADATA,
        UNFLATTEN_COMPLETION_STATUS_METADATA,
    )
    from d810.transforms.minimal_unflatten_emit import (
        CONCRETE_STATE_ROUTE_PROVENANCE_METADATA,
        NATIVE_BOUND_TRANSITION_ROUTE_RECEIPTS_METADATA,
    )

    return frozenset(
        {
            DISPATCHER_CORRIDOR_COVERAGE_METADATA,
            DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA,
            UNFLATTEN_COMPLETION_STATUS_METADATA,
            FULL_UNFLATTENING_CLAIM_METADATA,
            USE_DEF_SEVERANCE_AUDIT_METADATA,
            EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA,
            CONCRETE_STATE_ROUTE_PROVENANCE_METADATA,
            NATIVE_BOUND_TRANSITION_ROUTE_RECEIPTS_METADATA,
        }
    )


# Public for the codec/router seam and tests.  It is assembled from the
# current owners above, so this backstop cannot drift by omission.
LEGACY_UNFLATTEN_KEYS = _current_reserved_keys()


class MetadataKeyTypeError(ValueError):
    """A metadata key is not a closed, exact ``str`` routing input."""


def reserved_metadata_keys(plan: PatchPlan) -> tuple[str, ...]:
    """Return reserved top-level metadata keys in stable metadata order."""

    keys: list[str] = []
    try:
        raw_items = normalized_metadata_items(plan.metadata)
        # Validate the key domain before invoking dict/set hash or equality
        # semantics.  In particular, a str subclass or arbitrary alias must
        # not get an opportunity to impersonate a reserved key.
        for key, _value in raw_items:
            if type(key) is not str:
                raise MetadataKeyTypeError("metadata keys must be exact str")
        dict(raw_items)
        for key, _value in raw_items:
            if key in LEGACY_UNFLATTEN_KEYS:
                keys.append(key)
    except MetadataKeyTypeError:
        raise
    except Exception as exc:
        raise ValueError("metadata key inspection failed") from exc
    return tuple(keys)


@dataclass(frozen=True, slots=True)
class ProposalAccepted:
    """A validated typed proposal bound to one exact plan."""

    proposal: ProposedUnflattenContract

    def __post_init__(self) -> None:
        if type(self.proposal) is not ProposedUnflattenContract:
            raise TypeError("proposal must be a ProposedUnflattenContract")


@dataclass(frozen=True, slots=True)
class ProposalRejected:
    """A typed proposal rejection with an exhaustive authority reason."""

    reason: UnflattenAuthorityReason
    detail_code: str
    key: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.reason, UnflattenAuthorityReason):
            raise TypeError("reason must be an UnflattenAuthorityReason")
        if self.reason in (
            UnflattenAuthorityReason.ACCEPTED,
            UnflattenAuthorityReason.NOT_APPLICABLE,
        ):
            raise ValueError("rejection reason must describe rejection")
        if not isinstance(self.detail_code, str) or not self.detail_code.strip():
            raise ValueError("detail_code must not be blank")
        if self.key is not None and self.key not in LEGACY_UNFLATTEN_KEYS:
            raise ValueError("key must be a reserved unflatten metadata key")


ProposalValidationResult: TypeAlias = ProposalAccepted | ProposalRejected


def validate_proposal(
    plan: PatchPlan,
    proposal: object,
) -> ProposalValidationResult:
    """Validate exact proposal type and plan correlation without evaluation."""

    if type(proposal) is not ProposedUnflattenContract:
        return ProposalRejected(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "proposal_type_is_not_closed",
        )
    try:
        validate_canonical_roundtrip(proposal, ProposedUnflattenContract)
        ProposedUnflattenContract.__post_init__(proposal)
    except Exception:
        return ProposalRejected(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "proposal_invariants_invalid",
        )
    if proposal.plan_id != plan.plan_id:
        return ProposalRejected(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "proposal_plan_id_mismatch",
        )
    return ProposalAccepted(proposal)


@dataclass(frozen=True, slots=True)
class TypedProposalRoute:
    """The sole accepted semantic route in this task."""

    route: Literal[UnflattenPlanRoute.TYPED_PROPOSAL]
    proposal: ProposedUnflattenContract

    def __post_init__(self) -> None:
        if self.route is not UnflattenPlanRoute.TYPED_PROPOSAL:
            raise ValueError("typed route must be TYPED_PROPOSAL")
        if type(self.proposal) is not ProposedUnflattenContract:
            raise TypeError("typed route proposal must be closed")


@dataclass(frozen=True, slots=True)
class RejectedPlanRoute:
    """A total route-selection rejection."""

    reason: UnflattenAuthorityReason
    detail_code: str
    key: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.reason, UnflattenAuthorityReason):
            raise TypeError("reason must be an UnflattenAuthorityReason")
        if self.reason in (
            UnflattenAuthorityReason.ACCEPTED,
            UnflattenAuthorityReason.NOT_APPLICABLE,
        ):
            raise ValueError("rejection reason must describe rejection")
        if not isinstance(self.detail_code, str) or not self.detail_code.strip():
            raise ValueError("detail_code must not be blank")
        if self.key is not None and self.key not in LEGACY_UNFLATTEN_KEYS:
            raise ValueError("key must be a reserved unflatten metadata key")


PlanRouteResult: TypeAlias = (
    UnflattenAuthorityNotApplicable | TypedProposalRoute | RejectedPlanRoute
)


@dataclass(frozen=True, slots=True)
class ShadowValidationAccepted:
    """The exact shadow transport correlates with its owning plan."""


ShadowValidationResult: TypeAlias = ShadowValidationAccepted | RejectedPlanRoute


def validate_shadow_for_plan(
    plan: PatchPlan,
    shadow: object,
) -> ShadowValidationResult:
    """Return a typed rejection for malformed or stale shadow transport."""

    if type(shadow) is not LegacyUnflattenShadowEnvelope:
        return RejectedPlanRoute(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "shadow_type_is_not_closed",
        )
    try:
        LegacyUnflattenShadowEnvelope.__post_init__(shadow)
    except (TypeError, ValueError):
        return RejectedPlanRoute(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "shadow_invariants_invalid",
        )
    if shadow.plan_id != plan.plan_id:
        return RejectedPlanRoute(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "shadow_plan_id_mismatch",
        )
    if shadow.snapshot_id != plan.snapshot_id:
        return RejectedPlanRoute(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "shadow_snapshot_id_mismatch",
        )
    if shadow.source_generation != plan.source_generation:
        return RejectedPlanRoute(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "shadow_source_generation_mismatch",
        )
    return ShadowValidationAccepted()


__all__ = [
    "build_unflatten_plan_input_catalog",
    "LEGACY_UNFLATTEN_KEYS",
    "PlanRouteResult",
    "ProposalAccepted",
    "ProposalRejected",
    "ProposalValidationResult",
    "RejectedPlanRoute",
    "ShadowValidationAccepted",
    "ShadowValidationResult",
    "TypedProposalRoute",
    "reserved_metadata_keys",
    "validate_proposal",
    "validate_shadow_for_plan",
]
