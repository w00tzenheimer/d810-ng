"""Patch-transaction-facing route selection for unflatten authority."""

from __future__ import annotations

from d810.transforms.plan import PatchPlan

from .model import (
    UnflattenAuthorityNotApplicable,
    UnflattenAuthorityReason,
    UnflattenPlanRoute,
)
from .proposal import (
    MetadataKeyTypeError,
    PlanRouteResult,
    ProposalAccepted,
    ProposalRejected,
    RejectedPlanRoute,
    ShadowValidationAccepted,
    TypedProposalRoute,
    reserved_metadata_keys,
    validate_proposal,
    validate_shadow_for_plan,
)


def select_plan_route(plan: PatchPlan) -> PlanRouteResult:
    """Select the only valid authority route for ``plan``.

    Ordinary plans get a dedicated not-applicable result.  Every other route
    is explicit: a closed typed proposal is accepted, while legacy metadata
    requires an adapter and is never guessed as ordinary authority.
    """

    if type(plan) is not PatchPlan:
        raise TypeError("plan must be a PatchPlan")

    try:
        reserved_keys = reserved_metadata_keys(plan)
    except MetadataKeyTypeError:
        return RejectedPlanRoute(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "metadata_key_type_invalid",
        )
    except ValueError:
        return RejectedPlanRoute(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "metadata_shape_invalid",
        )
    proposal = plan.unflatten_proposal
    if proposal is not None:
        if reserved_keys:
            return RejectedPlanRoute(
                UnflattenAuthorityReason.DUAL_AUTHORITY_CHANNEL,
                "typed_proposal_has_top_level_legacy_metadata",
                reserved_keys[0],
            )
        validation = validate_proposal(plan, proposal)
        if isinstance(validation, ProposalRejected):
            return RejectedPlanRoute(
                validation.reason,
                validation.detail_code,
                validation.key,
            )
        if plan.legacy_unflatten_shadow is not None:
            rejection = validate_shadow_for_plan(
                plan, plan.legacy_unflatten_shadow
            )
            if not isinstance(rejection, ShadowValidationAccepted):
                return rejection
        if not isinstance(validation, ProposalAccepted):
            raise TypeError("proposal validation returned an unknown result")
        return TypedProposalRoute(
            UnflattenPlanRoute.TYPED_PROPOSAL,
            validation.proposal,
        )

    if plan.legacy_unflatten_shadow is not None:
        return RejectedPlanRoute(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "shadow_without_typed_proposal",
        )
    if reserved_keys:
        return RejectedPlanRoute(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "legacy_metadata_requires_explicit_codec_adaptation",
            reserved_keys[0],
        )
    return UnflattenAuthorityNotApplicable(UnflattenPlanRoute.ORDINARY)


__all__ = ["select_plan_route"]
