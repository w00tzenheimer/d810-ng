"""Narrow transaction-facing facade for unflatten semantic authority.

The Hex-Rays transaction layer may consume this facade, while the canonical
authority package remains inaccessible as a direct dependency.  The facade
contains no policy; it only exposes the transaction API's closed result and
phase-observation surface.
"""

from d810.transforms.unflatten_authority import transaction_api as _transaction_api
from d810.transforms.unflatten_authority.transaction_api import (
    GenericCfgGateBundle,
    PhaseTimings,
    TimedUnflattenAuthorityResult,
    UnflattenAuthorityBindingAccepted,
    UnflattenAuthorityBindingRejected,
    UnflattenAuthorityNotApplicable,
    UnflattenAuthorityPreparationAccepted,
    UnflattenAuthorityPreparationRejected,
    UnflattenAuthorityVerdict,
)
from d810.transforms.unflatten_authority.structural_transaction import (
    StructuralTransactionContext,
    StructuralTransactionCoordinates,
)


def bind_prepared_unflatten_authority(*, prepared, patch_binding, structural_context=None):
    return _transaction_api.bind_prepared_unflatten_authority(
        prepared=prepared, patch_binding=patch_binding,
        structural_context=structural_context,
    )


def compatibility_projection(verdict, kind):
    return _transaction_api.compatibility_projection(verdict, kind)


def phase_observation(
    verdict, *, maturity, source_ea, timings=None, views=None,
    projected_case=None, prepared_authority=None, correlation=None,
):
    return _transaction_api.phase_observation(
        verdict,
        maturity=maturity,
        source_ea=source_ea,
        timings=timings,
        views=views,
        projected_case=projected_case,
        prepared_authority=prepared_authority,
        correlation=correlation,
    )


def prepare_unflatten_authority_timed(
    *, source, projection, plan, attempt_id, generic_gates, structural_context=None,
):
    return _transaction_api.prepare_unflatten_authority_timed(
        source=source,
        projection=projection,
        plan=plan,
        attempt_id=attempt_id,
        generic_gates=generic_gates,
        structural_context=structural_context,
    )


def revalidate_bound_patch_plan_against_prepared(prepared, bound_plan, *, structural_context=None):
    return _transaction_api.revalidate_bound_patch_plan_against_prepared(
        prepared, bound_plan, structural_context=structural_context,
    )


def revalidate_observed_unflatten_authority_timed(
    *, authority, observed, observed_generation, generic_gates,
    observed_patch_binding, structural_context=None,
):
    return _transaction_api.revalidate_observed_unflatten_authority_timed(
        authority=authority,
        observed=observed,
        observed_generation=observed_generation,
        generic_gates=generic_gates,
        observed_patch_binding=observed_patch_binding,
        structural_context=structural_context,
    )


def validate_observed_commit_authority(authority, verdict, accepted, *, structural_context=None):
    """Revalidate the exact observed closure immediately before commit."""
    return _transaction_api.validate_observed_commit_authority(
        authority, verdict, accepted, structural_context=structural_context,
    )

__all__ = (
    "StructuralTransactionContext",
    "StructuralTransactionCoordinates",
    "GenericCfgGateBundle",
    "PhaseTimings",
    "TimedUnflattenAuthorityResult",
    "UnflattenAuthorityBindingAccepted",
    "UnflattenAuthorityBindingRejected",
    "UnflattenAuthorityNotApplicable",
    "UnflattenAuthorityPreparationAccepted",
    "UnflattenAuthorityPreparationRejected",
    "UnflattenAuthorityVerdict",
    "bind_prepared_unflatten_authority",
    "compatibility_projection",
    "phase_observation",
    "prepare_unflatten_authority_timed",
    "revalidate_bound_patch_plan_against_prepared",
    "revalidate_observed_unflatten_authority_timed",
    "validate_observed_commit_authority",
)
