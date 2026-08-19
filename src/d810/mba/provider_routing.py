"""Pure eligibility and ordering for local MBA simplification providers."""

from __future__ import annotations

import enum
from dataclasses import dataclass

from d810.mba.island_profile import MbaIslandClass, MbaIslandProfile
from d810.mba.root_chain_descriptor import MbaRootChainDescriptor


class MbaProviderKind(enum.StrEnum):
    """A provider family in the MBA simplification portfolio."""

    STRUCTURAL_CHAIN = "structural_chain"
    CATALOGUE = "catalogue"
    EGRAPH = "egraph"
    COEFFICIENT_SOLVER = "coefficient_solver"
    EXTERNAL_REFERENCE = "external_reference"


class MbaProviderOmissionReason(enum.StrEnum):
    """Stable pure reasons why a provider is not eligible for an island."""

    BLOCKED_SEMANTICS = "blocked_semantics"
    ROOT_CHAIN_DESCRIPTOR_REQUIRED = "root_chain_descriptor_required"
    ROOT_CHAIN_FINGERPRINT_MISMATCH = "root_chain_fingerprint_mismatch"
    NOT_LINEAR_MBA = "not_linear_mba"
    NONLINEAR_ISLAND = "nonlinear_island"
    LEAF_BUDGET = "leaf_budget"
    OPERATOR_BUDGET = "operator_budget"
    NONLINEAR_SOLVER_DISABLED = "nonlinear_solver_disabled"
    EXPLICIT_ONLY = "explicit_only"


@dataclass(frozen=True)
class MbaRoutingPolicy:
    """Portable route limits; availability and consent remain runtime concerns."""

    ac_match_comparison_budget: int = 256
    egraph_max_leaves: int = 2
    egraph_max_operators: int = 10
    coefficient_max_leaves: int = 8
    allow_nonlinear_solver: bool = False

    def __post_init__(self) -> None:
        for field_name in (
            "ac_match_comparison_budget",
            "egraph_max_leaves",
            "egraph_max_operators",
            "coefficient_max_leaves",
        ):
            value = getattr(self, field_name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{field_name} must be a positive integer")
        if type(self.allow_nonlinear_solver) is not bool:
            raise ValueError("allow_nonlinear_solver must be a boolean")


_AUTOMATIC_PROVIDERS = tuple(
    provider
    for provider in MbaProviderKind
    if provider is not MbaProviderKind.EXTERNAL_REFERENCE
)


def _structural_chain_omission(
    profile: MbaIslandProfile,
    chain_descriptor: MbaRootChainDescriptor | None,
) -> MbaProviderOmissionReason | None:
    if chain_descriptor is None:
        return MbaProviderOmissionReason.ROOT_CHAIN_DESCRIPTOR_REQUIRED
    if chain_descriptor.fingerprint != profile.fingerprint:
        return MbaProviderOmissionReason.ROOT_CHAIN_FINGERPRINT_MISMATCH
    return None


def _egraph_omission(
    profile: MbaIslandProfile,
    policy: MbaRoutingPolicy,
) -> MbaProviderOmissionReason | None:
    if profile.island_class is MbaIslandClass.NONLINEAR_MBA:
        return MbaProviderOmissionReason.NONLINEAR_ISLAND
    if profile.island_class is not MbaIslandClass.LINEAR_MBA:
        return MbaProviderOmissionReason.NOT_LINEAR_MBA
    if profile.distinct_leaf_count > policy.egraph_max_leaves:
        return MbaProviderOmissionReason.LEAF_BUDGET
    if profile.operator_count > policy.egraph_max_operators:
        return MbaProviderOmissionReason.OPERATOR_BUDGET
    return None


def _coefficient_solver_omission(
    profile: MbaIslandProfile,
    policy: MbaRoutingPolicy,
) -> MbaProviderOmissionReason | None:
    if profile.island_class is MbaIslandClass.NONLINEAR_MBA:
        if not policy.allow_nonlinear_solver:
            return MbaProviderOmissionReason.NONLINEAR_SOLVER_DISABLED
    elif profile.island_class is not MbaIslandClass.LINEAR_MBA:
        return MbaProviderOmissionReason.NOT_LINEAR_MBA
    if profile.distinct_leaf_count > policy.coefficient_max_leaves:
        return MbaProviderOmissionReason.LEAF_BUDGET
    return None


def provider_omission_reasons(
    profile: MbaIslandProfile,
    policy: MbaRoutingPolicy = MbaRoutingPolicy(),
    *,
    chain_descriptor: MbaRootChainDescriptor | None = None,
) -> dict[MbaProviderKind, MbaProviderOmissionReason]:
    """Return deterministic omissions for every provider not in the route.

    This pure function intentionally has no provider discovery.  A provider that
    is eligible here may still be unavailable or disabled at runtime.
    """

    if profile.blockers or profile.island_class is MbaIslandClass.UNSUPPORTED:
        return {
            provider: MbaProviderOmissionReason.BLOCKED_SEMANTICS
            for provider in _AUTOMATIC_PROVIDERS
        } | {
            MbaProviderKind.EXTERNAL_REFERENCE: MbaProviderOmissionReason.EXPLICIT_ONLY,
        }

    omissions: dict[MbaProviderKind, MbaProviderOmissionReason] = {
        MbaProviderKind.EXTERNAL_REFERENCE: MbaProviderOmissionReason.EXPLICIT_ONLY,
    }
    chain_omission = _structural_chain_omission(profile, chain_descriptor)
    if chain_omission is not None:
        omissions[MbaProviderKind.STRUCTURAL_CHAIN] = chain_omission
    egraph_omission = _egraph_omission(profile, policy)
    if egraph_omission is not None:
        omissions[MbaProviderKind.EGRAPH] = egraph_omission
    solver_omission = _coefficient_solver_omission(profile, policy)
    if solver_omission is not None:
        omissions[MbaProviderKind.COEFFICIENT_SOLVER] = solver_omission
    return omissions


def provider_route(
    profile: MbaIslandProfile,
    policy: MbaRoutingPolicy = MbaRoutingPolicy(),
    *,
    chain_descriptor: MbaRootChainDescriptor | None = None,
) -> tuple[MbaProviderKind, ...]:
    """Return the ordered eligible providers without enabling or invoking any."""

    omissions = provider_omission_reasons(
        profile,
        policy,
        chain_descriptor=chain_descriptor,
    )
    if profile.blockers or profile.island_class is MbaIslandClass.UNSUPPORTED:
        return ()
    ordered = (
        MbaProviderKind.STRUCTURAL_CHAIN,
        MbaProviderKind.CATALOGUE,
        MbaProviderKind.EGRAPH,
        MbaProviderKind.COEFFICIENT_SOLVER,
    )
    return tuple(provider for provider in ordered if provider not in omissions)


__all__ = [
    "MbaProviderKind",
    "MbaProviderOmissionReason",
    "MbaRoutingPolicy",
    "provider_omission_reasons",
    "provider_route",
]
