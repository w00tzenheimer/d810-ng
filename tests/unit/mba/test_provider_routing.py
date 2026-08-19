"""Tests for the pure MBA provider eligibility order."""

from __future__ import annotations

from dataclasses import replace

from d810.mba.island_profile import (
    IslandBlocker,
    MbaIslandClass,
    MbaIslandProfile,
)
from d810.mba.provider_routing import (
    MbaProviderKind,
    MbaProviderOmissionReason,
    MbaRoutingPolicy,
    provider_omission_reasons,
    provider_route,
)
from d810.mba.root_chain_descriptor import MbaRootChainDescriptor
from d810.mba.root_chain_descriptor import MbaRootChainFamily


def _profile(
    *,
    island_class: MbaIslandClass = MbaIslandClass.LINEAR_MBA,
    leaves: int = 2,
    operators: int = 3,
    operations: tuple[tuple[str, int], ...] = (("add", 1), ("and", 1), ("or", 1)),
    blockers: tuple[IslandBlocker, ...] = (),
) -> MbaIslandProfile:
    return MbaIslandProfile(
        width_bits=32,
        operator_count=operators,
        total_node_count=operators + leaves,
        distinct_leaf_count=leaves,
        constant_count=0,
        operations=operations,
        has_boolean=any(operation in {"and", "bnot", "or", "xor"} for operation, _ in operations),
        has_arithmetic=any(operation in {"add", "mul", "neg", "sub"} for operation, _ in operations),
        nonlinear_product_count=int(island_class is MbaIslandClass.NONLINEAR_MBA),
        island_class=island_class,
        blockers=blockers,
        fingerprint="profile",
    )


def _chain_descriptor(
    profile: MbaIslandProfile,
    *,
    family: MbaRootChainFamily = MbaRootChainFamily.SAME_OPERATION,
    root_operation: str = "xor",
    flattened_arity: int = 2,
) -> MbaRootChainDescriptor:
    return MbaRootChainDescriptor(
        family=family,
        root_operation=root_operation,
        flattened_arity=flattened_arity,
        fingerprint=profile.fingerprint,
    )


def test_small_linear_mba_routes_all_eligible_providers_in_portfolio_order() -> None:
    assert provider_route(_profile()) == (
        MbaProviderKind.CATALOGUE,
        MbaProviderKind.EGRAPH,
        MbaProviderKind.COEFFICIENT_SOLVER,
    )


def test_structural_chain_requires_a_root_chain_descriptor() -> None:
    profile = _profile(
        island_class=MbaIslandClass.NOT_MBA,
        operations=(("xor", 3),),
    )

    assert provider_route(profile) == (MbaProviderKind.CATALOGUE,)
    assert provider_omission_reasons(profile)[MbaProviderKind.STRUCTURAL_CHAIN] is (
        MbaProviderOmissionReason.ROOT_CHAIN_DESCRIPTOR_REQUIRED
    )


def test_root_chain_descriptor_precedes_catalogue_without_general_ac_grouping() -> None:
    profile = _profile(
        island_class=MbaIslandClass.NOT_MBA,
        operations=(("xor", 3),),
    )

    assert provider_route(profile, chain_descriptor=_chain_descriptor(profile)) == (
        MbaProviderKind.STRUCTURAL_CHAIN,
        MbaProviderKind.CATALOGUE,
    )

    mismatched = replace(profile, fingerprint="different-profile")
    mismatch_descriptor = _chain_descriptor(mismatched)
    assert provider_route(profile, chain_descriptor=mismatch_descriptor) == (
        MbaProviderKind.CATALOGUE,
    )
    assert provider_omission_reasons(profile, chain_descriptor=mismatch_descriptor)[
        MbaProviderKind.STRUCTURAL_CHAIN
    ] is MbaProviderOmissionReason.ROOT_CHAIN_FINGERPRINT_MISMATCH


def test_egraph_stops_at_inclusive_leaf_and_operator_boundaries() -> None:
    at_boundary = _profile(leaves=2, operators=10)
    too_many_leaves = replace(at_boundary, distinct_leaf_count=3)
    too_many_operators = replace(at_boundary, operator_count=11)

    assert MbaProviderKind.EGRAPH in provider_route(at_boundary)
    assert MbaProviderKind.EGRAPH not in provider_route(too_many_leaves)
    assert MbaProviderKind.EGRAPH not in provider_route(too_many_operators)
    assert provider_omission_reasons(too_many_leaves)[MbaProviderKind.EGRAPH] is (
        MbaProviderOmissionReason.LEAF_BUDGET
    )
    assert provider_omission_reasons(too_many_operators)[MbaProviderKind.EGRAPH] is (
        MbaProviderOmissionReason.OPERATOR_BUDGET
    )


def test_larger_linear_mba_skips_egraph_but_keeps_coefficient_solver_to_boundary() -> None:
    profile = _profile(leaves=8, operators=11)

    assert provider_route(profile) == (
        MbaProviderKind.CATALOGUE,
        MbaProviderKind.COEFFICIENT_SOLVER,
    )
    assert provider_omission_reasons(profile)[MbaProviderKind.EGRAPH] is (
        MbaProviderOmissionReason.LEAF_BUDGET
    )

    beyond_solver = replace(profile, distinct_leaf_count=9)
    assert provider_route(beyond_solver) == (MbaProviderKind.CATALOGUE,)
    assert provider_omission_reasons(beyond_solver)[MbaProviderKind.COEFFICIENT_SOLVER] is (
        MbaProviderOmissionReason.LEAF_BUDGET
    )


def test_nonlinear_solver_is_explicit_opt_in_and_egraph_is_never_routed() -> None:
    profile = _profile(island_class=MbaIslandClass.NONLINEAR_MBA)

    assert provider_route(profile) == (MbaProviderKind.CATALOGUE,)
    assert provider_omission_reasons(profile)[MbaProviderKind.EGRAPH] is (
        MbaProviderOmissionReason.NONLINEAR_ISLAND
    )
    assert provider_route(
        profile,
        MbaRoutingPolicy(allow_nonlinear_solver=True),
    ) == (
        MbaProviderKind.CATALOGUE,
        MbaProviderKind.COEFFICIENT_SOLVER,
    )


def test_every_blocker_fails_closed_with_stable_omissions() -> None:
    for blocker in IslandBlocker:
        profile = _profile(
            island_class=MbaIslandClass.UNSUPPORTED,
            blockers=(blocker,),
        )

        assert provider_route(profile) == ()
        assert provider_omission_reasons(profile) == {
            provider: MbaProviderOmissionReason.BLOCKED_SEMANTICS
            for provider in MbaProviderKind
            if provider is not MbaProviderKind.EXTERNAL_REFERENCE
        } | {
            MbaProviderKind.EXTERNAL_REFERENCE: MbaProviderOmissionReason.EXPLICIT_ONLY,
        }


def test_external_reference_is_never_an_automatic_route() -> None:
    omissions = provider_omission_reasons(_profile())

    assert MbaProviderKind.EXTERNAL_REFERENCE not in provider_route(_profile())
    assert omissions[MbaProviderKind.EXTERNAL_REFERENCE] is (
        MbaProviderOmissionReason.EXPLICIT_ONLY
    )
