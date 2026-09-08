"""Canonical reference projection for explicit route claim records.

These copies carry values only. Projection never grants runtime join authority.
"""

from dataclasses import dataclass, replace

from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalRouteIdProjection,
)
from d810.transforms.unflatten_authority.ids import authority_id, canonical_bytes
from d810.transforms.unflatten_authority.model import (
    EquivalentSemanticRouteClaim,
    EntryEndpointLivenessAllowance,
    ProposedUnflattenContract,
    RetiredDispatcherInfrastructureClaim,
    DetachedDeadHandlerComponentClaim,
    CorridorCoverageForecast,
    ProducerUnflattenClaim,
    canonical_model_order,
    DefaultGapInfeasibilityExclusion,
    DefaultGapInfeasibilityForecast,
    ExactInfeasibleEffectClaim,
    TerminalCycleBreakClaim,
    RouteSubjectLocator,
    SemanticSubjectRef,
)


@dataclass(frozen=True, slots=True)
class CanonicalRouteClaimProjection:
    claim: (
        EquivalentSemanticRouteClaim
        | ExactInfeasibleEffectClaim
        | TerminalCycleBreakClaim
    )
    claim_id_pair: tuple[str, str]
    subject_id_pairs: tuple[tuple[str, str], ...]


def project_equivalent_route_claim(
    claim: EquivalentSemanticRouteClaim,
    projection: CanonicalRouteIdProjection,
) -> CanonicalRouteClaimProjection:
    """Rebuild one claim through its constructors using complete ID correspondence."""
    if type(claim) is not EquivalentSemanticRouteClaim:
        raise TypeError("projection requires an exact equivalent route claim")
    if type(projection) is not CanonicalRouteIdProjection:
        raise TypeError("projection requires canonical route ID correspondence")
    if claim.source_generation != projection.evidence.generation:
        raise ValueError("claim belongs to another source generation")
    source_group, target_group = projection.group_id_pair
    if claim.atomic_group_id != source_group:
        raise ValueError("claim belongs to another source route group")
    if projection.evidence.atomic_group_id != target_group:
        raise ValueError("projection target group does not match its evidence")
    proof_ids = dict(projection.proof_id_pairs)
    if len(proof_ids) != len(projection.proof_id_pairs):
        raise ValueError("projection contains ambiguous source proof IDs")
    targets = {proof.proof_id for proof in projection.evidence.route_proofs}
    if not set(proof_ids.values()) <= targets:
        raise ValueError("projection names an absent canonical proof")
    if not set(claim.route_proof_ids) <= proof_ids.keys():
        raise ValueError("projection does not cover the claim's proof IDs")

    def route_subject(subject: SemanticSubjectRef) -> SemanticSubjectRef:
        locator = subject.locator
        if type(locator) is not RouteSubjectLocator:
            raise TypeError("route subject requires an exact route locator")
        if locator.atomic_group_id != source_group or locator.proof_id not in proof_ids:
            raise ValueError("projection does not cover the route locator")
        return replace(
            subject,
            locator=replace(
                locator,
                proof_id=proof_ids[locator.proof_id],
                atomic_group_id=target_group,
            ),
            _runtime_ref=None,
        )

    retired = route_subject(claim.retired_route_subject)
    replacement = route_subject(claim.replacement_route_subject)
    projected = replace(
        claim,
        retired_route_subject=retired,
        replacement_route_subject=replacement,
        source_subject=replace(claim.source_subject, _runtime_ref=None),
        destination_subjects=tuple(
            replace(subject, _runtime_ref=None)
            for subject in claim.destination_subjects
        ),
        dag_endpoint_subjects=tuple(
            replace(subject, _runtime_ref=None)
            for subject in claim.dag_endpoint_subjects
        ),
        route_proof_ids=tuple(
            proof_ids[proof_id] for proof_id in claim.route_proof_ids
        ),
        atomic_group_id=target_group,
        _runtime_refs=None,
    )
    return CanonicalRouteClaimProjection(
        projected,
        (claim.claim_id, projected.claim_id),
        (
            (claim.retired_route_subject.subject_id, retired.subject_id),
            (claim.replacement_route_subject.subject_id, replacement.subject_id),
        ),
    )


def project_proof_referencing_claim(
    claim: EquivalentSemanticRouteClaim
    | ExactInfeasibleEffectClaim
    | TerminalCycleBreakClaim,
    projection: CanonicalRouteIdProjection,
) -> CanonicalRouteClaimProjection:
    """Project the three closed producer claim families that select route proofs."""
    if type(claim) is EquivalentSemanticRouteClaim:
        return project_equivalent_route_claim(claim, projection)
    if type(claim) not in (ExactInfeasibleEffectClaim, TerminalCycleBreakClaim):
        raise TypeError("unsupported proof-referencing claim family")
    if type(projection) is not CanonicalRouteIdProjection:
        raise TypeError("projection requires canonical route ID correspondence")
    if claim.source_generation != projection.evidence.generation:
        raise ValueError("claim belongs to another source generation")
    if projection.group_id_pair[1] != projection.evidence.atomic_group_id:
        raise ValueError("projection target group does not match its evidence")
    proof_ids = dict(projection.proof_id_pairs)
    if len(proof_ids) != len(projection.proof_id_pairs):
        raise ValueError("projection contains ambiguous source proof IDs")
    if not set(proof_ids.values()) <= {
        proof.proof_id for proof in projection.evidence.route_proofs
    }:
        raise ValueError("projection names an absent canonical proof")
    selected = (
        claim.route_proof_ids
        if type(claim) is ExactInfeasibleEffectClaim
        else claim.terminal_route_proof_ids
    )
    if not set(selected) <= proof_ids.keys():
        raise ValueError("projection does not cover the claim's proof IDs")
    projected_ids = tuple(proof_ids[proof_id] for proof_id in selected)
    if type(claim) is ExactInfeasibleEffectClaim:
        projected = replace(
            claim,
            route_proof_ids=projected_ids,
            effect_subject=replace(claim.effect_subject, _runtime_ref=None),
            source_subject=replace(claim.source_subject, _runtime_ref=None),
            predicate_subject=replace(claim.predicate_subject, _runtime_ref=None),
            selected_target_subject=replace(
                claim.selected_target_subject, _runtime_ref=None
            ),
            discarded_effect_subject=replace(
                claim.discarded_effect_subject, _runtime_ref=None
            ),
        )
    else:
        projected = replace(
            claim,
            terminal_route_proof_ids=projected_ids,
            cycle_subject=replace(claim.cycle_subject, _runtime_ref=None),
            cleanup_source_subject=replace(
                claim.cleanup_source_subject, _runtime_ref=None
            ),
            terminal_subject=replace(claim.terminal_subject, _runtime_ref=None),
        )
    return CanonicalRouteClaimProjection(
        projected, (claim.claim_id, projected.claim_id), ()
    )


@dataclass(frozen=True, slots=True)
class CanonicalDefaultGapProjection:
    exclusion: DefaultGapInfeasibilityExclusion
    exclusion_id_pair: tuple[str, str]
    digest_pair: tuple[str, str]


def project_default_gap_exclusion(
    exclusion: DefaultGapInfeasibilityExclusion,
    projection: CanonicalRouteIdProjection,
) -> CanonicalDefaultGapProjection:
    """Rebuild proof seeds and the exclusion's two checked canonical identities."""
    if type(exclusion) is not DefaultGapInfeasibilityExclusion:
        raise TypeError("projection requires an exact default gap exclusion")
    if type(projection) is not CanonicalRouteIdProjection:
        raise TypeError("projection requires canonical route ID correspondence")
    if projection.group_id_pair[1] != projection.evidence.atomic_group_id:
        raise ValueError("projection target group does not match its evidence")
    proof_ids = dict(projection.proof_id_pairs)
    if len(proof_ids) != len(projection.proof_id_pairs):
        raise ValueError("projection contains ambiguous source proof IDs")
    if not set(proof_ids.values()) <= {
        proof.proof_id for proof in projection.evidence.route_proofs
    }:
        raise ValueError("projection names an absent canonical proof")
    if not set(exclusion.route_proof_ids) <= proof_ids.keys():
        raise ValueError("projection does not cover the exclusion's proof IDs")
    seeds = tuple(
        sorted(
            (
                replace(seed, route_proof_id=proof_ids[seed.route_proof_id])
                for seed in exclusion.initial_state_seeds
            ),
            key=canonical_bytes,
        )
    )
    selected = tuple(
        sorted(proof_ids[proof_id] for proof_id in exclusion.route_proof_ids)
    )
    content = (
        "unflatten.default-gap-infeasibility-exclusion.v2",
        exclusion.state_width_bytes,
        exclusion.state_identity,
        exclusion.dispatcher,
        exclusion.default_entry,
        exclusion.residual,
        seeds,
        selected,
        exclusion.normalized_reachable_states,
    )
    projected = replace(
        exclusion,
        initial_state_seeds=seeds,
        route_proof_ids=selected,
        exclusion_id=authority_id(content),
        digest=authority_id(
            ("unflatten.default-gap-infeasibility-exclusion-digest.v1", content)
        ),
    )
    return CanonicalDefaultGapProjection(
        projected,
        (exclusion.exclusion_id, projected.exclusion_id),
        (exclusion.digest, projected.digest),
    )


@dataclass(frozen=True, slots=True)
class CanonicalDefaultGapForecastProjection:
    forecast: DefaultGapInfeasibilityForecast
    path_id_pairs: tuple[tuple[str, str], ...]
    extension_id_pair: tuple[str, str]


def project_default_gap_forecast(
    forecast: DefaultGapInfeasibilityForecast,
    projection: CanonicalRouteIdProjection,
) -> CanonicalDefaultGapForecastProjection:
    """Rebuild the default-gap wrapper's dependent path and digest indexes."""
    if type(forecast) is not DefaultGapInfeasibilityForecast:
        raise TypeError("projection requires an exact default gap forecast")
    if type(projection) is not CanonicalRouteIdProjection:
        raise TypeError("projection requires canonical route ID correspondence")
    base = forecast.base_forecast
    if base.source_generation != projection.evidence.generation:
        raise ValueError("forecast belongs to another source generation")
    if base.source_native_key != projection.evidence.native_key:
        raise ValueError("forecast belongs to another native key")
    results = tuple(
        project_default_gap_exclusion(item, projection) for item in forecast.exclusions
    )
    exclusion_ids = {
        item.exclusion_id_pair[0]: item.exclusion_id_pair[1] for item in results
    }
    exclusions = tuple(
        sorted((item.exclusion for item in results), key=lambda item: item.exclusion_id)
    )
    paths = []
    path_pairs = []
    for path in forecast.paths:
        if path.exclusion_id not in exclusion_ids:
            raise ValueError("projection does not cover a forecast path exclusion")
        exclusion_id = exclusion_ids[path.exclusion_id]
        projected = replace(
            path,
            exclusion_id=exclusion_id,
            path_id=authority_id(
                (
                    "unflatten.default-gap-infeasibility-path.v1",
                    path.nodes,
                    path.state_merge,
                    exclusion_id,
                )
            ),
        )
        paths.append(projected)
        path_pairs.append((path.path_id, projected.path_id))
    ordered_paths = tuple(sorted(paths, key=lambda item: item.path_id))
    digests = tuple((item.exclusion_id, item.digest) for item in exclusions)
    projected = replace(
        forecast,
        paths=ordered_paths,
        exclusions=exclusions,
        exclusion_digests=digests,
        extension_id=authority_id(
            (
                "unflatten.default-gap-infeasibility-forecast.v1",
                base,
                ordered_paths,
                digests,
                exclusions,
            )
        ),
    )
    return CanonicalDefaultGapForecastProjection(
        projected, tuple(path_pairs), (forecast.extension_id, projected.extension_id)
    )


@dataclass(frozen=True, slots=True)
class CanonicalEntryAllowanceProjection:
    allowance: EntryEndpointLivenessAllowance
    allowance_id_pair: tuple[str, str]


def _entry_allowance_identity(
    allowance: EntryEndpointLivenessAllowance, proof_id: str, *, legacy: bool
) -> str:
    content = (
        "unflatten.entry-endpoint-liveness-allowance.v1",
        allowance.reason,
        allowance.normalized_state,
        proof_id,
        allowance.entry_predecessor_owner_refs,
        allowance.dispatcher_old_target_ref,
        allowance.replacement_endpoint_ref,
        allowance.exit_path_refs,
        allowance.patch_step_index,
        allowance.patch_step_digest,
        allowance.state_write_source_ref,
        allowance.state_write_instruction_ea,
    )
    if not legacy:
        content += (allowance.delivery_path_refs, allowance.delivery_path_edges)
    return authority_id((*content, allowance.cut_exit_path_uses))


def project_entry_allowance(
    allowance: EntryEndpointLivenessAllowance,
    projection: CanonicalRouteIdProjection,
) -> CanonicalEntryAllowanceProjection:
    """Preserve the accepted modern or legacy empty-corridor identity form."""
    if type(allowance) is not EntryEndpointLivenessAllowance:
        raise TypeError("projection requires an exact entry allowance")
    if type(projection) is not CanonicalRouteIdProjection:
        raise TypeError("projection requires canonical route ID correspondence")
    if projection.group_id_pair[1] != projection.evidence.atomic_group_id:
        raise ValueError("projection target group does not match its evidence")
    proof_ids = dict(projection.proof_id_pairs)
    if len(proof_ids) != len(projection.proof_id_pairs):
        raise ValueError("projection contains ambiguous source proof IDs")
    if not set(proof_ids.values()) <= {
        proof.proof_id for proof in projection.evidence.route_proofs
    }:
        raise ValueError("projection names an absent canonical proof")
    if allowance.route_proof_id not in proof_ids:
        raise ValueError("projection does not cover the allowance's proof ID")
    legacy = False
    if allowance.allowance_id != _entry_allowance_identity(
        allowance, allowance.route_proof_id, legacy=False
    ):
        if (
            allowance.delivery_path_refs
            or allowance.delivery_path_edges
            or allowance.allowance_id
            != _entry_allowance_identity(
                allowance, allowance.route_proof_id, legacy=True
            )
        ):
            raise ValueError(
                "entry allowance source identity does not match its content"
            )
        legacy = True
    proof_id = proof_ids[allowance.route_proof_id]
    projected = replace(
        allowance,
        route_proof_id=proof_id,
        allowance_id=_entry_allowance_identity(allowance, proof_id, legacy=legacy),
    )
    return CanonicalEntryAllowanceProjection(
        projected, (allowance.allowance_id, projected.allowance_id)
    )


@dataclass(frozen=True, slots=True)
class CanonicalRouteProposalProjection:
    proposal: ProposedUnflattenContract
    proposal_id_pair: tuple[str, str]
    claim_id_pairs: tuple[tuple[str, str], ...]
    subject_id_pairs: tuple[tuple[str, str], ...]
    path_id_pairs: tuple[tuple[str, str], ...]
    allowance_id_pairs: tuple[tuple[str, str], ...]


def _unbound_non_route_claim(claim: ProducerUnflattenClaim) -> ProducerUnflattenClaim:
    if type(claim) is RetiredDispatcherInfrastructureClaim:
        return replace(
            claim,
            infrastructure_subject=replace(
                claim.infrastructure_subject, _runtime_ref=None
            ),
            corridor_subject=replace(claim.corridor_subject, _runtime_ref=None),
            member_subjects=tuple(
                replace(item, _runtime_ref=None) for item in claim.member_subjects
            ),
        )
    if type(claim) is DetachedDeadHandlerComponentClaim:
        return replace(
            claim,
            dispatcher_subject=replace(claim.dispatcher_subject, _runtime_ref=None),
            dead_handler_subjects=tuple(
                replace(item, _runtime_ref=None) for item in claim.dead_handler_subjects
            ),
            retained_handler_subjects=tuple(
                replace(item, _runtime_ref=None)
                for item in claim.retained_handler_subjects
            ),
            component_subjects=tuple(
                replace(item, _runtime_ref=None) for item in claim.component_subjects
            ),
            comparison_region_subjects=tuple(
                replace(item, _runtime_ref=None)
                for item in claim.comparison_region_subjects
            ),
        )
    raise TypeError("unsupported non-route producer claim family")


def project_route_proposal(
    proposal: ProposedUnflattenContract,
    projection: CanonicalRouteIdProjection,
) -> CanonicalRouteProposalProjection:
    """Project the complete proposal boundary before source authority is minted."""
    if type(proposal) is not ProposedUnflattenContract:
        raise TypeError("projection requires an exact unflatten proposal")
    if type(projection) is not CanonicalRouteIdProjection:
        raise TypeError("projection requires canonical route ID correspondence")
    if projection.group_id_pair[1] != projection.evidence.atomic_group_id:
        raise ValueError("projection target group does not match its evidence")
    proof_ids = dict(projection.proof_id_pairs)
    if len(proof_ids) != len(projection.proof_id_pairs):
        raise ValueError("projection contains ambiguous source proof IDs")
    if not set(proof_ids.values()) <= {
        proof.proof_id for proof in projection.evidence.route_proofs
    }:
        raise ValueError("projection names an absent canonical proof")
    if proposal.route_evidence.atomic_group_id != projection.group_id_pair[0]:
        raise ValueError("proposal belongs to another source route group")
    if (
        projection.evidence.route_binding is not None
        or projection.evidence.runtime_identity is not None
    ):
        raise ValueError(
            "proposal projection requires unbound canonical target evidence"
        )
    if (
        proposal.source_identity_catalog.generation != projection.evidence.generation
        or proposal.source_identity_catalog.native_key != projection.evidence.native_key
    ):
        raise ValueError("proposal source coordinates differ from target evidence")
    if {old for old, _new in projection.proof_id_pairs} != {
        item.proof_id for item in proposal.route_evidence.route_proofs
    }:
        raise ValueError("projection must cover the complete source proof group")
    claims = []
    claim_pairs = []
    subject_pairs = []
    for claim in proposal.claims:
        if type(claim) in (
            EquivalentSemanticRouteClaim,
            ExactInfeasibleEffectClaim,
            TerminalCycleBreakClaim,
        ):
            result = project_proof_referencing_claim(claim, projection)
            projected = result.claim
            subject_pairs.extend(result.subject_id_pairs)
        else:
            projected = _unbound_non_route_claim(claim)
        claims.append(projected)
        claim_pairs.append((claim.claim_id, projected.claim_id))
    forecast = proposal.corridor_coverage_forecast
    path_pairs = ()
    if type(forecast) is DefaultGapInfeasibilityForecast:
        result = project_default_gap_forecast(forecast, projection)
        forecast = result.forecast
        path_pairs = result.path_id_pairs
    elif forecast is not None and type(forecast) is not CorridorCoverageForecast:
        raise TypeError("unsupported corridor forecast family")
    allowances = tuple(
        project_entry_allowance(item, projection)
        for item in proposal.entry_endpoint_liveness_allowances
    )
    projected = replace(
        proposal,
        route_evidence=projection.evidence,
        claims=canonical_model_order(claims, "claims"),
        corridor_coverage_forecast=forecast,
        entry_endpoint_liveness_allowances=canonical_model_order(
            tuple(item.allowance for item in allowances), "entry allowances"
        ),
    )
    return CanonicalRouteProposalProjection(
        projected,
        (authority_id(proposal), authority_id(projected)),
        tuple(claim_pairs),
        tuple(subject_pairs),
        path_pairs,
        tuple(item.allowance_id_pair for item in allowances),
    )
