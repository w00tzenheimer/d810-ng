"""Canonical reference projection for explicit route claim records.

These copies carry values only. Projection never grants runtime join authority.
"""

from dataclasses import dataclass, replace

from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalRouteIdProjection,
)
from d810.transforms.unflatten_authority.model import (
    EquivalentSemanticRouteClaim,
    RouteSubjectLocator,
    SemanticSubjectRef,
)


@dataclass(frozen=True, slots=True)
class CanonicalRouteClaimProjection:
    claim: EquivalentSemanticRouteClaim
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
