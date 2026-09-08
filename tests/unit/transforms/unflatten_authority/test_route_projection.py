"""Canonical route reference projection changes identity, never permission."""

from dataclasses import replace

import pytest

from d810.analyses.control_flow.semantic_route_evidence import (
    capture_structural_route_proof,
    project_owned_route_group,
    route_authority_phase,
)
from d810.core.runtime_identity import RuntimeAuthorityArena, RuntimeAuthorityScope
from d810.transforms.unflatten_authority.ids import canonical_bytes
from d810.transforms.unflatten_authority.producer_api import (
    build_equivalent_route_claims,
)
from d810.transforms.unflatten_authority.route_projection import (
    project_equivalent_route_claim,
)
from .helpers import exact_fixture


def projection_fixture():
    source, proposal, _exclusion, _refs = exact_fixture()
    canonical = proposal.route_evidence
    expected = build_equivalent_route_claims(
        source=source,
        source_catalog=proposal.source_identity_catalog,
        route_evidence=canonical,
        selected_proof_ids=tuple(proof.proof_id for proof in canonical.route_proofs),
    )
    source_group = "sha256:" + "a" * 64
    source_ids = {
        proof.proof_id: "sha256:" + format(index + 1, "064x")
        for index, proof in enumerate(canonical.route_proofs)
    }
    with route_authority_phase("projection-test") as owner:
        arena = RuntimeAuthorityArena(RuntimeAuthorityScope("owned-proofs"))
        owner.adopt(arena)
        entries = tuple(
            (
                source_ids[proof.proof_id],
                capture_structural_route_proof(arena.structural, proof),
                proof.diagnostic_provenance,
            )
            for proof in canonical.route_proofs
        )
        group = project_owned_route_group(
            arena.structural, canonical.generation, source_group, entries
        )
    claims = []
    for claim in expected:

        def remap_subject(subject):
            return replace(
                subject,
                locator=replace(
                    subject.locator,
                    proof_id=source_ids[subject.locator.proof_id],
                    atomic_group_id=source_group,
                ),
                _runtime_ref=None,
            )

        claims.append(
            replace(
                claim,
                retired_route_subject=remap_subject(claim.retired_route_subject),
                replacement_route_subject=remap_subject(
                    claim.replacement_route_subject
                ),
                route_proof_ids=tuple(
                    source_ids[item] for item in claim.route_proof_ids
                ),
                atomic_group_id=source_group,
                _runtime_refs=None,
            )
        )
    return tuple(claims), group, expected


def test_claim_projection_matches_original_canonical_producer_bytes():
    claims, group, expected = projection_fixture()
    results = tuple(project_equivalent_route_claim(claim, group) for claim in claims)
    assert sorted(canonical_bytes(item.claim) for item in results) == sorted(
        canonical_bytes(claim) for claim in expected
    )
    for original, result in zip(claims, results, strict=True):
        assert result.claim.runtime_refs is None
        assert result.claim_id_pair == (original.claim_id, result.claim.claim_id)
        assert result.claim_id_pair[0] != result.claim_id_pair[1]
        assert result.subject_id_pairs == (
            (
                original.retired_route_subject.subject_id,
                result.claim.retired_route_subject.subject_id,
            ),
            (
                original.replacement_route_subject.subject_id,
                result.claim.replacement_route_subject.subject_id,
            ),
        )
        assert result.claim.retired_route_subject.runtime_ref is None
        assert result.claim.replacement_route_subject.runtime_ref is None


@pytest.mark.parametrize(
    "mutation", ["foreign_group", "missing_proof", "ambiguous_proof", "foreign_target"]
)
def test_claim_projection_rejects_incomplete_or_conflicting_correspondence(mutation):
    claims, group, _expected = projection_fixture()
    if mutation == "foreign_group":
        group = replace(
            group, group_id_pair=("sha256:" + "b" * 64, group.group_id_pair[1])
        )
    elif mutation == "missing_proof":
        group = replace(group, proof_id_pairs=())
    elif mutation == "ambiguous_proof":
        group = replace(
            group, proof_id_pairs=group.proof_id_pairs + group.proof_id_pairs[:1]
        )
    else:
        group = replace(
            group,
            proof_id_pairs=tuple(
                (old, "sha256:" + "b" * 64) for old, _new in group.proof_id_pairs
            ),
        )
    with pytest.raises(ValueError):
        project_equivalent_route_claim(claims[0], group)


def test_projection_drops_live_claim_authority_even_when_ids_are_unchanged():
    _claims, group, expected = projection_fixture()
    claim = expected[0]
    assert claim.runtime_refs is not None
    identity_projection = replace(
        group,
        group_id_pair=(group.evidence.atomic_group_id, group.evidence.atomic_group_id),
        proof_id_pairs=tuple(
            (proof.proof_id, proof.proof_id) for proof in group.evidence.route_proofs
        ),
    )
    result = project_equivalent_route_claim(claim, identity_projection)
    assert canonical_bytes(result.claim) == canonical_bytes(claim)
    assert result.claim.runtime_refs is None
    assert all(
        subject.runtime_ref is None
        for subject in (
            result.claim.retired_route_subject,
            result.claim.replacement_route_subject,
            result.claim.source_subject,
            *result.claim.destination_subjects,
            *result.claim.dag_endpoint_subjects,
        )
    )
