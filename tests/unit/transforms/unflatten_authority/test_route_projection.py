"""Canonical route reference projection changes identity, never permission."""

from dataclasses import replace

import pytest

from d810.analyses.control_flow.semantic_route_evidence import (
    capture_structural_route_proof,
    canonical_semantic_evidence_from_proofs,
    project_owned_route_group,
    route_authority_phase,
)
from d810.core.runtime_identity import RuntimeAuthorityArena, RuntimeAuthorityScope
from d810.transforms.unflatten_authority.ids import (
    authority_id,
    canonical_bytes,
    canonical_decode,
)
from d810.transforms.unflatten_authority.producer_api import (
    build_equivalent_route_claims,
)
from d810.transforms.unflatten_authority.route_projection import (
    project_equivalent_route_claim,
)
from .helpers import exact_fixture
from .test_bind import _terminal_cycle_fixture
from .test_proposal import _default_gap_exclusion
from .test_model import _minimal_corridor_forecast, _default_gap_wrapper
from d810.transforms.unflatten_authority import model, route_projection


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


def test_claim_projection_rejects_another_source_generation():
    claims, group, _expected = projection_fixture()
    stale = replace(claims[0], source_generation=claims[0].source_generation + 1)
    with pytest.raises(ValueError, match="generation"):
        project_equivalent_route_claim(stale, group)


@pytest.mark.parametrize("family", ["exact_effect", "terminal_cycle"])
def test_other_proof_claim_projection_matches_original_bytes(family):
    if family == "exact_effect":
        _source, proposal, _exclusion, _refs = exact_fixture()
        expected = next(
            claim
            for claim in proposal.claims
            if type(claim) is model.ExactInfeasibleEffectClaim
        )
        field_name = "route_proof_ids"
    else:
        proposal, expected = _terminal_cycle_fixture()
        field_name = "terminal_route_proof_ids"
    evidence = proposal.route_evidence
    old_ids = {
        proof.proof_id: "sha256:" + format(index + 10, "064x")
        for index, proof in enumerate(evidence.route_proofs)
    }
    with route_authority_phase("other-claim-projection") as owner:
        arena = RuntimeAuthorityArena(RuntimeAuthorityScope("other-owned-proofs"))
        owner.adopt(arena)
        group = project_owned_route_group(
            arena.structural,
            evidence.generation,
            "sha256:" + "a" * 64,
            tuple(
                (
                    old_ids[proof.proof_id],
                    capture_structural_route_proof(arena.structural, proof),
                    proof.diagnostic_provenance,
                )
                for proof in evidence.route_proofs
            ),
        )
    original = replace(
        expected,
        **{field_name: tuple(old_ids[item] for item in getattr(expected, field_name))},
    )
    result = route_projection.project_proof_referencing_claim(original, group)
    assert canonical_bytes(result.claim) == canonical_bytes(expected)
    assert result.claim_id_pair == (original.claim_id, expected.claim_id)
    with pytest.raises(ValueError, match="generation"):
        route_projection.project_proof_referencing_claim(
            replace(original, source_generation=original.source_generation + 1), group
        )
    with pytest.raises(ValueError, match="cover"):
        route_projection.project_proof_referencing_claim(
            original, replace(group, proof_id_pairs=())
        )


def test_default_gap_projection_rebuilds_seed_exclusion_and_digest_ids():
    _claims, group, _expected = projection_fixture()
    _source, proposal, _exclusion, refs = exact_fixture()
    expected = _default_gap_exclusion(model, proposal, refs, residual_serial=2)
    inverse = {new: old for old, new in group.proof_id_pairs}
    seeds = tuple(
        replace(seed, route_proof_id=inverse[seed.route_proof_id])
        for seed in expected.initial_state_seeds
    )
    proofs = tuple(sorted(inverse[item] for item in expected.route_proof_ids))
    content = (
        "unflatten.default-gap-infeasibility-exclusion.v2",
        expected.state_width_bytes,
        expected.state_identity,
        expected.dispatcher,
        expected.default_entry,
        expected.residual,
        seeds,
        proofs,
        expected.normalized_reachable_states,
    )
    original = replace(
        expected,
        initial_state_seeds=seeds,
        route_proof_ids=proofs,
        exclusion_id=authority_id(content),
        digest=authority_id(
            ("unflatten.default-gap-infeasibility-exclusion-digest.v1", content)
        ),
    )
    result = route_projection.project_default_gap_exclusion(original, group)
    assert canonical_bytes(result.exclusion) == canonical_bytes(expected)
    assert result.exclusion_id_pair == (original.exclusion_id, expected.exclusion_id)
    assert result.digest_pair == (original.digest, expected.digest)
    assert original.exclusion_id != expected.exclusion_id
    with pytest.raises(ValueError, match="cover"):
        route_projection.project_default_gap_exclusion(
            original, replace(group, proof_id_pairs=())
        )


def test_default_gap_wrapper_projection_rebuilds_all_path_and_digest_indexes():
    _claims, group, _expected = projection_fixture()
    _source, proposal, _exclusion, _refs = exact_fixture()
    original, exclusion, path = _default_gap_wrapper(
        model, _minimal_corridor_forecast(model, proposal)
    )
    group = replace(
        group,
        proof_id_pairs=(
            (exclusion.route_proof_ids[0], group.evidence.route_proofs[0].proof_id),
        ),
    )
    expected_exclusion = route_projection.project_default_gap_exclusion(
        exclusion, group
    ).exclusion
    result = route_projection.project_default_gap_forecast(original, group)
    projected = result.forecast
    assert projected.base_forecast is original.base_forecast
    assert projected.exclusions == (expected_exclusion,)
    assert projected.exclusion_digests == (
        (expected_exclusion.exclusion_id, expected_exclusion.digest),
    )
    assert projected.paths[0].exclusion_id == expected_exclusion.exclusion_id
    assert projected.paths[0].nodes == path.nodes
    assert result.path_id_pairs == ((path.path_id, projected.paths[0].path_id),)
    assert result.extension_id_pair == (original.extension_id, projected.extension_id)
    assert projected.extension_id != original.extension_id
    assert projected.paths[0].path_id != path.path_id
    assert canonical_bytes(
        canonical_decode(canonical_bytes(projected))
    ) == canonical_bytes(projected)
    foreign_evidence = canonical_semantic_evidence_from_proofs(
        group.evidence.native_key,
        group.evidence.generation + 1,
        group.evidence.route_proofs,
    )
    with pytest.raises(ValueError, match="generation"):
        route_projection.project_default_gap_forecast(
            original,
            replace(
                group,
                evidence=foreign_evidence,
            ),
        )


def entry_allowance_fixture(proof_id, *, legacy, corridor):
    _source, proposal, _exclusion, refs = exact_fixture()
    fields = dict(
        reason=model.EntryEndpointLivenessReason.NO_PROVIDER_EXIT_PATH_LIVE_SAFE_ENDPOINT,
        normalized_state=7,
        route_proof_id=proof_id,
        entry_predecessor_owner_refs=(refs[0],),
        dispatcher_old_target_ref=refs[1],
        replacement_endpoint_ref=refs[2],
        exit_path_refs=(refs[1],),
        patch_step_index=0,
        patch_step_digest=authority_id("entry-step"),
        state_write_source_ref=refs[0],
        state_write_instruction_ea=0x1000,
        delivery_path_refs=(refs[0], refs[1]) if corridor else (),
        delivery_path_edges=((0, 1),) if corridor else (),
        cut_exit_path_uses=False,
    )
    content = (
        "unflatten.entry-endpoint-liveness-allowance.v1",
        fields["reason"],
        7,
        proof_id,
        (refs[0],),
        refs[1],
        refs[2],
        (refs[1],),
        0,
        fields["patch_step_digest"],
        refs[0],
        0x1000,
    )
    if not legacy:
        content += (fields["delivery_path_refs"], fields["delivery_path_edges"])
    return model.EntryEndpointLivenessAllowance(
        allowance_id=authority_id((*content, False)), **fields
    )


@pytest.mark.parametrize(
    "legacy,corridor", [(True, False), (False, False), (False, True)]
)
def test_entry_allowance_projection_preserves_each_accepted_identity_form(
    legacy, corridor
):
    _claims, group, _expected = projection_fixture()
    old, new = group.proof_id_pairs[0]
    original = entry_allowance_fixture(old, legacy=legacy, corridor=corridor)
    expected = entry_allowance_fixture(new, legacy=legacy, corridor=corridor)
    result = route_projection.project_entry_allowance(original, group)
    assert canonical_bytes(result.allowance) == canonical_bytes(expected)
    assert result.allowance_id_pair == (original.allowance_id, expected.allowance_id)
    assert original.allowance_id != expected.allowance_id
    with pytest.raises(ValueError, match="cover"):
        route_projection.project_entry_allowance(
            original, replace(group, proof_id_pairs=())
        )


@pytest.mark.parametrize("shape", ["exact", "terminal", "entry"])
def test_proposal_projection_preserves_complete_wire_bytes_and_clears_claim_authority(
    shape,
):
    _source, original, _exclusion, _refs = exact_fixture()
    if shape == "terminal":
        original, _claim = _terminal_cycle_fixture()
    elif shape == "entry":
        original = replace(
            original,
            corridor_coverage_forecast=_minimal_corridor_forecast(model, original),
            entry_endpoint_liveness_allowances=(
                entry_allowance_fixture(
                    original.route_evidence.route_proofs[0].proof_id,
                    legacy=True,
                    corridor=False,
                ),
            ),
        )
    with route_authority_phase("proposal-projection") as owner:
        arena = RuntimeAuthorityArena(RuntimeAuthorityScope("proposal-owned-proofs"))
        owner.adopt(arena)
        evidence = original.route_evidence
        group = project_owned_route_group(
            arena.structural,
            evidence.generation,
            evidence.atomic_group_id,
            tuple(
                (
                    proof.proof_id,
                    capture_structural_route_proof(arena.structural, proof),
                    proof.diagnostic_provenance,
                )
                for proof in evidence.route_proofs
            ),
        )
    result = route_projection.project_route_proposal(original, group)
    assert canonical_bytes(result.proposal) == canonical_bytes(original)
    assert result.proposal_id_pair == (authority_id(original), authority_id(original))
    assert result.proposal.route_evidence.route_binding is None
    for claim in result.proposal.claims:
        if type(claim) is model.EquivalentSemanticRouteClaim:
            assert claim.runtime_refs is None
    assert tuple(old for old, _new in result.claim_id_pairs) == tuple(
        claim.claim_id for claim in original.claims
    )
    foreign = replace(
        group, group_id_pair=("sha256:" + "b" * 64, group.group_id_pair[1])
    )
    with pytest.raises(ValueError, match="group"):
        route_projection.project_route_proposal(original, foreign)


@pytest.mark.parametrize(
    "mutation", ["duplicate", "missing", "wrong_target", "bound_target"]
)
def test_proposal_projection_rejects_invalid_complete_group_correspondence(mutation):
    _source, proposal, _exclusion, _refs = exact_fixture()
    _claims, group, _expected = projection_fixture()
    group = replace(
        group,
        group_id_pair=(
            proposal.route_evidence.atomic_group_id,
            group.evidence.atomic_group_id,
        ),
        proof_id_pairs=tuple(
            (proof.proof_id, proof.proof_id)
            for proof in proposal.route_evidence.route_proofs
        ),
    )
    if mutation == "duplicate":
        group = replace(
            group, proof_id_pairs=group.proof_id_pairs + group.proof_id_pairs[:1]
        )
    elif mutation == "missing":
        group = replace(group, proof_id_pairs=())
    elif mutation == "wrong_target":
        group = replace(
            group, group_id_pair=(group.group_id_pair[0], "sha256:" + "c" * 64)
        )
    else:
        group = replace(group, evidence=proposal.route_evidence)
    with pytest.raises(ValueError):
        route_projection.project_route_proposal(proposal, group)
