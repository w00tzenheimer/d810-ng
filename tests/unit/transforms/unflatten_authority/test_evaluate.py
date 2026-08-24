"""Task 4 evaluator contract tests."""

from __future__ import annotations

import inspect
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.semantic_route_evidence import BoundCanonicalSemanticEvidence
from d810.analyses.control_flow.semantic_route_evidence import BoundSemanticBlock
from d810.analyses.control_flow.semantic_route_evidence import BoundSemanticRoute
from d810.analyses.control_flow.semantic_route_evidence import BoundSemanticRouteDestination
from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalRouteAssessmentPhase, CanonicalRouteMaterialization,
    assess_canonical_route,
)
from d810.ir.maturity import MaturityEnvelope
from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority import gates
from d810.transforms.unflatten_authority import views
from d810.transforms.unflatten_authority.evaluate import _classify_effect_site
from d810.transforms.unflatten_authority.evaluate import _accepted_detached_component_results
from d810.transforms.unflatten_authority.evaluate import _dimensions
from d810.transforms.unflatten_authority.evaluate import _receipt_digest
from d810.transforms.unflatten_authority.evaluate import build_semantic_case
from d810.transforms.unflatten_authority.evaluate import derive_corridor_coverage_evidence
from d810.transforms.unflatten_authority.evaluate import evaluate_case
from d810.transforms.unflatten_authority.evaluate import REQUIRED_DIMENSIONS
from d810.transforms.patch_binding import BoundPatchPlan
from d810.transforms.plan import PatchPlan
from d810.transforms.unflatten_authority.ids import _case_factory, _claim_factory, _evidence_factory, _justification_factory, _subject_factory, authority_id as canonical_authority_id, bound_unflatten_binding_id, canonical_bytes, canonical_decode, content_id, receipt_id, semantic_graph_inventory_digest
from .helpers import authority_id, block_ref, state_identity
from .test_model import _minimal_corridor_forecast, _retirement_catalog, _valid_proposal


def test_equivalent_route_claim_uses_closed_subject_roles_and_reciprocal_topology() -> None:
    """Every canonical route must become one closed, topology-bound claim."""

    from d810.transforms.unflatten_authority import producer_api
    from .helpers import exact_fixture

    source, proposal, _exclusion, refs = exact_fixture()
    proof = proposal.route_evidence.route_proofs[0]
    route_claims = producer_api.build_equivalent_route_claims(
        source=source,
        source_catalog=proposal.source_identity_catalog,
        route_evidence=proposal.route_evidence,
        selected_proof_ids=(proof.proof_id,),
    )
    assert len(route_claims) == 1
    claim = route_claims[0]
    assert claim.route_proof_ids == (proof.proof_id,)
    assert claim.atomic_group_id == proof.atomic_group_id
    assert claim.source_subject.role is model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE
    assert all(
        item.role is model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION
        for item in claim.destination_subjects
    )
    assert claim.source_generation == proposal.source_identity_catalog.generation
    route_proposal = replace(
        proposal,
        claims=(claim,),
        plan_inputs=replace(
            proposal.plan_inputs,
            shape=model.UnflattenPlanShape.PARTIAL_REWRITE,
        ),
    )
    assert producer_api.resolve_equivalent_route_claim(
        source=source,
        proposal=route_proposal,
        claim=claim,
        block_refs_by_serial=refs,
    ) is claim


def test_equivalent_route_requires_one_accepted_source_and_projected_assessment_pair() -> None:
    """A route claim is not authority until both phase assessments close it."""

    from d810.transforms.unflatten_authority import producer_api

    source, proposal, _exclusion, refs = __import__(
        "tests.unit.transforms.unflatten_authority.helpers", fromlist=["exact_fixture"],
    ).exact_fixture()
    proof = proposal.route_evidence.route_proofs[0]
    claim = producer_api.build_equivalent_route_claims(
        source=source,
        source_catalog=proposal.source_identity_catalog,
        route_evidence=proposal.route_evidence,
        selected_proof_ids=(proof.proof_id,),
    )[0]
    source_assessment = assess_canonical_route(
        CanonicalRouteMaterialization.capture(
            source, generation=1, phase=CanonicalRouteAssessmentPhase.SOURCE,
        ), proposal.route_evidence,
    )
    projected_assessment = assess_canonical_route(
        CanonicalRouteMaterialization.capture(
            source, generation=1, phase=CanonicalRouteAssessmentPhase.PROJECTED,
        ), proposal.route_evidence,
    )
    inputs = SimpleNamespace(
        proposal=proposal,
        source_route_assessment=source_assessment,
        candidate_route_assessment=projected_assessment,
        source_inventory=SimpleNamespace(
            graph_fingerprint=source_assessment.graph_fingerprint, generation=1,
        ),
        candidate_inventory=SimpleNamespace(
            graph_fingerprint=projected_assessment.graph_fingerprint, generation=1,
        ),
    )
    inputs.proposal = replace(
        proposal,
        claims=(claim,),
        plan_inputs=replace(
            proposal.plan_inputs,
            shape=model.UnflattenPlanShape.PARTIAL_REWRITE,
        ),
    )
    from d810.transforms.unflatten_authority.evaluate import _validate_route_assessment_pair
    _validate_route_assessment_pair(
        inputs,
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        claim,
    )

    # Candidate observations may legitimately be a later graph generation;
    # the assessment and candidate inventory, rather than the source claim,
    # own that generation coordinate.
    candidate_generation_four = assess_canonical_route(
        CanonicalRouteMaterialization.capture(
            source, generation=4, phase=CanonicalRouteAssessmentPhase.PROJECTED,
        ), proposal.route_evidence,
    )
    inputs.candidate_route_assessment = candidate_generation_four
    inputs.candidate_inventory.generation = 4
    _validate_route_assessment_pair(
        inputs,
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        claim,
    )
    inputs.candidate_route_assessment = projected_assessment
    inputs.candidate_inventory.generation = 1

    observed_assessment = assess_canonical_route(
        CanonicalRouteMaterialization.capture(
            source, generation=1, phase=CanonicalRouteAssessmentPhase.OBSERVED,
        ), proposal.route_evidence,
    )
    inputs.candidate_route_assessment = observed_assessment
    with pytest.raises(ValueError, match="wrong phase"):
        _validate_route_assessment_pair(
            inputs,
            model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            claim,
        )
    inputs.candidate_route_assessment = projected_assessment
    object.__setattr__(projected_assessment, "graph_fingerprint", authority_id("foreign-candidate"))
    with pytest.raises((TypeError, ValueError)):
        _validate_route_assessment_pair(
            inputs,
            model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            claim,
        )
    object.__setattr__(projected_assessment, "graph_fingerprint", source_assessment.graph_fingerprint)
    object.__setattr__(projected_assessment, "generation", 99)
    with pytest.raises(ValueError, match="seal|immutable"):
        _validate_route_assessment_pair(
            inputs,
            model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            claim,
        )
    object.__setattr__(projected_assessment, "generation", 1)
    object.__setattr__(projected_assessment, "bound_evidence", None)
    with pytest.raises((TypeError, ValueError)):
        _validate_route_assessment_pair(
            inputs,
            model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            claim,
        )


def test_equivalent_route_positive_marks_one_stable_subject_route_equivalence() -> None:
    """One assessed route satisfies every exact cell on its stable subjects."""

    from d810.analyses.control_flow.graph_checks import (
        check_effectful_reachability_preserved,
        check_entry_reachability_not_collapsed,
        check_terminal_reachability_preserved,
    )
    from d810.transforms.cfg_transaction import CfgProjection
    from d810.transforms.plan import PatchPlan, PatchRedirectGoto
    from d810.transforms.unflatten_authority import producer_api
    from d810.transforms.unflatten_authority import transaction_api
    from d810.transforms.unflatten_authority.gates import GenericCfgGateBundle
    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest
    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture

    source, proposal, _exclusion, refs = exact_fixture()
    proof = proposal.route_evidence.route_proofs[0]
    claim = producer_api.build_equivalent_route_claims(
        source=source,
        source_catalog=proposal.source_identity_catalog,
        route_evidence=proposal.route_evidence,
        selected_proof_ids=(proof.proof_id,),
    )[0]
    proposal = replace(
        proposal,
        claims=(claim,),
        plan_inputs=replace(
            proposal.plan_inputs, shape=model.UnflattenPlanShape.PARTIAL_REWRITE,
        ),
    )
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("route-positive-snapshot"),
        source_generation=proposal.source_identity_catalog.generation,
        steps=(
            PatchRedirectGoto(refs[0], refs[1], refs[2]),
            PatchRedirectGoto(refs[1], refs[2], refs[0]),
        ),
        source_coordinates=tuple((ref, serial) for serial, ref in refs.items()),
    )
    manifest = canonical_redirect_manifest(plan)
    proposal = replace(
        proposal,
        use_def_witness=replace(
            proposal.use_def_witness,
            redirect_owner_refs=manifest.owner_refs,
            redirect_digest=manifest.digest,
        ),
    )
    plan = replace(plan, unflatten_proposal=proposal)
    projection = CfgProjection(plan.plan_id, plan.snapshot_id, source)
    generic = GenericCfgGateBundle(
        check_entry_reachability_not_collapsed(source, post_cfg=source),
        check_effectful_reachability_preserved(source, post_cfg=source),
        check_effectful_reachability_preserved(source, post_cfg=source),
        check_terminal_reachability_preserved(source, post_cfg=source),
    )
    inputs = transaction_api.derive_unflatten_preparation_inputs(
        source, projection, plan, proposal, generic,
    )
    case = build_semantic_case(
        authority_id=authority_id("route-positive-case"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=inputs,
    )
    assert claim.retired_route_subject == claim.replacement_route_subject
    assert len(claim.route_proof_ids) == 1
    route_subjects = {
        claim.retired_route_subject,
        claim.source_subject,
        *claim.destination_subjects,
    }
    route_cells = tuple(
        cell for cell in case.obligation_index.cells
        if cell.key.subject in route_subjects
    )
    assert route_cells
    assert all(cell.state is model.ObligationState.SATISFIED for cell in route_cells)
    assert any(
        cell.key.subject == claim.retired_route_subject
        and cell.key.dimension is model.SafetyDimension.ROUTE_EQUIVALENCE
        and cell.supporting_justification_ids
        for cell in route_cells
    )


def test_route_payload_uses_selected_claim_source_among_colocated_route_sources() -> None:
    """Route evidence follows the selected claim source, not first topology match."""

    from d810.transforms.unflatten_authority import producer_api
    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture

    source, proposal, _exclusion, _refs = exact_fixture()
    proof = proposal.route_evidence.route_proofs[0]
    claim = producer_api.build_equivalent_route_claims(
        source=source,
        source_catalog=proposal.source_identity_catalog,
        route_evidence=proposal.route_evidence,
        selected_proof_ids=(proof.proof_id,),
    )[0]
    proposal = replace(
        proposal,
        claims=(claim,),
        plan_inputs=replace(
            proposal.plan_inputs, shape=model.UnflattenPlanShape.PARTIAL_REWRITE,
        ),
    )
    duplicate_locator = replace(
        claim.retired_route_subject.locator,
        proof_id="sha256:" + "0" * 64,
    )
    duplicate = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.ROUTE,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        block_ref=claim.source_subject.block_ref,
        anchor_ea=claim.source_subject.anchor_ea,
        locator=duplicate_locator,
    )
    assert duplicate != claim.source_subject
    assert duplicate.block_ref == claim.source_subject.block_ref
    assert duplicate.anchor_ea == claim.source_subject.anchor_ea
    from d810.transforms.unflatten_authority.evaluate import _select_route_source_subject

    selected = _select_route_source_subject(
        claim,
        claim.retired_route_subject.locator,
        (claim.source_subject, duplicate),
    )
    assert selected is claim.source_subject


def test_evaluator_rejects_empty_or_incomplete_exclusion_path_correlations() -> None:
    """Evaluator correlation transport must close the exact forecast pair universe."""

    from tests.unit.transforms.unflatten_authority.test_model import (
        _candidate_prefix_correlation_fixture,
    )

    source_entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "correlation-universe")
    corridor = _role_subject(model.SemanticSubjectRole.DISPATCHER_CORRIDOR, "correlation-corridor")
    inputs = _complete_inputs(source_subjects=(source_entry, corridor))
    result, first, second = _candidate_prefix_correlation_fixture(model)
    source_ref = block_ref("b1")
    dispatcher_ref = inputs.proposal.plan_inputs.dispatcher_entry_ref
    source_node = model.CorridorCoveragePathNode(source_ref, 0x1300)
    dispatcher_node = model.CorridorCoveragePathNode(dispatcher_ref, 0x1000)
    alternate_node = model.CorridorCoveragePathNode(block_ref("b2"), 0x1100)
    path_nodes = ((source_node, dispatcher_node), (alternate_node, dispatcher_node))
    exclusion_state = inputs.proposal.plan_inputs.state_identity
    exclusion_typed = (
        "unflatten.corridor-semantic-exclusion.v1", 7, exclusion_state,
        source_node, alternate_node, source_node, dispatcher_node,
    )
    exclusion_id = canonical_authority_id(exclusion_typed)
    exclusion_digest = canonical_authority_id((
        "unflatten.corridor-semantic-exclusion-digest.v1", exclusion_typed,
    ))
    exclusion = model.CorridorSemanticExclusion(
        exclusion_id, exclusion_digest, 7, exclusion_state,
        source_node, alternate_node, source_node, dispatcher_node,
    )
    paths = tuple(
        model.CorridorCoveragePath(
            canonical_authority_id((
                "unflatten.corridor-coverage-path.v1", nodes, None,
                model.CorridorPathDisposition.SEMANTICALLY_EXCLUDED,
                (exclusion_id,),
            )),
            nodes, None, model.CorridorPathDisposition.SEMANTICALLY_EXCLUDED,
            (exclusion_id,),
        )
        for nodes in path_nodes
    )
    path_ids = tuple(path.path_id for path in paths)
    forecast_id = canonical_authority_id((
        "unflatten.corridor-coverage-forecast.v1", inputs.proposal.plan_id,
        inputs.source_inventory.function_ea,
        inputs.proposal.source_identity_catalog.native_key,
        inputs.source_inventory.generation, dispatcher_ref, 0x1000,
        paths, path_ids, (), True, ((exclusion_id, exclusion_digest),),
        (exclusion,), ((exclusion_id, path_ids),),
    ))
    forecast = model.CorridorCoverageForecast(
        forecast_id, inputs.proposal.plan_id, inputs.source_inventory.function_ea,
        inputs.proposal.source_identity_catalog.native_key,
        inputs.source_inventory.generation, dispatcher_ref, 0x1000,
        paths, path_ids, (), True, ((exclusion_id, exclusion_digest),),
        (exclusion,), ((exclusion_id, path_ids),),
    )
    object.__setattr__(inputs.proposal, "corridor_coverage_forecast", forecast)
    object.__setattr__(inputs.preparation_receipt, "corridor_coverage_forecast", forecast)
    object.__setattr__(inputs.preparation_receipt, "receipt_id", receipt_id(inputs.preparation_receipt))

    for correlations in ((first,),):
        correlations = tuple(
            replace(
                item,
                exclusion_id=exclusion_id,
                exclusion_digest=exclusion_digest,
                path_id=path_ids[0],
                ordered_prefix=paths[0].nodes,
                source_fingerprint=inputs.source_inventory.graph_fingerprint,
                candidate_fingerprint=inputs.candidate_inventory.graph_fingerprint,
            )
            for item in correlations
        )
        result_id = canonical_authority_id((
            "unflatten.corridor-coverage-phase.v1", forecast_id,
            result.phase, inputs.source_inventory.graph_fingerprint,
            inputs.candidate_inventory.graph_fingerprint,
            result.source_generation, result.candidate_generation,
            path_ids, (), (), True, (exclusion_id,),
            result.source_dispatcher_reachable,
            result.candidate_dispatcher_reachable,
            tuple(item.content_key for item in correlations),
        ))
        reminted_correlations = tuple(
            replace(item, phase_result_id=result_id) for item in correlations
        )
        reminted_result = model.CorridorCoveragePhaseResult(
            result_id, forecast_id, result.phase,
            inputs.source_inventory.graph_fingerprint,
            inputs.candidate_inventory.graph_fingerprint,
            result.source_generation, result.candidate_generation,
            path_ids, (), (), True, (exclusion_id,),
            result.source_dispatcher_reachable,
            result.candidate_dispatcher_reachable,
            reminted_correlations,
        )
        object.__setattr__(inputs, "corridor_coverage_phase_result", reminted_result)
        with pytest.raises(ValueError, match="exact forecast universe"):
            derive_corridor_coverage_evidence(
                inputs,
                model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            )



def _role_subject(role: model.SemanticSubjectRole, token: str) -> model.SemanticSubjectRef:
    if role in {
        model.SemanticSubjectRole.SOURCE_ENTRY,
        model.SemanticSubjectRole.DISPATCHER_ENTRY,
    }:
        ref = block_ref("b0")
    elif token.rsplit("-", 1)[-1].isdigit():
        ref = block_ref(f"b{int(token.rsplit('-', 1)[-1]) % 3}")
    else:
        ref = block_ref("b0")
    ref_anchor = {"b0": 0x1000, "b1": 0x1300, "b2": 0x1100}[ref.proxy_token]
    if role is model.SemanticSubjectRole.AUTHORITATIVE_HANDLER:
        kind, locator, owner, anchor = model.SemanticSubjectKind.HANDLER, model.HandlerSubjectLocator(ref, ref_anchor, (1,)), ref, ref_anchor
    elif role is model.SemanticSubjectRole.TERMINAL_SITE:
        kind, locator, owner, anchor = model.SemanticSubjectKind.TERMINAL, model.TerminalSubjectLocator(ref, ref_anchor, model.TerminalKind.RETURN, ref_anchor + 4), ref, ref_anchor
    elif role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW:
        kind, locator, owner, anchor = model.SemanticSubjectKind.VALUE_FLOW, model.ValueFlowSubjectLocator(authority_id("fragment"), state_identity(), (block_ref("b0"),)), None, None
    elif role is model.SemanticSubjectRole.DISPATCHER_CORRIDOR:
        kind, locator, owner, anchor = model.SemanticSubjectKind.CORRIDOR, model.CorridorSubjectLocator(authority_id(token), ref, ref_anchor, (ref,), (ref_anchor,)), ref, ref_anchor
    elif role is model.SemanticSubjectRole.EFFECT_SITE:
        kind, locator, owner, anchor = model.SemanticSubjectKind.EFFECT, model.EffectSubjectLocator(ref, ref_anchor, ref_anchor + 4, model.EffectSiteKind.STORE), ref, ref_anchor
    else:
        kind, locator, owner, anchor = model.SemanticSubjectKind.BLOCK, model.BlockSubjectLocator(ref, ref_anchor), ref, ref_anchor
    return _subject_factory(
        model.SemanticSubjectRef, kind=kind, role=role,
        block_ref=owner, anchor_ea=anchor, locator=locator,
    )


def test_route_payload_projects_destination_ids_in_locator_pair_order() -> None:
    """Destination IDs follow paired ref/EA order, not their hash order."""

    source = _role_subject(model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, "1")
    first = _role_subject(model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION, "0")
    second = _role_subject(model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION, "2")
    locator = model.RouteSubjectLocator(
        authority_id("route-order-proof"), authority_id("route-order-group"),
        source.block_ref, source.anchor_ea,
        (second.block_ref, first.block_ref),
        (second.anchor_ea, first.anchor_ea),
    )
    route = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.ROUTE,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        block_ref=locator.source_ref,
        anchor_ea=locator.source_anchor_ea,
        locator=locator,
    )
    by_pair = {
        (first.block_ref, first.anchor_ea): first.subject_id,
        (second.block_ref, second.anchor_ea): second.subject_id,
    }
    payload = model.SemanticRouteEvidencePayload(
        route.subject_id,
        (locator.proof_id,),
        locator.atomic_group_id,
        source.subject_id,
        tuple(by_pair[pair] for pair in zip(locator.destination_refs, locator.destination_anchor_eas)),
        True,
    )
    assert payload.destination_subject_ids != tuple(sorted(by_pair.values()))
    assert canonical_decode(canonical_bytes(payload)) == payload


def test_corridor_coverage_uses_plan_catalog_without_graph_rescan() -> None:
    """The aggregate corridor cell is a sealed path-domain phase result."""

    source_entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "source")
    entry = _role_subject(model.SemanticSubjectRole.DISPATCHER_ENTRY, "0")
    member0 = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "0")
    member1 = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "1")
    corridor_locator = model.CorridorSubjectLocator(
        authority_id("catalog-corridor"), entry.block_ref, entry.anchor_ea,
        (member0.block_ref, member1.block_ref),
        (member0.anchor_ea, member1.anchor_ea),
    )
    corridor = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.CORRIDOR,
        role=model.SemanticSubjectRole.DISPATCHER_CORRIDOR,
        block_ref=entry.block_ref,
        anchor_ea=entry.anchor_ea,
        locator=corridor_locator,
    )
    proposal_values = _valid_proposal(model)
    path_nodes = (
        model.CorridorCoveragePathNode(block_ref("b1"), 0x1300),
        model.CorridorCoveragePathNode(block_ref("b0"), 0x1000),
    )
    path_id = canonical_authority_id((
        "unflatten.corridor-coverage-path.v1", path_nodes, None,
        model.CorridorPathDisposition.STRUCTURALLY_COVERED, (),
    ))
    path = model.CorridorCoveragePath(
        path_id, path_nodes, None,
        model.CorridorPathDisposition.STRUCTURALLY_COVERED, (),
    )
    forecast_id = canonical_authority_id((
        "unflatten.corridor-coverage-forecast.v1", proposal_values["plan_id"],
        0, proposal_values["source_identity_catalog"].native_key, 3,
        block_ref("b0"), 0x1000, (path,), (path_id,), (), True, (), (), (),
    ))
    proposal_values["corridor_coverage_forecast"] = model.CorridorCoverageForecast(
        forecast_id, proposal_values["plan_id"], 0,
        proposal_values["source_identity_catalog"].native_key, 3, block_ref("b0"),
        0x1000, (path,), (path_id,), (), True, (), (), (),
    )
    proposal = model.ProposedUnflattenContract(**proposal_values)
    complete_inputs = _complete_inputs(
        source_subjects=(source_entry, entry, member0, member1, corridor),
        candidate_subjects=(source_entry, entry, member0, member1, corridor),
        proposal=proposal,
    )
    case = build_semantic_case(
        authority_id=authority_id("catalog-corridor-case"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=complete_inputs,
    )
    coverage = derive_corridor_coverage_evidence(
        complete_inputs,
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    assert coverage is not None
    assert coverage.forecast_id == proposal.corridor_coverage_forecast.forecast_id
    assert coverage.covered_path_ids == (path_id,)
    corridor_cells = tuple(
        cell for cell in case.obligation_index.cells
        if cell.key.subject == corridor
    )
    assert tuple(cell.key.dimension for cell in corridor_cells) == (
        model.SafetyDimension.CORRIDOR_COVERAGE,
        model.SafetyDimension.IDENTITY_BINDING,
    )
    assert all(cell.state is model.ObligationState.SATISFIED for cell in corridor_cells)
    assert not any(
        item.kind is model.AuthorityEvidenceKind.CORRIDOR_COVERAGE
        and item.subject.subject_id != corridor.subject_id
        for item in case.evidence
    )
    assert case.phase_metrics.view_graph_traversals == 0


def test_derived_inputs_reject_reminted_inventory_function_ea() -> None:
    """Direct construction cannot bypass the binder's function identity seal."""

    source_entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "source")
    entry = _role_subject(model.SemanticSubjectRole.DISPATCHER_ENTRY, "0")
    member0 = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "0")
    member1 = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "1")
    corridor = _role_subject(model.SemanticSubjectRole.DISPATCHER_CORRIDOR, "corridor")
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    proposal = replace(proposal, corridor_coverage_forecast=_minimal_corridor_forecast(model, proposal))
    inputs = _complete_inputs(
        source_subjects=(source_entry, entry, member0, member1, corridor),
        candidate_subjects=(source_entry, entry, member0, member1, corridor),
        proposal=proposal,
    )
    wrong_function_ea = 0x8000
    wrong_digest = semantic_graph_inventory_digest(
        inputs.source_inventory.phase, inputs.source_inventory.graph_fingerprint,
        inputs.source_inventory.generation, inputs.source_inventory.blocks,
        inputs.source_inventory.subjects, inputs.source_inventory.bindings,
        inputs.source_inventory.effects, inputs.source_inventory.terminals,
        inputs.source_inventory.topology, inputs.source_inventory.reachable_serials,
        inputs.source_inventory.entry_serial, inputs.source_inventory.source_subject_ids,
        wrong_function_ea,
    )
    reminted_source = replace(
        inputs.source_inventory,
        function_ea=wrong_function_ea,
        inventory_digest=wrong_digest,
    )
    candidate_digest = semantic_graph_inventory_digest(
        inputs.candidate_inventory.phase, inputs.candidate_inventory.graph_fingerprint,
        inputs.candidate_inventory.generation, inputs.candidate_inventory.blocks,
        inputs.candidate_inventory.subjects, inputs.candidate_inventory.bindings,
        inputs.candidate_inventory.effects, inputs.candidate_inventory.terminals,
        inputs.candidate_inventory.topology, inputs.candidate_inventory.reachable_serials,
        inputs.candidate_inventory.entry_serial, inputs.candidate_inventory.source_subject_ids,
        wrong_function_ea,
    )
    reminted_candidate = replace(
        inputs.candidate_inventory,
        function_ea=wrong_function_ea,
        inventory_digest=candidate_digest,
    )
    from copy import copy
    reminted_receipt = copy(inputs.preparation_receipt)
    object.__setattr__(reminted_receipt, "source_inventory_digest", wrong_digest)
    object.__setattr__(reminted_receipt, "candidate_inventory_digest", candidate_digest)
    object.__setattr__(reminted_receipt, "receipt_id", receipt_id(reminted_receipt))
    with pytest.raises(ValueError, match="function EA"):
        replace(
            inputs,
            source_inventory=reminted_source,
            candidate_inventory=reminted_candidate,
            preparation_receipt=reminted_receipt,
        )
    case = build_semantic_case(
        authority_id=authority_id("function-ea-case"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=inputs,
    )
    with pytest.raises(ValueError, match="function EA"):
        replace(
            case,
            source_inventory=reminted_source,
            preparation_receipt=reminted_receipt,
            preparation_receipt_id=reminted_receipt.receipt_id,
        )



def _digest(value: object) -> str:
    return content_id("unflatten.authority.v1", value)


def _receipt_fixture(**kwargs: object) -> model.PreparationAuthorityReceipt:
    """Construct a complete receipt through the closed mint API."""
    kwargs.setdefault(
        "projected_topology_reference_digest",
        kwargs["candidate_inventory_digest"],
    )
    return model.PreparationAuthorityReceipt.mint(**kwargs)


def _binding(subject: model.SemanticSubjectRef, phase: model.UnflattenAuthorityPhase, generation: int = 3, *, status: model.SubjectBindingStatus = model.SubjectBindingStatus.UNIQUE, fingerprint: str | None = None) -> model.PhaseSubjectBinding:
    if subject.block_ref is None:
        status = model.SubjectBindingStatus.MISSING
    if (
        type(subject.locator) is model.RouteSubjectLocator
        and subject.locator.proof_id.endswith("0" * 64)
    ):
        status = model.SubjectBindingStatus.MISSING
    serial_by_proxy = {"b0": 0, "b1": 1, "b2": 2, "b3": 3, "b4": 4}
    serial = serial_by_proxy.get(getattr(subject.block_ref, "proxy_token", ""), 0)
    native_instruction_eas = ((subject.anchor_ea,) if subject.anchor_ea is not None else ())
    return model.PhaseSubjectBinding(
        subject=subject, phase=phase, block_ref=subject.block_ref if status is model.SubjectBindingStatus.UNIQUE else None,
        graph_fingerprint=fingerprint or authority_id(f"graph-{phase.value}"), generation=generation, status=status,
        serial=serial if status is model.SubjectBindingStatus.UNIQUE else None,
        anchor_ea=subject.anchor_ea if status is model.SubjectBindingStatus.UNIQUE else None,
        native_instruction_eas=native_instruction_eas if status is model.SubjectBindingStatus.UNIQUE else (), role=subject.role,
    )


def _complete_inputs(*, source_subjects: tuple[model.SemanticSubjectRef, ...], candidate_subjects: tuple[model.SemanticSubjectRef, ...] | None = None, source_bindings: tuple[model.PhaseSubjectBinding, ...] | None = None, candidate_bindings: tuple[model.PhaseSubjectBinding, ...] | None = None, patch_step_facts: tuple[model.PatchStepEvidencePayload, ...] = (), claims: tuple[model.UnflattenClaim, ...] | None = None, proposal: model.ProposedUnflattenContract | None = None, native_instruction_eas_by_block: dict[object, tuple[int, ...]] | None = None) -> model.DerivedUnflattenPreparationInputs:
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model)) if proposal is None else proposal
    if tuple(proposal.use_def_witness.redirect_owner_refs) != tuple(proposal.plan_inputs.dispatcher_member_refs):
        object.__setattr__(proposal.use_def_witness, "redirect_owner_refs", proposal.plan_inputs.dispatcher_member_refs)
    claims = proposal.claims if claims is None else claims
    phase = model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
    def normalize_value_flow(subjects: tuple[model.SemanticSubjectRef, ...]) -> tuple[model.SemanticSubjectRef, ...]:
        return tuple(
            _subject_factory(
                model.SemanticSubjectRef,
                kind=model.SemanticSubjectKind.VALUE_FLOW,
                role=model.SemanticSubjectRole.NON_STATE_VALUE_FLOW,
                block_ref=None, anchor_ea=None,
                locator=model.ValueFlowSubjectLocator(
                    proposal.use_def_witness.fragment_id,
                    proposal.use_def_witness.state_identity,
                    proposal.use_def_witness.redirect_owner_refs,
                ),
            ) if subject.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW else subject
            for subject in subjects
        )
    source_subjects = normalize_value_flow(source_subjects)
    terminal_effect_subjects = []
    for subject in source_subjects:
        if (
            subject.role is not model.SemanticSubjectRole.TERMINAL_SITE
            or type(subject.locator) is not model.TerminalSubjectLocator
        ):
            continue
        effect_kind = {
            model.TerminalKind.RETURN: model.EffectSiteKind.RETURN,
            model.TerminalKind.TRAP: model.EffectSiteKind.TRAP,
            model.TerminalKind.NORETURN_CALL: model.EffectSiteKind.CALL,
        }.get(subject.locator.terminal_kind)
        if effect_kind is not None:
            terminal_effect_subjects.append(_subject_factory(
                model.SemanticSubjectRef,
                kind=model.SemanticSubjectKind.EFFECT,
                role=model.SemanticSubjectRole.EFFECT_SITE,
                block_ref=subject.block_ref,
                anchor_ea=subject.anchor_ea,
                locator=model.EffectSubjectLocator(
                    subject.locator.block_ref,
                    subject.locator.anchor_ea,
                    subject.locator.instruction_ea,
                    effect_kind,
                ),
            ))
    source_subjects = tuple({
        item.subject_id: item for item in (*source_subjects, *terminal_effect_subjects)
    }.values())
    if source_subjects and not any(item.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW for item in source_subjects):
        source_subjects = (*source_subjects, _subject_factory(
            model.SemanticSubjectRef,
            kind=model.SemanticSubjectKind.VALUE_FLOW,
            role=model.SemanticSubjectRole.NON_STATE_VALUE_FLOW,
            block_ref=None, anchor_ea=None,
            locator=model.ValueFlowSubjectLocator(
                proposal.use_def_witness.fragment_id,
                proposal.use_def_witness.state_identity,
                proposal.use_def_witness.redirect_owner_refs,
            ),
        ))
    # This fixture is deliberately proposal-complete: every plan-input and
    # producer-claim subject is explicit before bindings are built.
    required_subjects = (
        _role_subject(model.SemanticSubjectRole.DISPATCHER_ENTRY, "0"),
        _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "0"),
        _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "1"),
        _role_subject(model.SemanticSubjectRole.AUTHORITATIVE_HANDLER, "2"),
        *(subject for claim in claims for subject in (
            (claim.retired_route_subject, claim.replacement_route_subject,
             claim.source_subject, *claim.destination_subjects)
            if type(claim) is model.EquivalentSemanticRouteClaim
            else (claim.infrastructure_subject, claim.corridor_subject, *claim.member_subjects)
            if type(claim) is model.RetiredDispatcherInfrastructureClaim
            else (claim.effect_subject, claim.source_subject, claim.predicate_subject,
                  claim.selected_target_subject, claim.discarded_effect_subject)
            if type(claim) is model.ExactInfeasibleEffectClaim
            else (claim.owner_subject,)
            if type(claim) is model.LocalAliasEffectScalarizationClaim
            else (claim.cycle_subject, claim.cleanup_source_subject, claim.terminal_subject)
        )),
    )
    by_id = {subject.subject_id: subject for subject in (*source_subjects, *required_subjects)}
    source_subjects = tuple(by_id.values())
    candidate_subjects = source_subjects if candidate_subjects is None else candidate_subjects
    candidate_subjects = normalize_value_flow(candidate_subjects)
    gate_roles = {
        model.GenericCfgGateKind.ENTRY_REACHABILITY: model.SemanticSubjectRole.SOURCE_ENTRY,
        model.GenericCfgGateKind.EFFECTFUL_REACHABILITY: model.SemanticSubjectRole.EFFECT_SITE,
        model.GenericCfgGateKind.TERMINAL_REACHABILITY: model.SemanticSubjectRole.TERMINAL_SITE,
    }
    def default_gate_subject_ids(gate: model.GenericCfgGateKind) -> tuple[str, ...]:
        scoped = tuple(
            subject for subject in source_subjects
            if subject.role is gate_roles[gate]
        )
        if gate is model.GenericCfgGateKind.EFFECTFUL_REACHABILITY:
            scoped = tuple(
                subject for subject in scoped
                if type(subject.locator) is model.EffectSubjectLocator
                and subject.locator.effect_kind in {
                    model.EffectSiteKind.CALL,
                    model.EffectSiteKind.STORE,
                }
            )
        elif gate is model.GenericCfgGateKind.TERMINAL_REACHABILITY:
            scoped = tuple(
                subject for subject in scoped
                if type(subject.locator) is model.TerminalSubjectLocator
                and subject.locator.terminal_kind in {
                    model.TerminalKind.RETURN,
                    model.TerminalKind.STOP,
                }
            )
        return tuple(subject.subject_id for subject in scoped)
    if candidate_bindings is None:
        candidate_binding_map = {
            item.subject.subject_id: item
            for item in (
                _binding(item, phase, 4, fingerprint=authority_id("candidate-fp"))
                for item in candidate_subjects
            )
        }
        candidate_bindings = tuple(
            candidate_binding_map.get(
                item.subject_id,
                _binding(
                    item, phase, 4, status=model.SubjectBindingStatus.MISSING,
                    fingerprint=authority_id("candidate-fp"),
                ),
            )
            for item in source_subjects
        ) + tuple(
            value for key, value in candidate_binding_map.items()
            if key not in {item.subject_id for item in source_subjects}
        )
    else:
        provided = {item.subject.subject_id for item in candidate_bindings}
        candidate_bindings = tuple(candidate_bindings) + tuple(
            _binding(
                item, phase, 4, status=model.SubjectBindingStatus.MISSING,
                fingerprint=authority_id("candidate-fp"),
            )
            for item in source_subjects if item.subject_id not in provided
        )
    source_subjects = tuple(sorted(source_subjects, key=lambda item: item.subject_id))
    candidate_subjects = tuple(sorted(candidate_subjects, key=lambda item: item.subject_id))
    source_bindings = source_bindings if source_bindings is not None else tuple(
        _binding(item, model.UnflattenAuthorityPhase.PRODUCER_FORECAST, fingerprint=authority_id("source-fp"))
        for item in source_subjects
    )
    if native_instruction_eas_by_block:
        source_bindings = tuple(
            replace(binding, native_instruction_eas=native_instruction_eas_by_block[binding.block_ref])
            if binding.block_ref in native_instruction_eas_by_block
            else binding
            for binding in source_bindings
        )
        candidate_bindings = tuple(
            replace(binding, native_instruction_eas=native_instruction_eas_by_block[binding.block_ref])
            if binding.block_ref in native_instruction_eas_by_block
            and binding.status is model.SubjectBindingStatus.UNIQUE
            else binding
            for binding in candidate_bindings
        )
    relations = []
    def relation(subject, dimension, provenance="fixture-relation", target=None):
        relations.append(model.ConditionalSubjectRelation(
            subject.subject_id, target.subject_id if target is not None else subject.subject_id,
            dimension, authority_id(provenance),
        ))
    route_claims = tuple(claim for claim in claims if type(claim) is model.EquivalentSemanticRouteClaim)
    for subject in source_subjects:
        if subject.role is model.SemanticSubjectRole.EFFECT_SITE and any(
            candidate == subject for candidate in candidate_subjects
        ):
            relation(subject, model.SafetyDimension.TOPOLOGY_INTEGRITY)
        if subject.role is model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION:
            if any(
                candidate.role is model.SemanticSubjectRole.AUTHORITATIVE_HANDLER
                and candidate.block_ref == subject.block_ref and candidate.anchor_ea == subject.anchor_ea
                for candidate in source_subjects
            ):
                relation(subject, model.SafetyDimension.HANDLER_REACHABILITY)
                for candidate in source_subjects:
                    if candidate.role is model.SemanticSubjectRole.AUTHORITATIVE_HANDLER and candidate.block_ref == subject.block_ref and candidate.anchor_ea == subject.anchor_ea:
                        relation(subject, model.SafetyDimension.HANDLER_REACHABILITY, "fixture-handler-owner", candidate)
            if any(
                candidate.role is model.SemanticSubjectRole.TERMINAL_SITE
                and candidate.block_ref == subject.block_ref and candidate.anchor_ea == subject.anchor_ea
                for candidate in source_subjects
            ):
                relation(subject, model.SafetyDimension.TERMINAL_REACHABILITY)
                for candidate in source_subjects:
                    if candidate.role is model.SemanticSubjectRole.TERMINAL_SITE and candidate.block_ref == subject.block_ref and candidate.anchor_ea == subject.anchor_ea:
                        relation(subject, model.SafetyDimension.TERMINAL_REACHABILITY, "fixture-terminal-owner", candidate)
        if subject.role is model.SemanticSubjectRole.DISPATCHER_ENTRY and any(
            claim.source_subject.block_ref == subject.block_ref and claim.source_subject.anchor_ea == subject.anchor_ea
            for claim in route_claims
        ):
            relation(subject, model.SafetyDimension.ROUTE_EQUIVALENCE)
        if subject.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE and any(
            claim.infrastructure_subject.block_ref == subject.block_ref and claim.infrastructure_subject.anchor_ea == subject.anchor_ea
            for claim in claims if type(claim) is model.RetiredDispatcherInfrastructureClaim
        ):
            relation(subject, model.SafetyDimension.ROUTE_EQUIVALENCE)
    for helper in candidate_subjects:
        if helper.role is model.SemanticSubjectRole.PLANNED_HELPER and any(
            helper == claim.replacement_route_subject for claim in route_claims
        ):
            relation(helper, model.SafetyDimension.ROUTE_EQUIVALENCE)
    relations = tuple(sorted(relations, key=lambda item: (item.source_subject_id, item.target_subject_id, item.dimension.value, item.provenance_id)))
    metrics = model.PreparationBuildMetrics(1, 1, 1.25)
    patch_payloads = tuple(patch_step_facts)
    if not any(
        item.step_type in {"PatchRedirectGoto", "PatchRedirectBranch"}
        for item in patch_payloads
    ):
        redirect_facts = tuple(
            model.PatchStepEvidencePayload(
                proposal.plan_id, index, "PatchRedirectBranch", owner,
                authority_id(f"fixture-redirect-{index}"), None, None, None,
            )
            for index, owner in enumerate(proposal.use_def_witness.redirect_owner_refs)
        )
        patch_payloads = (*redirect_facts, *patch_payloads)
    if not patch_payloads:
        patch_payloads = tuple(
            model.PatchStepEvidencePayload(
                proposal.plan_id, index, "PatchRedirectBranch", owner,
                authority_id(f"fixture-redirect-{index}"), None, None, None,
            )
            for index, owner in enumerate(proposal.use_def_witness.redirect_owner_refs)
        )
    source_subject_ids = tuple(source_subjects)
    candidate_subject_ids = tuple(candidate_subjects)
    receipt = _receipt_fixture(
        proposal_id=_digest(proposal), plan_id=proposal.plan_id,
        source_fingerprint=authority_id("source-fp"), candidate_fingerprint=authority_id("candidate-fp"),
        source_generation=3, candidate_generation=4,
        source_inventory_digest=_digest(source_subject_ids),
        candidate_inventory_digest=_digest(candidate_subject_ids),
        source_binding_digest=_digest(tuple(sorted(source_bindings, key=lambda item: item.subject.subject_id))),
        candidate_binding_digest=_digest(tuple(sorted(candidate_bindings, key=lambda item: item.subject.subject_id))),
        route_expansion_digest=_digest(tuple(item for item in source_subjects if item.role in {model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION})),
        effect_catalog_digest=_digest(tuple(item.subject_id for item in source_subjects if item.role is model.SemanticSubjectRole.EFFECT_SITE)),
        terminal_catalog_digest=_digest(tuple(item.subject_id for item in source_subjects if item.role is model.SemanticSubjectRole.TERMINAL_SITE)),
        plan_input_digest=_digest(tuple(item.subject_id for item in source_subjects if item.role in {model.SemanticSubjectRole.SOURCE_ENTRY, model.SemanticSubjectRole.DISPATCHER_ENTRY, model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, model.SemanticSubjectRole.AUTHORITATIVE_HANDLER})),
        dispatcher_member_digest=_digest(tuple(item.subject_id for item in source_subjects if item.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE)),
        planned_helper_digest=_digest(tuple(item.subject_id for item in candidate_subjects if item.role is model.SemanticSubjectRole.PLANNED_HELPER)),
        patch_step_digest=_digest(tuple(sorted(patch_payloads, key=lambda item: (item.plan_id, item.step_index))),),
        conditional_relation_digest=_digest(relations), metrics=metrics,
        corridor_coverage_forecast=proposal.corridor_coverage_forecast,
        retirement_candidate_catalog=proposal.retirement_candidate_catalog,
    )
    def fixture_inventory(
        phase_value: model.UnflattenAuthorityPhase,
        fingerprint: str,
        generation: int,
        bindings: tuple[model.PhaseSubjectBinding, ...],
        subjects: tuple[model.SemanticSubjectRef, ...],
        source_partition: tuple[model.SemanticSubjectRef, ...] | None = None,
        site_subjects: tuple[model.SemanticSubjectRef, ...] | None = None,
    ) -> model.SemanticGraphInventory:
        # This helper models a closed inventory: typed site subjects become
        # raw instruction rows and their bindings are widened to include
        # those exact native EAs.
        unique = {
            binding.block_ref: binding
            for binding in bindings
            if binding.status is model.SubjectBindingStatus.UNIQUE
            and binding.block_ref is not None
        }
        effects_by_owner = {}
        terminals_by_owner = {}
        for subject in subjects if site_subjects is None else site_subjects:
            if subject.block_ref is None:
                continue
            if (
                subject.role is model.SemanticSubjectRole.EFFECT_SITE
                and type(subject.locator) is model.EffectSubjectLocator
            ):
                effects_by_owner.setdefault(subject.block_ref, []).append(subject.locator)
            if (
                subject.role is model.SemanticSubjectRole.TERMINAL_SITE
                and type(subject.locator) is model.TerminalSubjectLocator
            ):
                terminals_by_owner.setdefault(subject.block_ref, []).append(subject.locator)
        widened_bindings = []
        for binding in bindings:
            if binding.status is not model.SubjectBindingStatus.UNIQUE or binding.block_ref is None:
                widened_bindings.append(binding)
                continue
            eas = {binding.anchor_ea, *binding.native_instruction_eas}
            eas.update(locator.instruction_ea for locator in effects_by_owner.get(binding.block_ref, ()))
            eas.update(locator.instruction_ea for locator in terminals_by_owner.get(binding.block_ref, ()))
            return_eas = {
                locator.instruction_ea
                for locator in effects_by_owner.get(binding.block_ref, ())
                if locator.effect_kind is model.EffectSiteKind.RETURN
            }
            return_eas.update(
                locator.instruction_ea
                for locator in terminals_by_owner.get(binding.block_ref, ())
                if locator.terminal_kind is model.TerminalKind.RETURN
            )
            widened_bindings.append(replace(
                binding,
                native_instruction_eas=tuple(sorted(eas, key=lambda ea: (ea not in return_eas, ea))),
            ))
        bindings = tuple(widened_bindings)
        unique = {
            binding.block_ref: binding
            for binding in bindings
            if binding.status is model.SubjectBindingStatus.UNIQUE
            and binding.block_ref is not None
        }
        serials = tuple(binding.serial for binding in sorted(unique.values(), key=lambda item: item.serial))
        forecast = proposal.corridor_coverage_forecast
        forecast_edges: set[tuple[int, int]] = set()
        if forecast is not None and phase_value is model.UnflattenAuthorityPhase.PRODUCER_FORECAST:
            serial_by_ref = {
                binding.block_ref: binding.serial
                for binding in unique.values()
                if binding.block_ref is not None and binding.serial is not None
            }
            for path in forecast.paths:
                forecast_edges.update(
                    (serial_by_ref[left.block_ref], serial_by_ref[right.block_ref])
                    for left, right in zip(path.nodes, path.nodes[1:])
                    if left.block_ref in serial_by_ref and right.block_ref in serial_by_ref
                )
        if forecast_edges:
            predecessor_by_serial: dict[int, list[int]] = {serial: [] for serial in serials}
            successor_by_serial: dict[int, tuple[int, ...]] = {serial: () for serial in serials}
            for left, right in sorted(forecast_edges):
                successor_by_serial[left] = (*successor_by_serial[left], right)
                predecessor_by_serial[right].append(left)
        else:
            predecessor_by_serial = {
                serial: ([serials[index - 1]] if index else [])
                for index, serial in enumerate(serials)
            }
            successor_by_serial = {
                serial: ((serials[index + 1],) if index + 1 < len(serials) else ())
                for index, serial in enumerate(serials)
            }
        blocks = tuple(
            model.InventoryBlockObservation(
                binding.serial,
                binding.block_ref,
                binding.anchor_ea,
                binding.native_instruction_eas,
                tuple(sorted(predecessor_by_serial[binding.serial])),
                tuple(sorted(successor_by_serial[binding.serial])),
                next(
                    (
                        ea for ea in reversed(binding.native_instruction_eas)
                        if any(
                            locator.instruction_ea == ea
                            and locator.effect_kind is model.EffectSiteKind.RETURN
                            for locator in effects_by_owner.get(binding.block_ref, ())
                        ) or any(
                            locator.instruction_ea == ea
                            and locator.terminal_kind is model.TerminalKind.RETURN
                            for locator in terminals_by_owner.get(binding.block_ref, ())
                        )
                    ),
                    None,
                ),
                tuple(
                    model.InventoryInstructionObservation(
                        ordinal,
                        ea,
                        0,
                        1 if any(
                            locator.instruction_ea == ea
                            for locator in effects_by_owner.get(binding.block_ref, ())
                        ) else 0,
                        next(
                            (
                                model.InsnKind.STORE
                                if locator.effect_kind is model.EffectSiteKind.STORE
                                else model.InsnKind.CALL
                                if locator.effect_kind is model.EffectSiteKind.CALL
                                else model.InsnKind.TRAP
                                if locator.effect_kind is model.EffectSiteKind.TRAP
                                else model.InsnKind.RET
                                for locator in effects_by_owner.get(binding.block_ref, ())
                                if locator.instruction_ea == ea
                            ),
                            next(
                                (
                                    model.InsnKind.RET
                                    if locator.terminal_kind is model.TerminalKind.RETURN
                                    else model.InsnKind.TRAP
                                    if locator.terminal_kind is model.TerminalKind.TRAP
                                    else model.InsnKind.CALL
                                    if locator.terminal_kind is model.TerminalKind.NORETURN_CALL
                                    else model.InsnKind.NOP
                                    for locator in terminals_by_owner.get(binding.block_ref, ())
                                    if locator.instruction_ea == ea
                                ),
                                model.InsnKind.NOP,
                            ),
                        ),
                        model.ControlTransferKind.RETURN
                        if any(
                            locator.instruction_ea == ea
                            and locator.effect_kind is model.EffectSiteKind.RETURN
                            for locator in effects_by_owner.get(binding.block_ref, ())
                        ) or any(
                            locator.instruction_ea == ea
                            and locator.terminal_kind is model.TerminalKind.RETURN
                            for locator in terminals_by_owner.get(binding.block_ref, ())
                        ) else None,
                        any(
                            locator.instruction_ea == ea
                            and locator.effect_kind is model.EffectSiteKind.CALL
                            for locator in effects_by_owner.get(binding.block_ref, ())
                        ),
                        None,
                    )
                    for ordinal, ea in enumerate(binding.native_instruction_eas)
                ),
                model.BlockKind.STOP
                if any(
                    locator.terminal_kind is model.TerminalKind.STOP
                    for locator in terminals_by_owner.get(binding.block_ref, ())
                ) else model.BlockKind.UNKNOWN,
                binding.anchor_ea,
            )
            for index, binding in enumerate(sorted(unique.values(), key=lambda item: item.serial))
        )
        effects = tuple(
            item
            for block in blocks
            for item in model.resolve_inventory_block_sites(
                serial=block.serial,
                owner_ref=block.block_ref,
                owner_anchor_ea=block.anchor_ea if block.anchor_ea is not None else 0,
                block_kind=block.block_kind,
                successor_serials=block.successor_serials,
                instruction_observations=block.instruction_observations,
            )[0]
        )
        terminals = tuple(
            item
            for block in blocks
            for item in model.resolve_inventory_block_sites(
                serial=block.serial,
                owner_ref=block.block_ref,
                owner_anchor_ea=block.anchor_ea if block.anchor_ea is not None else 0,
                block_kind=block.block_kind,
                successor_serials=block.successor_serials,
                instruction_observations=block.instruction_observations,
            )[1]
        )
        topology = tuple(
            incidence
            for block in blocks
            if block.successor_serials
            for incidence in (
                model.InventoryTopologyIncidence(
                    model.TopologyIncidenceKind.SUCCESSOR,
                    block.serial,
                    block.successor_serials[0],
                    block.transfer_ea,
                ),
                model.InventoryTopologyIncidence(
                    model.TopologyIncidenceKind.PREDECESSOR,
                    block.successor_serials[0],
                    block.serial,
                    block.transfer_ea,
                ),
            )
        )
        effects = tuple(sorted(effects, key=lambda item: (item.owner_serial, item.instruction_ordinal, item.instruction_ea, item.effect_kind.value)))
        terminals = tuple(sorted(terminals, key=lambda item: (item.owner_serial, item.instruction_ordinal is None, item.instruction_ordinal if item.instruction_ordinal is not None else -1, item.instruction_ea, item.terminal_kind.value)))
        topology = tuple(sorted(topology, key=lambda item: (item.kind.value, item.owner_serial, item.peer_serial, -1)))
        closure_set: set[int] = set()
        pending = [blocks[0].serial] if blocks else []
        blocks_by_serial = {block.serial: block for block in blocks}
        while pending:
            serial = pending.pop()
            if serial in closure_set:
                continue
            closure_set.add(serial)
            pending.extend(blocks_by_serial[serial].successor_serials)
        closure = tuple(sorted(closure_set))
        partition = subjects if source_partition is None else source_partition
        function_ea = (
            proposal.corridor_coverage_forecast.function_ea
            if proposal.corridor_coverage_forecast is not None
            else 0
        )
        digest = semantic_graph_inventory_digest(
            phase_value, fingerprint, generation, blocks, subjects, bindings,
            effects, terminals, topology, closure,
            blocks[0].serial if blocks else 0,
            tuple(item.subject_id for item in partition), function_ea,
        )
        return model.SemanticGraphInventory(
            phase_value, fingerprint, generation, blocks, subjects, bindings,
            effects, terminals, topology, digest, closure,
            blocks[0].serial if blocks else 0,
            tuple(item.subject_id for item in partition),
            function_ea,
        )

    source_inventory = fixture_inventory(
        model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        authority_id("source-fp"), 3,
        tuple(sorted(source_bindings, key=lambda item: item.subject.subject_id)),
        source_subjects,
    )
    source_bindings = source_inventory.bindings
    if proposal.corridor_coverage_forecast is not None:
        dispatcher_ref = proposal.corridor_coverage_forecast.dispatcher_ref
        candidate_bindings = tuple(
            replace(
                binding,
                block_ref=None,
                anchor_ea=None,
                serial=None,
                native_instruction_eas=(),
                status=model.SubjectBindingStatus.MISSING,
            )
            if binding.subject.role is model.SemanticSubjectRole.DISPATCHER_ENTRY
            and binding.subject.block_ref == dispatcher_ref
            else binding
            for binding in candidate_bindings
        )
    candidate_inventory = fixture_inventory(
        phase, authority_id("candidate-fp"), 4,
        tuple(sorted(candidate_bindings, key=lambda item: item.subject.subject_id)),
        tuple(sorted({item.subject_id: item for item in (*source_subjects, *candidate_subjects)}.values(), key=lambda item: item.subject_id)),
        source_subjects,
        candidate_subjects,
    )
    candidate_bindings = candidate_inventory.bindings
    object.__setattr__(
        receipt,
        "source_binding_digest",
        _digest(tuple(sorted(source_bindings, key=lambda item: item.subject.subject_id))),
    )
    object.__setattr__(
        receipt,
        "candidate_binding_digest",
        _digest(tuple(sorted(candidate_bindings, key=lambda item: item.subject.subject_id))),
    )
    object.__setattr__(
        receipt,
        "effect_catalog_digest",
        _digest(tuple(item.subject_id for item in source_subjects if item.role is model.SemanticSubjectRole.EFFECT_SITE)),
    )
    object.__setattr__(
        receipt,
        "terminal_catalog_digest",
        _digest(tuple(item.subject_id for item in source_subjects if item.role is model.SemanticSubjectRole.TERMINAL_SITE)),
    )
    object.__setattr__(receipt, "source_inventory_digest", source_inventory.inventory_digest)
    object.__setattr__(receipt, "candidate_inventory_digest", candidate_inventory.inventory_digest)
    object.__setattr__(receipt, "projected_topology_reference_digest", candidate_inventory.inventory_digest)
    object.__setattr__(receipt, "receipt_id", receipt_id(receipt))
    corridor_result = None
    if proposal.corridor_coverage_forecast is not None:
        from d810.transforms.unflatten_authority.bind import bind_corridor_coverage_forecast
        corridor_result = bind_corridor_coverage_forecast(
            proposal=proposal,
            source_inventory=source_inventory,
            candidate_inventory=candidate_inventory,
            phase=phase,
        )
    retirement_result = None
    retirement_claims = tuple(
        claim for claim in claims
        if type(claim) is model.RetiredDispatcherInfrastructureClaim
    )
    if retirement_claims:
        from d810.transforms.unflatten_authority.bind import bind_retired_dispatcher_infrastructure_claim
        if len(retirement_claims) != 1:
            raise ValueError("fixture requires one retirement claim")
        retirement_result = bind_retired_dispatcher_infrastructure_claim(
            claim=retirement_claims[0], proposal=proposal,
            source_inventory=source_inventory,
            projected_inventory=candidate_inventory,
            phase=phase,
        ).phase_result
    return model.DerivedUnflattenPreparationInputs(
        proposal=proposal, claims=claims, preparation_receipt=receipt,
        source_inventory=source_inventory,
        candidate_inventory=candidate_inventory,
        projected_topology_reference=candidate_inventory,
        source_route_assessment=None, candidate_route_assessment=None,
        generic_gate_facts=None, conditional_relations=relations,
        patch_step_facts=patch_payloads,
        preparation_metrics=metrics,
        phase_build_metrics=model.PhaseBuildMetrics(phase, 1, 1, 1.25),
        corridor_coverage_phase_result=corridor_result,
        retirement_phase_result=retirement_result,
    )


def test_case_builder_accepts_only_closed_derived_inputs() -> None:
    signature = inspect.signature(build_semantic_case)
    assert tuple(signature.parameters) == ("authority_id", "phase", "inputs")
    with pytest.raises(TypeError):
        build_semantic_case(
            authority_id="sha256:" + "a" * 64,
            phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
            inputs=None,
            plan=object(),
        )
    with pytest.raises(TypeError):
        build_semantic_case(
            authority_id="sha256:" + "a" * 64,
            phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
            inputs=None,
            projection=object(),
        )
    with pytest.raises(TypeError):
        build_semantic_case(
            authority_id="sha256:" + "a" * 64,
            phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
            inputs=None,
            graph=object(),
        )
    with pytest.raises(TypeError):
        build_semantic_case(
            authority_id="sha256:" + "a" * 64,
            phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
            inputs=None,
            callback=lambda: None,
        )


def test_prepared_authority_accepts_canonical_bound_route_endpoints() -> None:
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    inputs = _complete_inputs(
        source_subjects=(_role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "0"),),
        proposal=proposal,
    )
    authority = authority_id("prepared-route-authority")
    case = build_semantic_case(
        authority_id=authority,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=inputs,
    )
    proof = proposal.route_evidence.route_proofs[0]
    source = BoundSemanticBlock(1, proof.source_identity, proof.source_anchor_ea)
    destinations = tuple(
        BoundSemanticRouteDestination(
            destination,
            BoundSemanticBlock(
                index + 2,
                destination.target_identity,
                destination.target_anchor_ea,
            ),
        )
        for index, destination in enumerate(proof.destinations)
    )
    bound_routes = BoundCanonicalSemanticEvidence(
        proposal.route_evidence,
        (BoundSemanticRoute(proof, source, destinations),),
    )

    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("prepared-snapshot"),
        source_generation=inputs.source_inventory.generation,
        source_coordinates=tuple(
            (block.block_ref, serial)
            for serial, block in enumerate(proposal.source_identity_catalog.blocks)
        ),
        unflatten_proposal=proposal,
    )

    expected_coordinates = tuple(
        sorted(plan.source_coordinates, key=lambda item: (repr(item[0]), item[1]))
    )
    prepared = model.PreparedUnflattenAuthority(
        authority_id=authority,
        route=model.UnflattenPlanRoute.ORDINARY,
        owning_plan=plan,
        proposal=proposal,
        claims=case.claims,
        bound_routes=bound_routes,
        snapshot_id=plan.snapshot_id,
        source_maturity=None,
        source_coordinate_digest=canonical_authority_id(expected_coordinates),
        source_fingerprint=inputs.source_inventory.graph_fingerprint,
        projected_fingerprint=inputs.candidate_inventory.graph_fingerprint,
        source_generation=inputs.source_inventory.generation,
        projected_generation=inputs.candidate_inventory.generation,
        source_bindings=inputs.source_inventory.bindings,
        projected_bindings=case.bindings,
        projected_case=case,
        source_inventory=inputs.source_inventory,
        source_inputs=inputs,
    )
    assert prepared.bound_routes.routes[0].destinations[0].evidence.role is proof.destinations[0].role
    with pytest.raises(ValueError, match="source bindings"):
        replace(prepared, source_bindings=prepared.source_bindings[:-1])
    swapped_destination = BoundSemanticRouteDestination(
        proof.destinations[0],
        BoundSemanticBlock(99, proof.source_identity, proof.source_anchor_ea),
    )
    swapped_routes = BoundCanonicalSemanticEvidence(
        proposal.route_evidence,
        (BoundSemanticRoute(proof, source, (swapped_destination,)),),
    )
    with pytest.raises(ValueError, match="destinations"):
        replace(prepared, bound_routes=swapped_routes)
    attempt = model.TransactionAttemptId(
        plan_id=proposal.plan_id, session_id="prepared-session",
        generation=inputs.candidate_inventory.generation, attempt_id="prepared-attempt",
    )
    live_maturity = MaturityEnvelope(ir=None, provider="test", provider_id=0)
    patch_binding = BoundPatchPlan(
        plan=plan,
        attempt_id=attempt,
        session_id=attempt.session_id,
        generation=attempt.generation,
        maturity=live_maturity,
        bindings=(),
    )
    with pytest.raises(TypeError, match="live_maturity"):
        model.BoundUnflattenAuthority(
            binding_id=authority_id("prepared-binding"), prepared=prepared,
            attempt_id=attempt, session_id=attempt.session_id,
            generation=attempt.generation, live_maturity=4, live_bindings=(),
            patch_binding=patch_binding,
        )
    bound = model.BoundUnflattenAuthority(
        binding_id=bound_unflatten_binding_id(prepared, patch_binding), prepared=prepared,
        attempt_id=attempt, session_id=attempt.session_id,
        generation=attempt.generation,
        live_maturity=live_maturity, live_bindings=(), patch_binding=patch_binding,
    )
    assert isinstance(bound.live_maturity, MaturityEnvelope)
    with pytest.raises(ValueError, match="binding_id"):
        replace(bound, binding_id=authority_id("unrelated-valid-digest"))


def test_fragment_wide_value_flow_identity_and_use_def_are_total() -> None:
    """The use-def witness owns one fragment-wide, fully classified cell pair."""

    source_entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "value-flow-total")
    case = build_semantic_case(
        authority_id=authority_id("value-flow-total"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(source_entry,)),
    )

    value_flow = next(
        subject for subject in case.subjects
        if subject.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW
    )
    cells = {
        cell.key.dimension: cell
        for cell in case.obligation_index.cells
        if cell.key.subject == value_flow
    }
    assert set(cells) == {
        model.SafetyDimension.IDENTITY_BINDING,
        model.SafetyDimension.USE_DEF_INTEGRITY,
    }
    assert cells[model.SafetyDimension.IDENTITY_BINDING].state is model.ObligationState.SATISFIED
    assert cells[model.SafetyDimension.USE_DEF_INTEGRITY].state is model.ObligationState.SATISFIED


def test_use_def_audit_evidence_is_evaluator_owned() -> None:
    source_entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "audit-injection")
    inputs = _complete_inputs(source_subjects=(source_entry,))
    value_flow = next(
        subject for subject in inputs.source_inventory.subjects
        if subject.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW
    )
    payload = model.UseDefAuditEvidencePayload(
        value_flow.locator.fragment_id, value_flow.locator.state_identity,
        True, True, 0, (),
    )
    injected = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.USE_DEF_AUDIT,
        value_flow, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, payload,
    )
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        replace(inputs, lineage_evidence=(injected,))


def test_use_def_redirect_owners_are_exact_patch_fact_projection() -> None:
    """The evaluator derives redirect owners from receipt-bound patch facts."""

    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "redirect-owner-facts")
    inputs = _complete_inputs(source_subjects=(entry,), proposal=proposal)
    redirect_facts = tuple(
        fact for fact in inputs.patch_step_facts
        if fact.step_type in {"PatchRedirectGoto", "PatchRedirectBranch"}
    )

    def with_facts(facts: tuple[model.PatchStepEvidencePayload, ...]):
        values = {
            name: getattr(inputs.preparation_receipt, name)
            for name in inputs.preparation_receipt.__dataclass_fields__
            if name not in {"receipt_id", "_minted"}
        }
        values["patch_step_digest"] = _digest(
            tuple(sorted(facts, key=lambda item: (item.plan_id, item.step_index)))
        )
        return replace(
            inputs, patch_step_facts=facts,
            preparation_receipt=_receipt_fixture(**values),
        )

    for index, facts in enumerate((
        (),
        redirect_facts[:-1],
        tuple(replace(fact, owner_ref=entry.block_ref) for fact in redirect_facts),
        tuple(replace(fact, step_type="PatchInsertBlock") for fact in redirect_facts),
        redirect_facts + (replace(redirect_facts[0], owner_ref=block_ref("foreign-owner"), step_index=98),),
    )):
        with pytest.raises(ValueError):
            build_semantic_case(
                authority_id=authority_id(f"redirect-owner-facts-{index}"),
                phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
                inputs=with_facts(facts),
            )

    # Owner order follows the canonical manifest, not patch-step order.
    reversed_case = build_semantic_case(
        authority_id=authority_id("redirect-owner-facts-reversed"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=with_facts(tuple(reversed(redirect_facts))),
    )
    assert reversed_case.case_id

    # Multiple redirect facts may name one owner; canonical projection
    # intentionally deduplicates that owner.
    repeated_case = build_semantic_case(
        authority_id=authority_id("redirect-owner-facts-repeated"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=with_facts(
            redirect_facts + (replace(redirect_facts[0], step_index=99),),
        ),
    )
    assert repeated_case.case_id


def test_value_flow_identity_is_conjunctive_over_every_owner_binding() -> None:
    source_entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "owner-conjunction")
    inputs = _complete_inputs(source_subjects=(source_entry,))
    good = build_semantic_case(
        authority_id=authority_id("owner-conjunction-good"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=inputs,
    )
    value_flow = next(
        subject for subject in good.subjects
        if subject.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW
    )
    good_cell = next(
        cell for cell in good.obligation_index.cells
        if cell.key.subject == value_flow
        and cell.key.dimension is model.SafetyDimension.IDENTITY_BINDING
    )
    assert good_cell.supporting_justification_ids
    owner_binding = next(
        binding for binding in inputs.candidate_inventory.bindings
        if binding.subject.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE
        and binding.subject.block_ref in value_flow.locator.redirect_owner_refs
    )
    mutations = (
        replace(
            owner_binding, status=model.SubjectBindingStatus.MISSING,
            block_ref=None, serial=None, anchor_ea=None, native_instruction_eas=(),
        ),
        replace(owner_binding, generation=999),
    )
    for index, mutated in enumerate(mutations):
        candidate_bindings = tuple(
            mutated if binding is owner_binding else binding
            for binding in inputs.candidate_inventory.bindings
        )
        receipt = inputs.preparation_receipt
        object.__setattr__(
            receipt, "candidate_binding_digest",
            _digest(tuple(sorted(candidate_bindings, key=lambda item: item.subject.subject_id))),
        )
        object.__setattr__(receipt, "receipt_id", receipt_id(receipt))
        object.__setattr__(
            inputs.candidate_inventory, "bindings",
            tuple(sorted(candidate_bindings, key=lambda item: item.subject.subject_id)),
        )
        object.__setattr__(
            inputs.candidate_inventory, "inventory_digest",
            semantic_graph_inventory_digest(
                inputs.candidate_inventory.phase,
                inputs.candidate_inventory.graph_fingerprint,
                inputs.candidate_inventory.generation,
                inputs.candidate_inventory.blocks,
                inputs.candidate_inventory.subjects,
                inputs.candidate_inventory.bindings,
                inputs.candidate_inventory.effects,
                inputs.candidate_inventory.terminals,
                inputs.candidate_inventory.topology,
                inputs.candidate_inventory.reachable_serials,
                inputs.candidate_inventory.entry_serial,
                inputs.candidate_inventory.source_subject_ids,
                inputs.candidate_inventory.function_ea,
            ),
        )
        object.__setattr__(
            receipt, "candidate_inventory_digest",
            inputs.candidate_inventory.inventory_digest,
        )
        object.__setattr__(
            receipt, "projected_topology_reference_digest",
            inputs.projected_topology_reference.inventory_digest,
        )
        object.__setattr__(receipt, "receipt_id", receipt_id(receipt))
        if index == 0:
            case = build_semantic_case(
                authority_id=authority_id("owner-conjunction-missing"),
                phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
                inputs=inputs,
            )
            cell = next(
                cell for cell in case.obligation_index.cells
                if cell.key.subject == value_flow
                and cell.key.dimension is model.SafetyDimension.IDENTITY_BINDING
            )
            assert not cell.supporting_justification_ids
            assert cell.refuting_justification_ids
        else:
            with pytest.raises(TypeError, match="unexpected keyword argument"):
                replace(inputs, candidate_bindings=candidate_bindings)

    object.__setattr__(
        inputs.candidate_inventory, "bindings", tuple(sorted((
            owner_binding if binding.subject == owner_binding.subject else binding
            for binding in inputs.candidate_inventory.bindings
        ), key=lambda item: item.subject.subject_id)),
    )
    object.__setattr__(
        inputs.candidate_inventory, "inventory_digest",
        semantic_graph_inventory_digest(
            inputs.candidate_inventory.phase,
            inputs.candidate_inventory.graph_fingerprint,
            inputs.candidate_inventory.generation,
            inputs.candidate_inventory.blocks,
            inputs.candidate_inventory.subjects,
            inputs.candidate_inventory.bindings,
            inputs.candidate_inventory.effects,
            inputs.candidate_inventory.terminals,
            inputs.candidate_inventory.topology,
            inputs.candidate_inventory.reachable_serials,
            inputs.candidate_inventory.entry_serial,
            inputs.candidate_inventory.source_subject_ids,
            inputs.candidate_inventory.function_ea,
        ),
    )
    object.__setattr__(receipt, "candidate_binding_digest", _digest(inputs.candidate_inventory.bindings))
    object.__setattr__(receipt, "candidate_inventory_digest", inputs.candidate_inventory.inventory_digest)
    object.__setattr__(receipt, "projected_topology_reference_digest", inputs.projected_topology_reference.inventory_digest)
    object.__setattr__(receipt, "receipt_id", receipt_id(receipt))

    unrelated = next(
        binding for binding in inputs.candidate_inventory.bindings
        if binding.subject.role is model.SemanticSubjectRole.SOURCE_ENTRY
        and binding.subject.block_ref in value_flow.locator.redirect_owner_refs
    )
    unrelated_bad = replace(
        unrelated, status=model.SubjectBindingStatus.MISSING,
        block_ref=None, serial=None, anchor_ea=None, native_instruction_eas=(),
    )
    candidate_bindings = tuple(
        unrelated_bad if binding is unrelated else binding
        for binding in inputs.candidate_inventory.bindings
    )
    receipt = inputs.preparation_receipt
    object.__setattr__(
        receipt, "candidate_binding_digest",
        _digest(tuple(sorted(candidate_bindings, key=lambda item: item.subject.subject_id))),
    )
    object.__setattr__(receipt, "receipt_id", receipt_id(receipt))
    object.__setattr__(
        inputs.candidate_inventory, "bindings",
        tuple(sorted(candidate_bindings, key=lambda item: item.subject.subject_id)),
    )
    object.__setattr__(
        inputs.candidate_inventory, "inventory_digest",
        semantic_graph_inventory_digest(
            inputs.candidate_inventory.phase,
            inputs.candidate_inventory.graph_fingerprint,
            inputs.candidate_inventory.generation,
            inputs.candidate_inventory.blocks,
            inputs.candidate_inventory.subjects,
            inputs.candidate_inventory.bindings,
            inputs.candidate_inventory.effects,
            inputs.candidate_inventory.terminals,
            inputs.candidate_inventory.topology,
            inputs.candidate_inventory.reachable_serials,
            inputs.candidate_inventory.entry_serial,
            inputs.candidate_inventory.source_subject_ids,
            inputs.candidate_inventory.function_ea,
        ),
    )
    object.__setattr__(receipt, "candidate_inventory_digest", inputs.candidate_inventory.inventory_digest)
    object.__setattr__(receipt, "projected_topology_reference_digest", inputs.projected_topology_reference.inventory_digest)
    object.__setattr__(receipt, "receipt_id", receipt_id(receipt))
    case = build_semantic_case(
        authority_id=authority_id("owner-conjunction-unrelated"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=inputs,
    )
    cell = next(
        cell for cell in case.obligation_index.cells
        if cell.key.subject == value_flow
        and cell.key.dimension is model.SafetyDimension.IDENTITY_BINDING
    )
    assert cell.supporting_justification_ids


def test_contextual_justification_validation_rejects_forged_stale_support() -> None:
    source_entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "contextual-forge")
    case = build_semantic_case(
        authority_id=authority_id("contextual-forge"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(source_entry,)),
    )
    from d810.transforms.unflatten_authority.evaluate import _validate_justification_graph
    with pytest.raises(ValueError, match="binding|context"):
        _validate_justification_graph(
            case.justifications, case.required_obligations, case.evidence, case.phase,
            case.claims, case.conditional_relations,
            candidate_fingerprint=authority_id("forged-candidate-fingerprint"),
            candidate_generation=case.candidate_generation,
            bindings=case.bindings, subjects=case.subjects,
        )


def test_contextual_justification_validation_rejects_forged_clean_audit() -> None:
    source_entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "clean-audit-forge")
    case = build_semantic_case(
        authority_id=authority_id("clean-audit-forge"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(source_entry,)),
    )
    audit_justification = next(
        item for item in case.justifications
        if item.rule is model.UnflattenJustificationRule.USE_DEF_AUDIT_CLEAN
    )
    audit_evidence = next(
        item for item in case.evidence
        if item.kind is model.AuthorityEvidenceKind.USE_DEF_AUDIT
    )
    forged_payload = replace(audit_evidence.payload, executed=False)
    forged_evidence = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.USE_DEF_AUDIT,
        audit_evidence.subject, case.phase, forged_payload,
    )
    forged_justification = _justification_factory(
        model.AuthorityJustification,
        rule=audit_justification.rule,
        premise_ids=(forged_evidence.evidence_id,),
        conclusion=audit_justification.conclusion,
        polarity=audit_justification.polarity,
        phase=audit_justification.phase,
        claim_id=None,
    )
    evidence = tuple(
        forged_evidence if item.evidence_id == audit_evidence.evidence_id else item
        for item in case.evidence
    )
    justifications = tuple(
        forged_justification if item.justification_id == audit_justification.justification_id else item
        for item in case.justifications
    )
    from d810.transforms.unflatten_authority.evaluate import _validate_justification_graph
    with pytest.raises(ValueError, match="clean use-def|contradictory"):
        _validate_justification_graph(
            justifications, case.required_obligations, evidence, case.phase,
            case.claims, case.conditional_relations,
            candidate_fingerprint=case.candidate_fingerprint,
            candidate_generation=case.candidate_generation,
            bindings=case.bindings, subjects=case.subjects,
        )


def test_value_flow_unique_binding_requires_exact_owner_premise_set() -> None:
    source_entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "owner-premise-set")
    case = build_semantic_case(
        authority_id=authority_id("owner-premise-set"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(source_entry,)),
    )
    justification = next(
        item for item in case.justifications
        if item.conclusion.subject.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW
        and item.rule is model.UnflattenJustificationRule.UNIQUE_PHASE_BINDING
    )
    assert len(justification.premise_ids) == 2
    for premise_ids in (
        justification.premise_ids[:-1],
        (*justification.premise_ids, justification.premise_ids[0]),
    ):
        values = {
            name: getattr(justification, name)
            for name in justification.__dataclass_fields__
            if name != "justification_id"
        }
        values["premise_ids"] = premise_ids
        if len(set(premise_ids)) != len(premise_ids):
            with pytest.raises(ValueError, match="duplicate"):
                _justification_factory(model.AuthorityJustification, **values)
            continue
        forged = _justification_factory(model.AuthorityJustification, **values)
        from d810.transforms.unflatten_authority.evaluate import _validate_justification_graph
        with pytest.raises(ValueError, match="owner|premise|duplicate"):
            _validate_justification_graph(
                tuple(forged if item is justification else item for item in case.justifications),
                case.required_obligations, case.evidence, case.phase,
                case.claims, case.conditional_relations,
                candidate_fingerprint=case.candidate_fingerprint,
                candidate_generation=case.candidate_generation,
                bindings=case.bindings, subjects=case.subjects,
            )
    wire = json.loads(canonical_bytes(case).decode("ascii"))
    def omit_owner_premise(value: object) -> bool:
        if isinstance(value, dict) and value.get("t") == "record" and value.get("n") == "AuthorityJustification":
            for name, encoded in value["v"]:
                if name == "premise_ids" and len(encoded.get("v", ())) == 2:
                    encoded["v"] = encoded["v"][:-1]
                    return True
        if isinstance(value, dict):
            return any(omit_owner_premise(item) for item in value.values())
        if isinstance(value, list):
            return any(omit_owner_premise(item) for item in value)
        return False
    assert omit_owner_premise(wire)
    with pytest.raises(ValueError, match="premise|record|case"):
        canonical_decode(json.dumps(wire, sort_keys=True, separators=(",", ":")).encode("ascii"))
    omitted_owner = next(
        subject for subject in case.subjects
        if subject.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE
        and subject.block_ref == justification.conclusion.subject.locator.redirect_owner_refs[-1]
    )
    from d810.transforms.unflatten_authority.evaluate import _validate_justification_graph
    with pytest.raises(ValueError, match="owner|subject|premise"):
        _validate_justification_graph(
            case.justifications, case.required_obligations, case.evidence, case.phase,
            case.claims, case.conditional_relations,
            candidate_fingerprint=case.candidate_fingerprint,
            candidate_generation=case.candidate_generation,
            bindings=tuple(item for item in case.bindings if item.subject.subject_id != omitted_owner.subject_id),
            subjects=tuple(item for item in case.subjects if item.subject_id != omitted_owner.subject_id),
        )


def test_severed_use_def_rule_requires_complete_actionable_audit() -> None:
    source_entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "severed-audit-forge")
    case = build_semantic_case(
        authority_id=authority_id("severed-audit-forge"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(source_entry,)),
    )
    value_flow = next(
        item for item in case.subjects
        if item.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW
    )
    with pytest.raises(ValueError, match="count"):
        model.UseDefAuditEvidencePayload(
            value_flow.locator.fragment_id, value_flow.locator.state_identity,
            True, True, 2, (authority_id("only-one"),),
        )
    payloads = (
        model.UseDefAuditEvidencePayload(
            value_flow.locator.fragment_id, value_flow.locator.state_identity,
            False, True, 1, (authority_id("unavailable"),),
        ),
        model.UseDefAuditEvidencePayload(
            value_flow.locator.fragment_id, value_flow.locator.state_identity,
            True, False, 1, (authority_id("partial"),),
        ),
    )
    severed = next(
        item for item in case.justifications
        if item.rule is model.UnflattenJustificationRule.USE_DEF_AUDIT_CLEAN
    )
    from d810.transforms.unflatten_authority.evaluate import _validate_justification_graph
    for payload in payloads:
        evidence_item = _evidence_factory(
            model.AuthorityEvidence, model.AuthorityEvidenceKind.USE_DEF_AUDIT,
            value_flow, case.phase, payload,
        )
        forged = _justification_factory(
            model.AuthorityJustification,
            rule=model.UnflattenJustificationRule.NON_STATE_USE_DEF_SEVERED,
            premise_ids=(evidence_item.evidence_id,),
            conclusion=severed.conclusion,
            polarity=model.EvidencePolarity.REFUTES,
            phase=case.phase,
            claim_id=None,
        )
        evidence = tuple(
            evidence_item if item.kind is model.AuthorityEvidenceKind.USE_DEF_AUDIT else item
            for item in case.evidence
        )
        justifications = tuple(
            forged if item.justification_id == severed.justification_id else item
            for item in case.justifications
        )
        with pytest.raises(ValueError, match="severance|actionable|unavailable|audit"):
            _validate_justification_graph(
                justifications, case.required_obligations, evidence, case.phase,
                case.claims, case.conditional_relations,
                candidate_fingerprint=case.candidate_fingerprint,
                candidate_generation=case.candidate_generation,
                bindings=case.bindings, subjects=case.subjects,
            )


def test_preparation_receipt_cannot_be_minted_by_callers() -> None:
    import d810.transforms.unflatten_authority.ids as authority_ids
    assert not hasattr(authority_ids, "_receipt_factory")
    with pytest.raises(TypeError, match="transaction-owned"):
        model.PreparationAuthorityReceipt(
            receipt_id=authority_id("receipt"), proposal_id=authority_id("proposal"),
            plan_id=authority_id("plan"), source_fingerprint=authority_id("source"),
            candidate_fingerprint=authority_id("candidate"), source_generation=3,
            candidate_generation=4, source_inventory_digest=authority_id("si"),
            candidate_inventory_digest=authority_id("ci"), source_binding_digest=authority_id("sb"),
            candidate_binding_digest=authority_id("cb"), route_expansion_digest=authority_id("route"),
            effect_catalog_digest=authority_id("effect"), terminal_catalog_digest=authority_id("terminal"),
            plan_input_digest=authority_id("plan-input"), dispatcher_member_digest=authority_id("members"),
            planned_helper_digest=authority_id("helpers"), patch_step_digest=authority_id("patch"),
            conditional_relation_digest=authority_id("relations"),
            metrics=model.PreparationBuildMetrics(1, 1, 1.25),
        )


def test_task4_records_and_total_result_variants_exist() -> None:
    for name in (
        "ObligationKey", "AuthorityJustification", "ObligationEvidenceCell",
        "ObligationEvidenceIndex", "SemanticSafetyCase", "FailedObligation",
        "UnflattenAuthorityVerdict", "UnflattenAuthorityNotApplicable",
        "UnflattenAuthorityPreparationAccepted", "UnflattenAuthorityPreparationRejected",
        "UnflattenAuthorityBindingAccepted", "UnflattenAuthorityBindingRejected",
        "PreparationBuildMetrics", "DerivedUnflattenPreparationInputs",
    ):
        assert hasattr(model, name)
    assert callable(evaluate_case)


def test_generic_gate_rows_are_closed_and_disjoint() -> None:
    gate = model.GenericCfgGateResult(
        model.GenericCfgGateKind.ENTRY_REACHABILITY,
        True,
        ("sha256:" + "a" * 64,),
        (),
        "ok",
    )
    assert gate.passed is True
    with pytest.raises(ValueError):
        model.GenericCfgGateResult(
            model.GenericCfgGateKind.ENTRY_REACHABILITY,
            True,
            ("sha256:" + "a" * 64,),
            ("sha256:" + "a" * 64,),
            "bad",
        )
    with pytest.raises(ValueError, match="duplicate"):
        model.GenericCfgGateResult(
            model.GenericCfgGateKind.ENTRY_REACHABILITY,
            True,
            ("sha256:" + "a" * 64, "sha256:" + "a" * 64),
            (),
            "duplicate",
        )


def test_obligation_cell_has_exact_four_state_truth_table() -> None:
    assert model.ObligationState.UNPROVEN.value == "unproven"
    assert model.ObligationState.SATISFIED.value == "satisfied"
    assert model.ObligationState.VIOLATED.value == "violated"
    assert model.ObligationState.INCONSISTENT.value == "inconsistent"


def test_detached_component_scope_requires_one_exact_accepted_sealed_result() -> None:
    """Only the dead handler rows receive the sealed applicability exception."""

    dispatcher = _role_subject(model.SemanticSubjectRole.DISPATCHER_ENTRY, "detached-dispatcher")
    dead = _role_subject(model.SemanticSubjectRole.AUTHORITATIVE_HANDLER, "detached-2")
    retained = _role_subject(model.SemanticSubjectRole.AUTHORITATIVE_HANDLER, "detached-1")
    unrelated = _role_subject(model.SemanticSubjectRole.AUTHORITATIVE_HANDLER, "detached-0")
    component = _role_subject(model.SemanticSubjectRole.DETACHED_DEAD_HANDLER_COMPONENT, "detached-2")
    claim = object.__new__(model.DetachedDeadHandlerComponentClaim)
    for name, value in {
        "claim_id": authority_id("detached-claim"),
        "dispatcher_subject": dispatcher,
        "dead_handler_subjects": (dead,),
        "retained_handler_subjects": (retained,),
        "component_subjects": (component,),
        "source_generation": 3,
    }.items():
        object.__setattr__(claim, name, value)
    source_fingerprint = authority_id("detached-source")
    candidate_fingerprint = authority_id("detached-candidate")
    corridor = SimpleNamespace(result_id=authority_id("detached-corridor"))
    result = object.__new__(model.DetachedDeadHandlerComponentPhaseResult)
    for name, value in {
        "result_id": authority_id("detached-result"),
        "claim_id": claim.claim_id,
        "phase": model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        "corridor_coverage_result_id": corridor.result_id,
        "source_fingerprint": source_fingerprint,
        "candidate_fingerprint": candidate_fingerprint,
        "source_generation": 3,
        "candidate_generation": 4,
        "accepted": True,
    }.items():
        object.__setattr__(result, name, value)
    inputs = SimpleNamespace(
        claims=(claim,),
        corridor_coverage_phase_result=corridor,
        detached_dead_handler_component_phase_results=(result,),
        source_inventory=SimpleNamespace(graph_fingerprint=source_fingerprint, generation=3),
        candidate_inventory=SimpleNamespace(graph_fingerprint=candidate_fingerprint, generation=4),
    )

    accepted = _accepted_detached_component_results(
        inputs, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    assert accepted == ((claim, result),)
    required = _dimensions(
        (dispatcher, dead, retained, unrelated, component),
        (claim,), (),
        detached_dead_handler_ids=frozenset(subject.subject_id for subject in claim.dead_handler_subjects),
    )
    dimensions = {(key.subject.subject_id, key.dimension) for key in required}
    assert (dead.subject_id, model.SafetyDimension.TOPOLOGY_INTEGRITY) not in dimensions
    assert (dead.subject_id, model.SafetyDimension.HANDLER_REACHABILITY) not in dimensions
    assert (retained.subject_id, model.SafetyDimension.TOPOLOGY_INTEGRITY) in dimensions
    assert (retained.subject_id, model.SafetyDimension.HANDLER_REACHABILITY) in dimensions
    assert (unrelated.subject_id, model.SafetyDimension.TOPOLOGY_INTEGRITY) in dimensions
    assert (unrelated.subject_id, model.SafetyDimension.HANDLER_REACHABILITY) in dimensions
    assert (component.subject_id, model.SafetyDimension.STRUCTURAL_ACCOUNTING) in dimensions
    object.__setattr__(result, "corridor_coverage_result_id", authority_id("foreign-corridor"))
    assert not _accepted_detached_component_results(
        inputs, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )


def test_case_builder_rejects_reissued_detached_source_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A canonical reissue cannot enter the evaluator as transaction authority."""

    from d810.transforms.unflatten_authority import bind
    from .test_bind import _detached_binding_fixture

    claim, source, projected, corridor = _detached_binding_fixture()
    binding = bind.bind_detached_dead_handler_component_claim(
        claim=claim,
        source_inventory=source,
        candidate_inventory=projected,
        corridor_result=corridor,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    sealed_source = binding.source_result
    source_values = (
        sealed_source.claim_id,
        sealed_source.corridor_forecast_id,
        sealed_source.corridor_coverage_result_id,
        sealed_source.source_fingerprint,
        sealed_source.source_generation,
        sealed_source.dispatcher_subject_id,
        sealed_source.dispatcher_block_ref,
        sealed_source.dead_handler_subject_ids,
        sealed_source.retained_handler_subject_ids,
        sealed_source.component_subject_ids,
        sealed_source.comparison_region_subject_ids,
        sealed_source.source_reachable_subject_ids,
        sealed_source.dead_handler_block_refs,
        sealed_source.retained_handler_block_refs,
        sealed_source.comparison_region_block_refs,
        sealed_source.terminal_digest,
        sealed_source.effect_digest,
        sealed_source.topology_digest,
        sealed_source.source_reachable_block_refs,
        sealed_source.component_block_refs,
        sealed_source.remainder_block_refs,
        (),
        sealed_source.effect_site_keys,
        sealed_source.source_blocks,
    )
    reissued_source = model.DetachedDeadHandlerComponentSourceResult(
        canonical_authority_id((
            "unflatten.detached-dead-handler-component-source.v2",
            *source_values,
        )),
        *source_values,
    )
    sealed_phase = binding.phase_result
    phase_values = (
        sealed_phase.claim_id,
        sealed_phase.phase,
        sealed_phase.corridor_coverage_result_id,
        sealed_phase.source_fingerprint,
        sealed_phase.candidate_fingerprint,
        sealed_phase.source_generation,
        sealed_phase.candidate_generation,
        sealed_phase.accepted,
        reissued_source.result_id,
    )
    reissued_phase = model.DetachedDeadHandlerComponentPhaseResult(
        canonical_authority_id((
            "unflatten.detached-dead-handler-component-phase.v1", *phase_values,
        )),
        *phase_values,
    )
    inputs = _complete_inputs(source_subjects=(_role_subject(
        model.SemanticSubjectRole.SOURCE_ENTRY, "case-reissued-source",
    ),))
    # The model validators correctly reject foreign detached rows as well.  Bypass
    # them only to exercise the evaluator's own transaction-authority boundary.
    object.__setattr__(
        inputs, "detached_dead_handler_component_source_results", (reissued_source,),
    )
    object.__setattr__(
        inputs, "detached_dead_handler_component_phase_results", (reissued_phase,),
    )
    monkeypatch.setattr(model.DerivedUnflattenPreparationInputs, "__post_init__", lambda _self: None)
    monkeypatch.setattr(model.SemanticSafetyCase, "__post_init__", lambda _self: None)

    with pytest.raises(
        ValueError,
        match="not minted by the transaction binder",
    ):
        build_semantic_case(
            authority_id=authority_id("case-reissued-detached-source"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=inputs,
        )


def test_case_builder_rejects_reissued_detached_phase_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The evaluator consumes only the binder-owned detached phase verdict."""

    from d810.transforms.unflatten_authority import bind
    from .test_bind import _detached_binding_fixture

    claim, source, projected, corridor = _detached_binding_fixture()
    binding = bind.bind_detached_dead_handler_component_claim(
        claim=claim,
        source_inventory=source,
        candidate_inventory=projected,
        corridor_result=corridor,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    sealed_phase = binding.phase_result
    phase_values = (
        sealed_phase.claim_id,
        sealed_phase.phase,
        sealed_phase.corridor_coverage_result_id,
        sealed_phase.source_fingerprint,
        sealed_phase.candidate_fingerprint,
        sealed_phase.source_generation,
        sealed_phase.candidate_generation,
        sealed_phase.accepted,
        sealed_phase.source_result_id,
    )
    reissued_phase = model.DetachedDeadHandlerComponentPhaseResult(
        canonical_authority_id((
            "unflatten.detached-dead-handler-component-phase.v1", *phase_values,
        )),
        *phase_values,
    )
    inputs = _complete_inputs(source_subjects=(_role_subject(
        model.SemanticSubjectRole.SOURCE_ENTRY, "case-reissued-phase",
    ),))
    # Bypass the model's coordinate checks solely to exercise the evaluator's
    # transaction-authority boundary with a genuine source result.
    object.__setattr__(
        inputs, "detached_dead_handler_component_source_results", (binding.source_result,),
    )
    object.__setattr__(
        inputs, "detached_dead_handler_component_phase_results", (reissued_phase,),
    )
    monkeypatch.setattr(model.DerivedUnflattenPreparationInputs, "__post_init__", lambda _self: None)
    monkeypatch.setattr(model.SemanticSafetyCase, "__post_init__", lambda _self: None)

    with pytest.raises(
        ValueError,
        match="not minted by the transaction binder",
    ):
        build_semantic_case(
            authority_id=authority_id("case-reissued-detached-phase"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=inputs,
        )


def test_role_inventory_is_exact_and_has_no_unrelated_cells() -> None:
    roles = tuple(
        role for role in model.SemanticSubjectRole
        if role is not model.SemanticSubjectRole.DISPATCHER_CORRIDOR
    )
    subjects = tuple(
        _role_subject(
            role,
            "2" if role is model.SemanticSubjectRole.AUTHORITATIVE_HANDLER
            else "0" if role in {
                model.SemanticSubjectRole.SOURCE_ENTRY,
                model.SemanticSubjectRole.DISPATCHER_ENTRY,
                model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
            } else f"role-{index}",
        )
        for index, role in enumerate(roles)
    )
    case = build_semantic_case(
        authority_id=authority_id("authority"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=subjects),
    )
    for subject in subjects:
        if subject.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW:
            subject = next(
                item for item in case.subjects
                if item.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW
            )
        actual = {key.dimension for key in case.required_obligations if key.subject == subject}
        expected = set(REQUIRED_DIMENSIONS[subject.role])
        if subject.role is model.SemanticSubjectRole.DISPATCHER_ENTRY:
            expected.add(model.SafetyDimension.ROUTE_EQUIVALENCE)
        if subject.role is model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION:
            expected.add(model.SafetyDimension.TERMINAL_REACHABILITY)
        if subject.role is model.SemanticSubjectRole.EFFECT_SITE:
            expected.add(model.SafetyDimension.TOPOLOGY_INTEGRITY)
        assert actual == expected


def test_inventory_topology_mismatches_refute_exact_case_cells() -> None:
    """Topology drift is injected into the closed candidate inventory itself."""

    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "topology-inventory")

    def candidate_case(mutator, token: str) -> model.SemanticSafetyCase:
        inputs = _complete_inputs(source_subjects=(entry,))
        inventory = inputs.candidate_inventory
        from copy import copy
        reference = copy(inventory)
        object.__setattr__(inputs, "projected_topology_reference", reference)
        object.__setattr__(inputs.preparation_receipt, "projected_topology_reference_digest", reference.inventory_digest)
        object.__setattr__(inputs.preparation_receipt, "receipt_id", receipt_id(inputs.preparation_receipt))
        blocks = tuple(mutator(list(inventory.blocks)))
        topology = list(inventory.topology)
        if token == "predecessor-missing":
            topology = [
                row for row in topology
                if not (
                    row.kind is model.TopologyIncidenceKind.PREDECESSOR
                    and row.owner_serial == 1 and row.peer_serial == 0
                )
            ]
        elif token == "successor-missing":
            topology = [
                row for row in topology
                if not (
                    (row.kind is model.TopologyIncidenceKind.SUCCESSOR
                     and row.owner_serial == 0 and row.peer_serial == 1)
                    or (row.kind is model.TopologyIncidenceKind.PREDECESSOR
                        and row.owner_serial == 1 and row.peer_serial == 0)
                )
            ]
        elif token == "addition":
            topology.extend((
                model.InventoryTopologyIncidence(
                    model.TopologyIncidenceKind.PREDECESSOR, 2, 0, None,
                ),
                model.InventoryTopologyIncidence(
                    model.TopologyIncidenceKind.SUCCESSOR, 0, 2, None,
                ),
            ))
        topology = tuple(sorted(
            topology,
            key=lambda row: (
                row.kind.value, row.owner_serial, row.peer_serial,
                row.source_transfer_ea if row.source_transfer_ea is not None else -1,
            ),
        ))
        object.__setattr__(inventory, "blocks", blocks)
        object.__setattr__(inventory, "topology", topology)
        if token == "successor-missing":
            object.__setattr__(inventory, "reachable_serials", (0,))
        digest = semantic_graph_inventory_digest(
            inventory.phase, inventory.graph_fingerprint, inventory.generation,
            inventory.blocks, inventory.subjects, inventory.bindings,
            inventory.effects, inventory.terminals, inventory.topology,
            inventory.reachable_serials, inventory.entry_serial,
            inventory.source_subject_ids, inventory.function_ea,
        )
        object.__setattr__(inventory, "inventory_digest", digest)
        object.__setattr__(inputs.preparation_receipt, "candidate_inventory_digest", digest)
        object.__setattr__(inputs.preparation_receipt, "projected_topology_reference_digest", inputs.projected_topology_reference.inventory_digest)
        object.__setattr__(inputs.preparation_receipt, "receipt_id", receipt_id(inputs.preparation_receipt))
        return build_semantic_case(
            authority_id=authority_id(f"topology-inventory-{token}"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=inputs,
        )

    variants = (
        (lambda blocks: [replace(block, predecessor_serials=()) if block.serial == 1 else block for block in blocks], "predecessor-missing"),
        (lambda blocks: [
            replace(block, successor_serials=()) if block.serial == 0
            else replace(block, predecessor_serials=()) if block.serial == 1
            else block
            for block in blocks
        ], "successor-missing"),
        (lambda blocks: [
            replace(block, successor_serials=(1, 2)) if block.serial == 0
            else replace(block, predecessor_serials=(0, 1)) if block.serial == 2
            else block
            for block in blocks
        ], "addition"),
    )
    for mutator, token in variants:
        with pytest.raises(ValueError, match="projected phase must reference"):
            candidate_case(mutator, token)


def test_projected_topology_reference_authorizes_intentional_redirect_for_incident_roles() -> None:
    """Projected topology is the reference for the projected authority phase."""

    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "topology-reference")
    route_source = _role_subject(
        model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, "topology-reference-source",
    )
    route_destination = _role_subject(
        model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION, "2",
    )
    inputs = _complete_inputs(
        source_subjects=(entry, route_source, route_destination),
    )
    candidate = inputs.candidate_inventory
    blocks = tuple(
        replace(
            block,
            successor_serials=(2,) if block.serial == 0 else (),
            predecessor_serials=(0,) if block.serial == 2 else (),
        )
        if block.serial in {0, 1, 2} else block
        for block in candidate.blocks
    )
    topology = tuple(sorted(
        (
            model.InventoryTopologyIncidence(
                model.TopologyIncidenceKind.SUCCESSOR, 0, 2, None,
            ),
            model.InventoryTopologyIncidence(
                model.TopologyIncidenceKind.PREDECESSOR, 2, 0, None,
            ),
        ),
        key=lambda row: (row.kind.value, row.owner_serial, row.peer_serial),
    ))
    object.__setattr__(candidate, "blocks", blocks)
    object.__setattr__(candidate, "topology", topology)
    object.__setattr__(candidate, "reachable_serials", (0, 2))
    digest = semantic_graph_inventory_digest(
        candidate.phase, candidate.graph_fingerprint, candidate.generation,
        candidate.blocks, candidate.subjects, candidate.bindings,
        candidate.effects, candidate.terminals, candidate.topology,
        candidate.reachable_serials, candidate.entry_serial,
        candidate.source_subject_ids, candidate.function_ea,
    )
    object.__setattr__(candidate, "inventory_digest", digest)
    object.__setattr__(inputs.preparation_receipt, "candidate_inventory_digest", digest)
    object.__setattr__(inputs.preparation_receipt, "projected_topology_reference_digest", digest)
    object.__setattr__(inputs.preparation_receipt, "receipt_id", receipt_id(inputs.preparation_receipt))

    case = build_semantic_case(
        authority_id=authority_id("projected-topology-reference"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=inputs,
    )
    incident_roles = {
        model.SemanticSubjectRole.SOURCE_ENTRY,
        model.SemanticSubjectRole.DISPATCHER_ENTRY,
        model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
        model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
        model.SemanticSubjectRole.AUTHORITATIVE_HANDLER,
    }
    incident_subjects = tuple(
        subject for subject in case.subjects
        if subject.block_ref is not None
        and subject.role in incident_roles
    )
    assert incident_subjects
    assert all(
        cell.state is model.ObligationState.SATISFIED
        for cell in case.obligation_index.cells
        if cell.key.dimension is model.SafetyDimension.TOPOLOGY_INTEGRITY
        and cell.key.subject in incident_subjects
    )


def test_observed_topology_is_rejected_against_prepared_projected_reference() -> None:
    """Observed source topology cannot replace the prepared projection."""

    from copy import copy

    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "observed-topology")
    route_source = _role_subject(
        model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, "observed-topology-source",
    )
    route_destination = _role_subject(
        model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION, "2",
    )
    baseline = _complete_inputs(
        source_subjects=(entry, route_source, route_destination),
    )
    actual = copy(baseline.candidate_inventory)
    reference = copy(baseline.candidate_inventory)
    reference_blocks = tuple(
        replace(
            block,
            successor_serials=(2,) if block.serial == 0 else (),
            predecessor_serials=(0,) if block.serial == 2 else (),
        )
        if block.serial in {0, 1, 2} else block
        for block in reference.blocks
    )
    reference_topology = (
        model.InventoryTopologyIncidence(
            model.TopologyIncidenceKind.PREDECESSOR, 2, 0, None,
        ),
        model.InventoryTopologyIncidence(
            model.TopologyIncidenceKind.SUCCESSOR, 0, 2, None,
        ),
    )
    object.__setattr__(reference, "blocks", reference_blocks)
    object.__setattr__(reference, "topology", reference_topology)
    object.__setattr__(reference, "reachable_serials", (0, 2))
    reference_digest = semantic_graph_inventory_digest(
        reference.phase, reference.graph_fingerprint, reference.generation,
        reference.blocks, reference.subjects, reference.bindings,
        reference.effects, reference.terminals, reference.topology,
        reference.reachable_serials, reference.entry_serial,
        reference.source_subject_ids, reference.function_ea,
    )
    object.__setattr__(reference, "inventory_digest", reference_digest)
    observed_fingerprint = authority_id("observed-topology")
    observed_generation = 5
    observed_bindings = tuple(
        replace(
            binding, phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            graph_fingerprint=observed_fingerprint, generation=observed_generation,
        )
        for binding in actual.bindings
    )
    object.__setattr__(actual, "phase", model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY)
    object.__setattr__(actual, "graph_fingerprint", observed_fingerprint)
    object.__setattr__(actual, "generation", observed_generation)
    object.__setattr__(actual, "bindings", observed_bindings)
    actual_digest = semantic_graph_inventory_digest(
        actual.phase, actual.graph_fingerprint, actual.generation,
        actual.blocks, actual.subjects, actual.bindings,
        actual.effects, actual.terminals, actual.topology,
        actual.reachable_serials, actual.entry_serial,
        actual.source_subject_ids, actual.function_ea,
    )
    object.__setattr__(actual, "inventory_digest", actual_digest)
    receipt_values = {
        name: getattr(baseline.preparation_receipt, name)
        for name in baseline.preparation_receipt.__dataclass_fields__
        if name not in {"receipt_id", "_minted"}
    }
    receipt_values.update({
        "candidate_fingerprint": observed_fingerprint,
        "candidate_generation": observed_generation,
        "candidate_inventory_digest": actual_digest,
        "candidate_binding_digest": _digest(tuple(sorted(observed_bindings, key=lambda item: item.subject.subject_id))),
        "projected_topology_reference_digest": reference_digest,
    })
    receipt = model.PreparationAuthorityReceipt.mint(**receipt_values)
    observed_inputs = replace(
        baseline,
        candidate_inventory=actual,
        projected_topology_reference=reference,
        preparation_receipt=receipt,
        phase_build_metrics=replace(
            baseline.phase_build_metrics,
            phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            source_inventory_builds=0,
        ),
    )
    case = build_semantic_case(
        authority_id=authority_id("observed-topology-reference"),
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        inputs=observed_inputs,
    )
    assert any(
        cell.state is model.ObligationState.VIOLATED
        for cell in case.obligation_index.cells
        if cell.key.dimension is model.SafetyDimension.TOPOLOGY_INTEGRITY
    )


def test_phase_binding_evidence_can_only_support_identity_dimension() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "exact-evidence")
    case = build_semantic_case(
        authority_id=authority_id("authority-exact-evidence"), phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=_complete_inputs(source_subjects=(subject,)),
    )
    identity = next(cell for cell in case.obligation_index.cells if cell.key == model.ObligationKey(subject, model.SafetyDimension.IDENTITY_BINDING))
    assert identity.state is model.ObligationState.SATISFIED
    for cell in case.obligation_index.cells:
        if cell.key.subject == subject and cell.key.dimension is not model.SafetyDimension.IDENTITY_BINDING:
            for justification_id in cell.supporting_justification_ids:
                justification = next(item for item in case.justifications if item.justification_id == justification_id)
                assert all(
                    not any(
                        evidence.evidence_id == premise
                        and evidence.kind is model.AuthorityEvidenceKind.PHASE_BINDING
                        for evidence in case.evidence
                    )
                    for premise in justification.premise_ids
                )


def test_generic_entry_gate_cannot_support_structure_or_topology() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "generic-scope")
    case = build_semantic_case(
        authority_id=authority_id("authority-generic-scope"), phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,)),
    )
    for dimension in (model.SafetyDimension.STRUCTURAL_ACCOUNTING, model.SafetyDimension.TOPOLOGY_INTEGRITY):
        cell = next(item for item in case.obligation_index.cells if item.key == model.ObligationKey(subject, dimension))
        for justification_id in cell.supporting_justification_ids:
            justification = next(item for item in case.justifications if item.justification_id == justification_id)
            assert all(
                not any(
                    evidence.evidence_id == premise
                    and evidence.kind is model.AuthorityEvidenceKind.GENERIC_CFG_GATE
                    for evidence in case.evidence
                )
                for premise in justification.premise_ids
            )


def test_missing_source_subject_retains_identity_and_structure_keys() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "missing")
    case = build_semantic_case(
        authority_id=authority_id("authority-missing"), phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,), candidate_subjects=(), candidate_bindings=()),
    )
    keys = {key.dimension for key in case.required_obligations}
    assert {model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.STRUCTURAL_ACCOUNTING} <= keys
    identity = next(
        item for item in case.obligation_index.cells
        if item.key == model.ObligationKey(subject, model.SafetyDimension.IDENTITY_BINDING)
    )
    assert identity.state is model.ObligationState.SATISFIED
    structural = next(
        item for item in case.obligation_index.cells
        if item.key == model.ObligationKey(subject, model.SafetyDimension.STRUCTURAL_ACCOUNTING)
    )
    assert structural.state is model.ObligationState.VIOLATED
    assert evaluate_case(case).reason is model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED


def test_canonical_case_roundtrip_preserves_source_partition_for_missing_identity() -> None:
    source = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "partition-source")
    candidate_only = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "partition-candidate")
    baseline = _complete_inputs(
        source_subjects=(source,), candidate_subjects=(source, candidate_only),
    )
    missing = next(
        item for item in baseline.candidate_inventory.bindings
        if item.subject == candidate_only
    )
    missing = replace(
        missing,
        status=model.SubjectBindingStatus.MISSING,
        block_ref=None, serial=None, anchor_ea=None, native_instruction_eas=(),
    )
    candidate_bindings = tuple(
        missing if item.subject == candidate_only else item
        for item in baseline.candidate_inventory.bindings
    )
    inputs = _complete_inputs(
        source_subjects=(source,), candidate_subjects=(source, candidate_only),
        candidate_bindings=candidate_bindings,
    )
    case = build_semantic_case(
        authority_id=authority_id("candidate-only-missing-partition"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=inputs,
    )
    identity = next(
        item for item in case.obligation_index.cells
        if item.key == model.ObligationKey(candidate_only, model.SafetyDimension.IDENTITY_BINDING)
    )
    assert identity.state is model.ObligationState.VIOLATED
    rebuilt = canonical_decode(canonical_bytes(case))
    assert rebuilt.source_subject_ids == case.source_subject_ids
    assert candidate_only.subject_id not in rebuilt.source_subject_ids
    rebuilt_identity = next(
        item for item in rebuilt.obligation_index.cells
        if item.key == model.ObligationKey(candidate_only, model.SafetyDimension.IDENTITY_BINDING)
    )
    assert rebuilt_identity.state is model.ObligationState.VIOLATED


def test_source_candidate_one_to_many_and_many_to_one_keep_source_keys() -> None:
    source = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "source")
    candidates = tuple(_role_subject(model.SemanticSubjectRole.PLANNED_HELPER, f"candidate-{i}") for i in range(2))
    case = build_semantic_case(
        authority_id=authority_id("authority-lineage"), phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(source,), candidate_subjects=candidates),
    )
    assert any(key.subject == source for key in case.required_obligations)
    assert all(any(key.subject == candidate for key in case.required_obligations) for candidate in candidates)


def test_justification_cells_are_four_state_and_sorted() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "cell")
    key = model.ObligationKey(subject, model.SafetyDimension.IDENTITY_BINDING)
    phase = model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
    def cell(supporting: tuple[str, ...], refuting: tuple[str, ...]) -> model.ObligationEvidenceCell:
        return model.ObligationEvidenceCell(key, phase, supporting, refuting)
    assert cell((), ()).state is model.ObligationState.UNPROVEN
    assert cell((authority_id("support"),), ()).state is model.ObligationState.SATISFIED
    assert cell((), (authority_id("refute"),)).state is model.ObligationState.VIOLATED
    assert cell((authority_id("support"),), (authority_id("refute"),)).state is model.ObligationState.INCONSISTENT


def test_case_ids_and_private_index_reject_tampering() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "tamper")
    case = build_semantic_case(
        authority_id=authority_id("authority-tamper"), phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,)),
    )
    with pytest.raises(TypeError):
        model.ObligationEvidenceIndex(case.obligation_index.cells)  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        replace(case, case_id=authority_id("forged"))


def test_justification_foreign_premise_and_cycle_are_rejected() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "dag")
    key = model.ObligationKey(subject, model.SafetyDimension.IDENTITY_BINDING)
    phase = model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
    values = dict(rule=model.UnflattenJustificationRule.UNIQUE_PHASE_BINDING,
                  premise_ids=(authority_id("not-in-inventory"),), conclusion=key,
                  polarity=model.EvidencePolarity.SUPPORTS, phase=phase)
    raw = object.__new__(model.AuthorityJustification)
    for name, value in values.items():
        object.__setattr__(raw, name, value)
    object.__setattr__(raw, "justification_id", "sha256:" + "0" * 64)
    from d810.transforms.unflatten_authority.ids import justification_id
    foreign = model.AuthorityJustification(justification_id=justification_id(raw), **values)
    with pytest.raises(ValueError, match="foreign"):
        from d810.transforms.unflatten_authority.evaluate import _validate_justification_graph
        _validate_justification_graph((foreign,), (key,), (), phase)


def test_metrics_and_view_counters_are_exact_and_preserved() -> None:
    metrics = model.PreparationBuildMetrics(1, 1, 4.5)
    assert metrics == model.PreparationBuildMetrics(1, 1, 4.5)
    for bad in ((0, 1, 1.0), (1, 2, 1.0), (1, 1, -1.0), (1, 1, float("inf"))):
        with pytest.raises((TypeError, ValueError)):
            model.PreparationBuildMetrics(*bad)
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "metrics")
    case = build_semantic_case(
        authority_id=authority_id("authority-metrics"), phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,)),
    )
    from d810.transforms.unflatten_authority.views import view_metrics
    assert view_metrics(case).index_folds == 1
    assert view_metrics(case).view_graph_traversals == 0
    assert view_metrics(case).preparation_metrics == model.PreparationBuildMetrics(1, 1, 1.25)
    assert canonical_decode(canonical_bytes(case)).phase_metrics == case.phase_metrics


def test_preparation_receipt_is_hashed_and_closed() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "manifest")
    base = _complete_inputs(source_subjects=(entry,))
    assert canonical_decode(canonical_bytes(base.preparation_receipt)) == base.preparation_receipt
    values = {name: getattr(base.preparation_receipt, name) for name in base.preparation_receipt.__dataclass_fields__ if name not in {"receipt_id", "_token", "_minted"}}
    values["plan_input_digest"] = authority_id("omitted-plan-input")
    incomplete = replace(base, preparation_receipt=_receipt_fixture(**values))
    with pytest.raises(ValueError, match="receipt|plan input"):
        build_semantic_case(
            authority_id=authority_id("manifest-omission"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=incomplete,
        )


def test_topology_support_requires_named_reciprocal_peer_rows() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "topology-entry")
    peer = _role_subject(model.SemanticSubjectRole.DISPATCHER_ENTRY, "topology-peer")
    payload = model.TopologyEvidencePayload(
        entry.subject_id, (), (peer.subject_id,), True,
        canonical_authority_id(()), canonical_authority_id(()),
    )
    evidence = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.TOPOLOGY,
        entry, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, payload,
    )
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        build_semantic_case(
            authority_id=authority_id("topology-peer-missing"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=replace(
                _complete_inputs(source_subjects=(entry, peer)),
                topology_evidence=(evidence,),
            ),
        )


def test_patch_step_evidence_must_match_closed_step_inventory() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "patch-inventory")
    helper = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "0")
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    payload = model.PatchStepEvidencePayload(
        proposal.plan_id, 0, "PatchInsertBlock", helper.block_ref,
        authority_id("patch-step"), helper.anchor_ea, 0x90, 4,
    )
    evidence = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.PATCH_STEP,
        helper, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, payload,
    )
    values = {name: getattr(_complete_inputs(source_subjects=(entry,), candidate_subjects=(entry, helper), patch_step_facts=(evidence.payload,), proposal=proposal).preparation_receipt, name) for name in model.PreparationAuthorityReceipt.__dataclass_fields__ if name not in {"receipt_id", "_token", "_minted"}}
    values["patch_step_digest"] = authority_id("forged-step-copy")
    with pytest.raises(ValueError, match="receipt|patch"):
        build_semantic_case(
            authority_id=authority_id("patch-inventory-forged"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=replace(_complete_inputs(source_subjects=(entry,), candidate_subjects=(entry, helper), patch_step_facts=(evidence.payload,), proposal=proposal), preparation_receipt=_receipt_fixture(**values)),
        )


def test_patch_step_lineage_materializes_one_row_per_exact_owner_role() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "patch-role-entry")
    dispatcher_entry = _role_subject(model.SemanticSubjectRole.DISPATCHER_ENTRY, "0")
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    payload = model.PatchStepEvidencePayload(
        proposal.plan_id, 0, "PatchLowerConditionalStateTransition", entry.block_ref,
        authority_id("patch-role-step"), entry.anchor_ea, None, None,
    )
    inputs = _complete_inputs(
        source_subjects=(entry,),
        candidate_subjects=(entry, dispatcher_entry),
        patch_step_facts=(payload,), proposal=proposal,
    )

    case = build_semantic_case(
        authority_id=authority_id("patch-role-case"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=inputs,
    )
    owner_subjects = tuple(
        subject for subject in inputs.candidate_inventory.subjects
        if subject.block_ref == payload.owner_ref
        and subject.kind is model.SemanticSubjectKind.BLOCK
    )
    patch_rows = tuple(
        item for item in case.evidence
        if item.kind is model.AuthorityEvidenceKind.PATCH_STEP
    )
    assert len(patch_rows) == len(owner_subjects)
    assert {item.subject.subject_id for item in patch_rows} == {
        item.subject_id for item in owner_subjects
    }
    assert canonical_decode(canonical_bytes(case)) == case
    with pytest.raises(ValueError, match="evidence_id"):
        replace(patch_rows[0], evidence_id=authority_id("forged-patch-row"))
    for justification in case.justifications:
        if justification.rule is model.UnflattenJustificationRule.HELPER_OWNER_LINEAGE_PROVEN:
            assert all(
                next(item for item in case.evidence if item.evidence_id == premise).subject.subject_id
                == justification.conclusion.subject.subject_id
                for premise in justification.premise_ids
            )


def test_hostile_same_name_resegmentation_step_is_not_authority() -> None:
    """A stringly named foreign step cannot create lineage authority."""

    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "hostile-resegment")
    helper = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "0")
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    payload = model.PatchStepEvidencePayload(
        proposal.plan_id, 0, "PatchResegmentBlock", helper.block_ref,
        authority_id("hostile-resegment-step"), helper.anchor_ea, 0x90, 4,
    )
    with pytest.raises(ValueError, match="unsupported step kind"):
        build_semantic_case(
            authority_id=authority_id("hostile-resegment-case"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=_complete_inputs(
                source_subjects=(entry,), candidate_subjects=(entry, helper),
                patch_step_facts=(payload,), proposal=proposal,
            ),
        )


def test_empty_or_claim_only_inputs_cannot_build_an_accepted_authority() -> None:
    inputs = _complete_inputs(source_subjects=(), candidate_subjects=(), candidate_bindings=())
    with pytest.raises(ValueError, match="inventory|obligation|subject"):
        build_semantic_case(
            authority_id=authority_id("empty-authority"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=inputs,
        )


def test_evidence_header_subject_and_phase_mismatch_is_rejected() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "header")
    other = _role_subject(model.SemanticSubjectRole.DISPATCHER_ENTRY, "foreign-header")
    payload = model.TopologyEvidencePayload(
        subject.subject_id, (), (), True, canonical_authority_id(()), canonical_authority_id(()),
    )
    evidence = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.TOPOLOGY, other,
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, payload,
    )
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        build_semantic_case(
            authority_id=authority_id("header-mismatch"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
                inputs=replace(
                    _complete_inputs(source_subjects=(subject,)),
                    lineage_evidence=(evidence,),
                ),
        )


def test_generic_gate_requires_exact_role_scope_and_multiple_rows() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "wrong-gate-role")
    gate = model.GenericCfgGateResult(
        model.GenericCfgGateKind.EFFECTFUL_REACHABILITY, True, (subject.subject_id,), (), "bad-role",
    )
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        build_semantic_case(
            authority_id=authority_id("wrong-gate-role"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=replace(
                _complete_inputs(source_subjects=(subject,)),
                generic_gates=(gate,),
            ),
        )


def test_public_decode_cannot_install_an_evaluator_owned_index() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "decode-index")
    case = build_semantic_case(
        authority_id=authority_id("decode-index"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,)),
    )
    with pytest.raises(ValueError):
        canonical_decode(canonical_bytes(case.obligation_index))


def test_case_decode_recomputes_and_rejects_erased_index_cells() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "decode-case")
    case = build_semantic_case(
        authority_id=authority_id("decode-case"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,)),
    )
    wire = json.loads(canonical_bytes(case).decode("ascii"))

    def erase_support(value: object) -> bool:
        if isinstance(value, dict) and value.get("t") == "record" and value.get("n") == "ObligationEvidenceIndex":
            for name, encoded in value["v"]:
                if name == "cells" and encoded["v"]:
                    for cell in encoded["v"]:
                        for cell_name, cell_value in cell["v"]:
                            if cell_name == "supporting_justification_ids" and cell_value["v"]:
                                cell_value["v"] = []
                                return True
        if isinstance(value, dict):
            return any(erase_support(item) for item in value.values())
        if isinstance(value, list):
            return any(erase_support(item) for item in value)
        return False

    assert erase_support(wire)
    with pytest.raises(ValueError, match="index|fold|record"):
        canonical_decode(json.dumps(wire, sort_keys=True, separators=(",", ":")).encode("ascii"))


def test_claim_without_correlated_typed_evidence_cannot_authorize_route() -> None:
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    claim = proposal.claims[0]
    subjects = (
        _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "claim-only-entry"),
        claim.retired_route_subject, claim.source_subject, *claim.destination_subjects,
    )
    case = build_semantic_case(
        authority_id=authority_id("claim-only-route"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=subjects),
    )
    route_cells = tuple(
        cell for cell in case.obligation_index.cells
        if cell.key.dimension is model.SafetyDimension.ROUTE_EQUIVALENCE
    )
    assert route_cells and all(not cell.supporting_justification_ids for cell in route_cells)


def test_non_block_identity_requires_the_exact_candidate_subject() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "nonblock-entry")
    effect = _role_subject(model.SemanticSubjectRole.EFFECT_SITE, "nonblock-effect")
    baseline = _complete_inputs(
        source_subjects=(entry, effect), candidate_subjects=(entry,),
    )
    missing_effect = tuple(
        replace(
            binding, status=model.SubjectBindingStatus.MISSING,
            block_ref=None, serial=None, anchor_ea=None,
            native_instruction_eas=(),
        ) if binding.subject == effect else binding
        for binding in baseline.candidate_inventory.bindings
    )
    with pytest.raises(ValueError, match="preserved lineage"):
        build_semantic_case(
            authority_id=authority_id("nonblock-absence"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=_complete_inputs(
                source_subjects=(entry, effect), candidate_subjects=(entry,),
                candidate_bindings=missing_effect,
            ),
        )


def test_planned_helper_without_receipt_relation_gets_no_route_authority() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "helper-entry")
    helper = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "0")
    case = build_semantic_case(
        authority_id=authority_id("helper-route"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(entry,), candidate_subjects=(entry, helper)),
    )
    helper_dimensions = {
        item.dimension for item in case.required_obligations if item.subject == helper
    }
    assert model.SafetyDimension.ROUTE_EQUIVALENCE not in helper_dimensions
    assert helper_dimensions == set(REQUIRED_DIMENSIONS[helper.role])


def test_stale_candidate_generation_precedes_obligation_reason() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "stale-generation")
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    flow = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.VALUE_FLOW,
        role=model.SemanticSubjectRole.NON_STATE_VALUE_FLOW,
        block_ref=None, anchor_ea=None,
        locator=model.ValueFlowSubjectLocator(
            proposal.use_def_witness.fragment_id,
            proposal.use_def_witness.state_identity,
            proposal.plan_inputs.dispatcher_member_refs,
        ),
    )
    candidate_subjects = (entry, flow)
    inputs = _complete_inputs(
        source_subjects=(entry,), candidate_subjects=candidate_subjects,
        proposal=proposal,
    )
    stale_bindings = tuple(
        _binding(item.subject, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
                 fingerprint=authority_id("stale-fingerprint"))
        for item in inputs.candidate_inventory.bindings
    )
    object.__setattr__(inputs.candidate_inventory, "bindings", stale_bindings)
    object.__setattr__(
        inputs.preparation_receipt, "candidate_binding_digest",
        _digest(tuple(sorted(stale_bindings, key=lambda item: item.subject.subject_id))),
    )
    object.__setattr__(inputs.preparation_receipt, "receipt_id", receipt_id(inputs.preparation_receipt))
    with pytest.raises(ValueError, match="binding|inventory"):
        build_semantic_case(
            authority_id=authority_id("stale-generation"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=inputs,
        )


def test_producer_forecast_uses_source_fingerprint_and_source_binding_reason() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "producer-phase")
    base = _complete_inputs(source_subjects=(entry,))
    missing_source_bindings = tuple(
        _binding(
            subject, model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
            fingerprint=authority_id("source-fp"), status=model.SubjectBindingStatus.MISSING,
        )
        for subject in base.source_inventory.subjects
    )
    phase_inputs = _complete_inputs(
        source_subjects=base.source_inventory.subjects,
        candidate_subjects=base.candidate_inventory.subjects,
        source_bindings=missing_source_bindings,
    )
    case = build_semantic_case(
        authority_id=authority_id("producer-phase"),
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        inputs=phase_inputs,
    )
    assert case.candidate_fingerprint == base.source_inventory.graph_fingerprint
    assert case.candidate_generation == base.source_inventory.generation
    assert evaluate_case(case).reason is model.UnflattenAuthorityReason.SOURCE_BINDING_FAILED


def test_patch_step_wrong_plan_is_rejected_at_closed_boundary() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "patch-entry")
    helper = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "0")
    payload = model.PatchStepEvidencePayload(
        authority_id("wrong-plan"), 0, "PatchRedirectBranch", helper.block_ref,
        authority_id("step"), None, None, None,
    )
    evidence = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.PATCH_STEP,
        helper, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, payload,
    )
    with pytest.raises(ValueError, match="plan"):
        build_semantic_case(
            authority_id=authority_id("wrong-plan-case"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=_complete_inputs(
                source_subjects=(entry,), candidate_subjects=(entry, helper),
                patch_step_facts=(evidence.payload,),
            ),
        )


def test_route_evidence_must_match_canonical_proof_scope() -> None:
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    claim = proposal.claims[0]
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "route-scope-entry")
    payload = model.SemanticRouteEvidencePayload(
        claim.retired_route_subject.subject_id,
        (authority_id("foreign-proof"),),
        claim.atomic_group_id,
        claim.source_subject.subject_id,
        tuple(item.subject_id for item in claim.destination_subjects),
        True,
    )
    evidence = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.SEMANTIC_ROUTE,
        claim.retired_route_subject, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        payload,
    )
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        build_semantic_case(
            authority_id=authority_id("route-scope-case"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=replace(
                _complete_inputs(
                    source_subjects=(entry, claim.retired_route_subject, claim.source_subject, *claim.destination_subjects),
                ),
                lineage_evidence=(evidence,),
            ),
        )


def test_rejected_result_variants_cannot_claim_accepted_or_empty_success() -> None:
    with pytest.raises(ValueError):
        model.UnflattenAuthorityVerdict(
            True, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            model.UnflattenAuthorityReason.ACCEPTED, authority_id("x"), None, None,
            authority_id("candidate"), None, (),
        )


def test_semantic_case_carries_exact_source_phase_bindings_for_loss_provenance() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "source-provenance")
    case = build_semantic_case(
        authority_id=authority_id("source-provenance"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,), candidate_subjects=()),
    )
    assert case.source_bindings
    assert case.preparation_receipt.receipt_id == case.preparation_receipt_id
    assert case.preparation_receipt.source_fingerprint == case.source_fingerprint
    assert case.preparation_receipt.source_inventory_digest == case.source_inventory.inventory_digest
    assert case.source_inventory.phase is model.UnflattenAuthorityPhase.PRODUCER_FORECAST
    assert case.source_inventory.graph_fingerprint == case.source_fingerprint
    assert case.source_inventory.bindings == case.source_bindings
    source_by_subject = {binding.subject.subject_id: binding for binding in case.source_bindings}
    assert set(case.source_subject_ids) == set(source_by_subject)
    assert all(binding.phase is model.UnflattenAuthorityPhase.PRODUCER_FORECAST for binding in case.source_bindings)
    assert canonical_decode(canonical_bytes(case)) == case


def test_semantic_case_rejects_reissued_source_inventory_or_binding_rows() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "source-reissue")
    case = build_semantic_case(
        authority_id=authority_id("source-reissue"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,), candidate_subjects=()),
    )
    with pytest.raises(ValueError):
        replace(
            case,
            source_inventory=replace(
                case.source_inventory,
                generation=case.source_inventory.generation + 1,
            ),
        )
    forged_binding = replace(case.source_bindings[0], serial=999)
    with pytest.raises(ValueError, match="source_bindings"):
        replace(case, source_bindings=(forged_binding, *case.source_bindings[1:]))
    with pytest.raises(ValueError, match="preparation_receipt"):
        replace(case, preparation_receipt_id=authority_id("foreign-receipt"))
    receipt_values = {
        name: getattr(case.preparation_receipt, name)
        for name in case.preparation_receipt.__dataclass_fields__
        if name not in {"receipt_id", "_minted"}
    }
    receipt_values["source_fingerprint"] = authority_id("reissued-source")
    forged_receipt = model.PreparationAuthorityReceipt.mint(**receipt_values)
    case_values = {
        name: getattr(case, name)
        for name in case.__dataclass_fields__
        if name != "case_id"
    }
    case_values["preparation_receipt_id"] = forged_receipt.receipt_id
    case_values["preparation_receipt"] = forged_receipt
    with pytest.raises(ValueError, match="source_fingerprint|source_inventory"):
        _case_factory(model.SemanticSafetyCase, **case_values)


def test_attached_rejection_must_report_exact_case_failures() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "verdict-failures")
    case = build_semantic_case(
        authority_id=authority_id("verdict-failures"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,), candidate_subjects=()),
    )
    expected = tuple(
        model.FailedObligation(cell.key, cell.state)
        for cell in case.obligation_index.cells
        if cell.state is not model.ObligationState.SATISFIED
    )
    with pytest.raises(ValueError, match="failed obligations"):
        model.UnflattenAuthorityVerdict(
            False, case.phase, model.UnflattenAuthorityReason.OBLIGATION_VIOLATED,
            case.authority_id, None, case.case_id, case.candidate_fingerprint,
            case, (),
        )
    verdict = model.UnflattenAuthorityVerdict(
        False, case.phase, model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
        case.authority_id, None, case.case_id, case.candidate_fingerprint,
        case, expected,
    )
    assert verdict.failed_obligations == expected


def test_case_decode_rejects_foreign_justification_premise() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "foreign-premise")
    case = build_semantic_case(
        authority_id=authority_id("foreign-premise-case"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,)),
    )
    wire = json.loads(canonical_bytes(case).decode("ascii"))

    def corrupt(value: object) -> bool:
        if isinstance(value, dict) and value.get("t") == "record" and value.get("n") == "AuthorityJustification":
            for name, encoded in value["v"]:
                if name == "premise_ids":
                    encoded["v"] = [{"t": "str", "v": authority_id("foreign-premise-id")}]
                    return True
        if isinstance(value, dict):
            return any(corrupt(item) for item in value.values())
        if isinstance(value, list):
            return any(corrupt(item) for item in value)
        return False

    assert corrupt(wire)
    with pytest.raises(ValueError, match="premise|record"):
        canonical_decode(json.dumps(wire, sort_keys=True, separators=(",", ":")).encode("ascii"))


def test_case_decode_rejects_cross_phase_justification() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "cross-phase")
    case = build_semantic_case(
        authority_id=authority_id("cross-phase-case"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,)),
    )
    wire = json.loads(canonical_bytes(case).decode("ascii"))

    def corrupt(value: object) -> bool:
        if isinstance(value, dict) and value.get("t") == "record" and value.get("n") == "AuthorityJustification":
            for name, encoded in value["v"]:
                if name == "phase":
                    encoded["v"] = {"t": "str", "v": "producer_forecast"}
                    return True
        if isinstance(value, dict):
            return any(corrupt(item) for item in value.values())
        if isinstance(value, list):
            return any(corrupt(item) for item in value)
        return False

    assert corrupt(wire)
    with pytest.raises(ValueError, match="phase|record"):
        canonical_decode(json.dumps(wire, sort_keys=True, separators=(",", ":")).encode("ascii"))


def test_justification_rule_schema_rejects_wrong_dimension_polarity_and_scope() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "rule-schema")
    case = build_semantic_case(
        authority_id=authority_id("rule-schema"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,)),
    )
    identity = next(
        item for item in case.justifications
        if item.conclusion == model.ObligationKey(subject, model.SafetyDimension.IDENTITY_BINDING)
    )
    for changes in (
        {"rule": model.UnflattenJustificationRule.SOURCE_PRESERVED},
        {"polarity": model.EvidencePolarity.REFUTES},
        {"premise_ids": ()},
    ):
        values = {
            name: getattr(identity, name)
            for name in identity.__dataclass_fields__ if name != "justification_id"
        }
        values.update(changes)
        forged = _justification_factory(model.AuthorityJustification, **values)
        with pytest.raises(ValueError, match="rule|dimension|polarity|premise|evidence"):
            from d810.transforms.unflatten_authority.evaluate import _validate_justification_graph
            _validate_justification_graph(
                (forged,), case.required_obligations, case.evidence, case.phase,
            )


def test_justification_ids_cannot_be_used_as_premises() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "justification-premise")
    case = build_semantic_case(
        authority_id=authority_id("justification-premise"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,)),
    )
    first, second = case.justifications[:2]
    values = {
        name: getattr(second, name)
        for name in second.__dataclass_fields__ if name != "justification_id"
    }
    values["premise_ids"] = (first.justification_id,)
    forged = _justification_factory(model.AuthorityJustification, **values)
    from d810.transforms.unflatten_authority.evaluate import _validate_justification_graph
    with pytest.raises(ValueError, match="premise"):
        _validate_justification_graph(
            (first, forged), case.required_obligations, case.evidence, case.phase,
        )


def test_split_and_fold_lineage_require_reciprocal_origin_witnesses() -> None:
    source = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "split-source")
    first = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "1")
    second = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "2")
    split = model.StructuralLineageEvidencePayload(
        source.subject_id, (first.subject_id, second.subject_id),
        model.StructuralDisposition.SPLIT, (), None,
    )
    split_evidence = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.STRUCTURAL_LINEAGE,
        source, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, split,
    )
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        build_semantic_case(
            authority_id=authority_id("split-without-origin"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=replace(
                _complete_inputs(source_subjects=(source,), candidate_subjects=(source, first, second)),
                lineage_evidence=(split_evidence,),
            ),
        )
    with pytest.raises(ValueError, match="folded lineage"):
        folded = model.StructuralLineageEvidencePayload(
            source.subject_id, (first.subject_id,),
            model.StructuralDisposition.FOLDED, (0x1000, 0x1300), None,
        )
        folded_evidence = _evidence_factory(
            model.AuthorityEvidence, model.AuthorityEvidenceKind.STRUCTURAL_LINEAGE,
            source, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, folded,
        )
        build_semantic_case(
            authority_id=authority_id("fold-with-origin"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=replace(
                _complete_inputs(source_subjects=(source,), candidate_subjects=(source, first)),
                lineage_evidence=(folded_evidence,),
            ),
        )


def test_split_and_fold_lineage_use_exact_reciprocal_binding_eas() -> None:
    source = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "reciprocal-source")
    folded_source = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "1")
    first = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "1")
    second = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "2")
    split = model.StructuralLineageEvidencePayload(
        source.subject_id, (first.subject_id, second.subject_id),
        model.StructuralDisposition.SPLIT, (0x1000, 0x1100, 0x1300), None,
    )
    with pytest.raises(ValueError, match="folded|source group"):
        model.StructuralLineageEvidencePayload(
            folded_source.subject_id, (first.subject_id,),
            model.StructuralDisposition.FOLDED, (0x1300,), None,
        )
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        build_semantic_case(
            authority_id=authority_id("forged-reciprocal"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=replace(
                _complete_inputs(
                    source_subjects=(source, folded_source),
                    candidate_subjects=(source, folded_source, first, second),
                ),
                lineage_evidence=(_evidence_factory(
                    model.AuthorityEvidence, model.AuthorityEvidenceKind.STRUCTURAL_LINEAGE,
                    source, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, split,
                ),),
            ),
        )


def test_fold_lineage_partitions_disjoint_source_origins_and_supports_each_member() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "0")
    first = _role_subject(model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, "0")
    second = _role_subject(model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION, "2")
    helper = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "0")
    baseline = _complete_inputs(source_subjects=(entry, first, second), candidate_subjects=(entry, first, second, helper))
    helper_binding = replace(
        next(item for item in baseline.candidate_inventory.bindings if item.subject == helper),
        native_instruction_eas=(first.anchor_ea, second.anchor_ea),
    )
    candidate_bindings = tuple(
        helper_binding if item.subject == helper else item
        for item in baseline.candidate_inventory.bindings
    )
    inputs = _complete_inputs(
        source_subjects=(entry, first, second),
        candidate_subjects=(entry, first, second, helper),
    )
    helper_block = next(
        block for block in inputs.candidate_inventory.blocks
        if block.serial == helper_binding.serial
    )
    helper_instructions = tuple(
        model.InventoryInstructionObservation(
            ordinal, ea, 0, 0, model.InsnKind.NOP, None, False, None,
        )
        for ordinal, ea in enumerate(helper_binding.native_instruction_eas)
    )
    object.__setattr__(
        inputs.candidate_inventory, "blocks",
        tuple(
            replace(
                block,
                native_instruction_eas=helper_binding.native_instruction_eas,
                instruction_observations=helper_instructions,
            ) if block is helper_block else block
            for block in inputs.candidate_inventory.blocks
        ),
    )
    object.__setattr__(inputs.candidate_inventory, "bindings", candidate_bindings)
    object.__setattr__(inputs.preparation_receipt, "candidate_binding_digest", _digest(tuple(sorted(candidate_bindings, key=lambda item: item.subject.subject_id))))
    object.__setattr__(
        inputs.candidate_inventory, "inventory_digest",
        semantic_graph_inventory_digest(
            inputs.candidate_inventory.phase,
            inputs.candidate_inventory.graph_fingerprint,
            inputs.candidate_inventory.generation,
            inputs.candidate_inventory.blocks,
            inputs.candidate_inventory.subjects,
            inputs.candidate_inventory.bindings,
            inputs.candidate_inventory.effects,
            inputs.candidate_inventory.terminals,
            inputs.candidate_inventory.topology,
            inputs.candidate_inventory.reachable_serials,
            inputs.candidate_inventory.entry_serial,
            inputs.candidate_inventory.source_subject_ids,
            inputs.candidate_inventory.function_ea,
        ),
    )
    object.__setattr__(inputs.preparation_receipt, "candidate_inventory_digest", inputs.candidate_inventory.inventory_digest)
    object.__setattr__(inputs.preparation_receipt, "projected_topology_reference_digest", inputs.projected_topology_reference.inventory_digest)
    object.__setattr__(inputs.preparation_receipt, "receipt_id", receipt_id(inputs.preparation_receipt))
    with pytest.raises(ValueError, match="binding|inventory"):
        build_semantic_case(
            authority_id=authority_id("valid-fold-group"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=inputs,
        )
def test_effect_topology_is_conditional_on_exact_owner_survival() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "effect-entry")
    effect = _role_subject(model.SemanticSubjectRole.EFFECT_SITE, "1")
    case = build_semantic_case(
        authority_id=authority_id("effect-owner-absent"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(
            source_subjects=(entry, effect), candidate_subjects=(entry,),
        ),
    )
    dimensions = {
        key.dimension for key in case.required_obligations if key.subject == effect
    }
    assert model.SafetyDimension.TOPOLOGY_INTEGRITY not in dimensions
    assert next(
        cell for cell in case.obligation_index.cells
        if cell.key == model.ObligationKey(effect, model.SafetyDimension.IDENTITY_BINDING)
    ).state is model.ObligationState.SATISFIED


def test_local_alias_support_targets_exact_store_effect_relation() -> None:
    values = _valid_proposal(model)
    b0, b2 = block_ref("b0"), block_ref("b2")
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "0")
    owner = _subject_factory(
        model.SemanticSubjectRef, kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.EFFECT_SITE, block_ref=b0, anchor_ea=0x1000,
        locator=model.BlockSubjectLocator(b0, 0x1000),
    )
    store = _subject_factory(
        model.SemanticSubjectRef, kind=model.SemanticSubjectKind.EFFECT,
        role=model.SemanticSubjectRole.EFFECT_SITE, block_ref=b0, anchor_ea=0x1000,
        locator=model.EffectSubjectLocator(b0, 0x1000, 0x1000, model.EffectSiteKind.STORE),
    )
    route = _subject_factory(
        model.SemanticSubjectRef, kind=model.SemanticSubjectKind.ROUTE,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, block_ref=b0, anchor_ea=0x1000,
        locator=model.RouteSubjectLocator(authority_id("proof"), authority_id("group"), b0, 0x1000, (b2,), (0x1100,)),
    )
    destination = _role_subject(model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION, "2")
    alias = _claim_factory(
        model.LocalAliasEffectScalarizationClaim,
        kind=model.UnflattenClaimKind.LOCAL_ALIAS_EFFECT_SCALARIZATION,
        owner_subject=owner, step_index=0, host_ea=0x1000, host_opcode=1,
        alias_token="alias", base_token="base", host_text_sha1=None, value_size=None,
        step_digest=authority_id("alias-step"), source_generation=3,
    )
    proposal = model.ProposedUnflattenContract(**values)
    helper = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "0")
    patch_payload = model.PatchStepEvidencePayload(
        proposal.plan_id, 0, "PatchScalarizeLocalAliasAccess", b0,
        alias.step_digest, 0x1000, 1, None,
    )
    patch_item = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.PATCH_STEP,
        helper, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, patch_payload,
    )
    relation = model.ConditionalSubjectRelation(
        owner.subject_id, store.subject_id, model.SafetyDimension.EFFECT_PRESERVATION,
        authority_id("alias-relation"),
    )
    inputs = _complete_inputs(
        source_subjects=(entry, owner, store, route, destination),
        candidate_subjects=(entry, owner, store, route, destination, helper),
        claims=(*proposal.claims, alias), proposal=proposal, patch_step_facts=(patch_item.payload,),
    )
    receipt_values = {
        name: getattr(inputs.preparation_receipt, name)
        for name in inputs.preparation_receipt.__dataclass_fields__
            if name not in {"receipt_id", "_minted"}
    }
    receipt_values["conditional_relation_digest"] = _digest((relation,))
    inputs = replace(
        inputs, conditional_relations=(relation,),
        preparation_receipt=_receipt_fixture(**receipt_values),
    )
    case = build_semantic_case(
        authority_id=authority_id("valid-alias-relation"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, inputs=inputs,
    )
    cell = next(
        cell for cell in case.obligation_index.cells
        if cell.key == model.ObligationKey(store, model.SafetyDimension.EFFECT_PRESERVATION)
    )
    assert cell.state is model.ObligationState.SATISFIED

    wrong_store = _subject_factory(
        model.SemanticSubjectRef, kind=model.SemanticSubjectKind.EFFECT,
        role=model.SemanticSubjectRole.EFFECT_SITE, block_ref=b2, anchor_ea=0x1100,
        locator=model.EffectSubjectLocator(b2, 0x1100, 0x1100, model.EffectSiteKind.STORE),
    )
    wrong_relation = model.ConditionalSubjectRelation(
        owner.subject_id, wrong_store.subject_id, model.SafetyDimension.EFFECT_PRESERVATION,
        authority_id("alias-wrong-owner"),
    )
    wrong_inputs = _complete_inputs(
        source_subjects=(entry, owner, wrong_store, route, destination),
        candidate_subjects=(entry, owner, wrong_store, route, destination, helper),
        claims=(*proposal.claims, alias), proposal=proposal, patch_step_facts=(patch_item.payload,),
    )
    wrong_receipt_values = {
        name: getattr(wrong_inputs.preparation_receipt, name)
        for name in wrong_inputs.preparation_receipt.__dataclass_fields__
            if name not in {"receipt_id", "_minted"}
    }
    wrong_receipt_values["conditional_relation_digest"] = _digest((wrong_relation,))
    wrong_inputs = replace(
        wrong_inputs, conditional_relations=(wrong_relation,),
        preparation_receipt=_receipt_fixture(**wrong_receipt_values),
    )
    with pytest.raises(ValueError, match="exact STORE alias effect"):
        build_semantic_case(
            authority_id=authority_id("alias-wrong-owner-case"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, inputs=wrong_inputs,
        )


def test_local_alias_requires_endpoint_bearing_reachability_path() -> None:
    values = _valid_proposal(model)
    b0, b2 = block_ref("b0"), block_ref("b2")
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "0")
    owner = _subject_factory(
        model.SemanticSubjectRef, kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.EFFECT_SITE, block_ref=b0, anchor_ea=0x1000,
        locator=model.BlockSubjectLocator(b0, 0x1000),
    )
    store = _subject_factory(
        model.SemanticSubjectRef, kind=model.SemanticSubjectKind.EFFECT,
        role=model.SemanticSubjectRole.EFFECT_SITE, block_ref=b0, anchor_ea=0x1000,
        locator=model.EffectSubjectLocator(b0, 0x1000, 0x1000, model.EffectSiteKind.STORE),
    )
    route = _subject_factory(
        model.SemanticSubjectRef, kind=model.SemanticSubjectKind.ROUTE,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, block_ref=b0, anchor_ea=0x1000,
        locator=model.RouteSubjectLocator(authority_id("proof"), authority_id("group"), b0, 0x1000, (b2,), (0x1100,)),
    )
    destination = _role_subject(model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION, "2")
    alias = _claim_factory(
        model.LocalAliasEffectScalarizationClaim,
        kind=model.UnflattenClaimKind.LOCAL_ALIAS_EFFECT_SCALARIZATION,
        owner_subject=owner, step_index=0, host_ea=0x1000, host_opcode=1,
        alias_token="alias", base_token="base", host_text_sha1=None, value_size=None,
        step_digest=authority_id("alias-step"), source_generation=3,
    )
    proposal = model.ProposedUnflattenContract(**values)
    helper = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "0")
    patch_item = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.PATCH_STEP, helper,
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        model.PatchStepEvidencePayload(
            proposal.plan_id, 0, "PatchScalarizeLocalAliasAccess", b0,
            alias.step_digest, 0x1000, 1, None,
        ),
    )
    relation = model.ConditionalSubjectRelation(
        owner.subject_id, store.subject_id, model.SafetyDimension.EFFECT_PRESERVATION,
        authority_id("alias-relation-path"),
    )
    inputs = _complete_inputs(
        source_subjects=(entry, owner, store, route, destination),
        candidate_subjects=(entry, owner, store, route, destination, helper),
            claims=(*proposal.claims, alias), proposal=proposal, patch_step_facts=(patch_item.payload,),
    )
    receipt_values = {
        name: getattr(inputs.preparation_receipt, name)
        for name in inputs.preparation_receipt.__dataclass_fields__
        if name not in {"receipt_id", "_minted"}
    }
    receipt_values["conditional_relation_digest"] = _digest((relation,))
    inputs = replace(
        inputs, conditional_relations=(relation,),
        preparation_receipt=_receipt_fixture(**receipt_values),
    )
    case = build_semantic_case(
        authority_id=authority_id("alias-bad-path"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, inputs=inputs,
    )
    cell = next(
        cell for cell in case.obligation_index.cells
        if cell.key == model.ObligationKey(store, model.SafetyDimension.EFFECT_PRESERVATION)
    )
    assert all(
        next(
            item for item in case.justifications
            if item.justification_id == justification_id
        ).rule is not model.UnflattenJustificationRule.LOCAL_ALIAS_SCALARIZATION_PROVEN
        for justification_id in cell.supporting_justification_ids
    )


def test_route_destination_reachability_correlates_handler_and_terminal_locators() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "route-entry")
    destination = _role_subject(model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION, "2")
    handler = _role_subject(model.SemanticSubjectRole.AUTHORITATIVE_HANDLER, "2")
    terminal = _role_subject(model.SemanticSubjectRole.TERMINAL_SITE, "2")
    case = build_semantic_case(
        authority_id=authority_id("destination-conditionals"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(entry, destination, handler, terminal)),
    )
    dimensions = {
        key.dimension for key in case.required_obligations if key.subject == destination
    }
    assert {
        model.SafetyDimension.HANDLER_REACHABILITY,
        model.SafetyDimension.TERMINAL_REACHABILITY,
    } <= dimensions

    satisfied_case = build_semantic_case(
        authority_id=authority_id("destination-reachability"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(
            source_subjects=(entry, destination, handler, terminal),
        ),
    )
    for subject, dimension in (
        (destination, model.SafetyDimension.HANDLER_REACHABILITY),
        (destination, model.SafetyDimension.TERMINAL_REACHABILITY),
        (handler, model.SafetyDimension.HANDLER_REACHABILITY),
        (terminal, model.SafetyDimension.TERMINAL_REACHABILITY),
    ):
        assert next(
            cell for cell in satisfied_case.obligation_index.cells
            if cell.key == model.ObligationKey(subject, dimension)
        ).state is model.ObligationState.SATISFIED


def test_retirement_claim_requires_one_authorized_lineage_per_member() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "retirement-entry")
    member0 = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "0")
    member1 = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "1")
    corridor_locator = model.CorridorSubjectLocator(
        authority_id("retired-corridor"), member0.block_ref, member0.anchor_ea,
        (member0.block_ref, member1.block_ref),
        (member0.anchor_ea, member1.anchor_ea),
    )
    corridor = _subject_factory(
        model.SemanticSubjectRef, kind=model.SemanticSubjectKind.CORRIDOR,
        role=model.SemanticSubjectRole.DISPATCHER_CORRIDOR,
        block_ref=member0.block_ref, anchor_ea=member0.anchor_ea,
        locator=corridor_locator,
    )
    route = _subject_factory(
        model.SemanticSubjectRef, kind=model.SemanticSubjectKind.ROUTE,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        block_ref=member0.block_ref, anchor_ea=member0.anchor_ea,
        locator=model.RouteSubjectLocator(
            authority_id("proof"), authority_id("group"),
            member0.block_ref, member0.anchor_ea,
            (block_ref("b2"),), (0x1100,),
        ),
    )
    destination = _role_subject(model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION, "2")
    candidate_catalog = _retirement_catalog(model, (member0.block_ref, member1.block_ref), (member0.anchor_ea, member1.anchor_ea), 3)
    retirement = _claim_factory(
        model.RetiredDispatcherInfrastructureClaim,
        kind=model.UnflattenClaimKind.RETIRED_DISPATCHER_INFRASTRUCTURE,
        infrastructure_subject=member0, corridor_subject=corridor,
        member_subjects=(member0, member1),
        candidate_evidence_ids=tuple(sorted({evidence_id for item in candidate_catalog.candidates for evidence_id in item.evidence_ids})),
        source_generation=3,
        candidate_catalog=candidate_catalog,
    )

    proposal_values = _valid_proposal(model)
    proposal_values["plan_inputs"] = replace(
        proposal_values["plan_inputs"],
        shape=model.UnflattenPlanShape.FULL_DISPATCHER_RETIREMENT,
    )
    proposal_base = model.ProposedUnflattenContract(**_valid_proposal(model))
    proposal_values["corridor_coverage_forecast"] = _minimal_corridor_forecast(model, proposal_base)
    route_claim = proposal_values["claims"][0]
    route = route_claim.retired_route_subject
    destination = route_claim.destination_subjects[0]
    retirement_proposal = model.ProposedUnflattenContract(
        **{**proposal_values, "claims": tuple(sorted((retirement, route_claim), key=lambda claim: claim.claim_id),),
           "retirement_candidate_catalog": candidate_catalog}
    )
    complete_inputs = _complete_inputs(
        source_subjects=(
            entry, member0, member1, corridor, route, destination,
        ),
        claims=tuple(sorted((retirement, route_claim), key=lambda claim: claim.claim_id)),
        proposal=retirement_proposal,
    )
    complete = build_semantic_case(
        authority_id=authority_id("retirement-complete"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=complete_inputs,
    )
    assert next(
        cell for cell in complete.obligation_index.cells
        if cell.key == model.ObligationKey(member0, model.SafetyDimension.STRUCTURAL_ACCOUNTING)
    ).state is model.ObligationState.SATISFIED

    phase_result = complete_inputs.retirement_phase_result
    assert phase_result is not None
    retained = next(
        item for item in phase_result.members
        if item.classification is model.RetirementPhaseClassification.RETAINED
    )
    equal_candidate_clone = replace(retained.candidate_binding)
    assert equal_candidate_clone == retained.candidate_binding
    assert equal_candidate_clone is not retained.candidate_binding
    object.__setattr__(retained, "candidate_binding", equal_candidate_clone)
    with pytest.raises(ValueError, match="retirement phase result bindings differ from inventories"):
        model.DerivedUnflattenPreparationInputs.__post_init__(complete_inputs)
    with pytest.raises(ValueError, match="retirement phase result bindings differ from inventories"):
        model.SemanticSafetyCase.__post_init__(complete)

    forged_candidate = replace(
        retained.candidate_binding,
        block_ref=None,
        serial=None,
        anchor_ea=None,
        native_instruction_eas=(),
        status=model.SubjectBindingStatus.MISSING,
    )
    forged_member = object.__new__(model.RetirementPhaseMember)
    for name, value in {
        "block_ref": retained.block_ref,
        "anchor_ea": retained.anchor_ea,
        "classification": model.RetirementPhaseClassification.RETIRED,
        "candidate_id": retained.candidate_id,
        "candidate_reachable": None,
        "reason": "candidate_missing",
        "source_binding": retained.source_binding,
        "candidate_binding": forged_candidate,
    }.items():
        object.__setattr__(forged_member, name, value)
    forged_member.__post_init__()
    forged_members = tuple(
        forged_member if item.block_ref == retained.block_ref else item
        for item in phase_result.members
    )
    forged_result = object.__new__(model.RetirementPhaseResult)
    for name, value in {
        "catalog_id": phase_result.catalog_id,
        "claim_id": phase_result.claim_id,
        "phase": phase_result.phase,
        "source_fingerprint": phase_result.source_fingerprint,
        "candidate_fingerprint": phase_result.candidate_fingerprint,
        "source_generation": phase_result.source_generation,
        "candidate_generation": phase_result.candidate_generation,
        "members": forged_members,
    }.items():
        object.__setattr__(forged_result, name, value)
    object.__setattr__(
        forged_result,
        "result_id",
        canonical_authority_id((
            "unflatten.dispatcher-retirement-phase.v1",
            forged_result.catalog_id,
            forged_result.claim_id,
            forged_result.phase,
            forged_result.source_fingerprint,
            forged_result.candidate_fingerprint,
            forged_result.source_generation,
            forged_result.candidate_generation,
            forged_result.members,
        )),
    )
    forged_result.__post_init__()
    with pytest.raises(ValueError, match="retirement phase result bindings differ from inventories"):
        replace(complete_inputs, retirement_phase_result=forged_result)
    with pytest.raises(ValueError, match="retirement phase result bindings differ from inventories"):
        replace(complete, retirement_phase_result=forged_result)

    unreachable_inputs = _complete_inputs(
        source_subjects=(entry, member0, member1, corridor, route, destination),
        claims=tuple(sorted((retirement, route_claim), key=lambda claim: claim.claim_id)),
        proposal=retirement_proposal,
    )
    retired_binding = next(
        binding for binding in unreachable_inputs.candidate_inventory.bindings
        if binding.subject == member0
    )
    candidate_inventory = unreachable_inputs.candidate_inventory
    object.__setattr__(candidate_inventory, "entry_serial", retired_binding.serial + 1)
    object.__setattr__(
        candidate_inventory,
        "reachable_serials",
        tuple(serial for serial in candidate_inventory.reachable_serials if serial != retired_binding.serial),
    )
    candidate_digest = semantic_graph_inventory_digest(
        candidate_inventory.phase, candidate_inventory.graph_fingerprint,
        candidate_inventory.generation, candidate_inventory.blocks,
        candidate_inventory.subjects, candidate_inventory.bindings,
        candidate_inventory.effects, candidate_inventory.terminals,
        candidate_inventory.topology, candidate_inventory.reachable_serials,
        candidate_inventory.entry_serial, candidate_inventory.source_subject_ids,
        candidate_inventory.function_ea,
    )
    object.__setattr__(candidate_inventory, "inventory_digest", candidate_digest)
    object.__setattr__(
        unreachable_inputs.preparation_receipt,
        "candidate_inventory_digest", candidate_digest,
    )
    object.__setattr__(
        unreachable_inputs.preparation_receipt,
        "projected_topology_reference_digest",
        unreachable_inputs.projected_topology_reference.inventory_digest,
    )
    object.__setattr__(
        unreachable_inputs.preparation_receipt,
        "receipt_id", receipt_id(unreachable_inputs.preparation_receipt),
    )
    from d810.transforms.unflatten_authority.bind import bind_retired_dispatcher_infrastructure_claim
    object.__setattr__(
        unreachable_inputs,
        "retirement_phase_result",
        bind_retired_dispatcher_infrastructure_claim(
            claim=retirement, proposal=retirement_proposal,
            source_inventory=unreachable_inputs.source_inventory,
            projected_inventory=unreachable_inputs.candidate_inventory,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        ).phase_result,
    )
    unreachable = build_semantic_case(
        authority_id=authority_id("retirement-unreachable-physical-row"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=unreachable_inputs,
    )
    assert any(
        type(item.payload) is model.StructuralLineageEvidencePayload
        and item.payload.source_subject_id == member0.subject_id
        and item.payload.disposition is model.StructuralDisposition.AUTHORIZED_RETIREMENT
        for item in unreachable.evidence
    )

    incomplete_inputs = _complete_inputs(
        source_subjects=(entry, member0, member1, corridor, route, destination),
        claims=tuple(sorted((retirement, route_claim), key=lambda claim: claim.claim_id)),
        proposal=retirement_proposal,
    )
    missing_member1 = tuple(
        replace(
            binding, status=model.SubjectBindingStatus.AMBIGUOUS,
            block_ref=None, serial=None, anchor_ea=None,
            native_instruction_eas=(),
            ) if (
                binding.subject == member1
                or binding.subject == corridor
                or binding.subject.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW
            ) else binding
        for binding in incomplete_inputs.candidate_inventory.bindings
    )
    candidate_inventory = incomplete_inputs.candidate_inventory
    object.__setattr__(candidate_inventory, "bindings", tuple(sorted(
        missing_member1, key=lambda binding: binding.subject.subject_id,
    )))
    candidate_digest = semantic_graph_inventory_digest(
        candidate_inventory.phase, candidate_inventory.graph_fingerprint,
        candidate_inventory.generation, candidate_inventory.blocks,
        candidate_inventory.subjects, candidate_inventory.bindings,
        candidate_inventory.effects, candidate_inventory.terminals,
        candidate_inventory.topology, candidate_inventory.reachable_serials,
        candidate_inventory.entry_serial, candidate_inventory.source_subject_ids,
        candidate_inventory.function_ea,
    )
    object.__setattr__(candidate_inventory, "inventory_digest", candidate_digest)
    object.__setattr__(
        incomplete_inputs.preparation_receipt,
        "candidate_binding_digest",
        canonical_authority_id(tuple(sorted(
            missing_member1, key=lambda binding: binding.subject.subject_id,
        ))),
    )
    object.__setattr__(
        incomplete_inputs.preparation_receipt,
        "candidate_inventory_digest", candidate_digest,
    )
    object.__setattr__(
        incomplete_inputs.preparation_receipt,
        "projected_topology_reference_digest",
        incomplete_inputs.projected_topology_reference.inventory_digest,
    )
    object.__setattr__(
        incomplete_inputs.preparation_receipt,
        "receipt_id", receipt_id(incomplete_inputs.preparation_receipt),
    )
    object.__setattr__(
        incomplete_inputs,
        "retirement_phase_result",
        bind_retired_dispatcher_infrastructure_claim(
            claim=retirement, proposal=retirement_proposal,
            source_inventory=incomplete_inputs.source_inventory,
            projected_inventory=incomplete_inputs.candidate_inventory,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        ).phase_result,
    )
    incomplete = build_semantic_case(
        authority_id=authority_id("retirement-incomplete"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=incomplete_inputs,
    )
    member1_structural = next(
        cell for cell in incomplete.obligation_index.cells
        if cell.key == model.ObligationKey(
            member1, model.SafetyDimension.STRUCTURAL_ACCOUNTING,
        )
    )
    assert member1_structural.state is model.ObligationState.VIOLATED
    assert any(
        next(
            item for item in incomplete.justifications
            if item.justification_id == justification_id
        ).rule is model.UnflattenJustificationRule.SOURCE_LOSS_UNACCOUNTED
        for justification_id in member1_structural.refuting_justification_ids
    )
    corridor_coverage = next(
        cell for cell in incomplete.obligation_index.cells
        if cell.key == model.ObligationKey(corridor, model.SafetyDimension.CORRIDOR_COVERAGE)
    )
    assert corridor_coverage.state is model.ObligationState.SATISFIED


def test_retirement_claim_accounts_only_exact_plan_catalog_members() -> None:
    """Retirement authority is structural and only covers exact retired rows."""

    from d810.transforms.unflatten_authority.legacy_codec import retirement_claim_from_legacy_proof
    from d810.transforms.unflatten_authority.bind import bind_retired_dispatcher_infrastructure_claim

    base = model.ProposedUnflattenContract(**_valid_proposal(model))
    refs = {index: item.block_ref for index, item in enumerate(base.source_identity_catalog.blocks)}
    claim = retirement_claim_from_legacy_proof(
        {"retired_infrastructure": (
            {"role": "comparison_dispatcher", "anchor": {"serial": 0, "ea": 0x1000}, "retired": True},
            {"role": "comparison_dispatcher", "anchor": {"serial": 1, "ea": 0x1300}, "retired": False},
        )},
        proposal=base,
        block_refs_by_serial=refs,
    )
    proposal = replace(
        base,
        claims=tuple(sorted((*base.claims, claim), key=lambda item: item.claim_id)),
        plan_inputs=replace(base.plan_inputs, shape=model.UnflattenPlanShape.PARTIAL_REWRITE),
        retirement_candidate_catalog=claim.candidate_catalog,
        corridor_coverage_forecast=_minimal_corridor_forecast(model, base),
    )
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "catalog-entry")
    member0 = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "0")
    member1 = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "1")
    route_claim = base.claims[0]
    inputs = _complete_inputs(
        source_subjects=(entry, member0, member1, route_claim.retired_route_subject, *route_claim.destination_subjects),
        claims=proposal.claims,
        proposal=proposal,
    )
    retired_binding = next(
        item for item in inputs.candidate_inventory.bindings
        if item.subject.block_ref == member0.block_ref
        and item.subject.anchor_ea == member0.anchor_ea
        and item.subject.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE
    )
    candidate_bindings = tuple(
        replace(
            item, status=model.SubjectBindingStatus.MISSING,
            block_ref=None, serial=None, anchor_ea=None,
            native_instruction_eas=(),
        ) if item is retired_binding else item
        for item in inputs.candidate_inventory.bindings
    )
    object.__setattr__(inputs.candidate_inventory, "bindings", candidate_bindings)
    object.__setattr__(inputs.candidate_inventory, "inventory_digest", semantic_graph_inventory_digest(
        inputs.candidate_inventory.phase, inputs.candidate_inventory.graph_fingerprint,
        inputs.candidate_inventory.generation, inputs.candidate_inventory.blocks,
        inputs.candidate_inventory.subjects, candidate_bindings,
        inputs.candidate_inventory.effects, inputs.candidate_inventory.terminals,
        inputs.candidate_inventory.topology, inputs.candidate_inventory.reachable_serials,
        inputs.candidate_inventory.entry_serial, inputs.candidate_inventory.source_subject_ids,
        inputs.candidate_inventory.function_ea,
    ))
    object.__setattr__(inputs.preparation_receipt, "candidate_binding_digest", _digest(tuple(sorted(candidate_bindings, key=lambda item: item.subject.subject_id))))
    object.__setattr__(inputs.preparation_receipt, "candidate_inventory_digest", inputs.candidate_inventory.inventory_digest)
    object.__setattr__(inputs.preparation_receipt, "projected_topology_reference_digest", inputs.projected_topology_reference.inventory_digest)
    object.__setattr__(inputs.preparation_receipt, "receipt_id", receipt_id(inputs.preparation_receipt))
    object.__setattr__(
        inputs,
        "retirement_phase_result",
        bind_retired_dispatcher_infrastructure_claim(
            claim=claim, proposal=proposal,
            source_inventory=inputs.source_inventory,
            projected_inventory=inputs.candidate_inventory,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        ).phase_result,
    )
    case = build_semantic_case(
        authority_id=authority_id("exact-retirement-catalog"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=inputs,
    )
    retired_cell = next(
        cell for cell in case.obligation_index.cells
        if cell.key == model.ObligationKey(member0, model.SafetyDimension.STRUCTURAL_ACCOUNTING)
    )
    retained_cell = next(
        cell for cell in case.obligation_index.cells
        if cell.key == model.ObligationKey(member1, model.SafetyDimension.STRUCTURAL_ACCOUNTING)
    )
    assert retired_cell.state is model.ObligationState.SATISFIED
    assert retained_cell.state is model.ObligationState.SATISFIED
    retired_non_structural = tuple(
        cell for cell in case.obligation_index.cells
        if cell.key.subject == member0
        and cell.key.dimension in {
            model.SafetyDimension.CORRIDOR_COVERAGE,
            model.SafetyDimension.TOPOLOGY_INTEGRITY,
        }
    )
    assert retired_non_structural
    assert not any(
        item.rule is model.UnflattenJustificationRule.RETIRED_INFRASTRUCTURE_PROVEN
        and item.conclusion in {cell.key for cell in retired_non_structural}
        for item in case.justifications
    )
    supporting = tuple(
        item for item in case.justifications
        if item.justification_id in retired_cell.supporting_justification_ids
    )
    assert supporting
    assert all(
        item.conclusion.dimension is model.SafetyDimension.STRUCTURAL_ACCOUNTING
        for item in supporting
    )
    retirement_support = tuple(
        item for item in supporting
        if item.rule is model.UnflattenJustificationRule.RETIRED_INFRASTRUCTURE_PROVEN
    )
    assert len(retirement_support) == 1
    assert retirement_support[0].claim_id == claim.claim_id
    assert retirement_support[0].conclusion == retired_cell.key
    retained_support = tuple(
        item for item in case.justifications
        if item.conclusion == retained_cell.key
        and item.rule is model.UnflattenJustificationRule.SOURCE_PRESERVED
    )
    assert retained_support
    ledger_row = next(
        row for row in views.semantic_loss_ledger(case).rows
        if row.source_subject.subject_id == member0.subject_id
    )
    assert ledger_row.kind is model.SemanticLossKind.UNCLASSIFIED
    retirement_view = views.retired_infrastructure_view(case, claim.claim_id)
    assert retirement_view.claim_id == claim.claim_id
    assert retirement_view.retired_member_subject_ids == (member0.subject_id,)
    assert retirement_view.retained_member_subject_ids == (member1.subject_id,)
    assert retirement_view.structural_cell_keys == (retired_cell.key,)
    with pytest.raises(ValueError):
        views.retirement_rows(case, claim.claim_id)
def test_resegmentation_patch_step_supports_only_its_helper_structural_key() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "resegment-entry")
    helper = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "0")
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    payload = model.PatchStepEvidencePayload(
        proposal.plan_id, 0, "PatchInsertBlock", helper.block_ref,
        authority_id("resegment-step"), helper.anchor_ea, 0x90, 4,
    )
    evidence = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.PATCH_STEP,
        helper, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, payload,
    )
    case = build_semantic_case(
        authority_id=authority_id("resegment-case"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(
            source_subjects=(entry,), candidate_subjects=(entry, helper),
            patch_step_facts=(evidence.payload,), proposal=proposal,
        ),
    )
    helper_cell = next(
        cell for cell in case.obligation_index.cells
        if cell.key == model.ObligationKey(helper, model.SafetyDimension.STRUCTURAL_ACCOUNTING)
    )
    assert helper_cell.state is model.ObligationState.SATISFIED
    for item in case.obligation_index.cells:
        if item.key.subject == helper and item.key.dimension is not model.SafetyDimension.STRUCTURAL_ACCOUNTING:
            assert all(
                next(j for j in case.justifications if j.justification_id == jid).rule
                is not model.UnflattenJustificationRule.RESEGMENTATION_LINEAGE_PROVEN
                for jid in item.supporting_justification_ids
            )


def test_effect_classifier_requires_exact_candidate_site_and_external_gate_facts() -> None:
    subject = _role_subject(model.SemanticSubjectRole.EFFECT_SITE, "classifier-site")
    source_binding = _binding(subject, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT)
    candidate_binding = _binding(subject, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT)
    effect = model.InventoryEffectSite(
        0, subject.block_ref, subject.anchor_ea or 0, 0,
        subject.locator.instruction_ea, subject.locator.effect_kind, 0x90, 4,
    )
    present = _classify_effect_site(
        effect, subject, source_binding, candidate_binding, effect, None, None, None,
    )
    assert present.preserved
    assert not present.authorized_loss
    missing = _classify_effect_site(
        effect, subject, source_binding, candidate_binding, None, None, None, None,
    )
    assert missing.refuted
    assert not missing.authorized_loss
    for candidate_kind in (
        model.EffectSiteKind.CALL, model.EffectSiteKind.STORE,
    ):
        if candidate_kind is effect.effect_kind:
            continue
        kind_drift = _classify_effect_site(
            effect, subject, source_binding, candidate_binding,
            (replace(effect, effect_kind=candidate_kind),), None, None, None,
        )
        assert kind_drift.refuted
        assert not kind_drift.authorized_loss
    duplicate = _classify_effect_site(
        effect, subject, source_binding, candidate_binding,
        (effect, effect), None, None, None,
    )
    assert duplicate.refuted
    wrong_owner_serial = _classify_effect_site(
        effect, subject, source_binding, candidate_binding,
        (replace(effect, owner_serial=1),), None, None, None,
    )
    assert wrong_owner_serial.refuted


@pytest.mark.parametrize(
    ("source_kind", "candidate_kind"),
    (
        (model.EffectSiteKind.CALL, model.EffectSiteKind.STORE),
        (model.EffectSiteKind.STORE, model.EffectSiteKind.CALL),
    ),
)
def test_effect_classifier_coordinate_kind_drift_is_refuted(
    source_kind: model.EffectSiteKind,
    candidate_kind: model.EffectSiteKind,
) -> None:
    locator = model.EffectSubjectLocator(
        block_ref("b0"), 0x1000, 0x1004, source_kind,
    )
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.EFFECT,
        role=model.SemanticSubjectRole.EFFECT_SITE,
        block_ref=locator.owner_ref, anchor_ea=locator.owner_anchor_ea,
        locator=locator,
    )
    effect = model.InventoryEffectSite(
        0, locator.owner_ref, locator.owner_anchor_ea, 0,
        locator.instruction_ea, source_kind, 0x90, 4,
    )
    candidate = replace(effect, effect_kind=candidate_kind)
    result = _classify_effect_site(
        effect, subject,
        _binding(subject, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT),
        _binding(subject, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT),
        (candidate,), None, None, None,
    )
    assert result.refuted
    assert not result.preserved
    assert not result.authorized_loss


@pytest.mark.parametrize(
    ("source_kind", "candidate_kind"),
    (
        (model.EffectSiteKind.CALL, model.EffectSiteKind.STORE),
        (model.EffectSiteKind.STORE, model.EffectSiteKind.CALL),
    ),
)
def test_inventory_case_effect_kind_drift_has_no_foreign_topology(
    source_kind: model.EffectSiteKind,
    candidate_kind: model.EffectSiteKind,
) -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "0")
    source_locator = model.EffectSubjectLocator(
        block_ref("b0"), 0x1000, 0x1004, source_kind,
    )
    source_effect = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.EFFECT,
        role=model.SemanticSubjectRole.EFFECT_SITE,
        block_ref=source_locator.owner_ref,
        anchor_ea=source_locator.owner_anchor_ea,
        locator=source_locator,
    )
    candidate_locator = replace(source_locator, effect_kind=candidate_kind)
    candidate_effect = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.EFFECT,
        role=model.SemanticSubjectRole.EFFECT_SITE,
        block_ref=candidate_locator.owner_ref,
        anchor_ea=candidate_locator.owner_anchor_ea,
        locator=candidate_locator,
    )
    candidate_subjects = [candidate_effect]
    if candidate_kind is model.EffectSiteKind.CALL:
        terminal_locator = model.TerminalSubjectLocator(
            block_ref("b0"), 0x1000, model.TerminalKind.NORETURN_CALL, 0x1004,
        )
        candidate_subjects.append(_subject_factory(
            model.SemanticSubjectRef,
            kind=model.SemanticSubjectKind.TERMINAL,
            role=model.SemanticSubjectRole.TERMINAL_SITE,
            block_ref=terminal_locator.block_ref,
            anchor_ea=terminal_locator.anchor_ea,
            locator=terminal_locator,
        ))
    case = build_semantic_case(
        authority_id=authority_id(f"inventory-effect-drift-{source_kind.value}"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(
            source_subjects=(entry, source_effect),
            candidate_subjects=tuple(candidate_subjects),
        ),
    )
    assert case.evidence
    effect_cell = next(
        cell for cell in case.obligation_index.cells
        if cell.key == model.ObligationKey(
            source_effect, model.SafetyDimension.EFFECT_PRESERVATION,
        )
    )
    assert effect_cell.state in {
        model.ObligationState.VIOLATED,
        model.ObligationState.INCONSISTENT,
    }
    assert any(
        next(
            item for item in case.justifications
            if item.justification_id == justification_id
        ).rule is model.UnflattenJustificationRule.EFFECT_LOST_UNACCOUNTED
        for justification_id in effect_cell.refuting_justification_ids
    )
    assert candidate_effect.subject_id not in {
        subject.subject_id for subject in case.subjects
    }
    assert not any(
        item.subject.subject_id == candidate_effect.subject_id
        and type(item.payload) is model.TopologyEvidencePayload
        for item in case.evidence
    )
    assert not any(
        cell.key.subject.subject_id == candidate_effect.subject_id
        and cell.key.dimension is model.SafetyDimension.TOPOLOGY_INTEGRITY
        for cell in case.obligation_index.cells
    )


def test_effect_classifier_authorizes_only_exact_missing_site_with_sealed_inputs() -> None:
    subject = _role_subject(model.SemanticSubjectRole.EFFECT_SITE, "classifier-positive")
    source_binding = _binding(subject, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT)
    missing_binding = _binding(
        subject, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        status=model.SubjectBindingStatus.MISSING,
    )
    effect = model.InventoryEffectSite(
        0, subject.block_ref, subject.anchor_ea or 0, 0,
        subject.locator.instruction_ea, subject.locator.effect_kind, 0x90, 1,
    )
    claim = SimpleNamespace(
        discarded_effect_subject=subject,
        discarded_effect_ea=effect.instruction_ea,
        width=effect.width,
        route_proof_ids=("proof",),
    )
    facts = gates.GenericCfgGateFacts(
        gates.GenericEntryGateFacts(True, 1, 1, 1.0, 0, 0.0, "ok"),
        gates.GenericEffectfulGateFacts(True, frozenset({0}), frozenset({0}), frozenset(), "raw"),
        gates.GenericEffectfulGateFacts(True, frozenset({0}), frozenset({0}), frozenset(), "effective"),
        gates.GenericTerminalGateFacts(True, frozenset({0}), frozenset({0}), 1, 1, "ok"),
    )
    route = SimpleNamespace(accepted=True, proof_ids=("proof",))
    authorized = _classify_effect_site(
        effect, subject, source_binding, missing_binding, None,
        claim, route, facts,
    )
    assert authorized.authorized_loss
    assert not authorized.refuted
    present = _classify_effect_site(
        effect, subject, source_binding, source_binding, effect,
        claim, route, facts,
    )
    assert present.preserved
    assert present.claim is None
    wrong_width = _classify_effect_site(
        effect, subject, source_binding, missing_binding, None,
        SimpleNamespace(
            discarded_effect_subject=subject,
            discarded_effect_ea=effect.instruction_ea,
            width=2,
            route_proof_ids=("proof",),
        ), route, facts,
    )
    assert wrong_width.refuted
    assert not wrong_width.authorized_loss
    mismatched_site = _classify_effect_site(
        effect, subject, source_binding, source_binding,
        replace(effect, opcode=0x91), claim, route, facts,
    )
    assert mismatched_site.refuted
    assert not mismatched_site.authorized_loss
    effective_lost = replace(
        facts,
        effectful_raw=replace(
            facts.effectful_raw,
            passed=False,
            post_reachable_effectful_block_serials=frozenset(),
            lost_block_serials=frozenset({0}),
        ),
        effectful_effective=replace(
            facts.effectful_effective,
            passed=False,
            post_reachable_effectful_block_serials=frozenset(),
            lost_block_serials=frozenset({0}),
        ),
    )
    loss_with_failed_raw_and_effective_gates = _classify_effect_site(
        effect, subject, source_binding, missing_binding, None,
        claim, route, effective_lost,
    )
    assert loss_with_failed_raw_and_effective_gates.authorized_loss
    assert not loss_with_failed_raw_and_effective_gates.refuted


def test_same_owner_missing_claim_does_not_authorize_unclaimed_sibling() -> None:
    first = _role_subject(model.SemanticSubjectRole.EFFECT_SITE, "same-owner-first")
    second = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.EFFECT,
        role=model.SemanticSubjectRole.EFFECT_SITE,
        block_ref=first.block_ref,
        anchor_ea=first.anchor_ea,
        locator=replace(
            first.locator, instruction_ea=first.locator.instruction_ea + 4,
        ),
    )
    source_binding = _binding(first, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT)
    missing_binding = _binding(
        first, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        status=model.SubjectBindingStatus.MISSING,
    )
    first_effect = model.InventoryEffectSite(
        0, first.block_ref, first.anchor_ea or 0, 0,
        first.locator.instruction_ea, first.locator.effect_kind, 0x90, 1,
    )
    sibling_effect = replace(first_effect, instruction_ea=second.locator.instruction_ea)
    claim = SimpleNamespace(
        discarded_effect_subject=first,
        discarded_effect_ea=first_effect.instruction_ea,
        width=first_effect.width,
        route_proof_ids=("proof",),
    )
    facts = gates.GenericCfgGateFacts(
        gates.GenericEntryGateFacts(True, 1, 1, 1.0, 0, 0.0, "ok"),
        gates.GenericEffectfulGateFacts(True, frozenset({0}), frozenset({0}), frozenset(), "raw"),
        gates.GenericEffectfulGateFacts(True, frozenset({0}), frozenset({0}), frozenset(), "effective"),
        gates.GenericTerminalGateFacts(True, frozenset({0}), frozenset({0}), 1, 1, "ok"),
    )
    route = SimpleNamespace(accepted=True, proof_ids=("proof",))
    claimed = _classify_effect_site(
        first_effect, first, source_binding, missing_binding, None,
        claim, route, facts,
    )
    sibling = _classify_effect_site(
        sibling_effect, second, source_binding, source_binding, sibling_effect,
        None, route, facts,
    )
    assert claimed.authorized_loss
    assert sibling.preserved
    unclaimed_missing = _classify_effect_site(
        sibling_effect, second, source_binding, missing_binding, None,
        None, route, facts,
    )
    assert unclaimed_missing.refuted
    assert not unclaimed_missing.authorized_loss


def test_exact_infeasible_effect_authorizes_classified_discarded_loss() -> None:
    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture
    from d810.analyses.control_flow.graph_checks import (
        check_effectful_reachability_preserved,
        check_entry_reachability_not_collapsed,
        check_terminal_reachability_preserved,
    )
    from d810.transforms.cfg_transaction import CfgProjection
    from d810.transforms.plan import PatchPlan, PatchRedirectGoto
    from d810.transforms.unflatten_authority import transaction_api
    from d810.transforms.unflatten_authority.gates import GenericCfgGateBundle
    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest
    from d810.ir.flowgraph import InsnKind

    source_graph, proposal, _exclusion, refs = exact_fixture()
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("exact-effect-snapshot"),
        source_generation=1,
        steps=(
            PatchRedirectGoto(refs[0], refs[1], refs[2]),
            PatchRedirectGoto(refs[1], refs[2], refs[0]),
        ),
        source_coordinates=tuple((ref, serial) for serial, ref in refs.items()),
        unflatten_proposal=proposal,
    )
    manifest = canonical_redirect_manifest(plan)
    proposal = replace(
        proposal,
        use_def_witness=replace(
            proposal.use_def_witness,
            redirect_owner_refs=manifest.owner_refs,
            redirect_digest=manifest.digest,
        ),
    )
    plan = replace(plan, unflatten_proposal=proposal)
    effect_block = source_graph.blocks[3]
    non_effect_instruction = replace(
        effect_block.insn_snapshots[0], kind=InsnKind.NOP, is_call=False,
    )
    projected_blocks = dict(source_graph.blocks)
    projected_blocks[3] = replace(
        effect_block, insn_snapshots=(non_effect_instruction,),
    )
    projected_graph = replace(source_graph, blocks=projected_blocks)
    # The candidate adapter keeps the native EA row while removing the CALL
    # observation.  Gate facts are the receipt-owned preflight facts; the
    # semantic inventory still proves the missing effect site exactly.
    generic_gates = GenericCfgGateBundle(
        check_entry_reachability_not_collapsed(source_graph, post_cfg=projected_graph),
        check_effectful_reachability_preserved(source_graph, post_cfg=source_graph),
        check_effectful_reachability_preserved(source_graph, post_cfg=source_graph),
        check_terminal_reachability_preserved(source_graph, post_cfg=projected_graph),
    )
    inputs = transaction_api.derive_unflatten_preparation_inputs(
        source_graph,
        CfgProjection(plan.plan_id, plan.snapshot_id, projected_graph),
        plan,
        proposal,
        generic_gates,
    )
    case = build_semantic_case(
        authority_id=authority_id("exact-effect-loss"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=inputs,
    )
    claim = next(
        claim for claim in case.claims
        if type(claim) is model.ExactInfeasibleEffectClaim
    )
    discarded = claim.discarded_effect_subject
    loss_rows = views.semantic_loss_ledger(case).rows
    discarded_rows = tuple(
        row for row in loss_rows
        if row.source_subject.subject_id == discarded.subject_id
    )
    assert len(discarded_rows) == 1
    assert discarded_rows[0].kind is model.SemanticLossKind.EXACT_INFEASIBLE_EFFECT
    assert discarded_rows[0].anchored_location == "blk3@0x4000"
    assert discarded_rows[0].evidence_ids
    assert discarded_rows[0].supporting_justification_ids
    assert discarded_rows[0].claim_ids == (claim.claim_id,)
    ledger = views.semantic_loss_ledger(case)
    assert ledger.allowed == discarded_rows
    assert len(ledger.unclassified) == 1
    assert ledger.unclassified[0].source_subject.role is model.SemanticSubjectRole.TERMINAL_SITE
    assert ledger.unclassified[0].claim_ids == ()
    assert ledger.unclassified[0].anchored_location == "blk3@0x4000"
    assert canonical_decode(canonical_bytes(case)) == case
    assert canonical_decode(canonical_bytes(ledger)) == ledger
    from d810.transforms.unflatten_authority.diagnostics import build_phase_payload
    payload = build_phase_payload(evaluate_case(case))
    payload_row = next(
        row for row in payload["loss_ledger"]
        if row["anchor"] == "blk3@0x4000"
        and row["classification"] == model.SemanticLossKind.EXACT_INFEASIBLE_EFFECT.value
    )
    assert payload["source_fingerprint"] == case.source_fingerprint
    assert payload_row["classification"] == model.SemanticLossKind.EXACT_INFEASIBLE_EFFECT.value
    assert payload_row["anchor"] == "blk3@0x4000"
    assert payload_row["claim_ids"] == (claim.claim_id,)
    assert payload_row["evidence_ids"] == discarded_rows[0].evidence_ids
    effect_rows = tuple(
        item for item in case.evidence
        if item.kind is model.AuthorityEvidenceKind.EFFECT_SITE
        and item.subject.subject_id == discarded.subject_id
    )
    assert len(effect_rows) == 1
    assert evaluate_case(case).reason is not model.UnflattenAuthorityReason.ACCEPTED


def test_terminal_cycle_claim_cannot_discharge_effect_or_handler_cells() -> None:
    """A terminal cycle break is structural/terminal authority only."""

    from .test_bind import _terminal_cycle_derived_inputs
    from d810.transforms.unflatten_authority.gates import (
        GenericCfgGateFacts,
        GenericEffectfulGateFacts,
        GenericEntryGateFacts,
        GenericTerminalGateFacts,
    )

    proposal, claim, inputs, source, _candidate, _residual = (
        _terminal_cycle_derived_inputs()
    )
    failed_terminal_facts = GenericCfgGateFacts(
        GenericEntryGateFacts(True, 1, 1, 1.0, 0, 0.0, "entry-ok"),
        GenericEffectfulGateFacts(
            True, frozenset({0}), frozenset({0}), frozenset(), "effect-ok",
        ),
        GenericEffectfulGateFacts(
            True, frozenset({0}), frozenset({0}), frozenset(), "effect-ok",
        ),
        GenericTerminalGateFacts(
            False, frozenset({4}), frozenset(), 1, 0, "terminal-lost",
        ),
    )
    from copy import copy
    reminted_receipt = copy(inputs.preparation_receipt)
    object.__setattr__(
        reminted_receipt, "generic_gate_facts_digest",
        _receipt_digest(failed_terminal_facts),
    )
    object.__setattr__(reminted_receipt, "receipt_id", receipt_id(reminted_receipt))
    inputs = replace(
        inputs,
        generic_gate_facts=failed_terminal_facts,
        preparation_receipt=reminted_receipt,
    )
    cycle = claim.cycle_subject
    cleanup = claim.cleanup_source_subject
    terminal = claim.terminal_subject
    terminal_effect = next(
        subject for subject in source.subjects
        if subject.role is model.SemanticSubjectRole.EFFECT_SITE
        and subject.block_ref.proxy_token == "b2"
    )
    handler = next(
        subject for subject in source.subjects
        if subject.role is model.SemanticSubjectRole.AUTHORITATIVE_HANDLER
        and subject.block_ref.proxy_token == "b2"
    )
    assert len(inputs.terminal_cycle_phase_results) == 1
    case = build_semantic_case(
        authority_id=authority_id("terminal-cycle-scope"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=inputs,
    )
    by_key = {cell.key: cell for cell in case.obligation_index.cells}

    cycle_cell = by_key[
        model.ObligationKey(cycle, model.SafetyDimension.STRUCTURAL_ACCOUNTING)
    ]
    assert cycle_cell.state is model.ObligationState.SATISFIED
    assert any(
        item.claim_id == claim.claim_id
        for item in case.justifications
        if item.conclusion == cycle_cell.key
    )
    cleanup_cell = by_key[
        model.ObligationKey(cleanup, model.SafetyDimension.STRUCTURAL_ACCOUNTING)
    ]
    assert cleanup_cell.state is model.ObligationState.SATISFIED
    assert not any(
        item.claim_id == claim.claim_id
        for item in case.justifications
        if item.conclusion == cleanup_cell.key
    )
    terminal_cell = by_key[
        model.ObligationKey(terminal, model.SafetyDimension.TERMINAL_REACHABILITY)
    ]
    assert terminal_cell.state is model.ObligationState.SATISFIED
    assert any(
        item.claim_id == claim.claim_id
        for item in case.justifications
        if item.conclusion == terminal_cell.key
    )
    assert any(
        item.claim_id == claim.claim_id
        and item.rule is model.UnflattenJustificationRule.TERMINAL_CYCLE_BREAK_PROVEN
        for item in case.justifications
        if item.conclusion == terminal_cell.key
    )
    assert any(
        item.payload.gate is model.GenericCfgGateKind.TERMINAL_REACHABILITY
        and not item.payload.passed
        for item in case.evidence
        if type(item.payload) is model.GenericCfgGateEvidencePayload
    )
    assert not any(
        item.conclusion == terminal_cell.key
        and item.rule is model.UnflattenJustificationRule.GENERIC_CFG_GATE_FAILED
        for item in case.justifications
    )
    terminal_effect_cell = by_key[
        model.ObligationKey(terminal_effect, model.SafetyDimension.EFFECT_PRESERVATION)
    ]
    assert terminal_effect_cell.state is model.ObligationState.SATISFIED
    assert not any(
        item.claim_id == claim.claim_id
        for item in case.justifications
        if item.conclusion == terminal_effect_cell.key
    )
    handler_cell = by_key[
        model.ObligationKey(handler, model.SafetyDimension.HANDLER_REACHABILITY)
    ]
    assert not any(
        item.claim_id == claim.claim_id
        for item in case.justifications
        if item.conclusion == handler_cell.key
    )

    with pytest.raises(
        ValueError,
        match="exactly one terminal-cycle phase result per claim",
    ):
        replace(inputs, terminal_cycle_phase_results=())


def test_terminal_cycle_evidence_must_match_case_owned_phase_result() -> None:
    """A reminted terminal payload cannot replace the transaction result."""

    from d810.transforms.unflatten_authority.evaluate import _build_obligation_index
    from .test_bind import _terminal_cycle_derived_inputs

    _proposal, claim, inputs, _source, _candidate, _residual = (
        _terminal_cycle_derived_inputs()
    )
    case = build_semantic_case(
        authority_id=authority_id("terminal-cycle-evidence-binding"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=inputs,
    )
    terminal_evidence = next(
        item for item in case.evidence
        if item.kind is model.AuthorityEvidenceKind.TERMINAL_CYCLE
    )
    payload_fields = {
        name: getattr(terminal_evidence.payload, name)
        for name in terminal_evidence.payload.__dataclass_fields__
        if name != "phase_result_id"
    }
    payload_fields["terminal_source_ref"] = block_ref("b0")
    forged_phase_result_id = canonical_authority_id((
        "unflatten.terminal-cycle-phase.v1",
        payload_fields["claim_id"], payload_fields["terminal_route_proof_id"],
        payload_fields["phase"], payload_fields["source_fingerprint"],
        payload_fields["candidate_fingerprint"], payload_fields["source_generation"],
        payload_fields["candidate_generation"], payload_fields["bound_subject_ids"],
        payload_fields["source_binding_digest"], payload_fields["candidate_binding_digest"],
        payload_fields["residue_refs"], payload_fields["source_cycle_edges"],
        payload_fields["candidate_cycle_edges"], payload_fields["terminal_source_ref"],
        payload_fields["cleanup_source_ref"], payload_fields["terminal_carrier_ref"],
        payload_fields["terminal_route_refs"], payload_fields["terminal_subject_id"],
        payload_fields["terminal_subject_ref"],
    ))
    forged_payload = model.TerminalCycleEvidencePayload(
        phase_result_id=forged_phase_result_id,
        **payload_fields,
    )
    forged_evidence = _evidence_factory(
        model.AuthorityEvidence,
        model.AuthorityEvidenceKind.TERMINAL_CYCLE,
        terminal_evidence.subject,
        case.phase,
        forged_payload,
    )
    terminal_justification = next(
        item for item in case.justifications
        if item.claim_id == claim.claim_id
        and item.rule is model.UnflattenJustificationRule.TERMINAL_CYCLE_BREAK_PROVEN
    )
    justification_values = {
        name: getattr(terminal_justification, name)
        for name in terminal_justification.__dataclass_fields__
        if name != "justification_id"
    }
    justification_values["premise_ids"] = (forged_evidence.evidence_id,)
    forged_justification = _justification_factory(
        model.AuthorityJustification, **justification_values,
    )
    evidence = tuple(sorted(
        (
            forged_evidence
            if item.evidence_id == terminal_evidence.evidence_id
            else item
            for item in case.evidence
        ),
        key=lambda item: item.evidence_id,
    ))
    justifications = tuple(sorted(
        (
            forged_justification
            if item.justification_id == terminal_justification.justification_id
            else item
            for item in case.justifications
        ),
        key=lambda item: item.justification_id,
    ))
    case_values = {
        name: getattr(case, name)
        for name in case.__dataclass_fields__
        if name != "case_id"
    }
    case_values["evidence"] = evidence
    case_values["justifications"] = justifications
    case_values["obligation_index"] = _build_obligation_index(
        case.required_obligations, justifications, case.phase,
    )
    with pytest.raises(ValueError, match="terminal-cycle evidence"):
        _case_factory(model.SemanticSafetyCase, **case_values)


def test_terminal_cycle_result_replays_exact_inventory_topology_and_path() -> None:
    """Copied coordinates cannot authorize a different candidate graph."""

    from d810.transforms.unflatten_authority import transaction_api
    from .test_bind import _terminal_cycle_derived_inputs

    proposal, _claim, inputs, source, _candidate, residual = (
        _terminal_cycle_derived_inputs()
    )
    receipt = transaction_api._receipt(
        proposal,
        inputs.preparation_metrics,
        source_inventory=source,
        candidate_inventory=residual,
        generic_gate_facts=inputs.generic_gate_facts,
        route_assessments=tuple(
            item for item in (
                inputs.source_route_assessment,
                inputs.candidate_route_assessment,
            )
            if item is not None
        ),
        conditional_relations=inputs.conditional_relations,
        patch_step_facts=inputs.patch_step_facts,
    )
    with pytest.raises(ValueError, match="projected phase must reference|residue topology"):
        replace(
            inputs,
            candidate_inventory=residual,
            preparation_receipt=receipt,
        )

    result = inputs.terminal_cycle_phase_results[0]
    false_route = (
        result.terminal_carrier_ref,
        result.terminal_source_ref,
        result.terminal_subject_ref,
    )
    fields = {
        name: getattr(result, name)
        for name in result.__dataclass_fields__
        if name != "result_id"
    }
    fields["terminal_route_refs"] = false_route
    reminted_id = canonical_authority_id((
        "unflatten.terminal-cycle-phase.v1", fields["claim_id"],
        fields["terminal_route_proof_id"], fields["phase"],
        fields["source_fingerprint"], fields["candidate_fingerprint"],
        fields["source_generation"], fields["candidate_generation"],
        fields["bound_subject_ids"], fields["source_binding_digest"],
        fields["candidate_binding_digest"], fields["residue_refs"],
        fields["source_cycle_edges"], fields["candidate_cycle_edges"],
        fields["terminal_source_ref"], fields["cleanup_source_ref"],
        fields["terminal_carrier_ref"], fields["terminal_route_refs"],
        fields["terminal_subject_id"], fields["terminal_subject_ref"],
    ))
    false_result = model.TerminalCyclePhaseResult(
        result_id=reminted_id, **fields,
    )
    with pytest.raises(ValueError, match="terminal path"):
        replace(inputs, terminal_cycle_phase_results=(false_result,))
