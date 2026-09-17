"""Task 4 evaluator contract tests."""

from __future__ import annotations

import inspect
import json
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from d810.analyses.control_flow.semantic_route_evidence import BoundCanonicalSemanticEvidence
from d810.analyses.control_flow.semantic_route_evidence import BoundSemanticBlock
from d810.analyses.control_flow.semantic_route_evidence import BoundSemanticRoute
from d810.analyses.control_flow.semantic_route_evidence import BoundSemanticRouteDestination
from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalRouteAssessmentPhase, CanonicalRouteMaterialization,
    SemanticRouteDestination, SemanticRouteProof, SemanticRouteProofKind,
    SemanticRouteShape, SemanticStateWriteDeliveryKind,
    SemanticStateWriteProof, assess_canonical_route,
)
from d810.ir.maturity import MaturityEnvelope
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority import gates
from d810.transforms.unflatten_authority import views
from d810.transforms.unflatten_authority import evaluate as evaluator
from d810.transforms.unflatten_authority.evaluate import _classify_effect_site
from d810.transforms.unflatten_authority.evaluate import _canonical_dispatcher_corridor_subject
from d810.transforms.unflatten_authority.evaluate import _accepted_detached_component_results
from d810.transforms.unflatten_authority.evaluate import _dimensions
from d810.transforms.unflatten_authority.evaluate import _receipt_digest
from d810.transforms.unflatten_authority.evaluate import build_semantic_case
from d810.transforms.unflatten_authority.evaluate import build_semantic_loss_ledger
from d810.transforms.unflatten_authority.evaluate import derive_corridor_coverage_evidence
from d810.transforms.unflatten_authority.evaluate import evaluate_case
from d810.transforms.unflatten_authority.evaluate import REQUIRED_DIMENSIONS
from d810.transforms.patch_binding import BoundPatchPlan, iter_refs
from d810.transforms.cfg_transaction import LogicalBlockRef, NativeBlockRef, PlanBlockRef
from d810.transforms.plan import PatchPlan
from d810.transforms.unflatten_authority.ids import _case_factory, _claim_factory, _evidence_factory, _justification_factory, _subject_factory, authority_id as canonical_authority_id, bound_unflatten_binding_id, canonical_bytes, canonical_decode, content_id, receipt_id, semantic_graph_inventory_digest
from .helpers import (
    authority_id,
    block_ref,
    observed_patch_binding_for_test,
    state_identity,
)
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


def test_equivalent_route_requires_bound_source_authority_and_realization() -> None:
    """The real Direct preparation seals the source authority to its realization."""

    from .test_transaction_api import _c1_direct_preparation_case
    from d810.transforms.cfg_transaction import CfgProjection
    from d810.transforms.unflatten_authority import transaction_api

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    result = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    )
    assert result.prepared is not None
    inputs = result.prepared.source_inputs
    assert inputs.source_route_authority is result.prepared.source_route_authority
    assert inputs.projected_route_realization is result.prepared.projected_route_realization
    assert inputs.projected_route_realization.source_authority is inputs.source_route_authority


def test_projected_entry_obligation_uses_typed_entry_reachability_not_raw_loss_ratio() -> None:
    """Retired dispatcher rows cannot refute a still-reachable physical entry."""
    from d810.analyses.control_flow.graph_checks import EntryReachabilityResult
    from d810.transforms.cfg_transaction import CfgProjection
    from d810.transforms.unflatten_authority import transaction_api
    from d810.transforms.unflatten_authority.gates import GenericCfgGateBundle
    from .test_transaction_api import _c1_direct_preparation_case

    fixture, source, plan, projected, generic_gates = _c1_direct_preparation_case()
    collapsed_global_count = EntryReachabilityResult(
        False, 20, 9, 0.45, 20, 0.5, "entry reachability collapsed",
    )
    gates = GenericCfgGateBundle(
        collapsed_global_count,
        generic_gates.effectful_raw,
        generic_gates.effectful_effective,
        generic_gates.terminal,
    )

    result = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    )

    assert type(result) is model.UnflattenAuthorityPreparationAccepted
    entry = next(
        cell for cell in result.prepared.projected_case.obligation_index.cells
        if cell.key.subject.role is model.SemanticSubjectRole.SOURCE_ENTRY
        and cell.key.dimension is model.SafetyDimension.ENTRY_REACHABILITY
    )
    assert entry.state is model.ObligationState.SATISFIED
    assert any(
        justification.rule is model.UnflattenJustificationRule.SUBJECT_REACHABLE
        and justification.conclusion == entry.key
        for justification in result.prepared.projected_case.justifications
    )
    raw_entry = next(
        evidence.payload for evidence in result.prepared.projected_case.evidence
        if type(evidence.payload) is model.GenericCfgGateEvidencePayload
        and evidence.payload.gate is model.GenericCfgGateKind.ENTRY_REACHABILITY
    )
    assert raw_entry.passed is False
    assert raw_entry.reason_code == "entry reachability collapsed"
    assert not any(
        justification.conclusion == entry.key
        and justification.rule in {
            model.UnflattenJustificationRule.GENERIC_CFG_GATE_PASSED,
            model.UnflattenJustificationRule.GENERIC_CFG_GATE_FAILED,
        }
        for justification in result.prepared.projected_case.justifications
    )


def _with_entry_gate_facts(
    inputs: model.DerivedUnflattenPreparationInputs,
    *,
    passed: bool,
    reason: str,
) -> model.DerivedUnflattenPreparationInputs:
    """Attach one exact diagnostic entry row and reseal the test receipt."""
    from copy import copy
    from d810.transforms.unflatten_authority.gates import (
        GenericCfgGateFacts,
        GenericEffectfulGateFacts,
        GenericEntryGateFacts,
        GenericTerminalGateFacts,
    )

    facts = GenericCfgGateFacts(
        GenericEntryGateFacts(
            passed,
            20,
            9 if not passed else 20,
            0.45 if not passed else 1.0,
            20,
            0.5,
            reason,
        ),
        GenericEffectfulGateFacts(
            True, frozenset(), frozenset(), frozenset(), "effect-ok",
        ),
        GenericEffectfulGateFacts(
            True, frozenset(), frozenset(), frozenset(), "effect-ok",
        ),
        GenericTerminalGateFacts(
            True, frozenset(), frozenset(), 0, 0, "terminal-ok",
        ),
    )
    receipt = copy(inputs.preparation_receipt)
    object.__setattr__(
        receipt,
        "generic_gate_facts_digest",
        _receipt_digest(facts),
    )
    object.__setattr__(receipt, "receipt_id", receipt_id(receipt))
    return replace(
        inputs,
        generic_gate_facts=facts,
        preparation_receipt=receipt,
    )


@pytest.mark.parametrize(
    "phase",
    (
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
    ),
)
def test_blank_successful_entry_gate_uses_neutral_diagnostic_reason(
    phase: model.UnflattenAuthorityPhase,
) -> None:
    """A native success without prose receives only the neutral reason code."""
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, f"blank-success-{phase.value}")
    catalog = tuple(
        _role_subject(model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK, str(index))
        for index in range(3)
    )
    inputs = _with_entry_gate_facts(
        _complete_inputs(source_subjects=(entry, *catalog), phase=phase),
        passed=True,
        reason="",
    )

    case = build_semantic_case(
        authority_id=authority_id(f"blank-success-entry-{phase.value}"),
        phase=phase,
        inputs=inputs,
    )
    raw_entry = next(
        evidence.payload for evidence in case.evidence
        if type(evidence.payload) is model.GenericCfgGateEvidencePayload
        and evidence.payload.gate is model.GenericCfgGateKind.ENTRY_REACHABILITY
    )

    assert raw_entry.passed is True
    assert raw_entry.reason_code == "entry_reachability"


@pytest.mark.parametrize(
    "phase",
    (
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
    ),
)
def test_blank_failed_entry_gate_is_rejected_without_neutral_relabeling(
    phase: model.UnflattenAuthorityPhase,
) -> None:
    """A failed native row must explain itself before entering authority evidence."""
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, f"blank-failure-{phase.value}")
    catalog = tuple(
        _role_subject(model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK, str(index))
        for index in range(3)
    )
    inputs = _with_entry_gate_facts(
        _complete_inputs(source_subjects=(entry, *catalog), phase=phase),
        passed=False,
        reason="",
    )

    with pytest.raises(
        ValueError,
        match="failed entry gate requires a nonblank reason",
    ):
        build_semantic_case(
            authority_id=authority_id(f"blank-failure-entry-{phase.value}"),
            phase=phase,
            inputs=inputs,
        )


def test_observed_entry_obligation_uses_typed_entry_reachability_not_raw_loss_ratio() -> None:
    """Observed validation retains a failed aggregate row without obeying it."""
    from d810.analyses.control_flow.graph_checks import EntryReachabilityResult
    from d810.transforms.unflatten_authority import transaction_api
    from .test_transaction_api import (
        _observed_gates,
        _prepared_lowered_conditional_observed_case,
    )

    source, observed, attempt, authority = _prepared_lowered_conditional_observed_case()
    generic_gates = _observed_gates(source, observed)
    gates = transaction_api.GenericCfgGateBundle(
        EntryReachabilityResult(
            False, 20, 9, 0.45, 20, 0.5, "observed entry count collapsed",
        ),
        generic_gates.effectful_raw,
        generic_gates.effectful_effective,
        generic_gates.terminal,
    )

    verdict = transaction_api.revalidate_observed_unflatten_authority(
        authority=authority,
        observed=observed,
        observed_generation=attempt.generation,
        generic_gates=gates,
        observed_patch_binding=observed_patch_binding_for_test(authority),
    )

    assert verdict.accepted is True
    case = verdict.safety_case
    entry = next(
        cell for cell in case.obligation_index.cells
        if cell.key.subject.role is model.SemanticSubjectRole.SOURCE_ENTRY
        and cell.key.dimension is model.SafetyDimension.ENTRY_REACHABILITY
    )
    raw_entry = next(
        evidence.payload for evidence in case.evidence
        if type(evidence.payload) is model.GenericCfgGateEvidencePayload
        and evidence.payload.gate is model.GenericCfgGateKind.ENTRY_REACHABILITY
    )
    assert raw_entry.passed is False
    assert raw_entry.reason_code == "observed entry count collapsed"
    assert entry.state is model.ObligationState.SATISFIED
    assert any(
        justification.conclusion == entry.key
        and justification.rule is model.UnflattenJustificationRule.SUBJECT_REACHABLE
        for justification in case.justifications
    )
    assert not any(
        justification.conclusion == entry.key
        and justification.rule in {
            model.UnflattenJustificationRule.GENERIC_CFG_GATE_PASSED,
            model.UnflattenJustificationRule.GENERIC_CFG_GATE_FAILED,
        }
        for justification in case.justifications
    )


@pytest.mark.parametrize(
    "phase",
    (
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
    ),
)
def test_entry_gate_success_cannot_rescue_typed_missing_entry(
    phase: model.UnflattenAuthorityPhase,
) -> None:
    """A passing aggregate row cannot authorize a missing exact source entry."""
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, f"missing-{phase.value}")
    catalog = tuple(
        _role_subject(model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK, str(index))
        for index in range(3)
    )
    baseline = _complete_inputs(source_subjects=(entry, *catalog), phase=phase)
    candidate_bindings = tuple(
        replace(
            binding,
            status=model.SubjectBindingStatus.MISSING,
            block_ref=None,
            serial=None,
            anchor_ea=None,
            native_instruction_eas=(),
        ) if binding.subject == entry else binding
        for binding in baseline.candidate_inventory.bindings
    )
    inputs = _with_entry_gate_facts(
        _complete_inputs(
            source_subjects=(entry, *catalog),
            candidate_bindings=candidate_bindings,
            phase=phase,
        ),
        passed=True,
        reason="raw-entry-count-passed",
    )

    case = build_semantic_case(
        authority_id=authority_id(f"missing-entry-{phase.value}"),
        phase=phase,
        inputs=inputs,
    )
    entry_key = model.ObligationKey(entry, model.SafetyDimension.ENTRY_REACHABILITY)
    entry_cell = next(cell for cell in case.obligation_index.cells if cell.key == entry_key)
    raw_entry = next(
        evidence.payload for evidence in case.evidence
        if type(evidence.payload) is model.GenericCfgGateEvidencePayload
        and evidence.payload.gate is model.GenericCfgGateKind.ENTRY_REACHABILITY
    )

    assert raw_entry.passed is True
    assert raw_entry.reason_code == "raw-entry-count-passed"
    assert entry_cell.state is model.ObligationState.VIOLATED
    assert evaluate_case(case).accepted is False
    assert any(
        justification.conclusion == entry_key
        and justification.rule is model.UnflattenJustificationRule.SUBJECT_UNREACHABLE
        for justification in case.justifications
    )
    assert not any(
        justification.conclusion == entry_key
        and justification.rule in {
            model.UnflattenJustificationRule.GENERIC_CFG_GATE_PASSED,
            model.UnflattenJustificationRule.GENERIC_CFG_GATE_FAILED,
        }
        for justification in case.justifications
    )


def _semantic_handler_delivery_rejected_case() -> model.SemanticSafetyCase:
    """Build the canonical case where discovery exists but delivery does not."""
    from copy import copy
    from .test_bind import _rewire_inventory

    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "0")
    inputs = _complete_inputs(source_subjects=(entry,))
    # The handler at serial 2 stays in semantic discovery via its typed
    # handler subject, but the physical entry path 0 -> 1 -> 2 is severed.
    candidate = _rewire_inventory(
        inputs.candidate_inventory,
        {0: (1,), 1: (), 2: ()},
        generation=inputs.candidate_inventory.generation,
    )
    assert candidate.reachable_serials == (0, 1, 2)
    assert candidate.physical_entry_reachable_serials == (0, 1)
    receipt = copy(inputs.preparation_receipt)
    object.__setattr__(receipt, "candidate_inventory_digest", candidate.inventory_digest)
    object.__setattr__(
        receipt, "projected_topology_reference_digest", candidate.inventory_digest,
    )
    object.__setattr__(receipt, "receipt_id", receipt_id(receipt))
    case = build_semantic_case(
        authority_id=authority_id("handler-physical-delivery"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=replace(
            inputs,
            candidate_inventory=candidate,
            projected_topology_reference=candidate,
            preparation_receipt=receipt,
        ),
    )
    return case


def test_semantic_handler_discovery_cannot_satisfy_physical_delivery() -> None:
    """A handler semantic root still needs a physical source-entry path."""
    case = _semantic_handler_delivery_rejected_case()
    handler = next(
        subject for subject in case.subjects
        if subject.role is model.SemanticSubjectRole.AUTHORITATIVE_HANDLER
    )
    key = model.ObligationKey(
        handler, model.SafetyDimension.HANDLER_REACHABILITY,
    )
    cell = next(cell for cell in case.obligation_index.cells if cell.key == key)
    assert cell.state is model.ObligationState.VIOLATED
    assert any(
        item.conclusion == key
        and item.rule is model.UnflattenJustificationRule.SUBJECT_UNREACHABLE
        for item in case.justifications
    )
    assert evaluate_case(case).accepted is False


def test_retained_indirect_dispatcher_satisfies_handler_delivery() -> None:
    """A sealed live residual dispatcher supplies the missing indirect edge."""

    from .test_bind import _corridor_inventories

    proposal, _source, candidate = _corridor_inventories(
        candidate_full=True,
        disposition=model.CorridorPathDisposition.RESIDUAL,
    )
    handler = next(
        subject
        for subject in candidate.subjects
        if subject.role is model.SemanticSubjectRole.AUTHORITATIVE_HANDLER
    )
    handler_binding = next(
        binding for binding in candidate.bindings if binding.subject == handler
    )
    assert handler_binding.serial in candidate.reachable_serials
    dispatcher = next(
        binding
        for binding in candidate.bindings
        if binding.subject.role is model.SemanticSubjectRole.DISPATCHER_ENTRY
    )
    writer = next(
        witness
        for witness in proposal.source_identity_catalog.blocks
        if type(witness.block_ref) is NativeBlockRef
    )
    write = SemanticStateWriteProof(
        identity=writer.block_ref.identity,
        instruction_ea=writer.anchor_ea,
        state_variable=proposal.plan_inputs.state_identity,
        width=4,
        state_constant=handler.locator.normalized_states[0],
        corridor_instruction_eas=(writer.anchor_ea,),
        authority_transfer_ea=None,
        preserved_call_instruction_eas=(),
        delivery_kind=SemanticStateWriteDeliveryKind.INDIRECT,
    )
    indirect_proof = SemanticRouteProof(
        proof_id="retained-indirect-handler",
        atomic_group_id="retained-indirect-group",
        proof_kind=SemanticRouteProofKind.STATE_ASSIGNMENT,
        shape=SemanticRouteShape.DIRECT,
        source_identity=writer.block_ref.identity,
        source_anchor_ea=writer.anchor_ea,
        delivery_region=NativeEaInterval(
            writer.anchor_ea, writer.anchor_ea + 1,
        ),
        destinations=(SemanticRouteDestination(
            role=model.SemanticEdgeRole.DIRECT,
            state_constant=handler.locator.normalized_states[0],
            target_identity=handler.block_ref.identity,
            target_anchor_ea=next(iter(
                handler.block_ref.identity.exact_instruction_eas
            )),
        ),),
        state_write=write,
    )

    path = evaluator._retained_dispatcher_handler_delivery_path(
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        subject=handler,
        candidate_serial=handler_binding.serial,
        candidate_semantic_reachable=frozenset(candidate.reachable_serials),
        candidate_physical_entry_reachable=frozenset((0, 1)),
        candidate_bindings={
            binding.subject.subject_id: binding
            for binding in candidate.bindings
        },
        plan_inputs=proposal.plan_inputs,
        route_proofs=(indirect_proof,),
    )
    assert path == (
        dispatcher.subject.subject_id,
        handler.subject_id,
    )
    direct_proof = replace(
        indirect_proof,
        state_write=replace(
            write, delivery_kind=SemanticStateWriteDeliveryKind.DIRECT,
        ),
    )
    assert evaluator._retained_dispatcher_handler_delivery_path(
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        subject=handler,
        candidate_serial=handler_binding.serial,
        candidate_semantic_reachable=frozenset(candidate.reachable_serials),
        candidate_physical_entry_reachable=frozenset((0, 1)),
        candidate_bindings={
            binding.subject.subject_id: binding
            for binding in candidate.bindings
        },
        plan_inputs=proposal.plan_inputs,
        route_proofs=(direct_proof,),
    ) == ()
    observed_dispatcher = replace(
        dispatcher, phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
    )
    assert evaluator._retained_dispatcher_handler_delivery_path(
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        subject=handler,
        candidate_serial=handler_binding.serial,
        candidate_semantic_reachable=frozenset(candidate.reachable_serials),
        candidate_physical_entry_reachable=frozenset((0, 1)),
        candidate_bindings={
            **{
                binding.subject.subject_id: binding
                for binding in candidate.bindings
            },
            observed_dispatcher.subject.subject_id: observed_dispatcher,
        },
        plan_inputs=proposal.plan_inputs,
        route_proofs=(indirect_proof,),
    ) == (
        dispatcher.subject.subject_id,
        handler.subject_id,
    )


def test_equivalent_route_positive_marks_one_stable_subject_route_equivalence() -> None:
    """The real Direct preparation exposes one sealed route equivalence."""

    from d810.transforms.cfg_transaction import CfgProjection
    from d810.transforms.unflatten_authority import transaction_api
    from .test_transaction_api import _c1_direct_preparation_case

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    preparation = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    )
    assert type(preparation) is model.UnflattenAuthorityPreparationAccepted
    inputs = preparation.prepared.source_inputs
    case = build_semantic_case(
        authority_id=preparation.prepared.authority_id,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=inputs,
    )
    claim = next(
        item for item in inputs.claims
        if type(item) is model.EquivalentSemanticRouteClaim
    )
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


def test_route_realization_rows_validate_the_canonical_pair_once() -> None:
    """Route cardinality consumes one validated transaction-owned realization."""
    from d810.transforms.cfg_transaction import CfgProjection
    from d810.transforms.unflatten_authority import bind, evaluate, transaction_api
    from .test_transaction_api import _c1_direct_preparation_case

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    preparation = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    )
    assert type(preparation) is model.UnflattenAuthorityPreparationAccepted
    inputs = preparation.prepared.source_inputs

    with (
        patch.object(
            bind, "validate_source_route_authority",
            wraps=bind.validate_source_route_authority,
        ) as source_validation,
        patch.object(
            bind, "validate_projected_route_realization",
            wraps=bind.validate_projected_route_realization,
        ) as projected_validation,
    ):
        rows = evaluate._validated_route_realization_rows(
            inputs, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        )

    assert len(rows) == len(inputs.projected_route_realization.rows)
    assert source_validation.call_count == 1
    assert projected_validation.call_count == 1


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
        model.SemanticSubjectRole.SOURCE_LOGICAL_EXIT,
        model.SemanticSubjectRole.SEMANTIC_DAG_ENDPOINT,
    }:
        serial = int(token.rsplit("-", 1)[-1]) if token.rsplit("-", 1)[-1].isdigit() else 0
        ref = LogicalBlockRef("authority-test", f"logical-{token}", 1)
        kind = model.SemanticSubjectKind.BLOCK
        locator = model.LogicalFunctionExitSubjectLocator(ref, serial)
        return _subject_factory(
            model.SemanticSubjectRef,
            kind=kind,
            role=role,
            block_ref=ref,
            anchor_ea=None,
            locator=locator,
        )
    if role in {
        model.SemanticSubjectRole.SOURCE_ENTRY,
        model.SemanticSubjectRole.DISPATCHER_ENTRY,
    }:
        ref = block_ref("b0")
    elif token.rsplit("-", 1)[-1].isdigit():
        ref = block_ref(f"b{int(token.rsplit('-', 1)[-1]) % 3}")
    else:
        ref = block_ref("b0")
    if role is model.SemanticSubjectRole.PLANNED_HELPER:
        ref = PlanBlockRef(authority_id("role-helper-plan"), token)
        ref_anchor = 0x1000
    else:
        ref_anchor = {"b0": 0x1000, "b1": 0x1300, "b2": 0x1100}[ref.proxy_token]
    if role is model.SemanticSubjectRole.AUTHORITATIVE_HANDLER:
        ref = NativeBlockRef(StableBlockIdentity.from_instruction_eas(
            (ref_anchor,),
            native_key=NativePreanalysisKey(
                "authority-handler-role-fixture", "x86", 64, 0,
                "f" * 64, "p" * 64, "s" * 64,
            ),
        ))
        kind, locator, owner, anchor = model.SemanticSubjectKind.HANDLER, model.HandlerSubjectLocator(ref, ref_anchor, (1,)), ref, ref_anchor
    elif role is model.SemanticSubjectRole.TERMINAL_SITE:
        kind, locator, owner, anchor = model.SemanticSubjectKind.TERMINAL, model.TerminalSubjectLocator(ref, ref_anchor, model.TerminalKind.RETURN, ref_anchor + 4), ref, ref_anchor
    elif role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW:
        kind, locator, owner, anchor = model.SemanticSubjectKind.VALUE_FLOW, model.ValueFlowSubjectLocator(authority_id("fragment"), state_identity(), (block_ref("b0"),)), None, None
    elif role is model.SemanticSubjectRole.DISPATCHER_CORRIDOR:
        member_refs = (block_ref("b0"), block_ref("b1"))
        member_anchors = (0x1000, 0x1300)
        kind, locator, owner, anchor = (
            model.SemanticSubjectKind.CORRIDOR,
            model.CorridorSubjectLocator(
                evaluator._content_id_digest("unflatten.corridor.v1", member_refs),
                block_ref("b0"), 0x1000, member_refs, member_anchors,
            ),
            block_ref("b0"),
            0x1000,
        )
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
        (
            model.BlockSubjectLocator(second.block_ref, second.anchor_ea),
            model.BlockSubjectLocator(first.block_ref, first.anchor_ea),
        ),
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
        tuple(
            by_pair[(member.block_ref, member.anchor_ea)]
            for member in locator.destination_locators
            if type(member) is model.BlockSubjectLocator
        ),
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
        evaluator._content_id_digest(
            "unflatten.corridor.v1", (entry.block_ref, member1.block_ref),
        ), entry.block_ref, entry.anchor_ea,
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
        path_nodes, None,
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
    is_logical_exit = type(subject.locator) is model.LogicalFunctionExitSubjectLocator
    if is_logical_exit:
        serial = subject.locator.serial
    native_instruction_eas = ((subject.anchor_ea,) if subject.anchor_ea is not None else ())
    return model.PhaseSubjectBinding(
        subject=subject, phase=phase, block_ref=subject.block_ref if status is model.SubjectBindingStatus.UNIQUE else None,
        graph_fingerprint=fingerprint or authority_id(f"graph-{phase.value}"), generation=generation, status=status,
        serial=serial if status is model.SubjectBindingStatus.UNIQUE else None,
        anchor_ea=(
            None if is_logical_exit else subject.anchor_ea
        ) if status is model.SubjectBindingStatus.UNIQUE else None,
        native_instruction_eas=native_instruction_eas if status is model.SubjectBindingStatus.UNIQUE else (), role=subject.role,
    )


def _make_binding_serials_injective(
    bindings: tuple[model.PhaseSubjectBinding, ...],
) -> tuple[model.PhaseSubjectBinding, ...]:
    """Keep fixture-local block serials injective without changing aliases."""

    serial_by_ref: dict[object, int] = {}
    ref_by_serial: dict[int, object] = {}
    next_serial = max(
        (
            binding.serial
            for binding in bindings
            if binding.status is model.SubjectBindingStatus.UNIQUE
            and binding.serial is not None
        ),
        default=-1,
    ) + 1
    normalized = []
    for binding in bindings:
        if type(binding.subject.locator) is model.LogicalFunctionExitSubjectLocator:
            normalized.append(binding)
            continue
        if (
            binding.status is not model.SubjectBindingStatus.UNIQUE
            or binding.block_ref is None
            or binding.serial is None
        ):
            normalized.append(binding)
            continue
        serial = serial_by_ref.get(binding.block_ref)
        if serial is None:
            serial = binding.serial
            if serial in ref_by_serial and ref_by_serial[serial] != binding.block_ref:
                while next_serial in ref_by_serial:
                    next_serial += 1
                serial = next_serial
                next_serial += 1
            serial_by_ref[binding.block_ref] = serial
            ref_by_serial[serial] = binding.block_ref
        normalized.append(replace(binding, serial=serial))
    return tuple(normalized)


def _complete_inputs(*, source_subjects: tuple[model.SemanticSubjectRef, ...], candidate_subjects: tuple[model.SemanticSubjectRef, ...] | None = None, source_bindings: tuple[model.PhaseSubjectBinding, ...] | None = None, candidate_bindings: tuple[model.PhaseSubjectBinding, ...] | None = None, patch_step_facts: tuple[model.PatchStepEvidencePayload, ...] = (), claims: tuple[model.UnflattenClaim, ...] | None = None, proposal: model.ProposedUnflattenContract | None = None, native_instruction_eas_by_block: dict[object, tuple[int, ...]] | None = None, phase: model.UnflattenAuthorityPhase = model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT) -> model.DerivedUnflattenPreparationInputs:
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model)) if proposal is None else proposal
    claims = proposal.claims if claims is None else claims
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
    # Caller token fixtures may still use logical placeholders.  Catalogue
    # membership is instead derived only from the proposal's exact identities.
    source_subjects = normalize_value_flow(tuple(
        subject for subject in source_subjects
        if subject.role not in {
            model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK,
            model.SemanticSubjectRole.AUTHORITATIVE_HANDLER,
        }
    ))
    # The source catalogue is a closed transaction input, not an inferred
    # evaluator convenience.  Every ordinary fixture therefore starts with
    # exactly one source-catalog subject for every proposal catalogue row;
    # adversarial tests can still remove or replace those rows after this
    # canonical construction when exercising the fail-closed boundary.
    source_catalog_subjects = tuple(
        _subject_factory(
            model.SemanticSubjectRef,
            kind=model.SemanticSubjectKind.BLOCK,
            role=model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK,
            block_ref=witness.block_ref,
            anchor_ea=witness.anchor_ea,
            locator=model.BlockSubjectLocator(
                witness.block_ref,
                witness.anchor_ea,
            ),
        )
        for witness in proposal.source_identity_catalog.blocks
    )
    source_subjects = tuple({
        item.subject_id: item
        for item in (*source_subjects, *source_catalog_subjects)
    }.values())
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
    handler_input = proposal.plan_inputs.authoritative_handlers[0]
    required_handler_subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.HANDLER,
        role=model.SemanticSubjectRole.AUTHORITATIVE_HANDLER,
        block_ref=handler_input.block_ref,
        anchor_ea=handler_input.anchor_ea,
        locator=model.HandlerSubjectLocator(
            handler_input.block_ref,
            handler_input.anchor_ea,
            handler_input.normalized_states,
        ),
    )
    required_subjects = (
        _role_subject(model.SemanticSubjectRole.DISPATCHER_ENTRY, "0"),
        _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "0"),
        _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "1"),
        required_handler_subject,
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
    candidate_subjects = source_subjects if candidate_subjects is None else tuple(
        subject for subject in candidate_subjects
        if subject.role is not model.SemanticSubjectRole.AUTHORITATIVE_HANDLER
    )
    candidate_subjects = tuple({
        item.subject_id: item
        for item in (
            *candidate_subjects,
            *source_catalog_subjects,
            required_handler_subject,
        )
    }.values())
    candidate_subjects = normalize_value_flow(candidate_subjects)
    candidate_terminal_sites = {
        (
            subject.block_ref,
            subject.anchor_ea,
            subject.locator.instruction_ea,
        )
        for subject in candidate_subjects
        if subject.role is model.SemanticSubjectRole.TERMINAL_SITE
        and type(subject.locator) is model.TerminalSubjectLocator
    }
    candidate_subjects = tuple({
        item.subject_id: item
        for item in (
            *candidate_subjects,
            *(
                effect
                for effect in terminal_effect_subjects
                if type(effect.locator) is model.EffectSubjectLocator
                and (
                    effect.block_ref,
                    effect.anchor_ea,
                    effect.locator.instruction_ea,
                ) in candidate_terminal_sites
            ),
        )
    }.values())
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
    source_bindings = _make_binding_serials_injective(tuple(source_bindings))
    candidate_bindings = _make_binding_serials_injective(tuple(candidate_bindings))
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
        route_expansion_digest=_digest(tuple(item for item in source_subjects if item.kind is model.SemanticSubjectKind.ROUTE)),
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
        entry_subjects = tuple(
            subject
            for subject in (subjects if source_partition is None else source_partition)
            if subject.role is model.SemanticSubjectRole.SOURCE_ENTRY
        )
        if not entry_subjects:
            # Empty/claim-only adversarial inputs are built first so the
            # evaluator, rather than this fixture, rejects their authority.
            entry_serial = min(
                (int(binding.serial) for binding in unique.values()
                 if binding.serial is not None),
                default=0,
            )
            entry_subjects = ()
        elif len(entry_subjects) != 1 or entry_subjects[0].block_ref is None:
            raise ValueError("fixture inventory requires one source entry")
        else:
            entry_serials = {
                int(binding.serial)
                for binding in bindings
                if (
                    binding.status is model.SubjectBindingStatus.UNIQUE
                    and binding.block_ref == entry_subjects[0].block_ref
                    and binding.serial is not None
                )
            }
            if not entry_serials and not unique:
                # A deliberately all-missing projected inventory has no physical
                # graph rows.  Its entry is still the source partition's exact
                # identity, but the empty inventory uses the model's sentinel.
                entry_serial = 0
            elif len(entry_serials) != 1:
                raise ValueError("fixture inventory requires one physical source entry")
            else:
                entry_serial = next(iter(entry_serials))
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
            eas = {*binding.native_instruction_eas}
            if binding.anchor_ea is not None:
                eas.add(binding.anchor_ea)
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
            # Forecast paths describe the dispatcher corridor, while the
            # inventory additionally records the physical source entry.  When
            # the fixture gives that entry a distinct predecessor block,
            # connect it to the unique corridor root instead of leaving a
            # valid source catalogue outside its own reachability closure.
            if not successor_by_serial[entry_serial]:
                corridor_roots = tuple(
                    serial for serial in serials
                    if serial != entry_serial and not predecessor_by_serial[serial]
                )
                if len(corridor_roots) == 1:
                    root = corridor_roots[0]
                    successor_by_serial[entry_serial] = (root,)
                    predecessor_by_serial[root].append(entry_serial)
        else:
            predecessor_by_serial = {
                serial: ([serials[index - 1]] if index else [])
                for index, serial in enumerate(serials)
            }
            successor_by_serial = {
                serial: ((serials[index + 1],) if index + 1 < len(serials) else ())
                for index, serial in enumerate(serials)
            }
        logical_exit_serials = {
            binding.serial
            for binding in unique.values()
            if type(binding.subject.locator) is model.LogicalFunctionExitSubjectLocator
        }
        # A logical function exit is an anchorless zero-way/STOP row.  It is
        # never an accidental member of this helper's synthetic native chain.
        for serial in serials:
            predecessor_by_serial[serial] = (
                [] if serial in logical_exit_serials else [
                    predecessor
                    for predecessor in predecessor_by_serial[serial]
                    if predecessor not in logical_exit_serials
                ]
            )
            successor_by_serial[serial] = tuple(
                successor
                for successor in successor_by_serial[serial]
                if serial not in logical_exit_serials
                and successor not in logical_exit_serials
            )
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
                (rows := tuple(
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
                        None,
                        None,
                        0,
                    )
                    for ordinal, ea in enumerate(binding.native_instruction_eas)
                )),
                model.BlockKind.STOP
                if binding.serial in logical_exit_serials or any(
                    locator.terminal_kind is model.TerminalKind.STOP
                    for locator in terminals_by_owner.get(binding.block_ref, ())
                ) else model.BlockKind.UNKNOWN,
                (
                    0xFFFFFFFFFFFFFFFF
                    if binding.serial in logical_exit_serials
                    else binding.anchor_ea if binding.anchor_ea is not None else 0
                ),
                tail_opcode=rows[-1].opcode if rows else None,
                raw_tail_opcode=rows[-1].raw_opcode if rows else None,
                tail_kind=rows[-1].instruction_kind if rows else None,
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
        blocks_by_serial = {block.serial: block for block in blocks}
        serial_by_ref = {
            block.block_ref: block.serial
            for block in blocks
            if block.block_ref is not None
        }
        semantic_roots = {entry_serial} if blocks else set()
        semantic_roots.update(
            serial_by_ref[subject.block_ref]
            for subject in subjects
            if (
                (
                    subject.role is model.SemanticSubjectRole.AUTHORITATIVE_HANDLER
                    and type(subject.locator) is model.HandlerSubjectLocator
                )
                or (
                    phase_value is model.UnflattenAuthorityPhase.PRODUCER_FORECAST
                    and
                    subject.role in {
                        model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
                        model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
                    }
                    and type(subject.locator) is model.BlockSubjectLocator
                )
            )
            and subject.block_ref in serial_by_ref
        )
        pending = list(semantic_roots)
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
            entry_serial if blocks else 0,
            tuple(item.subject_id for item in partition), function_ea,
        )
        return model.SemanticGraphInventory(
            phase_value, fingerprint, generation, blocks, subjects, bindings,
            effects, terminals, topology, digest, closure,
            entry_serial if blocks else 0,
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
    projected_topology_reference = candidate_inventory
    if phase is model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
        projected_reference_bindings = tuple(
            replace(
                binding,
                phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            )
            for binding in candidate_bindings
        )
        projected_topology_reference = fixture_inventory(
            model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            authority_id("candidate-fp"), 4,
            tuple(sorted(projected_reference_bindings, key=lambda item: item.subject.subject_id)),
            tuple(sorted({item.subject_id: item for item in (*source_subjects, *candidate_subjects)}.values(), key=lambda item: item.subject_id)),
            source_subjects,
            candidate_subjects,
        )
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
    object.__setattr__(receipt, "projected_topology_reference_digest", projected_topology_reference.inventory_digest)
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
        projected_topology_reference=projected_topology_reference,
        source_route_authority=None, projected_route_realization=None,
        generic_gate_facts=None, conditional_relations=relations,
        patch_step_facts=patch_payloads,
        preparation_metrics=metrics,
        phase_build_metrics=model.PhaseBuildMetrics(
            phase, 0 if phase is model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY else 1,
            1, 1.25,
        ),
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
    """Prepared authority retains the real source and projected products."""
    from d810.transforms.cfg_transaction import CfgProjection
    from d810.transforms.unflatten_authority import transaction_api
    from .test_transaction_api import _c1_direct_preparation_case

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    result = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    )
    assert type(result) is model.UnflattenAuthorityPreparationAccepted
    prepared = result.prepared
    assert prepared.projected_route_realization.source_authority is prepared.source_route_authority
    assert prepared.source_inputs.source_route_authority is prepared.source_route_authority
    assert prepared.source_inputs.projected_route_realization is prepared.projected_route_realization
    with pytest.raises(ValueError, match="source bindings"):
        replace(prepared, source_bindings=prepared.source_bindings[:-1])
    attempt = model.TransactionAttemptId(
        plan_id=plan.plan_id, session_id="prepared-session",
        generation=prepared.projected_generation, attempt_id="prepared-attempt",
    )
    live_maturity = MaturityEnvelope(ir=None, provider="test", provider_id=0)
    source_coordinates = dict(plan.source_coordinates)
    encountered_refs = tuple(dict.fromkeys(iter_refs(
        (plan.steps, plan.new_blocks, plan.relocation_map),
    )))
    canonical_bindings = tuple(
        (ref, source_coordinates[ref])
        for ref in encountered_refs
        if type(ref) is not PlanBlockRef
    ) + tuple(
        (spec.block_id, len(source.blocks) + offset)
        for offset, spec in enumerate(plan.new_blocks)
    )
    patch_binding = BoundPatchPlan(
        plan=plan,
        attempt_id=attempt,
        session_id=attempt.session_id,
        generation=attempt.generation,
        maturity=live_maturity,
        bindings=canonical_bindings,
    )
    with pytest.raises(TypeError, match="live_maturity"):
        model.BoundUnflattenAuthority(
            binding_id=authority_id("prepared-binding"), prepared=prepared,
            attempt_id=attempt, session_id=attempt.session_id,
            generation=attempt.generation, live_maturity=4,
            live_bindings=canonical_bindings,
            patch_binding=patch_binding,
        )
    bound = model.BoundUnflattenAuthority(
        binding_id=bound_unflatten_binding_id(prepared, patch_binding), prepared=prepared,
        attempt_id=attempt, session_id=attempt.session_id,
        generation=attempt.generation,
        live_maturity=live_maturity, live_bindings=canonical_bindings,
        patch_binding=patch_binding,
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


def test_value_flow_identity_accepts_bound_physical_owner_anchor_outside_instruction_origins() -> None:
    """Value-flow consumes the binder's physical-anchor verdict without replaying it."""

    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
    from d810.transforms.cfg_transaction import NativeBlockRef
    from d810.transforms.unflatten_authority.evaluate import (
        _identity_support, _make_justification, _validate_justification_graph,
    )

    phase = model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
    fingerprint = authority_id("value-flow-physical-owner")
    ref = NativeBlockRef(StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1000, 0x1020),),
        native_key=NativePreanalysisKey(
            "value-flow-physical-owner", "x86", 64, 0,
            "f" * 64, "p" * 64, "s" * 64,
        ),
        exact_instruction_eas=(0x1010,),
    ))
    owner = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        block_ref=ref,
        anchor_ea=0x1000,
        locator=model.BlockSubjectLocator(ref, 0x1000),
    )
    value_flow = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.VALUE_FLOW,
        role=model.SemanticSubjectRole.NON_STATE_VALUE_FLOW,
        block_ref=None,
        anchor_ea=None,
        locator=model.ValueFlowSubjectLocator(
            authority_id("value-flow-physical-fragment"), state_identity(), (ref,),
        ),
    )
    binding = model.PhaseSubjectBinding(
        subject=owner, phase=phase, block_ref=ref,
        graph_fingerprint=fingerprint, generation=4,
        status=model.SubjectBindingStatus.UNIQUE, serial=7,
        anchor_ea=0x1000, native_instruction_eas=(0x1010,), role=owner.role,
    )
    evidence = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.PHASE_BINDING,
        owner, phase, model.PhaseBindingEvidencePayload(binding),
    )
    key = model.ObligationKey(value_flow, model.SafetyDimension.IDENTITY_BINDING)
    justification = _make_justification(
        rule=model.UnflattenJustificationRule.UNIQUE_PHASE_BINDING,
        key=key, polarity=model.EvidencePolarity.SUPPORTS, phase=phase,
        premise_ids=(evidence.evidence_id,),
    )

    assert _identity_support(
        value_flow, (owner, value_flow), (binding,), phase, fingerprint, 4,
    )
    _validate_justification_graph(
        (justification,), (key,), (evidence,), phase,
        candidate_fingerprint=fingerprint, candidate_generation=4,
        bindings=(binding,), subjects=(owner, value_flow),
    )


def test_route_identity_consumes_its_complete_binder_row_once() -> None:
    """A UNIQUE route binding is identity authority; endpoint replay is not."""

    from d810.transforms.unflatten_authority import bind
    from d810.transforms.unflatten_authority.evaluate import _identity_support

    values = _valid_proposal(model)
    proposal = model.ProposedUnflattenContract(**values)
    proof = proposal.route_evidence.route_proofs[0]
    source_witness = proposal.source_identity_catalog.blocks[0]
    destination_witness = proposal.source_identity_catalog.blocks[-1]
    locator = model.RouteSubjectLocator(
        proof.proof_id,
        proof.atomic_group_id,
        source_witness.block_ref,
        source_witness.anchor_ea,
        (model.BlockSubjectLocator(
            destination_witness.block_ref,
            destination_witness.anchor_ea,
        ),),
    )
    route = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.ROUTE,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        block_ref=locator.source_ref,
        anchor_ea=locator.source_anchor_ea,
        locator=locator,
    )
    fingerprint = authority_id("route-binding-single-authority")
    (binding,) = bind.bind_inventory_subjects(
        (route,),
        catalog=proposal.source_identity_catalog,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        graph_fingerprint=fingerprint,
        generation=proposal.source_identity_catalog.generation,
        serial_by_ref={
            source_witness.block_ref: 10,
            destination_witness.block_ref: 11,
        },
        effects=(),
        terminals=(),
        reachable_serials=(10, 11),
        native_instruction_eas_by_ref={
            source_witness.block_ref: source_witness.native_instruction_eas,
            destination_witness.block_ref: destination_witness.native_instruction_eas,
        },
    )
    assert binding.status is model.SubjectBindingStatus.UNIQUE

    assert _identity_support(
        route,
        (route,),
        (binding,),
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        fingerprint,
        proposal.source_identity_catalog.generation,
    )


def test_observed_logical_endpoint_identity_accepts_only_its_minted_move() -> None:
    """An observed logical exit may move only through its sealed occurrence."""

    from d810.transforms.unflatten_authority import bind
    from d810.transforms.unflatten_authority.evaluate import _identity_support

    phase = model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
    # _complete_inputs fixes observed candidate coordinates to this immutable
    # fixture generation/fingerprint pair.
    fingerprint = authority_id("candidate-fp")
    endpoint = _role_subject(
        model.SemanticSubjectRole.SEMANTIC_DAG_ENDPOINT,
        "logical-endpoint-5",
    )
    owner = _role_subject(
        model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, "logical-owner-1",
    )
    locator = endpoint.locator
    assert type(locator) is model.LogicalFunctionExitSubjectLocator
    occurrence = bind._mint_observed_logical_endpoint_occurrence(
        logical_ref=locator.block_ref,
        projected_serial=locator.serial,
        observed_serial=127,
        owner_ref=owner.block_ref,
        predecessor_refs=(owner.block_ref,),
    )
    binding = model.PhaseSubjectBinding(
        subject=endpoint,
        phase=phase,
        block_ref=locator.block_ref,
        graph_fingerprint=fingerprint,
        generation=4,
        status=model.SubjectBindingStatus.UNIQUE,
        serial=127,
        anchor_ea=None,
        native_instruction_eas=(),
        role=endpoint.role,
        observed_logical_occurrence=occurrence,
    )

    # This is the exact predicate the observed semantic case uses to set its
    # IDENTITY_BINDING verdict for the endpoint subject.
    assert _identity_support(
        endpoint, (endpoint,), (binding,), phase, fingerprint, 4,
    )

    # A moved serial cannot appear without a binder-minted receipt.
    with pytest.raises(ValueError, match="serial movement requires one observed occurrence"):
        model.PhaseSubjectBinding(
            subject=endpoint,
            phase=phase,
            block_ref=locator.block_ref,
            graph_fingerprint=fingerprint,
            generation=4,
            status=model.SubjectBindingStatus.UNIQUE,
            serial=127,
            anchor_ea=None,
            native_instruction_eas=(),
            role=endpoint.role,
        )

    # Matching value content is insufficient: the evaluator must reject a
    # receipt that was not minted and sealed by the binder.
    forged = model.ObservedLogicalEndpointOccurrence(
        logical_ref=locator.block_ref,
        projected_serial=locator.serial,
        observed_serial=127,
        owner_ref=owner.block_ref,
        predecessor_refs=(owner.block_ref,),
    )
    forged_binding = replace(binding, observed_logical_occurrence=forged)
    assert not _identity_support(
        endpoint, (endpoint,), (forged_binding,), phase, fingerprint, 4,
    )

    with pytest.raises(ValueError, match="differs from binding"):
        model.PhaseSubjectBinding(
            subject=endpoint,
            phase=phase,
            block_ref=locator.block_ref,
            graph_fingerprint=fingerprint,
            generation=4,
            status=model.SubjectBindingStatus.UNIQUE,
            serial=128,
            anchor_ea=None,
            native_instruction_eas=(),
            role=endpoint.role,
            observed_logical_occurrence=occurrence,
        )


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
            tuple(replace(fact, owner_ref=block_ref("b1")) for fact in redirect_facts),
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


def test_value_flow_owner_resolution_rejects_same_role_ambiguity() -> None:
    """A sealed owner cannot be discharged by an ambiguous role binding."""

    from d810.transforms.unflatten_authority.evaluate import _value_flow_owner_subjects

    owner = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "0")
    with pytest.raises(
        ValueError,
        match=r"value-flow owner subject is missing or ambiguous: .*count=2",
    ):
        _value_flow_owner_subjects((owner, owner), (owner.block_ref,))


def test_value_flow_owner_resolution_accepts_exact_catalog_physical_root() -> None:
    """A redirect-owned physical root needs no fabricated semantic role."""
    from d810.transforms.unflatten_authority.evaluate import _value_flow_owner_subjects

    owner = _role_subject(
        model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK,
        "physical-entry-root",
    )

    assert _value_flow_owner_subjects(
        (owner,), (owner.block_ref,),
    ) == (owner,)


def test_catalog_membership_allows_only_in_range_native_route_subjects() -> None:
    """Proof-backed route anchors do not relax ordinary catalog subjects."""
    from d810.transforms.unflatten_authority.evaluate import _source_subject_matches_catalog

    native_key = NativePreanalysisKey(
        "route-anchor-membership", "x86", 64, 0,
        "f" * 64, "p" * 64, "s" * 64,
    )
    ref = NativeBlockRef(StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1000, 0x1020),),
        native_key=native_key,
        exact_instruction_eas=(0x1004,),
    ))
    witness = model.SourceBlockIdentityWitness(ref, 0x1000, (0x1004,))
    route_subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
        block_ref=ref,
        anchor_ea=0x1010,
        locator=model.BlockSubjectLocator(ref, 0x1010),
    )
    ordinary_subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SOURCE_ENTRY,
        block_ref=ref,
        anchor_ea=0x1010,
        locator=model.BlockSubjectLocator(ref, 0x1010),
    )

    assert _source_subject_matches_catalog(route_subject, witness)
    assert not _source_subject_matches_catalog(ordinary_subject, witness)
    outside_route_subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
        block_ref=ref,
        anchor_ea=0x1020,
        locator=model.BlockSubjectLocator(ref, 0x1020),
    )
    assert not _source_subject_matches_catalog(
        outside_route_subject, witness,
    )


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
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    proposal = replace(
        proposal,
        use_def_witness=replace(
            proposal.use_def_witness,
            redirect_owner_refs=proposal.plan_inputs.dispatcher_member_refs,
        ),
    )
    case = build_semantic_case(
        authority_id=authority_id("owner-premise-set"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(source_entry,), proposal=proposal),
    )
    justification = next(
        item for item in case.justifications
        if item.conclusion.subject.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW
        and item.rule is model.UnflattenJustificationRule.UNIQUE_PHASE_BINDING
    )
    assert len(justification.premise_ids) == 2
    evidence_by_id = {item.evidence_id: item for item in case.evidence}
    assert {
        evidence_by_id[premise].payload.binding.subject.block_ref
        for premise in justification.premise_ids
    } == set(proposal.plan_inputs.dispatcher_member_refs)
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
    with pytest.raises(ValueError, match="premise|record|case|non-canonical"):
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


def test_ordinary_identity_binding_rejects_multiple_phase_premises() -> None:
    """Only the aggregate value-flow subject may carry multiple owners."""

    source_entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "ordinary-premise")
    case = build_semantic_case(
        authority_id=authority_id("ordinary-premise"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(source_entry,)),
    )
    ordinary = next(
        item for item in case.justifications
        if item.conclusion.subject == source_entry
        and item.rule is model.UnflattenJustificationRule.UNIQUE_PHASE_BINDING
    )
    extra_premise = next(
        item.evidence_id for item in case.evidence
        if item.kind is model.AuthorityEvidenceKind.PHASE_BINDING
        and item.subject != source_entry
    )
    values = {
        name: getattr(ordinary, name)
        for name in ordinary.__dataclass_fields__
        if name != "justification_id"
    }
    values["premise_ids"] = tuple(sorted((*ordinary.premise_ids, extra_premise)))
    forged = _justification_factory(model.AuthorityJustification, **values)
    from d810.transforms.unflatten_authority.evaluate import _validate_justification_graph
    with pytest.raises(ValueError, match="ordinary identity binding requires one premise"):
        _validate_justification_graph(
            tuple(forged if item is ordinary else item for item in case.justifications),
            case.required_obligations, case.evidence, case.phase,
            case.claims, case.conditional_relations,
            candidate_fingerprint=case.candidate_fingerprint,
            candidate_generation=case.candidate_generation,
            bindings=case.bindings, subjects=case.subjects,
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
            else "99" if role in {
                model.SemanticSubjectRole.SOURCE_LOGICAL_EXIT,
                model.SemanticSubjectRole.SEMANTIC_DAG_ENDPOINT,
            }
            else "0" if role in {
                model.SemanticSubjectRole.SOURCE_ENTRY,
                model.SemanticSubjectRole.DISPATCHER_ENTRY,
                model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
            } else "1",
        )
        for role in roles
    )
    entry = next(
        subject for subject in subjects
        if subject.role is model.SemanticSubjectRole.SOURCE_ENTRY
    )
    for subject in subjects:
        source_subjects = (
            (entry,)
            if subject.role is model.SemanticSubjectRole.PLANNED_HELPER
            else (subject,)
            if subject is entry
            else (entry, subject)
        )
        candidate_subjects = (
            (*source_subjects, subject)
            if subject.role is model.SemanticSubjectRole.PLANNED_HELPER
            else source_subjects
        )
        case = build_semantic_case(
            authority_id=authority_id(f"role-authority:{subject.subject_id}"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=_complete_inputs(
                source_subjects=source_subjects,
                candidate_subjects=candidate_subjects,
            ),
        )
        if subject.role in {
            model.SemanticSubjectRole.NON_STATE_VALUE_FLOW,
            model.SemanticSubjectRole.AUTHORITATIVE_HANDLER,
        }:
            subject = next(
                item for item in case.subjects
                if item.role is subject.role
            )
        actual = {key.dimension for key in case.required_obligations if key.subject == subject}
        expected = set(REQUIRED_DIMENSIONS[(subject.kind, subject.role)])
        expected.update(
            relation.dimension for relation in case.conditional_relations
            if relation.target_subject_id == subject.subject_id
        )
        if subject.role is model.SemanticSubjectRole.DISPATCHER_ENTRY:
            expected.add(model.SafetyDimension.ROUTE_EQUIVALENCE)
        if (
            subject.role is model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION
            and any(
                relation.source_subject_id == subject.subject_id
                and relation.dimension is model.SafetyDimension.TERMINAL_REACHABILITY
                for relation in case.conditional_relations
            )
        ):
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
        with pytest.raises(
            ValueError,
            match=(
                "projected phase must match its candidate inventory"
                "|reachable_serials must equal the semantic-root successor closure"
                "|topology incidence does not match block topology"
            ),
        ):
            candidate_case(mutator, token)


def test_projected_topology_reference_authorizes_intentional_redirect_for_incident_roles() -> None:
    """Projected topology is the reference for the projected authority phase."""
    from d810.transforms.cfg_transaction import CfgProjection
    from d810.transforms.unflatten_authority import transaction_api
    from .test_transaction_api import _c1_direct_preparation_case

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    preparation = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    )
    assert preparation.prepared is not None
    case = preparation.prepared.projected_case
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
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.hexrays.mutation.patch_binding import bind_patch_plan
    from d810.transforms.cfg_transaction import CfgProjection
    from d810.transforms.unflatten_authority import transaction_api
    from .test_transaction_api import _c1_direct_preparation_case, _observed_gates

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    preparation = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    )
    assert preparation.prepared is not None
    refs = tuple(plan.source_coordinates)
    index = MbaBlockIdentityIndex.from_bindings(
        generation=fixture.attempt_id.generation,
        maturity=None,
        native_key=refs[0][0].identity.native_key,
        snapshot_id=plan.snapshot_id,
        session_id=fixture.attempt_id.session_id,
        bindings=tuple((ref.identity, serial) for ref, serial in refs),
    )
    index.begin_transaction(fixture.attempt_id, quantity=len(source.blocks))
    binding = transaction_api.bind_prepared_unflatten_authority(
        prepared=preparation.prepared,
        patch_binding=bind_patch_plan(plan, index, fixture.attempt_id).bound_plan,
    )
    assert binding.authority is not None
    # Source topology is deliberately different from the prepared projection.
    observed = transaction_api.revalidate_observed_unflatten_authority(
        authority=binding.authority,
        observed=source,
        observed_generation=fixture.attempt_id.generation,
        generic_gates=_observed_gates(source, source),
        observed_patch_binding=observed_patch_binding_for_test(binding.authority),
    )
    assert not observed.accepted
    assert observed.safety_case is not None
    assert any(
        cell.state is model.ObligationState.VIOLATED
        for cell in observed.safety_case.obligation_index.cells
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
    assert model.ObligationKey(
        subject, model.SafetyDimension.STRUCTURAL_ACCOUNTING,
    ) not in {cell.key for cell in case.obligation_index.cells}
    for dimension in (model.SafetyDimension.TOPOLOGY_INTEGRITY,):
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
    keys = {
        key.dimension for key in case.required_obligations
        if key.subject == subject
    }
    assert model.SafetyDimension.IDENTITY_BINDING in keys
    assert model.SafetyDimension.STRUCTURAL_ACCOUNTING not in keys
    identity = next(
        item for item in case.obligation_index.cells
        if item.key == model.ObligationKey(subject, model.SafetyDimension.IDENTITY_BINDING)
    )
    assert identity.state is model.ObligationState.SATISFIED
    assert evaluate_case(case).reason is model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED


def test_unclaimed_missing_canonical_catalog_block_has_one_physical_loss_row() -> None:
    """A physical source loss is one forbidden row, never one per role view."""

    from d810.transforms.unflatten_authority.evaluate import build_semantic_loss_ledger

    # The fixture's sole equivalent-route claim owns b0.  b2 is a real
    # catalog identity outside that claim, so its absence must stay forbidden.
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    witness = next(
        item for item in proposal.source_identity_catalog.blocks
        if item.anchor_ea == 0x1100
    )
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK,
        block_ref=witness.block_ref,
        anchor_ea=witness.anchor_ea,
        locator=model.BlockSubjectLocator(witness.block_ref, witness.anchor_ea),
    )
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "missing")
    baseline = _complete_inputs(
        source_subjects=(entry, subject), candidate_subjects=(entry,), proposal=proposal,
    )
    missing_b2 = tuple(
        replace(
            binding,
            status=model.SubjectBindingStatus.MISSING,
            block_ref=None,
            serial=None,
            anchor_ea=None,
            native_instruction_eas=(),
        ) if binding.subject == subject else binding
        for binding in baseline.candidate_inventory.bindings
    )
    case = build_semantic_case(
        authority_id=authority_id("canonical-unclaimed-loss"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(
            source_subjects=(entry, subject), candidate_subjects=(entry,),
            candidate_bindings=missing_b2, proposal=proposal,
        ),
    )
    verdict = evaluate_case(case)
    ledger = build_semantic_loss_ledger(case, verdict)
    assert len(ledger.rows) == 1
    row = ledger.rows[0]
    assert row.source_subject == subject
    assert row.kind is model.SemanticLossKind.UNCLASSIFIED
    assert row.structural_obligation.state is model.ObligationState.VIOLATED


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
    # ``case_id`` is derived, so a forged one cannot even be constructed.
    with pytest.raises((TypeError, ValueError), match="init=False"):
        replace(case, case_id=authority_id("forged"))


def test_case_id_compacts_every_sealed_occurrence_without_record_replay(
    monkeypatch,
) -> None:
    """The compact case ID remains sensitive to every case occurrence."""
    from d810.transforms.unflatten_authority import ids as authority_ids

    digest = lambda label: authority_id(f"compact-case:{label}")
    result_fields = {"retirement_phase_result", "corridor_coverage_phase_result"}
    result_tuple_fields = {
        "detached_dead_handler_component_source_results",
        "detached_dead_handler_component_phase_results",
        "terminal_cycle_phase_results",
    }
    identity_tuple_fields = {
        "claims": "claim_id", "subjects": "subject_id",
        "evidence": "evidence_id", "justifications": "justification_id",
    }
    values: dict[str, object] = {}
    for name in model.SemanticSafetyCase.__dataclass_fields__:
        if name == "case_id":
            continue
        if name == "preparation_receipt":
            values[name] = SimpleNamespace(receipt_id=digest(name))
        elif name in identity_tuple_fields:
            values[name] = (SimpleNamespace(**{identity_tuple_fields[name]: digest(name)}),)
        elif name in {"source_inventory", "candidate_inventory"}:
            values[name] = SimpleNamespace(inventory_digest=digest(name))
        elif name == "retirement_candidate_catalog":
            values[name] = SimpleNamespace(catalog_id=digest(name))
        elif name in result_fields:
            values[name] = SimpleNamespace(result_id=digest(name))
        elif name in result_tuple_fields:
            values[name] = (SimpleNamespace(result_id=digest(name)),)
        else:
            values[name] = digest(name)

    def raw_case(overrides: dict[str, object] | None = None):
        raw = object.__new__(model.SemanticSafetyCase)
        for name, value in values.items():
            object.__setattr__(raw, name, (overrides or {}).get(name, value))
        object.__setattr__(raw, "case_id", digest("placeholder"))
        return raw

    original_record_id = authority_ids._record_content_id
    replayed_case_trees: list[object] = []

    def counted_record_id(schema: str, value: object, id_field: str) -> str:
        if type(value) is model.SemanticSafetyCase:
            replayed_case_trees.append(value)
        return original_record_id(schema, value, id_field)

    monkeypatch.setattr(authority_ids, "_record_content_id", counted_record_id)
    baseline = authority_ids.case_id(raw_case())
    assert not replayed_case_trees

    for name in values:
        if name == "preparation_receipt":
            changed = SimpleNamespace(receipt_id=digest(f"changed:{name}"))
        elif name in identity_tuple_fields:
            changed = (SimpleNamespace(**{identity_tuple_fields[name]: digest(f"changed:{name}")}),)
        elif name in {"source_inventory", "candidate_inventory"}:
            changed = SimpleNamespace(inventory_digest=digest(f"changed:{name}"))
        elif name == "retirement_candidate_catalog":
            changed = SimpleNamespace(catalog_id=digest(f"changed:{name}"))
        elif name in result_fields:
            changed = SimpleNamespace(result_id=digest(f"changed:{name}"))
        elif name in result_tuple_fields:
            changed = (SimpleNamespace(result_id=digest(f"changed:{name}")),)
        else:
            changed = digest(f"changed:{name}")
        assert authority_ids.case_id(raw_case({name: changed})) != baseline, name


def test_compact_case_projection_preserves_field_order_and_occurrence_multiplicity() -> None:
    from d810.transforms.unflatten_authority import ids as authority_ids

    digest = authority_id("compact-projection")
    child = SimpleNamespace(claim_id=digest)
    raw = object.__new__(model.SemanticSafetyCase)
    for name in model.SemanticSafetyCase.__dataclass_fields__:
        if name == "case_id":
            object.__setattr__(raw, name, digest)
        elif name == "preparation_receipt":
            object.__setattr__(raw, name, SimpleNamespace(receipt_id=digest))
        elif name == "claims":
            object.__setattr__(raw, name, (child, child))
        elif name in {"subjects", "evidence", "justifications"}:
            object.__setattr__(raw, name, ())
        elif name in {"source_inventory", "candidate_inventory"}:
            object.__setattr__(raw, name, SimpleNamespace(inventory_digest=digest))
        elif name in {
            "retirement_candidate_catalog", "retirement_phase_result",
            "corridor_coverage_phase_result",
        }:
            object.__setattr__(raw, name, None)
        elif name in {
            "detached_dead_handler_component_source_results",
            "detached_dead_handler_component_phase_results",
            "terminal_cycle_phase_results",
        }:
            object.__setattr__(raw, name, ())
        else:
            object.__setattr__(raw, name, digest)

    projection = authority_ids._semantic_safety_case_projection(raw)
    assert tuple(name for name, _value in projection) == tuple(
        name for name in model.SemanticSafetyCase.__dataclass_fields__
        if name != "case_id"
    )
    assert dict(projection)["claims"] == (digest, digest)


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
    foreign = model.AuthorityJustification(**values)
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
    with pytest.raises((TypeError, ValueError), match="init=False"):
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


def test_non_block_identity_is_resolved_from_inventory_not_candidate_subject_list() -> None:
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
    case = build_semantic_case(
        authority_id=authority_id("nonblock-absence"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(
            source_subjects=(entry, effect), candidate_subjects=(entry,),
            candidate_bindings=missing_effect,
        ),
    )
    identity = next(
        cell for cell in case.obligation_index.cells
        if cell.key == model.ObligationKey(
            effect, model.SafetyDimension.IDENTITY_BINDING,
        )
    )
    assert identity.state is model.ObligationState.SATISFIED


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
    assert helper_dimensions == set(REQUIRED_DIMENSIONS[(helper.kind, helper.role)])


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
    with pytest.raises(ValueError, match="premise|record|non-canonical"):
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
    with pytest.raises(ValueError, match="phase|record|non-canonical"):
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
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "0")
    first = _role_subject(model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, "0")
    second_witness = next(
        item for item in proposal.source_identity_catalog.blocks
        if item.anchor_ea == 0x1100
    )
    second = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
        block_ref=second_witness.block_ref,
        anchor_ea=second_witness.anchor_ea,
        locator=model.BlockSubjectLocator(
            second_witness.block_ref, second_witness.anchor_ea,
        ),
    )
    helper = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "0")
    baseline = _complete_inputs(source_subjects=(entry, first, second), candidate_subjects=(entry, first, second, helper), proposal=proposal)
    helper_binding = replace(
        next(item for item in baseline.candidate_inventory.bindings if item.subject == helper),
        native_instruction_eas=(first.anchor_ea, second.anchor_ea),
    )
    candidate_bindings = tuple(
        helper_binding if item.subject == helper else item
        for item in baseline.candidate_inventory.bindings
    )
    # Keep the binding and graph mutation on the same prepared occurrence.
    # Rebuilding the fixture here would mint a second inventory occurrence and
    # make the copied binding foreign even though its coordinates are equal.
    inputs = baseline
    helper_block = next(
        block for block in inputs.candidate_inventory.blocks
        if block.serial == helper_binding.serial
    )
    helper_instructions = tuple(
        model.InventoryInstructionObservation(
            ordinal, ea, 0, 0, model.InsnKind.NOP, None, False, None,
            raw_opcode=0,
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
    case = build_semantic_case(
        authority_id=authority_id("unclaimed-fold-group"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=inputs,
    )
    assert not any(
        type(item.payload) is model.StructuralLineageEvidencePayload
        and item.payload.disposition is model.StructuralDisposition.FOLDED
        for item in case.evidence
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
    proof = values["route_evidence"].route_proofs[0]
    b0 = block_ref("b0")
    b2 = next(
        item.block_ref for item in values["source_identity_catalog"].blocks
        if item.anchor_ea == 0x1100
    )
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
            locator=model.RouteSubjectLocator(proof.proof_id, proof.atomic_group_id, b0, 0x1000, (model.BlockSubjectLocator(b2, 0x1100),)),
    )
    destination = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
        block_ref=b2,
        anchor_ea=0x1100,
        locator=model.BlockSubjectLocator(b2, 0x1100),
    )
    alias = _claim_factory(
        model.LocalAliasEffectScalarizationClaim,
        kind=model.UnflattenClaimKind.LOCAL_ALIAS_EFFECT_SCALARIZATION,
        owner_subject=owner, step_index=0, host_ea=0x1000, host_opcode=1,
        alias_token="alias", base_token="base", host_text_sha1=None, value_size=None,
        step_digest=authority_id("alias-step"), source_generation=3,
    )
    proposal = model.ProposedUnflattenContract(**values)
    canonical_catalog = tuple(
        _subject_factory(
            model.SemanticSubjectRef,
            kind=model.SemanticSubjectKind.BLOCK,
            role=model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK,
            block_ref=item.block_ref,
            anchor_ea=item.anchor_ea,
            locator=model.BlockSubjectLocator(item.block_ref, item.anchor_ea),
        )
        for item in proposal.source_identity_catalog.blocks
    )
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
        source_subjects=(entry, *canonical_catalog, owner, store, route, destination),
        candidate_subjects=(entry, *canonical_catalog, owner, store, route, destination, helper),
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
        source_subjects=(entry, *canonical_catalog, owner, wrong_store, route, destination),
        candidate_subjects=(entry, *canonical_catalog, owner, wrong_store, route, destination, helper),
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


def test_observed_local_alias_scalar_write_shape_is_closed() -> None:
    from d810.ir.flowgraph import InsnKind
    from d810.transforms.unflatten_authority import evaluate, model

    observation = model.InventoryInstructionObservation(
        ordinal=2,
        instruction_ea=0x1800135A4,
        opcode=12,
        width=4,
        instruction_kind=InsnKind.ADD,
        control_transfer_kind=None,
        is_call=False,
        call_kind=None,
        display_text="add    %var_398.4{144}, #1.4, %var_398.4{144}",
        raw_opcode=12,
    )

    assert evaluate._observed_local_alias_scalar_write_matches(
        observation, host_ea=0x1800135A4, base_token="%var_398", width=4,
    )
    assert not evaluate._observed_local_alias_scalar_write_matches(
        replace(observation, instruction_ea=0x1800135A5),
        host_ea=0x1800135A4,
        base_token="%var_398",
        width=4,
    )
    assert not evaluate._observed_local_alias_scalar_write_matches(
        replace(observation, display_text="add %var_398.4, #1.4, %var_399.4"),
        host_ea=0x1800135A4,
        base_token="%var_398",
        width=4,
    )
    assert not evaluate._observed_local_alias_scalar_write_matches(
        replace(observation, instruction_kind=InsnKind.STORE),
        host_ea=0x1800135A4,
        base_token="%var_398",
        width=4,
    )
    assert not evaluate._observed_local_alias_scalar_write_matches(
        replace(observation, is_call=True),
        host_ea=0x1800135A4,
        base_token="%var_398",
        width=4,
    )


def test_local_alias_requires_endpoint_bearing_reachability_path() -> None:
    values = _valid_proposal(model)
    proof = values["route_evidence"].route_proofs[0]
    b0 = block_ref("b0")
    b2 = next(
        item.block_ref for item in values["source_identity_catalog"].blocks
        if item.anchor_ea == 0x1100
    )
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
            locator=model.RouteSubjectLocator(proof.proof_id, proof.atomic_group_id, b0, 0x1000, (model.BlockSubjectLocator(b2, 0x1100),)),
    )
    destination = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
        block_ref=b2,
        anchor_ea=0x1100,
        locator=model.BlockSubjectLocator(b2, 0x1100),
    )
    alias = _claim_factory(
        model.LocalAliasEffectScalarizationClaim,
        kind=model.UnflattenClaimKind.LOCAL_ALIAS_EFFECT_SCALARIZATION,
        owner_subject=owner, step_index=0, host_ea=0x1000, host_opcode=1,
        alias_token="alias", base_token="base", host_text_sha1=None, value_size=None,
        step_digest=authority_id("alias-step"), source_generation=3,
    )
    proposal = model.ProposedUnflattenContract(**values)
    canonical_catalog = tuple(
        _subject_factory(
            model.SemanticSubjectRef,
            kind=model.SemanticSubjectKind.BLOCK,
            role=model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK,
            block_ref=item.block_ref,
            anchor_ea=item.anchor_ea,
            locator=model.BlockSubjectLocator(item.block_ref, item.anchor_ea),
        )
        for item in proposal.source_identity_catalog.blocks
    )
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
        source_subjects=(entry, *canonical_catalog, owner, store, route, destination),
        candidate_subjects=(entry, *canonical_catalog, owner, store, route, destination, helper),
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
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    handler_input = proposal.plan_inputs.authoritative_handlers[0]
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "route-entry")
    destination = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
        block_ref=handler_input.block_ref,
        anchor_ea=handler_input.anchor_ea,
        locator=model.BlockSubjectLocator(
            handler_input.block_ref, handler_input.anchor_ea,
        ),
    )
    handler = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.HANDLER,
        role=model.SemanticSubjectRole.AUTHORITATIVE_HANDLER,
        block_ref=handler_input.block_ref,
        anchor_ea=handler_input.anchor_ea,
        locator=model.HandlerSubjectLocator(
            handler_input.block_ref,
            handler_input.anchor_ea,
            handler_input.normalized_states,
        ),
    )
    terminal = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.TERMINAL,
        role=model.SemanticSubjectRole.TERMINAL_SITE,
        block_ref=handler_input.block_ref,
        anchor_ea=handler_input.anchor_ea,
        locator=model.TerminalSubjectLocator(
            handler_input.block_ref, handler_input.anchor_ea,
            model.TerminalKind.RETURN, handler_input.anchor_ea,
        ),
    )
    case = build_semantic_case(
        authority_id=authority_id("destination-conditionals"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(
            source_subjects=(entry, destination, handler, terminal),
            proposal=proposal,
        ),
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
            proposal=proposal,
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


def test_projected_retirement_cycle_requires_the_exact_minted_retirement_result() -> None:
    """Only the sealed, fully-retired plan cycle may satisfy SCC topology."""

    member0 = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "0")
    member1 = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "1")
    catalog0 = _role_subject(model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK, "0")
    catalog1 = _role_subject(model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK, "1")
    corridor = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.CORRIDOR,
        role=model.SemanticSubjectRole.DISPATCHER_CORRIDOR,
        block_ref=member0.block_ref,
        anchor_ea=member0.anchor_ea,
        locator=model.CorridorSubjectLocator(
            authority_id("retirement-cycle-corridor"),
            member0.block_ref,
            member0.anchor_ea,
            (member0.block_ref, member1.block_ref),
            (member0.anchor_ea, member1.anchor_ea),
        ),
    )
    candidate_catalog = _retirement_catalog(
        model,
        (member0.block_ref, member1.block_ref),
        (member0.anchor_ea, member1.anchor_ea),
        3,
    )
    retirement = _claim_factory(
        model.RetiredDispatcherInfrastructureClaim,
        kind=model.UnflattenClaimKind.RETIRED_DISPATCHER_INFRASTRUCTURE,
        infrastructure_subject=member0,
        corridor_subject=corridor,
        member_subjects=(member0, member1),
        candidate_evidence_ids=tuple(sorted({
            evidence_id
            for item in candidate_catalog.candidates
            for evidence_id in item.evidence_ids
        })),
        source_generation=3,
        candidate_catalog=candidate_catalog,
    )
    proposal_values = _valid_proposal(model)
    proposal_values["plan_inputs"] = replace(
        proposal_values["plan_inputs"],
        shape=model.UnflattenPlanShape.FULL_DISPATCHER_RETIREMENT,
    )
    route_claim = proposal_values["claims"][0]
    entry = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SOURCE_ENTRY,
        block_ref=route_claim.destination_subjects[0].block_ref,
        anchor_ea=route_claim.destination_subjects[0].anchor_ea,
        locator=model.BlockSubjectLocator(
            route_claim.destination_subjects[0].block_ref,
            route_claim.destination_subjects[0].anchor_ea,
        ),
    )
    proposal_values["plan_inputs"] = replace(
        proposal_values["plan_inputs"],
        source_entry_ref=entry.block_ref,
    )
    proposal_base = model.ProposedUnflattenContract(**_valid_proposal(model))
    proposal_values["corridor_coverage_forecast"] = _minimal_corridor_forecast(
        model, proposal_base,
    )
    proposal = model.ProposedUnflattenContract(
        **{
            **proposal_values,
            "claims": tuple(sorted((retirement, route_claim), key=lambda claim: claim.claim_id)),
            "retirement_candidate_catalog": candidate_catalog,
        },
    )
    source_subjects = (
        entry, catalog0, catalog1, member0, member1, corridor,
        route_claim.retired_route_subject, route_claim.destination_subjects[0],
    )
    candidate_bindings = tuple(
        _binding(
            subject,
            model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            4,
            status=(
                model.SubjectBindingStatus.MISSING
                if (
                    subject.block_ref == member1.block_ref
                )
                else model.SubjectBindingStatus.UNIQUE
            ),
            fingerprint=authority_id("candidate-fp"),
        )
        for subject in source_subjects
    )
    inputs = _complete_inputs(
        source_subjects=source_subjects,
        candidate_bindings=candidate_bindings,
        claims=proposal.claims,
        proposal=proposal,
    )
    result = inputs.retirement_phase_result
    assert result is not None
    assert set(evaluator._projected_cycle_authority_refs(inputs)) == set(
        inputs.proposal.retirement_candidate_catalog.candidate_refs
    )
    cycle_refs = frozenset(result.retired_refs)
    assert cycle_refs == frozenset((member1.block_ref,))
    assert all(
        member.classification is model.RetirementPhaseClassification.RETIRED
        and member.candidate_reachable is None
        for member in result.members
        if member.block_ref in cycle_refs
    )

    # RED: the evaluator did not yet have a consumer for the transaction-bound
    # retirement result, so merely minting this authoritative result could not
    # satisfy the projected SCC topology gate.
    covers = getattr(evaluator, "_retirement_cycle_allowance_covers", None)
    assert covers is not None
    assert covers(
        cycle_refs,
        inputs=inputs,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        candidate=inputs.candidate_inventory,
    )
    equal_catalog = replace(inputs.proposal.retirement_candidate_catalog)
    assert equal_catalog == inputs.proposal.retirement_candidate_catalog
    assert equal_catalog is not inputs.proposal.retirement_candidate_catalog
    equal_catalog_proposal = replace(
        inputs.proposal,
        retirement_candidate_catalog=equal_catalog,
    )
    assert covers(
        cycle_refs,
        inputs=SimpleNamespace(
            retirement_phase_result=result,
            proposal=equal_catalog_proposal,
            claims=inputs.claims,
            source_inventory=inputs.source_inventory,
        ),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        candidate=inputs.candidate_inventory,
    )
    assert not covers(
        cycle_refs,
        inputs=SimpleNamespace(
            retirement_phase_result=result,
            proposal=SimpleNamespace(
                retirement_candidate_catalog=SimpleNamespace(
                    catalog_id=authority_id("foreign-retirement-catalog"),
                    member_refs=inputs.proposal.retirement_candidate_catalog.member_refs,
                ),
            ),
            claims=inputs.claims,
            source_inventory=inputs.source_inventory,
        ),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        candidate=inputs.candidate_inventory,
    )
    assert not covers(
        frozenset((*cycle_refs, block_ref("unrelated-cycle"))),
        inputs=inputs,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        candidate=inputs.candidate_inventory,
    )
    assert not covers(
        frozenset(),
        inputs=inputs,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        candidate=inputs.candidate_inventory,
    )
    assert not covers(
        cycle_refs,
        inputs=inputs,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        candidate=inputs.candidate_inventory,
    )
    assert not covers(
        cycle_refs,
        inputs=inputs,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        candidate=SimpleNamespace(
            graph_fingerprint=authority_id("foreign-candidate"),
            generation=inputs.candidate_inventory.generation,
        ),
    )
    assert not covers(
        cycle_refs,
        inputs=inputs,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        candidate=SimpleNamespace(
            graph_fingerprint=inputs.candidate_inventory.graph_fingerprint,
            generation=inputs.candidate_inventory.generation + 1,
        ),
    )
    assert not covers(
        cycle_refs,
        inputs=SimpleNamespace(
            retirement_phase_result=result,
            proposal=inputs.proposal,
            claims=tuple(
                claim for claim in inputs.claims
                if type(claim) is not model.RetiredDispatcherInfrastructureClaim
            ),
            source_inventory=inputs.source_inventory,
        ),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        candidate=inputs.candidate_inventory,
    )
    assert not covers(
        cycle_refs,
        inputs=SimpleNamespace(
            retirement_phase_result=None,
            proposal=inputs.proposal,
            claims=inputs.claims,
            source_inventory=inputs.source_inventory,
        ),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        candidate=inputs.candidate_inventory,
    )

    reminted = object.__new__(model.RetirementPhaseResult)
    for field in result.__dataclass_fields__:
        object.__setattr__(reminted, field, getattr(result, field))
    assert not covers(
        cycle_refs,
        inputs=SimpleNamespace(
            retirement_phase_result=reminted,
            proposal=inputs.proposal,
            claims=inputs.claims,
            source_inventory=inputs.source_inventory,
        ),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        candidate=inputs.candidate_inventory,
    )
    unreachable_member = object.__new__(model.RetirementPhaseMember)
    target_member = next(
        member for member in result.members if member.block_ref in cycle_refs
    )
    for field in target_member.__dataclass_fields__:
        object.__setattr__(
            unreachable_member,
            field,
            True if field == "candidate_reachable" else getattr(target_member, field),
        )
    unreachable_result = object.__new__(model.RetirementPhaseResult)
    for field in result.__dataclass_fields__:
        object.__setattr__(
            unreachable_result,
            field,
            tuple(
                unreachable_member if member is target_member else member
                for member in result.members
            ) if field == "members" else getattr(result, field),
        )
    assert not covers(
        cycle_refs,
        inputs=SimpleNamespace(
            retirement_phase_result=unreachable_result,
            proposal=inputs.proposal,
            claims=inputs.claims,
            source_inventory=inputs.source_inventory,
        ),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        candidate=inputs.candidate_inventory,
    )


def test_retained_route_delivery_cycle_is_outside_projected_cycle_authority() -> None:
    """Dispatcher discovery membership must not imply retirement ownership."""

    route_a = block_ref("retained-route-a")
    route_b = block_ref("retained-route-b")
    retirement = block_ref("retirement-candidate")
    inventory = SimpleNamespace(
        serial_by_ref={route_a: 10, route_b: 11, retirement: 12},
        blocks=(
            SimpleNamespace(serial=10, successor_serials=(10, 11)),
            SimpleNamespace(serial=11, successor_serials=(10,)),
            SimpleNamespace(serial=12, successor_serials=()),
        ),
    )
    broad_dispatcher_members = (route_a, route_b, retirement)
    inputs = SimpleNamespace(
        proposal=SimpleNamespace(
            plan_inputs=SimpleNamespace(
                dispatcher_member_refs=broad_dispatcher_members,
            ),
            retirement_candidate_catalog=SimpleNamespace(
                member_refs=broad_dispatcher_members,
                candidate_refs=(retirement,),
            ),
        ),
        candidate_inventory=SimpleNamespace(
            serial_by_ref={route_a: 10, route_b: 11, retirement: 12},
            physical_entry_reachable_serials=(10, 11, 12),
        ),
        terminal_cycle_phase_results=(),
    )

    assert evaluator._projected_retirement_cycle_refs(
        candidate_refs=broad_dispatcher_members, inventory=inventory,
    ) == (frozenset((route_a, route_b)),)
    assert evaluator._projected_cycle_authority_refs(inputs) == (retirement,)
    assert evaluator._projected_retirement_cycle_refs(
        candidate_refs=evaluator._projected_cycle_authority_refs(inputs),
        inventory=inventory,
    ) == ()


def test_retirement_claim_requires_one_authorized_lineage_per_member() -> None:
    member0 = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "0")
    member1 = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "1")
    catalog0 = _role_subject(model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK, "0")
    catalog1 = _role_subject(model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK, "1")
    corridor_locator = model.CorridorSubjectLocator(
        evaluator._content_id_digest(
            "unflatten.corridor.v1", (member0.block_ref, member1.block_ref),
        ), member0.block_ref, member0.anchor_ea,
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
            (model.BlockSubjectLocator(block_ref("b2"), 0x1100),),
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
    entry = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SOURCE_ENTRY,
        block_ref=route_claim.destination_subjects[0].block_ref,
        anchor_ea=route_claim.destination_subjects[0].anchor_ea,
        locator=model.BlockSubjectLocator(
            route_claim.destination_subjects[0].block_ref,
            route_claim.destination_subjects[0].anchor_ea,
        ),
    )
    proposal_values["plan_inputs"] = replace(
        proposal_values["plan_inputs"], source_entry_ref=entry.block_ref,
    )
    route = route_claim.retired_route_subject
    destination = route_claim.destination_subjects[0]
    retirement_proposal = model.ProposedUnflattenContract(
        **{**proposal_values, "claims": tuple(sorted((retirement, route_claim), key=lambda claim: claim.claim_id),),
           "retirement_candidate_catalog": candidate_catalog}
    )
    complete_inputs = _complete_inputs(
        source_subjects=(
            entry, catalog0, catalog1, member0, member1, corridor, route,
            destination,
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
        if cell.key == model.ObligationKey(catalog0, model.SafetyDimension.STRUCTURAL_ACCOUNTING)
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
        source_subjects=(entry, catalog0, catalog1, member0, member1, corridor, route, destination),
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
    from d810.transforms.unflatten_authority.bind import bind_retired_dispatcher_infrastructure_claim
    # Reachability is now derived and sealed by SemanticGraphInventory.  A
    # hand-edited entry/closure pair is no longer an admissible candidate graph
    # for the retirement binder.
    with pytest.raises(ValueError, match="entry_serial must refer"):
        bind_retired_dispatcher_infrastructure_claim(
            claim=retirement, proposal=retirement_proposal,
            source_inventory=unreachable_inputs.source_inventory,
            projected_inventory=unreachable_inputs.candidate_inventory,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        )

    incomplete_inputs = _complete_inputs(
        source_subjects=(entry, catalog0, catalog1, member0, member1, corridor, route, destination),
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
    invalid_verdict = evaluate_case(incomplete)
    assert not invalid_verdict.accepted
    assert invalid_verdict.safety_case is incomplete
    assert invalid_verdict.reason in {
        model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
        model.UnflattenAuthorityReason.OBLIGATION_VIOLATED,
    }
    member1_structural = next(
        cell for cell in incomplete.obligation_index.cells
        if cell.key == model.ObligationKey(
            catalog1, model.SafetyDimension.STRUCTURAL_ACCOUNTING,
        )
    )
    assert member1_structural.state is model.ObligationState.SATISFIED
    assert not member1_structural.refuting_justification_ids
    corridor_coverage = next(
        cell for cell in incomplete.obligation_index.cells
        if cell.key == model.ObligationKey(corridor, model.SafetyDimension.CORRIDOR_COVERAGE)
    )
    assert corridor_coverage.state is model.ObligationState.SATISFIED
    invalid_view = views.retired_infrastructure_view(incomplete, retirement.claim_id)
    assert invalid_view.drifted_member_subject_ids == (member1.subject_id,)
    assert invalid_view.unaccounted_member_subject_ids == ()
    assert member1.subject_id not in invalid_view.retired_member_subject_ids
    assert member1.subject_id not in invalid_view.retained_member_subject_ids
    with pytest.raises(ValueError, match="satisfied structural cell"):
        views.retirement_rows(
            incomplete,
            build_semantic_loss_ledger(incomplete, invalid_verdict),
            retirement.claim_id,
        )

    reduced_candidates = tuple(
        item for item in candidate_catalog.candidates
        if item.block_ref != member1.block_ref
    )
    reduced_catalog = model.RetirementCandidateCatalog(
        canonical_authority_id((
            "unflatten.dispatcher-retirement-candidate-catalog.v1",
            candidate_catalog.source_generation,
            candidate_catalog.plan_members,
            reduced_candidates,
        )),
        candidate_catalog.source_generation,
        candidate_catalog.plan_members,
        reduced_candidates,
    )
    unsupported_retirement = _claim_factory(
        model.RetiredDispatcherInfrastructureClaim,
        kind=model.UnflattenClaimKind.RETIRED_DISPATCHER_INFRASTRUCTURE,
        infrastructure_subject=member0,
        corridor_subject=corridor,
        member_subjects=(member0,),
        candidate_evidence_ids=tuple(sorted({
            evidence_id
            for item in reduced_catalog.candidates
            for evidence_id in item.evidence_ids
        })),
        source_generation=3,
        candidate_catalog=reduced_catalog,
    )
    unsupported_proposal = replace(
        retirement_proposal,
        claims=tuple(sorted((unsupported_retirement, route_claim), key=lambda claim: claim.claim_id)),
        plan_inputs=replace(
            retirement_proposal.plan_inputs,
            shape=model.UnflattenPlanShape.PARTIAL_REWRITE,
        ),
        retirement_candidate_catalog=reduced_catalog,
    )
    candidate_missing_bindings = tuple(
        replace(
            binding,
            status=model.SubjectBindingStatus.MISSING,
            block_ref=None,
            serial=None,
            anchor_ea=None,
            native_instruction_eas=(),
        )
        if binding.subject == member1
        else binding
        for binding in incomplete_inputs.candidate_inventory.bindings
    )
    unsupported_inputs = _complete_inputs(
        source_subjects=(entry, catalog0, catalog1, member0, member1, corridor, route, destination),
        claims=unsupported_proposal.claims,
        proposal=unsupported_proposal,
        candidate_bindings=candidate_missing_bindings,
    )
    assert member1.block_ref not in unsupported_inputs.proposal.retirement_candidate_catalog.candidate_refs
    unsupported = build_semantic_case(
        authority_id=authority_id("retirement-unsupported"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=unsupported_inputs,
    )
    unsupported_verdict = evaluate_case(unsupported)
    assert not unsupported_verdict.accepted
    assert unsupported_verdict.safety_case is unsupported
    unsupported_phase_member = next(
        item for item in unsupported_inputs.retirement_phase_result.members
        if item.block_ref == member1.block_ref
    )
    assert unsupported_phase_member.classification is model.RetirementPhaseClassification.UNACCOUNTED, (
        unsupported_phase_member.classification,
        unsupported_phase_member.reason,
        unsupported_phase_member.candidate_id,
        unsupported_inputs.proposal.retirement_candidate_catalog.candidate_refs,
    )
    unsupported_structural = next(
        cell for cell in unsupported.obligation_index.cells
        if cell.key == model.ObligationKey(
            catalog1, model.SafetyDimension.STRUCTURAL_ACCOUNTING,
        )
    )
    assert unsupported_structural.state is model.ObligationState.SATISFIED
    assert not unsupported_structural.refuting_justification_ids
    unsupported_view = views.retired_infrastructure_view(
        unsupported, unsupported_retirement.claim_id,
    )
    assert unsupported_view.unaccounted_member_subject_ids == (member1.subject_id,)
    assert member1.subject_id not in unsupported_view.retired_member_subject_ids
    assert member1.subject_id not in unsupported_view.retained_member_subject_ids
    with pytest.raises(ValueError, match="satisfied structural cell"):
        views.retirement_rows(
            unsupported,
            build_semantic_loss_ledger(unsupported, unsupported_verdict),
            unsupported_retirement.claim_id,
        )


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
    catalog0 = _role_subject(model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK, "0")
    catalog1 = _role_subject(model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK, "1")
    route_claim = base.claims[0]
    inputs = _complete_inputs(
        source_subjects=(
            entry, catalog0, catalog1, member0, member1,
            route_claim.retired_route_subject, *route_claim.destination_subjects,
        ),
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
        if cell.key == model.ObligationKey(catalog0, model.SafetyDimension.STRUCTURAL_ACCOUNTING)
    )
    retained_cell = next(
        cell for cell in case.obligation_index.cells
        if cell.key == model.ObligationKey(catalog1, model.SafetyDimension.STRUCTURAL_ACCOUNTING)
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
    verdict = evaluate_case(case)
    ledger = build_semantic_loss_ledger(case, verdict)
    ledger_row = next(
        row for row in views.semantic_loss_projection(ledger).rows
        if row.source_subject.subject_id == catalog0.subject_id
    )
    assert ledger_row.kind is model.SemanticLossKind.RETIRED_DISPATCHER_INFRASTRUCTURE
    retirement_view = views.retired_infrastructure_view(case, claim.claim_id)
    assert retirement_view.claim_id == claim.claim_id
    assert retirement_view.retired_member_subject_ids == (member0.subject_id,)
    assert retirement_view.retained_member_subject_ids == (member1.subject_id,)
    assert retirement_view.structural_cell_keys == (retired_cell.key,)
    assert views.retirement_rows(case, ledger, claim.claim_id) == retirement_view
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
        effect, subject, source_binding, candidate_binding, effect, None, None, None, None,
    )
    assert present.preserved
    assert not present.authorized_loss
    missing = _classify_effect_site(
        effect, subject, source_binding, candidate_binding, None, None, None, None, None,
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
            (replace(effect, effect_kind=candidate_kind),), None, None, None, None,
        )
        assert kind_drift.refuted
        assert not kind_drift.authorized_loss
    duplicate = _classify_effect_site(
        effect, subject, source_binding, candidate_binding,
        (effect, effect), None, None, None, None,
    )
    assert duplicate.refuted
    wrong_owner_serial = _classify_effect_site(
        effect, subject, source_binding, candidate_binding,
        (replace(effect, owner_serial=1),), None, None, None, None,
    )
    assert wrong_owner_serial.refuted


def test_effect_classifier_consumes_sealed_relation_clone_coordinate() -> None:
    """A relation clone is checked at its canonical projected owner."""

    from . import test_bind
    from d810.transforms.unflatten_authority import bind

    family = next(
        item for item in test_bind._MECHANICAL_FAMILY_CASES
        if item.family == "CC"
    )
    values = family.values_from_case(family.build())
    result = bind.realize_projected_routes(**values)
    assert type(result) is model.ProjectedRouteRealizationAccepted
    realization = result.realization
    sealed = next(
        item for item in realization.site_phase_result.effect_results
        if item.outcome is model.ProjectedEffectSiteOutcome.RELATION_CLONED
    )
    subject = next(
        item for item in values["source_inventory"].subjects
        if item.subject_id == sealed.source_subject_id
    )
    source_binding = next(
        item for item in values["source_inventory"].bindings
        if item.subject.subject_id == sealed.source_subject_id
    )
    projected_binding = next(
        item for item in values["projected_inventory"].bindings
        if item.subject.subject_id == sealed.projected_subject_id
    )
    effect = next(
        item for item in values["source_inventory"].effects
        if item.owner_ref == sealed.source_site.owner.ref
        and item.owner_anchor_ea == sealed.source_site.owner.anchor_ea
        and item.instruction_ea == sealed.source_site.instruction_ea
        and item.effect_kind is sealed.source_site.effect_kind
    )
    projected_effect = next(
        item for item in values["projected_inventory"].effects
        if item.owner_ref == sealed.projected_site.owner.ref
        and item.owner_anchor_ea == sealed.projected_site.owner.anchor_ea
        and item.instruction_ea == sealed.projected_site.instruction_ea
        and item.effect_kind is sealed.projected_site.effect_kind
    )

    classified = _classify_effect_site(
        effect,
        subject,
        source_binding,
        projected_binding,
        projected_effect,
        None,
        values["source_authority"],
        realization,
        None,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )

    assert classified.preserved
    assert not classified.refuted


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
        (candidate,), None, None, None, None,
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


def test_effect_classifier_consumes_real_sealed_projected_site_rows() -> None:
    """Direct preparation supplies the classifier's closed authority inputs."""
    from d810.transforms.cfg_transaction import CfgProjection
    from d810.transforms.unflatten_authority import transaction_api
    from .test_transaction_api import _c1_direct_preparation_case

    fixture, source, plan, projected, gate_bundle = _c1_direct_preparation_case()
    prepared = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gate_bundle,
    ).prepared
    inputs = prepared.source_inputs
    site_row = inputs.projected_route_realization.site_phase_result.effect_results[0]
    subject = next(
        item for item in inputs.source_inventory.subjects
        if item.subject_id == site_row.source_subject_id
    )
    source_binding = next(
        item for item in inputs.source_inventory.bindings
        if item.subject is subject
    )
    candidate_binding = next(
        item for item in inputs.candidate_inventory.bindings
        if item.subject.subject_id == subject.subject_id
    )
    effect = next(
        item for item in inputs.source_inventory.effects
        if item.instruction_ea == subject.locator.instruction_ea
        and item.effect_kind is subject.locator.effect_kind
    )
    candidate_effect = next(
        item for item in inputs.candidate_inventory.effects
        if item.instruction_ea == effect.instruction_ea
        and item.effect_kind is effect.effect_kind
    )
    result = _classify_effect_site(
        effect, subject, source_binding, candidate_binding, candidate_effect,
        None, inputs.source_route_authority, inputs.projected_route_realization,
        inputs.generic_gate_facts,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    assert result.preserved
    assert not result.authorized_loss


def _sealed_exact_effect_classifier_inputs(effect_kind: str = "call"):
    """Return one real binder-owned exact-loss row and its closed inputs."""
    from . import test_bind
    from d810.transforms.unflatten_authority import bind

    values = test_bind._task_15_vertical_inputs(
        lambda: test_bind._task_15_exact_direct_case(effect_kind),
    )
    realization_result = bind.realize_projected_routes(**values)
    assert type(realization_result) is model.ProjectedRouteRealizationAccepted
    realization = realization_result.realization
    claim = next(
        item for item in values["claims"]
        if type(item) is model.ExactInfeasibleEffectClaim
    )
    subject = claim.discarded_effect_subject
    source_binding = next(
        item for item in values["source_inventory"].bindings
        if item.subject.subject_id == subject.subject_id
    )
    candidate_binding = next(
        item for item in values["projected_inventory"].bindings
        if item.subject.subject_id == subject.subject_id
    )
    effect = next(
        item for item in values["source_inventory"].effects
        if item.instruction_ea == claim.discarded_effect_ea
        and item.effect_kind is subject.locator.effect_kind
    )
    return values, realization, claim, subject, source_binding, candidate_binding, effect


def test_effect_classifier_authorizes_only_exact_missing_site_with_sealed_inputs() -> None:
    values, realization, claim, subject, source_binding, missing_binding, effect = (
        _sealed_exact_effect_classifier_inputs()
    )
    assert missing_binding.status is model.SubjectBindingStatus.MISSING
    authorized = _classify_effect_site(
        effect, subject, source_binding, missing_binding, None, claim,
        values["source_authority"], realization, None,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    assert authorized.authorized_loss
    assert authorized.claim is claim
    foreign_claim = next(
        item for item in values["claims"]
        if type(item) is model.EquivalentSemanticRouteClaim
    )
    rejected = _classify_effect_site(
        effect, subject, source_binding, missing_binding, None, foreign_claim,
        values["source_authority"], realization, None,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    assert rejected.refuted
    assert not rejected.authorized_loss


def test_same_owner_missing_claim_does_not_authorize_unclaimed_sibling() -> None:
    values, realization, claim, subject, source_binding, missing_binding, effect = (
        _sealed_exact_effect_classifier_inputs()
    )
    sibling_locator = replace(
        subject.locator,
        instruction_ea=subject.locator.instruction_ea + 1,
    )
    sibling = _subject_factory(
        model.SemanticSubjectRef,
        kind=subject.kind,
        role=subject.role,
        block_ref=subject.block_ref,
        anchor_ea=subject.anchor_ea,
        locator=sibling_locator,
    )
    sibling_effect = replace(effect, instruction_ea=effect.instruction_ea + 1)
    sibling_binding = replace(missing_binding, subject=sibling)
    rejected = _classify_effect_site(
        sibling_effect, sibling, source_binding, sibling_binding, None, claim,
        values["source_authority"], realization, None,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    assert rejected.refuted
    assert not rejected.authorized_loss


def test_exact_infeasible_effect_authorizes_classified_discarded_loss() -> None:
    """Public preparation owns the Direct exact-effect realization."""

    from d810.analyses.control_flow.graph_checks import (
        check_effectful_reachability_preserved,
        check_entry_reachability_not_collapsed,
        check_terminal_reachability_preserved,
    )
    from d810.transforms.cfg_transaction import CfgProjection
    from d810.transforms.edit_simulator import project_post_state
    from d810.transforms.unflatten_authority import transaction_api
    from d810.transforms.unflatten_authority.gates import GenericCfgGateBundle
    from d810.transforms.unflatten_authority.proposal import (
        ProposalAccepted,
        canonical_redirect_manifest,
        validate_proposal,
    )
    from . import test_bind

    raw = test_bind._task_15_exact_direct_case(
        "call", include_source_context=True,
    )
    plan, attempt_id, source_graph = raw[1], raw[5], raw[6]
    # The compiler fixture is intentionally raw input: give the public
    # transaction its normal immutable snapshot identifier before validation.
    plan = replace(plan, snapshot_id=authority_id(f"c1-exact-direct:{plan.plan_id}"))

    # The fixture's proposal predates the compiler's final redirect manifest.
    # Reclose that witness exactly as the public proposal validator requires.
    manifest = canonical_redirect_manifest(plan)
    proposal = replace(
        plan.unflatten_proposal,
        use_def_witness=replace(
            plan.unflatten_proposal.use_def_witness,
            redirect_owner_refs=manifest.owner_refs,
            redirect_digest=manifest.digest,
        ),
    )
    plan = replace(plan, unflatten_proposal=proposal)
    validation = validate_proposal(plan, proposal)
    assert type(validation) is ProposalAccepted

    projected_graph = project_post_state(source_graph, plan)
    raw_effect_gate = check_effectful_reachability_preserved(
        source_graph, post_cfg=projected_graph,
    )
    generic_gates = GenericCfgGateBundle(
        check_entry_reachability_not_collapsed(source_graph, post_cfg=projected_graph),
        raw_effect_gate,
        raw_effect_gate,
        check_terminal_reachability_preserved(source_graph, post_cfg=projected_graph),
    )
    result = transaction_api.prepare_unflatten_authority(
        source=source_graph,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected_graph),
        plan=plan,
        attempt_id=attempt_id,
        generic_gates=generic_gates,
    )
    assert type(result) is model.UnflattenAuthorityPreparationAccepted
    ledger = result.prepared.projected_loss_ledger
    assert ledger is not None
    # The discarded CALL instruction vanished while its native owner block
    # survived. The single canonical owner row carries that semantic delta;
    # it does not create a second instruction-level loss authority.
    realization = result.prepared.projected_route_realization
    exact_claim = next(
        claim for claim in proposal.claims
        if type(claim) is model.ExactInfeasibleEffectClaim
    )
    assert len(ledger.rows) == 1
    assert ledger.rows[0].kind is model.SemanticLossKind.EXACT_INFEASIBLE_EFFECT
    assert ledger.rows[0].source_subject.role is model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK
    assert ledger.rows[0].claim_ids == (exact_claim.claim_id,)
    case = result.prepared.projected_case
    effect_cell = next(
        cell for cell in case.obligation_index.cells
        if cell.key == model.ObligationKey(
            exact_claim.discarded_effect_subject,
            model.SafetyDimension.EFFECT_PRESERVATION,
        )
    )
    assert effect_cell.state is model.ObligationState.SATISFIED
    support = next(
        item for item in case.justifications
        if item.conclusion == effect_cell.key
        and item.rule is model.UnflattenJustificationRule.EXACT_INFEASIBLE_EFFECT_PROVEN
    )
    assert support.claim_id == exact_claim.claim_id
    assert len(support.premise_ids) == 1
    effect = realization.site_phase_result.effect_results
    assert len(effect) == 1
    result = effect[0]
    assert result.outcome is model.ProjectedEffectSiteOutcome.EXACT_INFEASIBLE
    assert result.source_subject_id == exact_claim.discarded_effect_subject.subject_id
    assert result.source_site.instruction_ea == exact_claim.discarded_effect_ea == 0x4000
    assert result.supporting_claim_id == exact_claim.claim_id
    assert result.supporting_binding_result_id in {
        row.binding_result_id
        for row in realization.site_phase_result.exact_effect_bindings
    }
    assert result.projected_subject_id is None
    assert result.projected_site is None



def test_terminal_cycle_carrier_does_not_duplicate_corridor_coverage_obligation() -> None:
    """Only the canonical dispatcher corridor owns coverage completeness."""

    from .test_bind import _terminal_cycle_derived_inputs

    proposal, claim, _inputs, source, _candidate, _residual = (
        _terminal_cycle_derived_inputs()
    )
    cycle = claim.cycle_subject
    catalog = {item.block_ref: item for item in proposal.source_identity_catalog.blocks}
    refs = proposal.plan_inputs.dispatcher_member_refs
    canonical = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.CORRIDOR,
        role=model.SemanticSubjectRole.DISPATCHER_CORRIDOR,
        block_ref=proposal.plan_inputs.dispatcher_entry_ref,
        anchor_ea=catalog[proposal.plan_inputs.dispatcher_entry_ref].anchor_ea,
        locator=model.CorridorSubjectLocator(
            content_id("unflatten.corridor.v1", refs),
            proposal.plan_inputs.dispatcher_entry_ref,
            catalog[proposal.plan_inputs.dispatcher_entry_ref].anchor_ea,
            refs,
            tuple(catalog[ref].anchor_ea for ref in refs),
        ),
    )

    dimensions = _dimensions(
        (canonical, cycle),
        (claim,),
        source.bindings,
        proposal=proposal,
    )

    assert model.ObligationKey(
        canonical, model.SafetyDimension.CORRIDOR_COVERAGE,
    ) in dimensions
    assert model.ObligationKey(
        cycle, model.SafetyDimension.CORRIDOR_COVERAGE,
    ) not in dimensions


def test_terminal_cycle_carrier_cannot_ambiguate_canonical_coverage_corridor() -> None:
    """Coverage selects the plan-owned corridor, not a claim-local cycle."""

    from .test_bind import _terminal_cycle_derived_inputs

    proposal, claim, _inputs, _source, _candidate, _residual = (
        _terminal_cycle_derived_inputs()
    )
    catalog = {
        item.block_ref: item for item in proposal.source_identity_catalog.blocks
    }
    refs = proposal.plan_inputs.dispatcher_member_refs
    canonical = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.CORRIDOR,
        role=model.SemanticSubjectRole.DISPATCHER_CORRIDOR,
        block_ref=proposal.plan_inputs.dispatcher_entry_ref,
        anchor_ea=catalog[proposal.plan_inputs.dispatcher_entry_ref].anchor_ea,
        locator=model.CorridorSubjectLocator(
            content_id("unflatten.corridor.v1", refs),
            proposal.plan_inputs.dispatcher_entry_ref,
            catalog[proposal.plan_inputs.dispatcher_entry_ref].anchor_ea,
            refs,
            tuple(catalog[ref].anchor_ea for ref in refs),
        ),
    )

    selected = _canonical_dispatcher_corridor_subject(
        (canonical, claim.cycle_subject), proposal,
    )

    assert selected is canonical


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
        and subject.block_ref
        == proposal.plan_inputs.source_entry_ref
    )
    handler = next(
        subject for subject in source.subjects
        if subject.role is model.SemanticSubjectRole.AUTHORITATIVE_HANDLER
        and subject.block_ref
        == proposal.plan_inputs.authoritative_handlers[0].block_ref
    )
    assert len(inputs.terminal_cycle_phase_results) == 1
    case = build_semantic_case(
        authority_id=authority_id("terminal-cycle-scope"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=inputs,
    )
    by_key = {cell.key: cell for cell in case.obligation_index.cells}

    canonical_cycle = next(
        subject for subject in source.subjects
        if subject.role is model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK
        and subject.block_ref == cycle.block_ref
    )
    cycle_cell = by_key[
        model.ObligationKey(canonical_cycle, model.SafetyDimension.STRUCTURAL_ACCOUNTING)
    ]
    assert cycle_cell.state is model.ObligationState.SATISFIED
    assert any(
        item.claim_id == claim.claim_id
        for item in case.justifications
        if item.conclusion == cycle_cell.key
    )
    canonical_cleanup = next(
        subject for subject in source.subjects
        if subject.role is model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK
        and subject.block_ref == cleanup.block_ref
    )
    cleanup_cell = by_key[
        model.ObligationKey(canonical_cleanup, model.SafetyDimension.STRUCTURAL_ACCOUNTING)
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
    assert all(
        cell.key.subject.role is model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK
        for cell in case.obligation_index.cells
        if cell.key.dimension is model.SafetyDimension.STRUCTURAL_ACCOUNTING
        and cell.key.subject in source.subjects
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
        source_route_authority=inputs.source_route_authority,
        projected_route_realization=inputs.projected_route_realization,
        conditional_relations=inputs.conditional_relations,
        patch_step_facts=inputs.patch_step_facts,
    )
    with pytest.raises(
        ValueError,
        match=(
            "projected phase must reference|projected phase must match its candidate inventory"
            "|residue topology"
        ),
    ):
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
    with pytest.raises(ValueError, match="not minted by the transaction binder|terminal path"):
        replace(inputs, terminal_cycle_phase_results=(false_result,))


def test_terminal_cycle_admission_requires_exact_binder_phase_occurrence() -> None:
    """Prepared inputs and semantic cases reject equal, reissued terminal authority."""

    from .test_bind import _terminal_cycle_derived_inputs

    _proposal, _claim, inputs, _source, _candidate, _residual = (
        _terminal_cycle_derived_inputs()
    )
    minted = inputs.terminal_cycle_phase_results[0]
    expected_cycle_refs = set(minted.residue_refs)
    if inputs.proposal.retirement_candidate_catalog is not None:
        expected_cycle_refs.update(
            inputs.proposal.retirement_candidate_catalog.candidate_refs,
        )
    assert set(evaluator._projected_cycle_authority_refs(inputs)) == expected_cycle_refs
    assert replace(inputs, terminal_cycle_phase_results=(minted,))
    equal_but_distinct = replace(minted)
    with pytest.raises(ValueError, match="not minted by the transaction binder"):
        replace(inputs, terminal_cycle_phase_results=(equal_but_distinct,))

    case = build_semantic_case(
        authority_id=authority_id("terminal-cycle-exact-admission"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=inputs,
    )
    assert replace(case, terminal_cycle_phase_results=(minted,))
    with pytest.raises(ValueError, match="not minted by the transaction binder"):
        replace(case, terminal_cycle_phase_results=(equal_but_distinct,))
