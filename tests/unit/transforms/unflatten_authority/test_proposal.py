"""Task 5 proposal-channel and plan-route contracts."""

from __future__ import annotations

import hashlib
from dataclasses import replace
import inspect

import pytest

from d810.transforms.plan import PatchPlan
from d810.transforms.unflatten_authority.ids import authority_id


def test_canonical_patch_step_descriptor_api_is_the_single_identity_owner() -> None:
    from d810.transforms.unflatten_authority import proposal

    assert hasattr(proposal, "CanonicalPatchStepDescriptor")
    assert callable(proposal.canonical_patch_step_descriptors)
    assert callable(proposal.canonical_patch_step_descriptor)


def test_corridor_forecast_adapter_accepts_prebuilt_default_gap_exclusions() -> None:
    from d810.transforms.unflatten_authority import proposal

    assert "default_gap_infeasibility_exclusions" in inspect.signature(
        proposal.corridor_coverage_forecast_from_analysis
    ).parameters


def test_default_gap_producer_derives_only_exact_u32_default_loop() -> None:
    """The producer may propose the typed gap only from closed route evidence."""
    from dataclasses import replace

    from d810.analyses.control_flow.route_predicate import DecisionDag, RouteComparison
    from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
    from d810.transforms.dispatcher_corridor_coverage import (
        DispatcherBlockAnchor, DispatcherCorridor, DispatcherCorridorCoverage,
    )
    from d810.transforms.unflatten_authority import proposal as proposal_api
    from .helpers import exact_fixture

    source, contract, _effect, refs = exact_fixture()
    # Residual default block 3 is an exact one-edge control-only loop to the
    # dispatcher.  The selected canonical proof supplies state 7.
    blocks = dict(source.blocks)
    original = blocks[3]
    blocks[3] = BlockSnapshot(
        original.serial, original.block_type, (1,), original.preds, original.flags,
        original.start_ea, (InsnSnapshot(0, original.start_ea, (), kind=InsnKind.GOTO, raw_opcode=0),),
        tail_opcode=0, kind=original.kind, tail_kind=InsnKind.GOTO,
    )
    blocks[1] = replace(blocks[1], preds=tuple(sorted((*blocks[1].preds, 3))))
    source = FlowGraph(blocks, source.entry_serial, source.func_ea)
    coverage = DispatcherCorridorCoverage(
        source.func_ea, DispatcherBlockAnchor(1, 0x2000),
        (DispatcherCorridor((DispatcherBlockAnchor(0, 0x1000), DispatcherBlockAnchor(1, 0x2000))),),
        (DispatcherCorridor((DispatcherBlockAnchor(3, 0x4000), DispatcherBlockAnchor(1, 0x2000))),),
        True,
    )
    dag = DecisionDag(32, {1: RouteComparison(1, "jz", 7, 2, 3)}, 1)

    exclusions = proposal_api._derive_default_gap_infeasibility_exclusions(
        source=source, proposal=contract, block_refs_by_serial=refs,
        selected_route_proof_ids=(contract.route_evidence.route_proofs[0].proof_id,),
        corridor_coverage=coverage, condition_chain_dag=dag,
        default_entry_serial=3,
    )

    assert len(exclusions) == 1
    assert exclusions[0].default_entry.block_ref == refs[3]
    assert exclusions[0].residual.block_ref == refs[3]
    assert exclusions[0].normalized_reachable_states == (7,)


def test_default_gap_producer_derives_connected_two_node_eq_chain() -> None:
    """A selected non-default state may traverse a closed multi-node EQ chain."""
    from dataclasses import replace

    from d810.analyses.control_flow.route_predicate import DecisionDag, RouteComparison
    from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot, MopSnapshot, OperandKind, PredicateKind
    from d810.transforms.dispatcher_corridor_coverage import (
        DispatcherBlockAnchor, DispatcherCorridor, DispatcherCorridorCoverage,
    )
    from d810.transforms.unflatten_authority import proposal as proposal_api
    from .helpers import exact_fixture

    source, contract, _effect, refs = exact_fixture()
    blocks = dict(source.blocks)
    state = MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=4, stack_refs=(4,))
    constant = MopSnapshot(kind=OperandKind.NUMBER, size=4, value=8)
    target = MopSnapshot(kind=OperandKind.BLOCK, block_ref=2)
    blocks[3] = BlockSnapshot(
        3, 0, (4, 2), (1,), 0, 0x4000,
        (InsnSnapshot(0, 0x4000, (), l=state, r=constant, d=target,
                      kind=InsnKind.COND_JUMP, branch_predicate=PredicateKind.EQ,
                      is_conditional_jump=True, raw_opcode=0),),
        tail_opcode=0, kind=BlockKind.TWO_WAY, tail_kind=InsnKind.COND_JUMP,
    )
    blocks[4] = BlockSnapshot(
        4, 0, (1,), (3,), 0, 0x5000,
        (InsnSnapshot(0, 0x5000, (), kind=InsnKind.GOTO, raw_opcode=0),),
        tail_opcode=0, kind=BlockKind.ONE_WAY, tail_kind=InsnKind.GOTO,
    )
    blocks[1] = replace(blocks[1], preds=(0, 4))
    blocks[2] = replace(blocks[2], preds=(1, 3))
    source = FlowGraph(blocks, source.entry_serial, source.func_ea)
    coverage = DispatcherCorridorCoverage(
        source.func_ea, DispatcherBlockAnchor(1, 0x2000),
        (DispatcherCorridor((DispatcherBlockAnchor(0, 0x1000), DispatcherBlockAnchor(1, 0x2000))),),
        (DispatcherCorridor((DispatcherBlockAnchor(4, 0x5000), DispatcherBlockAnchor(1, 0x2000))),),
        True,
    )
    dag = DecisionDag(32, {
        1: RouteComparison(1, "jz", 7, 2, 3),
        3: RouteComparison(3, "jz", 8, 2, 4),
    }, 1)

    exclusions = proposal_api._derive_default_gap_infeasibility_exclusions(
        source=source, proposal=contract, block_refs_by_serial=refs,
        selected_route_proof_ids=(contract.route_evidence.route_proofs[0].proof_id,),
        corridor_coverage=coverage, condition_chain_dag=dag,
        default_entry_serial=4,
    )

    assert len(exclusions) == 1
    assert exclusions[0].dispatcher.block_ref == refs[1]
    assert exclusions[0].default_entry.block_ref == refs[4]
    assert exclusions[0].residual.block_ref == refs[4]


def test_attach_typed_proposal_installs_default_gap_before_retirement_claims() -> None:
    """Attachment must install the sibling ledger before it asks for retirement."""
    from dataclasses import replace

    from d810.analyses.control_flow.route_predicate import DecisionDag, RouteComparison
    from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot, MopSnapshot, OperandKind, PredicateKind
    from d810.transforms.dispatcher_corridor_coverage import (
        DispatcherBlockAnchor, DispatcherCorridor, DispatcherCorridorCoverage,
        RetiredDispatcherInfrastructure,
    )
    from d810.transforms.plan import PatchPlan, PatchRedirectGoto
    from d810.transforms.unflatten_authority import model, proposal as proposal_api
    from .helpers import exact_fixture

    source, contract, _effect, refs = exact_fixture()
    blocks = dict(source.blocks)
    state = MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=4, stack_refs=(4,))
    constant = MopSnapshot(kind=OperandKind.NUMBER, size=4, value=8)
    target = MopSnapshot(kind=OperandKind.BLOCK, block_ref=2)
    blocks[3] = BlockSnapshot(
        3, 0, (4, 2), (1,), 0, 0x4000,
        (InsnSnapshot(0, 0x4000, (), l=state, r=constant, d=target,
                      kind=InsnKind.COND_JUMP, branch_predicate=PredicateKind.EQ,
                      is_conditional_jump=True, raw_opcode=0),),
        tail_opcode=0, kind=BlockKind.TWO_WAY, tail_kind=InsnKind.COND_JUMP,
    )
    blocks[4] = BlockSnapshot(
        4, 0, (1,), (3,), 0, 0x5000,
        (InsnSnapshot(0, 0x5000, (), kind=InsnKind.GOTO, raw_opcode=0),),
        tail_opcode=0, kind=BlockKind.ONE_WAY, tail_kind=InsnKind.GOTO,
    )
    blocks[1] = replace(blocks[1], preds=(0, 4))
    blocks[2] = replace(blocks[2], preds=(1, 3))
    source = FlowGraph(blocks, source.entry_serial, source.func_ea)
    dispatcher = DispatcherBlockAnchor(1, 0x2000)
    coverage = DispatcherCorridorCoverage(
        source.func_ea, dispatcher,
        (DispatcherCorridor((DispatcherBlockAnchor(0, 0x1000), dispatcher)),),
        (DispatcherCorridor((DispatcherBlockAnchor(4, 0x5000), dispatcher)),), True,
        retirement_candidates=(RetiredDispatcherInfrastructure("comparison_dispatcher", dispatcher),),
    )
    template = PatchPlan(
        plan_id=contract.plan_id, snapshot_id="default-gap-attach", source_generation=1,
        steps=(PatchRedirectGoto(refs[0], refs[1], refs[2]),),
    )
    manifest = proposal_api.canonical_redirect_manifest(template)
    witness = replace(
        contract.use_def_witness, redirect_owner_refs=manifest.owner_refs,
        redirect_digest=manifest.digest,
    )
    attached = proposal_api.attach_typed_proposal(
        template, source=source, block_refs_by_serial=refs,
        canonical_route_evidence=contract.route_evidence,
        selected_route_proof_ids=(contract.route_evidence.route_proofs[0].proof_id,),
        exact_state_effect_exclusions=(), dispatcher_entry_serial=1,
        dispatcher_member_serials=(1,), authoritative_handler_serials=(2,),
        state_identity=contract.plan_inputs.state_identity, use_def_witness=witness,
        corridor_coverage=coverage, dispatcher_removal_forecast=coverage,
        condition_chain_dag=DecisionDag(32, {
            1: RouteComparison(1, "jz", 7, 2, 3),
            3: RouteComparison(3, "jz", 8, 2, 4),
        }, 1),
        default_entry_serial=4,
    )

    forecast = attached.unflatten_proposal.corridor_coverage_forecast
    assert type(forecast) is model.DefaultGapInfeasibilityForecast
    assert len(forecast.exclusions) == len(forecast.paths) == 1
    assert forecast.exclusions[0].default_entry.block_ref == refs[4]
    assert attached.unflatten_proposal.retirement_candidate_catalog is not None
    assert attached.unflatten_proposal.plan_inputs.shape is model.UnflattenPlanShape.FULL_DISPATCHER_RETIREMENT
    assert any(type(claim) is model.RetiredDispatcherInfrastructureClaim
               for claim in attached.unflatten_proposal.claims)


@pytest.mark.parametrize("mutation", [
    "no_dag", "incomplete", "wrong_default", "foreign_default_leaf",
    "foreign_root", "true_arm_default", "disconnected_node", "wrong_identity",
    "wrong_constant", "wrong_explicit_target",
])
def test_default_gap_producer_fails_closed_for_non_exact_shape(mutation: str) -> None:
    """No topology shortcut may mint a producer-side semantic allowance."""
    from dataclasses import replace
    from d810.analyses.control_flow.route_predicate import DecisionDag, RouteComparison
    from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
    from d810.transforms.dispatcher_corridor_coverage import (
        DispatcherBlockAnchor, DispatcherCorridor, DispatcherCorridorCoverage,
    )
    from d810.transforms.unflatten_authority import proposal as proposal_api
    from .helpers import exact_fixture

    source, contract, _effect, refs = exact_fixture()
    if mutation in {"foreign_default_leaf", "foreign_root", "true_arm_default", "disconnected_node", "wrong_identity", "wrong_constant", "wrong_explicit_target"}:
        blocks = dict(source.blocks)
        original = blocks[3]
        blocks[3] = BlockSnapshot(
            original.serial, original.block_type, (1,), original.preds, original.flags,
            original.start_ea, (InsnSnapshot(0, original.start_ea, (), kind=InsnKind.GOTO, raw_opcode=0),),
            tail_opcode=0, kind=original.kind, tail_kind=InsnKind.GOTO,
        )
        blocks[1] = replace(blocks[1], preds=tuple(sorted((*blocks[1].preds, 3))))
        if mutation in {"wrong_identity", "wrong_constant", "wrong_explicit_target"}:
            prefix, tail = blocks[1].insn_snapshots
            if mutation == "wrong_identity":
                tail = replace(tail, l=replace(tail.l, stkoff=8, stack_refs=(8,)))
            elif mutation == "wrong_constant":
                tail = replace(tail, r=replace(tail.r, value=8))
            else:
                tail = replace(tail, d=replace(tail.d, block_ref=3))
            blocks[1] = replace(blocks[1], insn_snapshots=(prefix, tail))
        source = FlowGraph(blocks, source.entry_serial, source.func_ea)
    coverage = DispatcherCorridorCoverage(
        source.func_ea, DispatcherBlockAnchor(1, 0x2000), (),
        (DispatcherCorridor((DispatcherBlockAnchor(3, 0x4000), DispatcherBlockAnchor(1, 0x2000))),),
        mutation != "incomplete",
    )
    if mutation == "no_dag":
        dag = None
    elif mutation == "foreign_root":
        dag = DecisionDag(32, {99: RouteComparison(99, "jz", 7, 2, 3)}, 99)
    elif mutation == "true_arm_default":
        dag = DecisionDag(32, {1: RouteComparison(1, "jz", 7, 3, 2)}, 1)
    elif mutation == "disconnected_node":
        dag = DecisionDag(32, {
            1: RouteComparison(1, "jz", 7, 2, 3),
            99: RouteComparison(99, "jz", 8, 2, 3),
        }, 1)
    else:
        dag = DecisionDag(
            32, {1: RouteComparison(1, "jz", 7, 2, 4 if mutation == "foreign_default_leaf" else 3)}, 1,
        )
    assert proposal_api._derive_default_gap_infeasibility_exclusions(
        source=source, proposal=contract, block_refs_by_serial=refs,
        selected_route_proof_ids=(contract.route_evidence.route_proofs[0].proof_id,),
        corridor_coverage=coverage, condition_chain_dag=dag,
        default_entry_serial=2 if mutation == "wrong_default" else 3,
    ) == ()


def _default_gap_exclusion(model, proposal, refs, *, residual_serial: int):
    """Build one closed producer proposal against the shared canonical fixture."""
    proof_id = proposal.route_evidence.route_proofs[0].proof_id
    seed = model.DefaultGapInitialStateSeed(7, proof_id)
    dispatcher = model.CorridorCoveragePathNode(refs[1], 0x2000)
    default_entry = model.CorridorCoveragePathNode(refs[0], 0x1000)
    residual = model.CorridorCoveragePathNode(
        refs[residual_serial], 0x3000 if residual_serial == 2 else 0x4000,
    )
    content = (
        "unflatten.default-gap-infeasibility-exclusion.v2", 4,
        proposal.plan_inputs.state_identity, dispatcher, default_entry, residual,
        (seed,), (proof_id,), (7,),
    )
    from d810.transforms.unflatten_authority.ids import authority_id as canonical_id

    return model.DefaultGapInfeasibilityExclusion(
        canonical_id(content),
        canonical_id(("unflatten.default-gap-infeasibility-exclusion-digest.v1", content)),
        4, proposal.plan_inputs.state_identity, dispatcher, default_entry, residual,
        (seed,), (proof_id,), (7,),
    )


def _default_gap_coverage(source, *, residual_paths, retired=False):
    from d810.transforms.dispatcher_corridor_coverage import (
        DispatcherBlockAnchor, DispatcherCorridor, DispatcherCorridorCoverage,
        RetiredDispatcherInfrastructure,
    )

    anchors = {
        serial: DispatcherBlockAnchor(serial, source.blocks[serial].start_ea)
        for serial in source.blocks
    }
    dispatcher = anchors[1]
    return DispatcherCorridorCoverage(
        source.func_ea,
        dispatcher,
        (DispatcherCorridor((anchors[0], dispatcher)),),
        tuple(DispatcherCorridor(tuple(anchors[serial] for serial in path)) for path in residual_paths),
        True,
        retirement_candidates=(RetiredDispatcherInfrastructure("comparison_dispatcher", dispatcher),)
        if retired else (),
    )


def test_default_gap_adapter_empty_input_is_exact_legacy_forecast_roundtrip() -> None:
    from d810.transforms.unflatten_authority import model, proposal as proposal_api
    from d810.transforms.unflatten_authority.ids import canonical_bytes, validate_canonical_roundtrip
    from .helpers import exact_fixture

    source, proposal, _effect_exclusion, refs = exact_fixture()
    coverage = _default_gap_coverage(source, residual_paths=((2, 1),))
    omitted = proposal_api.corridor_coverage_forecast_from_analysis(
        coverage, proposal=proposal, block_refs_by_serial=refs,
    )
    explicit_empty = proposal_api.corridor_coverage_forecast_from_analysis(
        coverage, proposal=proposal, block_refs_by_serial=refs,
        default_gap_infeasibility_exclusions=(),
    )

    assert type(omitted) is model.CorridorCoverageForecast
    assert type(explicit_empty) is model.CorridorCoverageForecast
    assert explicit_empty.forecast_id == omitted.forecast_id
    assert canonical_bytes(explicit_empty) == canonical_bytes(omitted)
    assert validate_canonical_roundtrip(explicit_empty, model.CorridorCoverageForecast) == omitted


def test_default_gap_adapter_rejects_incomplete_or_ambiguous_residual_linkage() -> None:
    from d810.transforms.unflatten_authority import model, proposal as proposal_api
    from .helpers import exact_fixture

    source, proposal, _effect_exclusion, refs = exact_fixture()
    exclusion = _default_gap_exclusion(model, proposal, refs, residual_serial=2)
    two_residuals = _default_gap_coverage(source, residual_paths=((2, 1), (3, 1)))
    with pytest.raises(ValueError, match="cover every exact residual"):
        proposal_api.corridor_coverage_forecast_from_analysis(
            two_residuals, proposal=proposal, block_refs_by_serial=refs,
            default_gap_infeasibility_exclusions=(exclusion,),
        )

    shared_first = _default_gap_coverage(source, residual_paths=((2, 1), (2, 0, 1)))
    with pytest.raises(ValueError, match="exact residual path"):
        proposal_api.corridor_coverage_forecast_from_analysis(
            shared_first, proposal=proposal, block_refs_by_serial=refs,
            default_gap_infeasibility_exclusions=(exclusion,),
        )


def test_default_gap_adapter_rejects_covered_residual_coordinate_overlap() -> None:
    from d810.transforms.dispatcher_corridor_coverage import (
        DispatcherBlockAnchor, DispatcherCorridor, DispatcherCorridorCoverage,
    )
    from d810.transforms.unflatten_authority import model, proposal as proposal_api
    from .helpers import exact_fixture

    source, proposal, _effect_exclusion, refs = exact_fixture()
    dispatcher = DispatcherBlockAnchor(1, source.blocks[1].start_ea)
    duplicate = DispatcherCorridor((DispatcherBlockAnchor(2, source.blocks[2].start_ea), dispatcher))
    coverage = DispatcherCorridorCoverage(
        source.func_ea, dispatcher, (duplicate,), (duplicate,), True,
    )
    with pytest.raises(ValueError, match="unique and disjoint"):
        proposal_api.corridor_coverage_forecast_from_analysis(
            coverage, proposal=proposal, block_refs_by_serial=refs,
            default_gap_infeasibility_exclusions=(
                _default_gap_exclusion(model, proposal, refs, residual_serial=2),
            ),
        )


def test_default_gap_adapter_rejects_mismatched_canonical_proof_source() -> None:
    from d810.analyses.control_flow.semantic_route_evidence import (
        SemanticCarrierProof, SemanticCorridorPoint, SemanticPredicateProof,
        SemanticStateWriteDeliveryKind, SemanticStateWriteProof,
        canonical_semantic_evidence_from_proofs,
    )
    from d810.ir.block_identity import StableBlockIdentity
    from d810.transforms.unflatten_authority import producer_api
    from .helpers import exact_fixture

    source, proposal, _effect_exclusion, refs = exact_fixture()
    original = proposal.route_evidence.route_proofs[0]
    foreign_identity = StableBlockIdentity.from_instruction_eas(
        (0x6000,), native_key=refs[0].identity.native_key,
    )
    foreign_point = SemanticCorridorPoint(foreign_identity, 0x6000)
    mismatched_proof = replace(
        original,
        source_identity=foreign_identity,
        source_anchor_ea=0x6000,
        source_owner_identity=foreign_identity,
        source_owner_anchor_ea=0x6000,
        predicate=SemanticPredicateProof(
            original.predicate.kind, foreign_point, foreign_point, (foreign_point,),
            original.predicate.storage_identity, original.predicate.width,
            original.predicate.compare_constant,
        ),
        carriers=(SemanticCarrierProof(
            original.carriers[0].carrier_id, foreign_point, (foreign_point,),
            (foreign_point,), original.carriers[0].storage_identity,
            original.carriers[0].width, original.carriers[0].state_values,
            frozenset((0x6000,)),
        ),),
        state_write=SemanticStateWriteProof(
            foreign_identity, 0x6000, original.state_write.state_variable,
            original.state_write.width, original.state_write.state_constant,
            (0x6000,), None, (), SemanticStateWriteDeliveryKind.CONDITIONAL,
        ),
    )
    mismatched_evidence = canonical_semantic_evidence_from_proofs(
        native_key=proposal.route_evidence.native_key,
        generation=proposal.route_evidence.generation,
        proofs=(mismatched_proof,),
    )
    with pytest.raises(ValueError, match="canonical route source endpoint"):
        producer_api.build_proposal(
            plan_id=proposal.plan_id, source=source, block_refs_by_serial=refs,
            source_generation=proposal.source_identity_catalog.generation,
            canonical_route_evidence=mismatched_evidence,
            selected_route_proof_ids=(mismatched_evidence.route_proofs[0].proof_id,),
            exact_state_effect_exclusions=(_effect_exclusion,),
            dispatcher_entry_serial=1, dispatcher_member_serials=(0, 1),
            authoritative_handler_serials=(2,),
            state_identity=proposal.plan_inputs.state_identity,
            use_def_witness=proposal.use_def_witness,
        )


def test_fully_covered_default_gap_forecast_mints_retirement_claim_by_coordinate() -> None:
    from d810.transforms.unflatten_authority import model, proposal as proposal_api
    from .helpers import exact_fixture

    source, proposal, _effect_exclusion, refs = exact_fixture()
    coverage = _default_gap_coverage(source, residual_paths=((2, 1),), retired=True)
    forecast = proposal_api.corridor_coverage_forecast_from_analysis(
        coverage, proposal=proposal, block_refs_by_serial=refs,
        default_gap_infeasibility_exclusions=(
            _default_gap_exclusion(model, proposal, refs, residual_serial=2),
        ),
    )
    proposal_with_forecast = replace(proposal, corridor_coverage_forecast=forecast)
    claims = proposal_api.claims_from_dispatcher_removal_forecast(
        coverage, proposal=proposal_with_forecast, block_refs_by_serial=refs,
    )

    assert len(claims) == 1
    assert type(claims[0]) is model.RetiredDispatcherInfrastructureClaim
    assert {
        (path.nodes, path.state_merge) for path in forecast.paths
    } == {
        (path.nodes, path.state_merge)
        for path in forecast.base_forecast.paths
        if path.path_id in forecast.base_forecast.residual_path_ids
    }
    assert claims[0].infrastructure_subject.block_ref == refs[1]
    assert claims[0].corridor_subject.locator.member_refs == tuple(
        sorted((refs[0], refs[1]), key=proposal_api.canonical_bytes)
    )


def test_corridor_forecast_adapter_mints_default_gap_sibling_only_for_exact_residual() -> None:
    from d810.transforms.dispatcher_corridor_coverage import (
        DispatcherBlockAnchor, DispatcherCorridor, DispatcherCorridorCoverage,
    )
    from d810.transforms.unflatten_authority import model, proposal as proposal_api
    from d810.transforms.unflatten_authority.ids import authority_id as canonical_authority_id
    from .helpers import exact_fixture

    source, proposal, _effect_exclusion, refs = exact_fixture()
    dispatcher = DispatcherBlockAnchor(1, source.blocks[1].start_ea)
    coverage = DispatcherCorridorCoverage(
        function_ea=source.func_ea, dispatcher=dispatcher,
        covered_corridors=(DispatcherCorridor((DispatcherBlockAnchor(0, source.blocks[0].start_ea), dispatcher)),),
        residual_corridors=(DispatcherCorridor((DispatcherBlockAnchor(2, source.blocks[2].start_ea), dispatcher)),),
        enumeration_complete=True,
    )
    dispatcher_node = model.CorridorCoveragePathNode(refs[1], source.blocks[1].start_ea)
    default_entry = model.CorridorCoveragePathNode(refs[0], source.blocks[0].start_ea)
    residual = model.CorridorCoveragePathNode(refs[2], source.blocks[2].start_ea)
    proof_id = proposal.route_evidence.route_proofs[0].proof_id
    seed = model.DefaultGapInitialStateSeed(7, proof_id)
    content = (
        "unflatten.default-gap-infeasibility-exclusion.v2", 4,
        proposal.plan_inputs.state_identity, dispatcher_node, default_entry,
        residual, (seed,), (proof_id,), (7,),
    )
    exclusion = model.DefaultGapInfeasibilityExclusion(
        canonical_authority_id(content),
        canonical_authority_id(("unflatten.default-gap-infeasibility-exclusion-digest.v1", content)),
        4, proposal.plan_inputs.state_identity, dispatcher_node, default_entry,
        residual, (seed,), (proof_id,), (7,),
    )
    forecast = proposal_api.corridor_coverage_forecast_from_analysis(
        coverage, proposal=proposal, block_refs_by_serial=refs,
        default_gap_infeasibility_exclusions=(exclusion,),
    )

    assert type(forecast) is model.DefaultGapInfeasibilityForecast
    assert forecast.paths[0].nodes[0] == residual
    assert forecast.paths[0].nodes[-1] == dispatcher_node
    covered_content = (
        "unflatten.default-gap-infeasibility-exclusion.v2", 4,
        proposal.plan_inputs.state_identity, dispatcher_node, residual,
        default_entry, (seed,), (proof_id,), (7,),
    )
    covered_exclusion = model.DefaultGapInfeasibilityExclusion(
        canonical_authority_id(covered_content),
        canonical_authority_id(("unflatten.default-gap-infeasibility-exclusion-digest.v1", covered_content)),
        4, proposal.plan_inputs.state_identity, dispatcher_node, residual,
        default_entry, (seed,), (proof_id,), (7,),
    )
    with pytest.raises(ValueError, match="residual"):
        proposal_api.corridor_coverage_forecast_from_analysis(
            coverage, proposal=proposal, block_refs_by_serial=refs,
            default_gap_infeasibility_exclusions=(covered_exclusion,),
        )
    foreign_proof_id = authority_id("proposal-default-gap-foreign-proof")
    foreign_seed = model.DefaultGapInitialStateSeed(7, foreign_proof_id)
    foreign_content = (
        "unflatten.default-gap-infeasibility-exclusion.v2", 4,
        proposal.plan_inputs.state_identity, dispatcher_node, default_entry,
        residual, (foreign_seed,), (foreign_proof_id,), (7,),
    )
    foreign_proof_exclusion = model.DefaultGapInfeasibilityExclusion(
        canonical_authority_id(foreign_content),
        canonical_authority_id(("unflatten.default-gap-infeasibility-exclusion-digest.v1", foreign_content)),
        4, proposal.plan_inputs.state_identity, dispatcher_node, default_entry,
        residual, (foreign_seed,), (foreign_proof_id,), (7,),
    )
    with pytest.raises(ValueError, match="route proof"):
        proposal_api.corridor_coverage_forecast_from_analysis(
            coverage, proposal=proposal, block_refs_by_serial=refs,
            default_gap_infeasibility_exclusions=(foreign_proof_exclusion,),
        )


@pytest.mark.parametrize("seed_state, message", [(9, "seed state")])
def test_default_gap_adapter_rejects_canonical_proof_state_mismatch(seed_state, message) -> None:
    """Producer linkage rejects states that the cited canonical proof never selects."""
    from d810.transforms.dispatcher_corridor_coverage import DispatcherBlockAnchor, DispatcherCorridor, DispatcherCorridorCoverage
    from d810.transforms.unflatten_authority import model, proposal as proposal_api
    from d810.transforms.unflatten_authority.ids import authority_id as canonical_authority_id
    from .helpers import exact_fixture

    source, proposal, _effect_exclusion, refs = exact_fixture()
    dispatcher = DispatcherBlockAnchor(1, source.blocks[1].start_ea)
    coverage = DispatcherCorridorCoverage(source.func_ea, dispatcher,
        (DispatcherCorridor((DispatcherBlockAnchor(0, source.blocks[0].start_ea), dispatcher)),),
        (DispatcherCorridor((DispatcherBlockAnchor(2, source.blocks[2].start_ea), dispatcher)),), True)
    proof_id = proposal.route_evidence.route_proofs[0].proof_id
    seed = model.DefaultGapInitialStateSeed(seed_state, proof_id)
    nodes = (
        model.CorridorCoveragePathNode(refs[1], source.blocks[1].start_ea),
        model.CorridorCoveragePathNode(refs[0], source.blocks[0].start_ea),
        model.CorridorCoveragePathNode(refs[2], source.blocks[2].start_ea),
    )
    content = ("unflatten.default-gap-infeasibility-exclusion.v2", 4, proposal.plan_inputs.state_identity, nodes[0], nodes[1], nodes[2], (seed,), (proof_id,), (seed_state,))
    exclusion = model.DefaultGapInfeasibilityExclusion(canonical_authority_id(content), canonical_authority_id(("unflatten.default-gap-infeasibility-exclusion-digest.v1", content)), 4, proposal.plan_inputs.state_identity, nodes[0], nodes[1], nodes[2], (seed,), (proof_id,), (seed_state,))
    with pytest.raises(ValueError, match=message):
        proposal_api.corridor_coverage_forecast_from_analysis(coverage, proposal=proposal, block_refs_by_serial=refs, default_gap_infeasibility_exclusions=(exclusion,))


def test_canonical_patch_step_descriptor_owns_direct_step_identity() -> None:
    from d810.transforms.cfg_transaction import PatchStepKind
    from d810.transforms.plan import PatchRedirectGoto

    source, refs, _key = _discovery_fixture(((0, (1,), 1, (_snapshot(0x1000, 1),)), (1, (), 1, (_snapshot(0x1010, 1),))))
    plan = PatchPlan(
        plan_id="sha256:" + "1" * 64,
        snapshot_id="sha256:" + "2" * 64,
        steps=(PatchRedirectGoto(refs[0], refs[1], refs[1]),),
        source_coordinates=((refs[0], 0), (refs[1], 1)),
    )
    from d810.transforms.unflatten_authority.proposal import canonical_patch_step_descriptor
    descriptor = canonical_patch_step_descriptor(plan, 0)
    assert descriptor.plan_id == plan.plan_id
    assert descriptor.step_kind is PatchStepKind.REDIRECT_GOTO
    assert descriptor.owner_refs == (refs[0],)
    assert descriptor.step_digest.startswith("sha256:")


def test_conditional_redirect_descriptor_owns_both_creation_specs() -> None:
    """A cloned conditional step must bind clone and helper independently."""
    from d810.transforms.cfg_transaction import LogicalBlockRef, PlanBlockRef
    from d810.transforms.plan import (
        PatchBlockSpec,
        PatchConditionalRedirect,
        PatchEdgeRef,
    )
    from d810.transforms.unflatten_authority.proposal import (
        canonical_patch_step_descriptor,
    )

    plan_id = "sha256:" + "3" * 64
    f = LogicalBlockRef("source", "f", 1)
    r = LogicalBlockRef("source", "r", 1)
    t = LogicalBlockRef("source", "t", 1)
    l = LogicalBlockRef("source", "l", 1)
    clone = PlanBlockRef(plan_id, "conditional_redirect:0")
    helper = PlanBlockRef(plan_id, "conditional_redirect_fallthrough:1")
    plan = PatchPlan(
        plan_id=plan_id,
        snapshot_id="sha256:" + "4" * 64,
        steps=(PatchConditionalRedirect(
            block_id=clone,
            fallthrough_block_id=helper,
            source_serial=f,
            ref_block=r,
            conditional_target=t,
            fallthrough_target=l,
        ),),
        new_blocks=(
            PatchBlockSpec(
                clone, "conditional_redirect_clone", r,
                PatchEdgeRef(f, r),
                (PatchEdgeRef(clone, t), PatchEdgeRef(clone, helper)),
            ),
            PatchBlockSpec(
                helper, "conditional_redirect_fallthrough", r,
                PatchEdgeRef(clone, helper), (PatchEdgeRef(helper, l),),
            ),
        ),
        source_coordinates=((f, 0), (r, 1), (t, 2), (l, 3)),
    )

    descriptor = canonical_patch_step_descriptor(plan, 0)
    assert descriptor.owner_refs == (clone, helper)
    assert descriptor.new_block_spec_digests == (
        (clone, descriptor.new_block_spec_digests[0][1]),
        (helper, descriptor.new_block_spec_digests[1][1]),
    )
    assert descriptor.step_digest.startswith("sha256:")
    mutated = replace(
        plan,
        new_blocks=(replace(plan.new_blocks[0], kind="different_clone"), plan.new_blocks[1]),
    )
    mutated_descriptor = canonical_patch_step_descriptor(mutated, 0)
    assert mutated_descriptor.new_block_spec_digests[0][1] != descriptor.new_block_spec_digests[0][1]
    assert mutated_descriptor.step_digest != descriptor.step_digest


def test_lower_conditional_descriptor_encodes_synthetic_counter_bound() -> None:
    """The typed manifest must seal every field of a synthesized loop guard."""
    from d810.transforms.graph_modification import SyntheticCounterBoundCondition
    from d810.transforms.plan import PatchLowerConditionalStateTransition
    from d810.transforms.unflatten_authority.proposal import (
        canonical_patch_step_descriptor,
        canonical_redirect_manifest,
    )

    proposal, plan_id = _proposal_and_plan_ids()
    refs = tuple(block.block_ref for block in proposal.source_identity_catalog.blocks)

    def plan_for(bound: int) -> PatchPlan:
        return PatchPlan(
            plan_id=plan_id,
            snapshot_id="snapshot-1",
            source_generation=proposal.source_identity_catalog.generation,
            steps=(
                PatchLowerConditionalStateTransition(
                    source_serial=refs[0],
                    old_dispatcher_serial=refs[1],
                    rewrite_from_ea=0x1000,
                    condition_operand=SyntheticCounterBoundCondition(
                        counter_size=4,
                        bound=bound,
                        counter_stkoff=0x38,
                    ),
                    false_target_serial=refs[1],
                    true_target_serial=refs[2],
                ),
            ),
        )

    first = plan_for(100)
    changed = plan_for(101)
    assert canonical_patch_step_descriptor(first, 0).step_digest != (
        canonical_patch_step_descriptor(changed, 0).step_digest
    )
    assert canonical_redirect_manifest(first).digest != (
        canonical_redirect_manifest(changed).digest
    )


def _discovery_fixture(block_specs):
    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
    from d810.ir.flowgraph import BlockSnapshot, FlowGraph
    from d810.transforms.cfg_transaction import NativeBlockRef

    key = NativePreanalysisKey("input", "x86", 64, 0, "f" * 64, "p" * 64, "s" * 64)
    blocks = {}
    refs = {}
    for serial, succs, kind, instructions in block_specs:
        ea_values = tuple(instruction.ea for instruction in instructions)
        block = BlockSnapshot(
            serial=serial, block_type=0, succs=tuple(succs), preds=(), flags=0,
            start_ea=ea_values[0], insn_snapshots=tuple(instructions), kind=kind,
            tail_opcode=instructions[-1].opcode if instructions else None,
            raw_tail_opcode=instructions[-1].raw_opcode if instructions else None,
            tail_kind=instructions[-1].kind if instructions else None,
        )
        blocks[serial] = block
        identity = StableBlockIdentity.from_intervals(
            tuple(NativeEaInterval(ea, ea + 1) for ea in ea_values),
            native_key=key, exact_instruction_eas=ea_values,
        )
        refs[serial] = NativeBlockRef(identity)
    source = FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x1000)
    return source, refs, key


def _snapshot(ea, kind):
    from d810.ir.flowgraph import InsnSnapshot
    return InsnSnapshot(0, ea, (), kind=kind, native_ea=ea, raw_opcode=0)


def _empty_native_fixture(*, duplicate_start: bool = False):
    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
    from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph
    from d810.transforms.cfg_transaction import NativeBlockRef

    key = NativePreanalysisKey("input", "x86", 64, 0, "f" * 64, "p" * 64, "s" * 64)
    blocks = {
        0: BlockSnapshot(0, 0, (1,) if duplicate_start else (), (), 0, 0x1000, (), kind=BlockKind.ONE_WAY if duplicate_start else BlockKind.ZERO_WAY),
    }
    refs = {
        0: NativeBlockRef(
            StableBlockIdentity.from_intervals(
                (NativeEaInterval(0x1000, 0x1010),),
                native_key=key,
                exact_instruction_eas=(),
            )
        )
    }
    if duplicate_start:
        blocks[1] = BlockSnapshot(1, 0, (), (0,), 0, 0x1000, (), kind=BlockKind.ZERO_WAY)
        refs[1] = NativeBlockRef(
            StableBlockIdentity.from_intervals(
                (NativeEaInterval(0x1000, 0x1020),),
                native_key=key,
                exact_instruction_eas=(),
            )
        )
    return FlowGraph(blocks, 0, 0x1000), refs, key


def test_source_catalog_accepts_unique_empty_native_entry() -> None:
    from d810.transforms.unflatten_authority import producer_api

    source, refs, key = _empty_native_fixture()
    catalog = producer_api.build_source_identity_catalog(
        source, refs, native_key=key, source_generation=0,
    )
    assert catalog.blocks[0].anchor_ea == 0x1000
    assert catalog.blocks[0].native_instruction_eas == ()


def test_source_catalog_deduplicates_repeated_native_origins_from_one_instruction() -> None:
    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
    from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
    from d810.transforms.cfg_transaction import NativeBlockRef
    from d810.transforms.unflatten_authority import producer_api

    key = NativePreanalysisKey("input", "x86", 64, 0, "f" * 64, "p" * 64, "s" * 64)
    source = FlowGraph(
        {
            0: BlockSnapshot(
                0,
                0,
                (),
                (),
                0,
                0x1000,
                (
                    InsnSnapshot(0, 0x1000, (), kind=InsnKind.MOV, native_ea=0x1000),
                    InsnSnapshot(0, 0x1001, (), kind=InsnKind.MOV, native_ea=0x1000),
                ),
                kind=BlockKind.ZERO_WAY,
            )
        },
        0,
        0x1000,
    )
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1000, 0x1010),),
        native_key=key,
        exact_instruction_eas=(0x1000,),
    )
    catalog = producer_api.build_source_identity_catalog(
        source,
        {0: NativeBlockRef(identity)},
        native_key=key,
        source_generation=1,
    )
    assert catalog.blocks[0].native_instruction_eas == (0x1000,)


def test_phase_binding_accepts_unique_empty_native_entry_without_instruction_ownership() -> None:
    from d810.transforms.cfg_transaction import NativeBlockRef
    from d810.transforms.unflatten_authority import bind, model
    from d810.transforms.unflatten_authority.ids import _subject_factory

    source, refs, key = _empty_native_fixture()
    catalog = model.SourceIdentityCatalog(
        key,
        0,
        (
            model.SourceBlockIdentityWitness(
                refs[0], 0x1000, (),
            ),
        ),
    )
    assert type(refs[0]) is NativeBlockRef
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SOURCE_ENTRY,
        block_ref=refs[0],
        anchor_ea=0x1000,
        locator=model.BlockSubjectLocator(refs[0], 0x1000),
    )
    bindings = bind.bind_subjects(
        (subject,),
        catalog=catalog,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        graph_fingerprint="sha256:" + "a" * 64,
        generation=0,
        serial_by_ref={refs[0]: 0},
    )
    assert bindings[0].status is model.SubjectBindingStatus.UNIQUE
    assert bindings[0].native_instruction_eas == ()


def test_source_catalog_rejects_empty_witness_for_instruction_identity() -> None:
    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
    from d810.transforms.cfg_transaction import NativeBlockRef
    from d810.transforms.unflatten_authority.model import SourceBlockIdentityWitness

    key = NativePreanalysisKey("input", "x86", 64, 0, "f" * 64, "p" * 64, "s" * 64)
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1000, 0x1010),),
        native_key=key,
        exact_instruction_eas=(0x1000,),
    )
    with pytest.raises(ValueError, match="empty|instruction"):
        SourceBlockIdentityWitness(NativeBlockRef(identity), 0x1000, ())


def test_source_catalog_rejects_empty_logical_witness() -> None:
    from d810.transforms.cfg_transaction import LogicalBlockRef
    from d810.transforms.unflatten_authority.model import SourceBlockIdentityWitness

    with pytest.raises(ValueError, match="empty|instruction"):
        SourceBlockIdentityWitness(LogicalBlockRef("session", "proxy", 1), 0x1000, ())


def test_source_catalog_allows_duplicate_empty_native_starts_for_distinct_refs() -> None:
    from d810.transforms.unflatten_authority import producer_api

    source, refs, key = _empty_native_fixture(duplicate_start=True)
    catalog = producer_api.build_source_identity_catalog(
        source, refs, native_key=key, source_generation=0,
    )
    assert tuple(item.anchor_ea for item in catalog.blocks) == (0x1000, 0x1000)


def test_reachable_stop_terminal_is_based_on_block_tail() -> None:
    from d810.ir.flowgraph import BlockKind, InsnKind
    from d810.transforms.unflatten_authority import producer_api

    cases = [
        ((0, (), BlockKind.STOP, (_snapshot(0x1000, InsnKind.RET),)),),
        ((0, (), BlockKind.STOP, (_snapshot(0x1000, InsnKind.TRAP),)),),
        ((0, (), BlockKind.STOP, (_snapshot(0x1000, InsnKind.TRAP), _snapshot(0x1001, InsnKind.STORE))),),
    ]
    for specs in cases:
        source, refs, key = _discovery_fixture(specs)
        catalog = producer_api.build_source_identity_catalog(
            source, refs, native_key=key, source_generation=1,
        )
        discovered = producer_api.discover_reachable_effects_and_terminals(
            source, catalog, refs,
        )
        kinds = tuple(terminal.terminal_kind for terminal in discovered.terminals)
        if specs[0][3][-1].kind in (InsnKind.RET, InsnKind.TRAP):
            assert kinds == (producer_api.TerminalKind.RETURN if specs[0][3][-1].kind is InsnKind.RET else producer_api.TerminalKind.TRAP,)
        else:
            assert kinds == (producer_api.TerminalKind.TRAP, producer_api.TerminalKind.STOP)


def test_reachable_stop_terminals_include_each_stop_block() -> None:
    from d810.ir.flowgraph import BlockKind, InsnKind
    from d810.transforms.unflatten_authority import producer_api

    specs = (
        (0, (1, 2), BlockKind.TWO_WAY, (_snapshot(0x1000, InsnKind.GOTO),)),
        (1, (), BlockKind.STOP, (_snapshot(0x1010, InsnKind.STORE),)),
        (2, (), BlockKind.STOP, (_snapshot(0x1020, InsnKind.STORE),)),
    )
    source, refs, key = _discovery_fixture(specs)
    catalog = producer_api.build_source_identity_catalog(
        source, refs, native_key=key, source_generation=1,
    )
    discovered = producer_api.discover_reachable_effects_and_terminals(
        source, catalog, refs,
    )
    assert tuple(terminal.terminal_kind for terminal in discovered.terminals) == (
        producer_api.TerminalKind.STOP,
        producer_api.TerminalKind.STOP,
    )


def test_source_catalog_rejects_block_serial_mismatch() -> None:
    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
    from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
    from d810.transforms.cfg_transaction import NativeBlockRef
    from d810.transforms.unflatten_authority import producer_api

    key = NativePreanalysisKey("input", "x86", 64, 0, "f" * 64, "p" * 64, "s" * 64)
    source = FlowGraph({0: BlockSnapshot(1, 0, (), (), 0, 0x1000, (InsnSnapshot(0, 0x1000, (), kind=InsnKind.STORE),), kind=BlockKind.STOP)}, 0, 0x1000)
    identity = StableBlockIdentity.from_intervals((NativeEaInterval(0x1000, 0x1001),), native_key=key, exact_instruction_eas=(0x1000,))
    with pytest.raises(ValueError, match="serial"):
        producer_api.build_source_identity_catalog(
            source, {0: NativeBlockRef(identity)}, native_key=key, source_generation=1,
        )


def test_clean_use_def_conversion_rejects_contradictory_violation_rows() -> None:
    from d810.transforms.unflatten_authority import producer_api
    from d810.transforms.use_def_redirect_filter import (
        UseDefBlockAnchor, UseDefSeveranceAudit, UseDefSeveranceEvidence,
    )
    from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
    anchor = UseDefBlockAnchor(0, 0x1000)
    violation = UseDefSeveranceEvidence(anchor, anchor, anchor, 1, 4, anchor, 0x1000)
    audit = UseDefSeveranceAudit(True, 0, violations=(violation,))
    assert producer_api.build_use_def_fragment_witness(
        audit, fragment_id="sha256:" + "1" * 64,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, 0x40),
    ) is None


def test_plan_input_catalog_lifts_only_explicit_authoritative_handlers() -> None:
    """The producer must not promote an unlisted route destination to a handler."""

    from d810.transforms.unflatten_authority import producer_api
    from d810.analyses.control_flow.semantic_route_evidence import (
        CanonicalSemanticEvidence,
        canonical_semantic_evidence_from_proofs,
    )
    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
    from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
    from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
    from d810.transforms.cfg_transaction import NativeBlockRef

    key = NativePreanalysisKey("input", "x86", 64, 0, "fn", "profile", "sdk")
    def identity(ea: int) -> StableBlockIdentity:
        return StableBlockIdentity.from_intervals(
            (NativeEaInterval(ea, ea + 1),),
            native_key=key,
            exact_instruction_eas=(ea,),
        )
    source = FlowGraph(
        blocks={
            serial: BlockSnapshot(
                serial=serial,
                block_type=0,
                succs=succs,
                preds=preds,
                flags=0,
                start_ea=ea,
                insn_snapshots=(InsnSnapshot(1, ea, (), kind=InsnKind.RET),),
                kind=kind,
            )
            for serial, succs, preds, ea, kind in (
                (0, (1,), (), 0x1000, BlockKind.ONE_WAY),
                (1, (), (0,), 0x1010, BlockKind.STOP),
            )
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    refs = {serial: NativeBlockRef(identity(0x1000 + serial * 0x10)) for serial in (0, 1)}
    catalog = producer_api.build_source_identity_catalog(
        source, refs, native_key=key, source_generation=1
    )
    evidence = object.__new__(CanonicalSemanticEvidence)
    object.__setattr__(evidence, "native_key", key)
    object.__setattr__(evidence, "generation", 1)
    object.__setattr__(evidence, "atomic_group_id", "group")
    destination = type("Destination", (), {
        "target_identity": identity(0x1010),
        "target_anchor_ea": 0x1010,
        "state_constant": 7,
    })()
    destination9 = type("Destination", (), {
        "target_identity": identity(0x1010),
        "target_anchor_ea": 0x1010,
        "state_constant": 9,
    })()
    proof = type("Proof", (), {"destinations": (destination, destination9)})()
    object.__setattr__(evidence, "route_proofs", (proof,))

    exact_states = producer_api.build_unflatten_plan_input_catalog(
        source=source,
        source_catalog=catalog,
        block_refs_by_serial=refs,
        canonical_route_evidence=evidence,
        source_entry_serial=0,
        dispatcher_entry_serial=0,
        dispatcher_member_serials=(0,),
        authoritative_handler_serials=(1,),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, 0x40),
        shape="partial_rewrite",
    )
    assert exact_states.authoritative_handlers[0].normalized_states == (7, 9)

    destination.state_constant = 0x100000001
    exact_width = producer_api.build_unflatten_plan_input_catalog(
        source=source,
        source_catalog=catalog,
        block_refs_by_serial=refs,
        canonical_route_evidence=evidence,
        source_entry_serial=0,
        dispatcher_entry_serial=0,
        dispatcher_member_serials=(0,),
        authoritative_handler_serials=(1,),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, 0x40),
        shape="partial_rewrite",
    )
    assert exact_width.authoritative_handlers[0].normalized_states == (9, 0x100000001)

    with pytest.raises(ValueError, match="authoritative_handler_serials"):
        producer_api.build_unflatten_plan_input_catalog(
            source=source,
            source_catalog=catalog,
            block_refs_by_serial=refs,
            canonical_route_evidence=evidence,
            source_entry_serial=0,
            dispatcher_entry_serial=0,
            dispatcher_member_serials=(0,),
            authoritative_handler_serials=(2,),
            state_identity=StorageIdentity(StorageIdentityKind.STACK, 0x40),
            shape="partial_rewrite",
        )


def _proposal_and_plan_ids():
    from .helpers import import_authority_model
    from .test_model import _valid_proposal

    model = import_authority_model()
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    return proposal, proposal.plan_id


def _typed_plan(proposal):
    from d810.transforms.plan import PatchRedirectGoto
    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest

    refs = tuple(block.block_ref for block in proposal.source_identity_catalog.blocks)
    steps = (
        PatchRedirectGoto(refs[0], refs[1], refs[2]),
        PatchRedirectGoto(refs[1], refs[2], refs[0]),
    )
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id="snapshot-1",
        source_generation=proposal.source_identity_catalog.generation,
        steps=steps,
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
    return replace(plan, unflatten_proposal=proposal), proposal


def test_incomplete_dispatcher_forecast_mints_no_authority_claims() -> None:
    """An abstaining producer forecast cannot create a retirement claim."""

    from d810.transforms.dispatcher_corridor_coverage import DispatcherCorridorCoverage
    from d810.transforms.unflatten_authority import proposal as proposal_api
    from .helpers import exact_fixture

    source, proposal, _exclusion, refs = exact_fixture()
    coverage = DispatcherCorridorCoverage(
        function_ea=source.func_ea,
        dispatcher=None,
        covered_corridors=(),
        residual_corridors=(),
        enumeration_complete=False,
    )
    assert proposal_api.claims_from_dispatcher_removal_forecast(
        coverage, proposal=proposal, block_refs_by_serial=refs,
    ) == ()


def test_explicit_partial_route_forecast_keeps_corridor_validation() -> None:
    """Explicit producer intent retains corridor validation without retirement."""

    from d810.transforms.dispatcher_corridor_coverage import (
        DispatcherBlockAnchor,
        DispatcherCorridor,
        DispatcherCorridorCoverage,
    )
    from d810.transforms.plan import PatchRedirectGoto
    from d810.transforms.unflatten_authority.proposal import (
        attach_typed_proposal,
        canonical_redirect_manifest,
    )
    from d810.transforms.unflatten_authority import model
    from .helpers import exact_fixture

    source, proposal, exclusion, refs = exact_fixture()
    template = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id="partial-corridor-attachment",
        source_generation=proposal.source_identity_catalog.generation,
        steps=(PatchRedirectGoto(refs[0], refs[1], refs[2]),),
    )
    manifest = canonical_redirect_manifest(template)
    witness = replace(
        proposal.use_def_witness,
        redirect_owner_refs=manifest.owner_refs,
        redirect_digest=manifest.digest,
    )
    dispatcher = DispatcherBlockAnchor(1, source.blocks[1].start_ea)
    coverage = DispatcherCorridorCoverage(
        function_ea=source.func_ea,
        dispatcher=dispatcher,
        covered_corridors=(DispatcherCorridor((
            DispatcherBlockAnchor(0, source.blocks[0].start_ea), dispatcher,
        )),),
        residual_corridors=(DispatcherCorridor((
            DispatcherBlockAnchor(2, source.blocks[2].start_ea), dispatcher,
        )),),
        enumeration_complete=True,
    )

    attached = attach_typed_proposal(
        template,
        source=source,
        block_refs_by_serial=refs,
        canonical_route_evidence=proposal.route_evidence,
        exact_state_effect_exclusions=(exclusion,),
        dispatcher_entry_serial=1,
        dispatcher_member_serials=(0, 1),
        authoritative_handler_serials=(2,),
        state_identity=proposal.plan_inputs.state_identity,
        use_def_witness=witness,
        corridor_coverage=coverage,
        dispatcher_removal_forecast=coverage,
    )

    assert attached.unflatten_proposal is not None
    partial = attached.unflatten_proposal
    assert partial.corridor_coverage_forecast is not None
    assert partial.retirement_candidate_catalog is None
    assert not any(
        type(claim) is model.RetiredDispatcherInfrastructureClaim
        for claim in partial.claims
    )


def test_partial_retirement_forecast_keeps_corridor_validation_after_normalization() -> None:
    """A non-full retirement forecast remains transaction-owned authority."""

    from d810.transforms.dispatcher_corridor_coverage import (
        DispatcherBlockAnchor,
        DispatcherCorridor,
        DispatcherCorridorCoverage,
        RetiredDispatcherInfrastructure,
    )
    from d810.transforms.plan import PatchRedirectGoto
    from d810.transforms.unflatten_authority import model
    from d810.transforms.unflatten_authority.proposal import (
        attach_typed_proposal,
        canonical_redirect_manifest,
    )
    from .helpers import exact_fixture

    source, proposal, _exclusion, refs = exact_fixture()
    template = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id="partial-retirement-corridor-attachment",
        source_generation=proposal.source_identity_catalog.generation,
        steps=(PatchRedirectGoto(refs[0], refs[1], refs[2]),),
    )
    manifest = canonical_redirect_manifest(template)
    dispatcher = DispatcherBlockAnchor(1, source.blocks[1].start_ea)
    coverage = DispatcherCorridorCoverage(
        function_ea=source.func_ea,
        dispatcher=dispatcher,
        covered_corridors=(DispatcherCorridor((
            DispatcherBlockAnchor(0, source.blocks[0].start_ea), dispatcher,
        )),),
        residual_corridors=(),
        enumeration_complete=True,
        retirement_candidates=(RetiredDispatcherInfrastructure(
            role="comparison_dispatcher", anchor=dispatcher,
        ),),
    )

    attached = attach_typed_proposal(
        template,
        source=source,
        block_refs_by_serial=refs,
        canonical_route_evidence=proposal.route_evidence,
        selected_route_proof_ids=(proposal.route_evidence.route_proofs[0].proof_id,),
        exact_state_effect_exclusions=(),
        dispatcher_entry_serial=1,
        dispatcher_member_serials=(0, 1),
        authoritative_handler_serials=(2,),
        state_identity=proposal.plan_inputs.state_identity,
        use_def_witness=replace(
            proposal.use_def_witness,
            redirect_owner_refs=manifest.owner_refs,
            redirect_digest=manifest.digest,
        ),
        corridor_coverage=coverage,
        dispatcher_removal_forecast=coverage,
    )

    attached_proposal = attached.unflatten_proposal
    assert attached_proposal is not None
    assert attached_proposal.plan_inputs.shape is model.UnflattenPlanShape.PARTIAL_REWRITE
    assert attached_proposal.corridor_coverage_forecast is not None
    assert attached_proposal.retirement_candidate_catalog is None
    assert {claim.kind for claim in attached_proposal.claims} == {
        model.UnflattenClaimKind.EQUIVALENT_SEMANTIC_ROUTE,
    }


def test_complete_route_only_attachment_does_not_mint_a_corridor_forecast() -> None:
    """Complete coverage does not widen a route-only partial rewrite."""

    from d810.transforms.dispatcher_corridor_coverage import (
        DispatcherBlockAnchor,
        DispatcherCorridor,
        DispatcherCorridorCoverage,
    )
    from d810.transforms.plan import PatchRedirectGoto
    from d810.transforms.unflatten_authority import model
    from d810.transforms.unflatten_authority.proposal import (
        attach_typed_proposal,
        canonical_redirect_manifest,
    )
    from .helpers import exact_fixture

    source, proposal, _exclusion, refs = exact_fixture()
    template = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id="complete-route-only-corridor-attachment",
        source_generation=proposal.source_identity_catalog.generation,
        steps=(PatchRedirectGoto(refs[0], refs[1], refs[2]),),
    )
    manifest = canonical_redirect_manifest(template)
    coverage = DispatcherCorridorCoverage(
        function_ea=source.func_ea,
        dispatcher=DispatcherBlockAnchor(1, source.blocks[1].start_ea),
        covered_corridors=(DispatcherCorridor((
            DispatcherBlockAnchor(0, source.blocks[0].start_ea),
            DispatcherBlockAnchor(1, source.blocks[1].start_ea),
        )),),
        residual_corridors=(),
        enumeration_complete=True,
    )

    attached = attach_typed_proposal(
        template,
        source=source,
        block_refs_by_serial=refs,
        canonical_route_evidence=proposal.route_evidence,
        selected_route_proof_ids=(proposal.route_evidence.route_proofs[0].proof_id,),
        exact_state_effect_exclusions=(),
        dispatcher_entry_serial=1,
        dispatcher_member_serials=(0, 1),
        authoritative_handler_serials=(2,),
        state_identity=proposal.plan_inputs.state_identity,
        use_def_witness=replace(
            proposal.use_def_witness,
            redirect_owner_refs=manifest.owner_refs,
            redirect_digest=manifest.digest,
        ),
        corridor_coverage=coverage,
    )

    attached_proposal = attached.unflatten_proposal
    assert attached_proposal is not None
    assert attached_proposal.plan_inputs.shape is model.UnflattenPlanShape.PARTIAL_REWRITE
    assert attached_proposal.corridor_coverage_forecast is None
    assert {claim.kind for claim in attached_proposal.claims} == {
        model.UnflattenClaimKind.EQUIVALENT_SEMANTIC_ROUTE,
    }


def test_complete_exact_effect_attachment_does_not_mint_a_corridor_forecast() -> None:
    """Complete coverage is unrelated to an exact-effect-only proposal."""

    from d810.transforms.dispatcher_corridor_coverage import (
        DispatcherBlockAnchor,
        DispatcherCorridor,
        DispatcherCorridorCoverage,
    )
    from d810.transforms.plan import PatchRedirectGoto
    from d810.transforms.unflatten_authority import model
    from d810.transforms.unflatten_authority.proposal import (
        attach_typed_proposal,
        canonical_redirect_manifest,
    )
    from .helpers import exact_fixture

    source, proposal, exclusion, refs = exact_fixture()
    template = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id="complete-exact-effect-corridor-attachment",
        source_generation=proposal.source_identity_catalog.generation,
        steps=(PatchRedirectGoto(refs[0], refs[1], refs[2]),),
    )
    manifest = canonical_redirect_manifest(template)
    coverage = DispatcherCorridorCoverage(
        function_ea=source.func_ea,
        dispatcher=DispatcherBlockAnchor(1, source.blocks[1].start_ea),
        covered_corridors=(DispatcherCorridor((
            DispatcherBlockAnchor(0, source.blocks[0].start_ea),
            DispatcherBlockAnchor(1, source.blocks[1].start_ea),
        )),),
        residual_corridors=(),
        enumeration_complete=True,
    )

    attached = attach_typed_proposal(
        template,
        source=source,
        block_refs_by_serial=refs,
        canonical_route_evidence=proposal.route_evidence,
        selected_route_proof_ids=(),
        exact_state_effect_exclusions=(exclusion,),
        dispatcher_entry_serial=1,
        dispatcher_member_serials=(0, 1),
        authoritative_handler_serials=(2,),
        state_identity=proposal.plan_inputs.state_identity,
        use_def_witness=replace(
            proposal.use_def_witness,
            redirect_owner_refs=manifest.owner_refs,
            redirect_digest=manifest.digest,
        ),
        corridor_coverage=coverage,
    )

    attached_proposal = attached.unflatten_proposal
    assert attached_proposal is not None
    assert attached_proposal.plan_inputs.shape is model.UnflattenPlanShape.EXACT_EFFECT_ONLY
    assert attached_proposal.corridor_coverage_forecast is None
    assert {claim.kind for claim in attached_proposal.claims} == {
        model.UnflattenClaimKind.EXACT_INFEASIBLE_EFFECT,
    }


def test_full_dispatcher_retirement_attachment_keeps_the_coverage_forecast_fail_closed() -> None:
    """A complete retirement retains the aggregate forecast and its invariant."""

    from d810.transforms.unflatten_authority import model
    from .test_transaction_api import _full_corridor_fixture

    _source, plan, _projected, _gates = _full_corridor_fixture()
    proposal = plan.unflatten_proposal

    assert proposal is not None
    assert proposal.plan_inputs.shape is model.UnflattenPlanShape.FULL_DISPATCHER_RETIREMENT
    assert proposal.corridor_coverage_forecast is not None
    assert proposal.retirement_candidate_catalog is not None
    assert any(
        type(claim) is model.RetiredDispatcherInfrastructureClaim
        for claim in proposal.claims
    )
    with pytest.raises(ValueError, match="coverage forecast"):
        replace(proposal, corridor_coverage_forecast=None)


def test_detached_component_attachment_carries_sealed_corridor_into_transaction() -> None:
    """A detached claim reaches the transaction binder with sealed coverage."""

    from d810.transforms.dispatcher_corridor_coverage import (
        DetachedDeadHandlerComponentAnalysis,
        DispatcherBlockAnchor,
        DispatcherCorridor,
        DispatcherCorridorCoverage,
    )
    from d810.analyses.control_flow.semantic_route_evidence import (
        CanonicalRouteAssessmentPhase,
        CanonicalRouteMaterialization,
    )
    from d810.transforms.unflatten_authority import model, proposal as proposal_api
    from d810.transforms.unflatten_authority import transaction_api
    from d810.transforms.edit_simulator import project_post_state
    from .helpers import exact_fixture

    source, proposal, exclusion, refs = exact_fixture()
    from d810.transforms.unflatten_authority.model import AuthoritativeHandlerInput
    proposal = replace(
        proposal,
        plan_inputs=replace(
            proposal.plan_inputs,
            authoritative_handlers=tuple(sorted(
                (*proposal.plan_inputs.authoritative_handlers,
                 AuthoritativeHandlerInput(refs[3], source.blocks[3].start_ea, (8,))),
                key=lambda item: item.anchor_ea,
            )),
        ),
    )
    anchors = {
        serial: DispatcherBlockAnchor(serial, source.blocks[serial].start_ea)
        for serial in (0, 1, 2, 3)
    }
    analysis = DetachedDeadHandlerComponentAnalysis(
        dispatcher=anchors[1], dead_handlers=(anchors[2],),
        retained_handlers=(anchors[3],), component=(anchors[2],),
    )
    coverage = DispatcherCorridorCoverage(
        function_ea=source.func_ea,
        dispatcher=anchors[1],
        covered_corridors=(DispatcherCorridor((anchors[0], anchors[1])),),
        residual_corridors=(),
        enumeration_complete=True,
        detached_dead_handler_component=analysis,
    )

    from d810.transforms.plan import PatchRedirectGoto

    template = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("detached-corridor-snapshot"),
        source_generation=1,
        steps=(PatchRedirectGoto(refs[0], refs[1], refs[3]),),
        source_coordinates=tuple((ref, serial) for serial, ref in refs.items()),
    )
    manifest = proposal_api.canonical_redirect_manifest(template)
    attached = proposal_api.attach_typed_proposal(
        template,
        source=source,
        block_refs_by_serial=refs,
        canonical_route_evidence=proposal.route_evidence,
        exact_state_effect_exclusions=(exclusion,),
        dispatcher_entry_serial=1,
        dispatcher_member_serials=(0, 1),
        authoritative_handler_serials=(2, 3),
        state_identity=proposal.plan_inputs.state_identity,
        use_def_witness=replace(
            proposal.use_def_witness,
            redirect_owner_refs=manifest.owner_refs,
            redirect_digest=manifest.digest,
        ),
        corridor_coverage=coverage,
        dispatcher_removal_forecast=coverage,
    )

    attached_proposal = attached.unflatten_proposal
    assert attached_proposal is not None
    claims = tuple(
        claim for claim in attached_proposal.claims
        if type(claim) is model.DetachedDeadHandlerComponentClaim
    )
    assert len(claims) == 1
    assert claims[0].dead_handler_subjects[0].block_ref == refs[2]
    assert attached_proposal.corridor_coverage_forecast is not None

    materialization = CanonicalRouteMaterialization.capture(
        source, generation=1, phase=CanonicalRouteAssessmentPhase.SOURCE,
    )
    source_inventory = transaction_api._build_semantic_graph_inventory(
        source, attached_proposal, attached, source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        materialization=materialization,
    )
    projected = project_post_state(source, attached)
    projected_inventory = transaction_api._build_semantic_graph_inventory(
        projected, attached_proposal, attached, source=False,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        source_subjects=source_inventory.subjects,
        materialization=CanonicalRouteMaterialization.capture(
            projected, generation=1, phase=CanonicalRouteAssessmentPhase.PROJECTED,
        ),
    )
    corridor = transaction_api.authority_bind.bind_corridor_coverage_forecast(
        proposal=attached_proposal,
        source_inventory=source_inventory,
        candidate_inventory=projected_inventory,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    _sources, phase_results = transaction_api._bind_detached_authority_results(
        claims=claims,
        source_inventory=source_inventory,
        candidate_inventory=projected_inventory,
        corridor_result=corridor,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    assert len(phase_results) == 1
    assert phase_results[0].accepted
    assert (
        projected_inventory.serial_by_ref[refs[2]]
        not in projected_inventory.reachable_serials
    )


def test_proposal_module_has_no_local_removal_verdict_api() -> None:
    from d810.transforms import dispatcher_corridor_coverage as coverage_api
    from d810.transforms.unflatten_authority import proposal as proposal_api

    names = vars(coverage_api)
    assert "DispatcherRemoval" + "PreflightValidation" not in names
    assert "DispatcherRemoval" + "PreflightProof" not in names
    assert "claims_from_dispatcher_removal" + "_validation" not in vars(proposal_api)



def test_redirect_manifest_is_canonical_and_plan_bound() -> None:
    """The typed witness must be derived from the complete PatchPlan redirects."""

    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest

    proposal, plan_id = _proposal_and_plan_ids()
    ref0 = proposal.source_identity_catalog.blocks[0].block_ref
    ref1 = proposal.source_identity_catalog.blocks[1].block_ref
    plan = PatchPlan(
        plan_id=plan_id,
        snapshot_id="snapshot-1",
        source_generation=3,
        steps=(
            __import__("d810.transforms.plan", fromlist=["PatchRedirectGoto"]).PatchRedirectGoto(ref0, ref1, ref0),
        ),
    )
    manifest = canonical_redirect_manifest(plan)
    assert manifest.owner_refs == (ref0,)
    assert manifest.digest.startswith("sha256:")


def test_proposal_validation_requires_the_exact_redirect_manifest() -> None:
    from d810.transforms.plan import PatchRedirectGoto
    from d810.transforms.cfg_transaction import PlanBlockRef
    from d810.transforms.unflatten_authority.proposal import (
        ProposalAccepted, canonical_redirect_manifest, validate_proposal,
    )

    proposal, plan_id = _proposal_and_plan_ids()
    refs = tuple(block.block_ref for block in proposal.source_identity_catalog.blocks)
    steps = (
        PatchRedirectGoto(refs[1], refs[2], refs[0]),
        PatchRedirectGoto(refs[0], refs[1], refs[2]),
    )
    plan = PatchPlan(
        plan_id=plan_id, snapshot_id="snapshot-1", source_generation=3, steps=steps,
    )
    manifest = canonical_redirect_manifest(plan)
    witness = replace(
        proposal.use_def_witness,
        redirect_owner_refs=manifest.owner_refs,
        redirect_digest=manifest.digest,
    )
    proposal = replace(proposal, use_def_witness=witness)
    assert isinstance(validate_proposal(plan, proposal), ProposalAccepted)

    reordered = PatchPlan(
        plan_id=plan_id, snapshot_id="snapshot-1", source_generation=3,
        steps=tuple(reversed(steps)),
    )
    assert canonical_redirect_manifest(reordered).digest != manifest.digest

    with pytest.raises(ValueError, match="duplicates"):
        replace(
            witness,
            redirect_owner_refs=(manifest.owner_refs[0], manifest.owner_refs[0]),
        )
    with pytest.raises(ValueError, match="absent from source catalog"):
        replace(
            proposal,
            use_def_witness=replace(
                witness, redirect_owner_refs=(PlanBlockRef(plan_id, "helper"),)
            ),
        )

    mutations = (
        ("zero", PatchPlan(plan_id=plan_id, snapshot_id="snapshot-1", source_generation=3), witness),
        ("omit", plan, replace(witness, redirect_owner_refs=manifest.owner_refs[:-1])),
        ("extra", plan, replace(witness, redirect_owner_refs=(*manifest.owner_refs, refs[2]))),
        ("substitute", plan, replace(witness, redirect_owner_refs=(refs[2],))),
        ("unrelated digest", plan, replace(witness, redirect_digest="sha256:" + "f" * 64)),
        ("source generation", replace(plan, source_generation=999), witness),
    )
    for label, candidate_plan, candidate_witness in mutations:
        candidate = replace(proposal, use_def_witness=candidate_witness)
        assert not isinstance(validate_proposal(candidate_plan, candidate), ProposalAccepted), label


def test_use_def_allows_authoritative_redirect_owner_outside_dispatcher_members() -> None:
    """Redirect ownership follows the exact use-def manifest, not retirement scope."""

    from d810.transforms.plan import PatchRedirectGoto
    from d810.transforms.unflatten_authority.proposal import (
        ProposalAccepted, canonical_redirect_manifest, validate_proposal,
    )

    proposal, plan_id = _proposal_and_plan_ids()
    refs = tuple(block.block_ref for block in proposal.source_identity_catalog.blocks)
    assert refs[2] in tuple(
        handler.block_ref for handler in proposal.plan_inputs.authoritative_handlers
    )
    assert refs[2] not in proposal.plan_inputs.dispatcher_member_refs
    plan = PatchPlan(
        plan_id=plan_id,
        snapshot_id="snapshot-1",
        source_generation=3,
        steps=(PatchRedirectGoto(refs[2], refs[0], refs[1]),),
    )
    manifest = canonical_redirect_manifest(plan)
    candidate = replace(
        proposal,
        use_def_witness=replace(
            proposal.use_def_witness,
            redirect_owner_refs=manifest.owner_refs,
            redirect_digest=manifest.digest,
        ),
    )
    assert isinstance(validate_proposal(plan, candidate), ProposalAccepted)


def test_redirect_manifest_rejects_subclasses_and_invalid_typed_targets() -> None:
    from d810.transforms.cfg_transaction import PlanBlockRef
    from d810.transforms.plan import PatchRedirectBranch, PatchRedirectGoto
    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest

    proposal, plan_id = _proposal_and_plan_ids()
    refs = tuple(block.block_ref for block in proposal.source_identity_catalog.blocks)
    local = PlanBlockRef(plan_id, "helper")
    foreign = PlanBlockRef("foreign-plan", "helper")

    class RedirectSubclass(PatchRedirectGoto):
        pass

    invalid_steps = (
        RedirectSubclass(refs[0], refs[1], refs[2]),
        PatchRedirectBranch(refs[0], refs[1], refs[2], refs[1]),
    )
    for step in invalid_steps:
        plan = PatchPlan(
            plan_id=plan_id, snapshot_id="snapshot-1", source_generation=3,
            steps=(step,),
        )
        with pytest.raises((TypeError, ValueError), match="redirect|typed|plan|helper|manifest"):
            canonical_redirect_manifest(plan)
    with pytest.raises(ValueError, match="PlanBlockRef"):
        PatchPlan(
            plan_id=plan_id, snapshot_id="snapshot-1", source_generation=3,
            steps=(PatchRedirectGoto(refs[0], foreign, refs[1]),),
        )
    valid = PatchPlan(
        plan_id=plan_id, snapshot_id="snapshot-1", source_generation=3,
        steps=(PatchRedirectGoto(refs[0], local, refs[1]),),
    )
    assert canonical_redirect_manifest(valid).owner_refs == (refs[0],)


def test_typed_plan_has_no_parallel_shadow_transport() -> None:
    """A typed plan has only the canonical proposal channel."""

    # Direct construction still exercises the independent dual-channel guard.
    from dataclasses import fields
    assert "unflatten_proposal" in {item.name for item in fields(PatchPlan)}
    assert "legacy_unflatten_shadow" not in {item.name for item in fields(PatchPlan)}
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route

    proposal, plan_id = _proposal_and_plan_ids()
    typed, proposal = _typed_plan(proposal)
    selected = select_plan_route(typed)
    from d810.transforms.unflatten_authority.model import (
        UnflattenPlanRoute,
    )

    assert selected.route is UnflattenPlanRoute.TYPED_PROPOSAL

    with pytest.raises(ValueError, match="reserved legacy metadata"):
        replace(typed, metadata=(("dispatcher_corridor_coverage", {"legacy": True}),))

    assert not hasattr(typed, "legacy_unflatten_shadow")


def test_typed_attachment_seals_full_source_coordinates_from_source_mapping() -> None:
    """Typed authority retains the full source graph beyond executable rows."""

    from .test_bind import _exact_fixture
    from d810.transforms.plan import PatchRedirectGoto
    from d810.transforms.unflatten_authority.proposal import (
        attach_typed_proposal,
        canonical_redirect_manifest,
    )

    source, proposal, exclusion, refs = _exact_fixture()
    template = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id="snapshot-1",
        source_generation=1,
        steps=(PatchRedirectGoto(refs[0], refs[1], refs[2]),),
        source_coordinates=((refs[0], 0),),
    )
    manifest = canonical_redirect_manifest(template)
    witness = replace(
        proposal.use_def_witness,
        redirect_owner_refs=manifest.owner_refs,
        redirect_digest=manifest.digest,
    )

    attached = attach_typed_proposal(
        template,
        source=source,
        block_refs_by_serial=refs,
        canonical_route_evidence=proposal.route_evidence,
        exact_state_effect_exclusions=(exclusion,),
        dispatcher_entry_serial=1,
        dispatcher_member_serials=(0, 1),
        authoritative_handler_serials=(2,),
        state_identity=proposal.plan_inputs.state_identity,
        use_def_witness=witness,
    )

    assert attached.source_coordinates == tuple(
        (refs[serial], serial) for serial in sorted(source.blocks)
    )


def test_typed_attachment_snapshots_source_coordinates_before_mapping_mutation() -> None:
    """Late mapping mutation cannot change the sealed source coordinate table."""

    from collections.abc import Mapping

    from .test_bind import _exact_fixture
    from d810.transforms.plan import PatchRedirectGoto
    from d810.transforms.unflatten_authority.proposal import (
        attach_typed_proposal,
        canonical_redirect_manifest,
    )

    class LaterMutatingMapping(Mapping):
        def __init__(self, rows) -> None:
            self._rows = dict(rows)
            self._reads = 0

        def __getitem__(self, serial):
            self._reads += 1
            if self._reads == 61:
                self._rows[0], self._rows[1] = self._rows[1], self._rows[0]
            return self._rows[serial]

        def __iter__(self):
            return iter(self._rows)

        def __len__(self):
            return len(self._rows)

    source, proposal, exclusion, refs = _exact_fixture()
    template = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id="snapshot-1",
        source_generation=1,
        steps=(PatchRedirectGoto(refs[0], refs[1], refs[2]),),
    )
    manifest = canonical_redirect_manifest(template)
    witness = replace(
        proposal.use_def_witness,
        redirect_owner_refs=manifest.owner_refs,
        redirect_digest=manifest.digest,
    )

    mapping = LaterMutatingMapping(refs)
    attached = attach_typed_proposal(
        template,
        source=source,
        block_refs_by_serial=mapping,
        canonical_route_evidence=proposal.route_evidence,
        exact_state_effect_exclusions=(exclusion,),
        dispatcher_entry_serial=1,
        dispatcher_member_serials=(0, 1),
        authoritative_handler_serials=(2,),
        state_identity=proposal.plan_inputs.state_identity,
        use_def_witness=witness,
    )

    assert attached.source_coordinates == tuple(
        (refs[serial], serial) for serial in sorted(source.blocks)
    )
    assert mapping._reads == len(refs)


def test_first_typed_effect_plan_removes_reserved_legacy_metadata() -> None:
    """The first typed proposal leaves no parallel metadata channel."""

    from d810.transforms.unflatten_authority.legacy_keys import LEGACY_UNFLATTEN_KEYS
    from d810.transforms.unflatten_authority.proposal import attach_typed_proposal
    from .test_bind import _exact_fixture
    source, proposal, exclusion, refs = _exact_fixture()
    from d810.transforms.plan import PatchRedirectGoto
    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest
    plan_template = PatchPlan(
        plan_id=proposal.plan_id, snapshot_id="snapshot-1", source_generation=1,
        steps=(PatchRedirectGoto(refs[0], refs[1], refs[2]),),
    )
    manifest = canonical_redirect_manifest(plan_template)
    witness = replace(proposal.use_def_witness, redirect_owner_refs=manifest.owner_refs, redirect_digest=manifest.digest)
    from d810.transforms.unflatten_authority.legacy_keys import DISPATCHER_CORRIDOR_COVERAGE_METADATA
    values = tuple((key, {"family": key}) for key in LEGACY_UNFLATTEN_KEYS if key != DISPATCHER_CORRIDOR_COVERAGE_METADATA)
    plan = replace(plan_template, metadata=values, unflatten_proposal=None)
    with pytest.raises(ValueError, match="reserved legacy metadata"):
        attach_typed_proposal(
            plan,
            source=source, block_refs_by_serial=refs,
            canonical_route_evidence=proposal.route_evidence,
            exact_state_effect_exclusions=(exclusion,), dispatcher_entry_serial=1,
            dispatcher_member_serials=(0, 1), authoritative_handler_serials=(2,),
            state_identity=proposal.plan_inputs.state_identity, use_def_witness=witness,
        )


def test_typed_attachment_keeps_dispatcher_entry_when_not_a_redirect_owner() -> None:
    from .test_bind import _exact_fixture
    from d810.transforms.plan import PatchRedirectGoto
    from d810.transforms.unflatten_authority.proposal import attach_typed_proposal, canonical_redirect_manifest
    from d810.transforms.unflatten_authority.legacy_keys import LEGACY_UNFLATTEN_KEYS
    from d810.transforms.unflatten_authority.legacy_keys import DISPATCHER_CORRIDOR_COVERAGE_METADATA
    source, proposal, exclusion, refs = _exact_fixture()
    steps = (PatchRedirectGoto(refs[0], refs[2], refs[1]),)
    plan = PatchPlan(
        plan_id=proposal.plan_id, snapshot_id="snapshot-1",
        source_generation=1,
        steps=steps,
        metadata=tuple((key, {"family": key}) for key in LEGACY_UNFLATTEN_KEYS if key != DISPATCHER_CORRIDOR_COVERAGE_METADATA),
    )
    manifest = canonical_redirect_manifest(plan)
    witness = replace(proposal.use_def_witness, redirect_owner_refs=manifest.owner_refs, redirect_digest=manifest.digest)
    with pytest.raises(ValueError, match="reserved legacy metadata"):
        attach_typed_proposal(
            plan, source=source, block_refs_by_serial=refs,
            canonical_route_evidence=proposal.route_evidence,
            exact_state_effect_exclusions=(exclusion,), dispatcher_entry_serial=1,
            dispatcher_member_serials=(0, 1), authoritative_handler_serials=(2,),
            state_identity=proposal.plan_inputs.state_identity, use_def_witness=witness,
        )


def test_retirement_attachment_routes_present_family_keys_and_rejects_malformed_shapes() -> None:
    from d810.transforms.plan import PatchRedirectGoto
    from d810.transforms.unflatten_authority.legacy_keys import (
        DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA,
    )
    from d810.transforms.unflatten_authority.proposal import (
        attach_typed_proposal, canonical_redirect_manifest,
    )
    from .helpers import authority_id
    from .test_bind import _exact_fixture

    source, proposal, exclusion, refs = _exact_fixture()
    rows = tuple(
        {
            "role": "comparison_dispatcher",
            "anchor": {"serial": serial, "ea": proposal.source_identity_catalog.blocks[serial].anchor_ea},
            "retired": serial == 0,
        }
        for serial in (0, 1)
    )

    class TupleSubclass(tuple):
        pass

    class StringSubclass(str):
        pass

    cases = (
        [*rows],
        StringSubclass("not-rows"),
        TupleSubclass(rows),
        {"0": rows[0]},
    )
    for value in cases:
        template = PatchPlan(
            plan_id=proposal.plan_id, snapshot_id=authority_id("retirement-attach"),
            source_generation=1,
            steps=(PatchRedirectGoto(refs[0], refs[1], refs[2]),),
            metadata=((DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA, {
                "retired_infrastructure": value,
            }),),
        )
        manifest = canonical_redirect_manifest(template)
        witness = replace(
            proposal.use_def_witness,
            redirect_owner_refs=manifest.owner_refs,
            redirect_digest=manifest.digest,
        )
        with pytest.raises(ValueError, match="reserved legacy metadata"):
            attach_typed_proposal(
                template, source=source, block_refs_by_serial=refs,
                canonical_route_evidence=proposal.route_evidence,
                exact_state_effect_exclusions=(exclusion,), dispatcher_entry_serial=1,
                dispatcher_member_serials=(0, 1), authoritative_handler_serials=(2,),
                state_identity=proposal.plan_inputs.state_identity, use_def_witness=witness,
            )

    template = PatchPlan(
        plan_id=proposal.plan_id, snapshot_id=authority_id("retirement-attach-ambiguous"),
        source_generation=1,
        steps=(PatchRedirectGoto(refs[0], refs[1], refs[2]),),
        metadata=((DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA, {
            "retired_infrastructure": rows,
            "retired_corridor": rows,
        }),),
    )
    manifest = canonical_redirect_manifest(template)
    witness = replace(
        proposal.use_def_witness,
        redirect_owner_refs=manifest.owner_refs,
        redirect_digest=manifest.digest,
    )
    with pytest.raises(ValueError, match="reserved legacy metadata"):
        attach_typed_proposal(
            template, source=source, block_refs_by_serial=refs,
            canonical_route_evidence=proposal.route_evidence,
            exact_state_effect_exclusions=(exclusion,), dispatcher_entry_serial=1,
            dispatcher_member_serials=(0, 1), authoritative_handler_serials=(2,),
            state_identity=proposal.plan_inputs.state_identity, use_def_witness=witness,
        )

    terminal_template = PatchPlan(
        plan_id=proposal.plan_id, snapshot_id=authority_id("terminal-attach-none"),
        source_generation=1,
        steps=(PatchRedirectGoto(refs[0], refs[1], refs[2]),),
        metadata=((DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA, {
            "terminal_switch_cycle_break": None,
        }),),
    )
    terminal_manifest = canonical_redirect_manifest(terminal_template)
    terminal_witness = replace(
        proposal.use_def_witness,
        redirect_owner_refs=terminal_manifest.owner_refs,
        redirect_digest=terminal_manifest.digest,
    )
    with pytest.raises(ValueError, match="reserved legacy metadata"):
        attach_typed_proposal(
            terminal_template, source=source, block_refs_by_serial=refs,
            canonical_route_evidence=proposal.route_evidence,
            exact_state_effect_exclusions=(exclusion,), dispatcher_entry_serial=1,
            dispatcher_member_serials=(0, 1), authoritative_handler_serials=(2,),
            state_identity=proposal.plan_inputs.state_identity,
            use_def_witness=terminal_witness,
        )


def test_producer_exact_effect_claim_correlates_all_canonical_dimensions() -> None:
    from d810.analyses.control_flow.effect_branch_exclusion import ExactStateBranchEffectExclusion
    from d810.analyses.control_flow.semantic_route_evidence import (
        CanonicalSemanticEvidence,
        canonical_semantic_evidence_from_proofs,
        SemanticCarrierProof,
        SemanticCorridorPoint,
        SemanticPredicateKind,
        SemanticPredicateProof,
        SemanticRouteDestination,
        SemanticRouteProof,
        SemanticRouteProofKind,
        SemanticRouteShape,
        SemanticStateWriteDeliveryKind,
        SemanticStateWriteProof,
    )
    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.block_identity import StableBlockIdentity
    from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
    from d810.ir.semantic_edge import SemanticEdgeRole
    from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
    from d810.transforms.cfg_transaction import NativeBlockRef
    from d810.transforms.unflatten_authority import producer_api
    from d810.transforms.unflatten_authority.ids import authority_id
    from d810.transforms.unflatten_authority.model import UseDefFragmentWitness

    key = NativePreanalysisKey("input", "x86", 64, 0, "f" * 64, "p" * 64, "s" * 64)
    state = StorageIdentity(StorageIdentityKind.STACK, 4)
    specs = (
        (0, (1,), (), 0x1000, (InsnSnapshot(0, 0x1000, (), kind=InsnKind.MOV),)),
        (1, (2, 3), (0,), 0x2000, (InsnSnapshot(0, 0x2000, (), kind=InsnKind.NOP), InsnSnapshot(0, 0x2001, (), kind=InsnKind.COND_JUMP))),
        (2, (), (1,), 0x3000, (InsnSnapshot(0, 0x3000, (), kind=InsnKind.NOP),)),
        (3, (), (1,), 0x4000, (InsnSnapshot(0, 0x4000, (), kind=InsnKind.CALL, is_call=True),)),
    )
    blocks = {
        serial: BlockSnapshot(
            serial=serial, block_type=0, succs=succs, preds=preds, flags=0,
            start_ea=ea, native_start_ea=ea, insn_snapshots=insns,
            kind=BlockKind.TWO_WAY if len(succs) == 2 else BlockKind.ONE_WAY if succs else BlockKind.ZERO_WAY,
        )
        for serial, succs, preds, ea, insns in specs
    }
    blocks = {
        serial: replace(
            block,
            insn_snapshots=(rows := tuple(
                replace(insn, raw_opcode=insn.opcode) for insn in block.insn_snapshots
            )),
            tail_opcode=rows[-1].opcode if rows else None,
            raw_tail_opcode=rows[-1].raw_opcode if rows else None,
            tail_kind=rows[-1].kind if rows else None,
        )
        for serial, block in blocks.items()
    }
    source = FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x5000)
    refs = {}
    for serial, _succs, _preds, ea, insns in specs:
        identity = StableBlockIdentity.from_instruction_eas(
            [instruction.ea for instruction in insns], native_key=key,
        )
        refs[serial] = NativeBlockRef(identity)
    source_point = SemanticCorridorPoint(refs[0].identity, 0x1000)
    predicate_point = SemanticCorridorPoint(refs[1].identity, 0x2001)
    predicate_consumer = predicate_point
    state_write = SemanticStateWriteProof(
        refs[0].identity, 0x1000, state, 4, 7, (0x1000, 0x2000), None, (),
        SemanticStateWriteDeliveryKind.CONDITIONAL,
    )
    predicate = SemanticPredicateProof(
        SemanticPredicateKind.STORAGE_EQUALS, predicate_point, predicate_consumer,
        (predicate_point,), state, 4, 7, None, (),
    )
    carrier = SemanticCarrierProof(
        authority_id("carrier"), source_point, (predicate_consumer,),
        (source_point, predicate_consumer), state, 4, (7, 8), (0x1000,),
    )
    route = SemanticRouteProof(
        authority_id("route"), authority_id("group"), SemanticRouteProofKind.STATE_CHOICE,
        SemanticRouteShape.CONDITIONAL, refs[1].identity, 0x2000,
        (
            SemanticRouteDestination(SemanticEdgeRole.CONDITIONAL_TAKEN, 7, refs[2].identity, 0x3000),
            SemanticRouteDestination(SemanticEdgeRole.CONDITIONAL_FALLTHROUGH, 8, refs[3].identity, 0x4000),
        ), source_owner_identity=refs[0].identity, source_owner_anchor_ea=0x1000,
        state_write=state_write, predicate=predicate, carriers=(carrier,),
        diagnostic_provenance=(("provider_proof_kind", "state_choice"),),
    )
    evidence = canonical_semantic_evidence_from_proofs(
        native_key=key, generation=1, proofs=(route,),
    )
    catalog_refs = {serial: ref for serial, ref in refs.items()}
    exclusion = ExactStateBranchEffectExclusion(
        7, 0, 0x1000, 0x1000, 1, 0x2000, 0x2001, 2, 0x3000, 3, 0x4000, state,
    )
    witness = UseDefFragmentWitness(
        authority_id("fragment"), state, (refs[0],), authority_id("redirect"),
        True, True, 0, (),
    )
    proposal = producer_api.build_proposal(
        plan_id=authority_id("plan"), source=source, block_refs_by_serial=catalog_refs,
        source_generation=1, canonical_route_evidence=evidence,
        exact_state_effect_exclusions=(exclusion,), dispatcher_entry_serial=1,
        dispatcher_member_serials=(0, 1), authoritative_handler_serials=(2,),
        state_identity=state, use_def_witness=witness,
    )
    claim = proposal.claims[0]
    assert claim.width == 4
    assert claim.source_write_ea == 0x1000
    assert claim.predicate_branch_ea == 0x2001
    assert claim.selected_target_subject.block_ref == refs[2]
    assert claim.discarded_effect_subject.block_ref == refs[3]
    assert claim.source_generation == 1
    from d810.transforms.unflatten_authority.model import ProviderConsensusMode
    assert claim.consensus.mode is ProviderConsensusMode.NOT_APPLICABLE
    assert claim.consensus.provider_ids == ()

    with pytest.raises(ValueError, match="state identity"):
        producer_api.build_proposal(
            plan_id=authority_id("plan"), source=source, block_refs_by_serial=catalog_refs,
            source_generation=1, canonical_route_evidence=evidence,
            exact_state_effect_exclusions=(replace(exclusion, state_identity=StorageIdentity(StorageIdentityKind.STACK, 8)),),
            dispatcher_entry_serial=1, dispatcher_member_serials=(0, 1),
            authoritative_handler_serials=(2,), state_identity=state, use_def_witness=witness,
        )
    for field in (
        "source_serial", "predicate_serial", "selected_target_serial",
        "discarded_effect_serial",
    ):
        with pytest.raises(ValueError):
            producer_api.build_proposal(
                plan_id=authority_id("plan"), source=source, block_refs_by_serial=catalog_refs,
                source_generation=1, canonical_route_evidence=evidence,
                exact_state_effect_exclusions=(replace(exclusion, **{field: 99}),),
                dispatcher_entry_serial=1, dispatcher_member_serials=(0, 1),
                authoritative_handler_serials=(2,), state_identity=state, use_def_witness=witness,
            )


@pytest.mark.parametrize("kind_name", ["TRAP", "RET"])
def test_producer_exact_effect_claim_rejects_non_call_store_sites(kind_name) -> None:
    from dataclasses import replace
    from d810.ir.flowgraph import InsnKind
    from d810.transforms.unflatten_authority import producer_api
    from .test_bind import _exact_fixture
    kind = getattr(InsnKind, kind_name)
    source, proposal, exclusion, refs = _exact_fixture()
    discarded = source.blocks[exclusion.discarded_effect_serial]
    source = replace(
        source,
        blocks={
            **source.blocks,
            exclusion.discarded_effect_serial: replace(
                discarded,
                insn_snapshots=(replace(discarded.insn_snapshots[0], kind=kind, is_call=False),),
                tail_kind=kind,
            ),
        },
    )
    with pytest.raises(ValueError, match="effect"):
        producer_api.build_proposal(
            plan_id=proposal.plan_id, source=source, block_refs_by_serial=refs,
            source_generation=1, canonical_route_evidence=proposal.route_evidence,
            exact_state_effect_exclusions=(exclusion,), dispatcher_entry_serial=1,
            dispatcher_member_serials=(0, 1), authoritative_handler_serials=(2,),
            state_identity=proposal.plan_inputs.state_identity,
            use_def_witness=proposal.use_def_witness,
        )


def test_ordinary_and_legacy_only_plans_are_not_typed_authority() -> None:
    from d810.transforms.unflatten_authority.model import (
        UnflattenAuthorityNotApplicable,
        UnflattenAuthorityReason,
    )
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route

    ordinary = select_plan_route(PatchPlan(plan_id="ordinary", snapshot_id="snap"))
    assert isinstance(ordinary, UnflattenAuthorityNotApplicable)

    legacy_only = select_plan_route(
        PatchPlan(
            plan_id="legacy",
            snapshot_id="snap",
            metadata=(("dispatcher_corridor_coverage", {"legacy": True}),),
        )
    )
    assert legacy_only.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert legacy_only.detail_code == "legacy_metadata_requires_explicit_codec_adaptation"


def test_shadow_records_are_closed_sorted_and_digest_bound() -> None:
    from d810.transforms.unflatten_authority.legacy_wire import encode_legacy_value
    from d810.transforms.unflatten_authority.model import (
        LegacyShadowEntry,
        LegacyUnflattenShadowEnvelope,
    )

    payload = encode_legacy_value({"value": [1, 2]})
    digest = hashlib.sha256(payload).hexdigest()
    first = LegacyShadowEntry("dispatcher_corridor_coverage", payload, digest)
    second_payload = encode_legacy_value({"value": 2})
    second = LegacyShadowEntry(
        "use_def_severance_audit",
        second_payload,
        hashlib.sha256(second_payload).hexdigest(),
    )
    envelope = LegacyUnflattenShadowEnvelope(
        1, "plan", "snapshot", 0, (first, second)
    )
    assert envelope.entries == (first, second)
    with pytest.raises(ValueError, match="sorted"):
        LegacyUnflattenShadowEnvelope(1, "plan", "snapshot", 0, (second, first))
    with pytest.raises(ValueError, match="digest"):
        LegacyShadowEntry(first.key, payload, "0" * 64)
    with pytest.raises(ValueError, match="reserved"):
        LegacyShadowEntry("not-authority", payload, digest)
    with pytest.raises(ValueError, match="empty"):
        LegacyUnflattenShadowEnvelope(1, "plan", "snapshot", 0, ())


def test_typed_plan_requires_exact_plan_snapshot_and_generation_correlation() -> None:
    proposal, plan_id = _proposal_and_plan_ids()
    with pytest.raises(ValueError, match="proposal authority"):
        PatchPlan(
            plan_id="different",
            snapshot_id="snapshot-1",
            source_generation=3,
            unflatten_proposal=proposal,
        )
def test_mutated_proposal_is_revalidated_at_route_boundary() -> None:
    from d810.transforms.unflatten_authority.model import (
        ProposalValidationStage,
        UnflattenAuthorityReason,
    )
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route

    plan = PatchPlan(
        plan_id=_proposal_and_plan_ids()[1],
        snapshot_id="snapshot-1",
        source_generation=3,
        unflatten_proposal=_proposal_and_plan_ids()[0],
    )
    object.__setattr__(plan.unflatten_proposal, "schema_version", 2)
    result = select_plan_route(plan)
    assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert result.detail_code == "proposal_invariants_invalid"
    assert result.stage is ProposalValidationStage.ROUNDTRIP

    object.__setattr__(plan.unflatten_proposal, "schema_version", 1)
    object.__setattr__(plan.unflatten_proposal, "rule_set_version", 2)
    result = select_plan_route(plan)
    assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert result.detail_code == "proposal_invariants_invalid"
    assert result.stage is ProposalValidationStage.ROUNDTRIP

    object.__setattr__(plan.unflatten_proposal, "rule_set_version", 1)
    object.__setattr__(plan.unflatten_proposal, "plan_id", "sha256:" + "0" * 64)
    result = select_plan_route(plan)
    assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert result.detail_code == "proposal_plan_id_mismatch"


def test_proposal_versions_require_exact_int_one() -> None:
    from d810.transforms.unflatten_authority.model import UnflattenAuthorityReason
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route

    class IntSubclass(int):
        pass

    invalid_values = (True, False, IntSubclass(1), 1.0, "1")
    for field in ("schema_version", "rule_set_version"):
        for value in invalid_values:
            proposal, plan_id = _proposal_and_plan_ids()
            object.__setattr__(proposal, field, value)
            result = select_plan_route(PatchPlan(
                plan_id=plan_id,
                snapshot_id="snapshot-1",
                source_generation=3,
                unflatten_proposal=proposal,
            ))
            assert getattr(result, "reason", None) is UnflattenAuthorityReason.MALFORMED_PROPOSAL, (field, value)
            assert getattr(result, "detail_code", None) == "proposal_invariants_invalid", (field, value)

    proposal, plan_id = _proposal_and_plan_ids()
    typed, _ = _typed_plan(proposal)
    selected = select_plan_route(typed)
    assert selected.route.value == "typed_proposal"


def test_typed_route_revalidates_deep_canonical_proposal_mutations() -> None:
    from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
    from d810.transforms.unflatten_authority.model import UnflattenAuthorityReason
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route
    from .helpers import import_authority_model
    from .test_model import _native_key

    mutations = (
        ("anchor", lambda proposal: object.__setattr__(
            proposal.source_identity_catalog.blocks[0], "anchor_ea", 0xDEAD,
        )),
        ("empty_route_proofs", lambda proposal: object.__setattr__(
            proposal.route_evidence, "route_proofs", (),
        )),
        ("negative_handler_state", lambda proposal: object.__setattr__(
            proposal.plan_inputs.authoritative_handlers[0], "normalized_states", (-1,),
        )),
        ("string_shape", lambda proposal: object.__setattr__(
            proposal.plan_inputs, "shape", "partial_rewrite",
        )),
        ("duplicate_catalog_block", lambda proposal: object.__setattr__(
            proposal.source_identity_catalog, "blocks",
            (proposal.source_identity_catalog.blocks[0],) * 2
            + proposal.source_identity_catalog.blocks[2:],
        )),
        ("wrong_native_key", lambda proposal: object.__setattr__(
            proposal.route_evidence, "native_key", _native_key(
                import_authority_model(), fingerprint="wrong-route-key",
            ),
        )),
        ("wrong_generation", lambda proposal: object.__setattr__(
            proposal.route_evidence, "generation", 99,
        )),
        ("wrong_state_identity", lambda proposal: object.__setattr__(
            proposal.plan_inputs, "state_identity",
            StorageIdentity(StorageIdentityKind.REGISTER, 1),
        )),
        ("wrong_claim_child", lambda proposal: object.__setattr__(
            proposal.claims[0], "route_proof_ids", (),
        )),
    )
    for label, mutate in mutations:
        proposal, plan_id = _proposal_and_plan_ids()
        mutate(proposal)
        plan = PatchPlan(
            plan_id=plan_id,
            snapshot_id="snapshot-1",
            source_generation=3,
            unflatten_proposal=proposal,
        )
        result = select_plan_route(plan)
        assert getattr(result, "reason", None) is UnflattenAuthorityReason.MALFORMED_PROPOSAL, label
        assert getattr(result, "detail_code", None) == "proposal_invariants_invalid", label


def test_valid_proposal_has_stable_canonical_roundtrip_and_typed_route() -> None:
    from d810.transforms.unflatten_authority.ids import canonical_bytes, canonical_decode
    from d810.transforms.unflatten_authority.proposal import TypedProposalRoute
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route

    proposal, plan_id = _proposal_and_plan_ids()
    encoded = canonical_bytes(proposal)
    decoded = canonical_decode(encoded)
    assert type(decoded) is type(proposal)
    assert decoded == proposal
    assert canonical_bytes(decoded) == encoded
    typed, _ = _typed_plan(proposal)
    selected = select_plan_route(typed)
    assert isinstance(selected, TypedProposalRoute)


def test_reserved_metadata_shapes_fail_closed_and_cover_all_keys() -> None:
    from d810.transforms.unflatten_authority.proposal import LEGACY_UNFLATTEN_KEYS
    from d810.transforms.unflatten_authority.model import UnflattenAuthorityReason
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route

    for index, key in enumerate(sorted(LEGACY_UNFLATTEN_KEYS)):
        proposal, plan_id = _proposal_and_plan_ids()
        with pytest.raises(ValueError, match="reserved legacy metadata"):
            PatchPlan(
                plan_id=plan_id,
                snapshot_id="snapshot-1",
                source_generation=3,
                unflatten_proposal=proposal,
                metadata=([key, index],),
            )

    proposal, plan_id = _proposal_and_plan_ids()
    with pytest.raises(ValueError, match="reserved legacy metadata"):
        PatchPlan(
            plan_id=plan_id,
            snapshot_id="snapshot-1",
            source_generation=3,
            unflatten_proposal=proposal,
            metadata={"use_def_severance_audit": True},
        )

    malformed = PatchPlan(
        plan_id="ordinary",
        snapshot_id="snapshot-1",
    )
    object.__setattr__(malformed, "metadata", (("broken",),))
    result = select_plan_route(malformed)
    assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert result.detail_code == "metadata_shape_invalid"


def test_route_rejections_cannot_use_success_or_not_applicable_reasons() -> None:
    from d810.transforms.unflatten_authority.model import UnflattenAuthorityReason
    from d810.transforms.unflatten_authority.proposal import (
        ProposalRejected,
        RejectedPlanRoute,
    )

    for cls in (ProposalRejected, RejectedPlanRoute):
        with pytest.raises(ValueError, match="rejection reason"):
            cls(UnflattenAuthorityReason.ACCEPTED, "bad")
        with pytest.raises(ValueError, match="rejection reason"):
            cls(UnflattenAuthorityReason.NOT_APPLICABLE, "bad")


def test_metadata_generator_is_snapshotted_before_route_selection() -> None:
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route
    calls = []

    def metadata_generator():
        calls.append("iterated")
        yield ("ordinary", 1)

    plan = PatchPlan(
        plan_id="ordinary",
        snapshot_id="snapshot",
        metadata=metadata_generator(),
    )
    assert plan.metadata == (("ordinary", 1),)
    assert plan.metadata_dict() == {"ordinary": 1}
    assert select_plan_route(plan).route.value == "ordinary"
    assert plan.metadata_dict() == {"ordinary": 1}
    assert len(calls) == 1


def test_reserved_generator_remains_reserved_before_and_after_metadata_lookup() -> None:
    proposal, plan_id = _proposal_and_plan_ids()
    calls = []

    def metadata_generator():
        calls.append("iterated")
        yield ("use_def_severance_audit", True)

    with pytest.raises(ValueError, match="reserved legacy metadata"):
        PatchPlan(
            plan_id=plan_id,
            snapshot_id="snapshot-1",
            source_generation=3,
            metadata=metadata_generator(),
            unflatten_proposal=proposal,
        )
    assert len(calls) == 1


class _ReservedAlias:
    def __hash__(self):
        return hash("use_def_severance_audit")

    def __eq__(self, other):
        return other == "use_def_severance_audit"


class _ExplodingHash:
    def __hash__(self):
        raise RuntimeError("hash exploded")


class _ExplodingPair:
    def __iter__(self):
        raise RuntimeError("pair exploded")


class _ExplodingMapping(dict):
    def items(self):
        raise RuntimeError("mapping exploded")


def test_reserved_scan_precedes_duplicate_collapse_and_aliases_fail_closed() -> None:
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route
    proposal, plan_id = _proposal_and_plan_ids()
    with pytest.raises(ValueError, match="reserved legacy metadata"):
        PatchPlan(
            plan_id=plan_id,
            snapshot_id="snapshot-1",
            source_generation=3,
            metadata=((_ReservedAlias(), 1), ("use_def_severance_audit", 2)),
            unflatten_proposal=proposal,
        )

    hostile = PatchPlan(plan_id="ordinary", snapshot_id="snapshot")
    object.__setattr__(hostile, "metadata", ((_ExplodingHash(), 1),))
    result = select_plan_route(hostile)
    assert result.reason.value == "malformed_proposal"
    assert result.detail_code == "metadata_key_type_invalid"

    hostile_pair = PatchPlan(plan_id="ordinary", snapshot_id="snapshot")
    object.__setattr__(hostile_pair, "metadata", (_ExplodingPair(),))
    result = select_plan_route(hostile_pair)
    assert result.reason.value == "malformed_proposal"
    assert result.detail_code == "metadata_shape_invalid"

    constructor_hostile = PatchPlan(
        plan_id="ordinary", snapshot_id="snapshot", metadata=_ExplodingMapping()
    )
    result = select_plan_route(constructor_hostile)
    assert result.reason.value == "malformed_proposal"
    assert result.detail_code == "metadata_shape_invalid"

    constructor_pair = PatchPlan(
        plan_id="ordinary", snapshot_id="snapshot", metadata=(_ExplodingPair(),)
    )
    result = select_plan_route(constructor_pair)
    assert result.reason.value == "malformed_proposal"
    assert result.detail_code == "metadata_shape_invalid"


class _LateAlias(str):
    def __hash__(self):
        return hash("use_def_severance_audit")

    def __eq__(self, other):
        return other == "use_def_severance_audit"


def test_str_subclass_metadata_key_is_not_authority_routing_input() -> None:

    proposal, plan_id = _proposal_and_plan_ids()
    with pytest.raises(ValueError, match="reserved legacy metadata"):
        PatchPlan(
            plan_id=plan_id,
            snapshot_id="snapshot-1",
            source_generation=3,
            metadata=((_LateAlias("use_def_severance_audit"), True),),
            unflatten_proposal=proposal,
        )
@pytest.mark.parametrize(
    ("fixture", "expected_kind"),
    (
        ("_compiler_direct_branch_case", "REDIRECT_BRANCH"),
        ("_compiler_helper_branch_case", "REDIRECT_BRANCH"),
        ("_three_b3_split_trampoline_case", "SPLIT"),
        ("_three_b3_one_block_corridor_case", "HELPER_CORRIDOR"),
        ("_three_b3_two_block_corridor_case", "HELPER_CORRIDOR"),
    ),
)
def test_3b3_descriptor_and_creation_rows_match_compiler_families(fixture, expected_kind) -> None:
    from d810.transforms.unflatten_authority.proposal import (
        _patch_block_spec_preimage, canonical_patch_step_descriptor,
    )
    from tests.unit.transforms.unflatten_authority import test_bind as bind_tests

    _authority, plan, *_ = getattr(bind_tests, fixture)()
    descriptor = canonical_patch_step_descriptor(plan, 0)
    assert descriptor.step_kind.name == expected_kind
    assert descriptor.plan_id == plan.plan_id
    expected_owners = tuple(spec.block_id for spec in plan.new_blocks)
    source_owner = getattr(plan.steps[0], "from_serial", None)
    expected_owner_refs = ((source_owner, *expected_owners) if source_owner is not None else expected_owners)
    if expected_owners:
        assert descriptor.owner_refs == expected_owner_refs
        assert descriptor.helper_refs == expected_owners
    else:
        assert descriptor.owner_refs == (plan.steps[0].from_serial,)
        assert descriptor.helper_refs == ()
    expected_rows = tuple(
        (spec.block_id, authority_id(_patch_block_spec_preimage(index, spec)))
        for index, spec in enumerate(plan.new_blocks)
    )
    assert descriptor.new_block_spec_digests == expected_rows
    assert tuple(owner for owner, _digest in descriptor.new_block_spec_digests) == expected_owners
