"""Focused total route-selection tests for the transaction facade."""

from __future__ import annotations

from copy import copy, deepcopy
from dataclasses import FrozenInstanceError, fields, replace
from inspect import signature
import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from d810.transforms.plan import (
    PatchBlockSpec,
    PatchEdgeRef,
    PatchPlan,
    PatchRedirectBranch,
    PatchRedirectGoto,
)
from d810.transforms.cfg_transaction import CfgProjection, PlanBlockRef, TransactionAttemptId
from d810.transforms.unflatten_authority.model import (
    UnflattenAuthorityReason,
    UnflattenAuthorityNotApplicable,
    UnflattenPlanRoute,
)
from d810.transforms.unflatten_authority.transaction_api import select_plan_route
from d810.transforms.unflatten_authority.proposal import attach_typed_proposal
from d810.transforms.unflatten_authority.ids import authority_id
from d810.transforms.unflatten_authority import model, transaction_api
from d810.core import LevelFlag

from .helpers import (
    authority_id as helper_authority_id,
    block_ref,
    exact_fixture,
    import_authority_model,
    observed_patch_binding_for_test,
)
from .test_model import _valid_proposal
from .test_bind import _compiler_redirect_goto_case


def test_observed_native_origin_diagnostic_matches_canonical_subset_admission(
    caplog,
) -> None:
    """Diagnostics must not call a binder-admitted subset a mismatch."""

    source, proposal, _exclusion, refs = exact_fixture()
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        source_generation=1,
        source_coordinates=tuple(
            (refs[serial], serial) for serial in sorted(source.blocks)
        ),
    )
    inventory = transaction_api._build_semantic_graph_inventory(
        source,
        proposal,
        plan,
        source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
    )
    witnesses = {
        witness.block_ref: witness
        for witness in proposal.source_identity_catalog.blocks
    }
    row = next(
        candidate
        for candidate in inventory.blocks
        if (
            type(candidate.block_ref).__name__ == "NativeBlockRef"
            and len(candidate.native_instruction_eas) > 1
            and witnesses[candidate.block_ref].anchor_ea
            in candidate.native_instruction_eas
        )
    )
    expected = row.native_instruction_eas
    anchor = witnesses[row.block_ref].anchor_ea
    admitted = tuple(ea for ea in expected if ea != expected[-1])
    if anchor not in admitted:
        admitted = tuple(ea for ea in expected if ea != expected[0])
    assert model._phase_native_origin_subset_preserves_anchor(
        row.block_ref, anchor, admitted, expected,
    )
    invalid = tuple(ea for ea in expected if ea != anchor)
    assert not model._phase_native_origin_subset_preserves_anchor(
        row.block_ref, anchor, invalid, expected,
    )

    def with_origins(origins):
        drifted = copy(row)
        object.__setattr__(drifted, "native_instruction_eas", origins)
        return [
            drifted if candidate is row else candidate
            for candidate in inventory.blocks
        ]

    caplog.set_level(
        logging.DEBUG,
        logger="d810.transforms.unflatten_authority.transaction_api",
    )
    # ``caplog.set_level`` sets the stdlib ``Logger.level`` directly and does
    # not know about ``LevelFlag``'s process-global version counter, so a
    # ``logger.debug_on`` result cached earlier in this worker (by any test
    # that hit ``_observed_native_origin_mismatch_diagnostics`` while the
    # logger was still at its default INFO level) stays stale and the
    # DEBUG-gated log line below is silently skipped. Only
    # ``LoggerConfigurator.set_level`` (the production entry point) bumps the
    # version; mirror that here so this test does not depend on run order.
    LevelFlag.bump_config_version()
    transaction_api._observed_native_origin_mismatch_diagnostics(
        block_rows=with_origins(admitted),
        blocks_by_serial=source.blocks,
        proposal=proposal,
        plan=plan,
        function_ea=source.func_ea,
    )
    messages = tuple(record.getMessage() for record in caplog.records)
    assert any("native-origin subset accepted" in message for message in messages)
    assert not any(
        record.levelno >= logging.WARNING
        and "native-origin mismatch" in record.getMessage()
        for record in caplog.records
    )

    caplog.clear()
    transaction_api._observed_native_origin_mismatch_diagnostics(
        block_rows=with_origins(invalid),
        blocks_by_serial=source.blocks,
        proposal=proposal,
        plan=plan,
        function_ea=source.func_ea,
    )
    assert any(
        record.levelno >= logging.WARNING
        and "native-origin mismatch" in record.getMessage()
        for record in caplog.records
    )


def test_binds_no_provider_entry_endpoint_liveness_to_its_exact_redirect_fact() -> None:
    """A nested-style entry bridge is authorized only by its own patch fact."""
    (
        _source_authority,
        plan,
        source_inventory,
        _projected_inventory,
        patch_step_facts,
        _attempt_id,
        *_ignored,
    ) = _compiler_redirect_goto_case()
    fact = next(item for item in patch_step_facts if item.step_type == "PatchRedirectGoto")
    owner = fact.owner_ref
    step = plan.steps[fact.step_index]
    old_target = step.old_target
    replacement = step.new_target
    (route_proof,) = plan.unflatten_proposal.route_evidence.route_proofs
    write_ref = next(
        ref for ref, _serial in plan.source_coordinates
        if getattr(ref, "identity", None) == route_proof.state_write.identity
    )
    source, *_ = exact_fixture()
    source_inventory = transaction_api._build_semantic_graph_inventory(
        source, plan.unflatten_proposal, plan, source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
    )
    serials = dict(plan.source_coordinates)
    owner_serial = serials[step.from_serial]
    old_serial = serials[step.old_target]
    replacement_serial = serials[step.new_target]
    projected_blocks = dict(source.blocks)
    projected_blocks[owner_serial] = replace(
        projected_blocks[owner_serial],
        succs=(replacement_serial,),
    )
    projected_blocks[old_serial] = replace(
        projected_blocks[old_serial], preds=tuple(
            serial for serial in projected_blocks[old_serial].preds
            if serial != owner_serial
        ),
    )
    projected_blocks[replacement_serial] = replace(
        projected_blocks[replacement_serial], preds=tuple(sorted((
            *projected_blocks[replacement_serial].preds, owner_serial,
        ))),
    )
    from d810.ir.flowgraph import FlowGraph
    projected = FlowGraph(projected_blocks, source.entry_serial, source.func_ea)
    allowance_fields = (
        model.EntryEndpointLivenessReason.NO_PROVIDER_EXIT_PATH_LIVE_SAFE_ENDPOINT,
        int(route_proof.state_write.state_constant), route_proof.proof_id,
        (owner,), old_target, replacement, (old_target,),
        fact.step_index, fact.step_digest, write_ref,
        route_proof.state_write.instruction_ea, False,
    )
    allowance = model.EntryEndpointLivenessAllowance(
        allowance_id=authority_id(("unflatten.entry-endpoint-liveness-allowance.v1", *allowance_fields)),
        reason=model.EntryEndpointLivenessReason.NO_PROVIDER_EXIT_PATH_LIVE_SAFE_ENDPOINT,
        normalized_state=int(route_proof.state_write.state_constant),
        route_proof_id=route_proof.proof_id,
        entry_predecessor_owner_refs=(owner,),
        dispatcher_old_target_ref=old_target,
        replacement_endpoint_ref=replacement,
        exit_path_refs=(old_target,),
        patch_step_index=fact.step_index,
        patch_step_digest=fact.step_digest,
        state_write_source_ref=write_ref,
        state_write_instruction_ea=route_proof.state_write.instruction_ea,
    )
    plan = replace(
        plan,
        unflatten_proposal=replace(
            plan.unflatten_proposal,
            entry_endpoint_liveness_allowances=(allowance,),
        ),
    )

    bound = transaction_api.bind_entry_endpoint_liveness_allowances(
        plan=plan, allowances=(allowance,), patch_step_facts=patch_step_facts,
        source=source, projected=projected,
        source_inventory=source_inventory,
        projected_inventory=transaction_api._build_semantic_graph_inventory(
            projected, plan.unflatten_proposal, plan, source=False,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            source_subjects=source_inventory.subjects,
        ),
    )

    assert bound[0].allowance is allowance
    assert bound[0].patch_step_fact is fact
    with pytest.raises(ValueError, match="unique step indices"):
        transaction_api.bind_entry_endpoint_liveness_allowances(
            plan=plan, allowances=(allowance,), patch_step_facts=(*patch_step_facts, fact),
            source=source, projected=projected, source_inventory=source_inventory,
            projected_inventory=transaction_api._build_semantic_graph_inventory(
                projected, plan.unflatten_proposal, plan, source=False,
                phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
                source_subjects=source_inventory.subjects,
            ),
        )
    with pytest.raises(ValueError, match="ambiguous"):
        transaction_api._admit_bound_entry_endpoint_liveness(
            proposal=plan.unflatten_proposal, receipts=bound,
            patch_step_facts=(*patch_step_facts, fact),
        )
    assert not hasattr(
        transaction_api.authority_bind,
        "mint_bound_entry_endpoint_liveness_allowance",
    )
    # Content equality is insufficient authority: the receipt must be the
    # exact binder-minted occurrence that the transaction admitted.
    reconstructed = replace(bound[0])
    with pytest.raises(ValueError, match="binder-minted"):
        transaction_api._admit_bound_entry_endpoint_liveness(
            proposal=plan.unflatten_proposal,
            receipts=(reconstructed,),
            patch_step_facts=patch_step_facts,
        )
    # The lower publication primitive prechecks the complete batch: a later
    # duplicate cannot leave the first occurrence partially published.
    with pytest.raises(ValueError, match="duplicated"):
        transaction_api.authority_bind._publish_bound_entry_endpoint_liveness_batch(
            (reconstructed, reconstructed)
        )
    with pytest.raises(ValueError, match="binder-minted"):
        transaction_api.authority_bind.validate_bound_entry_endpoint_liveness_allowance(
            reconstructed
        )
    with pytest.raises(ValueError, match="allowance ID"):
        transaction_api.bind_entry_endpoint_liveness_allowances(
            plan=plan,
            allowances=(replace(allowance, patch_step_digest=authority_id("drift")),),
            patch_step_facts=patch_step_facts,
            source=source, projected=projected,
            source_inventory=source_inventory,
            projected_inventory=transaction_api._build_semantic_graph_inventory(
                projected, plan.unflatten_proposal, plan, source=False,
                phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
                source_subjects=source_inventory.subjects,
            ),
        )


def test_closed_entry_forecast_flows_from_canonical_proof_to_transaction_binding() -> None:
    """A one-shot selected-proof iterable seals the entry receipt end to end."""
    (
        _source_authority,
        compiled,
        _source_inventory,
        _projected_inventory,
        _patch_step_facts,
        _attempt_id,
        *_ignored,
    ) = _compiler_redirect_goto_case()
    original_proposal = compiled.unflatten_proposal
    assert original_proposal is not None
    (route_proof,) = original_proposal.route_evidence.route_proofs
    source, *_ = exact_fixture()
    refs_by_serial = {serial: ref for ref, serial in compiled.source_coordinates}
    serials_by_ref = dict(compiled.source_coordinates)
    step = compiled.steps[0]
    assert type(step) is PatchRedirectGoto
    owner = step.from_serial
    old = step.old_target
    replacement = step.new_target
    write_ref = next(
        ref for ref, _serial in compiled.source_coordinates
        if ref.identity == route_proof.state_write.identity
    )
    forecast = model.EntryEndpointLivenessForecast(
        model.EntryEndpointLivenessReason.NO_PROVIDER_EXIT_PATH_LIVE_SAFE_ENDPOINT,
        int(route_proof.state_write.state_constant),
        route_proof.proof_id,
        owner,
        write_ref,
        route_proof.state_write.instruction_ea,
        old,
        replacement,
        (old,),
    )
    plan = attach_typed_proposal(
        replace(compiled, unflatten_proposal=None),
        source=source,
        block_refs_by_serial=refs_by_serial,
        canonical_route_evidence=original_proposal.route_evidence,
        selected_route_proof_ids=(
            proof_id for proof_id in (route_proof.proof_id,)
        ),
        exact_state_effect_exclusions=(),
        dispatcher_entry_serial=serials_by_ref[old],
        dispatcher_member_serials=(serials_by_ref[old],),
        authoritative_handler_serials=(serials_by_ref[replacement],),
        state_identity=original_proposal.plan_inputs.state_identity,
        use_def_witness=original_proposal.use_def_witness,
        entry_endpoint_liveness_forecasts=(forecast,),
    )
    (allowance,) = plan.unflatten_proposal.entry_endpoint_liveness_allowances
    assert allowance.route_proof_id == route_proof.proof_id
    assert allowance.state_write_source_ref == write_ref

    owner_serial = serials_by_ref[owner]
    old_serial = serials_by_ref[old]
    replacement_serial = serials_by_ref[replacement]
    blocks = dict(source.blocks)
    blocks[owner_serial] = replace(blocks[owner_serial], succs=(replacement_serial,))
    blocks[old_serial] = replace(
        blocks[old_serial],
        preds=tuple(serial for serial in blocks[old_serial].preds if serial != owner_serial),
    )
    blocks[replacement_serial] = replace(
        blocks[replacement_serial],
        preds=tuple(sorted((*blocks[replacement_serial].preds, owner_serial))),
    )
    from d810.ir.flowgraph import FlowGraph
    projected = FlowGraph(blocks, source.entry_serial, source.func_ea)
    source_inventory = transaction_api._build_semantic_graph_inventory(
        source, plan.unflatten_proposal, plan, source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
    )
    projected_inventory = transaction_api._build_semantic_graph_inventory(
        projected, plan.unflatten_proposal, plan, source=False,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        source_subjects=source_inventory.subjects,
    )
    facts = transaction_api._derive_transaction_facts(
        source_inventory, plan,
    ).patch_step_facts
    (bound,) = transaction_api.bind_entry_endpoint_liveness_allowances(
        plan=plan,
        allowances=(allowance,),
        patch_step_facts=facts,
        source=source,
        projected=projected,
        source_inventory=source_inventory,
        projected_inventory=projected_inventory,
    )
    assert bound.allowance is allowance
    assert bound.route_proof_id == route_proof.proof_id


def test_entry_liveness_distinct_owner_requires_delivery_corridor() -> None:
    """P cannot borrow W's route proof without an exact W -> P -> D path."""
    source, proposal, _exclusion, refs = exact_fixture()
    (proof,) = proposal.route_evidence.route_proofs

    with pytest.raises(ValueError, match="distinct owner requires.*corridor"):
        model.EntryEndpointLivenessForecast(
            model.EntryEndpointLivenessReason.NO_PROVIDER_EXIT_PATH_LIVE_SAFE_ENDPOINT,
            int(proof.state_write.state_constant),
            proof.proof_id,
            refs[1],
            refs[0],
            proof.state_write.instruction_ea,
            refs[2],
            refs[3],
            (refs[2],),
        )


@pytest.mark.parametrize(
    ("redirect_factory", "expected_step_type"),
    (
        pytest.param(
            "goto", PatchRedirectGoto,
            id="redirect-goto",
        ),
        pytest.param(
            "branch", PatchRedirectBranch,
            id="redirect-branch",
        ),
    ),
)
def test_entry_liveness_keeps_state_write_distinct_from_physical_redirect_owner(
    redirect_factory: str,
    expected_step_type: type[PatchRedirectGoto | PatchRedirectBranch],
) -> None:
    """A state write may reach D through P while P owns the physical rewrite.

    W=blk0 writes the dispatcher state, P=blk1 selects the D=blk2 arm, and
    the projected edit redirects exactly P:D -> H=blk3.  This is deliberately
    not a fabricated relation: evidence, proposal, inventories, patch fact,
    receipt, and projected realization are all rebuilt through the public
    authority helpers.
    """
    from d810.analyses.control_flow import semantic_route_evidence as route
    from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
    from d810.ir.flowgraph import FlowGraph
    from d810.transforms.cfg_transaction import NativeBlockRef
    from d810.transforms.cfg_transaction import TransactionAttemptId
    from d810.transforms.edit_simulator import project_post_state
    from d810.transforms.graph_modification import RedirectBranch, RedirectGoto
    from d810.transforms.unflatten_authority import bind, producer_api
    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest
    from tests.typed_patch_authority import compile_patch_plan

    source, base, _exclusion, refs = exact_fixture()
    blocks = dict(source.blocks)
    # The physical microcode block start is a valid source-catalog witness,
    # but the canonical route destination is anchored at its first native
    # instruction.  The two coordinates must not be compared as one model.
    blocks[4] = replace(blocks[4], start_ea=0x4FF0)
    refs = {
        **refs,
        4: NativeBlockRef(StableBlockIdentity.from_intervals(
            (NativeEaInterval(0x4FF0, 0x5001),),
            native_key=base.source_identity_catalog.native_key,
            exact_instruction_eas=(0x5000,),
        )),
    }
    if redirect_factory == "goto":
        # GOTO is a real one-way P -> D edge; H is introduced by the edit.
        from .test_bind import _one_way_goto

        blocks[1] = _one_way_goto(blocks[1], 2, preds=(0,))
        blocks[2] = replace(blocks[2], preds=(1,))
        blocks[3] = replace(blocks[3], preds=())
    else:
        # BRANCH preserves P's other arm (blk3) and redirects only P:D -> H.
        blocks[4] = replace(blocks[4], preds=())
    source = FlowGraph(blocks, source.entry_serial, source.func_ea)
    state = base.route_evidence.route_proofs[0].state_write.state_variable
    fact = route.SemanticRouteFact(
        route.SemanticRouteFactKind.NATIVE_BOUND,
        0,  # W: physical state write
        0,
        0x1000,
        7,
        4,  # H: semantic destination
        0x1000,
        0x5000,
        (0,),
        (),
        authority_id(("entry-liveness-distinct-owner", redirect_factory)),
        physical_state_write=route.SemanticPhysicalStateWriteWitness(
            route._instruction_projection(source.blocks[0].insn_snapshots[0]),
            state,
            4,
            7,
        ),
    )
    produced = route.build_canonical_semantic_evidence(
        (fact,),
        route.CanonicalSemanticEvidenceProductionContext(
            base.source_identity_catalog.native_key,
            1,
            authority_id(("entry-liveness-distinct-owner-context", redirect_factory)),
            state,
            tuple(source.blocks.values()),
            tuple((serial, ref.identity) for serial, ref in refs.items()),
            source.entry_serial,
        ),
    )
    assert produced.abstention is None and produced.evidence is not None
    evidence = produced.evidence
    (proof,) = evidence.route_proofs
    assert proof.state_write.identity == refs[0].identity
    assert refs[0] != refs[1]

    modification = (
        RedirectGoto(1, 2, 4)
        if redirect_factory == "goto"
        else RedirectBranch(1, 2, 4)
    )
    compiled = compile_patch_plan(
        (modification,),
        source,
        plan_id=authority_id(("entry-liveness-distinct-owner-plan", redirect_factory)),
        source_generation=1,
        block_refs_by_serial=refs,
    )
    manifest = canonical_redirect_manifest(compiled)
    forecast = model.EntryEndpointLivenessForecast(
        model.EntryEndpointLivenessReason.NO_PROVIDER_EXIT_PATH_LIVE_SAFE_ENDPOINT,
        7,
        proof.proof_id,
        refs[1],  # P: physical owner, deliberately distinct from W
        refs[0],
        proof.state_write.instruction_ea,
        refs[2],  # D
        refs[4],  # H
        (refs[2],),
        (refs[0], refs[1], refs[2]),
        ((0, 1), (1, 2)),
    )

    def attach_entry(entry_evidence, entry_forecast):
        (entry_proof,) = entry_evidence.route_proofs
        return attach_typed_proposal(
            replace(compiled, unflatten_proposal=None),
            source=source,
            block_refs_by_serial=refs,
            canonical_route_evidence=entry_evidence,
            selected_route_proof_ids=(entry_proof.proof_id,),
            exact_state_effect_exclusions=(),
            dispatcher_entry_serial=2,
            dispatcher_member_serials=(2,),
            authoritative_handler_serials=(4,),
            state_identity=state,
            use_def_witness=model.UseDefFragmentWitness(
                authority_id((
                    "entry-liveness-distinct-owner-fragment", redirect_factory,
                )),
                state,
                manifest.owner_refs,
                manifest.digest,
                True,
                True,
                0,
                (),
            ),
            entry_endpoint_liveness_forecasts=(replace(
                entry_forecast,
                route_proof_id=entry_proof.proof_id,
            ),),
        )

    def evidence_with_destination(destination):
        return route.canonical_semantic_evidence_from_proofs(
            native_key=evidence.native_key,
            generation=evidence.generation,
            proofs=(replace(proof, destinations=(destination,)),),
        )

    # Keep target identity and the exact-one-destination requirement closed:
    # a source-catalog block start is not a semantic route anchor.
    with pytest.raises(
        ValueError,
        match=(
            "entry liveness forecast does not name its selected canonical "
            "route proof: destination"
        ),
    ):
        attach_entry(
            evidence_with_destination(replace(
                proof.destinations[0], target_anchor_ea=0x4FF0,
            )),
            forecast,
        )
    with pytest.raises(
        ValueError,
        match=(
            "entry liveness forecast does not name its selected canonical "
            "route proof: destination"
        ),
    ):
        attach_entry(
            evidence_with_destination(replace(
                proof.destinations[0],
                target_identity=refs[3].identity,
                target_anchor_ea=0x4000,
            )),
            forecast,
        )
    # A-shaped lifecycle regression: the physical redirect owner P is a
    # source witness, but it is not the selected canonical proof's state
    # write W.  A forecast must reject that substitution at the exact clause.
    with pytest.raises(
        ValueError,
        match=(
            "entry liveness forecast does not name its selected canonical "
            "route proof: state_write_identity"
        ),
    ):
        attach_entry(
            evidence,
            replace(
                forecast,
                state_write_source_ref=refs[1],
                state_write_instruction_ea=source.blocks[1].start_ea,
                delivery_path_refs=(refs[1], refs[2]),
                delivery_path_edges=((0, 1),),
            ),
        )
    plan = attach_entry(evidence, forecast)
    (allowance,) = plan.unflatten_proposal.entry_endpoint_liveness_allowances
    assert allowance.state_write_source_ref == refs[0]
    assert allowance.entry_predecessor_owner_refs == (refs[1],)
    assert allowance.delivery_path_refs == (refs[0], refs[1], refs[2])
    assert allowance.delivery_path_edges == ((0, 1), (1, 2))

    materialization = route.CanonicalRouteMaterialization.capture(
        source,
        generation=1,
        phase=route.CanonicalRouteAssessmentPhase.SOURCE,
    )
    source_inventory = transaction_api._build_semantic_graph_inventory(
        source,
        plan.unflatten_proposal,
        plan,
        source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        materialization=materialization,
    )
    source_result = bind.bind_source_route_authority(
        proposal=plan.unflatten_proposal,
        source_inventory=source_inventory,
        source_materialization=materialization,
    )
    assert type(source_result) is model.SourceBoundRouteAuthorityAccepted
    projected = project_post_state(source, plan)
    projected_inventory = transaction_api._build_semantic_graph_inventory(
        projected,
        plan.unflatten_proposal,
        plan,
        source=False,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        source_subjects=source_inventory.subjects,
    )
    from d810.analyses.control_flow.graph_checks import (
        check_effectful_reachability_preserved,
        check_entry_reachability_not_collapsed,
        check_terminal_reachability_preserved,
    )
    from d810.transforms.unflatten_authority.gates import GenericCfgGateBundle

    raw_effect = check_effectful_reachability_preserved(source, post_cfg=projected)
    preparation = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=TransactionAttemptId(
            plan.plan_id,
            authority_id(("entry-liveness-distinct-owner-session", redirect_factory)),
            1,
            authority_id(("entry-liveness-distinct-owner-attempt", redirect_factory)),
        ),
        generic_gates=GenericCfgGateBundle(
            check_entry_reachability_not_collapsed(source, post_cfg=projected),
            raw_effect,
            raw_effect,
            check_terminal_reachability_preserved(source, post_cfg=projected),
        ),
    )

    assert type(plan.steps[0]) is expected_step_type
    assert type(preparation) is model.UnflattenAuthorityPreparationAccepted
    assert preparation.prepared is not None
    (row,) = preparation.prepared.projected_route_realization.rows
    if redirect_factory == "goto":
        assert type(row.relation) is model.RetainedPrefixRouteRealization
        assert row.relation.proof_source.ref == refs[0]
        assert row.relation.delivery_owner.ref == refs[1]
        assert row.relation.old_target.ref == refs[2]
        assert row.relation.new_target.ref == refs[4]
    else:
        assert type(row.relation) is model.TwoArmDirectBranchRouteRealization
        assert row.relation.feeder.ref == refs[1]
        assert row.relation.source_rewritten_arm.ref == refs[2]
        assert row.relation.projected_replacement_arm.ref == refs[4]
    assert proof.state_write.identity == refs[0].identity

    if redirect_factory == "goto":
        broken_blocks = dict(source.blocks)
        broken_blocks[0] = _one_way_goto(broken_blocks[0], 3, preds=())
        broken_blocks[1] = replace(broken_blocks[1], preds=())
        broken_blocks[3] = replace(broken_blocks[3], preds=(0,))
        broken_source = FlowGraph(
            broken_blocks, source.entry_serial, source.func_ea,
        )
        broken_projected = project_post_state(broken_source, plan)
        broken_materialization = route.CanonicalRouteMaterialization.capture(
            broken_source,
            generation=1,
            phase=route.CanonicalRouteAssessmentPhase.SOURCE,
        )
        broken_source_inventory = transaction_api._build_semantic_graph_inventory(
            broken_source,
            plan.unflatten_proposal,
            plan,
            source=True,
            phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
            materialization=broken_materialization,
        )
        broken_projected_inventory = transaction_api._build_semantic_graph_inventory(
            broken_projected,
            plan.unflatten_proposal,
            plan,
            source=False,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            source_subjects=broken_source_inventory.subjects,
        )
        broken_facts = transaction_api._derive_patch_lineage_facts(
            broken_source_inventory, plan,
        )
        with pytest.raises(ValueError, match="delivery corridor drifted"):
            transaction_api.bind_entry_endpoint_liveness_allowances(
                plan=plan,
                allowances=(allowance,),
                patch_step_facts=broken_facts,
                source=broken_source,
                projected=broken_projected,
                source_inventory=broken_source_inventory,
                projected_inventory=broken_projected_inventory,
            )


def test_entry_liveness_admission_rejects_two_receipts_in_noncanonical_binding_order() -> None:
    """The prepared transaction never normalizes caller receipt ordering."""
    from . import test_bind

    (
        _authority, plan, source_inventory, projected_inventory, facts, _attempt,
        source, projected,
    ) = test_bind._two_proof_shared_target_case(include_graphs=True)
    proofs = {
        proof.source_identity: proof
        for proof in plan.unflatten_proposal.route_evidence.route_proofs
    }
    allowances = []
    for fact in facts:
        step = plan.steps[fact.step_index]
        proof = proofs[fact.owner_ref.identity]
        fields = (
            model.EntryEndpointLivenessReason.NO_PROVIDER_EXIT_PATH_LIVE_SAFE_ENDPOINT,
            int(proof.state_write.state_constant), proof.proof_id,
            (fact.owner_ref,), step.old_target, step.new_target,
            (step.old_target,), fact.step_index, fact.step_digest,
            fact.owner_ref, proof.state_write.instruction_ea, False,
        )
        allowances.append(model.EntryEndpointLivenessAllowance(
            authority_id(("unflatten.entry-endpoint-liveness-allowance.v1", *fields)),
            *fields[:-1], (), (), fields[-1],
        ))
    plan = replace(
        plan,
        unflatten_proposal=replace(
            plan.unflatten_proposal,
            entry_endpoint_liveness_allowances=model.canonical_model_order(
                allowances, "entry_endpoint_liveness_allowances",
            ),
        ),
    )
    receipts = transaction_api.bind_entry_endpoint_liveness_allowances(
        plan=plan, allowances=tuple(allowances), patch_step_facts=facts,
        source=source, projected=projected,
        source_inventory=source_inventory, projected_inventory=projected_inventory,
    )

    assert tuple(item.binding_id for item in receipts) == tuple(
        sorted(item.binding_id for item in receipts)
    )
    with pytest.raises(ValueError, match="canonical"):
        transaction_api._admit_bound_entry_endpoint_liveness(
            proposal=plan.unflatten_proposal,
            receipts=tuple(reversed(receipts)),
            patch_step_facts=facts,
        )
def test_projected_corridor_union_binds_default_gap_with_source_authority() -> None:
    """The transaction chooses the typed binder before compatibility projection."""
    from . import test_bind
    from d810.transforms.unflatten_authority import bind, model, transaction_api

    proposal, source, projected, source_authority = (
        test_bind._default_gap_bound_projected_case()
    )
    result = transaction_api._bind_projected_corridor_authority(
        proposal=proposal,
        source_inventory=source,
        candidate_inventory=projected,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        source_route_authority=source_authority,
    )

    assert type(result) is model.DefaultGapInfeasibilityPhaseResult
    assert result.forecast is proposal.corridor_coverage_forecast


def test_observed_corridor_union_reuses_default_gap_projected_occurrence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Observed validation consumes a projected default-gap result, never remints it."""
    from . import test_bind
    from d810.transforms.unflatten_authority import bind, model, transaction_api

    proposal, source, projected_inventory, source_authority = (
        test_bind._default_gap_bound_projected_case()
    )
    projected = transaction_api._bind_projected_corridor_authority(
        proposal=proposal,
        source_inventory=source,
        candidate_inventory=projected_inventory,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        source_route_authority=source_authority,
    )
    observed_inventory = test_bind._inventory_rephase(
        projected_inventory,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        fingerprint=authority_id("default-gap-transaction-observed"),
        generation=4,
    )

    def forbidden_projected_binder(**_kwargs):
        raise AssertionError("observed validation must not rebind producer authority")

    monkeypatch.setattr(bind, "bind_default_gap_infeasibility_forecast", forbidden_projected_binder)
    observed = transaction_api._revalidate_observed_corridor_authority(
        projected_result=projected,
        proposal=proposal,
        claims=proposal.claims,
        source_inventory=source,
        observed_inventory=observed_inventory,
        source_route_authority=source_authority,
    )

    assert type(observed) is model.DefaultGapInfeasibilityPhaseResult
    assert observed.phase is model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
    assert observed.forecast is projected.forecast


def test_observed_corridor_union_rejects_reminted_default_gap_or_missing_source_authority() -> None:
    """The transaction boundary rejects equal DTOs and detached source proof."""
    from . import test_bind
    from d810.transforms.unflatten_authority import model, transaction_api

    proposal, source, projected_inventory, source_authority = (
        test_bind._default_gap_bound_projected_case()
    )
    projected = transaction_api._bind_projected_corridor_authority(
        proposal=proposal,
        source_inventory=source,
        candidate_inventory=projected_inventory,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        source_route_authority=source_authority,
    )
    observed_inventory = test_bind._inventory_rephase(
        projected_inventory,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        fingerprint=authority_id("default-gap-transaction-remint"),
        generation=4,
    )
    reminted = object.__new__(model.DefaultGapInfeasibilityPhaseResult)
    for name in model.DefaultGapInfeasibilityPhaseResult.__dataclass_fields__:
        object.__setattr__(reminted, name, getattr(projected, name))

    kwargs = dict(
        proposal=proposal,
        claims=proposal.claims,
        source_inventory=source,
        observed_inventory=observed_inventory,
    )
    with pytest.raises(ValueError, match="not minted"):
        transaction_api._revalidate_observed_corridor_authority(
            projected_result=reminted,
            source_route_authority=source_authority,
            **kwargs,
        )
    with pytest.raises(TypeError, match="source route authority"):
        transaction_api._revalidate_observed_corridor_authority(
            projected_result=projected,
            source_route_authority=None,
            **kwargs,
        )
    foreign_proposal = replace(
        proposal,
        corridor_coverage_forecast=copy(proposal.corridor_coverage_forecast),
    )
    with pytest.raises(ValueError, match="proposal is not the source-authority occurrence"):
        transaction_api._revalidate_observed_corridor_authority(
            projected_result=projected,
            proposal=foreign_proposal,
            claims=foreign_proposal.claims,
            source_inventory=source,
            observed_inventory=observed_inventory,
            source_route_authority=source_authority,
        )


def test_default_gap_authority_closes_the_full_transaction_vertical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One producer-realizable default gap survives projected-to-observed closure.

    This deliberately enters through ``_derive_inputs`` rather than testing
    either corridor helper in isolation.  The transaction must retain the
    typed wrapper while compatibility evidence exposes its base ledger only.
    """
    from . import test_bind
    from d810.transforms.unflatten_authority import bind, evaluate, model, transaction_api

    proposal, source, projected_inventory, source_authority, plan, derived, realization = (
        _producer_realizable_default_gap_transaction_case()
    )
    phase_metrics = model.PhaseBuildMetrics(
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, 1, 1, 0.0,
    )
    preparation_metrics = model.PreparationBuildMetrics(1, 1, 0.0)
    projected_inputs = transaction_api._derive_inputs(
        source, projected_inventory, plan, proposal, None,
        phase_build_metrics=phase_metrics,
        preparation_metrics=preparation_metrics,
        source_route_authority=source_authority,
        projected_route_realization=realization,
        derived_claim_inventory=derived,
    )
    assert projected_inputs.projected_route_realization is realization
    projected_case = evaluate.build_semantic_case(
        authority_id=authority_id("default-gap-full-vertical-projected"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=projected_inputs,
    )
    projected_verdict = evaluate.evaluate_case(projected_case)
    assert projected_verdict.accepted, projected_verdict.failed_obligations
    projected_evidence = evaluate.derive_corridor_coverage_evidence(
        projected_inputs, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    assert type(projected_inputs.corridor_coverage_phase_result) is model.DefaultGapInfeasibilityPhaseResult
    assert projected_case.corridor_coverage_phase_result is projected_inputs.corridor_coverage_phase_result
    assert projected_evidence is not None, tuple(
        (subject.block_ref, subject.anchor_ea, subject.locator)
        for subject in projected_inputs.candidate_inventory.subjects
        if subject.role is model.SemanticSubjectRole.DISPATCHER_CORRIDOR
    )
    assert projected_evidence.phase_result_id == projected_inputs.corridor_coverage_phase_result.base_result.result_id

    observed_inventory = test_bind._inventory_rephase(
        projected_inventory,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        fingerprint=authority_id("default-gap-full-vertical-observed"),
        generation=4,
    )

    def forbidden(*_args, **_kwargs):
        raise AssertionError("observed default-gap closure must not recover producer authority")

    monkeypatch.setattr(bind, "bind_default_gap_infeasibility_forecast", forbidden)
    monkeypatch.setattr(transaction_api, "_derive_transaction_facts", forbidden)
    monkeypatch.setattr(bind, "bind_source_route_authority", forbidden)
    monkeypatch.setattr(bind, "realize_projected_routes", forbidden)
    monkeypatch.setattr(transaction_api, "realize_projected_routes", forbidden)
    observed_inputs = transaction_api._derive_inputs(
        source, observed_inventory, plan, proposal, None,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        candidate_generation=observed_inventory.generation,
        phase_build_metrics=model.PhaseBuildMetrics(
            model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY, 0, 1, 0.0,
        ),
        preparation_metrics=preparation_metrics,
        source_route_authority=source_authority,
        projected_route_realization=realization,
        preparation_inputs=projected_inputs,
    )
    observed_case = evaluate.build_semantic_case(
        authority_id=authority_id("default-gap-full-vertical-observed"),
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        inputs=observed_inputs,
    )
    observed_evidence = evaluate.derive_corridor_coverage_evidence(
        observed_inputs, model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
    )

    projected_result = projected_inputs.corridor_coverage_phase_result
    observed_result = observed_inputs.corridor_coverage_phase_result
    assert type(observed_result) is model.DefaultGapInfeasibilityPhaseResult
    assert observed_case.corridor_coverage_phase_result is observed_result
    assert observed_result is not projected_result
    assert observed_result.correlations[0].route_proof_ids == projected_result.correlations[0].route_proof_ids
    assert observed_result.correlations[0].initial_state_seeds == projected_result.correlations[0].initial_state_seeds
    assert observed_evidence is not None
    assert observed_evidence.phase_result_id == observed_result.base_result.result_id


def _rf4_observed_helper_elision_inputs():
    """Hex-Rays may fold the planned branch helper into F -> N post-apply.

    RF-4's projected realization proves ``F -> H -> N`` and ``F -> U`` once.
    Observation must consume that same sealed relation when the backend elides
    the empty H block and exposes ``F -> N`` directly; it must not demand a
    second helper subject or re-assess the route.
    """
    from d810.ir.flowgraph import FlowGraph
    from d810.transforms.unflatten_authority import bind, evaluate, model, transaction_api
    from . import test_bind

    fixture = test_bind._task_15_branch_helper_vertical_case()
    values = test_bind._task_15_two_arm_vertical_inputs(fixture)
    realization_result = bind.realize_projected_routes(**values)
    assert type(realization_result) is model.ProjectedRouteRealizationAccepted
    realization = realization_result.realization
    (route_row,) = realization.rows
    relation = route_row.relation
    assert type(relation) is model.BranchFallthroughHelperRouteRealization

    projected_inputs = transaction_api._derive_inputs(
        fixture.source_inventory,
        fixture.projected_inventory,
        fixture.plan,
        fixture.proposal,
        None,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        phase_build_metrics=model.PhaseBuildMetrics(
            model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, 1, 1, 0.0,
        ),
        preparation_metrics=model.PreparationBuildMetrics(1, 1, 0.0),
        source_route_authority=fixture.source_authority,
        projected_route_realization=realization,
    )

    feeder_serial = fixture.projected_inventory.serial_by_ref[relation.feeder.ref]
    helper_serial = fixture.projected_inventory.serial_by_ref[relation.helper.ref]
    untouched_serial = fixture.projected_inventory.serial_by_ref[
        relation.untouched_conditional_arm.ref
    ]
    semantic_target_serial = fixture.projected_inventory.serial_by_ref[
        relation.semantic_target.ref
    ]
    (redirect_step,) = fixture.plan.steps
    assert type(redirect_step) is PatchRedirectBranch
    old_target_serial = fixture.projected_inventory.serial_by_ref[
        redirect_step.old_target
    ]
    assert fixture.projected_graph.blocks[feeder_serial].succs == (
        helper_serial,
        untouched_serial,
    )
    assert fixture.projected_graph.blocks[helper_serial].succs == (
        semantic_target_serial,
    )

    # The compiler-owned old arm remains structurally present but unreachable.
    # The only observed delta is H's elision and its exact F -> H -> N splice.
    observed_blocks = dict(fixture.projected_graph.blocks)
    del observed_blocks[helper_serial]
    observed_blocks[feeder_serial] = replace(
        observed_blocks[feeder_serial],
        succs=(semantic_target_serial, untouched_serial),
    )
    observed_blocks[semantic_target_serial] = replace(
        observed_blocks[semantic_target_serial],
        preds=(feeder_serial, old_target_serial),
    )
    observed = FlowGraph(
        observed_blocks,
        fixture.projected_graph.entry_serial,
        fixture.projected_graph.func_ea,
        metadata=fixture.projected_graph.metadata,
    )
    assert observed.blocks[feeder_serial].succs == (
        semantic_target_serial,
        untouched_serial,
    )
    assert helper_serial not in observed.blocks
    assert observed.blocks[semantic_target_serial].preds == (
        feeder_serial,
        old_target_serial,
    )

    observed_inventory = transaction_api._build_semantic_graph_inventory(
        observed,
        fixture.proposal,
        fixture.plan,
        source=False,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        source_subjects=fixture.source_inventory.subjects,
        source_inventory=fixture.source_inventory,
    )
    assert relation.helper.ref not in observed_inventory.serial_by_ref
    assert observed_inventory.serial_by_ref[relation.feeder.ref] == feeder_serial
    assert observed_inventory.serial_by_ref[relation.semantic_target.ref] == (
        semantic_target_serial
    )

    observed_inputs = transaction_api._derive_inputs(
        fixture.source_inventory,
        observed_inventory,
        fixture.plan,
        fixture.proposal,
        None,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        candidate_generation=observed_inventory.generation,
        phase_build_metrics=model.PhaseBuildMetrics(
            model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY, 0, 1, 0.0,
        ),
        preparation_metrics=projected_inputs.preparation_metrics,
        source_route_authority=fixture.source_authority,
        projected_route_realization=realization,
        preparation_inputs=projected_inputs,
    )
    return observed_inputs, relation


def test_observed_branch_helper_elision_reuses_the_sealed_route_relation() -> None:
    """The sealed RF-4 relation normalizes its exact observed helper elision."""
    from d810.transforms.unflatten_authority import evaluate, model

    observed_inputs, relation = _rf4_observed_helper_elision_inputs()
    observed_case = evaluate.build_semantic_case(
        authority_id=authority_id("rf4-observed-helper-elision"),
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        inputs=observed_inputs,
    )
    verdict = evaluate.evaluate_case(observed_case)

    assert verdict.accepted, verdict.failed_obligations
    assert not any(
        subject.role is model.SemanticSubjectRole.PLANNED_HELPER
        for subject in observed_case.subjects
    )
    assert not any(
        type(evidence.payload) is model.PatchStepEvidencePayload
        and evidence.payload.owner_ref == relation.helper.ref
        for evidence in observed_case.evidence
    )


def test_observed_route_endpoint_covers_only_sealed_pure_origin_fold() -> None:
    """A route-touched block may fold pure origins only with its patch receipt."""
    from d810.transforms.unflatten_authority import evaluate, model

    observed_inputs, relation = _rf4_observed_helper_elision_inputs()
    target_subject = next(
        subject
        for subject in observed_inputs.source_inventory.subjects
        if subject.role is model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK
        and subject.block_ref == relation.semantic_target.ref
    )
    source_binding = next(
        binding
        for binding in observed_inputs.source_inventory.bindings
        if binding.subject.subject_id == target_subject.subject_id
    )
    candidate_binding = next(
        binding
        for binding in observed_inputs.candidate_inventory.bindings
        if binding.subject.subject_id == target_subject.subject_id
    )
    assert source_binding.native_instruction_eas == candidate_binding.native_instruction_eas
    folded_pure_ea = source_binding.native_instruction_eas[0] - 1
    source_with_pure_helper = replace(
        source_binding,
        native_instruction_eas=(
            folded_pure_ea,
            *source_binding.native_instruction_eas,
        ),
    )

    assert evaluate._observed_route_endpoint_origin_fold_covered(
        observed_inputs,
        subject=target_subject,
        source_binding=source_with_pure_helper,
        candidate_binding=candidate_binding,
    )
    assert not evaluate._observed_route_endpoint_origin_fold_covered(
        replace(observed_inputs, patch_step_facts=()),
        subject=target_subject,
        source_binding=source_with_pure_helper,
        candidate_binding=candidate_binding,
    )


def test_observed_branch_helper_elision_rejects_foreign_fact_and_extra_topology() -> None:
    """RF-4 cannot turn a generic missing helper into an observed allowance."""
    from d810.transforms.unflatten_authority import evaluate, model

    observed_inputs, relation = _rf4_observed_helper_elision_inputs()
    projected_topology = evaluate._topology_relations_for_inventory(
        observed_inputs.projected_topology_reference,
        topology_roles=evaluate._TOPOLOGY_ROLES,
    )
    candidate_topology = evaluate._topology_relations_for_inventory(
        observed_inputs.candidate_inventory,
        topology_roles=evaluate._TOPOLOGY_ROLES,
    )
    helper_fact_index = next(
        index
        for index, fact in enumerate(observed_inputs.patch_step_facts)
        if fact.owner_ref == relation.helper.ref
    )
    original_facts = observed_inputs.patch_step_facts
    foreign_facts = list(original_facts)
    foreign_facts[helper_fact_index] = replace(
        foreign_facts[helper_fact_index],
        creation_spec_digest=authority_id("rf4-foreign-helper-creation"),
    )
    # Deliberately bypass the sealed input constructor: this is an adversarial
    # replay of otherwise valid phase inputs with a foreign helper receipt.
    object.__setattr__(observed_inputs, "patch_step_facts", tuple(foreign_facts))
    try:
        assert evaluate._derive_observed_branch_helper_elisions(
            observed_inputs,
            projected_topology=projected_topology,
            candidate_topology=candidate_topology,
        ) == ()
    finally:
        object.__setattr__(observed_inputs, "patch_step_facts", original_facts)

    exemplar = candidate_topology[0]
    extra_topology = model.TopologyEdgeRelation(
        model.SemanticEdgeRole.DIRECT,
        exemplar.source_subject_id,
        exemplar.target_subject_id,
        0xF4E1,
    )
    assert extra_topology not in candidate_topology
    assert evaluate._derive_observed_branch_helper_elisions(
        observed_inputs,
        projected_topology=projected_topology,
        candidate_topology=(*candidate_topology, extra_topology),
    ) == ()


def test_default_gap_observed_inputs_reject_reminted_result_and_equal_projected_topology() -> None:
    """Observed input derivation requires the exact prepared wrapper and topology."""
    from . import test_bind
    from d810.transforms.unflatten_authority import model, transaction_api

    proposal, source, projected_inventory, source_authority, plan, derived, realization = (
        _producer_realizable_default_gap_transaction_case()
    )
    metrics = model.PreparationBuildMetrics(1, 1, 0.0)
    projected_inputs = transaction_api._derive_inputs(
        source, projected_inventory, plan, proposal, None,
        phase_build_metrics=model.PhaseBuildMetrics(
            model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, 1, 1, 0.0,
        ),
        preparation_metrics=metrics,
        source_route_authority=source_authority,
        projected_route_realization=realization,
        derived_claim_inventory=derived,
    )
    observed_inventory = test_bind._inventory_rephase(
        projected_inventory,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        fingerprint=authority_id("default-gap-full-negative-observed"), generation=4,
    )
    reminted = object.__new__(model.DefaultGapInfeasibilityPhaseResult)
    for field in model.DefaultGapInfeasibilityPhaseResult.__dataclass_fields__:
        object.__setattr__(reminted, field, getattr(projected_inputs.corridor_coverage_phase_result, field))
    reminted_inputs = replace(
        projected_inputs, corridor_coverage_phase_result=reminted,
    )
    kwargs = dict(
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        candidate_generation=observed_inventory.generation,
        phase_build_metrics=model.PhaseBuildMetrics(
            model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY, 0, 1, 0.0,
        ),
        preparation_metrics=metrics,
        source_route_authority=source_authority,
        projected_route_realization=realization,
    )
    with pytest.raises(ValueError, match="not minted"):
        transaction_api._derive_inputs(
            source, observed_inventory, plan, proposal, None,
            preparation_inputs=reminted_inputs, **kwargs,
        )
    copied_topology_inputs = replace(
        projected_inputs,
        projected_topology_reference=deepcopy(projected_inventory),
    )
    with pytest.raises(ValueError, match="exact prepared projected topology occurrence"):
        transaction_api._derive_inputs(
            source, observed_inventory, plan, proposal, None,
            preparation_inputs=copied_topology_inputs, **kwargs,
        )


def test_default_gap_candidate_inventory_does_not_root_its_typed_residual() -> None:
    """Projected root closure leaves proposed default-gap loss to its binder."""
    from . import test_bind
    from d810.analyses.control_flow import semantic_route_evidence as route_model
    from d810.transforms.edit_simulator import project_patch_plan
    from d810.transforms.unflatten_authority import model, transaction_api

    proposal, old_source, _old_candidate, _old_authority, source_graph, plan = (
        test_bind._default_gap_bound_projected_case(include_graph=True)
    )
    projected_graph = project_patch_plan(
        source_graph, plan, snapshot_id=plan.snapshot_id,
    ).graph
    materialization = route_model.CanonicalRouteMaterialization.capture(
        source_graph, generation=1,
        phase=route_model.CanonicalRouteAssessmentPhase.SOURCE,
    )
    source = transaction_api._build_semantic_graph_inventory(
        source_graph, proposal, plan, source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        materialization=materialization,
    )
    candidate = transaction_api._build_semantic_graph_inventory(
        projected_graph, proposal, plan, source=False,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        source_subjects=source.subjects,
    )
    residual_ref = proposal.corridor_coverage_forecast.exclusions[0].residual.block_ref
    assert candidate.serial_by_ref[residual_ref] not in candidate.reachable_serials


def test_default_gap_conditional_fold_matcher_rejects_foreign_arm_or_proof_link() -> None:
    """A conditional fold is admitted only by the exact typed default-gap edge."""
    from d810.transforms.plan import PatchConvertToGoto, PatchRedirectGoto
    from d810.transforms.unflatten_authority import bind
    from d810.transforms.unflatten_authority.proposal import canonical_patch_step_descriptors

    proposal, source, _projected, _authority, plan, _derived, _realization = (
        _producer_realizable_default_gap_transaction_case()
    )
    proof = proposal.route_evidence.route_proofs[0]
    refs = {serial: ref for ref, serial in source.serial_by_ref.items()}
    descriptors = canonical_patch_step_descriptors(plan)
    folds = tuple(
        descriptor for descriptor in descriptors
        if (
            descriptor.step_type == "PatchConvertToGoto"
            and descriptor.owner_refs == (refs[1],)
            and descriptor.route_refs == (refs[1], refs[2])
        )
    )
    assert len(folds) == 1
    (descriptor,) = folds
    assert bind._default_gap_conditional_fold_coordinates_match(plan, proof, descriptor)
    wrong_arm = replace(
        plan, steps=(PatchConvertToGoto(refs[1], refs[3]),),
    )
    assert not bind._default_gap_conditional_fold_coordinates_match(
        wrong_arm, proof, canonical_patch_step_descriptors(wrong_arm)[0],
    )
    wrong_proof = replace(proof, proof_id=authority_id("foreign-default-gap-proof"))
    assert not bind._default_gap_conditional_fold_coordinates_match(
        plan, wrong_proof, descriptor,
    )
    no_gap_plan = replace(
        plan,
        unflatten_proposal=replace(
            proposal,
            corridor_coverage_forecast=proposal.corridor_coverage_forecast.base_forecast,
        ),
    )
    assert not bind._default_gap_conditional_fold_coordinates_match(
        no_gap_plan, proof, descriptor,
    )


def _producer_realizable_default_gap_transaction_case():
    """Build one closed default-gap case through the real patch compiler path."""
    from . import test_bind
    from d810.analyses.control_flow import semantic_route_evidence as route_model
    from d810.transforms.cfg_transaction import TransactionAttemptId
    from d810.transforms.edit_simulator import project_patch_plan
    from d810.transforms.plan import PatchConvertToGoto
    from d810.transforms.unflatten_authority import bind, model, transaction_api
    from d810.transforms.unflatten_authority.gates import GenericEffectfulGateFacts
    from d810.transforms.unflatten_authority.ids import projected_authority_id
    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest

    proposal, old_source, _old_projected, _old_authority, source_graph, plan = (
        test_bind._default_gap_bound_projected_case(include_graph=True)
    )
    refs_by_serial = {serial: ref for ref, serial in old_source.serial_by_ref.items()}
    plan = replace(
        plan,
        # The entry redirect removes the remaining ingress to the dispatcher;
        # the exact conditional fold preserves the default-gap relation being
        # exercised.  Both are valid source operations, and together produce
        # the fully retired corridor required by the transaction verdict.
        steps=(
            PatchRedirectGoto(refs_by_serial[0], refs_by_serial[1], refs_by_serial[2]),
            PatchConvertToGoto(refs_by_serial[1], refs_by_serial[2]),
        ),
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
    projected_graph = project_patch_plan(
        source_graph, plan, snapshot_id=plan.snapshot_id,
    ).graph
    materialization = route_model.CanonicalRouteMaterialization.capture(
        source_graph, generation=1,
        phase=route_model.CanonicalRouteAssessmentPhase.SOURCE,
    )
    source = transaction_api._build_semantic_graph_inventory(
        source_graph, proposal, plan, source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        materialization=materialization,
    )
    source_binding = bind.bind_source_route_authority(
        proposal=proposal, source_inventory=source,
        source_materialization=materialization,
    )
    assert type(source_binding) is model.SourceBoundRouteAuthorityAccepted
    projected = transaction_api._build_semantic_graph_inventory(
        projected_graph, proposal, plan, source=False,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        source_subjects=source.subjects,
    )
    derived = transaction_api._derive_transaction_facts(source, plan)
    attempt = TransactionAttemptId(
        plan.plan_id, authority_id("default-gap-full-vertical-session"), 1,
        authority_id("default-gap-full-vertical-attempt"),
    )
    owners = frozenset(
        row.owner_serial for row in source.effects
        if row.owner_serial in source.reachable_serials
    )
    source_refs = {row.serial: row.block_ref for row in source.blocks}
    retained = frozenset(
        serial for serial, ref in source_refs.items()
        if serial in owners
        and (projected_serial := projected.serial_by_ref.get(ref)) is not None
        and projected_serial in projected.reachable_serials
    )
    raw_gate_facts = GenericEffectfulGateFacts(
        not (owners - retained), owners, retained, owners - retained,
        "default-gap-full-vertical",
    )
    raw_effect_gate_fact = bind.bind_raw_effect_gate_phase_fact(
        source_inventory=source,
        projected_inventory=projected,
        raw_gate_facts=raw_gate_facts,
        derived_claim_inventory=derived,
    )
    realization_authority_id = projected_authority_id(
        attempt_id=attempt,
        proposal_id=authority_id(proposal),
        source_authority_id=source_binding.authority.source_authority_id,
        plan_id=plan.plan_id,
        claims=derived.claims,
        patch_step_facts=derived.patch_step_facts,
        source_inventory=source,
        projected_inventory=projected,
        raw_effect_gate_fact=raw_effect_gate_fact,
    )
    realization_result = transaction_api.realize_projected_routes(
        authority_id_value=realization_authority_id,
        derived_claim_inventory=derived,
        source_route_authority=source_binding.authority,
        attempt_id=attempt,
        projected_inventory=projected,
        raw_effect_gate_fact=raw_effect_gate_fact,
        legacy_effective_gate_facts=(
            transaction_api._legacy_effective_gate_comparison_facts(raw_gate_facts)
        ),
    )
    assert type(realization_result) is model.ProjectedRouteRealizationAccepted
    return (
        proposal, source, projected, source_binding.authority, plan, derived,
        realization_result.realization,
    )


def test_route_reassessment_rule_enrolls_transaction_binder():
    rule_text = (
        Path(__file__).resolve().parents[4]
        / "rules"
        / "no-unflatten-route-assessment-in-transaction.yml"
    ).read_text(encoding="utf-8")

    assert '"src/d810/transforms/unflatten_authority/bind.py"' in rule_text


def _c1_direct_preparation_case(*, local_alias: bool = False):
    """Use the final compiled plan and its real projected graph."""
    from d810.analyses.control_flow.graph_checks import (
        check_effectful_reachability_preserved,
        check_entry_reachability_not_collapsed,
        check_terminal_reachability_preserved,
    )
    from d810.transforms.edit_simulator import project_post_state
    from d810.transforms.unflatten_authority.gates import GenericCfgGateBundle
    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest
    from . import test_bind

    fixture = test_bind._task_15_direct_vertical_case(
        local_alias=local_alias, include_graph=True, derive_transaction=True,
    )
    source, plan = fixture.source_graph, fixture.plan
    # The compiler fixture predates the final plan manifest.  Rebuild only the
    # test-local proposal witness; production proposal validation remains
    # strict about final-plan ownership.
    plan = replace(plan, snapshot_id=authority_id(("c1-direct", plan.plan_id)))
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
    projected = project_post_state(source, plan)
    gates = GenericCfgGateBundle(
        check_entry_reachability_not_collapsed(source, post_cfg=projected),
        check_effectful_reachability_preserved(source, post_cfg=projected),
        check_effectful_reachability_preserved(source, post_cfg=projected),
        check_terminal_reachability_preserved(source, post_cfg=projected),
    )
    return fixture, source, plan, projected, gates


def test_revalidate_bound_patch_plan_trusts_sealed_rows_but_requires_prepared_occurrence():
    """DTO coverage belongs to BoundPatchPlan; preparation identity remains exact."""
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.hexrays.mutation.patch_binding import bind_patch_plan
    from d810.transforms.patch_binding import BoundPatchPlan
    from d810.transforms.unflatten_authority import model, transaction_api

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    preparation = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    )
    assert type(preparation) is model.UnflattenAuthorityPreparationAccepted
    prepared = preparation.prepared
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
    bound_plan = bind_patch_plan(plan, index, fixture.attempt_id).bound_plan
    assert transaction_api.revalidate_bound_patch_plan_against_prepared(
        prepared, bound_plan,
    ) is bound_plan

    foreign_plan = replace(
        plan, snapshot_id=authority_id("foreign-prepared-occurrence"),
    )
    foreign_bound_plan = BoundPatchPlan(
        foreign_plan, bound_plan.attempt_id, bound_plan.session_id,
        bound_plan.generation, bound_plan.maturity, bound_plan.bindings,
    )
    with pytest.raises(ValueError, match="foreign plan"):
        transaction_api.revalidate_bound_patch_plan_against_prepared(
            prepared, foreign_bound_plan,
        )
    index.abort_proxy_transaction(fixture.attempt_id.attempt_id)


def _logical_dag_source_bind_case(
    *,
    bootstrap: bool = False,
    endpoint_kind_name: str = "zero_way",
    endpoint_override: dict[str, object] | None = None,
):
    """Build one public source bind with an owned logical function exit.

    The decision compares the dispatcher state and branches either to its
    native handler or to an instructionless BADADDR logical function exit.
    The function exit may use the Hex-Rays STOP or ZERO_WAY sink shape.  An
    unrelated STOP is deliberately present in the graph without a source
    coordinate: it remains structural bookkeeping rather than semantic route
    authority.
    """
    from d810.analyses.control_flow import semantic_route_evidence as route
    from d810.analyses.control_flow.route_predicate import RouteComparison
    from d810.ir.expressions import ValueOpKind
    from d810.ir.flowgraph import (
        BlockKind, BlockSnapshot, ControlTransferKind, FlowGraph, InsnKind,
        MopSnapshot, OperandKind, PredicateKind,
    )
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.transforms.graph_modification import RedirectGoto
    from d810.transforms.plan import PatchPlan
    from d810.transforms.unflatten_authority import model, producer_api, transaction_api
    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest
    from tests.typed_patch_authority import compile_patch_plan
    from . import test_bind

    source_seed, base, _exclusion, native_refs = test_bind.exact_fixture()
    blocks = dict(source_seed.blocks)
    state = base.route_evidence.route_proofs[0].state_write.state_variable
    first, branch = blocks[1].insn_snapshots
    state_number = MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7)
    state_slot = MopSnapshot(
        kind=OperandKind.STACK, size=4, stkoff=4, stack_refs=(4,),
    )
    dag_entry = 2
    dag_instruction_ea = blocks[dag_entry].insn_snapshots[0].ea
    native_handler = replace(branch.d, block_ref=4)
    route_goto = replace(
        branch,
        l=None,
        r=None,
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=dag_entry),
        kind=InsnKind.GOTO,
        control_transfer_kind=ControlTransferKind.GOTO,
        branch_predicate=None,
        predicate_kind=None,
        is_conditional_jump=False,
        is_unconditional_jump=True,
        operands=(MopSnapshot(kind=OperandKind.BLOCK, block_ref=dag_entry),),
        operand_slots=(("d", MopSnapshot(kind=OperandKind.BLOCK, block_ref=dag_entry)),),
    )
    blocks[1] = replace(
        blocks[1],
        succs=(dag_entry,),
        insn_snapshots=(
            replace(
                first,
                kind=InsnKind.MOV,
                value_op_kind=ValueOpKind.MOVE,
                l=state_number,
                d=state_slot,
                operands=(state_number, state_slot),
                operand_slots=(
                    ("l", state_number),
                    ("d", state_slot),
                ),
            ),
            route_goto,
        ),
        kind=BlockKind.ONE_WAY,
        tail_kind=InsnKind.GOTO,
    )
    dag_comparison = replace(
        branch,
        ea=dag_instruction_ea,
        d=native_handler,
        control_transfer_kind=ControlTransferKind.CONDITIONAL_BRANCH,
        branch_predicate=PredicateKind.EQ,
        predicate_kind=PredicateKind.EQ,
        is_conditional_jump=True,
        is_unconditional_jump=False,
        operands=(branch.l, branch.r, native_handler),
        operand_slots=(("l", branch.l), ("r", branch.r), ("d", native_handler)),
    )
    blocks[2] = replace(
        blocks[2], succs=(4, 5), preds=(1,), insn_snapshots=(dag_comparison,),
        kind=BlockKind.TWO_WAY, tail_kind=InsnKind.COND_JUMP,
    )
    blocks[3] = replace(blocks[3], preds=(4,))
    handler_goto = replace(
        blocks[4].insn_snapshots[0],
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=3),
        kind=InsnKind.GOTO,
        control_transfer_kind=ControlTransferKind.GOTO,
        is_unconditional_jump=True,
    )
    blocks[4] = replace(
        blocks[4],
        succs=(3,),
        preds=(2,),
        insn_snapshots=(handler_goto,),
        kind=BlockKind.ONE_WAY,
        tail_kind=InsnKind.GOTO,
    )
    endpoint_kind = {
        "zero_way": BlockKind.ZERO_WAY,
        "stop": BlockKind.STOP,
    }[endpoint_kind_name]
    blocks[5] = BlockSnapshot(
        5, 0, (), (2,), 0, 0xFFFFFFFFFFFFFFFF, (), None,
        endpoint_kind, None, None,
    )
    blocks[6] = BlockSnapshot(
        6, 0, (), (), 0, 0xFFFFFFFFFFFFFFFF, (), None,
        BlockKind.STOP, None, None,
    )
    source = FlowGraph(blocks, source_seed.entry_serial, source_seed.func_ea)
    ref_index = MbaBlockIdentityIndex.from_flow_graph(
        generation=1,
        native_key=base.route_evidence.native_key,
        flow_graph=source,
        session_id="logical-dag-public",
    )
    refs = dict(ref_index.plan_refs_by_serial())
    logical_exit = refs[5]
    endpoint = route.SemanticLogicalDagEndpoint(
        route.SemanticDagEndpointKind.FUNCTION_EXIT,
        5,
        **({
            "session_id": logical_exit.session_id,
            "proxy_token": logical_exit.proxy_token,
            "version": logical_exit.version,
        } | (endpoint_override or {})),
    )
    dag = route.DecisionDagRouteWitness(
        state, 7, dag_entry, blocks[dag_entry].start_ea,
        (dag_entry,), (blocks[dag_entry].start_ea,),
        (
            route.DecisionDagComparisonWitness(
                dag_entry,
                RouteComparison(dag_entry, "jz", 7, 4, 5),
                state,
            ),
        ),
        (),
    )
    bootstrap_witness = route.SemanticBootstrapRouteWitness(
        0, 1, blocks[1].start_ea, dag_entry, 4, state, 7, 4,
        (1, dag_entry, 4),
        (
            blocks[1].start_ea,
            blocks[dag_entry].start_ea,
            blocks[4].start_ea,
        ),
        (), dag,
    )
    fact = route.SemanticRouteFact(
        route.SemanticRouteFactKind.BOOTSTRAP
        if bootstrap else route.SemanticRouteFactKind.DECISION_DAG,
        dag_entry if bootstrap else 1,
        1,
        blocks[1].start_ea,
        7,
        4,
        blocks[dag_entry].start_ea if bootstrap else blocks[1].start_ea,
        blocks[4].start_ea,
        (1, dag_entry) if bootstrap else (1,),
        ((1, dag_entry),) if bootstrap else (),
        authority_id(("logical-dag-public-fact", bootstrap)),
        decision_dag_witness=dag,
        bootstrap_witness=bootstrap_witness if bootstrap else None,
    )
    context = route.CanonicalSemanticEvidenceProductionContext(
        base.route_evidence.native_key,
        1,
        authority_id(("logical-dag-public-group", bootstrap)),
        state,
        tuple(source.blocks.values()),
        tuple(
            (serial, ref.identity)
            for serial, ref in refs.items()
            if type(ref).__name__ == "NativeBlockRef"
        ),
        logical_endpoints_by_serial=((5, endpoint),),
        entry_serial=source.entry_serial,
    )
    produced = route.build_canonical_semantic_evidence((fact,), context)
    assert produced.abstention is None and produced.evidence is not None
    proof = produced.evidence.route_proofs[0]
    proposal = producer_api.build_proposal(
        plan_id=authority_id(("logical-dag-public-plan", bootstrap)),
        source=source,
        block_refs_by_serial=refs,
        source_generation=1,
        canonical_route_evidence=produced.evidence,
        selected_route_proof_ids=(proof.proof_id,),
        exact_state_effect_exclusions=(),
        dispatcher_entry_serial=1,
        dispatcher_member_serials=(1, dag_entry),
        authoritative_handler_serials=(4,),
        state_identity=state,
        use_def_witness=replace(
            base.use_def_witness,
            redirect_owner_refs=(refs[1],),
        ),
    )
    compiled = compile_patch_plan(
        [RedirectGoto(1, dag_entry, 4)],
        source,
        plan_id=proposal.plan_id,
        source_generation=1,
        block_refs_by_serial=refs,
    )
    plan = PatchPlan(
        plan_id=compiled.plan_id,
        snapshot_id=compiled.snapshot_id,
        source_maturity=compiled.source_maturity,
        source_generation=compiled.source_generation,
        steps=compiled.steps,
        new_blocks=compiled.new_blocks,
        relocation_map=compiled.relocation_map,
        execution_policy=compiled.execution_policy,
        metadata=compiled.metadata,
        semantic_contract=compiled.semantic_contract,
        source_coordinates=tuple((refs[serial], serial) for serial in sorted(refs)),
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
    materialization = route.CanonicalRouteMaterialization.capture(
        source, generation=1, phase=route.CanonicalRouteAssessmentPhase.SOURCE,
    )
    inventory = transaction_api._build_semantic_graph_inventory(
        source, proposal, plan, source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        materialization=materialization,
    )
    return source, plan, proposal, inventory, materialization, endpoint


@pytest.mark.parametrize("bootstrap", (False, True), ids=("ordinary", "bootstrap"))
@pytest.mark.parametrize("endpoint_kind_name", ("zero_way", "stop"))
def test_public_source_bind_accepts_owned_logical_decision_dag_exit(
    bootstrap: bool, endpoint_kind_name: str,
):
    """Both selected producer proof families survive the public source bind."""
    from d810.transforms.unflatten_authority import bind, model

    _source, _plan, proposal, inventory, materialization, endpoint = (
        _logical_dag_source_bind_case(
            bootstrap=bootstrap,
            endpoint_kind_name=endpoint_kind_name,
        )
    )
    result = bind.bind_source_route_authority(
        proposal=proposal,
        source_inventory=inventory,
        source_materialization=materialization,
    )

    assert type(result) is model.SourceBoundRouteAuthorityAccepted
    assert any(
        item == endpoint
        for proof in result.authority.proposal.route_evidence.route_proofs
        for comparison in proof.state_dag.witness.comparisons
        for item in (comparison.true_target, comparison.false_target)
    )
    stop = next(row for row in inventory.blocks if row.serial == 6)
    assert stop.block_ref is None


def test_selected_logical_dag_exit_is_a_typed_route_endpoint_subject():
    """The selected route claim owns its logical leaf outside redirect targets."""
    from d810.transforms.unflatten_authority import model

    _source, _plan, proposal, _inventory, _materialization, _endpoint = (
        _logical_dag_source_bind_case()
    )
    (claim,) = tuple(
        item for item in proposal.claims
        if type(item) is model.EquivalentSemanticRouteClaim
    )

    logical_subjects = tuple(
        subject for subject in claim.dag_endpoint_subjects
        if type(subject.locator) is model.LogicalFunctionExitSubjectLocator
    )
    assert len(logical_subjects) == 1
    logical_subject = logical_subjects[0]
    assert logical_subject.kind is model.SemanticSubjectKind.BLOCK
    assert logical_subject.role is model.SemanticSubjectRole.SEMANTIC_DAG_ENDPOINT
    assert logical_subject.block_ref == next(
        ref for ref, serial in _plan.source_coordinates if serial == 5
    )
    assert logical_subject.anchor_ea is None
    assert logical_subject.locator.serial == 5
    assert logical_subject.locator.block_ref == logical_subject.block_ref
    assert logical_subject.locator in claim.retired_route_subject.locator.dag_endpoint_locators
    assert all(
        type(subject.locator) is model.BlockSubjectLocator
        for subject in claim.destination_subjects
    )


def test_patch_lineage_admits_exact_selected_logical_dag_endpoint():
    """A redirect may target the logical leaf sealed by its route claim."""
    from d810.transforms.plan import PatchRedirectGoto
    from d810.transforms.unflatten_authority import transaction_api

    _source, plan, _proposal, inventory, _materialization, _endpoint = (
        _logical_dag_source_bind_case()
    )
    refs_by_serial = {serial: ref for ref, serial in plan.source_coordinates}
    exact_logical_exit = refs_by_serial[5]
    redirect = plan.steps[0]
    assert type(redirect) is PatchRedirectGoto
    logical_target_plan = replace(
        plan,
        steps=(replace(redirect, new_target=exact_logical_exit),),
    )

    (fact,) = transaction_api._derive_patch_lineage_facts(
        inventory,
        logical_target_plan,
    )

    assert fact.step_type == "PatchRedirectGoto"
    assert fact.owner_ref == redirect.from_serial


def test_patch_lineage_admits_exact_source_logical_exit_without_route_claim():
    """The transaction binds an exact source ZERO_WAY exit as a coordinate."""
    from d810.transforms.cfg_transaction import LogicalBlockRef
    from d810.transforms.plan import PatchRedirectGoto
    from d810.transforms.unflatten_authority import model, transaction_api

    source, plan, proposal, inventory, _materialization, _endpoint = (
        _logical_dag_source_bind_case()
    )
    redirect = plan.steps[0]
    assert type(redirect) is PatchRedirectGoto
    exact_logical_exit = next(
        ref for ref, serial in plan.source_coordinates if serial == 5
    )
    assert exact_logical_exit in inventory.serial_by_ref
    tampered_proposal = deepcopy(proposal)
    (tampered_route_claim,) = tuple(
        claim for claim in tampered_proposal.claims
        if type(claim) is model.EquivalentSemanticRouteClaim
    )
    object.__setattr__(
        tampered_route_claim,
        "dag_endpoint_subjects",
        (),
    )
    closure_removed_plan = replace(
        plan,
        steps=(replace(redirect, new_target=exact_logical_exit),),
        unflatten_proposal=tampered_proposal,
    )

    assert transaction_api._catalog_serials(
        source,
        tampered_proposal,
        closure_removed_plan,
    )[exact_logical_exit] == 5

    (fact,) = transaction_api._derive_patch_lineage_facts(
        inventory,
        closure_removed_plan,
    )

    assert fact.step_type == "PatchRedirectGoto"
    assert fact.owner_ref == redirect.from_serial


def test_source_catalog_admits_only_reciprocal_source_logical_stop():
    """A reciprocal source STOP is owned; the detached synthetic STOP is not."""
    from d810.transforms.unflatten_authority import evaluate, model, transaction_api

    source, plan, proposal, _inventory, materialization, _endpoint = (
        _logical_dag_source_bind_case(endpoint_kind_name="stop")
    )
    reciprocal_logical_stop = next(
        ref for ref, serial in plan.source_coordinates if serial == 5
    )
    tampered_proposal = deepcopy(proposal)
    object.__setattr__(tampered_proposal, "claims", ())
    unclaimed_plan = replace(plan, unflatten_proposal=tampered_proposal)

    catalog = transaction_api._catalog_serials(
        source,
        tampered_proposal,
        unclaimed_plan,
    )

    assert catalog[reciprocal_logical_stop] == 5
    assert 6 not in catalog.values()

    inventory = transaction_api._build_semantic_graph_inventory(
        source,
        tampered_proposal,
        unclaimed_plan,
        source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        materialization=materialization,
    )
    logical_endpoint_subjects = tuple(
        subject
        for subject in inventory.subjects
        if subject.role is model.SemanticSubjectRole.SOURCE_LOGICAL_EXIT
        and type(subject.locator) is model.LogicalFunctionExitSubjectLocator
    )
    assert tuple(
        (subject.block_ref, subject.locator.serial)
        for subject in logical_endpoint_subjects
    ) == ((reciprocal_logical_stop, 5),)
    assert all(
        terminal.owner_ref != reciprocal_logical_stop
        for terminal in inventory.terminals
    )
    (logical_binding,) = tuple(
        binding
        for binding in inventory.bindings
        if binding.subject is logical_endpoint_subjects[0]
    )
    assert logical_binding.status is model.SubjectBindingStatus.UNIQUE
    assert logical_binding.serial == 5
    assert logical_binding.anchor_ea is None
    assert evaluate.REQUIRED_DIMENSIONS[
        (
            model.SemanticSubjectKind.BLOCK,
            model.SemanticSubjectRole.SOURCE_LOGICAL_EXIT,
        )
    ] == (model.SafetyDimension.IDENTITY_BINDING,)


def test_patch_lineage_rejects_unselected_reminted_logical_dag_endpoint():
    """A reminted logical endpoint is not selected route authority."""
    import re

    from d810.transforms.cfg_transaction import LogicalBlockRef
    from d810.transforms.plan import PatchRedirectGoto
    from d810.transforms.unflatten_authority import transaction_api

    _source, plan, _proposal, inventory, _materialization, _endpoint = (
        _logical_dag_source_bind_case()
    )
    redirect = plan.steps[0]
    assert type(redirect) is PatchRedirectGoto
    reminted_exit = LogicalBlockRef(
        plan.plan_id,
        "reminted-selected-logical-exit",
        1,
    )
    reminted_target_plan = replace(
        plan,
        steps=(replace(redirect, new_target=reminted_exit),),
    )

    with pytest.raises(
        ValueError,
        match=re.escape(
            "foreign to the source plan: step=0 kind=PatchRedirectGoto "
            "ref_position=2 ref_type=LogicalBlockRef source_member=False "
            "route_member=False structural_preimage=False serial_anchor=None@None "
            f"logical_ref={reminted_exit!r} source_coordinate_candidates=()"
        ),
    ):
        transaction_api._derive_patch_lineage_facts(
            inventory,
            reminted_target_plan,
        )


def test_selected_route_subject_closure_includes_native_dag_alias_members():
    """Patch lineage consumes every native member of the selected DAG proof."""
    from types import SimpleNamespace

    from d810.analyses.control_flow.semantic_route_evidence import (
        SemanticCorridorPoint,
    )
    from d810.transforms.unflatten_authority import transaction_api

    source, _plan, proposal, _inventory, _materialization, _endpoint = (
        _logical_dag_source_bind_case()
    )
    refs_by_serial = {
        serial: ref for ref, serial in _plan.source_coordinates
    }
    alias_source_ref = refs_by_serial[3]
    alias_target_ref = refs_by_serial[4]
    proof = proposal.route_evidence.route_proofs[0]
    assert proof.state_dag is not None
    alias = (
        SemanticCorridorPoint(
            alias_source_ref.identity, source.blocks[3].start_ea,
        ),
        SemanticCorridorPoint(
            alias_target_ref.identity, source.blocks[4].start_ea,
        ),
    )
    aliased_proof = replace(
        proof,
        state_dag=replace(
            proof.state_dag,
            witness=replace(proof.state_dag.witness, aliases=(alias,)),
        ),
    )
    selected_proposal = SimpleNamespace(
        claims=proposal.claims,
        route_evidence=SimpleNamespace(route_proofs=(aliased_proof,)),
        source_identity_catalog=proposal.source_identity_catalog,
    )

    route_refs = transaction_api._selected_route_subject_refs(selected_proposal)

    assert alias_source_ref in route_refs
    assert alias_target_ref in route_refs


def test_selected_route_subject_closure_includes_bootstrap_corridor_members():
    """Patch lineage consumes the selected proof's exact entry corridor."""
    from d810.transforms.unflatten_authority import transaction_api

    _source, plan, proposal, _inventory, _materialization, _endpoint = (
        _logical_dag_source_bind_case(bootstrap=True)
    )
    proof = proposal.route_evidence.route_proofs[0]
    assert proof.bootstrap is not None
    refs_by_identity = {
        ref.identity: ref
        for ref, _serial in plan.source_coordinates
        if hasattr(ref, "identity")
    }

    route_refs = transaction_api._selected_route_subject_refs(proposal)

    expected = {
        refs_by_identity[point.identity]
        for point in (
            proof.bootstrap.entry,
            proof.bootstrap.source,
            proof.bootstrap.owner,
            proof.bootstrap.dispatcher,
            *proof.bootstrap.corridor,
        )
    }
    assert expected <= route_refs


def test_selected_route_subject_closure_includes_distinct_route_owner():
    """The canonical delivery owner is part of the selected route closure."""
    from types import SimpleNamespace

    from d810.transforms.unflatten_authority import transaction_api

    source, plan, proposal, _inventory, _materialization, _endpoint = (
        _logical_dag_source_bind_case()
    )
    refs_by_serial = {
        serial: ref for ref, serial in plan.source_coordinates
    }
    owner_ref = refs_by_serial[3]
    proof = proposal.route_evidence.route_proofs[0]
    owned_proof = replace(
        proof,
        source_owner_identity=owner_ref.identity,
        source_owner_anchor_ea=source.blocks[3].start_ea,
    )
    selected_proposal = SimpleNamespace(
        claims=proposal.claims,
        route_evidence=SimpleNamespace(route_proofs=(owned_proof,)),
        source_identity_catalog=proposal.source_identity_catalog,
    )

    route_refs = transaction_api._selected_route_subject_refs(selected_proposal)

    assert owner_ref in route_refs


def test_transaction_classifies_only_physical_entry_dispatcher_frontier():
    """Entry bridges are source-topology facts, not naked source allowances."""
    from d810.transforms.plan import PatchPlan
    from d810.transforms.unflatten_authority import model, transaction_api

    source, proposal, _exclusion, refs = exact_fixture()
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("entry-frontier"),
        source_generation=1,
        source_coordinates=tuple(
            (ref, serial) for serial, ref in sorted(refs.items())
        ),
        unflatten_proposal=proposal,
    )
    inventory = transaction_api._build_semantic_graph_inventory(
        source,
        proposal,
        plan,
        source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
    )

    frontier = transaction_api._source_entry_dispatcher_frontier_refs(
        inventory, proposal,
    )

    assert frontier == {refs[0]}
    assert refs[3] not in frontier


def test_transaction_classifies_additional_physical_entry_root():
    """A zero-predecessor native root may share the dispatcher frontier."""
    from d810.transforms.plan import PatchPlan
    from d810.transforms.unflatten_authority import model, transaction_api

    source, proposal, _exclusion, refs = exact_fixture()
    source = replace(
        source,
        blocks={
            **source.blocks,
            1: replace(source.blocks[1], preds=(0, 4)),
            4: replace(source.blocks[4], preds=(), succs=(1,)),
        },
    )
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("additional-entry-root"),
        source_generation=1,
        source_coordinates=tuple(
            (ref, serial) for serial, ref in sorted(refs.items())
        ),
        unflatten_proposal=proposal,
    )
    inventory = transaction_api._build_semantic_graph_inventory(
        source,
        proposal,
        plan,
        source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
    )

    frontier = transaction_api._source_entry_dispatcher_frontier_refs(
        inventory, proposal,
    )

    assert frontier == {refs[0], refs[4]}


def test_projected_inventory_uniquely_binds_retained_logical_function_exit():
    """Projected preflight retains the one sealed logical DAG endpoint."""
    from d810.analyses.control_flow.semantic_route_evidence import (
        CanonicalRouteAssessmentPhase,
        CanonicalRouteMaterialization,
    )
    from d810.transforms.unflatten_authority import model, transaction_api

    source, plan, proposal, source_inventory, _materialization, _endpoint = (
        _logical_dag_source_bind_case()
    )
    projected_inventory = transaction_api._build_semantic_graph_inventory(
        source,
        proposal,
        plan,
        source=False,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        source_subjects=source_inventory.subjects,
        materialization=CanonicalRouteMaterialization.capture(
            source,
            generation=1,
            phase=CanonicalRouteAssessmentPhase.PROJECTED,
        ),
    )

    logical_binding = next(
        binding
        for binding in projected_inventory.bindings
        if type(binding.subject.locator) is model.LogicalFunctionExitSubjectLocator
    )
    assert logical_binding.status is model.SubjectBindingStatus.UNIQUE
    assert logical_binding.block_ref == logical_binding.subject.locator.block_ref
    assert logical_binding.serial == logical_binding.subject.locator.serial
    assert logical_binding.anchor_ea is None
    assert logical_binding.native_instruction_eas == ()


def test_observed_inventory_uses_producer_endpoint_authority_for_missing_route_leaf():
    """Observed route loss is classified from the sealed producer endpoint.

    The candidate inventory carries the route subject but not the logical STOP
    coordinate.  It must therefore bind MISSING rather than treating its own
    sibling subject as proof of source ownership.
    """
    from d810.ir.flowgraph import FlowGraph
    from d810.transforms.unflatten_authority import model, transaction_api

    source, plan, proposal, source_inventory, _materialization, _endpoint = (
        _logical_dag_source_bind_case()
    )
    observed = FlowGraph(
        {
            **{serial: block for serial, block in source.blocks.items() if serial != 5},
            2: replace(source.blocks[2], succs=(4,)),
        },
        source.entry_serial,
        source.func_ea,
    )

    inventory = transaction_api._build_semantic_graph_inventory(
        observed,
        proposal,
        plan,
        source=False,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        source_subjects=source_inventory.subjects,
        source_inventory=source_inventory,
    )
    route_binding = next(
        binding
        for binding in inventory.bindings
        if binding.subject.role is model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE
        and type(binding.subject.locator) is model.RouteSubjectLocator
        and any(
            type(member) is model.LogicalFunctionExitSubjectLocator
            for member in binding.subject.locator.dag_endpoint_members()
        )
    )
    assert route_binding.status is model.SubjectBindingStatus.MISSING


@pytest.mark.parametrize(
    "observed_mutation",
    (None, "endpoint_shape", "comparison_edge"),
    ids=("accepted", "endpoint-shape-drift", "comparison-edge-drift"),
)
def test_public_logical_dag_authority_lifecycle_closes_one_endpoint_authority(
    observed_mutation: str | None,
):
    """One logical endpoint is closed by prepare, bind, and observation.

    This deliberately uses only the transaction facade.  The selected
    ``SemanticDagEndpoint`` therefore has to survive the proposal, projected
    inventory, immutable prepared authority, live patch binding, and observed
    inventory as the same logical coordinate rather than as a native anchor.
    """
    from d810.analyses.control_flow.graph_checks import (
        check_effectful_reachability_preserved,
        check_entry_reachability_not_collapsed,
        check_terminal_reachability_preserved,
    )
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.hexrays.mutation.patch_binding import bind_patch_plan
    from d810.transforms.edit_simulator import project_post_state
    from d810.transforms.cfg_transaction import CfgProjection, TransactionAttemptId
    from d810.transforms.unflatten_authority import model, transaction_api
    from d810.transforms.unflatten_authority.gates import GenericCfgGateBundle

    source, plan, proposal, _inventory, _materialization, endpoint = (
        _logical_dag_source_bind_case()
    )
    attempt = TransactionAttemptId(
        plan.plan_id,
        "logical-dag-public",
        1,
        authority_id(("logical-dag-public-attempt", plan.plan_id)),
    )
    projected = project_post_state(source, plan)
    gates = GenericCfgGateBundle(
        check_entry_reachability_not_collapsed(source, post_cfg=projected),
        check_effectful_reachability_preserved(source, post_cfg=projected),
        check_effectful_reachability_preserved(source, post_cfg=projected),
        check_terminal_reachability_preserved(source, post_cfg=projected),
    )
    preparation = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=attempt,
        generic_gates=gates,
    )
    assert type(preparation) is model.UnflattenAuthorityPreparationAccepted
    prepared = preparation.prepared
    assert prepared is not None
    (claim,) = tuple(
        item for item in proposal.claims
        if type(item) is model.EquivalentSemanticRouteClaim
    )
    assert claim.dag_endpoint_subjects
    endpoint_subject_ids = tuple(
        subject.subject_id for subject in claim.dag_endpoint_subjects
    )
    route_payloads = tuple(
        item.payload
        for item in prepared.projected_case.evidence
        if type(item.payload) is model.SemanticRouteEvidencePayload
    )
    assert route_payloads
    assert all(
        payload.dag_endpoint_subject_ids == endpoint_subject_ids
        for payload in route_payloads
    )
    refs = tuple(plan.source_coordinates)
    index = MbaBlockIdentityIndex.from_flow_graph(
        generation=attempt.generation,
        maturity=None,
        native_key=proposal.source_identity_catalog.native_key,
        snapshot_id=plan.snapshot_id,
        session_id=attempt.session_id,
        flow_graph=source,
    )
    assert dict(index.plan_refs_by_serial()) == {
        serial: ref for ref, serial in refs
    }
    index.begin_transaction(attempt, quantity=len(source.blocks))
    binding = transaction_api.bind_prepared_unflatten_authority(
        prepared=prepared,
        patch_binding=bind_patch_plan(plan, index, attempt).bound_plan,
    )
    assert binding.authority is not None
    observed_graph = projected
    if observed_mutation is not None:
        from d810.ir.flowgraph import BlockKind, FlowGraph

        if observed_mutation == "endpoint_shape":
            changed_blocks = {
                **projected.blocks,
                5: replace(
                    projected.blocks[5],
                    succs=(3,),
                    kind=BlockKind.ONE_WAY,
                ),
            }
        else:
            changed_blocks = {
                **projected.blocks,
                2: replace(projected.blocks[2], succs=(3, 5)),
            }
        observed_graph = FlowGraph(
            changed_blocks, projected.entry_serial, projected.func_ea,
        )
    observed_gates = GenericCfgGateBundle(
        check_entry_reachability_not_collapsed(source, post_cfg=observed_graph),
        check_effectful_reachability_preserved(source, post_cfg=observed_graph),
        check_effectful_reachability_preserved(source, post_cfg=observed_graph),
        check_terminal_reachability_preserved(source, post_cfg=observed_graph),
    )
    observed = transaction_api.revalidate_observed_unflatten_authority(
        authority=binding.authority,
        observed=observed_graph,
        observed_generation=attempt.generation,
        generic_gates=observed_gates,
        observed_patch_binding=observed_patch_binding_for_test(binding.authority),
    )
    if observed_mutation is not None:
        assert not observed.accepted
        assert observed.reason is model.UnflattenAuthorityReason.LIVE_BINDING_FAILED
        return
    assert observed.accepted
    assert observed.observed_acceptance is not None
    assert observed.observed_acceptance.bound_authority is binding.authority
    assert any(
        item == endpoint
        for proof in binding.authority.prepared.proposal.route_evidence.route_proofs
        for comparison in proof.state_dag.witness.comparisons
        for item in (comparison.true_target, comparison.false_target)
    )


def test_observed_logical_endpoint_occurrence_rebinds_exact_plan_owned_sink():
    """One prepared logical target may move without changing its identity."""
    from d810.ir.flowgraph import FlowGraph, MopSnapshot, OperandKind
    from d810.transforms.plan import PatchRedirectGoto
    from d810.transforms.unflatten_authority import bind, model, transaction_api
    from d810.transforms.unflatten_authority.proposal import (
        canonical_redirect_manifest,
    )

    source, plan, proposal, source_inventory, _materialization, _endpoint = (
        _logical_dag_source_bind_case()
    )
    refs_by_serial = {
        serial: ref for ref, serial in plan.source_coordinates
    }
    logical_ref = refs_by_serial[5]
    redirect = plan.steps[0]
    assert type(redirect) is PatchRedirectGoto
    logical_plan = replace(
        plan,
        steps=(replace(redirect, new_target=logical_ref),),
    )
    manifest = canonical_redirect_manifest(logical_plan)
    proposal = replace(
        proposal,
        use_def_witness=replace(
            proposal.use_def_witness,
            redirect_owner_refs=manifest.owner_refs,
            redirect_digest=manifest.digest,
        ),
    )
    logical_plan = replace(logical_plan, unflatten_proposal=proposal)

    def retarget(block, target_serial):
        tail = replace(
            block.insn_snapshots[-1],
            d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=target_serial),
            operands=(MopSnapshot(kind=OperandKind.BLOCK, block_ref=target_serial),),
            operand_slots=((
                "d", MopSnapshot(kind=OperandKind.BLOCK, block_ref=target_serial),
            ),),
        )
        return replace(
            block,
            succs=(target_serial,),
            insn_snapshots=(*block.insn_snapshots[:-1], tail),
        )

    projected_blocks = {
        **source.blocks,
        1: retarget(source.blocks[1], 5),
        2: replace(source.blocks[2], preds=()),
        5: replace(source.blocks[5], preds=(1, 2)),
    }
    projected = FlowGraph(
        projected_blocks, source.entry_serial, source.func_ea,
    )
    projected_inventory = transaction_api._build_semantic_graph_inventory(
        projected,
        proposal,
        logical_plan,
        source=False,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        source_subjects=source_inventory.subjects,
        source_inventory=source_inventory,
    )

    observed_serial = 127
    observed_blocks = {
        **{
            serial: block
            for serial, block in projected.blocks.items()
            if serial != 5
        },
        1: retarget(projected.blocks[1], observed_serial),
        2: replace(
            projected.blocks[2],
            succs=tuple(
                observed_serial if serial == 5 else serial
                for serial in projected.blocks[2].succs
            ),
        ),
        observed_serial: replace(
            projected.blocks[5], serial=observed_serial,
        ),
    }
    observed = FlowGraph(
        observed_blocks, projected.entry_serial, projected.func_ea,
    )
    serial_by_ref = transaction_api._projected_serials(
        observed,
        proposal,
        plan=logical_plan,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
    )
    occurrence = transaction_api._resolve_observed_logical_endpoint_occurrences(
        blocks=observed.blocks,
        plan=logical_plan,
        serial_by_ref=serial_by_ref,
        projected_inventory=projected_inventory,
    )

    assert occurrence == (
        model.ObservedLogicalEndpointOccurrence(
            logical_ref=logical_ref,
            projected_serial=5,
            observed_serial=observed_serial,
            owner_ref=refs_by_serial[1],
            predecessor_refs=(refs_by_serial[1], refs_by_serial[2]),
        ),
    )
    bind._validate_observed_logical_endpoint_occurrence(occurrence[0])
    with pytest.raises(ValueError, match="not minted"):
        bind._validate_observed_logical_endpoint_occurrence(
            model.ObservedLogicalEndpointOccurrence(
                logical_ref=logical_ref,
                projected_serial=5,
                observed_serial=observed_serial,
                owner_ref=refs_by_serial[1],
                predecessor_refs=(refs_by_serial[1], refs_by_serial[2]),
            ),
        )

    foreign_target = MopSnapshot(kind=OperandKind.BLOCK, block_ref=999)
    contradictory_owner = replace(
        observed.blocks[1],
        insn_snapshots=(
            *observed.blocks[1].insn_snapshots[:-1],
            replace(
                observed.blocks[1].insn_snapshots[-1],
                l=foreign_target,
            ),
        ),
    )
    assert not transaction_api._is_exact_unconditional_goto_to(
        contradictory_owner, observed_serial,
    )

    hidden_predecessor_blocks = {
        **observed.blocks,
        6: replace(observed.blocks[6], succs=(observed_serial,)),
    }
    assert transaction_api._resolve_observed_logical_endpoint_occurrences(
        blocks=hidden_predecessor_blocks,
        plan=logical_plan,
        serial_by_ref=serial_by_ref,
        projected_inventory=projected_inventory,
    ) == ()

    malformed_sink_blocks = {
        **observed.blocks,
        observed_serial: replace(
            observed.blocks[observed_serial],
            kind=observed.blocks[1].kind,
            succs=(3,),
        ),
    }
    assert transaction_api._resolve_observed_logical_endpoint_occurrences(
        blocks=malformed_sink_blocks,
        plan=logical_plan,
        serial_by_ref=serial_by_ref,
        projected_inventory=projected_inventory,
    ) == ()


def test_projected_serials_preserve_exact_logical_clone_occurrence() -> None:
    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.flowgraph import (
        BlockKind,
        BlockSnapshot,
        FlowGraph,
        InsnKind,
        InsnSnapshot,
    )
    from d810.transforms.cfg_transaction import LogicalBlockRef

    logical_ref = LogicalBlockRef("session", "clone", 1)
    instruction = InsnSnapshot(
        0,
        0x1004,
        (),
        kind=InsnKind.NOP,
        raw_opcode=0,
    )
    block = BlockSnapshot(
        0,
        0,
        (),
        (),
        0,
        0x1000,
        (instruction,),
        tail_opcode=instruction.opcode,
        kind=BlockKind.ZERO_WAY,
        tail_kind=instruction.kind,
        raw_tail_opcode=instruction.raw_opcode,
    )
    graph = FlowGraph({0: block}, 0, 0x1000)
    key = NativePreanalysisKey(
        "input", "x86", 64, 0, "f" * 64, "p" * 64, "s" * 64,
    )
    catalog = model.SourceIdentityCatalog(
        key,
        0,
        (model.SourceBlockIdentityWitness(logical_ref, 0x1004, (0x1004,)),),
    )
    proposal = SimpleNamespace(
        source_identity_catalog=catalog,
        claims=(),
        route_evidence=None,
    )
    plan = SimpleNamespace(
        source_coordinates=((logical_ref, 0),),
        new_blocks=(),
    )

    assert transaction_api._projected_serials(
        graph,
        proposal,
        plan=plan,
    ) == {logical_ref: 0}


def test_projected_native_source_with_synthetic_start_keeps_sealed_owner() -> None:
    """A retained CALL block uses its source coordinate, not a fictitious EA."""
    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
    from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
    from d810.transforms.cfg_transaction import NativeBlockRef

    key = NativePreanalysisKey(
        "input", "x86", 64, 0, "f" * 64, "p" * 64, "s" * 64,
    )
    owner = NativeBlockRef(StableBlockIdentity.from_intervals(
        (
            NativeEaInterval(0x1000, 0x1001),
            NativeEaInterval(0x1004, 0x1005),
            NativeEaInterval(0x1008, 0x1009),
        ),
        native_key=key,
        exact_instruction_eas=(0x1004, 0x1008),
    ))
    instructions = (
        InsnSnapshot(1, 0x1004, (), kind=InsnKind.CALL, raw_opcode=1),
        InsnSnapshot(2, 0x1008, (), kind=InsnKind.CALL, raw_opcode=2),
    )
    projected_block = BlockSnapshot(
        0, 0, (), (), 0, 0xF1C0000000000020, instructions,
        tail_opcode=2, kind=BlockKind.ZERO_WAY, tail_kind=InsnKind.CALL,
        raw_tail_opcode=2, native_start_ea=None,
    )
    graph = FlowGraph({0: projected_block}, 0, 0x1000)
    catalog = model.SourceIdentityCatalog(
        key, 0, (model.SourceBlockIdentityWitness(owner, 0x1000, (0x1004, 0x1008)),),
    )
    proposal = SimpleNamespace(source_identity_catalog=catalog, claims=(), route_evidence=None)
    plan = SimpleNamespace(source_coordinates=((owner, 0),), new_blocks=())

    resolution = transaction_api._resolve_candidate_identities(
        graph, proposal, plan=plan,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )

    assert dict(resolution.serial_bindings) == {owner: 0}

    # An edited native inventory is not the sealed source occurrence. Native
    # candidates still use ordinary rebinding; they do not inherit the strict
    # logical-clone rejection rule merely because their serial was retained.
    changed = replace(
        projected_block,
        insn_snapshots=(instructions[0], InsnSnapshot(3, 0x100C, (), kind=InsnKind.CALL, raw_opcode=3)),
    )
    changed_graph = FlowGraph({0: changed}, 0, 0x1000)
    changed_resolution = transaction_api._resolve_candidate_identities(
        changed_graph, proposal, plan=plan,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    assert dict(changed_resolution.serial_bindings) == {}

    # An unsealed generated CALL occurrence with the same native origins
    # cannot borrow the retained source block's typed identity.
    generated = replace(projected_block, serial=1, start_ea=0xF1C0000000000024)
    graph_with_generated_call = FlowGraph(
        {0: projected_block, 1: generated}, 0, 0x1000,
    )
    generated_resolution = transaction_api._resolve_candidate_identities(
        graph_with_generated_call, proposal, plan=plan,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    assert dict(generated_resolution.serial_bindings) == {owner: 0}

    # A changed retained owner and an unsealed CALL with the old source
    # coordinates must not let the generated occurrence inherit that owner.
    generated_collision = replace(generated, start_ea=0x1000)
    collided_graph = FlowGraph(
        {0: changed, 1: generated_collision}, 0, 0x1000,
    )
    collided_resolution = transaction_api._resolve_candidate_identities(
        collided_graph, proposal, plan=plan,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    assert dict(collided_resolution.serial_bindings) == {}

    # An explicit native start that contradicts the sealed identity must not
    # be hidden by matching instruction origins and a synthetic graph start.
    contradictory_start = replace(projected_block, native_start_ea=0x1010)
    contradictory_graph = FlowGraph({0: contradictory_start}, 0, 0x1000)
    contradictory_resolution = transaction_api._resolve_candidate_identities(
        contradictory_graph, proposal, plan=plan,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    assert dict(contradictory_resolution.serial_bindings) == {}

    # A changed block at A's sealed serial cannot acquire B's catalog ref
    # merely because B's original occurrence disappeared from the projection.
    other = NativeBlockRef(StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x2000, 0x2001), NativeEaInterval(0x2004, 0x2005)),
        native_key=key, exact_instruction_eas=(0x2004,),
    ))
    two_owner_catalog = model.SourceIdentityCatalog(
        key, 0,
        (
            model.SourceBlockIdentityWitness(owner, 0x1000, (0x1004, 0x1008)),
            model.SourceBlockIdentityWitness(other, 0x2000, (0x2004,)),
        ),
    )
    replaced_owner = replace(
        projected_block,
        native_start_ea=0x2000,
        insn_snapshots=(InsnSnapshot(4, 0x2004, (), kind=InsnKind.CALL, raw_opcode=4),),
        tail_opcode=4,
        raw_tail_opcode=4,
    )
    cross_ref_resolution = transaction_api._resolve_candidate_identities(
        FlowGraph({0: replaced_owner}, 0, 0x1000),
        SimpleNamespace(
            source_identity_catalog=two_owner_catalog,
            claims=(), route_evidence=None,
        ),
        plan=SimpleNamespace(
            source_coordinates=((owner, 0), (other, 1)), new_blocks=(),
        ),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    assert dict(cross_ref_resolution.serial_bindings) == {}


def test_logical_clone_catalog_ref_is_not_labeled_as_function_exit() -> None:
    """Logical refs also name native clone occurrences; they are not exits."""
    from d810.transforms.cfg_transaction import LogicalBlockRef

    _source, plan, proposal, _inventory, _materialization, _endpoint = (
        _logical_dag_source_bind_case()
    )
    logical_ref = LogicalBlockRef("session", "clone", 1)
    catalog = model.SourceIdentityCatalog(
        proposal.source_identity_catalog.native_key,
        proposal.source_identity_catalog.generation,
        (*proposal.source_identity_catalog.blocks,
         model.SourceBlockIdentityWitness(logical_ref, 0x1004, (0x1004,))),
    )
    proposal = replace(proposal, source_identity_catalog=catalog)
    source_serials = {
        **dict(plan.source_coordinates),
        logical_ref: 99,
    }

    subjects = transaction_api._inventory_subjects(
        proposal,
        source_serials,
        (),
        (),
        plan,
    )

    assert not any(
        subject.role is model.SemanticSubjectRole.SOURCE_LOGICAL_EXIT
        and subject.block_ref == logical_ref
        for subject in subjects
    )


def test_observed_logical_clones_rebind_by_exact_predecessor_occurrence() -> None:
    """Shared native CALL clones retain predecessor-owned observed identity."""
    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.flowgraph import (
        BlockKind,
        BlockSnapshot,
        FlowGraph,
        InsnKind,
        InsnSnapshot,
    )
    from d810.transforms.cfg_transaction import LogicalBlockRef

    refs = {
        serial: LogicalBlockRef("session", f"block-{serial}", 1)
        for serial in range(4)
    }
    def predecessor(serial, ea, target):
        return BlockSnapshot(
            serial, 0, (target,), (), 0, ea,
            (InsnSnapshot(0, ea, (), kind=InsnKind.GOTO, raw_opcode=0),),
            tail_opcode=0, kind=BlockKind.ONE_WAY, tail_kind=InsnKind.GOTO,
            raw_tail_opcode=0, native_start_ea=ea,
        )

    def clone(serial, predecessor_serial):
        return BlockSnapshot(
            serial, 0, (), (predecessor_serial,), 0, 0xF1C0000000000004,
            (InsnSnapshot(
                1, 0x3000, (), kind=InsnKind.CALL, raw_opcode=1, is_call=True,
            ),),
            tail_opcode=1, kind=BlockKind.ZERO_WAY, tail_kind=InsnKind.CALL,
            raw_tail_opcode=1, native_start_ea=0x3000,
        )
    blocks = {
        0: predecessor(0, 0x1000, 2),
        1: predecessor(1, 0x2000, 3),
        2: clone(2, 0),
        3: clone(3, 1),
    }
    graph = FlowGraph(blocks, 0, 0x1000)
    key = NativePreanalysisKey(
        "input", "x86", 64, 0, "f" * 64, "p" * 64, "s" * 64,
    )
    catalog = model.SourceIdentityCatalog(
        key,
        0,
        (
            model.SourceBlockIdentityWitness(refs[0], 0x1000, (0x1000,)),
            model.SourceBlockIdentityWitness(refs[1], 0x2000, (0x2000,)),
            model.SourceBlockIdentityWitness(refs[2], 0x3000, (0x3000,)),
            model.SourceBlockIdentityWitness(refs[3], 0x3000, (0x3000,)),
        ),
    )
    proposal = SimpleNamespace(
        source_identity_catalog=catalog,
        claims=(),
        route_evidence=None,
    )
    plan = SimpleNamespace(
        source_coordinates=tuple((refs[serial], serial) for serial in range(4)),
        new_blocks=(),
    )
    source_inventory = SimpleNamespace(blocks=tuple(
        SimpleNamespace(
            serial=serial,
            block_ref=refs[serial],
            predecessor_serials=blocks[serial].preds,
        )
        for serial in range(4)
    ))

    resolution = transaction_api._resolve_candidate_identities(
        graph,
        proposal,
        plan=plan,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        source_inventory=source_inventory,
    )

    assert dict(resolution.serial_bindings) == {
        refs[0]: 0,
        refs[1]: 1,
        refs[2]: 2,
        refs[3]: 3,
    }

    swapped = FlowGraph(
        {**blocks, 2: clone(2, 1), 3: clone(3, 0)},
        0,
        0x1000,
    )
    swapped_resolution = transaction_api._resolve_candidate_identities(
        swapped,
        proposal,
        plan=plan,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        source_inventory=source_inventory,
    )
    assert dict(swapped_resolution.serial_bindings) == {
        refs[0]: 0,
        refs[1]: 1,
        refs[2]: 3,
        refs[3]: 2,
    }

    ambiguous = FlowGraph(
        {**blocks, 2: clone(2, 0), 3: clone(3, 0)},
        0,
        0x1000,
    )
    ambiguous_resolution = transaction_api._resolve_candidate_identities(
        ambiguous,
        proposal,
        plan=plan,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        source_inventory=source_inventory,
    )
    assert dict(ambiguous_resolution.serial_bindings) == {
        refs[0]: 0,
        refs[1]: 1,
    }


def test_observed_shared_ea_occurrences_rebind_by_exact_control_shape() -> None:
    """A table transfer and its synthetic abort CALL are distinct rows."""
    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.flowgraph import (
        BlockKind,
        BlockSnapshot,
        FlowGraph,
        InsnKind,
        InsnSnapshot,
    )
    from d810.transforms.cfg_transaction import LogicalBlockRef
    from d810.transforms.unflatten_authority import producer_api

    table_ref = LogicalBlockRef("session", "table", 1)
    abort_ref = LogicalBlockRef("session", "abort", 1)
    table_insn = InsnSnapshot(
        1, 0x3000, (), kind=InsnKind.TABLE_JUMP, raw_opcode=1,
    )
    abort_insn = InsnSnapshot(
        2, 0x3000, (), kind=InsnKind.CALL, raw_opcode=2, is_call=True,
    )
    blocks = {
        0: BlockSnapshot(
            0, 0, (1,), (1,), 0, 0xFFFFFFFFFFFFFFFF, (table_insn,),
            tail_opcode=1, kind=BlockKind.N_WAY,
            tail_kind=InsnKind.TABLE_JUMP, raw_tail_opcode=1,
            native_start_ea=None,
        ),
        1: BlockSnapshot(
            1, 0, (), (0,), 0, 0xF1C0000000000004, (abort_insn,),
            tail_opcode=2, kind=BlockKind.ZERO_WAY,
            tail_kind=InsnKind.CALL, raw_tail_opcode=2,
            native_start_ea=0x3000,
        ),
    }
    graph = FlowGraph(blocks, 0, 0x3000)
    key = NativePreanalysisKey(
        "input", "x86", 64, 0, "f" * 64, "p" * 64, "s" * 64,
    )
    catalog = model.SourceIdentityCatalog(
        key,
        0,
        (
            model.SourceBlockIdentityWitness(table_ref, 0x3000, (0x3000,)),
            model.SourceBlockIdentityWitness(abort_ref, 0x3000, (0x3000,)),
        ),
    )
    proposal = SimpleNamespace(
        source_identity_catalog=catalog, claims=(), route_evidence=None,
    )
    plan = SimpleNamespace(
        source_coordinates=((table_ref, 0), (abort_ref, 1)), new_blocks=(),
    )
    source_inventory = SimpleNamespace(blocks=(
        producer_api.observe_inventory_block(
            blocks[0], owner_ref=table_ref, owner_anchor_ea=0x3000,
        ),
        producer_api.observe_inventory_block(
            blocks[1], owner_ref=abort_ref, owner_anchor_ea=0x3000,
        ),
    ))

    resolution = transaction_api._resolve_candidate_identities(
        graph,
        proposal,
        plan=plan,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        source_inventory=source_inventory,
    )

    assert dict(resolution.serial_bindings) == {
        table_ref: 0,
        abort_ref: 1,
    }


def test_projected_serials_exclude_unsealed_or_malformed_logical_stops():
    """Only the selected, sealed, exact logical exit survives projection."""
    from d810.ir.flowgraph import BlockKind, FlowGraph
    from d810.transforms.cfg_transaction import LogicalBlockRef
    from d810.transforms.unflatten_authority import transaction_api

    source, plan, proposal, _inventory, _materialization, _endpoint = (
        _logical_dag_source_bind_case()
    )
    logical_ref = next(ref for ref, serial in plan.source_coordinates if serial == 5)
    assert transaction_api._projected_serials(source, proposal, plan=plan)[logical_ref] == 5

    malformed = FlowGraph(
        {**source.blocks, 5: replace(source.blocks[5], succs=(4,), kind=BlockKind.ONE_WAY)},
        source.entry_serial,
        source.func_ea,
    )
    assert logical_ref not in transaction_api._projected_serials(
        malformed, proposal, plan=plan,
    )

    unrelated = LogicalBlockRef("logical-dag-public", "unrelated-exit", 1)
    wrong_coordinate = replace(
        plan,
        source_coordinates=tuple(
            (unrelated if serial == 5 else ref, serial)
            for ref, serial in plan.source_coordinates
        ),
    )
    assert unrelated not in transaction_api._projected_serials(
        source, proposal, plan=wrong_coordinate,
    )

    wrong_serial = replace(
        plan,
        source_coordinates=tuple(
            (next(ref for ref, candidate in plan.source_coordinates if candidate == 6)
             if serial == 5 else logical_ref if serial == 6 else ref, serial)
            for ref, serial in plan.source_coordinates
        ),
    )
    assert logical_ref not in transaction_api._projected_serials(
        source, proposal, plan=wrong_serial,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("session_id", "reminted-logical-session"),
        ("proxy_token", "reminted-logical-token"),
        ("version", 2),
    ),
)
@pytest.mark.parametrize("endpoint_kind_name", ("zero_way", "stop"))
def test_public_source_bind_rejects_reminted_logical_endpoint_at_source_authority(
    field: str, value: object, endpoint_kind_name: str,
):
    """Graph-valid endpoint evidence still needs the live transaction identity."""
    from d810.transforms.unflatten_authority import bind, model

    _source, _plan, proposal, inventory, materialization, _endpoint = (
        _logical_dag_source_bind_case(
            endpoint_kind_name=endpoint_kind_name,
            endpoint_override={field: value},
        )
    )
    # The reminted proof is itself canonical; rejection must occur at the
    # transaction-owned source inventory comparison, not during ID minting.
    proposal.route_evidence.__post_init__()
    result = bind.bind_source_route_authority(
        proposal=proposal,
        source_inventory=inventory,
        source_materialization=materialization,
    )

    assert type(result) is model.SourceBoundRouteAuthorityRejected
    assert result.failures[0].stage is model.RouteRealizationFailureStage.SOURCE_AUTHORITY


def test_public_source_bind_rejects_unrelated_logical_coordinate():
    """Only the exact routed logical exit may be present beside the STOP row."""
    from d810.transforms.cfg_transaction import LogicalBlockRef
    from d810.transforms.unflatten_authority import model, transaction_api

    source, plan, proposal, _inventory, materialization, _endpoint = (
        _logical_dag_source_bind_case()
    )
    unrelated = LogicalBlockRef("logical-dag-public", "unrelated", 1)
    malformed = replace(
        plan,
        source_coordinates=(
            *tuple((ref, serial) for ref, serial in plan.source_coordinates if serial != 5),
            (unrelated, 5),
        ),
    )
    with pytest.raises(ValueError, match="logical function-exit coordinate"):
        transaction_api._build_semantic_graph_inventory(
            source,
            proposal,
            malformed,
            source=True,
            phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
            materialization=materialization,
        )


def test_public_source_inventory_rejects_unselected_logical_zero_way_coordinate():
    """Only selected DAG evidence may mint an owned anchorless ZERO_WAY row."""
    from d810.ir.flowgraph import BlockKind, FlowGraph
    from d810.transforms.unflatten_authority import model, transaction_api

    source, plan, proposal, _inventory, _materialization, _endpoint = (
        _logical_dag_source_bind_case()
    )
    unselected = FlowGraph(
        {**source.blocks, 6: replace(source.blocks[6], kind=BlockKind.ZERO_WAY)},
        source.entry_serial,
        source.func_ea,
    )
    with pytest.raises(ValueError, match="unowned non-structural"):
        transaction_api._build_semantic_graph_inventory(
            unselected,
            proposal,
            plan,
            source=True,
            phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        )

def test_public_preparation_closes_guarded_convert_to_goto_evidence() -> None:
    """Prepare consumes the exact folded relation and its typed patch fact."""

    from d810.analyses.control_flow.graph_checks import (
        check_effectful_reachability_preserved,
        check_entry_reachability_not_collapsed,
        check_terminal_reachability_preserved,
    )
    from d810.transforms.cfg_transaction import CfgProjection
    from d810.transforms.unflatten_authority import model, transaction_api
    from d810.transforms.unflatten_authority.gates import GenericCfgGateBundle
    from . import test_bind

    values = test_bind._compiler_guarded_convert_to_goto_case(
        include_graphs=True,
    )
    plan, attempt, source, projected = values[1], values[5], values[6], values[7]
    raw_effect = check_effectful_reachability_preserved(
        source, post_cfg=projected,
    )
    gates = GenericCfgGateBundle(
        check_entry_reachability_not_collapsed(source, post_cfg=projected),
        raw_effect,
        raw_effect,
        check_terminal_reachability_preserved(source, post_cfg=projected),
    )
    result = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=attempt,
        generic_gates=gates,
    )
    assert type(result) is model.UnflattenAuthorityPreparationAccepted
    prepared = result.prepared
    assert prepared is not None
    (row,) = prepared.projected_route_realization.rows
    assert type(row.relation) is model.FoldedConditionalRouteRealization
    patch_rows = tuple(
        item for item in prepared.projected_case.evidence
        if type(item.payload) is model.PatchStepEvidencePayload
        and item.payload.step_type == "PatchConvertToGoto"
    )
    assert len(patch_rows) == 1
    assert patch_rows[0].subject.kind is model.SemanticSubjectKind.BLOCK
    assert patch_rows[0].subject.role is (
        model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE
    )


@pytest.mark.parametrize(
    "mutation",
    (None, "wrong_target", "foreign_source_origin", "unrelated_edge_loss"),
)
def test_observed_guarded_convert_to_goto_binds_backend_generated_tail(
    mutation: str | None,
    caplog,
) -> None:
    """Observed validation consumes the same fold after Hex-Rays m_goto mint."""

    from d810.analyses.control_flow.graph_checks import (
        check_effectful_reachability_preserved,
        check_entry_reachability_not_collapsed,
        check_terminal_reachability_preserved,
    )
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.hexrays.mutation.patch_binding import bind_patch_plan
    from d810.ir.flowgraph import (
        BlockKind, FlowGraph, InsnKind, InsnSnapshot, MopSnapshot, OperandKind,
    )
    from d810.ir.semantics import ControlTransferKind
    from d810.transforms.cfg_transaction import CfgProjection
    from d810.transforms.unflatten_authority import model, transaction_api
    from d810.transforms.unflatten_authority.gates import GenericCfgGateBundle
    from . import test_bind

    values = test_bind._compiler_guarded_convert_to_goto_case(
        include_graphs=True,
    )
    plan, attempt, source, projected = values[1], values[5], values[6], values[7]
    projected_gates = GenericCfgGateBundle(
        check_entry_reachability_not_collapsed(source, post_cfg=projected),
        check_effectful_reachability_preserved(source, post_cfg=projected),
        check_effectful_reachability_preserved(source, post_cfg=projected),
        check_terminal_reachability_preserved(source, post_cfg=projected),
    )
    prepared = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=attempt,
        generic_gates=projected_gates,
    ).prepared
    assert prepared is not None
    refs = tuple(plan.source_coordinates)
    index = MbaBlockIdentityIndex.from_bindings(
        generation=attempt.generation,
        maturity=None,
        native_key=refs[0][0].identity.native_key,
        snapshot_id=plan.snapshot_id,
        session_id=attempt.session_id,
        bindings=tuple((ref.identity, serial) for ref, serial in refs),
    )
    index.begin_transaction(attempt, quantity=len(source.blocks))
    authority = transaction_api.bind_prepared_unflatten_authority(
        prepared=prepared,
        patch_binding=bind_patch_plan(plan, index, attempt).bound_plan,
    ).authority
    assert authority is not None

    folded_serial = dict(plan.source_coordinates)[plan.steps[0].block_serial]
    folded = projected.blocks[folded_serial]
    backend_target = folded.succs[0]
    if mutation == "wrong_target":
        backend_target = next(
            target for target in source.blocks[folded_serial].succs
            if target != folded.succs[0]
        )
    backend_goto = InsnSnapshot(
        opcode=55,
        raw_opcode=55,
        ea=source.func_ea,
        native_ea=(
            source.blocks[7].insn_snapshots[0].ea
            if mutation == "foreign_source_origin" else None
        ),
        operands=(),
        l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=backend_target),
        kind=InsnKind.GOTO,
        control_transfer_kind=ControlTransferKind.GOTO,
    )
    observed = FlowGraph(
        {
            **projected.blocks,
            folded_serial: replace(
                folded,
                insn_snapshots=(*folded.insn_snapshots[:-1], backend_goto),
                tail_opcode=backend_goto.opcode,
                raw_tail_opcode=backend_goto.raw_opcode,
                tail_kind=InsnKind.GOTO,
            ),
        },
        projected.entry_serial,
        projected.func_ea,
    )
    if mutation == "unrelated_edge_loss":
        # Route the entry through the source-catalog-only discarded block so
        # every generic reachability gate remains green while the unrelated
        # semantic predecessor edge 7 -> folded_serial is removed.  Edges
        # incident to block 2 do not masquerade as route-role topology.
        observed = FlowGraph(
            {
                **observed.blocks,
                7: replace(observed.blocks[7], succs=(2,)),
                2: replace(
                    observed.blocks[2],
                    kind=BlockKind.ONE_WAY,
                    preds=(7,),
                    succs=(folded_serial,),
                ),
                folded_serial: replace(
                    observed.blocks[folded_serial], preds=(2,),
                ),
            },
            observed.entry_serial,
            observed.func_ea,
        )
    observed_gates = GenericCfgGateBundle(
        check_entry_reachability_not_collapsed(source, post_cfg=observed),
        check_effectful_reachability_preserved(source, post_cfg=observed),
        check_effectful_reachability_preserved(source, post_cfg=observed),
        check_terminal_reachability_preserved(source, post_cfg=observed),
    )
    if mutation == "unrelated_edge_loss":
        assert observed_gates.entry.passed
        assert observed_gates.effectful_raw.passed
        assert observed_gates.effectful_effective.passed
        assert observed_gates.terminal.passed

    with caplog.at_level(
        "WARNING",
        logger="d810.transforms.unflatten_authority.transaction_api",
    ):
        verdict = transaction_api.revalidate_observed_unflatten_authority(
            authority=authority,
            observed=observed,
            observed_generation=attempt.generation,
            generic_gates=observed_gates,
            observed_patch_binding=observed_patch_binding_for_test(authority),
        )

    if mutation in {
        "wrong_target", "foreign_source_origin", "unrelated_edge_loss",
    }:
        assert not verdict.accepted
        if mutation in {"wrong_target", "foreign_source_origin"}:
            assert verdict.reason is (
                model.UnflattenAuthorityReason.LIVE_BINDING_FAILED
            )
        else:
            assert any(
                item.key.dimension is model.SafetyDimension.TOPOLOGY_INTEGRITY
                and item.state is model.ObligationState.VIOLATED
                for item in verdict.failed_obligations
            )
        if mutation == "unrelated_edge_loss":
            assert any(
                "observed authority first failure dimension=" in record.getMessage()
                and " state=" in record.getMessage()
                and " subject=" in record.getMessage()
                for record in caplog.records
            )
        return

    failed = tuple(
        (
            item.key.subject.kind.value,
            item.key.subject.role.value,
            item.key.subject.anchor_ea,
            item.key.dimension.value,
            item.state.value,
        )
        for item in verdict.failed_obligations
    )
    assert verdict.accepted, (verdict.reason, failed)


def test_public_preparation_accepts_non_dispatcher_route_source_owner():
    """A real manifest owner may be a semantic feeder, not retired infrastructure."""

    from d810.transforms.unflatten_authority import model, producer_api, transaction_api
    from d810.transforms.unflatten_authority.proposal import (
        ProposalAccepted,
        canonical_redirect_manifest,
        validate_proposal,
    )

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    refs_by_serial = {
        serial: ref for ref, serial in plan.source_coordinates
    }
    original = plan.unflatten_proposal
    assert original is not None
    proposal = producer_api.build_proposal(
        plan_id=plan.plan_id,
        source=source,
        block_refs_by_serial=refs_by_serial,
        source_generation=plan.source_generation,
        canonical_route_evidence=original.route_evidence,
        selected_route_proof_ids=(original.route_evidence.route_proofs[0].proof_id,),
        exact_state_effect_exclusions=(),
        dispatcher_entry_serial=1,
        dispatcher_member_serials=(1,),
        authoritative_handler_serials=(3,),
        state_identity=original.plan_inputs.state_identity,
        use_def_witness=original.use_def_witness,
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
    assert type(validate_proposal(plan, proposal)) is ProposalAccepted

    prepared = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    ).prepared
    assert prepared is not None
    case = prepared.projected_case
    structural_subjects = {
        cell.key.subject for cell in case.obligation_index.cells
        if cell.key.dimension is model.SafetyDimension.STRUCTURAL_ACCOUNTING
    }
    assert structural_subjects
    assert all(
        subject.role is model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK
        for subject in structural_subjects
    )
    assert any(
        subject.role is model.SemanticSubjectRole.SOURCE_ENTRY
        and subject.block_ref == refs_by_serial[0]
        for subject in case.subjects
    )
    assert any(
        subject.role is model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE
        and subject.block_ref == refs_by_serial[0]
        for subject in case.subjects
    )
    value_flow = next(
        subject for subject in case.subjects
        if subject.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW
    )
    states = {
        cell.key.dimension: cell.state
        for cell in case.obligation_index.cells
        if cell.key.subject == value_flow
    }
    assert states[model.SafetyDimension.IDENTITY_BINDING] is model.ObligationState.SATISFIED
    assert states[model.SafetyDimension.USE_DEF_INTEGRITY] is model.ObligationState.SATISFIED
    justification = next(
        item for item in case.justifications
        if item.conclusion.subject == value_flow
        and item.rule is model.UnflattenJustificationRule.UNIQUE_PHASE_BINDING
    )
    evidence_by_id = {item.evidence_id: item for item in case.evidence}
    owner_bindings = tuple(
        evidence_by_id[premise].payload.binding
        for premise in justification.premise_ids
    )
    assert tuple(
        (binding.subject.kind, binding.subject.role, binding.subject.block_ref)
        for binding in owner_bindings
    ) == ((
        model.SemanticSubjectKind.BLOCK,
        model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        refs_by_serial[0],
    ),)


def test_direct_local_alias_prepare_uses_the_sealed_owner_scalarization():
    """A sealed STORE-to-MOV transition preserves its owning block."""
    from d810.transforms.unflatten_authority import transaction_api

    fixture, source, plan, projected, gates = _c1_direct_preparation_case(
        local_alias=True,
    )

    result = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    )

    assert type(result).__name__ == "UnflattenAuthorityPreparationAccepted"


def _c2_exact_direct_preparation_case():
    """One proposal-valid Direct CALL loss with a real loss-ledger row."""
    from d810.analyses.control_flow.graph_checks import (
        check_effectful_reachability_preserved,
        check_entry_reachability_not_collapsed,
        check_terminal_reachability_preserved,
    )
    from d810.transforms.edit_simulator import project_post_state
    from d810.transforms.unflatten_authority.gates import GenericCfgGateBundle
    from d810.transforms.unflatten_authority.proposal import (
        ProposalAccepted,
        canonical_redirect_manifest,
        validate_proposal,
    )
    from . import test_bind

    raw = test_bind._task_15_exact_direct_case("call", include_source_context=True)
    plan, attempt_id, source = raw[1], raw[5], raw[6]
    plan = replace(plan, snapshot_id=authority_id(("c2-exact-direct", plan.plan_id)))
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
    assert type(validate_proposal(plan, proposal)) is ProposalAccepted
    projected = project_post_state(source, plan)
    raw_effect = check_effectful_reachability_preserved(source, post_cfg=projected)
    gates = GenericCfgGateBundle(
        check_entry_reachability_not_collapsed(source, post_cfg=projected),
        raw_effect,
        raw_effect,
        check_terminal_reachability_preserved(source, post_cfg=projected),
    )
    return source, plan, projected, attempt_id, gates


def test_direct_observed_validation_retains_one_exact_observed_authority_result():
    """A Direct observed pass closes the bound/projected occurrences once."""
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.hexrays.mutation.patch_binding import bind_patch_plan
    from d810.transforms.unflatten_authority import transaction_api

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

    observed = transaction_api.revalidate_observed_unflatten_authority(
        authority=binding.authority,
        observed=projected,
        observed_generation=fixture.attempt_id.generation,
        generic_gates=gates,
        observed_patch_binding=observed_patch_binding_for_test(binding.authority),
    )

    accepted = observed.observed_acceptance
    assert accepted.bound_authority is binding.authority
    assert accepted.projected_ledger is preparation.prepared.projected_loss_ledger
    assert accepted.observed_case is observed.safety_case
    assert accepted.observed_ledger.case is accepted.observed_case
    assert accepted.delta.projected_ledger_id == accepted.projected_ledger.ledger_id
    assert accepted.delta.observed_ledger_id == accepted.observed_ledger.ledger_id


@pytest.mark.parametrize(
    ("failure_stage", "error_type"),
    (
        ("bound_authority_validation", TypeError),
        ("bound_patch_plan_validation", ValueError),
        ("observed_helper_bindings", AttributeError),
        ("observed_inventory", ValueError),
        ("observed_input_derivation", TypeError),
        ("authority_type", TypeError),
    ),
)
def test_observed_live_binding_failure_logs_its_stage_and_cause(
    monkeypatch, caplog, failure_stage, error_type,
):
    """A live binding failure remains fail-closed with an actionable warning."""
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.hexrays.mutation.patch_binding import bind_patch_plan
    from d810.transforms.unflatten_authority import model, transaction_api

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
    observed_identity = {}

    def raise_live_binding_failure(*_args, **_kwargs):
        if failure_stage == "observed_input_derivation":
            observed_identity["candidate_fingerprint"] = _args[1].graph_fingerprint
        raise error_type("controlled observed live binding failure")

    if failure_stage == "bound_authority_validation":
        monkeypatch.setattr(
            model.BoundUnflattenAuthority,
            "__post_init__",
            raise_live_binding_failure,
        )
    elif failure_stage == "bound_patch_plan_validation":
        monkeypatch.setattr(
            transaction_api,
            "revalidate_bound_patch_plan_against_prepared",
            raise_live_binding_failure,
        )
    elif failure_stage == "observed_helper_bindings":
        monkeypatch.setattr(
            transaction_api,
            "_observed_helper_serial_bindings",
            raise_live_binding_failure,
        )
    elif failure_stage == "observed_inventory":
        monkeypatch.setattr(
            transaction_api,
            "_build_semantic_graph_inventory",
            raise_live_binding_failure,
        )
    elif failure_stage == "observed_input_derivation":
        monkeypatch.setattr(
            transaction_api,
            "_derive_inputs",
            raise_live_binding_failure,
        )

    authority = object() if failure_stage == "authority_type" else binding.authority
    expected_message = (
        "expected BoundUnflattenAuthority, got object"
        if failure_stage == "authority_type"
        else "controlled observed live binding failure"
    )

    with caplog.at_level("WARNING", logger="d810.transforms.unflatten_authority.transaction_api"):
        verdict = transaction_api.revalidate_observed_unflatten_authority(
            authority=authority,
            observed=projected,
            observed_generation=fixture.attempt_id.generation,
            generic_gates=gates,
            observed_patch_binding=observed_patch_binding_for_test(binding.authority),
        )

    assert verdict.reason is model.UnflattenAuthorityReason.LIVE_BINDING_FAILED
    if failure_stage in {
        "bound_authority_validation",
        "bound_patch_plan_validation",
        "observed_helper_bindings",
        "authority_type",
    }:
        assert verdict.authority_id is None
        assert verdict.binding_id is None
        assert verdict.candidate_fingerprint == (
            transaction_api._unavailable_candidate_fingerprint(
                "observed-live-binding"
            )
        )
    elif failure_stage == "observed_inventory":
        assert verdict.authority_id == binding.authority.prepared.authority_id
        assert verdict.binding_id == binding.authority.binding_id
        assert verdict.candidate_fingerprint == (
            transaction_api._unavailable_candidate_fingerprint(
                "observed-inventory"
            )
        )
    else:
        assert verdict.authority_id == binding.authority.prepared.authority_id
        assert verdict.binding_id == binding.authority.binding_id
        assert verdict.candidate_fingerprint == observed_identity["candidate_fingerprint"]
    assert any(
        f"stage={failure_stage}" in record.getMessage()
        and f"cause={error_type.__name__}: {expected_message}"
        in record.getMessage()
        for record in caplog.records
    )


def test_observed_live_binding_failure_truncates_untrusted_error_message(
    caplog,
) -> None:
    """Observed failure diagnostics bound an exception's rendered payload."""
    from d810.transforms.unflatten_authority import model, transaction_api

    with caplog.at_level(
        "WARNING", logger="d810.transforms.unflatten_authority.transaction_api"
    ):
        verdict = transaction_api._observed_live_binding_failure(
            "bounded_message", ValueError("x" * 513),
        )

    assert verdict.reason is model.UnflattenAuthorityReason.LIVE_BINDING_FAILED
    assert verdict.authority_id is None
    assert verdict.binding_id is None
    assert verdict.candidate_fingerprint == (
        transaction_api._unavailable_candidate_fingerprint(
            "observed-live-binding"
        )
    )
    (record,) = tuple(
        record
        for record in caplog.records
        if "stage=bounded_message" in record.getMessage()
    )
    rendered_message = record.getMessage().split("cause=ValueError: ", 1)[1]
    assert rendered_message == ("x" * 509) + "..."
    assert len(rendered_message) == 512


def test_observed_validation_does_not_recursively_replay_sealed_projected_case(
    monkeypatch,
):
    """Observation validates its new case, not the already-sealed projected tree."""
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.hexrays.mutation.patch_binding import bind_patch_plan
    from d810.transforms.unflatten_authority import model, transaction_api

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    preparation = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    )
    prepared = preparation.prepared
    assert prepared is not None
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
    authority = transaction_api.bind_prepared_unflatten_authority(
        prepared=prepared,
        patch_binding=bind_patch_plan(plan, index, fixture.attempt_id).bound_plan,
    ).authority
    assert authority is not None

    original = model.SemanticSafetyCase.__post_init__
    projected_replays = 0
    observed_validations = 0

    def counted(case):
        nonlocal projected_replays, observed_validations
        if case is prepared.projected_case:
            projected_replays += 1
        else:
            observed_validations += 1
        return original(case)

    monkeypatch.setattr(model.SemanticSafetyCase, "__post_init__", counted)
    observed = transaction_api.revalidate_observed_unflatten_authority(
        authority=authority,
        observed=projected,
        observed_generation=fixture.attempt_id.generation,
        generic_gates=gates,
        observed_patch_binding=observed_patch_binding_for_test(authority),
    )

    assert observed.accepted
    assert projected_replays == 0
    # One construction validation and one unified ledger-gate validation.
    # Case-ID sealing and row construction compose exact sealed occurrences;
    # neither may replay the complete observed tree.
    assert observed_validations == 2


def test_compact_case_boundary_revalidates_every_child_seal() -> None:
    """A stale child ID cannot hide mutated content behind the compact case ID."""
    from d810.transforms.unflatten_authority import model, transaction_api

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    result = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    )
    case = result.prepared.projected_case

    def stale(record: object, **changes: object):
        forged = object.__new__(type(record))
        for record_field in fields(record):
            object.__setattr__(
                forged, record_field.name,
                changes.get(record_field.name, getattr(record, record_field.name)),
            )
        return forged

    def forged_case(**changes: object):
        return stale(case, **changes)

    claim = case.claims[0]
    attacks = [
        forged_case(claims=(stale(
            claim, kind=model.UnflattenClaimKind.EXACT_INFEASIBLE_EFFECT,
        ),)),
    ]

    generic = next(
        item for item in case.evidence
        if type(item.payload) is model.GenericCfgGateEvidencePayload
    )
    generic_payload = stale(generic.payload, reason_code="")
    attacks.append(forged_case(evidence=tuple(
        stale(item, payload=generic_payload) if item is generic else item
        for item in case.evidence
    )))

    reachability = next(
        item for item in case.evidence
        if type(item.payload) is model.ReachabilityEvidencePayload
    )
    reachability_payload = stale(
        reachability.payload,
        path_subject_ids=reachability.payload.path_subject_ids
        + (helper_authority_id("stale-path"),),
    )
    attacks.append(forged_case(evidence=tuple(
        stale(item, payload=reachability_payload)
        if item is reachability else item
        for item in case.evidence
    )))

    phase_binding = next(
        item for item in case.evidence
        if type(item.payload) is model.PhaseBindingEvidencePayload
    )
    wrong_role = next(
        role for role in model.SemanticSubjectRole
        if role is not phase_binding.payload.binding.role
    )
    binding_payload = stale(
        phase_binding.payload,
        binding=stale(phase_binding.payload.binding, role=wrong_role),
    )
    attacks.append(forged_case(evidence=tuple(
        stale(item, payload=binding_payload)
        if item is phase_binding else item
        for item in case.evidence
    )))

    lineage = next(
        item for item in case.evidence
        if type(item.payload) is model.StructuralLineageEvidencePayload
    )
    lineage_payload = stale(
        lineage.payload,
        reciprocal_native_origin_eas=
        lineage.payload.reciprocal_native_origin_eas + (0x7FFF0000,),
    )
    attacks.append(forged_case(evidence=tuple(
        stale(item, payload=lineage_payload) if item is lineage else item
        for item in case.evidence
    )))

    class DigestSubclass(str):
        pass

    justification = case.justifications[0]
    subclass_premises = tuple(
        DigestSubclass(value) for value in justification.premise_ids
    )
    attacks.append(forged_case(justifications=tuple(
        stale(item, premise_ids=subclass_premises)
        if item is justification else item
        for item in case.justifications
    )))

    from d810.transforms.unflatten_authority import ids as authority_ids

    # ``stale`` copies the *original* case's identity onto a body that no
    # longer produces it.  That is a state no production path can reach any
    # more -- ``case_id`` is not a constructor input (ticket d81-cxzv) -- so
    # it is built here the only way a defect could: by writing the slots.
    structural = []
    for index, forged in enumerate(attacks):
        assert forged.case_id == case.case_id
        try:
            model.SemanticSafetyCase.__post_init__(forged)
        except (TypeError, ValueError):
            structural.append(index)

    # Three of the six forgeries are caught by a structural check in
    # __post_init__ and stay caught.  The other three were caught *only* by
    # the construction-time case-ID recheck, which is gone; they are caught at
    # the canonical boundary instead, which is where a forged record has to
    # pass to reach persistence, replay or a receipt.
    assert structural == [0, 1, 3], structural
    for index in (2, 4, 5):
        with pytest.raises((TypeError, ValueError)):
            authority_ids.validate_canonical_roundtrip(
                attacks[index], model.SemanticSafetyCase,
            )


def test_compact_case_boundary_rejects_equal_reminted_detached_results() -> None:
    """Detached authority requires the binder-owned occurrence, not equal data."""
    from d810.transforms.unflatten_authority import bind, model, transaction_api
    from d810.transforms.unflatten_authority.ids import case_id
    from .test_bind import _detached_binding_fixture

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    prepared = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    ).prepared
    case = prepared.projected_case
    claim, detached_source, detached_candidate, corridor = _detached_binding_fixture()
    detached = bind.bind_detached_dead_handler_component_claim(
        claim=claim,
        source_inventory=detached_source,
        candidate_inventory=detached_candidate,
        corridor_result=corridor,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    reminted_source = replace(detached.source_result)
    reminted_phase = replace(detached.phase_result)
    assert reminted_source == detached.source_result
    assert reminted_source is not detached.source_result
    assert reminted_phase == detached.phase_result
    assert reminted_phase is not detached.phase_result

    for field_name, reminted in (
        ("detached_dead_handler_component_source_results", reminted_source),
        ("detached_dead_handler_component_phase_results", reminted_phase),
    ):
        forged = object.__new__(model.SemanticSafetyCase)
        for record_field in fields(case):
            object.__setattr__(
                forged,
                record_field.name,
                (reminted,) if record_field.name == field_name
                else getattr(case, record_field.name),
            )
        object.__setattr__(forged, "case_id", case_id(forged))
        with pytest.raises(ValueError, match="not minted by the transaction binder"):
            model.SemanticSafetyCase.__post_init__(forged)


def test_direct_observed_route_rewrite_preserves_anchor_subset_structurally():
    """A sealed route rewrite owns live removal of its replaced transfer origin."""
    from d810.analyses.control_flow.graph_checks import (
        check_effectful_reachability_preserved,
        check_entry_reachability_not_collapsed,
        check_terminal_reachability_preserved,
    )
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.hexrays.mutation.patch_binding import bind_patch_plan
    from d810.ir.flowgraph import FlowGraph
    from d810.transforms.unflatten_authority import model, transaction_api
    from d810.transforms.unflatten_authority.gates import GenericCfgGateBundle

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
    authority = transaction_api.bind_prepared_unflatten_authority(
        prepared=preparation.prepared,
        patch_binding=bind_patch_plan(plan, index, fixture.attempt_id).bound_plan,
    ).authority
    assert authority is not None

    owner = projected.blocks[0]
    synthetic_goto = replace(
        owner.insn_snapshots[-1],
        ea=0x6000,
        native_ea=0x6000,
        l=replace(owner.insn_snapshots[-1].l, block_ref=owner.succs[0]),
    )
    observed = FlowGraph(
        {
            **projected.blocks,
            0: replace(
                owner,
                insn_snapshots=(owner.insn_snapshots[0], synthetic_goto),
            ),
        },
        projected.entry_serial,
        projected.func_ea,
    )
    observed_gates = GenericCfgGateBundle(
        check_entry_reachability_not_collapsed(source, post_cfg=observed),
        check_effectful_reachability_preserved(source, post_cfg=observed),
        check_effectful_reachability_preserved(source, post_cfg=observed),
        check_terminal_reachability_preserved(source, post_cfg=observed),
    )

    verdict = transaction_api.revalidate_observed_unflatten_authority(
        authority=authority,
        observed=observed,
        observed_generation=fixture.attempt_id.generation,
        generic_gates=observed_gates,
        observed_patch_binding=observed_patch_binding_for_test(authority),
    )

    assert verdict.accepted, verdict.failed_obligations
    assert verdict.safety_case is not None
    owner_subject = next(
        subject for subject in verdict.safety_case.subjects
        if subject.role is model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK
        and subject.block_ref == plan.steps[0].from_serial
    )
    structural = next(
        cell for cell in verdict.safety_case.obligation_index.cells
        if cell.key.subject == owner_subject
        and cell.key.dimension is model.SafetyDimension.STRUCTURAL_ACCOUNTING
    )
    assert structural.state is model.ObligationState.SATISFIED


def test_direct_observed_validation_uses_one_inventory_without_reassessment(monkeypatch):
    """Breaking the old assessor cannot affect a bound Direct observation."""
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.hexrays.mutation.patch_binding import bind_patch_plan
    from d810.transforms.unflatten_authority import transaction_api

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    prepared = transaction_api.prepare_unflatten_authority(
        source=source, projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan, attempt_id=fixture.attempt_id, generic_gates=gates,
    ).prepared
    assert prepared is not None
    refs = tuple(plan.source_coordinates)
    index = MbaBlockIdentityIndex.from_bindings(
        generation=fixture.attempt_id.generation, maturity=None,
        native_key=refs[0][0].identity.native_key, snapshot_id=plan.snapshot_id,
        session_id=fixture.attempt_id.session_id,
        bindings=tuple((ref.identity, serial) for ref, serial in refs),
    )
    index.begin_transaction(fixture.attempt_id, quantity=len(source.blocks))
    authority = transaction_api.bind_prepared_unflatten_authority(
        prepared=prepared,
        patch_binding=bind_patch_plan(plan, index, fixture.attempt_id).bound_plan,
    ).authority
    assert authority is not None
    original_inventory = transaction_api._build_semantic_graph_inventory
    observed_inventory_calls = []

    def inventory(*args, **kwargs):
        if kwargs.get("phase").value == "observed_post_apply":
            observed_inventory_calls.append(args)
        return original_inventory(*args, **kwargs)

    monkeypatch.setattr(transaction_api, "_build_semantic_graph_inventory", inventory)
    assert not hasattr(transaction_api, "route_model")
    assert not hasattr(transaction_api, "assess_canonical_route")
    observed = transaction_api.revalidate_observed_unflatten_authority(
        authority=authority, observed=projected,
        observed_generation=fixture.attempt_id.generation, generic_gates=gates,
        observed_patch_binding=observed_patch_binding_for_test(authority),
    )
    assert observed.accepted
    assert len(observed_inventory_calls) == 1


def test_direct_observed_validation_never_replays_preparation_claim_derivation(monkeypatch):
    """Observed authority consumes sealed preparation facts, never planner replay."""
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.hexrays.mutation.patch_binding import bind_patch_plan
    from d810.transforms.unflatten_authority import transaction_api

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    prepared = transaction_api.prepare_unflatten_authority(
        source=source, projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan, attempt_id=fixture.attempt_id, generic_gates=gates,
    ).prepared
    assert prepared is not None
    refs = tuple(plan.source_coordinates)
    index = MbaBlockIdentityIndex.from_bindings(
        generation=fixture.attempt_id.generation, maturity=None,
        native_key=refs[0][0].identity.native_key, snapshot_id=plan.snapshot_id,
        session_id=fixture.attempt_id.session_id,
        bindings=tuple((ref.identity, serial) for ref, serial in refs),
    )
    index.begin_transaction(fixture.attempt_id, quantity=len(source.blocks))
    authority = transaction_api.bind_prepared_unflatten_authority(
        prepared=prepared,
        patch_binding=bind_patch_plan(plan, index, fixture.attempt_id).bound_plan,
    ).authority
    assert authority is not None

    def forbidden(*_args, **_kwargs):
        raise AssertionError("observed authority replayed preparation work")

    monkeypatch.setattr(transaction_api, "_derive_transaction_facts", forbidden)
    monkeypatch.setattr(transaction_api, "_derive_patch_lineage_relations", forbidden)
    monkeypatch.setattr(
        transaction_api.authority_bind,
        "bind_retired_dispatcher_infrastructure_claim",
        forbidden,
    )
    monkeypatch.setattr(
        transaction_api.authority_bind, "bind_terminal_cycle_break_claim", forbidden,
    )
    monkeypatch.setattr(
        transaction_api.authority_bind, "bind_corridor_coverage_forecast", forbidden,
    )

    observed = transaction_api.revalidate_observed_unflatten_authority(
        authority=authority, observed=projected,
        observed_generation=fixture.attempt_id.generation, generic_gates=gates,
        observed_patch_binding=observed_patch_binding_for_test(authority),
    )
    assert observed.accepted


def test_observed_phase_adapters_reclassify_prepared_corridor_retirement_and_terminal_domains():
    """Observed adapters retain each exact prepared authority domain."""
    from d810.transforms.unflatten_authority import bind, model
    from . import test_bind

    corridor_proposal, corridor_source, corridor_projected = test_bind._corridor_inventories()
    corridor_parent = bind.bind_corridor_coverage_forecast(
        proposal=corridor_proposal, source_inventory=corridor_source,
        candidate_inventory=corridor_projected,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    corridor_observed_inventory = test_bind._inventory_rephase(
        corridor_projected,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        fingerprint=authority_id("c3-observed-corridor"), generation=4,
    )
    corridor_observed = bind.revalidate_observed_corridor_coverage(
        projected_result=corridor_parent, proposal=corridor_proposal,
        claims=corridor_proposal.claims, source_inventory=corridor_source,
        observed_inventory=corridor_observed_inventory,
    )
    assert corridor_observed is not None
    assert corridor_parent.phase is model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
    assert corridor_observed.phase is model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
    assert corridor_observed.forecast_id == corridor_parent.forecast_id

    retirement_proposal, retirement_claim, retirement_source, retirement_projected = test_bind._retirement_inventories()
    retirement_parent = bind.bind_retired_dispatcher_infrastructure_claim(
        claim=retirement_claim, proposal=retirement_proposal,
        source_inventory=retirement_source, projected_inventory=retirement_projected,
    ).phase_result
    retirement_observed_inventory = test_bind._inventory_rephase(
        retirement_projected,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        fingerprint=authority_id("c3-observed-retirement"), generation=4,
    )
    retirement_observed = bind.revalidate_observed_retired_dispatcher_infrastructure(
        projected_result=retirement_parent, claim=retirement_claim,
        proposal=retirement_proposal, source_inventory=retirement_source,
        observed_inventory=retirement_observed_inventory,
    )
    assert retirement_observed.phase is model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
    assert retirement_observed.claim_id == retirement_parent.claim_id

    terminal_proposal, terminal_claim, _fixture, terminal_source, terminal_projected, _residual = test_bind._terminal_cycle_inventory_fixture()
    terminal_parent = bind.bind_terminal_cycle_break_claim(
        claim=terminal_claim, proposal=terminal_proposal,
        source_inventory=terminal_source, candidate_inventory=terminal_projected,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    ).phase_result
    terminal_observed_inventory = test_bind._inventory_rephase(
        terminal_projected,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        fingerprint=authority_id("c3-observed-terminal"), generation=4,
    )
    terminal_observed = bind.revalidate_observed_terminal_cycle_break(
        projected_result=terminal_parent, claim=terminal_claim,
        proposal=terminal_proposal, source_inventory=terminal_source,
        observed_inventory=terminal_observed_inventory,
    )
    assert terminal_observed.phase is model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
    assert terminal_observed.claim_id == terminal_parent.claim_id


def test_observed_phase_adapters_are_carried_into_the_semantic_case():
    """The observed case consumes the adapter results, not empty phase facts."""
    from d810.transforms.unflatten_authority import model, transaction_api
    from d810.transforms.unflatten_authority.evaluate import build_semantic_case
    from . import test_bind

    source, plan, _projected, gates, prepared_inputs = _full_corridor_inputs()
    observed_inventory = test_bind._inventory_rephase(
        prepared_inputs.candidate_inventory,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        fingerprint=authority_id("c3-case-corridor-retirement"), generation=4,
    )
    observed_inputs = transaction_api._derive_inputs(
        prepared_inputs.source_inventory, observed_inventory, plan,
        prepared_inputs.proposal, gates,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        candidate_generation=4,
        phase_build_metrics=model.PhaseBuildMetrics(
            model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY, 0, 1, 0,
        ),
        preparation_metrics=prepared_inputs.preparation_metrics,
        source_route_authority=prepared_inputs.source_route_authority,
        projected_route_realization=prepared_inputs.projected_route_realization,
        preparation_inputs=prepared_inputs,
    )
    corridor = observed_inputs.corridor_coverage_phase_result
    retirement = observed_inputs.retirement_phase_result
    assert corridor is not None and retirement is not None
    assert corridor.phase is model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
    assert retirement.phase is model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
    corridor_case = build_semantic_case(
        authority_id=authority_id("c3-case-corridor-retirement"),
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        inputs=observed_inputs,
    )
    assert corridor_case.corridor_coverage_phase_result is corridor
    assert corridor_case.retirement_phase_result is retirement

    terminal_proposal, _terminal_claim, terminal_inputs, terminal_source, terminal_projected, _residual = test_bind._terminal_cycle_derived_inputs()
    terminal_observed_inventory = test_bind._inventory_rephase(
        terminal_projected,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        fingerprint=authority_id("c3-case-terminal"), generation=4,
    )
    terminal_plan = PatchPlan(
        plan_id=terminal_proposal.plan_id,
        snapshot_id=authority_id("terminal-cycle-snapshot"),
        source_generation=terminal_source.generation,
        steps=tuple(
            PatchRedirectBranch(
                owner,
                block_ref("b1") if owner == block_ref("b0") else block_ref("b0"),
                block_ref("b2"),
            )
            for owner in terminal_proposal.use_def_witness.redirect_owner_refs
        ),
        source_coordinates=tuple(
            (block.block_ref, block.serial)
            for block in terminal_source.blocks
            if block.block_ref is not None
        ),
        unflatten_proposal=terminal_proposal,
    )
    terminal_observed_inputs = transaction_api._derive_inputs(
        terminal_source, terminal_observed_inventory,
        terminal_plan, terminal_proposal, None,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        candidate_generation=4,
        phase_build_metrics=model.PhaseBuildMetrics(
            model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY, 0, 1, 0,
        ),
        preparation_metrics=terminal_inputs.preparation_metrics,
        source_route_authority=terminal_inputs.source_route_authority,
        projected_route_realization=terminal_inputs.projected_route_realization,
        preparation_inputs=terminal_inputs,
    )
    assert len(terminal_observed_inputs.terminal_cycle_phase_results) == 1
    assert (
        terminal_observed_inputs.terminal_cycle_phase_results[0].phase
        is model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
    )
    terminal_case = build_semantic_case(
        authority_id=authority_id("c3-case-terminal"),
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        inputs=terminal_observed_inputs,
    )
    assert (
        terminal_case.terminal_cycle_phase_results[0]
        is terminal_observed_inputs.terminal_cycle_phase_results[0]
    )
    observed_terminal = terminal_observed_inputs.terminal_cycle_phase_results[0]
    assert replace(
        terminal_observed_inputs,
        terminal_cycle_phase_results=(observed_terminal,),
    )
    with pytest.raises(ValueError, match="not minted by the transaction binder"):
        replace(
            terminal_observed_inputs,
            terminal_cycle_phase_results=(replace(observed_terminal),),
        )
    with pytest.raises(ValueError, match="not minted by the transaction binder"):
        replace(
            terminal_case,
            terminal_cycle_phase_results=(replace(observed_terminal),),
        )


def test_direct_observed_gate_consumes_one_exact_ledger_once(monkeypatch):
    """Observed validation consumes its accepted ledger occurrence once."""
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.hexrays.mutation.patch_binding import bind_patch_plan
    from d810.transforms.unflatten_authority import gates, transaction_api

    fixture, source, plan, projected, generic_gates = _c1_direct_preparation_case()
    prepared = transaction_api.prepare_unflatten_authority(
        source=source, projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan, attempt_id=fixture.attempt_id, generic_gates=generic_gates,
    ).prepared
    assert prepared is not None
    refs = tuple(plan.source_coordinates)
    index = MbaBlockIdentityIndex.from_bindings(
        generation=fixture.attempt_id.generation, maturity=None,
        native_key=refs[0][0].identity.native_key, snapshot_id=plan.snapshot_id,
        session_id=fixture.attempt_id.session_id,
        bindings=tuple((ref.identity, serial) for ref, serial in refs),
    )
    index.begin_transaction(fixture.attempt_id, quantity=len(source.blocks))
    authority = transaction_api.bind_prepared_unflatten_authority(
        prepared=prepared,
        patch_binding=bind_patch_plan(plan, index, fixture.attempt_id).bound_plan,
    ).authority
    assert authority is not None
    seen = []
    original = gates.validate_projected_loss_ledger
    def wrapped(ledger, case):
        seen.append(ledger)
        return original(ledger, case)
    monkeypatch.setattr(gates, "validate_projected_loss_ledger", wrapped)
    observed = transaction_api.revalidate_observed_unflatten_authority(
        authority=authority, observed=projected,
        observed_generation=fixture.attempt_id.generation, generic_gates=generic_gates,
        observed_patch_binding=observed_patch_binding_for_test(authority),
    )
    assert observed.accepted
    assert seen == [observed.observed_acceptance.observed_ledger]


def test_transaction_phases_own_distinct_closed_canonical_sessions(monkeypatch):
    """Preparation seals its inventories once; observation starts fresh."""

    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.hexrays.mutation.patch_binding import bind_patch_plan
    from d810.transforms.unflatten_authority.canonical_session import (
        CanonicalSessionPhase,
        active_canonical_session,
    )

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    seen = []
    builder = transaction_api._build_semantic_graph_inventory

    def capture_session(*args, **kwargs):
        seen.append((kwargs["phase"], active_canonical_session()))
        return builder(*args, **kwargs)

    monkeypatch.setattr(
        transaction_api, "_build_semantic_graph_inventory", capture_session,
    )
    prepared = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    ).prepared
    assert prepared is not None
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
    authority = transaction_api.bind_prepared_unflatten_authority(
        prepared=prepared,
        patch_binding=bind_patch_plan(plan, index, fixture.attempt_id).bound_plan,
    ).authority
    assert authority is not None
    observed = transaction_api.revalidate_observed_unflatten_authority(
        authority=authority,
        observed=projected,
        observed_generation=fixture.attempt_id.generation,
        generic_gates=gates,
        observed_patch_binding=observed_patch_binding_for_test(authority),
    )
    assert observed.accepted

    assert [phase for phase, _session in seen] == [
        model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
    ]
    projected_session = seen[0][1]
    assert projected_session is seen[1][1]
    assert projected_session.phase is CanonicalSessionPhase.PROJECTED_PREPARATION
    # Each constructor still computes the supplied digest plus the strict
    # public dataclass digest check.  The session removes later consumers'
    # replays; internal single-digest minting remains a separate plan step.
    assert projected_session.metrics.inventory_validations == 4
    observed_session = seen[2][1]
    assert observed_session is not projected_session
    assert observed_session.phase is CanonicalSessionPhase.OBSERVED_REVALIDATION
    assert projected_session.closed and observed_session.closed
    assert active_canonical_session() is None


def _prepared_lowered_conditional_observed_case(*, unrelated_same_owner_site=False):
    """Prepare the RF-1 fixture through the public observed boundary once."""
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.hexrays.mutation.patch_binding import bind_patch_plan
    from d810.ir.flowgraph import BlockKind
    from d810.analyses.control_flow.graph_checks import (
        check_effectful_reachability_preserved,
        check_entry_reachability_not_collapsed,
        check_terminal_reachability_preserved,
    )
    from d810.transforms.unflatten_authority import transaction_api, model
    from . import test_bind

    fixture = test_bind._task_15_lowered_conditional_vertical_case(
        include_graph=True,
        separate_terminal=True,
        unrelated_same_owner_site=unrelated_same_owner_site,
    )
    source, plan, projected, attempt = (
        fixture.source_graph, fixture.plan, fixture.projected_graph, fixture.attempt_id,
    )
    from d810.transforms.plan import PatchRedirectGoto
    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest
    plan = replace(plan, snapshot_id=authority_id(("c3-lowered", plan.plan_id)))
    refs_by_serial = dict((serial, ref) for ref, serial in plan.source_coordinates)
    plan = replace(plan, steps=(*plan.steps, PatchRedirectGoto(
        refs_by_serial[0], refs_by_serial[1], refs_by_serial[1],
    )))
    manifest = canonical_redirect_manifest(plan)
    plan = replace(plan, unflatten_proposal=replace(plan.unflatten_proposal, use_def_witness=replace(plan.unflatten_proposal.use_def_witness, redirect_owner_refs=manifest.owner_refs, redirect_digest=manifest.digest)))
    raw = check_effectful_reachability_preserved(source, post_cfg=projected)
    gates = transaction_api.GenericCfgGateBundle(
        check_entry_reachability_not_collapsed(source, post_cfg=projected), raw, raw,
        check_terminal_reachability_preserved(source, post_cfg=projected),
    )
    prepared = transaction_api.prepare_unflatten_authority(
        source=source, projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan, attempt_id=attempt, generic_gates=gates,
    ).prepared
    assert prepared is not None
    refs = tuple(plan.source_coordinates)
    index = MbaBlockIdentityIndex.from_bindings(
        generation=attempt.generation, maturity=None, native_key=refs[0][0].identity.native_key,
        snapshot_id=plan.snapshot_id, session_id=attempt.session_id,
        bindings=tuple((ref.identity, serial) for ref, serial in refs),
    )
    index.begin_transaction(attempt, quantity=len(source.blocks))
    authority = transaction_api.bind_prepared_unflatten_authority(
        prepared=prepared, patch_binding=bind_patch_plan(plan, index, attempt).bound_plan,
    ).authority
    assert authority is not None
    return source, projected, attempt, authority


def _replace_observed_block_without_eas(
    observed, serial, eas, *, kind=None, retain_native_anchor=False,
):
    retained = tuple(
        item for item in observed.blocks[serial].insn_snapshots
        if item.ea not in eas
    )
    if retain_native_anchor:
        retained = (
            replace(retained[0], native_ea=observed.blocks[serial].start_ea),
            *retained[1:],
        )
    return replace(observed, blocks={
        **observed.blocks,
        serial: replace(observed.blocks[serial], insn_snapshots=retained,
                   tail_opcode=retained[-1].opcode,
                   raw_tail_opcode=retained[-1].raw_opcode, tail_kind=retained[-1].kind,
                   kind=observed.blocks[serial].kind if kind is None else kind),
    })


def _observed_gates(source, observed):
    from d810.analyses.control_flow.graph_checks import (
        check_effectful_reachability_preserved,
        check_entry_reachability_not_collapsed,
        check_terminal_reachability_preserved,
    )
    from d810.transforms.unflatten_authority import transaction_api

    observed_raw = check_effectful_reachability_preserved(source, post_cfg=observed)
    return transaction_api.GenericCfgGateBundle(
        check_entry_reachability_not_collapsed(source, post_cfg=observed), observed_raw,
        observed_raw, check_terminal_reachability_preserved(source, post_cfg=observed),
    )


def _lowered_conditional_observed_helper_case(*, valid_helper: bool):
    """Materialize RF-1's portable false arm through one backend helper.

    The projected RF-1 relation is the portable ``F -> {false, true}``
    conditional.  Hex-Rays may instead retain the false arm through a fresh,
    ownerless helper: ``F -> {H, true}``, ``H -> false``.  This helper has no
    source identity, so the observed transaction must accept it only through
    the sealed lower-conditional realization and its exact patch fact.
    """
    from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot, MopSnapshot, OperandKind

    source, projected, attempt, authority = _prepared_lowered_conditional_observed_case()
    # Native insertion shifts every following serial.  Model that real backend
    # coordinate change rather than using a non-adjacent synthetic helper.
    renumber = {0: 0, 1: 2, 2: 3, 3: 4, 4: 5}
    helper_serial, feeder_serial, false_serial, true_serial = 1, 0, 4, 3
    badaddr = 0xFFFFFFFFFFFFFFFF
    helper_target = false_serial if valid_helper else 4
    helper = BlockSnapshot(
        helper_serial,
        0,
        (false_serial,),
        (feeder_serial,),
        0,
        badaddr,
        (
            InsnSnapshot(
                55,
                badaddr,
                (),
                d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=helper_target),
                kind=InsnKind.GOTO,
                raw_opcode=55 if valid_helper else 0,
            ),
        ),
        tail_opcode=55,
        kind=BlockKind.ONE_WAY,
        tail_kind=InsnKind.GOTO,
        raw_tail_opcode=55 if valid_helper else 0,
    )
    def remap_operand(operand):
        if operand is None or operand.kind is not OperandKind.BLOCK:
            return operand
        return replace(operand, block_ref=renumber.get(operand.block_ref, operand.block_ref))

    remapped = {
        renumber[serial]: replace(
            block,
            serial=renumber[serial],
            succs=tuple(renumber[item] for item in block.succs),
            preds=tuple(renumber[item] for item in block.preds),
            insn_snapshots=tuple(replace(
                item,
                l=remap_operand(item.l), r=remap_operand(item.r),
                d=remap_operand(item.d),
            ) for item in block.insn_snapshots),
        )
        for serial, block in projected.blocks.items()
    }
    observed = FlowGraph(
        {
            **remapped,
            helper_serial: helper,
            feeder_serial: replace(
                remapped[feeder_serial],
                succs=(helper_serial, true_serial),
            ),
            false_serial: replace(
                remapped[false_serial],
                preds=(helper_serial, renumber[1]),
            ),
        },
        projected.entry_serial,
        projected.func_ea,
        metadata=projected.metadata,
    )
    return source, attempt, authority, observed


def test_observed_lowered_conditional_helper_reuses_sealed_route_relation() -> None:
    """RF-1 accepts only the exact lowered route represented by its receipt."""
    from d810.transforms.unflatten_authority import model, transaction_api

    source, attempt, authority, observed = _lowered_conditional_observed_helper_case(
        valid_helper=True,
    )
    (row,) = authority.prepared.projected_route_realization.rows
    assert type(row.relation) is model.LoweredConditionalRouteRealization
    assert row.plan_step_type is model.PatchStepKind.LOWER_CONDITIONAL

    verdict = transaction_api.revalidate_observed_unflatten_authority(
        authority=authority,
        observed=observed,
        observed_generation=attempt.generation,
        generic_gates=_observed_gates(source, observed),
        observed_patch_binding=observed_patch_binding_for_test(authority),
    )

    assert verdict.accepted, verdict.failed_obligations


def test_observed_lowered_conditional_rejects_missing_false_edge_without_valid_helper() -> None:
    """RF-1 must not excuse a lost false arm merely because its feeder lowered."""
    from d810.transforms.unflatten_authority import transaction_api

    source, attempt, authority, observed = _lowered_conditional_observed_helper_case(
        valid_helper=False,
    )
    verdict = transaction_api.revalidate_observed_unflatten_authority(
        authority=authority,
        observed=observed,
        observed_generation=attempt.generation,
        generic_gates=_observed_gates(source, observed),
        observed_patch_binding=observed_patch_binding_for_test(authority),
    )

    assert not verdict.accepted


def test_unrepresented_lowered_conditional_helper_mints_exact_transaction_occurrence() -> None:
    """A plan-bound conditional omitted from route rows still has one authority."""
    from d810.transforms.unflatten_authority import bind, model, transaction_api

    _source, _attempt, authority, observed = _lowered_conditional_observed_helper_case(
        valid_helper=True,
    )
    prepared = authority.prepared
    plan = authority.patch_binding.plan
    projected = prepared.source_inputs.candidate_inventory
    lower_step_index = next(
        index for index, step in enumerate(plan.steps)
        if type(step).__name__ == "PatchLowerConditionalStateTransition"
    )
    facts = tuple(
        fact for fact in prepared.source_inputs.patch_step_facts
        if fact.step_index == lower_step_index
    )
    observed_serial_by_ref = {
        ref: (serial if serial == 0 else serial + 1)
        for ref, serial in projected.serial_by_ref.items()
    }

    occurrences = transaction_api._mint_observed_lowered_conditional_topology_occurrences(
        blocks=observed.blocks,
        serial_by_ref=observed_serial_by_ref,
        projected_inventory=projected,
        realization=None,
        patch_facts=facts,
        plan=plan,
    )

    assert len(occurrences) == 1
    occurrence = occurrences[0]
    assert type(occurrence) is model.ObservedLoweredConditionalTopologyOccurrence
    assert occurrence.patch_fact is facts[0]
    assert occurrence.source_ref == plan.steps[lower_step_index].source_serial
    assert occurrence.false_target_ref == plan.steps[lower_step_index].false_target_serial
    assert occurrence.true_target_ref == plan.steps[lower_step_index].true_target_serial
    bind.validate_observed_lowered_conditional_topology_occurrence(occurrence)


def test_unrepresented_lowered_conditional_occurrence_rejects_non_synthetic_helper() -> None:
    """A real or malformed helper cannot borrow lowered-conditional authority."""
    from d810.transforms.unflatten_authority import transaction_api

    _source, _attempt, authority, observed = _lowered_conditional_observed_helper_case(
        valid_helper=False,
    )
    prepared = authority.prepared
    plan = authority.patch_binding.plan
    projected = prepared.source_inputs.candidate_inventory
    lower_step_index = next(
        index for index, step in enumerate(plan.steps)
        if type(step).__name__ == "PatchLowerConditionalStateTransition"
    )
    facts = tuple(
        fact for fact in prepared.source_inputs.patch_step_facts
        if fact.step_index == lower_step_index
    )
    observed_serial_by_ref = {
        ref: (serial if serial == 0 else serial + 1)
        for ref, serial in projected.serial_by_ref.items()
    }

    assert transaction_api._mint_observed_lowered_conditional_topology_occurrences(
        blocks=observed.blocks,
        serial_by_ref=observed_serial_by_ref,
        projected_inventory=projected,
        realization=None,
        patch_facts=facts,
        plan=plan,
    ) == ()


def test_lowered_conditional_observed_only_exact_loss_correlates_to_latent_binding():
    """An observed-only CALL loss consumes the projected latent exact authority."""
    from d810.transforms.unflatten_authority import transaction_api, model
    from d810.ir.flowgraph import BlockKind

    source, projected, attempt, authority = _prepared_lowered_conditional_observed_case()
    observed = _replace_observed_block_without_eas(
        projected, 3, {0x4001}, kind=BlockKind.ZERO_WAY,
    )
    assert tuple(item.ea for item in observed.blocks[3].insn_snapshots) == (0x4000, 0x4002)
    verdict = transaction_api.revalidate_observed_unflatten_authority(
        authority=authority, observed=observed, observed_generation=attempt.generation,
        generic_gates=_observed_gates(source, observed),
        observed_patch_binding=observed_patch_binding_for_test(authority),
    )
    assert verdict.accepted
    ledger = verdict.observed_acceptance.observed_ledger
    assert len(ledger.rows) == 1
    assert ledger.rows[0].kind is model.SemanticLossKind.EXACT_INFEASIBLE_EFFECT
    expected_claims = tuple(
        claim for claim in authority.prepared.source_inputs.claims
        if (
            type(claim) is model.ExactInfeasibleEffectClaim
            and type(claim.discarded_effect_subject.locator)
            is model.EffectSubjectLocator
            and claim.discarded_effect_subject.locator.owner_anchor_ea == 0x4000
            and claim.discarded_effect_subject.locator.instruction_ea == 0x4001
            and claim.discarded_effect_subject.locator.effect_kind
            is model.EffectSiteKind.CALL
        )
    )
    assert len(expected_claims) == 1
    (exact_claim,) = expected_claims
    # The fixture also carries another exact-effect claim.  Its ID must not
    # satisfy the observed-loss row merely because it has the same claim kind.
    assert all(
        claim.claim_id != exact_claim.claim_id
        for claim in authority.prepared.source_inputs.claims
        if (
            type(claim) is model.ExactInfeasibleEffectClaim
            and claim is not exact_claim
        )
    )
    assert ledger.rows[0].claim_ids == (exact_claim.claim_id,)
    effect_cell = next(
        cell for cell in verdict.safety_case.obligation_index.cells
        if cell.key == model.ObligationKey(
            exact_claim.discarded_effect_subject,
            model.SafetyDimension.EFFECT_PRESERVATION,
        )
    )
    assert effect_cell.state is model.ObligationState.SATISFIED
    assert any(
        item.rule is model.UnflattenJustificationRule.EXACT_INFEASIBLE_EFFECT_PROVEN
        and item.claim_id == exact_claim.claim_id
        for item in verdict.safety_case.justifications
        if item.conclusion == effect_cell.key
    )


def test_lowered_conditional_observed_unclaimed_same_owner_losses_reject_atomically(monkeypatch):
    """An exact CALL allowance cannot conceal a same-owner unclaimed STORE loss."""
    from d810.transforms.unflatten_authority import transaction_api, model
    from d810.ir.flowgraph import BlockKind

    source, projected, attempt, authority = _prepared_lowered_conditional_observed_case(
        unrelated_same_owner_site=True,
    )
    observed = _replace_observed_block_without_eas(
        projected, 3, {0x4001}, kind=BlockKind.ZERO_WAY,
    )
    # Keep the GOTO tail and native anchor: this is a missing effect, not a
    # topology or terminal fixture shortcut.
    observed = _replace_observed_block_without_eas(
        observed, 4, {0x5000}, retain_native_anchor=True,
    )
    assert tuple(item.ea for item in observed.blocks[3].insn_snapshots) == (0x4000, 0x4002)
    assert observed.blocks[4].tail_kind.name == "GOTO"
    ledgers = []
    factory = transaction_api.build_semantic_loss_ledger
    monkeypatch.setattr(
        transaction_api,
        "build_semantic_loss_ledger",
        lambda case, verdict: ledgers.append(factory(case, verdict)) or ledgers[-1],
    )

    verdict = transaction_api.revalidate_observed_unflatten_authority(
        authority=authority,
        observed=observed,
        observed_generation=attempt.generation,
        generic_gates=_observed_gates(source, observed),
        observed_patch_binding=observed_patch_binding_for_test(authority),
    )

    assert not verdict.accepted
    assert verdict.observed_acceptance is None
    assert len(ledgers) == 1
    ledger = ledgers[0]
    assert ledger.case is verdict.safety_case
    # Each physical source owner has one canonical row. The exact CALL owner is
    # allowed, while the separate unclaimed STORE owner rejects atomically.
    assert len(ledger.rows) == 2
    assert {row.kind for row in ledger.rows} == {
        model.SemanticLossKind.EXACT_INFEASIBLE_EFFECT,
        model.SemanticLossKind.UNCLASSIFIED,
    }
    unclaimed_effect = next(
        subject for subject in verdict.safety_case.subjects
        if subject.role is model.SemanticSubjectRole.EFFECT_SITE
        and subject.kind is model.SemanticSubjectKind.EFFECT
        and subject.locator.instruction_ea == 0x5000
    )
    unclaimed_cell = next(
        cell for cell in verdict.safety_case.obligation_index.cells
        if cell.key == model.ObligationKey(
            unclaimed_effect, model.SafetyDimension.EFFECT_PRESERVATION,
        )
    )
    assert unclaimed_cell.state is model.ObligationState.VIOLATED


def test_direct_transaction_preparation_owns_source_and_projected_authority():
    from d810.transforms.unflatten_authority import transaction_api

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    prepared = transaction_api.prepare_unflatten_authority(
        source=source, projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan, attempt_id=fixture.attempt_id, generic_gates=gates,
    ).prepared
    assert prepared.source_inputs.source_route_authority is prepared.source_route_authority
    assert prepared.source_inputs.projected_route_realization is prepared.projected_route_realization
    assert prepared.projected_route_realization.source_authority is prepared.source_route_authority


def test_direct_preparation_preserves_live_mba_snapshot_coordinate():
    """Snapshot coordinates are transaction bindings, not authority digests."""
    from d810.transforms.unflatten_authority import transaction_api

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    snapshot_id = "live-mba-session:maturity-1:generation-1"
    plan = replace(plan, snapshot_id=snapshot_id)
    result = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    )

    assert result.prepared.snapshot_id == snapshot_id
    assert result.prepared.owning_plan.snapshot_id == snapshot_id


def test_prepared_authority_accepts_only_inventory_owned_structural_stop_coordinate():
    """Graph-only STOP bookkeeping is not a counterfeit semantic identity."""
    from types import SimpleNamespace

    from d810.ir.flowgraph import BlockKind
    from d810.transforms.cfg_transaction import LogicalBlockRef
    from d810.transforms.unflatten_authority import model, transaction_api
    from d810.transforms.unflatten_authority.ids import (
        semantic_graph_inventory_digest,
    )

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    prepared = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    ).prepared
    stop_serial = max(row.serial for row in prepared.source_inventory.blocks) + 1
    stop_ref = LogicalBlockRef(plan.plan_id, "unowned-structural-stop", 1)
    stop_row = model.InventoryBlockObservation(
        stop_serial,
        None,
        None,
        (),
        (),
        (),
        None,
        (),
        BlockKind.STOP,
    )
    source_inventory = replace(
        prepared.source_inventory,
        blocks=(*prepared.source_inventory.blocks, stop_row),
        inventory_digest=semantic_graph_inventory_digest(
            prepared.source_inventory.phase,
            prepared.source_inventory.graph_fingerprint,
            prepared.source_inventory.generation,
            (*prepared.source_inventory.blocks, stop_row),
            prepared.source_inventory.subjects,
            prepared.source_inventory.bindings,
            prepared.source_inventory.effects,
            prepared.source_inventory.terminals,
            prepared.source_inventory.topology,
            prepared.source_inventory.reachable_serials,
            prepared.source_inventory.entry_serial,
            prepared.source_inventory.source_subject_ids,
            prepared.source_inventory.function_ea,
        ),
    )
    owning_plan = replace(
        plan,
        source_coordinates=(*plan.source_coordinates, (stop_ref, stop_serial)),
    )

    rebound = replace(
        prepared,
        owning_plan=owning_plan,
        source_coordinate_digest=authority_id(
            model._canonical_source_coordinates(owning_plan.source_coordinates)
        ),
        source_inventory=source_inventory,
        source_inputs=None,
    )
    assert rebound.owning_plan.source_coordinates[-1] == (stop_ref, stop_serial)

    malformed_stop = deepcopy(stop_row)
    object.__setattr__(malformed_stop, "transfer_ea", 0xDEAD)
    assert not model._is_unowned_structural_stop_row(malformed_stop)
    malformed_blocks = (*prepared.source_inventory.blocks, malformed_stop)
    with pytest.raises(ValueError, match="transfer_ea"):
        replace(
            prepared.source_inventory,
            blocks=malformed_blocks,
            inventory_digest=semantic_graph_inventory_digest(
                prepared.source_inventory.phase,
                prepared.source_inventory.graph_fingerprint,
                prepared.source_inventory.generation,
                malformed_blocks,
                prepared.source_inventory.subjects,
                prepared.source_inventory.bindings,
                prepared.source_inventory.effects,
                prepared.source_inventory.terminals,
                prepared.source_inventory.topology,
                prepared.source_inventory.reachable_serials,
                prepared.source_inventory.entry_serial,
                prepared.source_inventory.source_subject_ids,
                prepared.source_inventory.function_ea,
            ),
        )


    first_ref, first_serial = plan.source_coordinates[0]
    duplicate_ref_coordinates = (
        *plan.source_coordinates,
        (first_ref, stop_serial),
    )
    duplicate_ref_plan = SimpleNamespace(
        plan_id=plan.plan_id,
        snapshot_id=plan.snapshot_id,
        source_generation=plan.source_generation,
        source_maturity=plan.source_maturity,
        source_coordinates=duplicate_ref_coordinates,
    )
    with pytest.raises(ValueError, match="duplicate source coordinate references"):
        replace(
            prepared,
            owning_plan=duplicate_ref_plan,
            source_coordinate_digest=authority_id(
                model._canonical_source_coordinates(duplicate_ref_coordinates)
            ),
            source_inventory=source_inventory,
            source_inputs=None,
        )

    counterfeit_ref = LogicalBlockRef(
        plan.plan_id, "counterfeit-semantic-coordinate", 1
    )
    counterfeit_plan = replace(
        plan,
        source_coordinates=(
            *plan.source_coordinates,
            (counterfeit_ref, prepared.source_inventory.blocks[0].serial),
        ),
    )
    with pytest.raises(ValueError, match="source coordinates|semantic source"):
        replace(
            prepared,
            owning_plan=counterfeit_plan,
            source_coordinate_digest=authority_id(
                model._canonical_source_coordinates(
                    counterfeit_plan.source_coordinates
                )
            ),
            source_inputs=None,
        )


def test_redirect_lineage_retains_exact_unowned_structural_stop_preimage():
    """A STOP old edge is a sealed preimage, never a semantic source ref."""

    from types import SimpleNamespace

    from d810.ir.flowgraph import BlockKind
    from d810.transforms.cfg_transaction import LogicalBlockRef
    from d810.transforms.unflatten_authority import model, transaction_api
    from d810.transforms.unflatten_authority.ids import (
        semantic_graph_inventory_digest,
    )

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    prepared = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    ).prepared
    assert prepared is not None
    source_inventory = prepared.source_inventory
    stop_serial = max(row.serial for row in source_inventory.blocks) + 1
    stop_ref = LogicalBlockRef(plan.plan_id, "redirect-old-structural-stop", 1)
    stop_row = model.InventoryBlockObservation(
        stop_serial,
        None,
        None,
        (),
        (),
        (),
        None,
        (),
        BlockKind.STOP,
    )
    blocks = (*source_inventory.blocks, stop_row)
    source_inventory = replace(
        source_inventory,
        blocks=blocks,
        inventory_digest=semantic_graph_inventory_digest(
            source_inventory.phase,
            source_inventory.graph_fingerprint,
            source_inventory.generation,
            blocks,
            source_inventory.subjects,
            source_inventory.bindings,
            source_inventory.effects,
            source_inventory.terminals,
            source_inventory.topology,
            source_inventory.reachable_serials,
            source_inventory.entry_serial,
            source_inventory.source_subject_ids,
            source_inventory.function_ea,
        ),
    )
    redirect = plan.steps[0]
    assert type(redirect) is PatchRedirectGoto
    stop_plan = replace(
        plan,
        steps=(replace(redirect, old_target=stop_ref), *plan.steps[1:]),
        source_coordinates=(*plan.source_coordinates, (stop_ref, stop_serial)),
    )
    classify = transaction_api._structural_stop_patch_preimage
    classify_kwargs = dict(
        source_inventory=source_inventory,
        plan=stop_plan,
        step=stop_plan.steps[0],
        ref_position=1,
        ref=stop_ref,
    )
    preimage = classify(**classify_kwargs)
    assert preimage is not None
    assert preimage.block_ref == stop_ref
    assert preimage.serial == stop_serial

    first_instruction = next(
        instruction
        for row in source_inventory.blocks
        for instruction in row.instruction_observations
    )
    for field, value in (
        ("block_kind", BlockKind.ZERO_WAY),
        ("block_ref", stop_ref),
        ("instruction_observations", (first_instruction,)),
    ):
        malformed_inventory = deepcopy(source_inventory)
        malformed_stop = deepcopy(stop_row)
        object.__setattr__(malformed_stop, field, value)
        object.__setattr__(
            malformed_inventory,
            "blocks",
            (*source_inventory.blocks[:-1], malformed_stop),
        )
        assert classify(
            **{**classify_kwargs, "source_inventory": malformed_inventory},
        ) is None

    for coordinates in (
        plan.source_coordinates,
        (*plan.source_coordinates, (stop_ref, 0)),
        (*stop_plan.source_coordinates, (stop_ref, 0)),
    ):
        coordinate_plan = SimpleNamespace(source_coordinates=coordinates)
        assert classify(**{**classify_kwargs, "plan": coordinate_plan}) is None

    (fact,) = transaction_api._derive_patch_lineage_facts(
        source_inventory,
        stop_plan,
    )
    assert fact.step_type == "PatchRedirectGoto"
    assert fact.owner_ref == redirect.from_serial
    assert fact.step_digest == (
        transaction_api.canonical_patch_step_descriptor(stop_plan, 0).step_digest
    )
    assert stop_ref not in source_inventory.serial_by_ref
    assert all(
        subject.block_ref != stop_ref for subject in source_inventory.subjects
    )
    assert all(
        witness.block_ref != stop_ref
        for witness in stop_plan.unflatten_proposal.source_identity_catalog.blocks
    )

    wrong_ref = LogicalBlockRef(plan.plan_id, "unsealed-structural-stop", 1)
    wrong_plan = replace(
        stop_plan,
        steps=(replace(stop_plan.steps[0], old_target=wrong_ref),),
    )
    with pytest.raises(ValueError, match="foreign to the source plan"):
        transaction_api._derive_patch_lineage_facts(source_inventory, wrong_plan)

    foreign_new = LogicalBlockRef(plan.plan_id, "foreign-new-target", 1)
    stop_as_owner = replace(
        stop_plan,
        steps=(PatchRedirectGoto(stop_ref, redirect.old_target, redirect.new_target),),
    )
    stop_as_new = replace(
        stop_plan,
        steps=(PatchRedirectGoto(redirect.from_serial, redirect.old_target, stop_ref),),
    )
    absent_new = replace(
        stop_plan,
        steps=(PatchRedirectGoto(redirect.from_serial, stop_ref, foreign_new),),
    )
    branch_step = replace(
        stop_plan,
        steps=(PatchRedirectBranch(redirect.from_serial, stop_ref, redirect.new_target),),
    )
    for invalid_plan in (stop_as_owner, stop_as_new, absent_new, branch_step):
        with pytest.raises(ValueError, match="foreign"):
            transaction_api._derive_patch_lineage_facts(
                source_inventory,
                invalid_plan,
            )

    malformed_inventory = deepcopy(source_inventory)
    malformed_stop = deepcopy(stop_row)
    object.__setattr__(malformed_stop, "successor_serials", (0,))
    object.__setattr__(
        malformed_inventory,
        "blocks",
        (*source_inventory.blocks[:-1], malformed_stop),
    )
    with pytest.raises(ValueError, match="STOP observations"):
        transaction_api._derive_patch_lineage_facts(
            malformed_inventory,
            stop_plan,
        )


def test_redirect_branch_lineage_retains_only_an_exact_native_old_edge_preimage():
    """A native old branch arm is structural provenance, never route authority."""

    from d810.ir.flowgraph import BlockKind, FlowGraph
    from d810.transforms.unflatten_authority import transaction_api

    fixture, source, plan, _projected, _gates = _c1_direct_preparation_case()
    refs = {serial: ref for ref, serial in plan.source_coordinates}
    # Make the selected semantic source a genuine two-arm owner.  Its second
    # arm is native block 4, which is deliberately absent from the selected
    # route closure; it is only the exact old edge replaced by this step.
    blocks = dict(source.blocks)
    blocks[0] = replace(
        blocks[0],
        succs=(3, 4),
        kind=BlockKind.TWO_WAY,
    )
    blocks[1] = replace(blocks[1], preds=())
    blocks[3] = replace(blocks[3], preds=(0, 1))
    blocks[4] = replace(blocks[4], preds=(0,))
    native_preimage_source = FlowGraph(
        blocks, source.entry_serial, source.func_ea,
    )
    branch_plan = replace(
        plan,
        steps=(PatchRedirectBranch(refs[0], refs[4], refs[3]),),
    )
    inventory = transaction_api._build_semantic_graph_inventory(
        native_preimage_source,
        branch_plan.unflatten_proposal,
        branch_plan,
        source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
    )

    preimage = transaction_api._native_source_edge_patch_preimage(
        source_inventory=inventory,
        plan=branch_plan,
        step=branch_plan.steps[0],
        ref_position=1,
        ref=refs[4],
    )
    assert preimage is not None
    assert (preimage.source_serial, preimage.target_serial) == (0, 4)
    assert refs[4] not in transaction_api._selected_route_subject_refs(
        branch_plan.unflatten_proposal,
    )
    (fact,) = transaction_api._derive_patch_lineage_facts(
        inventory, branch_plan, semantic_admission=True,
    )
    assert fact.owner_ref == refs[0]

    # A destination is never admitted as a preimage, and a merely named native
    # target must still be the reciprocal old edge of the exact source block.
    assert transaction_api._native_source_edge_patch_preimage(
        source_inventory=inventory,
        plan=branch_plan,
        step=branch_plan.steps[0],
        ref_position=2,
        ref=refs[3],
    ) is None
    broken_blocks = dict(native_preimage_source.blocks)
    broken_blocks[0] = replace(broken_blocks[0], succs=(3,))
    broken_blocks[4] = replace(broken_blocks[4], preds=())
    broken_source = FlowGraph(
        broken_blocks, source.entry_serial, source.func_ea,
    )
    broken_inventory = transaction_api._build_semantic_graph_inventory(
        broken_source,
        branch_plan.unflatten_proposal,
        branch_plan,
        source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
    )
    assert transaction_api._native_source_edge_patch_preimage(
        source_inventory=broken_inventory,
        plan=branch_plan,
        step=branch_plan.steps[0],
        ref_position=1,
        ref=refs[4],
    ) is None
    with pytest.raises(ValueError, match="outside proposal route subjects"):
        transaction_api._derive_patch_lineage_facts(
            broken_inventory, branch_plan, semantic_admission=True,
        )


def test_redirect_lineage_retains_only_an_exact_conditional_suffix_owner():
    """A non-route GOTO owner belongs only to its adjacent branch triangle."""

    from d810.ir.flowgraph import BlockKind, FlowGraph
    from d810.transforms.unflatten_authority import transaction_api
    from .test_bind import _one_way_goto

    _fixture, source, plan, _projected, _gates = _c1_direct_preparation_case()
    refs = {serial: ref for ref, serial in plan.source_coordinates}
    # A=0 is the selected semantic route block, B=2 its native fallthrough
    # suffix, and C=4 their shared old target.  The paired edits are exactly
    # A:C->A followed by B:C->A.
    blocks = dict(source.blocks)
    blocks[0] = replace(
        blocks[0], succs=(2, 4), kind=BlockKind.TWO_WAY,
    )
    blocks[1] = replace(blocks[1], preds=())
    blocks[2] = _one_way_goto(blocks[2], 4, preds=(0,))
    blocks[4] = replace(blocks[4], preds=(0, 2))
    suffix_source = FlowGraph(blocks, source.entry_serial, source.func_ea)
    suffix_plan = replace(
        plan,
        steps=(
            PatchRedirectBranch(refs[0], refs[4], refs[0]),
            PatchRedirectGoto(refs[2], refs[4], refs[0]),
        ),
    )
    inventory = transaction_api._build_semantic_graph_inventory(
        suffix_source,
        suffix_plan.unflatten_proposal,
        suffix_plan,
        source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
    )
    route_refs = transaction_api._selected_route_subject_refs(
        suffix_plan.unflatten_proposal,
    )
    assert refs[0] in route_refs and refs[2] not in route_refs

    preimage = transaction_api._native_conditional_suffix_patch_preimage(
        source_inventory=inventory,
        plan=suffix_plan,
        step_index=1,
        step=suffix_plan.steps[1],
        ref_position=0,
        ref=refs[2],
        route_refs=route_refs,
    )
    assert preimage is not None
    assert (
        preimage.branch_owner_serial,
        preimage.suffix_owner_serial,
        preimage.old_target_serial,
    ) == (0, 2, 4)
    facts = transaction_api._derive_patch_lineage_facts(
        inventory, suffix_plan, semantic_admission=True,
    )
    assert tuple(fact.owner_ref for fact in facts) == (refs[0], refs[2])

    # The authority is the exact adjacent pair and its triangle.  Neither an
    # unrelated prior branch nor topology with a detached suffix may lend it.
    wrong_pair = replace(
        suffix_plan,
        steps=(
            replace(suffix_plan.steps[0], old_target=refs[3]),
            suffix_plan.steps[1],
        ),
    )
    assert transaction_api._native_conditional_suffix_patch_preimage(
        source_inventory=inventory,
        plan=wrong_pair,
        step_index=1,
        step=wrong_pair.steps[1],
        ref_position=0,
        ref=refs[2],
        route_refs=route_refs,
    ) is None
    detached_blocks = dict(suffix_source.blocks)
    detached_blocks[0] = replace(detached_blocks[0], succs=(3, 4))
    detached_blocks[2] = replace(detached_blocks[2], preds=())
    detached_blocks[3] = replace(detached_blocks[3], preds=(0, 1))
    detached_source = FlowGraph(
        detached_blocks, source.entry_serial, source.func_ea,
    )
    detached_inventory = transaction_api._build_semantic_graph_inventory(
        detached_source,
        suffix_plan.unflatten_proposal,
        suffix_plan,
        source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
    )
    assert transaction_api._native_conditional_suffix_patch_preimage(
        source_inventory=detached_inventory,
        plan=suffix_plan,
        step_index=1,
        step=suffix_plan.steps[1],
        ref_position=0,
        ref=refs[2],
        route_refs=route_refs,
    ) is None
    with pytest.raises(ValueError, match="outside proposal route subjects"):
        transaction_api._derive_patch_lineage_facts(
            detached_inventory, suffix_plan, semantic_admission=True,
        )


def test_direct_projected_gate_validates_one_exact_loss_ledger_once(monkeypatch):
    """The transaction validates its shared exhaustive ledger once."""
    from d810.transforms.unflatten_authority import transaction_api

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    constructed = []
    consumed = []
    factory = transaction_api.build_projected_semantic_loss_ledger
    monkeypatch.setattr(
        transaction_api,
        "build_projected_semantic_loss_ledger",
        lambda case, verdict: constructed.append(case) or factory(case, verdict),
    )
    consumer = transaction_api.gates.validate_projected_loss_ledger
    monkeypatch.setattr(
        transaction_api.gates,
        "validate_projected_loss_ledger",
        lambda ledger, case: (
            consumed.append((ledger, case)) or consumer(ledger, case)
        ),
    )

    result = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    )

    prepared = result.prepared
    assert len(constructed) == 1
    assert constructed[0] is prepared.projected_case
    assert len(consumed) == 1
    assert all(ledger is prepared.projected_loss_ledger for ledger, _case in consumed)
    assert all(case is prepared.projected_case for _ledger, case in consumed)


def test_direct_projected_ledger_view_returns_prepared_occurrence():
    """Diagnostic consumers cannot remint a second transaction ledger."""
    from d810.transforms.unflatten_authority import transaction_api, views

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    prepared = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    ).prepared
    assert views.semantic_loss_ledger(prepared) is prepared.projected_loss_ledger


def test_projected_gate_boundary_rejects_naked_loss_allowances():
    """No serial-set exemption can be threaded through the authority facade."""
    import d810.transforms.unflatten_authority_facade as facade
    from d810.transforms.unflatten_authority import gates

    forbidden = {
        "validated_exact_effect_exclusion_serials",
        "allowed_lost_serials",
        "allowed_lost_block_serials",
        "permitted_loss_serials",
    }
    for callable_ in (
        facade.prepare_unflatten_authority_timed,
        facade.bind_prepared_unflatten_authority,
        gates.validate_projected_loss_ledger,
        gates.validate_projected_effect_loss_ledger,
        gates.validate_projected_dispatcher_removal_ledger,
        gates.validate_projected_corridor_coverage_ledger,
        gates.validate_projected_terminal_loss_ledger,
    ):
        assert forbidden.isdisjoint(signature(callable_).parameters)


def test_projected_gate_compatibility_projection_cannot_replace_ledger():
    """Case-only diagnostics are not accepted as a projected gate authority."""
    from d810.transforms.unflatten_authority import gates, transaction_api, views

    source, plan, projected, attempt_id, generic_gates = _c2_exact_direct_preparation_case()
    prepared = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan, attempt_id=attempt_id, generic_gates=generic_gates,
    ).prepared
    projection = views.semantic_loss_projection(prepared.projected_loss_ledger)
    with pytest.raises(TypeError, match="SemanticLossLedger"):
        gates.validate_projected_effect_loss_ledger(projection, prepared.projected_case)
    gates.validate_projected_effect_loss_ledger(
        prepared.projected_loss_ledger, prepared.projected_case,
    )


def test_projected_loss_ledger_seals_complete_case_rows_and_is_immutable():
    """One canonical physical owner row carries the exact semantic loss."""
    from d810.transforms.unflatten_authority import model, transaction_api

    source, plan, projected, attempt_id, generic_gates = _c2_exact_direct_preparation_case()
    prepared = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=attempt_id,
        generic_gates=generic_gates,
    ).prepared
    ledger = prepared.projected_loss_ledger
    assert len(ledger.rows) == 1
    assert ledger.rows[0].kind is model.SemanticLossKind.EXACT_INFEASIBLE_EFFECT
    with pytest.raises(FrozenInstanceError):
        ledger.ledger_id = "forged"  # type: ignore[misc]
    exact_effect = next(
        subject for subject in prepared.projected_case.subjects
        if subject.role is model.SemanticSubjectRole.EFFECT_SITE
        and subject.kind is model.SemanticSubjectKind.EFFECT
    )
    effect_cell = next(
        cell for cell in prepared.projected_case.obligation_index.cells
        if cell.key == model.ObligationKey(
            exact_effect, model.SafetyDimension.EFFECT_PRESERVATION,
        )
    )
    assert effect_cell.state is model.ObligationState.SATISFIED
    assert any(
        justification.rule is model.UnflattenJustificationRule.EXACT_INFEASIBLE_EFFECT_PROVEN
        for justification in prepared.projected_case.justifications
        if justification.conclusion == effect_cell.key
    )


def test_projected_loss_ledger_rejects_equal_reminted_case_occurrence():
    """A nonempty ledger cannot be rebound to equal but foreign case/row objects."""
    from d810.transforms.unflatten_authority import transaction_api

    source, plan, projected, attempt_id, generic_gates = _c2_exact_direct_preparation_case()
    prepared = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=attempt_id,
        generic_gates=generic_gates,
    ).prepared
    ledger = prepared.projected_loss_ledger
    assert ledger.rows
    reminted_case = deepcopy(ledger.case)
    assert reminted_case == ledger.case
    assert reminted_case is not ledger.case
    reminted_rows = tuple(replace(row, case=reminted_case) for row in ledger.rows)
    reminted_ledger_id = authority_id((
        "unflatten.semantic-loss-ledger.v1",
        ledger.case_id,
        tuple(
            (
                row.source_subject.subject_id,
                row.kind.value,
                tuple(item.justification_id for item in row.justifications),
                tuple(item.evidence_id for item in row.evidence),
                tuple(item.claim_id for item in row.claims),
            )
            for row in reminted_rows
        ),
    ))

    with pytest.raises(ValueError, match="exact case"):
        replace(ledger, rows=reminted_rows, ledger_id=reminted_ledger_id)


def test_direct_transaction_preparation_binds_source_once_without_assessor(monkeypatch):
    from d810.transforms.unflatten_authority import transaction_api

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    calls = []
    realizations = []
    binder = transaction_api.authority_bind.bind_source_route_authority
    def counted(*args, **kwargs):
        calls.append((args, kwargs)); return binder(*args, **kwargs)
    monkeypatch.setattr(transaction_api.authority_bind, "bind_source_route_authority", counted)
    realizer = transaction_api.realize_projected_routes
    monkeypatch.setattr(
        transaction_api,
        "realize_projected_routes",
        lambda **kwargs: realizations.append(kwargs) or realizer(**kwargs),
    )
    assert not hasattr(transaction_api, "assess_canonical_route")
    result = transaction_api.prepare_unflatten_authority(
        source=source, projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan, attempt_id=fixture.attempt_id, generic_gates=gates,
    )
    assert result.prepared is not None
    assert len(calls) == len(realizations) == 1


def test_direct_transaction_exposes_no_duplicate_preparation_entry():
    from d810.transforms.unflatten_authority import transaction_api
    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    assert not hasattr(transaction_api, "derive_unflatten_preparation_inputs")
    first = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    )
    second_attempt = replace(fixture.attempt_id, attempt_id="c1-second-attempt")
    second = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=second_attempt,
        generic_gates=gates,
    )
    assert first is not second
    assert first.prepared is not second.prepared
    assert first.prepared.source_route_authority is not second.prepared.source_route_authority
    assert first.prepared.projected_route_realization is not second.prepared.projected_route_realization



def test_preparation_receipt_closes_source_and_projected_ids():
    from d810.transforms.unflatten_authority import transaction_api
    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    prepared = transaction_api.prepare_unflatten_authority(source=source, projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected), plan=plan, attempt_id=fixture.attempt_id, generic_gates=gates).prepared
    receipt = prepared.source_inputs.preparation_receipt
    assert not hasattr(receipt, "route_assessment_digest")
    assert receipt.source_route_authority_id == prepared.source_route_authority.source_authority_id
    assert receipt.projected_route_realization_id == prepared.projected_route_realization.realization_id


def test_direct_preparation_reuses_transaction_built_inputs(monkeypatch):
    from d810.transforms.unflatten_authority import transaction_api
    from d810.transforms.unflatten_authority.gates import GenericCfgGateBundle
    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    captured = []
    realized = []
    derived = []
    facts_accesses = []
    facts_property = GenericCfgGateBundle.facts
    monkeypatch.setattr(
        GenericCfgGateBundle,
        "facts",
        property(lambda bundle: facts_accesses.append(bundle) or facts_property.__get__(bundle)),
    )
    binder = transaction_api.authority_bind.bind_raw_effect_gate_phase_fact
    monkeypatch.setattr(transaction_api.authority_bind, "bind_raw_effect_gate_phase_fact", lambda **kwargs: captured.append(kwargs) or binder(**kwargs))
    derive = transaction_api._derive_transaction_facts
    def capture_derived(*args, **kwargs):
        result = derive(*args, **kwargs)
        derived.append(result)
        return result
    monkeypatch.setattr(transaction_api, "_derive_transaction_facts", capture_derived)
    realizer = transaction_api.realize_projected_routes
    monkeypatch.setattr(
        transaction_api, "realize_projected_routes",
        lambda **kwargs: realized.append(kwargs) or realizer(**kwargs),
    )
    result = transaction_api.prepare_unflatten_authority(source=source, projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected), plan=plan, attempt_id=fixture.attempt_id, generic_gates=gates)
    assert result.prepared is not None
    assert len(captured) == len(derived) == len(realized) == 1
    assert facts_accesses == [gates]
    assert captured[0]["source_inventory"] is result.prepared.source_inventory
    assert captured[0]["projected_inventory"] is result.prepared.source_inputs.candidate_inventory
    assert realized[0]["derived_claim_inventory"] is derived[0]
    assert realized[0]["source_route_authority"] is result.prepared.source_route_authority
    assert realized[0]["projected_inventory"] is result.prepared.source_inputs.candidate_inventory
    facts = result.prepared.source_inputs.generic_gate_facts
    assert captured[0]["raw_gate_facts"] is facts.effectful_raw
    comparison = realized[0]["legacy_effective_gate_facts"]
    assert comparison.passed
    assert comparison.lost_block_serials == frozenset()
    assert comparison.pre_effectful_block_serials == facts.effectful_raw.pre_effectful_block_serials


def test_ordinary_preparation_remains_not_applicable(monkeypatch):
    from d810.transforms.unflatten_authority import transaction_api
    from .helpers import exact_fixture

    source, _proposal, _exclusion, _refs = exact_fixture()
    plan = PatchPlan(plan_id="ordinary-c1", snapshot_id="ordinary-snapshot")
    assert isinstance(transaction_api.select_plan_route(plan), UnflattenAuthorityNotApplicable)
    monkeypatch.setattr(
        transaction_api.authority_bind, "bind_source_route_authority",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("ordinary plan bound source authority")),
    )
    monkeypatch.setattr(
        transaction_api, "realize_projected_routes",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("ordinary plan realized routes")),
    )
    result = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, source),
        plan=plan,
        attempt_id=TransactionAttemptId(
            plan.plan_id, "ordinary-c1", 1, "ordinary-c1-attempt",
        ),
        generic_gates=None,
    )
    assert type(result) is UnflattenAuthorityNotApplicable


@pytest.mark.parametrize(
    "fixture_name",
    ("_three_b3_split_trampoline_case", "_three_b3_one_block_corridor_case"),
    ids=("split-trampoline", "split-corridor"),
)
def test_3b3_physical_descriptor_failure_preserves_canonical_error(fixture_name: str) -> None:
    from d810.transforms.unflatten_authority import transaction_api
    from . import test_bind

    authority, plan, source, _projected, _facts, _attempt, *_ = getattr(test_bind, fixture_name)()
    assert authority.proposal.plan_id == plan.plan_id
    # The derivation asks for the plan's descriptors once, not once per step
    # (ticket d81-cxzv), so the malformed-preimage failure is injected there.
    with patch.object(
        transaction_api,
        "canonical_patch_step_descriptors",
        side_effect=ValueError("canonical descriptor coordinates are malformed"),
    ):
        with pytest.raises(ValueError, match="canonical descriptor coordinates"):
            transaction_api._derive_patch_lineage_facts(
                source, plan, semantic_admission=True,
            )


def test_transaction_derivation_rejects_a_residual_terminal_cycle() -> None:
    """The transaction consumes the same topology-aware terminal binder."""

    from d810.transforms.unflatten_authority import transaction_api
    from .test_bind import _terminal_cycle_inventory_fixture

    proposal, _claim, fixture, source, _candidate, residual = (
        _terminal_cycle_inventory_fixture()
    )
    with pytest.raises(ValueError, match="residual cycle"):
        transaction_api._derive_inputs(
            source,
            residual,
            object(),
            proposal,
            None,
            phase_build_metrics=fixture.phase_build_metrics,
            preparation_metrics=fixture.preparation_metrics,
            candidate_generation=source.generation,
        )


def test_inventory_subjects_only_projects_selected_route_claims() -> None:
    """Unselected canonical proofs cannot mint inventory route subjects."""

    from d810.transforms.unflatten_authority import producer_api, transaction_api
    from d810.transforms.unflatten_authority import model
    from d810.transforms.unflatten_authority.model import SemanticSubjectKind
    from d810.analyses.control_flow.semantic_route_evidence import (
        canonical_semantic_evidence_from_proofs,
    )
    from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
    from types import SimpleNamespace

    source, proposal, _exclusion, refs = exact_fixture()
    selected = proposal.route_evidence.route_proofs[0]
    selected_claim = producer_api.build_equivalent_route_claims(
        source=source,
        source_catalog=proposal.source_identity_catalog,
        route_evidence=proposal.route_evidence,
        selected_proof_ids=(selected.proof_id,),
    )[0]
    physical_target = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x2FF0, 0x3001),),
        native_key=selected.destinations[0].target_identity.native_key,
        exact_instruction_eas=(0x3000,),
    )
    unselected = replace(
        selected,
        proof_id=helper_authority_id("unselected-route-proof"),
        destinations=(
            replace(
                selected.destinations[0],
                target_identity=physical_target,
                target_anchor_ea=0x2FF0,
            ),
            selected.destinations[1],
        ),
    )
    inventory_proposal = SimpleNamespace(
        source_identity_catalog=proposal.source_identity_catalog,
        corridor_coverage_forecast=proposal.corridor_coverage_forecast,
        use_def_witness=proposal.use_def_witness,
        plan_inputs=proposal.plan_inputs,
        claims=(*proposal.claims, selected_claim),
        route_evidence=canonical_semantic_evidence_from_proofs(
            native_key=proposal.route_evidence.native_key,
            generation=proposal.route_evidence.generation,
            proofs=(selected, unselected),
        ),
    )

    subjects = transaction_api._inventory_subjects(
        inventory_proposal,
        {ref: serial for serial, ref in refs.items()},
    )
    route_subjects = tuple(
        subject for subject in subjects
        if subject.kind is SemanticSubjectKind.ROUTE
    )

    route_proof_ids = {
        subject.locator.proof_id
        for subject in route_subjects
    }
    assert selected.proof_id in route_proof_ids
    assert unselected.proof_id not in route_proof_ids

    exact_claim = next(
        claim for claim in inventory_proposal.claims
        if type(claim) is model.ExactInfeasibleEffectClaim
    )
    exact_target = next(
        subject for subject in subjects
        if subject.subject_id == exact_claim.selected_target_subject.subject_id
    )
    discarded_owner = next(
        subject for subject in subjects
        if subject.role is model.SemanticSubjectRole.EXACT_EFFECT_DISCARDED_OWNER
    )
    assert exact_target.role is model.SemanticSubjectRole.EXACT_EFFECT_SELECTED_TARGET
    assert discarded_owner.block_ref == exact_claim.discarded_effect_subject.block_ref
    assert discarded_owner.block_ref != exact_target.block_ref


def test_inventory_has_one_canonical_physical_subject_per_catalog_block() -> None:
    """Source catalog identities never become inferred planned helpers."""

    from d810.transforms.unflatten_authority import model, transaction_api

    _source, proposal, _exclusion, refs = exact_fixture()
    subjects = transaction_api._inventory_subjects(
        proposal, {ref: serial for serial, ref in refs.items()},
    )
    canonical = tuple(
        subject for subject in subjects
        if subject.role is model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK
    )
    assert {(subject.block_ref, subject.anchor_ea) for subject in canonical} == {
        (item.block_ref, item.anchor_ea)
        for item in proposal.source_identity_catalog.blocks
    }
    assert not any(
        subject.role is model.SemanticSubjectRole.PLANNED_HELPER
        and subject.block_ref in {item.block_ref for item in proposal.source_identity_catalog.blocks}
        for subject in subjects
    )


def test_topology_reference_is_not_caller_selectable() -> None:
    from inspect import signature
    from d810.transforms.unflatten_authority import transaction_api

    assert "projected_topology_reference" not in signature(
        transaction_api._derive_inputs
    ).parameters
    assert "projected_topology_reference" not in signature(
        transaction_api._receipt
    ).parameters


def test_new_plan_has_no_legacy_metadata_or_shadow_transport_after_cutover() -> None:
    """Task20 removes transaction-local legacy synchronization seams."""

    from d810.hexrays.mutation import patch_transaction
    from d810.transforms.unflatten_authority import transaction_api, views
    from d810.transforms.unflatten_authority.proposal import reserved_metadata_keys

    # PatchPlan is the typed authority carrier after cutover; the temporary
    # shadow is not a dormant compatibility field or an attribute channel.
    assert "legacy_unflatten_shadow" not in {
        item.name for item in fields(PatchPlan)
    }
    new_plan = PatchPlan(plan_id="task20-plan", snapshot_id="task20-snapshot")
    assert reserved_metadata_keys(new_plan) == ()

    # Compatibility names are projections, never independently assigned
    # validation objects.  The views module remains graph-free by contract.
    compatibility_names = (
        "projected_dispatcher_removal_validation",
        "projected_dispatcher_coverage_validation",
        "observed_dispatcher_removal_validation",
        "observed_dispatcher_coverage_validation",
    )
    for owner in (
        patch_transaction.PatchTransactionExecution,
        patch_transaction.PatchTransactionPreflightRejected,
        patch_transaction.PatchTransactionPostObservationRejected,
        patch_transaction.PatchTransactionPoisoned,
    ):
        for name in compatibility_names:
            assert isinstance(getattr(owner, name, None), property)
        assert views.VIEW_GRAPH_TRAVERSALS == 0


def test_compatibility_properties_project_the_exact_canonical_verdict() -> None:
    from d810.hexrays.mutation.patch_transaction import (
        PatchTransactionExecution,
        PatchTransactionPoisoned,
        PatchTransactionPostObservationRejected,
        PatchTransactionPreflightRejected,
    )
    from d810.transforms.cfg_transaction import (
        CfgProjection,
        CfgTransactionFailure,
        CfgTransactionPhase,
    )
    from d810.transforms.unflatten_authority import model, views
    from d810.transforms.unflatten_authority import transaction_api
    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    attempt = fixture.attempt_id
    prepared = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=attempt,
        generic_gates=gates,
    )
    assert prepared.prepared is not None
    preflight = PatchTransactionPreflightRejected(
        "preflight", unflatten_verdict=prepared.verdict,
    )
    projected_view = views.compatibility_projection(prepared.verdict, "removal")
    assert preflight.projected_dispatcher_removal_validation.to_payload() == projected_view.to_payload()
    projected_accepted = prepared.verdict
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.hexrays.mutation.patch_binding import bind_patch_plan

    refs = {
        block.block_ref: block
        for block in plan.unflatten_proposal.source_identity_catalog.blocks
    }
    index = MbaBlockIdentityIndex.from_bindings(
        generation=attempt.generation,
        maturity=None,
        native_key=next(iter(refs)).identity.native_key,
        snapshot_id=plan.snapshot_id,
        session_id=attempt.session_id,
        bindings=tuple((ref.identity, serial) for ref, serial in plan.source_coordinates),
    )
    index.begin_transaction(attempt, quantity=len(source.blocks))
    bound = transaction_api.bind_prepared_unflatten_authority(
        prepared=prepared.prepared,
        patch_binding=bind_patch_plan(plan, index, attempt).bound_plan,
    )
    assert bound.authority is not None
    observed_accepted = transaction_api.revalidate_observed_unflatten_authority(
        authority=bound.authority,
        observed=projected,
        observed_generation=attempt.generation,
        generic_gates=gates,
        observed_patch_binding=observed_patch_binding_for_test(bound.authority),
    )
    assert observed_accepted.accepted
    rejected_projected = model.UnflattenAuthorityVerdict(
        False,
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
        authority_id("compatibility-rejected-projected"),
        None,
        None,
        authority_id("compatibility-rejected-candidate"),
        None,
        (),
    )
    rejected_observed = model.UnflattenAuthorityVerdict(
        False,
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        model.UnflattenAuthorityReason.LIVE_BINDING_FAILED,
        authority_id("compatibility-rejected-observed"),
        authority_id("compatibility-rejected-binding"),
        None,
        authority_id("compatibility-rejected-observed-candidate"),
        None,
        (),
    )
    projected_view = views.compatibility_projection(projected_accepted, "removal")
    observed_view = views.compatibility_projection(observed_accepted, "removal")
    execution = PatchTransactionExecution(
        applied_count=1,
        graph=projected,
        receipt=object(),
        projected_unflatten_verdict=projected_accepted,
        observed_unflatten_verdict=observed_accepted,
    )
    assert execution.projected_dispatcher_removal_validation.to_payload() == projected_view.to_payload()
    assert execution.observed_dispatcher_removal_validation.to_payload() == observed_view.to_payload()
    assert execution.projected_dispatcher_removal_validation.phase == "projected_preflight"
    assert execution.observed_dispatcher_removal_validation.phase == "observed_post_apply"
    assert execution.projected_dispatcher_removal_validation.authority_id == execution.observed_dispatcher_removal_validation.authority_id
    assert execution.projected_dispatcher_removal_validation.binding_id != execution.observed_dispatcher_removal_validation.binding_id
    assert execution.projected_dispatcher_removal_validation.case_id != execution.observed_dispatcher_removal_validation.case_id
    with pytest.raises((AttributeError, TypeError)):
        execution.observed_dispatcher_removal_validation = None

    preflight_view = views.compatibility_projection(rejected_projected, "removal")
    observed_rejection_view = views.compatibility_projection(rejected_observed, "coverage")
    preflight = PatchTransactionPreflightRejected(
        "preflight", unflatten_verdict=rejected_projected,
    )
    observed = PatchTransactionPostObservationRejected(
        "observed", unflatten_verdict=rejected_observed,
    )
    failure = CfgTransactionFailure(
        TransactionAttemptId(
            "compatibility-plan", "compatibility-session", 1,
            "compatibility-attempt",
        ),
        CfgTransactionPhase.POISONED_RESTART_REQUIRED,
        "poisoned",
        True,
        failure_phase="post_observation_contract",
    )
    poisoned = PatchTransactionPoisoned(failure, unflatten_verdict=rejected_observed)
    assert preflight.projected_dispatcher_removal_validation.to_payload() == preflight_view.to_payload()
    assert preflight.observed_dispatcher_removal_validation is None
    assert observed.observed_dispatcher_coverage_validation.to_payload() == observed_rejection_view.to_payload()
    assert observed.projected_dispatcher_removal_validation is None
    assert poisoned.observed_dispatcher_removal_validation.to_payload() == (
        views.compatibility_projection(rejected_observed, "removal").to_payload()
    )
    assert observed.unflatten_verdict is poisoned.unflatten_verdict is rejected_observed


def test_transaction_derivation_carries_terminal_cycle_phase_result() -> None:
    """The transaction carries the canonical binder result unchanged."""

    from d810.transforms.unflatten_authority import bind, transaction_api
    from .test_bind import _terminal_cycle_inventory_fixture

    proposal, claim, fixture, source, candidate, _residual = (
        _terminal_cycle_inventory_fixture()
    )
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("terminal-cycle-carry-snapshot"),
        source_generation=source.generation,
        steps=tuple(
            PatchRedirectBranch(
                owner,
                block_ref("b1")
                if owner == block_ref("b0")
                else block_ref("b0"),
                proposal.plan_inputs.authoritative_handlers[0].block_ref,
            )
            for owner in proposal.use_def_witness.redirect_owner_refs
        ),
        source_coordinates=tuple(
            (block.block_ref, block.serial)
            for block in source.blocks if block.block_ref is not None
        ),
        unflatten_proposal=proposal,
    )
    direct = bind.bind_terminal_cycle_break_claim(
        claim=claim,
        proposal=proposal,
        source_inventory=source,
        candidate_inventory=candidate,
        phase=fixture.phase_build_metrics.phase,
    )
    inputs = transaction_api._derive_inputs(
        source,
        candidate,
        plan,
        proposal,
        None,
        phase_build_metrics=fixture.phase_build_metrics,
        preparation_metrics=fixture.preparation_metrics,
        candidate_generation=candidate.generation,
    )
    assert inputs.terminal_cycle_phase_results == (direct.phase_result,)


def _full_corridor_fixture():
    """Build a live, non-empty corridor retirement around an unaffected route."""

    from d810.analyses.control_flow.graph_checks import (
        check_effectful_reachability_preserved,
        check_entry_reachability_not_collapsed,
        check_terminal_reachability_preserved,
    )
    from d810.ir.block_identity import StableBlockIdentity
    from d810.ir.flowgraph import BlockKind, BlockSnapshot, InsnKind, InsnSnapshot
    from d810.transforms import dispatcher_corridor_coverage
    from d810.transforms.cfg_transaction import NativeBlockRef
    from d810.transforms.graph_modification import RedirectBranch
    from d810.transforms.plan import PatchRedirectBranch
    from d810.transforms.unflatten_authority.proposal import (
        attach_typed_proposal,
        canonical_redirect_manifest,
    )
    from d810.transforms.unflatten_authority.gates import GenericCfgGateBundle

    source, base, exclusion, refs = exact_fixture()
    blocks = dict(source.blocks)
    blocks[0] = replace(blocks[0], preds=(5, 6))
    # The corridor is a linear bypass into the existing canonical route.  The
    # patch-owned feeder edge is the only edge rewritten by the projection.
    blocks[4] = BlockSnapshot(
        4, 0, (5,), (), 0, 0x5000,
        (InsnSnapshot(0, 0x5000, (), kind=InsnKind.GOTO, raw_opcode=0),),
        kind=BlockKind.ONE_WAY,
        tail_opcode=0, raw_tail_opcode=0, tail_kind=InsnKind.GOTO,
    )
    blocks[5] = BlockSnapshot(
        5, 0, (0, 6), (4,), 0, 0x6000,
        (InsnSnapshot(0, 0x6000, (), kind=InsnKind.COND_JUMP, raw_opcode=0),),
        kind=BlockKind.TWO_WAY,
        tail_opcode=0, raw_tail_opcode=0, tail_kind=InsnKind.COND_JUMP,
    )
    blocks[6] = BlockSnapshot(
        6, 0, (0,), (5,), 0, 0x7000,
        (InsnSnapshot(0, 0x7000, (), kind=InsnKind.GOTO, raw_opcode=0),),
        kind=BlockKind.ONE_WAY,
        tail_opcode=0, raw_tail_opcode=0, tail_kind=InsnKind.GOTO,
    )
    source = type(source)(blocks, 4, 0x7000)
    native_key = refs[0].identity.native_key
    refs = dict(refs)
    for serial, ea in ((5, 0x6000), (6, 0x7000)):
        refs[serial] = NativeBlockRef(
            StableBlockIdentity.from_instruction_eas((ea,), native_key=native_key)
        )
    evidence = base.route_evidence
    modifications = (RedirectBranch(from_serial=5, old_target=6, new_target=0),)
    coverage = dispatcher_corridor_coverage.analyze_dispatcher_corridor_coverage(
        source, modifications=modifications, dispatcher_entry_serial=6,
    )
    assert coverage.covered_corridors and not coverage.residual_corridors, coverage.to_metadata()
    template = PatchPlan(
        plan_id=authority_id("full-corridor-plan"), snapshot_id=authority_id("full-corridor-snapshot"),
        source_generation=1,
        steps=(
            PatchRedirectBranch(refs[5], refs[6], refs[0]),
        ),
        source_coordinates=tuple((ref, serial) for serial, ref in refs.items()),
    )
    removal_forecast = dispatcher_corridor_coverage.build_dispatcher_removal_forecast(
        source,
        coverage=coverage,
        dispatcher_entry_serial=6,
    )
    manifest = canonical_redirect_manifest(template)
    witness = replace(
        base.use_def_witness,
        redirect_owner_refs=manifest.owner_refs,
        redirect_digest=manifest.digest,
    )
    plan = attach_typed_proposal(
        template, source=source, block_refs_by_serial=refs,
        canonical_route_evidence=evidence,
        exact_state_effect_exclusions=(exclusion,), dispatcher_entry_serial=6,
        dispatcher_member_serials=(5, 6), authoritative_handler_serials=(2,),
        state_identity=base.plan_inputs.state_identity, use_def_witness=witness,
        corridor_coverage=coverage,
        dispatcher_removal_forecast=removal_forecast,
    )
    # This is a deliberately deduplicated projected graph.  It exercises the
    # corridor fact boundary, not the public patch-plan realizer.
    projected = type(source)(
        {
            **source.blocks,
            0: replace(source.blocks[0], preds=(5, 6)),
            5: replace(source.blocks[5], succs=(0,)),
            6: replace(source.blocks[6], preds=()),
        },
        source.entry_serial,
        source.func_ea,
    )
    gates = GenericCfgGateBundle(
        check_entry_reachability_not_collapsed(source, post_cfg=projected),
        check_effectful_reachability_preserved(source, post_cfg=projected),
        check_effectful_reachability_preserved(source, post_cfg=projected),
        check_terminal_reachability_preserved(source, post_cfg=projected),
    )
    return source, plan, projected, gates


def _full_corridor_inputs():
    """Derive corridor facts at the inventory boundary only."""
    from d810.analyses.control_flow.semantic_route_evidence import (
        CanonicalRouteAssessmentPhase, CanonicalRouteMaterialization,
    )
    from d810.transforms.unflatten_authority import model, transaction_api

    source, plan, projected, gates = _full_corridor_fixture()
    proposal = plan.unflatten_proposal
    source_inventory = transaction_api._build_semantic_graph_inventory(
        source, proposal, plan, source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        materialization=CanonicalRouteMaterialization.capture(
            source, generation=1, phase=CanonicalRouteAssessmentPhase.SOURCE,
        ),
    )
    projected_inventory = transaction_api._build_semantic_graph_inventory(
        projected, proposal, plan, source=False,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        source_subjects=source_inventory.subjects,
        materialization=CanonicalRouteMaterialization.capture(
            projected, generation=1,
            phase=CanonicalRouteAssessmentPhase.PROJECTED,
        ),
    )
    inputs = transaction_api._derive_inputs(
        source_inventory, projected_inventory, plan, proposal, gates,
        candidate_generation=1,
        phase_build_metrics=model.PhaseBuildMetrics(
            model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, 1, 1, 0,
        ),
        preparation_metrics=model.PreparationBuildMetrics(1, 1, 0),
        source_route_authority=None,
        projected_route_realization=None,
    )
    return source, plan, projected, gates, inputs


def test_prepare_preserves_typed_proposal_failure_stage(monkeypatch) -> None:
    from d810.transforms.cfg_transaction import CfgProjection, TransactionAttemptId
    from d810.transforms.unflatten_authority import model, transaction_api

    source, plan, projected, gates = _full_corridor_fixture()
    object.__setattr__(plan.unflatten_proposal, "schema_version", 2)
    attempt = TransactionAttemptId(
        plan.plan_id, authority_id("proposal-stage-session"), 1,
        authority_id("proposal-stage-attempt"),
    )
    result = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=attempt,
        generic_gates=gates,
    )
    assert isinstance(result, model.UnflattenAuthorityPreparationRejected)
    assert result.proposal_failure is not None
    assert result.proposal_failure.stage is model.ProposalValidationStage.ROUNDTRIP
    assert result.proposal_failure.detail_code == "proposal_invariants_invalid"


def test_prepare_rejects_projected_direct_realization_binding_failure() -> None:
    """A projected Direct-route mismatch is rejected by typed realization binding."""
    from d810.ir.flowgraph import BlockKind
    from d810.transforms.cfg_transaction import CfgProjection
    from d810.transforms.unflatten_authority import model, transaction_api
    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    entry = projected.blocks[projected.entry_serial]
    broken = replace(projected, blocks={**projected.blocks, projected.entry_serial: replace(entry, succs=(), kind=BlockKind.ZERO_WAY)})
    result = transaction_api.prepare_unflatten_authority(source=source, projection=CfgProjection(plan.plan_id, plan.snapshot_id, broken), plan=plan, attempt_id=fixture.attempt_id, generic_gates=gates)
    assert isinstance(result, model.UnflattenAuthorityPreparationRejected)
    assert result.verdict.reason is model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED
    assert not hasattr(result, "route_assessments")
    assert not hasattr(result, "route_assessment_context")



def test_prepare_reports_source_projected_realization_failure_coordinates() -> None:
    """A real Direct binder rejection reports typed source/projected coordinates."""

    from d810.ir.flowgraph import BlockKind
    from d810.transforms.cfg_transaction import CfgProjection
    from d810.transforms.unflatten_authority import model, transaction_api

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    entry = projected.blocks[projected.entry_serial]
    broken = replace(
        projected,
        blocks={
            **projected.blocks,
            projected.entry_serial: replace(entry, succs=(), kind=BlockKind.ZERO_WAY),
        },
    )
    result = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, broken),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    )
    assert isinstance(result, model.UnflattenAuthorityPreparationRejected)
    assert result.verdict.reason is model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED
    assert not hasattr(result, "route_assessments")
    assert not hasattr(result, "route_assessment_context")


def test_preparation_rejection_has_no_legacy_route_assessment_dto() -> None:
    from d810.transforms.unflatten_authority import model

    assert not hasattr(model, "PreparationRouteAssessmentContext")
    assert "route_assessments" not in model.UnflattenAuthorityPreparationRejected.__dataclass_fields__


def test_prepare_inventory_failure_does_not_return_orphaned_route_context(monkeypatch) -> None:
    from d810.transforms.cfg_transaction import CfgProjection, TransactionAttemptId
    from d810.transforms.plan import PatchPlan
    from d810.transforms.unflatten_authority import model, transaction_api
    from d810.transforms.unflatten_authority.proposal import TypedProposalRoute

    source, proposal, _exclusion, _refs = exact_fixture()
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id="inventory-failure-snapshot",
        source_generation=proposal.source_identity_catalog.generation,
    )
    object.__setattr__(plan, "unflatten_proposal", proposal)
    monkeypatch.setattr(
        transaction_api,
        "select_plan_route",
        lambda _plan: TypedProposalRoute(model.UnflattenPlanRoute.TYPED_PROPOSAL, proposal),
    )
    monkeypatch.setattr(
        transaction_api,
        "_build_semantic_graph_inventory",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("forced inventory failure")),
    )
    monkeypatch.setattr(
        transaction_api,
        "authority_id",
        lambda *_args, **_kwargs: "sha256:" + "e" * 64,
    )
    monkeypatch.setattr(
        model,
        "authority_id",
        lambda *_args, **_kwargs: "sha256:" + "e" * 64,
    )
    result = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, source),
        plan=plan,
        attempt_id=TransactionAttemptId(
            plan.plan_id, "inventory-failure-session",
            proposal.source_identity_catalog.generation,
            "inventory-failure-attempt",
        ),
        generic_gates=None,
    )
    assert isinstance(result, model.UnflattenAuthorityPreparationRejected)
    assert not hasattr(result, "route_assessments")
    assert not hasattr(result, "route_assessment_context")


def test_lower_boundary_corridor_phase_keeps_sealed_nonempty_forecast() -> None:
    """Legacy classifier characterization, not C1 public-authority evidence."""
    # This intentionally supplies synthetic lower-boundary inputs; the public
    # PatchPlan realizer is not valid for this corridor fixture.
    _source, _plan, _projected, _gates, inputs = _full_corridor_inputs()
    forecast = inputs.proposal.corridor_coverage_forecast
    assert forecast is not None and forecast.paths and forecast.enumeration_complete
    phase_result = inputs.corridor_coverage_phase_result
    assert phase_result is not None and phase_result.full
    assert phase_result.source_dispatcher_reachable
    assert not phase_result.candidate_dispatcher_reachable
    assert phase_result.forecast_id == forecast.forecast_id


def test_lower_boundary_case_evaluation_does_not_require_route_realization() -> None:
    """Legacy evaluator inputs retain no realization-derived effect exemptions."""
    from d810.transforms.unflatten_authority import model
    from d810.transforms.unflatten_authority.evaluate import build_semantic_case

    _source, _plan, _projected, _gates, inputs = _full_corridor_inputs()
    case = build_semantic_case(
        authority_id=authority_id("lower-boundary-no-route-realization"),
        phase=inputs.phase_build_metrics.phase,
        inputs=inputs,
    )
    assert case.phase is model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT



def test_public_prepare_rejects_reminted_forecast_function_ea_drift() -> None:
    """A validly reminted forecast cannot change the source function identity."""

    from d810.transforms.unflatten_authority import transaction_api

    source, plan, projected, gates = _full_corridor_fixture()
    forecast = plan.unflatten_proposal.corridor_coverage_forecast
    assert forecast is not None and source.func_ea == 0x7000
    wrong_function_ea = 0x8000
    reminted_id = authority_id((
        "unflatten.corridor-coverage-forecast.v1", forecast.plan_id,
        wrong_function_ea, forecast.source_native_key, forecast.source_generation,
        forecast.dispatcher_ref, forecast.dispatcher_anchor_ea, forecast.paths,
        forecast.covered_path_ids, forecast.residual_path_ids,
        forecast.enumeration_complete, forecast.semantic_exclusion_digests,
        forecast.semantic_exclusions, forecast.semantic_exclusion_path_ids,
    ))
    reminted = replace(
        forecast, function_ea=wrong_function_ea, forecast_id=reminted_id,
    )
    proposal = replace(
        plan.unflatten_proposal, corridor_coverage_forecast=reminted,
    )
    plan = replace(plan, unflatten_proposal=proposal)
    result = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=TransactionAttemptId(
            plan.plan_id, authority_id("function-ea-drift-session"), 1,
            authority_id("function-ea-drift-attempt"),
        ),
        generic_gates=gates,
    )
    assert getattr(result, "prepared", None) is None
    assert result.verdict.reason is UnflattenAuthorityReason.PROJECTED_BINDING_FAILED


def test_full_corridor_retained_feeder_topology_drift_is_not_coverage_exempt() -> None:
    """Lower-boundary topology facts retain drift outside corridor coverage."""
    from d810.ir.flowgraph import BlockKind
    from d810.transforms.unflatten_authority import model, transaction_api
    from d810.analyses.control_flow.semantic_route_evidence import CanonicalRouteAssessmentPhase, CanonicalRouteMaterialization
    source, plan, projected, gates, inputs = _full_corridor_inputs()
    blocks = dict(projected.blocks)
    blocks[1] = replace(blocks[1], succs=(2,), kind=BlockKind.ONE_WAY)
    blocks[3] = replace(blocks[3], preds=())
    drifted = type(projected)(blocks, projected.entry_serial, projected.func_ea)
    drifted_inventory = transaction_api._build_semantic_graph_inventory(drifted, plan.unflatten_proposal, plan, source=False, phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, source_subjects=inputs.source_inventory.subjects, materialization=CanonicalRouteMaterialization.capture(drifted, generation=1, phase=CanonicalRouteAssessmentPhase.PROJECTED))
    drifted_inputs = transaction_api._derive_inputs(inputs.source_inventory, drifted_inventory, plan, plan.unflatten_proposal, gates, candidate_generation=1, phase_build_metrics=inputs.phase_build_metrics, preparation_metrics=inputs.preparation_metrics, source_route_authority=None, projected_route_realization=None)
    assert drifted_inputs.corridor_coverage_phase_result is not None
    assert drifted_inputs.candidate_inventory.graph_fingerprint != inputs.candidate_inventory.graph_fingerprint
    assert any(binding.status is model.SubjectBindingStatus.MISSING for binding in drifted_inputs.candidate_inventory.bindings)



def test_lower_boundary_retirement_phase_retains_canonical_obligations() -> None:
    """Legacy classifier characterization, not C1 public-authority evidence."""
    # This checks the already-derived phase result, not transaction prepare.
    _source, _plan, _projected, _gates, inputs = _full_corridor_inputs()
    result = inputs.retirement_phase_result
    assert result is not None
    assert result.retired_refs
    assert result.retained_refs
    assert result.accepted
    assert result.result_id



def test_helper_and_resegmentation_lineage_is_derived_before_case_builder(monkeypatch) -> None:
    """Helper ownership enters closed facts before semantic-case construction."""
    from copy import copy
    from d810.transforms.unflatten_authority import transaction_api, producer_api, model
    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest
    from d810.analyses.control_flow.semantic_route_evidence import CanonicalRouteAssessmentPhase, CanonicalRouteMaterialization
    from d810.ir.block_identity import StableBlockIdentity
    from d810.ir.flowgraph import InsnKind, InsnSnapshot
    source, proposal, exclusion, refs = exact_fixture()
    source = replace(source, blocks={**source.blocks, 4: replace(source.blocks[4], insn_snapshots=(source.blocks[4].insn_snapshots[0], InsnSnapshot(0, 0x5001, (), kind=InsnKind.NOP, raw_opcode=0)))})
    refs = {**refs, 4: type(refs[4])(StableBlockIdentity.from_instruction_eas((0x5000, 0x5001), native_key=refs[4].identity.native_key))}
    proposal = producer_api.build_proposal(plan_id=proposal.plan_id, source=source, block_refs_by_serial=refs, source_generation=proposal.source_identity_catalog.generation, canonical_route_evidence=proposal.route_evidence, exact_state_effect_exclusions=(exclusion,), dispatcher_entry_serial=1, dispatcher_member_serials=(0, 1), authoritative_handler_serials=(2,), state_identity=proposal.plan_inputs.state_identity, use_def_witness=proposal.use_def_witness)
    helper, second_helper = PlanBlockRef(proposal.plan_id, "fallthrough-helper"), PlanBlockRef(proposal.plan_id, "second-helper")
    plan = PatchPlan(plan_id=proposal.plan_id, snapshot_id=helper_authority_id("snapshot-lineage"), source_generation=1, steps=(PatchRedirectBranch(refs[0], refs[1], refs[2], helper), PatchRedirectBranch(refs[1], refs[2], refs[0], second_helper)), source_coordinates=tuple((ref, serial) for serial, ref in refs.items()), new_blocks=(PatchBlockSpec(helper, "insert_block", template_block=refs[4]), PatchBlockSpec(second_helper, "insert_block", template_block=refs[4])), unflatten_proposal=proposal)
    manifest = canonical_redirect_manifest(plan)
    proposal = replace(proposal, use_def_witness=replace(proposal.use_def_witness, redirect_owner_refs=manifest.owner_refs, redirect_digest=manifest.digest))
    plan = replace(plan, unflatten_proposal=proposal)
    projected = type(source)({serial: block for serial, block in source.blocks.items() if serial != 4} | {4: replace(source.blocks[4], serial=4, insn_snapshots=(source.blocks[4].insn_snapshots[0],)), 5: replace(source.blocks[4], serial=5, start_ea=0x5001, insn_snapshots=(source.blocks[4].insn_snapshots[1],))}, source.entry_serial, source.func_ea)
    source_inventory = transaction_api._build_semantic_graph_inventory(source, proposal, plan, source=True, phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST, materialization=CanonicalRouteMaterialization.capture(source, generation=1, phase=CanonicalRouteAssessmentPhase.SOURCE))
    projected_inventory = transaction_api._build_semantic_graph_inventory(projected, proposal, plan, source=False, phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, source_subjects=source_inventory.subjects, materialization=CanonicalRouteMaterialization.capture(projected, generation=1, phase=CanonicalRouteAssessmentPhase.PROJECTED))
    derived = transaction_api._derive_transaction_facts(source_inventory, plan)
    descriptor_scans = 0
    original_descriptors = transaction_api.canonical_patch_step_descriptors

    def counted_descriptors(current_plan):
        nonlocal descriptor_scans
        descriptor_scans += 1
        return original_descriptors(current_plan)

    monkeypatch.setattr(transaction_api, "canonical_patch_step_descriptors", counted_descriptors)

    def forbidden_single_descriptor(*_args, **_kwargs):
        raise AssertionError("lineage must not rescan the complete plan per fact")

    monkeypatch.setattr(transaction_api, "canonical_patch_step_descriptor", forbidden_single_descriptor)
    relations = transaction_api._derive_patch_lineage_relations(source_inventory, projected_inventory, plan, derived.patch_step_facts)
    assert descriptor_scans == 1
    assert set((fact.step_type, fact.owner_ref) for fact in derived.patch_step_facts) == {("PatchRedirectBranch", refs[0]), ("PatchRedirectBranch", helper), ("PatchRedirectBranch", refs[1]), ("PatchRedirectBranch", second_helper)}
    assert any(item.source_subject_id for item in relations)
    assert any(item.target_subject_id for item in relations)
    forged = copy(next(
        fact for fact in derived.patch_step_facts if fact.step_index == 1
    ))
    object.__setattr__(forged, "step_index", True)
    assert transaction_api._derive_patch_lineage_relations(
        source_inventory, projected_inventory, plan, (forged,),
    ) == ()

def test_transaction_transport_reuses_detached_source_authority_across_phases() -> None:
    """The transaction transport owns one detached source result per claim."""

    from d810.transforms.unflatten_authority import model, transaction_api
    from .test_bind import _detached_binding_fixture

    claim, source, projected, projected_corridor = _detached_binding_fixture()
    projected_sources, projected_phases = transaction_api._bind_detached_authority_results(
        claims=(claim,), source_inventory=source, candidate_inventory=projected,
        corridor_result=projected_corridor,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    assert len(projected_sources) == len(projected_phases) == 1
    assert projected_phases[0].accepted
    assert projected_phases[0].source_result_id == projected_sources[0].result_id
    _, _, observed, observed_corridor = _detached_binding_fixture(
        candidate_phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        candidate_fingerprint=authority_id("detached-transaction-observed"),
        candidate_generation=5,
    )
    observed_sources, observed_phases = transaction_api._bind_detached_authority_results(
        claims=(claim,), source_inventory=source, candidate_inventory=observed,
        corridor_result=observed_corridor,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        prior_source_results=projected_sources,
    )
    assert observed_sources[0] is projected_sources[0]
    assert observed_phases[0].accepted

    with pytest.raises(ValueError, match="exactly one projected source result"):
        transaction_api._bind_detached_authority_results(
            claims=(claim,), source_inventory=source, candidate_inventory=observed,
            corridor_result=observed_corridor,
            phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            prior_source_results=(),
        )
    with pytest.raises(ValueError, match="duplicate projected source result"):
        transaction_api._bind_detached_authority_results(
            claims=(claim,), source_inventory=source, candidate_inventory=observed,
            corridor_result=observed_corridor,
            phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            prior_source_results=(*projected_sources, *projected_sources),
        )
    with pytest.raises(ValueError, match="foreign projected source result"):
        transaction_api._bind_detached_authority_results(
            claims=(), source_inventory=source, candidate_inventory=observed,
            corridor_result=observed_corridor,
            phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            prior_source_results=projected_sources,
        )


def test_derived_detached_authority_reuses_projected_source_across_observation() -> None:
    """Derived inputs keep one source result while each phase binds its corridor."""

    from d810.transforms.unflatten_authority import model, transaction_api
    from d810.transforms.unflatten_authority.ids import (
        _claim_factory,
        _subject_factory,
        semantic_graph_inventory_digest,
    )
    from d810.transforms.unflatten_authority.proposal import (
        canonical_redirect_manifest,
    )
    from d810.transforms.cfg_transaction import NativeBlockRef
    from .test_bind import _detached_binding_fixture

    claim, source, projected, _ = _detached_binding_fixture()

    def with_plan_catalog_subjects(inventory):
        blocks = {item.serial: item for item in inventory.blocks}
        subject_specs = (
            (model.SemanticSubjectRole.SOURCE_ENTRY, 0),
            (model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, 0),
            (model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, 1),
        )
        added_subjects = tuple(
            _subject_factory(
                model.SemanticSubjectRef,
                kind=model.SemanticSubjectKind.BLOCK,
                role=role,
                block_ref=blocks[serial].block_ref,
                anchor_ea=blocks[serial].anchor_ea,
                locator=model.BlockSubjectLocator(
                    blocks[serial].block_ref, blocks[serial].anchor_ea,
                ),
            )
            for role, serial in subject_specs
        )
        subjects = tuple(sorted({
            item.subject_id: item
            for item in (*inventory.subjects, *added_subjects)
        }.values(), key=lambda item: item.subject_id))
        bindings = tuple(sorted({
            item.subject.subject_id: item
            for item in (
                *inventory.bindings,
                *(
                model.PhaseSubjectBinding(
                    subject, inventory.phase, blocks[serial].block_ref,
                    inventory.graph_fingerprint, inventory.generation,
                    model.SubjectBindingStatus.UNIQUE, blocks[serial].serial,
                    blocks[serial].anchor_ea, blocks[serial].native_instruction_eas,
                    subject.role,
                )
                for subject, (_role, serial) in zip(added_subjects, subject_specs)
                ),
            )
        }.values(), key=lambda item: item.subject.subject_id))
        source_subject_ids = tuple(sorted({
            *inventory.source_subject_ids,
            *(subject.subject_id for subject in added_subjects),
        }))
        digest = semantic_graph_inventory_digest(
            inventory.phase, inventory.graph_fingerprint, inventory.generation,
            inventory.blocks, subjects, bindings, inventory.effects,
            inventory.terminals, inventory.topology, inventory.reachable_serials,
            inventory.entry_serial, source_subject_ids, inventory.function_ea,
        )
        return model.SemanticGraphInventory(
            inventory.phase, inventory.graph_fingerprint, inventory.generation,
            inventory.blocks, subjects, bindings, inventory.effects,
            inventory.terminals, inventory.topology, digest,
            inventory.reachable_serials, inventory.entry_serial,
            source_subject_ids, inventory.function_ea,
        )

    source = with_plan_catalog_subjects(source)
    projected = with_plan_catalog_subjects(projected)
    base = model.ProposedUnflattenContract(**_valid_proposal(model))
    source_native_key = next(
        block.block_ref.identity.native_key
        for block in source.blocks
        if type(block.block_ref) is NativeBlockRef
    )
    catalog = model.SourceIdentityCatalog(
        source_native_key,
        source.generation,
        tuple(
            model.SourceBlockIdentityWitness(
                block.block_ref, block.anchor_ea, block.native_instruction_eas,
            )
            for block in source.blocks
            if block.block_ref in {
                subject.block_ref for subject in source.subjects
                if subject.block_ref is not None
            }
        ),
    )
    by_ref = {block.block_ref: block for block in source.blocks}
    entry_ref = by_ref[block_ref("detached-0")].block_ref
    dispatcher_ref = claim.dispatcher_subject.block_ref
    assert entry_ref is not None
    assert dispatcher_ref is not None
    path_nodes = (
        model.CorridorCoveragePathNode(
            entry_ref, by_ref[entry_ref].anchor_ea,
        ),
        model.CorridorCoveragePathNode(
            dispatcher_ref, by_ref[dispatcher_ref].anchor_ea,
        ),
    )
    path_id = authority_id((
        "unflatten.corridor-coverage-path.v1", path_nodes, None,
        model.CorridorPathDisposition.STRUCTURALLY_COVERED, (),
    ))
    path = model.CorridorCoveragePath(
        path_nodes, None,
        model.CorridorPathDisposition.STRUCTURALLY_COVERED, (),
    )
    forecast_id = authority_id((
        "unflatten.corridor-coverage-forecast.v1", base.plan_id,
        source.function_ea, catalog.native_key, source.generation,
        dispatcher_ref, by_ref[dispatcher_ref].anchor_ea, (path,), (path_id,),
        (), True, (), (), (),
    ))
    forecast = model.CorridorCoverageForecast(
        forecast_id, base.plan_id, source.function_ea, catalog.native_key,
        source.generation, dispatcher_ref, by_ref[dispatcher_ref].anchor_ea,
        (path,), (path_id,), (), True, (), (), (),
    )
    from d810.analyses.control_flow.semantic_route_evidence import (
        SemanticRouteDestination,
        SemanticRouteProof,
        SemanticRouteProofKind,
        SemanticRouteShape,
        canonical_semantic_evidence_from_proofs,
    )
    from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
    from d810.ir.semantic_edge import SemanticEdgeRole

    route_destination_ref = claim.retained_handler_subjects[0].block_ref
    route_source = by_ref[entry_ref]
    route_destination = by_ref[route_destination_ref]
    route_proof = SemanticRouteProof(
        authority_id("derived-detached-route"),
        authority_id("derived-detached-route-group"),
        SemanticRouteProofKind.STATE_CHOICE, SemanticRouteShape.DIRECT,
        StableBlockIdentity.from_instruction_eas(
            route_source.native_instruction_eas, native_key=catalog.native_key,
        ),
        route_source.anchor_ea,
        (SemanticRouteDestination(
            SemanticEdgeRole.DIRECT, 0,
            StableBlockIdentity.from_instruction_eas(
                route_destination.native_instruction_eas,
                native_key=catalog.native_key,
            ),
            route_destination.anchor_ea,
        ),),
        NativeEaInterval(route_source.anchor_ea, route_source.anchor_ea + 1),
    )
    route_evidence = canonical_semantic_evidence_from_proofs(
        catalog.native_key, source.generation, (route_proof,),
    )
    route_proof = route_evidence.route_proofs[0]

    semantic_route_source = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        block_ref=entry_ref, anchor_ea=route_source.anchor_ea,
        locator=model.BlockSubjectLocator(entry_ref, route_source.anchor_ea),
    )
    route_subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.ROUTE,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        block_ref=entry_ref, anchor_ea=route_source.anchor_ea,
        locator=model.RouteSubjectLocator(
            route_proof.proof_id, route_proof.atomic_group_id,
            entry_ref, route_source.anchor_ea,
            (model.BlockSubjectLocator(route_destination_ref, route_destination.anchor_ea),),
        ),
    )
    destination_subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
        block_ref=route_destination_ref,
        anchor_ea=route_destination.anchor_ea,
        locator=model.BlockSubjectLocator(
            route_destination_ref, route_destination.anchor_ea,
        ),
    )
    route_claim = _claim_factory(
        model.EquivalentSemanticRouteClaim,
        kind=model.UnflattenClaimKind.EQUIVALENT_SEMANTIC_ROUTE,
        retired_route_subject=route_subject,
        replacement_route_subject=route_subject,
        source_subject=semantic_route_source,
        destination_subjects=(destination_subject,),
        route_proof_ids=(route_proof.proof_id,),
        atomic_group_id=route_proof.atomic_group_id,
        source_generation=source.generation,
    )

    def with_route_expansion(inventory):
        added = (semantic_route_source, route_subject, destination_subject)
        serial_by_ref = {block.block_ref: block for block in inventory.blocks}
        subjects = tuple(sorted((*inventory.subjects, *added), key=lambda item: item.subject_id))
        bindings = tuple(sorted((
            *inventory.bindings,
            *(model.PhaseSubjectBinding(
                subject, inventory.phase, subject.block_ref,
                inventory.graph_fingerprint, inventory.generation,
                model.SubjectBindingStatus.UNIQUE,
                serial_by_ref[subject.block_ref].serial, subject.anchor_ea,
                serial_by_ref[subject.block_ref].native_instruction_eas, subject.role,
            ) for subject in added),
        ), key=lambda item: item.subject.subject_id))
        source_subject_ids = tuple(sorted(
            (*inventory.source_subject_ids, *(subject.subject_id for subject in added)),
        ))
        digest = semantic_graph_inventory_digest(
            inventory.phase, inventory.graph_fingerprint, inventory.generation,
            inventory.blocks, subjects, bindings, inventory.effects,
            inventory.terminals, inventory.topology, inventory.reachable_serials,
            inventory.entry_serial, source_subject_ids, inventory.function_ea,
        )
        return model.SemanticGraphInventory(
            inventory.phase, inventory.graph_fingerprint, inventory.generation,
            inventory.blocks, subjects, bindings, inventory.effects,
            inventory.terminals, inventory.topology, digest,
            inventory.reachable_serials, inventory.entry_serial,
            source_subject_ids, inventory.function_ea,
        )

    source = with_route_expansion(source)
    projected = with_route_expansion(projected)
    proposal = model.ProposedUnflattenContract(
        schema_version=1,
        rule_set_version=1,
        plan_id=base.plan_id,
        route_evidence=route_evidence,
        source_identity_catalog=catalog,
        use_def_witness=model.UseDefFragmentWitness(
            authority_id("derived-detached-fragment"),
            base.plan_inputs.state_identity,
            (entry_ref,),
            authority_id("derived-detached-redirect"), True, True, 0, (),
        ),
        claims=model.canonical_model_order((route_claim, claim), "claims"),
        plan_inputs=model.UnflattenPlanInputCatalog(
            model.UnflattenPlanShape.PARTIAL_REWRITE,
            entry_ref, dispatcher_ref, (entry_ref, dispatcher_ref),
            tuple(sorted(
                (
                    model.AuthoritativeHandlerInput(
                        subject.block_ref, subject.anchor_ea, (index + 1,),
                    )
                    for index, subject in enumerate((
                        *claim.dead_handler_subjects,
                        *claim.retained_handler_subjects,
                    ))
                ),
                key=lambda item: item.anchor_ea,
            )),
            base.plan_inputs.state_identity,
        ),
        corridor_coverage_forecast=forecast,
    )
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("derived-detached-snapshot"),
        source_generation=source.generation,
        # This route-owned redirect is independent of the detached claim.  It
        # makes the enclosing contract pass the same sealed-manifest path as a
        # public transaction while the assertions below prove detached source
        # authority is transported independently of that route occurrence.
        steps=(PatchRedirectGoto(entry_ref, dispatcher_ref, route_destination_ref),),
        source_coordinates=tuple(
            (block.block_ref, block.serial)
            for block in source.blocks
            if block.block_ref is not None
        ),
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
    projected_metrics = model.PhaseBuildMetrics(
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, 1, 1, 0.0,
    )
    preparation_metrics = model.PreparationBuildMetrics(1, 1, 0.0)
    projected_inputs = transaction_api._derive_inputs(
        source, projected, plan, proposal, None,
        phase_build_metrics=projected_metrics,
        preparation_metrics=preparation_metrics,
    )
    (route_patch_fact,) = projected_inputs.patch_step_facts
    detached_refs = {
        subject.block_ref
        for subject in (
            claim.dispatcher_subject,
            *claim.dead_handler_subjects,
            *claim.retained_handler_subjects,
            *claim.component_subjects,
        )
    }
    assert route_patch_fact.owner_ref == entry_ref
    assert route_patch_fact.owner_ref not in detached_refs
    assert (
        projected_inputs.detached_dead_handler_component_source_results[0].claim_id
        == claim.claim_id
    )
    _, _, observed, _ = _detached_binding_fixture(
        candidate_phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        candidate_fingerprint=authority_id("derived-detached-observed"),
        candidate_generation=5,
    )
    observed = with_route_expansion(with_plan_catalog_subjects(observed))
    observed_inputs = transaction_api._derive_inputs(
        source, observed, plan, proposal, None,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        candidate_generation=observed.generation,
        phase_build_metrics=model.PhaseBuildMetrics(
            model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY, 0, 1, 0.0,
        ),
        preparation_metrics=preparation_metrics,
        preparation_inputs=projected_inputs,
    )

    projected_corridor = projected_inputs.corridor_coverage_phase_result
    observed_corridor = observed_inputs.corridor_coverage_phase_result
    assert projected_corridor is not None and observed_corridor is not None
    assert projected_corridor.forecast_id == observed_corridor.forecast_id == forecast_id
    assert projected_corridor.result_id != observed_corridor.result_id
    assert (
        observed_inputs.detached_dead_handler_component_source_results[0]
        is projected_inputs.detached_dead_handler_component_source_results[0]
    )
    assert observed_inputs.detached_dead_handler_component_phase_results[0].accepted

    model.DerivedUnflattenPreparationInputs.__post_init__(projected_inputs)
    model.DerivedUnflattenPreparationInputs.__post_init__(observed_inputs)
def _typed_plan() -> PatchPlan:
    model = import_authority_model()
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    from d810.transforms.plan import PatchRedirectGoto
    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest

    refs = tuple(block.block_ref for block in proposal.source_identity_catalog.blocks)
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id="snapshot-1",
        source_generation=3,
        steps=(
            PatchRedirectGoto(refs[0], refs[1], refs[2]),
            PatchRedirectGoto(refs[1], refs[2], refs[0]),
        ),
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
    return replace(plan, unflatten_proposal=proposal)


def test_select_plan_route_is_total_and_has_disjoint_result_shapes() -> None:
    ordinary = select_plan_route(PatchPlan(plan_id="ordinary", snapshot_id="snap"))
    assert isinstance(ordinary, UnflattenAuthorityNotApplicable)
    assert ordinary.route is UnflattenPlanRoute.ORDINARY

    typed = select_plan_route(_typed_plan())
    assert typed.route is UnflattenPlanRoute.TYPED_PROPOSAL
    assert typed.proposal is not None
    assert typed.proposal.plan_id == _typed_plan().plan_id
    assert not isinstance(typed, UnflattenAuthorityNotApplicable)


def test_reserved_legacy_only_route_requires_explicit_adaptation() -> None:
    plan = PatchPlan(
        plan_id="legacy",
        snapshot_id="snap",
        metadata=(("use_def_severance_audit", {"clean": True}),),
    )
    result = select_plan_route(plan)
    assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert result.key == "use_def_severance_audit"
    assert result.detail_code == "legacy_metadata_requires_explicit_codec_adaptation"


def test_typed_plan_with_reserved_key_rejects_dual_authority() -> None:
    with pytest.raises(ValueError, match="reserved legacy metadata"):
        _typed_plan().with_metadata(
            concrete_state_route_provenance=("legacy",)
        )


def test_mapping_proposal_is_rejected_without_truthy_authority() -> None:
    plan = _typed_plan()
    object.__setattr__(plan, "unflatten_proposal", {"plan_id": plan.plan_id})
    result = select_plan_route(plan)
    assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert result.detail_code == "proposal_type_is_not_closed"


def test_public_prepare_derives_closed_inputs_and_closes_receipt_ids(monkeypatch) -> None:
    """Public preparation is the sole closed-input entry point."""
    from d810.transforms.cfg_transaction import CfgProjection
    from d810.transforms.unflatten_authority import transaction_api
    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    build_calls = []
    builder = transaction_api._build_semantic_graph_inventory
    monkeypatch.setattr(transaction_api, "_build_semantic_graph_inventory", lambda *args, **kwargs: build_calls.append(True) or builder(*args, **kwargs))
    prepared_result = transaction_api.prepare_unflatten_authority(source=source, projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected), plan=plan, attempt_id=fixture.attempt_id, generic_gates=gates)
    assert prepared_result.prepared is not None
    assert len(build_calls) == 2
    assert not hasattr(transaction_api, "derive_unflatten_preparation_inputs")
    receipt = prepared_result.prepared.source_inputs.preparation_receipt
    assert receipt.source_route_authority_id == prepared_result.prepared.source_route_authority.source_authority_id
    assert receipt.projected_route_realization_id == prepared_result.prepared.projected_route_realization.realization_id
    with pytest.raises((TypeError, ValueError)):
        replace(receipt, projected_route_realization_id=authority_id("forged-receipt"))



def test_bound_patch_plan_transport_is_exact_nominal_and_gate_bundle_is_lossless() -> None:
    from types import SimpleNamespace

    from d810.analyses.control_flow.graph_checks import (
        EffectfulReachabilityResult,
        EntryReachabilityResult,
        TerminalReachabilityResult,
    )
    from d810.transforms.patch_binding import BoundPatchPlan
    from d810.transforms.unflatten_authority.gates import GenericCfgGateBundle

    entry = EntryReachabilityResult(True, 4, 4, 1.0, 20, 0.5)
    raw = EffectfulReachabilityResult(True, frozenset({2}), frozenset({2}), frozenset())
    effective = EffectfulReachabilityResult(True, frozenset({2}), frozenset({2}), frozenset())
    terminal = TerminalReachabilityResult(True, frozenset({3}), frozenset({3}), 4, 4)
    bundle = GenericCfgGateBundle(entry, raw, effective, terminal)
    assert bundle.effectful_raw is raw
    assert bundle.effectful_effective is effective

    forged = SimpleNamespace(
        plan=None,
        attempt_id=None,
        session_id="session",
        generation=0,
        maturity=0,
        bindings=(),
    )
    assert type(forged) is not BoundPatchPlan


def test_gate_bundle_rejects_lossy_rows_and_raw_effect_drift() -> None:
    from dataclasses import replace

    from d810.analyses.control_flow.graph_checks import (
        EffectfulReachabilityResult,
        EntryReachabilityResult,
        TerminalReachabilityResult,
    )
    from d810.transforms.unflatten_authority.gates import GenericCfgGateBundle

    entry = EntryReachabilityResult(True, 4, 4, 1.0, 20, 0.5)
    raw = EffectfulReachabilityResult(
        True, frozenset({2}), frozenset({2}), frozenset()
    )
    effective = EffectfulReachabilityResult(
        True, frozenset({2}), frozenset({2}), frozenset()
    )
    terminal = TerminalReachabilityResult(
        True, frozenset({3}), frozenset({3}), 4, 4
    )
    GenericCfgGateBundle(entry, raw, effective, terminal)

    with pytest.raises(ValueError, match="raw/effective effect pre sets differ"):
        GenericCfgGateBundle(
            entry,
            raw,
            replace(
                effective,
                pre_effectful_block_serials=frozenset({4}),
                post_reachable_effectful_block_serials=frozenset({4}),
            ),
            terminal,
        )
    with pytest.raises(TypeError, match="exact finite float"):
        GenericCfgGateBundle(
            replace(entry, retained_ratio=float("nan")),
            raw,
            effective,
            terminal,
        )

    def fresh_bundle():
        return GenericCfgGateBundle(
            EntryReachabilityResult(True, 4, 4, 1.0, 20, 0.5),
            EffectfulReachabilityResult(True, frozenset({2}), frozenset({2}), frozenset()),
            EffectfulReachabilityResult(True, frozenset({2}), frozenset({2}), frozenset()),
            TerminalReachabilityResult(True, frozenset({3}), frozenset({3}), 4, 4),
        )

    from d810.transforms.unflatten_authority.gates import validate_generic_cfg_gate_bundle
    for target, field, value in (
        ("entry", "retained_ratio", float("nan")),
        ("effectful_raw", "passed", False),
        ("effectful_raw", "lost_block_serials", frozenset({2})),
        ("effectful_effective", "post_reachable_effectful_block_serials", frozenset()),
        ("terminal", "post_reachable_terminals", frozenset()),
        ("terminal", "post_reachable_count", True),
        ("terminal", "passed", False),
    ):
        bundle = fresh_bundle()
        object.__setattr__(getattr(bundle, target), field, value)
        with pytest.raises((TypeError, ValueError)):
            validate_generic_cfg_gate_bundle(bundle)


def test_same_owner_effect_gate_uses_exact_effect_locator_presence() -> None:
    """Gate transport contains facts only; effect identity comes from inventory."""
    from d810.transforms.unflatten_authority import transaction_api
    from d810.transforms.unflatten_authority.model import UnflattenAuthorityPhase
    from d810.transforms.plan import PatchRedirectGoto

    source, proposal, _exclusion, refs = __import__(
        "tests.unit.transforms.unflatten_authority.test_bind",
        fromlist=["_exact_fixture"],
    )._exact_fixture()
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("snapshot-same-owner-effects"),
        source_generation=1,
        steps=(PatchRedirectGoto(refs[0], refs[1], refs[2]),),
        source_coordinates=tuple((ref, serial) for serial, ref in refs.items()),
        unflatten_proposal=proposal,
    )
    proposal = replace(
        proposal,
        use_def_witness=replace(
            proposal.use_def_witness,
            redirect_owner_refs=__import__(
                "d810.transforms.unflatten_authority.proposal",
                fromlist=["canonical_redirect_manifest"],
            ).canonical_redirect_manifest(plan).owner_refs,
            redirect_digest=__import__(
                "d810.transforms.unflatten_authority.proposal",
                fromlist=["canonical_redirect_manifest"],
            ).canonical_redirect_manifest(plan).digest,
        ),
    )
    plan = replace(plan, unflatten_proposal=proposal)
    source_inventory = transaction_api._build_semantic_graph_inventory(
        source, proposal, plan, source=True,
        phase=UnflattenAuthorityPhase.PRODUCER_FORECAST,
    )
    candidate_inventory = transaction_api._build_semantic_graph_inventory(
        source, proposal, plan, source=False,
        phase=UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    source_effects = tuple(source_inventory.effects)
    candidate_effects = tuple(candidate_inventory.effects)
    assert source_effects
    assert {item.effect_kind for item in source_effects} >= {item.effect_kind for item in candidate_effects}
    assert all(item.owner_serial in source_inventory.reachable_serials for item in source_effects)
    assert not hasattr(transaction_api, "_generic_gates")
    assert not hasattr(transaction_api, "_topology_relations_from_inventory")


def test_prepare_rejects_projected_route_predicate_erasure() -> None:
    """A candidate with the canonical branch erased cannot inherit source authority."""
    from dataclasses import replace

    from d810.ir.flowgraph import InsnKind, InsnSnapshot
    from d810.transforms.cfg_transaction import CfgProjection, TransactionAttemptId
    from d810.transforms.unflatten_authority import transaction_api
    from d810.transforms.unflatten_authority.model import (
        GenericCfgGateKind,
        GenericCfgGateResult,
    )

    source, proposal, _exclusion, refs = __import__(
        "tests.unit.transforms.unflatten_authority.test_bind",
        fromlist=["_exact_fixture"],
    )._exact_fixture()
    from d810.transforms.plan import PatchRedirectGoto
    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest

    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("snapshot-erased"),
        source_generation=1,
        steps=(PatchRedirectGoto(refs[0], refs[1], refs[2]),),
        source_coordinates=tuple((ref, serial) for serial, ref in refs.items()),
        unflatten_proposal=proposal,
    )
    proposal = replace(
        proposal,
        use_def_witness=replace(
            proposal.use_def_witness,
            redirect_owner_refs=canonical_redirect_manifest(plan).owner_refs,
            redirect_digest=canonical_redirect_manifest(plan).digest,
        ),
    )
    plan = replace(plan, unflatten_proposal=proposal)
    branch_block = source.blocks[1]
    candidate = replace(
        source,
        blocks={
            **source.blocks,
            1: replace(
                branch_block,
                insn_snapshots=(
                    branch_block.insn_snapshots[0],
                    InsnSnapshot(0, 0x2001, (), kind=InsnKind.NOP),
                ),
            ),
        },
    )
    projection = CfgProjection(plan.plan_id, plan.snapshot_id, candidate)
    attempt = TransactionAttemptId(
        plan.plan_id,
        "session-erased",
        1,
        "attempt-erased",
    )
    generic_gates = tuple(
        GenericCfgGateResult(kind, True, (), (), "fixture")
        for kind in (
            GenericCfgGateKind.ENTRY_REACHABILITY,
            GenericCfgGateKind.EFFECTFUL_REACHABILITY,
            GenericCfgGateKind.TERMINAL_REACHABILITY,
        )
    )

    result = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=projection,
        plan=plan,
        attempt_id=attempt,
        generic_gates=generic_gates,
    )

    assert getattr(result, "prepared", None) is None
    assert result.verdict.reason.name == "PROJECTED_BINDING_FAILED"


def test_state_carrier_feeder_redirect_is_selected_by_its_typed_corridor() -> None:
    """A carrier proof owns feeder -> comparison -> destination exactly.

    The carrier's semantic source is the producer block, but the physical
    redirect is intentionally applied at its typed feeder.  Selection must
    use those closed carrier coordinates rather than requiring the rewrite to
    originate at the producer block.
    """
    from d810.analyses.control_flow import semantic_route_evidence as route
    from d810.transforms.cfg_transaction import NativeBlockRef
    from d810.transforms.plan import PatchPlan, PatchRedirectGoto
    from types import SimpleNamespace

    from d810.transforms.unflatten_authority import bind
    from d810.transforms.unflatten_authority import model
    from d810.transforms.unflatten_authority.proposal import (
        canonical_patch_step_descriptors,
    )

    evidence, _graph, _stage = (
        __import__(
            "tests.unit.transforms.unflatten_authority.test_bind",
            fromlist=["_branch_x_canonical_replay_case"],
        )._branch_x_canonical_replay_case(
            route.SemanticRouteProofKind.STATE_CARRIER,
        )
    )
    proof = evidence.route_proofs[0]
    carrier = proof.state_carrier
    assert carrier is not None and not carrier.requires_feeder_clone
    source_ref = NativeBlockRef(carrier.source_identity)
    feeder_ref = NativeBlockRef(carrier.feeder_identity)
    comparison_ref = NativeBlockRef(carrier.comparison_entry_identity)
    destination_ref = NativeBlockRef(proof.destinations[0].target_identity)
    plan = PatchPlan(
        plan_id=authority_id("carrier-feeder-direct-plan"),
        snapshot_id=authority_id("carrier-feeder-direct-snapshot"),
        steps=(PatchRedirectGoto(feeder_ref, comparison_ref, destination_ref),),
    )
    descriptor = canonical_patch_step_descriptors(plan)[0]

    assert bind._state_carrier_feeder_direct_coordinates_match(
        plan, proof, descriptor,
    )
    assert descriptor.route_refs[0] != source_ref
    facts = tuple(
        model.PatchStepEvidencePayload(
            plan.plan_id,
            descriptor.step_index,
            descriptor.step_type,
            owner_ref,
            descriptor.step_digest,
            descriptor.host_ea,
            descriptor.host_opcode,
            None,
        )
        for owner_ref in descriptor.owner_refs
    )
    selected = bind._select_lineage_fact_group(
        bind._index_lineage_fact_groups(plan, facts),
        plan=plan,
        claim=SimpleNamespace(
            source_subject=SimpleNamespace(
                locator=SimpleNamespace(block_ref=source_ref),
            ),
        ),
        proof=proof,
        source_inventory=SimpleNamespace(blocks=()),
    )
    assert selected.descriptor.step_index == 0

    wrong_plan = PatchPlan(
        plan_id=authority_id("carrier-feeder-direct-wrong-old-plan"),
        snapshot_id=authority_id("carrier-feeder-direct-wrong-old-snapshot"),
        steps=(PatchRedirectGoto(feeder_ref, source_ref, destination_ref),),
    )
    wrong_descriptor = canonical_patch_step_descriptors(wrong_plan)[0]
    assert not bind._state_carrier_feeder_direct_coordinates_match(
        wrong_plan, proof, wrong_descriptor,
    )


def test_entry_liveness_carrier_matcher_requires_the_exact_typed_corridor() -> None:
    """Carrier evidence owns source -> feeder -> comparison -> destination."""
    from d810.analyses.control_flow import semantic_route_evidence as route
    from d810.transforms.cfg_transaction import NativeBlockRef
    from d810.transforms.unflatten_authority.proposal import (
        _entry_liveness_route_proof_rejection_detail,
    )

    evidence, _graph, _stage = (
        __import__(
            "tests.unit.transforms.unflatten_authority.test_bind",
            fromlist=["_branch_x_canonical_replay_case"],
        )._branch_x_canonical_replay_case(
            route.SemanticRouteProofKind.STATE_CARRIER,
        )
    )
    proof = evidence.route_proofs[0]
    carrier = proof.state_carrier
    assert carrier is not None
    source_ref = NativeBlockRef(carrier.source_identity)
    owner_ref = NativeBlockRef(carrier.owner_identity)
    feeder_ref = NativeBlockRef(carrier.feeder_identity)
    comparison_ref = NativeBlockRef(carrier.comparison_entry_identity)
    replacement_ref = NativeBlockRef(proof.destinations[0].target_identity)
    source_witnesses = {
        ref: model.SourceBlockIdentityWitness(
            ref,
            anchor,
            ref.identity.exact_instruction_eas,
        )
        for ref, anchor in (
            (owner_ref, carrier.owner_anchor_ea),
            (source_ref, carrier.source_anchor_ea),
            (feeder_ref, carrier.feeder_anchor_ea),
            (comparison_ref, carrier.comparison_entry_anchor_ea),
            (
                replacement_ref,
                proof.destinations[0].target_anchor_ea,
            ),
        )
    }
    exact = dict(
        source_witnesses=source_witnesses,
        replacement_ref=replacement_ref,
        redirect_owner_ref=source_ref,
        dispatcher_old_target_ref=feeder_ref,
        state_production_source_ref=source_ref,
        state_production_instruction_ea=carrier.source_anchor_ea,
        route_proof_id=proof.proof_id,
        selected_ids={proof.proof_id},
        proof=proof,
        state_identity=carrier.state_identity,
        normalized_state=carrier.state_constant,
    )

    assert _entry_liveness_route_proof_rejection_detail(**exact) is None

    # Source-owned carrier routes normally leave the enclosing owner empty.
    # An explicit owner is also legitimate only when it seals the exact nested
    # carrier/redirect owner coordinate.
    proof_with_matching_route_owner = replace(
        proof,
        source_owner_identity=carrier.owner_identity,
        source_owner_anchor_ea=carrier.owner_anchor_ea,
    )
    assert _entry_liveness_route_proof_rejection_detail(
        **(exact | {"proof": proof_with_matching_route_owner})
    ) is None

    # Every piece below is authority, not descriptive metadata.  Each drift
    # must close the carrier route before proposal attachment or admission.
    source_witnesses_without_source = dict(source_witnesses)
    del source_witnesses_without_source[source_ref]
    carrier_with_foreign_owner = replace(
        carrier,
        owner_identity=carrier.feeder_identity,
        owner_anchor_ea=carrier.feeder_anchor_ea,
    )
    proof_with_foreign_owner = replace(
        proof,
        state_carrier=carrier_with_foreign_owner,
    )
    proof_with_foreign_route_owner = replace(
        proof,
        source_owner_identity=carrier.feeder_identity,
        source_owner_anchor_ea=carrier.feeder_anchor_ea,
    )
    # Repeated identities now fail at construction, before route matching.
    with pytest.raises(route.SemanticRouteEvidenceRejected, match="corridor"):
        replace(
            carrier,
            comparison_entry_identity=carrier.feeder_identity,
            comparison_entry_anchor_ea=carrier.feeder_anchor_ea,
            corridor=(carrier.corridor[0], carrier.corridor[1], carrier.corridor[1]),
        )
    drifted_cases = (
        ("source catalogue witness", {"source_witnesses": source_witnesses_without_source}),
        ("source identity", {"state_production_source_ref": feeder_ref}),
        ("source EA", {"state_production_instruction_ea": carrier.source_anchor_ea + 1}),
        (
            "carrier owner identity and anchor",
            {"proof": proof_with_foreign_owner},
        ),
        (
            "route-level owner identity and anchor",
            {"proof": proof_with_foreign_route_owner},
        ),
        ("feeder identity", {"dispatcher_old_target_ref": comparison_ref}),
        ("state namespace", {"state_identity": object()}),
        ("state constant", {"normalized_state": carrier.state_constant + 1}),
        ("destination identity", {"replacement_ref": feeder_ref}),
        ("selected proof ID", {"selected_ids": set()}),
        ("entry redirect owner", {"redirect_owner_ref": feeder_ref}),
    )
    for label, drift in drifted_cases:
        assert _entry_liveness_route_proof_rejection_detail(
            **(exact | drift)
        ) is not None, label


def test_entry_liveness_semantic_point_uses_inventory_before_explicit_range_fallback() -> None:
    """A catalogue block anchor is not silently promoted to an endpoint point."""
    from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
    from d810.transforms.cfg_transaction import NativeBlockRef
    from d810.transforms.unflatten_authority.proposal import (
        _source_witness_covers_semantic_point,
    )
    from tests.native_preanalysis import make_native_key

    ref = NativeBlockRef(StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1000, 0x1010),),
        native_key=make_native_key(),
        exact_instruction_eas=(0x1004,),
    ))
    witness = model.SourceBlockIdentityWitness(
        ref, 0x1000, (0x1004,),
    )
    assert _source_witness_covers_semantic_point(
        witness, witness.native_instruction_eas[0],
    )
    assert not _source_witness_covers_semantic_point(
        witness, 0x1000,
    )
    assert _source_witness_covers_semantic_point(
        witness, 0x1000, allow_native_range_fallback=True,
    )
    assert not _source_witness_covers_semantic_point(
        witness, 0x1010, allow_native_range_fallback=True,
    )


def test_cloned_state_carrier_corridor_is_selected_by_its_typed_relation() -> None:
    """A cloned carrier corridor owns source -> feeder -> comparison -> target."""
    from dataclasses import replace

    from d810.analyses.control_flow import semantic_route_evidence as route
    from d810.transforms.cfg_transaction import NativeBlockRef, PlanBlockRef
    from d810.transforms.plan import PatchEdgeSplitCorridor, PatchPlan
    from d810.transforms.unflatten_authority import bind
    from d810.transforms.unflatten_authority.proposal import (
        canonical_patch_step_descriptors,
    )

    evidence, _graph, _stage = (
        __import__(
            "tests.unit.transforms.unflatten_authority.test_bind",
            fromlist=["_branch_x_canonical_replay_case"],
        )._branch_x_canonical_replay_case(
            route.SemanticRouteProofKind.STATE_CARRIER,
        )
    )
    base_proof = evidence.route_proofs[0]
    carrier = replace(base_proof.state_carrier, requires_feeder_clone=True)
    proof = replace(base_proof, state_carrier=carrier)
    source_ref = NativeBlockRef(carrier.source_identity)
    feeder_ref = NativeBlockRef(carrier.feeder_identity)
    comparison_ref = NativeBlockRef(carrier.comparison_entry_identity)
    destination_ref = NativeBlockRef(proof.destinations[0].target_identity)
    plan_id = authority_id("carrier-helper-corridor-plan")
    clone = PlanBlockRef(plan_id, "carrier-feeder-clone")
    plan = PatchPlan(
        plan_id=plan_id,
        snapshot_id=authority_id("carrier-helper-corridor-snapshot"),
        steps=(PatchEdgeSplitCorridor(
            (clone,), feeder_ref, source_ref, comparison_ref, destination_ref,
            feeder_ref, (feeder_ref,),
        ),),
    )
    descriptor = canonical_patch_step_descriptors(plan)[0]

    assert bind._state_carrier_helper_corridor_coordinates_match(
        plan, proof, descriptor,
    )
    from types import SimpleNamespace
    from d810.transforms.unflatten_authority import model
    facts = tuple(
        model.PatchStepEvidencePayload(
            plan.plan_id, descriptor.step_index, descriptor.step_type,
            owner_ref, descriptor.step_digest, descriptor.host_ea,
            descriptor.host_opcode, None,
        )
        for owner_ref in descriptor.owner_refs
    )
    selected = bind._select_lineage_fact_group(
        bind._index_lineage_fact_groups(plan, facts),
        plan=plan,
        claim=SimpleNamespace(
            source_subject=SimpleNamespace(
                locator=SimpleNamespace(block_ref=source_ref),
            ),
        ),
        proof=proof,
        source_inventory=SimpleNamespace(blocks=()),
    )
    assert selected.descriptor.step_index == 0
    wrong_plan = replace(
        plan,
        steps=(PatchEdgeSplitCorridor(
            (clone,), feeder_ref, source_ref, feeder_ref, destination_ref,
            feeder_ref, (feeder_ref,),
        ),),
    )
    assert not bind._state_carrier_helper_corridor_coordinates_match(
        wrong_plan, proof, canonical_patch_step_descriptors(wrong_plan)[0],
    )


def _exact_cloned_state_carrier_preparation_case(
    *,
    setup_tail: bool = False,
    implicit_feeder: bool = False,
    direct_state: bool = False,
    direct_source_bypass: bool = False,
    feeder_direct: bool = False,
    shared_source_bypass: bool = False,
    unclaimed_shared_bypass: bool = False,
    include_graphs: bool = False,
):
    """Build S -> F -> C -> N with only the physical feeder cloned."""
    assert sum((direct_source_bypass, feeder_direct, shared_source_bypass)) <= 1
    assert not unclaimed_shared_bypass or shared_source_bypass
    from d810.analyses.control_flow import semantic_route_evidence as route
    from d810.analyses.control_flow.graph_checks import (
        check_effectful_reachability_preserved,
        check_entry_reachability_not_collapsed,
        check_terminal_reachability_preserved,
    )
    from d810.analyses.control_flow.state_carrier import ExactCarrierStateWrite
    from d810.ir.block_identity import stable_block_identity_from_snapshot
    from d810.ir.expressions import ValueOpKind
    from d810.ir.flowgraph import (
        BlockKind, BlockSnapshot, ControlTransferKind, FlowGraph, InsnKind,
        InsnSnapshot, MopSnapshot, OperandKind, PredicateKind,
    )
    from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
    from d810.ir.varnode import Space, Varnode
    from d810.transforms.cfg_transaction import NativeBlockRef
    from d810.transforms.edit_simulator import project_post_state
    from d810.transforms.graph_modification import EdgeRedirectViaPredSplit
    from d810.transforms.unflatten_authority import model, producer_api
    from d810.transforms.unflatten_authority.gates import GenericCfgGateBundle
    from tests.typed_patch_authority import compile_patch_plan
    from tests.unit.analyses.control_flow.test_semantic_route_evidence import (
        NATIVE_KEY,
    )

    def goto(ea: int, target: int) -> InsnSnapshot:
        return InsnSnapshot(
            0, ea, (),
            d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=target),
            kind=InsnKind.GOTO, raw_opcode=0,
            control_transfer_kind=ControlTransferKind.GOTO,
            is_unconditional_jump=True,
        )

    state = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    state_mop = MopSnapshot(
        kind=OperandKind.STACK, size=4, stkoff=0x40, stack_refs=(0x40,),
    )
    source_blocks = {
        1: BlockSnapshot(
            1, 0, (2,), (), 0, 0x1100, (goto(0x1100, 2),),
            tail_opcode=0, kind=BlockKind.ONE_WAY,
            tail_kind=InsnKind.GOTO, raw_tail_opcode=0,
        ),
        2: BlockSnapshot(
            2, 0, (3,), (1,), 0, 0x1200,
            (
                InsnSnapshot(
                    0, 0x1200, (),
                    l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
                    d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=16),
                    kind=InsnKind.MOV, raw_opcode=0,
                    value_op_kind=ValueOpKind.MOVE,
                ),
                goto(0x1201, 3),
            ),
            tail_opcode=0, kind=BlockKind.ONE_WAY,
            tail_kind=InsnKind.GOTO, raw_tail_opcode=0,
        ),
        3: BlockSnapshot(
            3, 0, (4,), (2,), 0, 0x1300,
            (
                InsnSnapshot(
                    0, 0x1300, (),
                    l=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=16),
                    d=state_mop, kind=InsnKind.MOV, raw_opcode=0,
                    value_op_kind=ValueOpKind.MOVE,
                ),
                *(() if feeder_direct or shared_source_bypass else (InsnSnapshot(
                    0, 0x1301, (),
                    l=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=20),
                    d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=24),
                    kind=InsnKind.MOV, raw_opcode=0,
                    value_op_kind=ValueOpKind.MOVE,
                ),)),
                goto(0x1302, 4),
            ),
            tail_opcode=0, kind=BlockKind.ONE_WAY,
            tail_kind=InsnKind.GOTO, raw_tail_opcode=0,
        ),
        4: BlockSnapshot(
            4, 0, (6, 5), (3,), 0, 0x1400,
            (InsnSnapshot(
                0, 0x1400, (), l=state_mop,
                r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
                d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=5),
                kind=InsnKind.COND_JUMP, raw_opcode=0,
                control_transfer_kind=ControlTransferKind.CONDITIONAL_BRANCH,
                branch_predicate=PredicateKind.EQ,
                is_conditional_jump=True,
            ),),
            tail_opcode=0, kind=BlockKind.TWO_WAY,
            tail_kind=InsnKind.COND_JUMP, raw_tail_opcode=0,
        ),
        5: BlockSnapshot(
            5, 0, (), (4, 6), 0, 0x1500,
            (InsnSnapshot(0, 0x1500, (), kind=InsnKind.RET, raw_opcode=0),),
            tail_opcode=0, kind=BlockKind.ZERO_WAY,
            tail_kind=InsnKind.RET, raw_tail_opcode=0,
        ),
        6: BlockSnapshot(
            6, 0, (5,), (4,), 0, 0x1600,
            (goto(0x1600, 5),),
            tail_opcode=0, kind=BlockKind.ONE_WAY,
            tail_kind=InsnKind.GOTO, raw_tail_opcode=0,
        ),
    }
    if shared_source_bypass:
        source_blocks[3] = replace(source_blocks[3], preds=(2, 7))
        source_blocks[7] = BlockSnapshot(
            7, 0, (3,), (), 0, 0x1700,
            (
                InsnSnapshot(
                    0, 0x1700, (),
                    l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=8),
                    d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=16),
                    kind=InsnKind.MOV, raw_opcode=0,
                    value_op_kind=ValueOpKind.MOVE,
                ),
                goto(0x1701, 3),
            ),
            tail_opcode=0, kind=BlockKind.ONE_WAY,
            tail_kind=InsnKind.GOTO, raw_tail_opcode=0,
        )
    if setup_tail:
        source_blocks[3] = replace(
            source_blocks[3], succs=(7,),
            insn_snapshots=source_blocks[3].insn_snapshots[:-1] + (goto(0x1302, 7),),
        )
        source_blocks[7] = replace(
            source_blocks[3], serial=7, start_ea=0x1700, preds=(3,), succs=(4,),
            insn_snapshots=(replace(source_blocks[3].insn_snapshots[1], ea=0x1700), goto(0x1701, 4)),
        )
        source_blocks[4] = replace(source_blocks[4], preds=(7,))
        source_blocks[8] = replace(
            source_blocks[5], serial=8, start_ea=0x1800, preds=(),
            insn_snapshots=(replace(source_blocks[5].insn_snapshots[0], ea=0x1800),),
        )
    if direct_state:
        source_blocks[2] = replace(
            source_blocks[2],
            insn_snapshots=(replace(source_blocks[2].insn_snapshots[0], d=state_mop), *source_blocks[2].insn_snapshots[1:]),
        )
        source_blocks[3] = replace(
            source_blocks[3], insn_snapshots=(
                replace(source_blocks[3].insn_snapshots[1], ea=0x1300),
                *source_blocks[3].insn_snapshots[2:],
            ),
        )
    if implicit_feeder:
        source_blocks[3] = replace(
            source_blocks[3], insn_snapshots=source_blocks[3].insn_snapshots[:-1],
            tail_kind=InsnKind.MOV,
        )
    source = FlowGraph(source_blocks, entry_serial=1, func_ea=0x1000)
    identities = {
        serial: stable_block_identity_from_snapshot(block, native_key=NATIVE_KEY)
        for serial, block in source.blocks.items()
    }
    assert all(identity is not None for identity in identities.values())
    semantic_facts = [route.SemanticRouteFact(
            route.SemanticRouteFactKind.STATE_CARRIER,
            2, 2, 0x1200, 7, 5, 0x1200, 0x1500, (2,), (),
            carrier_witness=ExactCarrierStateWrite(
                state=7, source_serial=2, source_instruction_ea=0x1200,
                feeder_serial=3, comparison_entry_serial=4,
                carrier=Varnode(Space.STACK, 0x40, 4) if direct_state else Varnode(Space.REGISTER, 16, 4),
                state_identity=state,
                requires_feeder_clone=(
                    not feeder_direct and not shared_source_bypass
                ),
                clone_until_serial=7 if setup_tail else 3 if direct_state else None,
            ),
        )]
    if unclaimed_shared_bypass:
        semantic_facts.append(route.SemanticRouteFact(
            route.SemanticRouteFactKind.STATE_CARRIER,
            7, 7, 0x1700, 8, 6, 0x1700, 0x1600, (7,), (),
            carrier_witness=ExactCarrierStateWrite(
                state=8, source_serial=7, source_instruction_ea=0x1700,
                feeder_serial=3, comparison_entry_serial=4,
                carrier=Varnode(Space.REGISTER, 16, 4),
                state_identity=state,
                requires_feeder_clone=False,
            ),
        ))
    produced = route.build_canonical_semantic_evidence(
        tuple(semantic_facts),
        route.CanonicalSemanticEvidenceProductionContext(
            NATIVE_KEY, 1, authority_id("exact-cloned-carrier-evidence"),
            state, tuple(source.blocks.values()), tuple(identities.items()),
            source.entry_serial,
        ),
    )
    assert produced.abstention is None and produced.evidence is not None
    from . import test_bind
    if direct_source_bypass or feeder_direct or shared_source_bypass:
        from d810.transforms.graph_modification import RedirectGoto
        from d810.transforms.unflatten_authority import bind, transaction_api

        refs = {
            serial: NativeBlockRef(identities[serial])
            for serial in source.blocks
        }
        source_catalog = producer_api.build_source_identity_catalog(
            source, refs, native_key=produced.evidence.native_key,
            source_generation=produced.evidence.generation,
        )
        proof = next(
            item for item in produced.evidence.route_proofs
            if item.source_identity == identities[2]
        )
        claims = producer_api.build_equivalent_route_claims(
            source=source, source_catalog=source_catalog,
            route_evidence=produced.evidence,
            selected_proof_ids=(proof.proof_id,),
        )
        assert len(claims) == 1
        proposal = producer_api.build_proposal(
            plan_id=authority_id("exact-cloned-carrier-direct-plan"),
            source=source,
            block_refs_by_serial=refs,
            source_generation=produced.evidence.generation,
            canonical_route_evidence=produced.evidence,
            selected_route_proof_ids=(proof.proof_id,),
            exact_state_effect_exclusions=(),
            dispatcher_entry_serial=2,
            dispatcher_member_serials=tuple(source.blocks),
            authoritative_handler_serials=(),
            state_identity=state,
            use_def_witness=model.UseDefFragmentWitness(
                authority_id("exact-cloned-carrier-direct-fragment"),
                state, (refs[2],),
                authority_id("exact-cloned-carrier-direct-redirect"),
                True, True, 0, (),
            ),
        )
        direct_coordinates = (3, 4, 5) if feeder_direct else (2, 3, 5)
        modifications = [RedirectGoto(*direct_coordinates)]
        if unclaimed_shared_bypass:
            modifications.append(RedirectGoto(7, 3, 6))
        compiled = compile_patch_plan(
            modifications, source,
            plan_id=proposal.plan_id,
            source_generation=produced.evidence.generation,
            block_refs_by_serial=refs,
        )
        plan = replace(
            compiled,
            source_coordinates=tuple(
                (ref, serial) for serial, ref in refs.items()
            ),
            unflatten_proposal=proposal,
        )
        from d810.transforms.unflatten_authority.proposal import (
            canonical_redirect_manifest,
        )
        redirect_manifest = canonical_redirect_manifest(plan)
        proposal = replace(
            proposal,
            use_def_witness=replace(
                proposal.use_def_witness,
                redirect_owner_refs=redirect_manifest.owner_refs,
                redirect_digest=redirect_manifest.digest,
            ),
        )
        plan = replace(plan, unflatten_proposal=proposal)
        materialization = route.CanonicalRouteMaterialization.capture(
            source, generation=produced.evidence.generation,
            phase=route.CanonicalRouteAssessmentPhase.SOURCE,
        )
        source_inventory = transaction_api._build_semantic_graph_inventory(
            source, proposal, plan, source=True,
            phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
            materialization=materialization,
        )
        bound = bind.bind_source_route_authority(
            proposal=proposal, source_inventory=source_inventory,
            source_materialization=materialization,
        )
        assert type(bound) is model.SourceBoundRouteAuthorityAccepted
        projected_graph = project_post_state(source, plan)
        projected_inventory = transaction_api._build_semantic_graph_inventory(
            projected_graph, proposal, plan, source=False,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            materialization=None, source_subjects=source_inventory.subjects,
        )
        facts = transaction_api._derive_patch_lineage_facts(
            source_inventory, plan,
        )
        attempt = TransactionAttemptId(
            plan.plan_id, authority_id("exact-cloned-carrier-direct-session"),
            produced.evidence.generation,
            authority_id("exact-cloned-carrier-direct-attempt"),
        )
        values = (
            bound.authority, plan, source_inventory, projected_inventory,
            facts, attempt, refs,
        )
        return (*values, source, projected_graph) if include_graphs else values
    authority, plan, source_inventory, projected_inventory, facts, attempt = (
        test_bind._compile_corridor_from_canonical_evidence(
            source=source, evidence=produced.evidence,
            from_serial=3, old_target=7 if setup_tail else 4, new_target=5,
            predecessor_serial=2, clone_until=7 if setup_tail else 3, state_identity=state,
            tag="exact-cloned-carrier",
        )
    )
    refs = {serial: ref for ref, serial in source_inventory.serial_by_ref.items()}
    values = (
        authority, plan, source_inventory, projected_inventory, facts, attempt,
        refs,
    )
    return (*values, source, None) if include_graphs else values


def test_exact_cloned_carrier_rejects_direct_semantic_source_bypass() -> None:
    """A clone-required carrier cannot masquerade as an ordinary redirect."""
    from d810.transforms.unflatten_authority import model
    from . import test_bind

    authority, plan, source, projected, facts, attempt, _refs = (
        _exact_cloned_state_carrier_preparation_case(
            direct_source_bypass=True,
        )
    )
    result = test_bind.realize_projected_routes_for_test(
        source_authority=authority,
        plan=plan,
        source_inventory=source,
        projected_inventory=projected,
        patch_step_facts=facts,
        attempt_id=attempt,
    )

    assert type(result) is model.ProjectedRouteRealizationRejected
    assert (
        result.failures[0].stage
        is model.RouteRealizationFailureStage.UNSUPPORTED_REALIZATION_KIND
    )


def test_exact_noncloned_carrier_accepts_only_physical_feeder_redirect() -> None:
    """Non-cloned carrier direct authority belongs to its exact feeder edge."""
    from d810.transforms.unflatten_authority import model
    from . import test_bind

    authority, plan, source, projected, facts, attempt, refs = (
        _exact_cloned_state_carrier_preparation_case(feeder_direct=True)
    )
    result = test_bind.realize_projected_routes_for_test(
        source_authority=authority,
        plan=plan,
        source_inventory=source,
        projected_inventory=projected,
        patch_step_facts=facts,
        attempt_id=attempt,
    )

    assert type(result) is model.ProjectedRouteRealizationAccepted
    relation = result.realization.rows[0].relation
    assert type(relation) is model.DirectRouteRealization
    assert relation.feeder.ref == refs[3]
    assert relation.old_target.ref == refs[4]
    assert relation.new_target.ref == refs[5]


def test_exact_shared_feeder_carrier_accepts_source_specific_bypass() -> None:
    """A shared feeder needs one typed source-specific route per carrier state."""
    from d810.transforms.unflatten_authority import ids, model
    from . import test_bind

    authority, plan, source, projected, facts, attempt, refs = (
        _exact_cloned_state_carrier_preparation_case(
            shared_source_bypass=True,
        )
    )
    result = test_bind.realize_projected_routes_for_test(
        source_authority=authority,
        plan=plan,
        source_inventory=source,
        projected_inventory=projected,
        patch_step_facts=facts,
        attempt_id=attempt,
    )

    assert type(result) is model.ProjectedRouteRealizationAccepted
    relation = result.realization.rows[0].relation
    assert type(relation) is model.SharedCarrierSourceBypassRouteRealization
    assert relation.proof_source.ref == refs[2]
    assert relation.shared_feeder.ref == refs[3]
    assert relation.comparison_entry.ref == refs[4]
    assert relation.semantic_target.ref == refs[5]
    test_bind.bind.validate_projected_route_realization(result.realization)
    with pytest.raises(TypeError, match="transaction-owned"):
        copy(relation)
    with pytest.raises(TypeError, match="transaction-owned"):
        deepcopy(relation)
    with pytest.raises(TypeError, match="binder-owned"):
        model.SharedCarrierSourceBypassRouteRealization(
            relation.proof_source,
            relation.shared_feeder,
            relation.comparison_entry,
            relation.semantic_target,
            relation.relation_id,
        )
    forged = object.__new__(model.SharedCarrierSourceBypassRouteRealization)
    for field in fields(relation):
        object.__setattr__(forged, field.name, getattr(relation, field.name))
    object.__setattr__(forged, "relation_id", authority_id("forged-shared-carrier"))
    with pytest.raises(ValueError, match="relation_id"):
        ids.canonical_bytes(forged)
    with pytest.raises(ValueError, match="invalid record value"):
        ids.canonical_decode(ids.canonical_bytes(relation))


def test_shared_feeder_carrier_matcher_rejects_coordinate_and_topology_drift() -> None:
    """Every source/carrier/corridor coordinate is independently replayed."""
    from types import SimpleNamespace

    from d810.transforms.unflatten_authority import bind
    from d810.transforms.unflatten_authority.proposal import (
        canonical_patch_step_descriptors,
    )

    authority, plan, source, _projected, _facts, _attempt, refs = (
        _exact_cloned_state_carrier_preparation_case(
            shared_source_bypass=True,
        )
    )
    proof = authority.proposal.route_evidence.route_proofs[0]
    descriptor = canonical_patch_step_descriptors(plan)[0]
    assert bind._shared_state_carrier_source_bypass_coordinates_match(
        plan, proof, descriptor, source,
    )

    rows = {row.block_ref: row for row in source.blocks}

    def inventory(*changed):
        replacements = {row.block_ref: row for row in changed}
        return SimpleNamespace(
            blocks=tuple(replacements.get(row.block_ref, row) for row in source.blocks),
        )

    source_row = rows[refs[2]]
    feeder_row = rows[refs[3]]
    comparison_row = rows[refs[4]]
    for changed in (
        replace(source_row, successor_serials=(3, 4)),
        replace(feeder_row, predecessor_serials=(7,)),
        replace(feeder_row, predecessor_serials=(2,)),
        replace(feeder_row, successor_serials=(5,)),
        replace(comparison_row, predecessor_serials=()),
    ):
        assert not bind._shared_state_carrier_source_bypass_coordinates_match(
            plan, proof, descriptor, inventory(changed),
        )

    for index, wrong_ref in ((0, refs[7]), (1, refs[4]), (2, refs[6])):
        route_refs = list(descriptor.route_refs)
        route_refs[index] = wrong_ref
        assert not bind._shared_state_carrier_source_bypass_coordinates_match(
            plan, proof, replace(descriptor, route_refs=tuple(route_refs)), source,
        )


def test_shared_feeder_carrier_rejects_unclaimed_second_source_bypass() -> None:
    """Every exact source-specific bypass needs one unique claim owner."""
    from d810.transforms.unflatten_authority import model
    from . import test_bind

    authority, plan, source, projected, facts, attempt, _refs = (
        _exact_cloned_state_carrier_preparation_case(
            shared_source_bypass=True,
            unclaimed_shared_bypass=True,
        )
    )
    result = test_bind.realize_projected_routes_for_test(
        source_authority=authority,
        plan=plan,
        source_inventory=source,
        projected_inventory=projected,
        patch_step_facts=facts,
        attempt_id=attempt,
    )

    assert type(result) is model.ProjectedRouteRealizationRejected
    assert (
        result.failures[0].stage
        is model.RouteRealizationFailureStage.CLAIM_SELECTION
    )


def test_public_prepare_consumes_shared_carrier_source_bypass_relation() -> None:
    """The public transaction facade consumes the same sealed relation."""
    from d810.analyses.control_flow.graph_checks import (
        check_effectful_reachability_preserved,
        check_entry_reachability_not_collapsed,
        check_terminal_reachability_preserved,
    )
    from d810.transforms.unflatten_authority import model, transaction_api
    from d810.transforms.unflatten_authority.gates import GenericCfgGateBundle

    values = _exact_cloned_state_carrier_preparation_case(
        shared_source_bypass=True,
        include_graphs=True,
    )
    plan, attempt, source, projected = values[1], values[5], values[7], values[8]
    raw_effect = check_effectful_reachability_preserved(
        source, post_cfg=projected,
    )
    gates = GenericCfgGateBundle(
        check_entry_reachability_not_collapsed(source, post_cfg=projected),
        raw_effect,
        raw_effect,
        check_terminal_reachability_preserved(source, post_cfg=projected),
    )
    result = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=attempt,
        generic_gates=gates,
    )

    assert type(result) is model.UnflattenAuthorityPreparationAccepted
    prepared = result.prepared
    assert prepared is not None
    (row,) = prepared.projected_route_realization.rows
    assert type(row.relation) is model.SharedCarrierSourceBypassRouteRealization


@pytest.mark.parametrize("setup_tail,implicit_feeder,direct_state", ((False, False, False), (True, False, False), (True, True, False), (False, False, True), (True, True, True)))
def test_realization_mints_exact_cloned_carrier_with_distinct_semantic_source(setup_tail, implicit_feeder, direct_state) -> None:
    """Exact cloned carrier keeps semantic source distinct from physical feeder."""
    from d810.transforms.unflatten_authority import model
    from . import test_bind

    authority, plan, source, projected, facts, attempt, refs = (
        _exact_cloned_state_carrier_preparation_case(setup_tail=setup_tail, implicit_feeder=implicit_feeder, direct_state=direct_state)
    )
    result = test_bind.realize_projected_routes_for_test(
        source_authority=authority,
        plan=plan,
        source_inventory=source,
        projected_inventory=projected,
        patch_step_facts=facts,
        attempt_id=attempt,
    )

    assert type(result) is model.ProjectedRouteRealizationAccepted
    relation = result.realization.rows[0].relation
    assert type(relation).__name__ == "ClonedCarrierRouteCorridorRealization"
    assert relation.proof_source.ref == refs[2]
    assert relation.physical_feeder.ref == refs[3]
    assert tuple(item.ref for item in relation.source_corridor) == (
        (refs[3], refs[7]) if setup_tail else (refs[3],)
    )
    assert tuple(item.ref for item in relation.cloned_corridor) == plan.steps[0].clone_block_ids
    assert relation.comparison_entry.ref == refs[4]
    assert relation.semantic_target.ref == refs[5]


def test_entry_liveness_binding_allows_unrelated_multi_block_clone_facts() -> None:
    """One corridor step has one fact per cloned block, not an ambiguous entry."""
    from d810.transforms.edit_simulator import project_post_state
    values = _exact_cloned_state_carrier_preparation_case(setup_tail=True, include_graphs=True)
    _authority, plan, source_inventory, projected_inventory, facts, _attempt, _refs, source, _ = values
    assert len({fact.step_index for fact in facts}) < len(facts)
    projected = project_post_state(source, plan)
    assert transaction_api.bind_entry_endpoint_liveness_allowances(
        plan=plan, allowances=(), patch_step_facts=facts,
        source=source, projected=projected, source_inventory=source_inventory,
        projected_inventory=projected_inventory,
    ) == ()
    assert transaction_api._admit_bound_entry_endpoint_liveness(
        proposal=plan.unflatten_proposal, receipts=(), patch_step_facts=facts,
    ) == ()


@pytest.mark.parametrize(
    ("field", "wrong_ref"),
    (
        ("via_pred", 1),
        ("source_serial", 2),
        ("old_target", 3),
        ("new_target", 6),
    ),
)
def test_realization_rejects_mutated_exact_cloned_carrier_coordinate(
    field: str,
    wrong_ref: int,
) -> None:
    """Every exact carrier relation coordinate is transaction-bound."""
    from d810.transforms.unflatten_authority import model, transaction_api

    authority, plan, source, projected, _facts, attempt, refs = (
        _exact_cloned_state_carrier_preparation_case()
    )
    step = plan.steps[0]
    broken_plan = replace(
        plan,
        steps=(replace(step, **{field: refs[wrong_ref]}),),
    )
    facts = transaction_api._derive_patch_lineage_facts(source, broken_plan)
    from . import test_bind
    result = test_bind.realize_projected_routes_for_test(
        source_authority=authority,
        plan=broken_plan,
        source_inventory=source,
        projected_inventory=projected,
        patch_step_facts=facts,
        attempt_id=attempt,
    )

    assert type(result) is model.ProjectedRouteRealizationRejected


@pytest.mark.parametrize(
    ("field", "overlap_field"),
    (
        ("proof_source", "physical_feeder"),
        ("comparison_entry", "physical_feeder"),
        ("semantic_target", "physical_feeder"),
        ("cloned_corridor", "physical_feeder"),
    ),
)
def test_cloned_carrier_relation_rejects_overlapping_primary_roles(
    field: str,
    overlap_field: str,
) -> None:
    """Distinct carrier roles cannot be collapsed after structural selection."""
    from d810.transforms.unflatten_authority import model
    from . import test_bind

    authority, plan, source, projected, facts, attempt, _refs = (
        _exact_cloned_state_carrier_preparation_case()
    )
    result = test_bind.realize_projected_routes_for_test(
        source_authority=authority,
        plan=plan,
        source_inventory=source,
        projected_inventory=projected,
        patch_step_facts=facts,
        attempt_id=attempt,
    )
    assert type(result) is model.ProjectedRouteRealizationAccepted
    relation = result.realization.rows[0].relation
    assert type(relation) is model.ClonedCarrierRouteCorridorRealization

    candidate = object.__new__(type(relation))
    for name in relation.__dataclass_fields__:
        object.__setattr__(candidate, name, getattr(relation, name))
    overlapping = getattr(relation, overlap_field)
    if field == "cloned_corridor":
        overlapping = (overlapping,)
    object.__setattr__(candidate, field, overlapping)

    with pytest.raises(
        ValueError,
        match=(
            "carrier (proof source and physical feeder must differ|"
            "relation roles are incoherent)"
        ),
    ):
        candidate.__post_init__()


def test_local_alias_claim_is_derived_before_authority_id() -> None:
    """A scalarization step is transaction authority, not producer metadata."""
    from d810.transforms.unflatten_authority import model, transaction_api
    from . import test_bind
    _authority, plan, source_inventory, _projected, _facts, _attempt = test_bind._compiler_direct_branch_case(two_local_aliases=True)
    derived = transaction_api._derive_transaction_facts(source_inventory, plan)
    claims = tuple(claim for claim in derived.claims if type(claim) is model.LocalAliasEffectScalarizationClaim)
    assert len(claims) == 2
    assert {fact.step_digest for fact in derived.patch_step_facts} >= {claim.step_digest for claim in claims}
    alias_index = next(index for index, step in enumerate(plan.steps) if type(step).__name__ == "PatchScalarizeLocalAliasAccess")
    mutated_steps = list(plan.steps)
    mutated_steps[alias_index] = replace(mutated_steps[alias_index], alias_token="mutated-alias")
    with pytest.raises(ValueError, match="tokens"):
        transaction_api._derive_transaction_facts(source_inventory, replace(plan, steps=tuple(mutated_steps)))


def test_local_alias_source_coordinate_uses_catalog_binding_not_route_binding() -> None:
    """Scalar ownership remains source-catalog-bound despite a route-local anchor.

    A canonical route may legitimately bind an interior native EA of the same
    source block.  That role-specific binding is not authority for a planner
    scalarization: the step's typed source coordinate must select the immutable
    source-catalog block binding, then projected MOV validation happens later.
    """
    from d810.transforms.unflatten_authority.ids import (
        _subject_factory,
        semantic_graph_inventory_digest,
    )

    _authority, plan, source_inventory, _projected, _facts, _attempt = (
        __import__(
            "tests.unit.transforms.unflatten_authority.test_bind",
            fromlist=["_compiler_direct_branch_case"],
        )._compiler_direct_branch_case(two_local_aliases=True)
    )
    step = next(
        item for item in plan.steps
        if type(item).__name__ == "PatchScalarizeLocalAliasAccess"
        and item.host_ea == 0x1000
    )
    source_binding = next(
        item for item in source_inventory.bindings
        if item.block_ref == step.block_serial
        and item.role is model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK
    )
    alternate_anchor = next(
        ea for ea in source_binding.native_instruction_eas
        if ea != source_binding.anchor_ea
    )
    route_subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
        block_ref=step.block_serial,
        anchor_ea=alternate_anchor,
        locator=model.BlockSubjectLocator(step.block_serial, alternate_anchor),
    )
    route_binding = model.PhaseSubjectBinding(
        subject=route_subject,
        phase=source_inventory.phase,
        block_ref=step.block_serial,
        graph_fingerprint=source_inventory.graph_fingerprint,
        generation=source_inventory.generation,
        status=model.SubjectBindingStatus.UNIQUE,
        serial=source_binding.serial,
        anchor_ea=alternate_anchor,
        native_instruction_eas=source_binding.native_instruction_eas,
        role=route_subject.role,
    )
    subjects = tuple(sorted(
        (*source_inventory.subjects, route_subject),
        key=lambda item: item.subject_id,
    ))
    bindings = tuple(sorted(
        (*source_inventory.bindings, route_binding),
        key=lambda item: item.subject.subject_id,
    ))
    source_subject_ids = tuple(sorted(
        (*source_inventory.source_subject_ids, route_subject.subject_id),
    ))
    source_with_route_local_binding = replace(
        source_inventory,
        subjects=subjects,
        bindings=bindings,
        source_subject_ids=source_subject_ids,
        inventory_digest=semantic_graph_inventory_digest(
            source_inventory.phase,
            source_inventory.graph_fingerprint,
            source_inventory.generation,
            source_inventory.blocks,
            subjects,
            bindings,
            source_inventory.effects,
            source_inventory.terminals,
            source_inventory.topology,
            source_inventory.reachable_serials,
            source_inventory.entry_serial,
            source_subject_ids,
            source_inventory.function_ea,
            source_inventory.observed_route_topology_occurrences,
            source_inventory.observed_lowered_conditional_topology_occurrences,
        ),
    )
    model.validate_semantic_graph_inventory(source_with_route_local_binding)

    occurrences, facts, relations = transaction_api._derive_local_alias_transaction_facts(
        source_with_route_local_binding,
        plan,
    )

    assert len(occurrences) == 2
    scalar_claim = next(
        item.claim for item in occurrences
        if item.claim.host_ea == step.host_ea
    )
    assert scalar_claim.owner_subject.anchor_ea == source_binding.anchor_ea
    assert len(facts) == 2
    assert len(relations) == 2

    foreign_owner = next(
        ref for ref, _serial in plan.source_coordinates
        if ref != step.block_serial
    )
    foreign_steps = tuple(
        replace(item, block_serial=foreign_owner) if item is step else item
        for item in plan.steps
    )
    with pytest.raises(ValueError, match="owner is not uniquely bound"):
        transaction_api._derive_local_alias_transaction_facts(
            source_with_route_local_binding,
            replace(plan, steps=foreign_steps),
        )

    stale_coordinates = tuple(
        (ref, 3 if ref == step.block_serial else serial)
        for ref, serial in plan.source_coordinates
    )
    with pytest.raises(ValueError, match="owner binding is stale"):
        transaction_api._derive_local_alias_transaction_facts(
            source_with_route_local_binding,
            replace(plan, source_coordinates=stale_coordinates),
        )



def test_prepare_rejects_projected_route_carrier_interference() -> None:
    """A projected extra carrier writer cannot inherit source route authority."""
    from dataclasses import replace

    from d810.ir.expressions import ValueOpKind
    from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
    from d810.transforms.cfg_transaction import CfgProjection, TransactionAttemptId
    from d810.transforms.unflatten_authority import transaction_api
    from d810.transforms.unflatten_authority.model import (
        GenericCfgGateKind,
        GenericCfgGateResult,
    )

    source, proposal, _exclusion, refs = __import__(
        "tests.unit.transforms.unflatten_authority.test_bind",
        fromlist=["_exact_fixture"],
    )._exact_fixture()
    from d810.transforms.plan import PatchRedirectGoto
    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest

    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("snapshot-carrier-interference"),
        source_generation=1,
        steps=(PatchRedirectGoto(refs[0], refs[1], refs[2]),),
        source_coordinates=tuple((ref, serial) for serial, ref in refs.items()),
        unflatten_proposal=proposal,
    )
    proposal = replace(
        proposal,
        use_def_witness=replace(
            proposal.use_def_witness,
            redirect_owner_refs=canonical_redirect_manifest(plan).owner_refs,
            redirect_digest=canonical_redirect_manifest(plan).digest,
        ),
    )
    plan = replace(plan, unflatten_proposal=proposal)
    branch_block = source.blocks[1]
    candidate = replace(
        source,
        blocks={
            **source.blocks,
            1: replace(
                branch_block,
                insn_snapshots=(
                    InsnSnapshot(
                        0,
                        0x2000,
                        (),
                        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=8),
                        d=MopSnapshot(
                            kind=OperandKind.STACK,
                            size=4,
                            stkoff=4,
                            stack_refs=(4,),
                        ),
                        kind=InsnKind.MOV,
                        value_op_kind=ValueOpKind.MOVE,
                    ),
                    branch_block.insn_snapshots[1],
                ),
            ),
        },
    )
    result = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, candidate),
        plan=plan,
        attempt_id=TransactionAttemptId(
            plan.plan_id, "session-carrier-interference", 1, "attempt-carrier-interference"
        ),
        generic_gates=tuple(
            GenericCfgGateResult(kind, True, (), (), "fixture")
            for kind in (
                GenericCfgGateKind.ENTRY_REACHABILITY,
                GenericCfgGateKind.EFFECTFUL_REACHABILITY,
                GenericCfgGateKind.TERMINAL_REACHABILITY,
            )
        ),
    )

    assert getattr(result, "prepared", None) is None
    assert result.verdict.reason.name == "PROJECTED_BINDING_FAILED"
