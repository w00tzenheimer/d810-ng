"""Focused total route-selection tests for the transaction facade."""

from __future__ import annotations

from dataclasses import fields, replace
from inspect import signature

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
from d810.transforms.unflatten_authority.ids import authority_id

from .helpers import (
    authority_id as helper_authority_id,
    block_ref,
    exact_fixture,
    import_authority_model,
)
from .test_model import _valid_proposal


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
    assert not hasattr(new_plan, "legacy_unflatten_shadow")
    assert reserved_metadata_keys(new_plan) == ()

    # The decisive transaction path must not retain a replay/capture branch or
    # call any of the legacy graph validators/canonicalizer.
    transaction_source = __import__(
        "inspect", fromlist=["getsource"]
    ).getsource(patch_transaction)
    authority_source = __import__(
        "inspect", fromlist=["getsource"]
    ).getsource(transaction_api)
    for source in (transaction_source, authority_source):
        assert "_validated_exact_effect_exclusions" not in source
        assert "validate_dispatcher_corridor_coverage_metadata" not in source
        assert "validate_dispatcher_removal_preflight_proof" not in source
        assert "validate_terminal_switch_cycle_break_allowance" not in source
        assert "canonicalize_observed_dispatcher_graph" not in source
        assert "_LegacyEffectReplay" not in source
        assert "_LegacyGateDecision" not in source
        assert "_legacy_phase_outcome" not in source
        assert "_validated_effect_exclusion_serials" not in source
        assert "legacy_shadow" not in source
        assert "shadow_parity" not in source

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
    source, plan, projected, gates = _full_corridor_fixture()
    attempt = TransactionAttemptId(
        plan.plan_id, authority_id("compatibility-session"), 1,
        authority_id("compatibility-attempt"),
    )
    prepared = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=attempt,
        generic_gates=gates,
    )
    assert prepared.prepared is not None
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
                block_ref("b2"),
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
    from d810.transforms.edit_simulator import project_patch_plan
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
        (InsnSnapshot(0, 0x5000, (), kind=InsnKind.GOTO),),
        kind=BlockKind.ONE_WAY,
    )
    blocks[5] = BlockSnapshot(
        5, 0, (0, 6), (4,), 0, 0x6000,
        (InsnSnapshot(0, 0x6000, (), kind=InsnKind.COND_JUMP),),
        kind=BlockKind.TWO_WAY,
    )
    blocks[6] = BlockSnapshot(
        6, 0, (0,), (5,), 0, 0x7000,
        (InsnSnapshot(0, 0x7000, (), kind=InsnKind.GOTO),),
        kind=BlockKind.ONE_WAY,
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
        steps=(PatchRedirectBranch(refs[5], refs[6], refs[0]),),
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
    projected = project_patch_plan(source, plan, snapshot_id=plan.snapshot_id).graph
    projected_blocks = {
        serial: block for serial, block in projected.blocks.items()
        if serial != 6
    }
    projected_blocks[0] = replace(projected_blocks[0], preds=(5,))
    projected_blocks[5] = replace(
        projected_blocks[5], succs=(0,), kind=BlockKind.ONE_WAY,
    )
    projected = type(projected)(projected_blocks, projected.entry_serial, projected.func_ea)
    gates = GenericCfgGateBundle(
        check_entry_reachability_not_collapsed(source, post_cfg=projected),
        check_effectful_reachability_preserved(source, post_cfg=projected),
        check_effectful_reachability_preserved(source, post_cfg=projected),
        check_terminal_reachability_preserved(source, post_cfg=projected),
    )
    return source, plan, projected, gates


def test_full_corridor_public_lifecycle_uses_sealed_nonempty_forecast(monkeypatch) -> None:
    """A real covered corridor survives prepare, bind, and observed revalidation."""

    from d810.transforms import dispatcher_corridor_coverage
    from d810.transforms.cfg_transaction import TransactionAttemptId
    from d810.transforms.unflatten_authority import transaction_api

    source, plan, projected, gates = _full_corridor_fixture()
    attempt = TransactionAttemptId(
        plan.plan_id, authority_id("full-corridor-session"), 1,
        authority_id("full-corridor-attempt"),
    )
    monkeypatch.setattr(
        dispatcher_corridor_coverage, "analyze_dispatcher_corridor_coverage",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("analyzer called after attachment")),
    )
    prepared_result = transaction_api.prepare_unflatten_authority(
        source=source, projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan, attempt_id=attempt, generic_gates=gates,
    )
    assert getattr(prepared_result, "prepared", None) is not None, (
        getattr(prepared_result, "verdict", prepared_result),
        getattr(getattr(prepared_result, "verdict", None), "reason", None),
        getattr(getattr(prepared_result, "verdict", None), "failed_obligations", ()),
    )
    forecast = prepared_result.prepared.source_inputs.proposal.corridor_coverage_forecast
    assert forecast is not None and forecast.paths and forecast.enumeration_complete
    phase_result = prepared_result.prepared.source_inputs.corridor_coverage_phase_result
    assert phase_result is not None and phase_result.full
    assert phase_result.source_dispatcher_reachable
    assert not phase_result.candidate_dispatcher_reachable

    # Continue through the public binder with the same closed forecast and
    # receipt.  The observed phase must consume the bound authority rather
    # than re-running the producer or legacy corridor adapters.
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
        bindings=tuple(
            (ref.identity, serial)
            for ref, serial in plan.source_coordinates
        ),
    )
    index.begin_transaction(attempt, quantity=len(source.blocks))
    patch_binding = bind_patch_plan(plan, index, attempt).bound_plan
    bound_result = transaction_api.bind_prepared_unflatten_authority(
        prepared=prepared_result.prepared,
        patch_binding=patch_binding,
    )
    assert bound_result.authority is not None, getattr(bound_result, "verdict", bound_result)
    bound_forecast = bound_result.authority.prepared.source_inputs.proposal.corridor_coverage_forecast
    assert bound_forecast is not None
    assert bound_forecast.forecast_id == forecast.forecast_id
    assert bound_result.authority.prepared.source_inputs.corridor_coverage_phase_result.result_id == phase_result.result_id
    observed_result = transaction_api.revalidate_observed_unflatten_authority(
        authority=bound_result.authority,
        observed=projected,
        observed_generation=attempt.generation,
        generic_gates=gates,
    )
    assert observed_result.accepted, getattr(observed_result, "verdict", observed_result)
    observed_phase = observed_result.safety_case.corridor_coverage_phase_result
    assert observed_phase is not None
    assert observed_phase.forecast_id == forecast.forecast_id
    assert observed_phase.full


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
    """Aggregate coverage cannot authorize unrelated retained topology drift."""

    from d810.ir.flowgraph import BlockKind
    from d810.transforms.cfg_transaction import TransactionAttemptId
    from d810.transforms.unflatten_authority import model
    from d810.transforms.unflatten_authority import transaction_api

    source, plan, projected, gates = _full_corridor_fixture()
    blocks = dict(projected.blocks)
    blocks[5] = replace(blocks[5], succs=(0, 2), kind=BlockKind.TWO_WAY)
    blocks[2] = replace(blocks[2], preds=tuple(sorted(set(blocks[2].preds + (5,)))))
    drifted = type(projected)(blocks, projected.entry_serial, projected.func_ea)
    attempt = TransactionAttemptId(
        plan.plan_id, authority_id("retained-feeder-drift-session"), 1,
        authority_id("retained-feeder-drift-attempt"),
    )
    prepared_result = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=attempt,
        generic_gates=gates,
    )
    assert prepared_result.prepared is not None
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
    patch_binding = bind_patch_plan(plan, index, attempt).bound_plan
    bound_result = transaction_api.bind_prepared_unflatten_authority(
        prepared=prepared_result.prepared,
        patch_binding=patch_binding,
    )
    assert bound_result.authority is not None
    result = transaction_api.revalidate_observed_unflatten_authority(
        authority=bound_result.authority,
        observed=drifted,
        observed_generation=attempt.generation,
        generic_gates=gates,
    )
    assert not result.accepted
    failed = {
        (item.key.subject.role, item.key.subject.anchor_ea, item.key.dimension)
        for item in result.failed_obligations
    }
    assert (
        model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
        0x6000,
        model.SafetyDimension.TOPOLOGY_INTEGRITY,
    ) in failed


def test_retirement_public_prepare_projects_canonical_case_obligations(monkeypatch) -> None:
    """A typed partial retirement preserves its case-owned structural rows."""

    from d810.transforms.unflatten_authority import transaction_api, views
    from d810.transforms.unflatten_authority.gates import GenericCfgGateBundle
    from d810.analyses.control_flow.graph_checks import (
        check_effectful_reachability_preserved,
        check_entry_reachability_not_collapsed,
        check_terminal_reachability_preserved,
    )

    model = import_authority_model()
    source, plan, projected, _gates = _full_corridor_fixture()
    projected = type(projected)(
        {
            **projected.blocks,
            5: replace(projected.blocks[5], succs=(1,)),
        },
        projected.entry_serial,
        projected.func_ea,
    )
    monkeypatch.setattr(
        "d810.transforms.dispatcher_corridor_coverage.analyze_dispatcher_corridor_coverage",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("legacy analyzer called")),
    )
    projection = CfgProjection(plan.plan_id, plan.snapshot_id, projected)
    from d810.transforms.cfg_transaction import TransactionAttemptId
    generic_gates = GenericCfgGateBundle(
        check_entry_reachability_not_collapsed(source, post_cfg=projected),
        check_effectful_reachability_preserved(source, post_cfg=projected),
        check_effectful_reachability_preserved(source, post_cfg=projected),
        check_terminal_reachability_preserved(source, post_cfg=projected),
    )
    attempt = TransactionAttemptId(
        plan.plan_id, authority_id("retirement-session"), 1,
        authority_id("retirement-attempt"),
    )
    result = transaction_api.prepare_unflatten_authority(
        source=source, projection=projection, plan=plan,
        attempt_id=attempt, generic_gates=generic_gates,
    )
    assert result.prepared is not None
    assert result.verdict.accepted
    assert result.verdict.reason is model.UnflattenAuthorityReason.ACCEPTED
    assert result.verdict.case_id == result.prepared.projected_case.case_id
    assert result.verdict.safety_case is result.prepared.projected_case
    case = result.prepared.projected_case
    retirement_view = views.retirement_rows(case)
    assert retirement_view.retired_member_subject_ids
    assert retirement_view.retained_member_subject_ids
    assert any(
        cell.key.dimension is model.SafetyDimension.STRUCTURAL_ACCOUNTING
        and cell.state is model.ObligationState.SATISFIED
        for cell in case.obligation_index.cells
        if cell.key.subject.subject_id in retirement_view.retired_member_subject_ids
    )
    assert any(
        cell.key.dimension is model.SafetyDimension.STRUCTURAL_ACCOUNTING
        and cell.state is model.ObligationState.SATISFIED
        for cell in case.obligation_index.cells
        if cell.key.subject.subject_id in retirement_view.retained_member_subject_ids
    )
    ledger = views.semantic_loss_ledger(case)
    retired_rows = tuple(
        row for row in ledger.rows
        if row.source_subject.subject_id in retirement_view.retired_member_subject_ids
    )
    assert len(retired_rows) == len(retirement_view.retired_member_subject_ids)
    assert all(
        row.kind is model.SemanticLossKind.RETIRED_DISPATCHER_INFRASTRUCTURE
        and row.claim_ids == (retirement_view.claim_id,)
        and any(
            justification.rule is model.UnflattenJustificationRule.RETIRED_INFRASTRUCTURE_PROVEN
            and justification.claim_id == retirement_view.claim_id
            for justification in row.justifications
        )
        for row in retired_rows
    )
    coverage_view = views.corridor_coverage_rows(case)
    assert coverage_view.state is model.ObligationState.SATISFIED
    assert not result.verdict.failed_obligations


def test_helper_and_resegmentation_lineage_is_derived_before_case_builder(monkeypatch) -> None:
    """Helper ownership must enter the closed facts before case construction."""

    from d810.transforms.unflatten_authority import transaction_api

    source, proposal, _exclusion, refs = exact_fixture()
    from d810.ir.block_identity import StableBlockIdentity
    from d810.ir.flowgraph import InsnKind, InsnSnapshot
    from d810.transforms.unflatten_authority import producer_api
    source = replace(
        source,
        blocks={
            **source.blocks,
            4: replace(
                source.blocks[4],
                insn_snapshots=(
                    source.blocks[4].insn_snapshots[0],
                    InsnSnapshot(0, 0x5001, (), kind=InsnKind.NOP),
                ),
            ),
        },
    )
    refs = {
        **refs,
        4: type(refs[4])(
            StableBlockIdentity.from_instruction_eas(
                (0x5000, 0x5001), native_key=refs[4].identity.native_key,
            )
        ),
    }
    proposal = producer_api.build_proposal(
        plan_id=proposal.plan_id,
        source=source,
        block_refs_by_serial=refs,
        source_generation=proposal.source_identity_catalog.generation,
        canonical_route_evidence=proposal.route_evidence,
        exact_state_effect_exclusions=(_exclusion,),
        dispatcher_entry_serial=1,
        dispatcher_member_serials=(0, 1),
        authoritative_handler_serials=(2,),
        state_identity=proposal.plan_inputs.state_identity,
        use_def_witness=proposal.use_def_witness,
    )
    helper = PlanBlockRef(proposal.plan_id, "fallthrough-helper")
    second_helper = PlanBlockRef(proposal.plan_id, "second-helper")
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=helper_authority_id("snapshot-lineage"),
        source_generation=1,
        steps=(
            PatchRedirectBranch(refs[0], refs[1], refs[2], helper),
            PatchRedirectBranch(refs[1], refs[2], refs[0], second_helper),
        ),
        source_coordinates=tuple((ref, serial) for serial, ref in refs.items()),
        new_blocks=(
            PatchBlockSpec(helper, "insert_block", template_block=refs[4]),
            PatchBlockSpec(second_helper, "insert_block", template_block=refs[4]),
        ),
        unflatten_proposal=proposal,
    )
    projected = type(source)(
        {serial: block for serial, block in source.blocks.items() if serial != 4}
        | {
            4: replace(
                source.blocks[4], serial=4,
                insn_snapshots=(source.blocks[4].insn_snapshots[0],),
            ),
                5: replace(
                    source.blocks[4], serial=5,
                    start_ea=0x5001,
                    insn_snapshots=(source.blocks[4].insn_snapshots[1],),
            ),
        },
        source.entry_serial, source.func_ea,
    )
    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest
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
    projection = CfgProjection(plan.plan_id, plan.snapshot_id, projected)

    inputs = transaction_api.derive_unflatten_preparation_inputs(
        source, projection, plan, proposal, None,
    )

    assert tuple(
        (fact.step_type, fact.owner_ref)
        for fact in inputs.patch_step_facts
    ) == (
        ("PatchRedirectBranch", refs[0]),
        ("PatchRedirectBranch", helper),
        ("PatchRedirectBranch", refs[1]),
        ("PatchRedirectBranch", second_helper),
    )
    case = transaction_api.build_semantic_case(
        authority_id=helper_authority_id("lineage-case"),
        phase=import_authority_model().UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=inputs,
    )
    assert case.evidence
    assert any(
        getattr(item.payload, "owner_ref", None) == helper
        for item in case.evidence
    )

    from d810.analyses.control_flow.graph_checks import (
        check_effectful_reachability_preserved,
        check_entry_reachability_not_collapsed,
        check_terminal_reachability_preserved,
    )
    from d810.transforms.cfg_transaction import TransactionAttemptId
    from d810.transforms.unflatten_authority.gates import GenericCfgGateBundle
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.hexrays.mutation.patch_binding import bind_patch_plan

    index = MbaBlockIdentityIndex.from_bindings(
        generation=1,
        maturity=None,
        native_key=refs[0].identity.native_key,
        snapshot_id=plan.snapshot_id,
        session_id=helper_authority_id("lineage-session"),
        bindings=tuple((ref.identity, serial) for serial, ref in refs.items()),
    )
    attempt = TransactionAttemptId(
        plan.plan_id, index.session_id, 1,
        helper_authority_id("lineage-attempt"),
    )
    generic_gates = GenericCfgGateBundle(
        check_entry_reachability_not_collapsed(source, post_cfg=source),
        check_effectful_reachability_preserved(source, post_cfg=source),
        check_effectful_reachability_preserved(source, post_cfg=source),
        check_terminal_reachability_preserved(source, post_cfg=source),
    )
    prepared_result = transaction_api.prepare_unflatten_authority(
        source=source, projection=projection, plan=plan,
        attempt_id=attempt, generic_gates=generic_gates,
    )
    assert getattr(prepared_result, "prepared", None) is not None, getattr(
        prepared_result, "verdict", prepared_result,
    )
    index.begin_transaction(attempt, quantity=len(source.blocks))
    patch_binding = bind_patch_plan(plan, index, attempt).bound_plan
    bound_result = transaction_api.bind_prepared_unflatten_authority(
        prepared=prepared_result.prepared, patch_binding=patch_binding,
    )
    assert getattr(bound_result, "authority", None) is not None, getattr(bound_result, "verdict", bound_result)
    live_observed = type(source)(
        {serial: block for serial, block in source.blocks.items() if serial != 4}
        | {
            5: replace(
                source.blocks[4], serial=5,
                insn_snapshots=(source.blocks[4].insn_snapshots[0],),
            ),
            6: replace(
                source.blocks[4], serial=6,
                start_ea=0x5001,
                insn_snapshots=(source.blocks[4].insn_snapshots[1],),
            ),
        },
        source.entry_serial, source.func_ea,
    )
    observed_result = transaction_api.revalidate_observed_unflatten_authority(
        authority=bound_result.authority, observed=live_observed,
        observed_generation=attempt.generation, generic_gates=generic_gates,
    )
    assert observed_result.accepted


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
        _subject_factory,
        semantic_graph_inventory_digest,
    )
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
        subjects = tuple(sorted(
            (*inventory.subjects, *added_subjects), key=lambda item: item.subject_id,
        ))
        bindings = tuple(sorted((
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
        ), key=lambda item: item.subject.subject_id))
        source_subject_ids = tuple(sorted(
            (*inventory.source_subject_ids,
             *(subject.subject_id for subject in added_subjects)),
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

    source = with_plan_catalog_subjects(source)
    projected = with_plan_catalog_subjects(projected)
    base = model.ProposedUnflattenContract(**_valid_proposal(model))
    catalog = model.SourceIdentityCatalog(
        base.source_identity_catalog.native_key,
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
        path_id, path_nodes, None,
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
        CanonicalSemanticEvidence,
        SemanticRouteDestination,
        SemanticRouteProof,
        SemanticRouteProofKind,
        SemanticRouteShape,
    )
    from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
    from d810.ir.semantic_edge import SemanticEdgeRole

    route_destination_ref = claim.retained_handler_subjects[0].block_ref
    route_source = by_ref[entry_ref]
    route_destination = by_ref[route_destination_ref]
    route_proof = SemanticRouteProof(
        authority_id("derived-detached-route"),
        authority_id("derived-detached-route-group"),
        SemanticRouteProofKind.BOOTSTRAP, SemanticRouteShape.DIRECT,
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
    route_evidence = CanonicalSemanticEvidence(
        catalog.native_key, source.generation,
        authority_id("derived-detached-route-group"), (route_proof,),
    )

    def with_route_expansion(inventory):
        route_subject = _subject_factory(
            model.SemanticSubjectRef,
            kind=model.SemanticSubjectKind.ROUTE,
            role=model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
            block_ref=entry_ref, anchor_ea=route_source.anchor_ea,
            locator=model.RouteSubjectLocator(
                route_proof.proof_id, route_proof.atomic_group_id,
                entry_ref, route_source.anchor_ea, (route_destination_ref,),
                (route_destination.anchor_ea,),
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
        added = (route_subject, destination_subject)
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
        claims=(claim,),
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
        steps=(PatchRedirectGoto(entry_ref, dispatcher_ref, route_destination_ref),),
    )
    projected_metrics = model.PhaseBuildMetrics(
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, 1, 1, 0.0,
    )
    preparation_metrics = model.PreparationBuildMetrics(1, 1, 0.0)
    projected_inputs = transaction_api._derive_inputs(
        source, projected, plan, proposal, None,
        phase_build_metrics=projected_metrics,
        preparation_metrics=preparation_metrics,
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


def test_prepare_derives_closed_inputs_and_bind_consumes_exact_bound_patch_plan(monkeypatch) -> None:
    """The transaction facade owns preparation and the exact live bind."""

    from types import SimpleNamespace
    from d810.transforms.cfg_transaction import CfgProjection, TransactionAttemptId
    from d810.transforms.unflatten_authority import transaction_api
    from d810.transforms.unflatten_authority import producer_api
    from d810.analyses.control_flow import graph_checks

    assert tuple(signature(transaction_api.prepare_unflatten_authority).parameters) == (
        "source", "projection", "plan", "attempt_id", "generic_gates",
    )
    assert tuple(signature(transaction_api.bind_prepared_unflatten_authority).parameters) == (
        "prepared", "patch_binding",
    )
    assert tuple(signature(transaction_api.revalidate_observed_unflatten_authority).parameters) == (
        "authority", "observed", "observed_generation", "generic_gates",
    )

    source, proposal, _exclusion, refs = __import__(
        "tests.unit.transforms.unflatten_authority.test_bind",
        fromlist=["_exact_fixture"],
    )._exact_fixture()
    from d810.transforms.plan import PatchRedirectGoto
    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("snapshot-exact"),
        source_generation=1,
        steps=(PatchRedirectGoto(refs[0], refs[1], refs[2]), PatchRedirectGoto(refs[1], refs[2], refs[0])),
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
    projection = CfgProjection(plan.plan_id, plan.snapshot_id, source)
    attempt = TransactionAttemptId(
        plan.plan_id, "session-exact", 1, "attempt-exact",
    )
    from d810.analyses.control_flow.graph_checks import (
        check_effectful_reachability_preserved,
        check_entry_reachability_not_collapsed,
        check_terminal_reachability_preserved,
    )
    from d810.transforms.unflatten_authority.gates import GenericCfgGateBundle
    generic_gates = GenericCfgGateBundle(
        check_entry_reachability_not_collapsed(source, post_cfg=source),
        check_effectful_reachability_preserved(source, post_cfg=source),
        check_effectful_reachability_preserved(source, post_cfg=source),
        check_terminal_reachability_preserved(source, post_cfg=source),
    )
    build_calls = []
    original_builder = transaction_api._build_semantic_graph_inventory

    def counted_builder(*args, **kwargs):
        result = original_builder(*args, **kwargs)
        build_calls.append(result)
        return result

    monkeypatch.setattr(transaction_api, "_build_semantic_graph_inventory", counted_builder)
    prepared_result = transaction_api.prepare_unflatten_authority(
        source=source, projection=projection, plan=plan,
        attempt_id=attempt, generic_gates=generic_gates,
    )
    assert getattr(prepared_result, "prepared", None) is not None, getattr(prepared_result, "verdict", prepared_result)
    assert prepared_result.prepared.source_inventory is prepared_result.prepared.source_inputs.source_inventory
    assert len(build_calls) == 2
    assert len(prepared_result.prepared.source_inventory.blocks) == len(source.blocks)
    assert set(prepared_result.prepared.source_inventory.reachable_serials) <= set(source.blocks)
    derived_inputs = transaction_api.derive_unflatten_preparation_inputs(
        source, projection, plan, proposal, generic_gates,
    )
    from d810.transforms.unflatten_authority import model
    derived_case = transaction_api.build_semantic_case(
        authority_id=authority_id("legacy-derived-inputs"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=derived_inputs,
    )
    assert derived_case.phase is model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
    from d810.analyses.control_flow.semantic_route_evidence import CanonicalRouteAssessmentPhase
    candidate_assessment = prepared_result.prepared.source_inputs.candidate_route_assessment
    assert candidate_assessment is not None
    original_assessment_phase = candidate_assessment.phase
    object.__setattr__(candidate_assessment, "phase", CanonicalRouteAssessmentPhase.OBSERVED)
    with pytest.raises(ValueError, match="route assessment"):
        prepared_result.prepared.source_inputs.__post_init__()
    object.__setattr__(candidate_assessment, "phase", original_assessment_phase)
    prepared_result.prepared.source_inputs.__post_init__()
    receipt = prepared_result.prepared.source_inputs.preparation_receipt
    assert receipt.source_inventory_digest == prepared_result.prepared.source_inventory.inventory_digest
    assert receipt.candidate_inventory_digest == prepared_result.prepared.source_inputs.candidate_inventory.inventory_digest
    with pytest.raises((TypeError, ValueError)):
        replace(receipt, candidate_inventory_digest=authority_id("forged-receipt"))

    from d810.transforms.patch_binding import BoundPatchPlan
    from d810.ir.maturity import MaturityEnvelope

    patch_binding = BoundPatchPlan(
        plan=plan, attempt_id=attempt, session_id=attempt.session_id,
        generation=attempt.generation,
        maturity=MaturityEnvelope(ir=None, provider="hexrays", provider_id=0),
        bindings=tuple(
            (ref, serial) for serial, ref in refs.items() if serial in {0, 1, 2}
        ),
    )
    replacement = replace(proposal)
    assert replacement == proposal
    assert replacement is not proposal
    object.__setattr__(plan, "unflatten_proposal", replacement)
    replacement_result = transaction_api.bind_prepared_unflatten_authority(
        prepared=prepared_result.prepared,
        patch_binding=patch_binding,
    )
    assert getattr(replacement_result, "authority", None) is None
    object.__setattr__(plan, "unflatten_proposal", proposal)
    bound_result = transaction_api.bind_prepared_unflatten_authority(
        prepared=prepared_result.prepared,
        patch_binding=patch_binding,
    )
    assert bound_result.authority is not None
    assert bound_result.authority.patch_binding is patch_binding
    observed_same = transaction_api.revalidate_observed_unflatten_authority(
        authority=bound_result.authority,
        observed=source,
        observed_generation=attempt.generation,
        generic_gates=generic_gates,
    )
    assert observed_same.accepted
    from d810.ir.flowgraph import FlowGraph
    build_calls.clear()
    empty_observed = transaction_api.revalidate_observed_unflatten_authority(
        authority=bound_result.authority,
        observed=FlowGraph({}, 0, source.func_ea),
        observed_generation=attempt.generation,
        generic_gates=generic_gates,
    )
    assert not empty_observed.accepted
    assert empty_observed.phase.value == "observed_post_apply"
    assert len(build_calls) == 1
    build_calls.clear()
    class GenerationInt(int):
        pass
    for invalid_generation in (True, GenerationInt(attempt.generation), -1):
        invalid = transaction_api.revalidate_observed_unflatten_authority(
            authority=bound_result.authority,
            observed=source,
            observed_generation=invalid_generation,
            generic_gates=generic_gates,
        )
        assert not invalid.accepted
        assert invalid.reason is UnflattenAuthorityReason.GRAPH_GENERATION_MISMATCH
        assert invalid.authority_id is None
        assert invalid.binding_id is None
        assert invalid.case_id is None
        assert not build_calls
    original_binding_id = bound_result.authority.binding_id
    object.__setattr__(bound_result.authority, "binding_id", authority_id("forged-binding"))
    forged = transaction_api.revalidate_observed_unflatten_authority(
        authority=bound_result.authority,
        observed=source,
        observed_generation=attempt.generation,
        generic_gates=generic_gates,
    )
    assert not forged.accepted
    assert forged.reason is UnflattenAuthorityReason.LIVE_BINDING_FAILED
    assert forged.authority_id is None
    assert forged.binding_id is None
    assert forged.case_id is None
    assert not build_calls
    object.__setattr__(bound_result.authority, "binding_id", original_binding_id)
    malformed_carriers = (
        ("prepared", object()),
        ("attempt_id", object()),
        ("session_id", object()),
        ("generation", True),
        ("live_maturity", object()),
        ("live_bindings", object()),
        ("patch_binding", object()),
    )
    for field, malformed in malformed_carriers:
        original = getattr(bound_result.authority, field)
        object.__setattr__(bound_result.authority, field, malformed)
        malformed_result = transaction_api.revalidate_observed_unflatten_authority(
            authority=bound_result.authority,
            observed=source,
            observed_generation=attempt.generation,
            generic_gates=generic_gates,
        )
        assert not malformed_result.accepted
        assert malformed_result.reason is UnflattenAuthorityReason.LIVE_BINDING_FAILED
        assert malformed_result.authority_id is None
        assert malformed_result.binding_id is None
        assert malformed_result.case_id is None
        assert not build_calls
        object.__setattr__(bound_result.authority, field, original)
    monkeypatch.setattr(
        producer_api,
        "discover_reachable_effects_and_terminals",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("legacy discovery used")),
    )
    monkeypatch.setattr(
        graph_checks,
        "reachable_terminal_blocks",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("legacy terminal walk used")),
    )
    poisoned_observed = transaction_api.revalidate_observed_unflatten_authority(
        authority=bound_result.authority,
        observed=source,
        observed_generation=attempt.generation,
        generic_gates=generic_gates,
    )
    assert poisoned_observed.accepted
    source_block = prepared_result.prepared.source_inventory.blocks[0]
    original_graph_start = source_block.graph_start_ea
    object.__setattr__(source_block, "graph_start_ea", original_graph_start + 1)
    corrupted_source_observed = transaction_api.revalidate_observed_unflatten_authority(
        authority=bound_result.authority,
        observed=source,
        observed_generation=attempt.generation,
        generic_gates=generic_gates,
    )
    assert not corrupted_source_observed.accepted
    object.__setattr__(source_block, "graph_start_ea", original_graph_start)
    observed_distinct = transaction_api.revalidate_observed_unflatten_authority(
        authority=bound_result.authority,
        observed=replace(source, func_ea=source.func_ea + 1),
        observed_generation=attempt.generation,
        generic_gates=generic_gates,
    )
    assert observed_distinct.candidate_fingerprint != prepared_result.prepared.projected_fingerprint

    def observed_authority_rejected() -> None:
        result = transaction_api.revalidate_observed_unflatten_authority(
            authority=bound_result.authority,
            observed=source,
            observed_generation=attempt.generation,
            generic_gates=generic_gates,
        )
        assert not result.accepted

    replacement_after_bind = replace(proposal)
    object.__setattr__(plan, "unflatten_proposal", replacement_after_bind)
    observed_authority_rejected()
    object.__setattr__(plan, "unflatten_proposal", proposal)
    object.__setattr__(plan, "source_generation", True)
    observed_authority_rejected()
    object.__setattr__(plan, "source_generation", 1)
    object.__setattr__(proposal, "schema_version", True)
    observed_authority_rejected()
    object.__setattr__(proposal, "schema_version", 1)

    forged = SimpleNamespace(
        plan=patch_binding.plan,
        attempt_id=patch_binding.attempt_id,
        session_id=patch_binding.session_id,
        generation=patch_binding.generation,
        maturity=patch_binding.maturity,
        bindings=patch_binding.bindings,
    )
    forged_result = transaction_api.bind_prepared_unflatten_authority(
        prepared=prepared_result.prepared,
        patch_binding=forged,
    )
    assert getattr(forged_result, "authority", None) is None

    class ForgedBoundPatchPlan(BoundPatchPlan):
        pass

    subclass_result = transaction_api.bind_prepared_unflatten_authority(
        prepared=prepared_result.prepared,
        patch_binding=ForgedBoundPatchPlan(
            plan=patch_binding.plan,
            attempt_id=patch_binding.attempt_id,
            session_id=patch_binding.session_id,
            generation=patch_binding.generation,
            maturity=patch_binding.maturity,
            bindings=patch_binding.bindings,
        ),
    )
    assert getattr(subclass_result, "authority", None) is None

    def corrupted(field, value):
        candidate = BoundPatchPlan(
            plan=patch_binding.plan,
            attempt_id=patch_binding.attempt_id,
            session_id=patch_binding.session_id,
            generation=patch_binding.generation,
            maturity=patch_binding.maturity,
            bindings=patch_binding.bindings,
        )
        object.__setattr__(candidate, field, value)
        return transaction_api.bind_prepared_unflatten_authority(
            prepared=prepared_result.prepared,
            patch_binding=candidate,
        )

    for field, value in (
        ("maturity", True),
        ("generation", True),
        ("session_id", ""),
        ("bindings", list(patch_binding.bindings)),
        ("bindings", tuple((ref, True if index == 0 else serial) for index, (ref, serial) in enumerate(patch_binding.bindings))),
        ("bindings", patch_binding.bindings + (patch_binding.bindings[0],)),
        ("bindings", patch_binding.bindings[::-1]),
    ):
        assert getattr(corrupted(field, value), "authority", None) is None

    class StrSubclass(str):
        pass

    nested_attempt = TransactionAttemptId(
        attempt.plan_id, attempt.session_id, attempt.generation, attempt.attempt_id
    )
    nested_candidate = BoundPatchPlan(
        plan=plan,
        attempt_id=nested_attempt,
        session_id=attempt.session_id,
        generation=attempt.generation,
        maturity=patch_binding.maturity,
        bindings=patch_binding.bindings,
    )

    def corrupted_nested(field, value):
        object.__setattr__(nested_attempt, field, value)
        result = transaction_api.bind_prepared_unflatten_authority(
            prepared=prepared_result.prepared,
            patch_binding=nested_candidate,
        )
        object.__setattr__(nested_attempt, field, getattr(attempt, field))
        return result

    for field, value in (
        ("generation", True),
        ("plan_id", ""),
        ("session_id", StrSubclass(attempt.session_id)),
        ("attempt_id", StrSubclass(attempt.attempt_id)),
    ):
        assert getattr(corrupted_nested(field, value), "authority", None) is None

    object.__setattr__(plan, "source_generation", True)
    assert getattr(
        transaction_api.bind_prepared_unflatten_authority(
            prepared=prepared_result.prepared, patch_binding=patch_binding
        ),
        "authority",
        None,
    ) is None
    object.__setattr__(plan, "source_generation", 1)
    object.__setattr__(plan, "source_maturity", True)
    assert getattr(
        transaction_api.bind_prepared_unflatten_authority(
            prepared=prepared_result.prepared, patch_binding=patch_binding
        ),
        "authority",
        None,
    ) is None
    object.__setattr__(plan, "source_maturity", None)

    object.__setattr__(proposal, "schema_version", True)
    assert getattr(
        transaction_api.bind_prepared_unflatten_authority(
            prepared=prepared_result.prepared, patch_binding=patch_binding
        ),
        "authority",
        None,
    ) is None
    object.__setattr__(proposal, "schema_version", 1)
    catalog = proposal.source_identity_catalog
    object.__setattr__(catalog, "generation", True)
    assert getattr(
        transaction_api.bind_prepared_unflatten_authority(
            prepared=prepared_result.prepared, patch_binding=patch_binding
        ),
        "authority",
        None,
    ) is None
    object.__setattr__(catalog, "generation", 1)

    # A failed fold must report the already-built candidate fingerprint. In
    # particular, it must not rematerialize either live graph for the error.
    from d810.analyses.control_flow.semantic_route_evidence import CanonicalRouteMaterialization

    captures = []
    original_capture = CanonicalRouteMaterialization.capture

    def counted_capture(*args, **kwargs):
        captures.append(True)
        return original_capture(*args, **kwargs)

    monkeypatch.setattr(CanonicalRouteMaterialization, "capture", counted_capture)
    monkeypatch.setattr(
        transaction_api,
        "_derive_inputs",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("forced fold failure")),
    )
    failed_result = transaction_api.prepare_unflatten_authority(
        source=source, projection=projection, plan=plan,
        attempt_id=attempt, generic_gates=generic_gates,
    )
    assert getattr(failed_result, "prepared", None) is None
    assert failed_result.verdict.candidate_fingerprint == prepared_result.prepared.projected_fingerprint
    assert len(captures) == 2


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
def test_local_alias_claim_is_derived_before_authority_id() -> None:
    """A scalarization step is transaction authority, not producer metadata."""

    from d810.transforms.cfg_transaction import CfgProjection
    from d810.transforms.plan import PatchPlan, PatchScalarizeLocalAliasAccess
    from d810.transforms.unflatten_authority import model, transaction_api
    from d810.ir.flowgraph import (
        BlockKind, BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot,
        MopSnapshot, OperandKind,
    )

    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    refs = tuple(item.block_ref for item in proposal.source_identity_catalog.blocks)
    source = FlowGraph(
        {
            0: BlockSnapshot(0, 0, (), (), 0, 0x1000, (
                    InsnSnapshot(
                        58, 0x1000, (),
                        l=MopSnapshot(kind=OperandKind.LVAR, size=4),
                        display_text="store alias base",
                        kind=InsnKind.STORE,
                    ),
            ), kind=BlockKind.ZERO_WAY),
            1: BlockSnapshot(1, 0, (), (), 0, 0x1300, (
                InsnSnapshot(0, 0x1300, (), kind=InsnKind.NOP),
            ), kind=BlockKind.ZERO_WAY),
            2: BlockSnapshot(2, 0, (), (), 0, 0x1100, (
                InsnSnapshot(0, 0x1100, (), kind=InsnKind.NOP),
            ), kind=BlockKind.ZERO_WAY),
        },
        0,
        0x1000,
    )
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("local-alias-derived"),
        source_generation=proposal.source_identity_catalog.generation,
        steps=(PatchScalarizeLocalAliasAccess(
            block_serial=refs[0], host_ea=0x1000, host_opcode=58,
            alias_token="alias", base_token="base",
        ),),
        source_coordinates=tuple((ref, serial) for serial, ref in enumerate(refs)),
        unflatten_proposal=proposal,
    )
    inputs = transaction_api.derive_unflatten_preparation_inputs(
        source, CfgProjection(plan.plan_id, plan.snapshot_id, source),
        plan, proposal, None,
    )

    assert any(
        type(claim) is model.LocalAliasEffectScalarizationClaim
        for claim in inputs.claims
    )
    alias_claim = next(
        claim for claim in inputs.claims
        if type(claim) is model.LocalAliasEffectScalarizationClaim
    )
    assert inputs.preparation_receipt.patch_step_digest == authority_id(
        inputs.patch_step_facts
    )
    assert inputs.preparation_receipt.conditional_relation_digest == authority_id(
        inputs.conditional_relations
    )
    assert inputs.patch_step_facts[0].step_digest == alias_claim.step_digest
    with pytest.raises((TypeError, ValueError)):
        replace(proposal, claims=(*proposal.claims, alias_claim))
    mutated_plan = replace(
        plan,
        steps=(replace(plan.steps[0], alias_token="mutated-alias"),),
    )
    with pytest.raises(ValueError, match="tokens"):
        transaction_api.derive_unflatten_preparation_inputs(
            source,
            CfgProjection(mutated_plan.plan_id, mutated_plan.snapshot_id, source),
            mutated_plan,
            proposal,
            None,
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
