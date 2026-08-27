"""Focused total route-selection tests for the transaction facade."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError, fields, replace
from inspect import signature
from pathlib import Path
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
from d810.transforms.unflatten_authority.ids import authority_id

from .helpers import (
    authority_id as helper_authority_id,
    block_ref,
    exact_fixture,
    import_authority_model,
)
from .test_model import _valid_proposal


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
    )

    accepted = observed.observed_acceptance
    assert accepted.bound_authority is binding.authority
    assert accepted.projected_ledger is preparation.prepared.projected_loss_ledger
    assert accepted.observed_case is observed.safety_case
    assert accepted.observed_ledger.case is accepted.observed_case
    assert accepted.delta.projected_ledger_id == accepted.projected_ledger.ledger_id
    assert accepted.delta.observed_ledger_id == accepted.observed_ledger.ledger_id


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


def test_direct_observed_gates_consume_one_exact_ledger(monkeypatch):
    """All observed gates receive the accepted ledger occurrence, not a clone."""
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
    for name in (
        "validate_projected_effect_loss_ledger",
        "validate_projected_dispatcher_removal_ledger",
        "validate_projected_corridor_coverage_ledger",
        "validate_projected_terminal_loss_ledger",
    ):
        original = getattr(gates, name)
        def wrapped(ledger, case, *, _original=original):
            seen.append(ledger)
            return _original(ledger, case)
        monkeypatch.setattr(gates, name, wrapped)
    observed = transaction_api.revalidate_observed_unflatten_authority(
        authority=authority, observed=projected,
        observed_generation=fixture.attempt_id.generation, generic_gates=generic_gates,
    )
    assert observed.accepted
    assert seen == [observed.observed_acceptance.observed_ledger] * 4


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
    )
    assert verdict.accepted
    exact_claim = next(
        claim for claim in authority.prepared.source_inputs.claims
        if type(claim) is model.ExactInfeasibleEffectClaim
    )
    ledger = verdict.observed_acceptance.observed_ledger
    assert len(ledger.rows) == 1
    assert ledger.rows[0].kind is model.SemanticLossKind.EXACT_INFEASIBLE_EFFECT
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


def test_direct_projected_gates_receive_one_exact_loss_ledger(monkeypatch):
    """Projected safety consumers share the ledger minted for this attempt."""
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
    for name in (
        "validate_projected_effect_loss_ledger",
        "validate_projected_dispatcher_removal_ledger",
        "validate_projected_corridor_coverage_ledger",
        "validate_projected_terminal_loss_ledger",
    ):
        consumer = getattr(transaction_api.gates, name)
        monkeypatch.setattr(
            transaction_api.gates,
            name,
            lambda ledger, case, _consumer=consumer: (
                consumed.append((ledger, case)) or _consumer(ledger, case)
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
    assert len(consumed) == 4
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
    with patch.object(
        transaction_api,
        "canonical_patch_step_descriptor",
        side_effect=ValueError("canonical descriptor coordinates are malformed"),
    ):
        with pytest.raises(ValueError, match="canonical descriptor coordinates"):
            transaction_api._derive_patch_lineage_facts(source, plan)


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



def test_helper_and_resegmentation_lineage_is_derived_before_case_builder() -> None:
    """Helper ownership enters closed facts before semantic-case construction."""
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
    relations = transaction_api._derive_patch_lineage_relations(source_inventory, projected_inventory, plan, derived.patch_step_facts)
    assert set((fact.step_type, fact.owner_ref) for fact in derived.patch_step_facts) == {("PatchRedirectBranch", refs[0]), ("PatchRedirectBranch", helper), ("PatchRedirectBranch", refs[1]), ("PatchRedirectBranch", second_helper)}
    assert any(item.source_subject_id for item in relations)
    assert any(item.target_subject_id for item in relations)

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
        unflatten_proposal=proposal,
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
