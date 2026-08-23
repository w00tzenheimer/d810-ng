"""Focused total route-selection tests for the transaction facade."""

from __future__ import annotations

from dataclasses import replace
from inspect import signature

import pytest

from d810.transforms.plan import PatchBlockSpec, PatchEdgeRef, PatchPlan, PatchRedirectBranch
from d810.transforms.cfg_transaction import CfgProjection, PlanBlockRef
from d810.transforms.unflatten_authority.model import (
    UnflattenAuthorityReason,
    UnflattenAuthorityNotApplicable,
    UnflattenPlanRoute,
)
from d810.transforms.unflatten_authority.transaction_api import select_plan_route
from d810.transforms.unflatten_authority.ids import authority_id

from .helpers import exact_fixture, import_authority_model, authority_id as helper_authority_id
from .test_model import _valid_proposal
from .test_proposal import _shadow


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
        ("PatchRedirectBranch", helper),
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
    from d810.transforms import dispatcher_corridor_coverage
    monkeypatch.setattr(
        dispatcher_corridor_coverage,
        "canonicalize_observed_dispatcher_graph",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("typed observed authority must not canonicalize")
        ),
    )
    observed_result = transaction_api.revalidate_observed_unflatten_authority(
        authority=bound_result.authority, observed=live_observed,
        observed_generation=attempt.generation, generic_gates=generic_gates,
    )
    assert observed_result.accepted
    unused_source_collision = replace(
        patch_binding,
        bindings=tuple(
            (ref, 3 if ref == helper else serial)
            for ref, serial in patch_binding.bindings
        ),
    )
    collision_authority = transaction_api.bind_prepared_unflatten_authority(
        prepared=prepared_result.prepared, patch_binding=unused_source_collision,
    )
    assert getattr(collision_authority, "authority", None) is not None
    builder_calls = []
    case_calls = []
    with monkeypatch.context() as collision_patch:
        collision_patch.setattr(
            transaction_api,
            "_build_semantic_graph_inventory",
            lambda *_args, **_kwargs: builder_calls.append(True),
        )
        collision_patch.setattr(
            transaction_api,
            "build_semantic_case",
            lambda *_args, **_kwargs: case_calls.append(True),
        )
        collision_observed = transaction_api.revalidate_observed_unflatten_authority(
            authority=collision_authority.authority, observed=live_observed,
            observed_generation=attempt.generation, generic_gates=generic_gates,
        )
    assert not collision_observed.accepted
    assert builder_calls == []
    assert case_calls == []
    missing_helper = transaction_api.revalidate_observed_unflatten_authority(
        authority=bound_result.authority, observed=projected,
        observed_generation=attempt.generation, generic_gates=generic_gates,
    )
    assert not missing_helper.accepted

    original_spec, second_spec = plan.new_blocks
    mutations = {
        "block_id": PlanBlockRef(plan.plan_id, "different-helper"),
        "kind": "changed-kind",
        "template_block": refs[3],
        "incoming_edge": PatchEdgeRef(refs[0], refs[1]),
        "outgoing_edges": (PatchEdgeRef(refs[1], refs[2]),),
        "instructions": (source.blocks[0].insn_snapshots[0],),
        "captured_body": object(),
    }
    for field, value in mutations.items():
        object.__setattr__(
            plan, "new_blocks", (replace(original_spec, **{field: value}), second_spec),
        )
        mutated_result = transaction_api.bind_prepared_unflatten_authority(
            prepared=prepared_result.prepared, patch_binding=patch_binding,
        )
        assert getattr(mutated_result, "authority", None) is None, field
        observed_mutation = transaction_api.revalidate_observed_unflatten_authority(
            authority=bound_result.authority, observed=live_observed,
            observed_generation=attempt.generation, generic_gates=generic_gates,
        )
        assert not observed_mutation.accepted, field
        object.__setattr__(plan, "new_blocks", (original_spec, second_spec))
    object.__setattr__(plan, "new_blocks", (second_spec, original_spec))
    reordered_result = transaction_api.bind_prepared_unflatten_authority(
        prepared=prepared_result.prepared, patch_binding=patch_binding,
    )
    assert getattr(reordered_result, "authority", None) is None
    object.__setattr__(plan, "new_blocks", (original_spec, second_spec))

    shifted_bindings = tuple(
        (ref, 99 if ref == helper else serial)
        for ref, serial in patch_binding.bindings
    )
    shifted_binding = replace(patch_binding, bindings=shifted_bindings)
    shifted_result = transaction_api.bind_prepared_unflatten_authority(
        prepared=prepared_result.prepared, patch_binding=shifted_binding,
    )
    assert shifted_result.authority is not None
    shifted_observed = transaction_api.revalidate_observed_unflatten_authority(
        authority=shifted_result.authority, observed=live_observed,
        observed_generation=attempt.generation, generic_gates=generic_gates,
    )
    assert not shifted_observed.accepted

    original_bindings = patch_binding.bindings
    object.__setattr__(
        patch_binding, "bindings",
        tuple((ref, 0 if ref == helper else serial) for ref, serial in original_bindings),
    )
    colliding_observed = transaction_api.revalidate_observed_unflatten_authority(
        authority=bound_result.authority, observed=live_observed,
        observed_generation=attempt.generation, generic_gates=generic_gates,
    )
    assert not colliding_observed.accepted
    object.__setattr__(patch_binding, "bindings", original_bindings)
    object.__setattr__(
        patch_binding, "bindings", original_bindings + ((helper, 5),),
    )
    duplicate_observed = transaction_api.revalidate_observed_unflatten_authority(
        authority=bound_result.authority, observed=live_observed,
        observed_generation=attempt.generation, generic_gates=generic_gates,
    )
    assert not duplicate_observed.accepted
    object.__setattr__(patch_binding, "bindings", original_bindings)

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
    typed = _typed_plan().with_metadata(
        concrete_state_route_provenance=("legacy",)
    )
    result = select_plan_route(typed)
    assert result.reason is UnflattenAuthorityReason.DUAL_AUTHORITY_CHANNEL
    assert result.key == "concrete_state_route_provenance"


def test_exact_shadow_is_allowed_but_mapping_lookalike_is_rejected() -> None:
    typed = _typed_plan()
    object.__setattr__(typed, "legacy_unflatten_shadow", _shadow(typed.plan_id))
    selected = select_plan_route(typed)
    assert selected.route is UnflattenPlanRoute.TYPED_PROPOSAL

    forged = _typed_plan()
    object.__setattr__(forged, "legacy_unflatten_shadow", {"schema_version": 1})
    rejected = select_plan_route(forged)
    assert rejected.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert rejected.detail_code == "shadow_type_is_not_closed"


def test_shadow_plan_snapshot_and_generation_drift_rejects() -> None:
    for field, value, detail in (
        ("plan_id", "wrong-plan", "shadow_plan_id_mismatch"),
        ("snapshot_id", "wrong-snapshot", "shadow_snapshot_id_mismatch"),
    ):
        plan = _typed_plan()
        shadow = _shadow(plan.plan_id)
        if field == "plan_id":
            shadow = type(shadow)(1, value, shadow.snapshot_id, shadow.source_generation, shadow.entries)
        else:
            shadow = type(shadow)(1, shadow.plan_id, value, shadow.source_generation, shadow.entries)
        object.__setattr__(plan, "legacy_unflatten_shadow", shadow)
        result = select_plan_route(plan)
        assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
        assert result.detail_code == detail

    plan = _typed_plan()
    shadow = _shadow(plan.plan_id)
    object.__setattr__(plan, "legacy_unflatten_shadow", type(shadow)(
        1, shadow.plan_id, shadow.snapshot_id, 4, shadow.entries
    ))
    result = select_plan_route(plan)
    assert result.detail_code == "shadow_source_generation_mismatch"


def test_shadow_is_the_single_legacy_transport_at_transaction_boundary() -> None:
    typed = _typed_plan()
    shadow = _shadow(typed.plan_id)
    object.__setattr__(typed, "legacy_unflatten_shadow", shadow)
    assert typed.metadata == ()
    selected = select_plan_route(typed)
    assert selected.route is UnflattenPlanRoute.TYPED_PROPOSAL
    assert selected.proposal is not None
    assert selected.proposal.plan_id == typed.plan_id


def test_exact_effect_shadow_preserves_payload_and_typed_route() -> None:
    from dataclasses import replace
    from d810.transforms.plan import PatchRedirectGoto
    from d810.transforms.unflatten_authority.legacy_keys import EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA
    from d810.transforms.unflatten_authority.legacy_codec import replay_legacy_unflatten_shadow
    from d810.transforms.unflatten_authority.proposal import attach_typed_proposal, canonical_redirect_manifest
    from .test_bind import _exact_fixture

    source, proposal, exclusion, refs = _exact_fixture()
    plan = PatchPlan(
        plan_id=proposal.plan_id, snapshot_id="snapshot-exact", source_generation=1,
        steps=(PatchRedirectGoto(refs[0], refs[1], refs[2]),),
        metadata=((EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA, (exclusion.to_metadata(),)),),
    )
    manifest = canonical_redirect_manifest(plan)
    proposal = replace(proposal, use_def_witness=replace(
        proposal.use_def_witness, redirect_owner_refs=manifest.owner_refs,
        redirect_digest=manifest.digest,
    ))
    attached = attach_typed_proposal(
        plan, source=source, block_refs_by_serial=refs,
        canonical_route_evidence=proposal.route_evidence,
        exact_state_effect_exclusions=(exclusion,), dispatcher_entry_serial=1,
        dispatcher_member_serials=(0, 1), authoritative_handler_serials=(2,),
        state_identity=proposal.plan_inputs.state_identity,
        use_def_witness=proposal.use_def_witness,
    )
    selected = select_plan_route(attached)
    assert selected.route is UnflattenPlanRoute.TYPED_PROPOSAL
    assert selected.proposal == proposal
    replayed = replay_legacy_unflatten_shadow(attached)
    assert attached.metadata == ()
    assert replayed.metadata_value(EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA) == (
        exclusion.to_metadata(),
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

    valid_shadow = replace(
        _shadow(plan.plan_id, plan.snapshot_id),
        source_generation=plan.source_generation,
    )
    object.__setattr__(plan, "legacy_unflatten_shadow", valid_shadow)
    shadow_prepared_result = transaction_api.prepare_unflatten_authority(
        source=source, projection=projection, plan=plan,
        attempt_id=attempt, generic_gates=generic_gates,
    )
    assert getattr(shadow_prepared_result, "prepared", None) is not None
    shadow_bound_result = transaction_api.bind_prepared_unflatten_authority(
        prepared=shadow_prepared_result.prepared,
        patch_binding=patch_binding,
    )
    assert shadow_bound_result.authority is not None
    shadow_clone = replace(valid_shadow)
    object.__setattr__(plan, "legacy_unflatten_shadow", shadow_clone)
    assert getattr(
        transaction_api.bind_prepared_unflatten_authority(
            prepared=shadow_prepared_result.prepared,
            patch_binding=patch_binding,
        ),
        "authority",
        None,
    ) is None
    object.__setattr__(plan, "legacy_unflatten_shadow", valid_shadow)
    object.__setattr__(plan, "legacy_unflatten_shadow", shadow_clone)
    observed_shadow_result = transaction_api.revalidate_observed_unflatten_authority(
        authority=shadow_bound_result.authority,
        observed=source,
        observed_generation=attempt.generation,
        generic_gates=generic_gates,
    )
    assert not observed_shadow_result.accepted
    object.__setattr__(plan, "legacy_unflatten_shadow", None)

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

    object.__setattr__(plan, "legacy_unflatten_shadow", valid_shadow)
    object.__setattr__(valid_shadow, "source_generation", True)
    shadow_corruption_result = transaction_api.revalidate_observed_unflatten_authority(
        authority=shadow_bound_result.authority,
        observed=source,
        observed_generation=attempt.generation,
        generic_gates=generic_gates,
    )
    assert not shadow_corruption_result.accepted
    object.__setattr__(valid_shadow, "source_generation", 1)
    object.__setattr__(plan, "legacy_unflatten_shadow", None)

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
