"""Task 5 proposal-channel and plan-route contracts."""

from __future__ import annotations

import hashlib
import inspect
from dataclasses import replace

import pytest

from d810.transforms.plan import PatchPlan


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
    return InsnSnapshot(0, ea, (), kind=kind, native_ea=ea)


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


def _typed_plan(proposal, *, legacy_shadow=None):
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
    return replace(plan, unflatten_proposal=proposal, legacy_unflatten_shadow=legacy_shadow), proposal


def _shadow(plan_id: str, snapshot_id: str = "snapshot-1"):
    from d810.transforms.unflatten_authority.legacy_wire import encode_legacy_value
    from d810.transforms.unflatten_authority.model import (
        LegacyShadowEntry,
        LegacyUnflattenShadowEnvelope,
    )

    payload = encode_legacy_value({"legacy": True})
    entry = LegacyShadowEntry(
        "dispatcher_corridor_coverage",
        payload,
        hashlib.sha256(payload).hexdigest(),
    )
    return LegacyUnflattenShadowEnvelope(
        1, plan_id, snapshot_id, 3, (entry,)
    )


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


def test_explicit_shadow_envelope_is_the_only_dual_channel_exception() -> None:
    """A typed plan may carry only the exact temporary shadow transport."""

    # Direct construction still exercises the independent dual-channel guard.
    assert "unflatten_proposal" in inspect.signature(PatchPlan).parameters
    assert "legacy_unflatten_shadow" in inspect.signature(PatchPlan).parameters
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route

    proposal, plan_id = _proposal_and_plan_ids()
    envelope = _shadow(plan_id)
    typed, proposal = _typed_plan(proposal, legacy_shadow=envelope)
    selected = select_plan_route(typed)
    from d810.transforms.unflatten_authority.model import (
        UnflattenAuthorityReason,
        UnflattenPlanRoute,
    )

    assert selected.route is UnflattenPlanRoute.TYPED_PROPOSAL

    dual = replace(typed, metadata=(("dispatcher_corridor_coverage", {"legacy": True}),))
    rejected = select_plan_route(dual)
    assert rejected.reason is UnflattenAuthorityReason.DUAL_AUTHORITY_CHANNEL

    with pytest.raises(TypeError, match="shadow"):
        PatchPlan(
            plan_id=plan_id,
            snapshot_id="snapshot-1",
            source_generation=3,
            unflatten_proposal=proposal,
            legacy_unflatten_shadow={"schema_version": 1},
        )


def test_first_typed_effect_plan_moves_all_legacy_keys_into_shadow() -> None:
    """The first typed proposal must capture every legacy family once."""

    from d810.transforms.unflatten_authority.legacy_keys import LEGACY_UNFLATTEN_KEYS
    from d810.transforms.unflatten_authority.proposal import attach_typed_proposal
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route
    from .helpers import import_authority_model
    model = import_authority_model()
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
    attached = attach_typed_proposal(
        plan,
        source=source, block_refs_by_serial=refs,
        canonical_route_evidence=proposal.route_evidence,
        exact_state_effect_exclusions=(exclusion,), dispatcher_entry_serial=1,
        dispatcher_member_serials=(0, 1), authoritative_handler_serials=(2,),
        state_identity=proposal.plan_inputs.state_identity, use_def_witness=witness,
    )
    selected = select_plan_route(attached)
    assert getattr(selected, "route", None) is model.UnflattenPlanRoute.TYPED_PROPOSAL
    assert attached.legacy_unflatten_shadow is not None
    assert attached.metadata == ()
    assert tuple(entry.key for entry in attached.legacy_unflatten_shadow.entries) == tuple(sorted(key for key in LEGACY_UNFLATTEN_KEYS if key != DISPATCHER_CORRIDOR_COVERAGE_METADATA))


def test_typed_attachment_keeps_dispatcher_entry_when_not_a_redirect_owner() -> None:
    from .helpers import import_authority_model
    from .test_bind import _exact_fixture
    from d810.transforms.plan import PatchRedirectGoto
    from d810.transforms.unflatten_authority.proposal import attach_typed_proposal, canonical_redirect_manifest
    from d810.transforms.unflatten_authority.legacy_keys import LEGACY_UNFLATTEN_KEYS
    from d810.transforms.unflatten_authority.legacy_keys import DISPATCHER_CORRIDOR_COVERAGE_METADATA
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route

    model = import_authority_model()
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
    attached = attach_typed_proposal(
        plan,
        source=source, block_refs_by_serial=refs,
        canonical_route_evidence=proposal.route_evidence,
        exact_state_effect_exclusions=(exclusion,), dispatcher_entry_serial=1,
        dispatcher_member_serials=(0, 1), authoritative_handler_serials=(2,),
        state_identity=proposal.plan_inputs.state_identity, use_def_witness=witness,
    )
    assert select_plan_route(attached).route is model.UnflattenPlanRoute.TYPED_PROPOSAL


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
        with pytest.raises(ValueError, match="retirement proof|retirement families"):
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
    with pytest.raises(ValueError, match="ambiguous|conversion failed"):
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
    with pytest.raises(ValueError, match="terminal proof conversion"):
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
    evidence = CanonicalSemanticEvidence(key, 1, authority_id("group"), (route,))
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
    with pytest.raises(ValueError, match="shadow snapshot"):
        PatchPlan(
            plan_id=plan_id,
            snapshot_id="different-snapshot",
            source_generation=3,
            unflatten_proposal=proposal,
            legacy_unflatten_shadow=_shadow(plan_id),
        )


def test_mutated_proposal_is_revalidated_at_route_boundary() -> None:
    from d810.transforms.unflatten_authority.model import UnflattenAuthorityReason
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

    object.__setattr__(plan.unflatten_proposal, "schema_version", 1)
    object.__setattr__(plan.unflatten_proposal, "rule_set_version", 2)
    result = select_plan_route(plan)
    assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert result.detail_code == "proposal_invariants_invalid"

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


def test_mutated_shadow_is_revalidated_at_route_boundary() -> None:
    from d810.transforms.unflatten_authority.model import UnflattenAuthorityReason
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route

    proposal, plan_id = _proposal_and_plan_ids()
    plan, _ = _typed_plan(proposal, legacy_shadow=_shadow(plan_id))
    object.__setattr__(plan.legacy_unflatten_shadow, "schema_version", 2)
    result = select_plan_route(plan)
    assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert result.detail_code == "shadow_invariants_invalid"

    object.__setattr__(plan.legacy_unflatten_shadow, "schema_version", 1)
    object.__setattr__(plan.legacy_unflatten_shadow.entries[0], "payload_sha256", "0" * 64)
    result = select_plan_route(plan)
    assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert result.detail_code == "shadow_invariants_invalid"

    object.__setattr__(plan.legacy_unflatten_shadow.entries[0], "payload_sha256", hashlib.sha256(
        plan.legacy_unflatten_shadow.entries[0].canonical_payload
    ).hexdigest())
    from d810.transforms.unflatten_authority.legacy_wire import encode_legacy_value
    from d810.transforms.unflatten_authority.model import LegacyShadowEntry

    payload = encode_legacy_value({"legacy": 2})
    second = LegacyShadowEntry(
        "use_def_severance_audit", payload, hashlib.sha256(payload).hexdigest()
    )
    object.__setattr__(plan.legacy_unflatten_shadow, "entries", (second, plan.legacy_unflatten_shadow.entries[0]))
    result = select_plan_route(plan)
    assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert result.detail_code == "shadow_invariants_invalid"

    object.__setattr__(plan.legacy_unflatten_shadow, "entries", (plan.legacy_unflatten_shadow.entries[0],) * 2)
    result = select_plan_route(plan)
    assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert result.detail_code == "shadow_invariants_invalid"


def test_reserved_metadata_shapes_fail_closed_and_cover_all_keys() -> None:
    from d810.transforms.unflatten_authority.proposal import LEGACY_UNFLATTEN_KEYS
    from d810.transforms.unflatten_authority.model import UnflattenAuthorityReason
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route

    for index, key in enumerate(sorted(LEGACY_UNFLATTEN_KEYS)):
        proposal, plan_id = _proposal_and_plan_ids()
        plan = PatchPlan(
            plan_id=plan_id,
            snapshot_id="snapshot-1",
            source_generation=3,
            unflatten_proposal=proposal,
            metadata=([key, index],),
        )
        result = select_plan_route(plan)
        assert result.reason is UnflattenAuthorityReason.DUAL_AUTHORITY_CHANNEL
        assert result.key == key

    proposal, plan_id = _proposal_and_plan_ids()
    mapping_shape = PatchPlan(
        plan_id=plan_id,
        snapshot_id="snapshot-1",
        source_generation=3,
        unflatten_proposal=proposal,
        metadata={"use_def_severance_audit": True},
    )
    result = select_plan_route(mapping_shape)
    assert result.reason is UnflattenAuthorityReason.DUAL_AUTHORITY_CHANNEL

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
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route
    proposal, plan_id = _proposal_and_plan_ids()
    calls = []

    def metadata_generator():
        calls.append("iterated")
        yield ("use_def_severance_audit", True)

    plan = PatchPlan(
        plan_id=plan_id,
        snapshot_id="snapshot-1",
        source_generation=3,
        metadata=metadata_generator(),
        unflatten_proposal=proposal,
    )
    assert plan.metadata_dict()["use_def_severance_audit"] is True
    result = select_plan_route(plan)
    assert result.reason.value == "dual_authority_channel"
    assert select_plan_route(plan).reason.value == "dual_authority_channel"
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
    plan = PatchPlan(
        plan_id=plan_id,
        snapshot_id="snapshot-1",
        source_generation=3,
        metadata=((_ReservedAlias(), 1), ("use_def_severance_audit", 2)),
        unflatten_proposal=proposal,
    )
    result = select_plan_route(plan)
    assert result.reason.value == "malformed_proposal"
    assert result.detail_code == "metadata_key_type_invalid"

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
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route

    proposal, plan_id = _proposal_and_plan_ids()
    plan = PatchPlan(
        plan_id=plan_id,
        snapshot_id="snapshot-1",
        source_generation=3,
        metadata=((_LateAlias("use_def_severance_audit"), True),),
        unflatten_proposal=proposal,
    )
    result = select_plan_route(plan)
    assert result.reason.value == "malformed_proposal"
    assert result.detail_code == "metadata_key_type_invalid"
