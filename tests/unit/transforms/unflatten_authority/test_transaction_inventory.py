from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from d810.ir.flowgraph import BlockKind, BlockSnapshot
from d810.transforms.cfg_transaction import PlanBlockRef
from d810.transforms.unflatten_authority import producer_api
from d810.transforms.unflatten_authority import transaction_api
from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority.ids import authority_id, semantic_graph_inventory_digest, _subject_factory


_BADADDR = 0xFFFFFFFFFFFFFFFF


@pytest.mark.parametrize("drift", [None, "payload", "missing_payload", "extra_payload", "foreign_successor", "nonadjacent", "different_corridor", "native_goto"])
def test_observed_corridor_helper_accepts_only_exact_synthetic_fallthrough(drift):
    from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
    from d810.ir.maturity import MaturityEnvelope
    from d810.ir.semantics import ControlTransferKind
    from d810.transforms.cfg_transaction import TransactionAttemptId
    from d810.transforms.patch_binding import BoundPatchPlan, iter_refs, observed_patch_binding
    from d810.transforms.plan import PatchBlockSpec, PatchEdgeSplitCorridor, PatchPlan
    from tests.unit.transforms.unflatten_authority.test_bind import _exact_fixture

    source, proposal, _exclusion, refs = _exact_fixture()
    helper = PlanBlockRef(proposal.plan_id, "fallthrough-first")
    following = PlanBlockRef(proposal.plan_id, "fallthrough-second")
    step = PatchEdgeSplitCorridor(
        (helper, following), refs[1], refs[0], refs[2], refs[0], refs[2], (refs[1], refs[2]),
    )
    plan = PatchPlan(
        plan_id=proposal.plan_id, snapshot_id=authority_id("fallthrough-test"), steps=(step,),
        source_coordinates=tuple((ref, serial) for serial, ref in refs.items()),
        new_blocks=(PatchBlockSpec(helper, "edge_split_corridor_clone", template_block=refs[1]),
                    PatchBlockSpec(following, "edge_split_corridor_clone", template_block=refs[2])),
    )
    if drift == "different_corridor":
        plan = replace(plan, steps=(replace(step, clone_block_ids=(helper,)), replace(step, clone_block_ids=(following,))))
    attempt = TransactionAttemptId(plan.plan_id, "fallthrough-test", 1, "exact")
    next_serial = 11 if drift == "nonadjacent" else 10
    serials = {ref: serial for serial, ref in refs.items()}
    serials.update({helper: 9, following: next_serial})
    ordered_refs = tuple(ref for ref in dict.fromkeys(iter_refs((plan.steps, plan.new_blocks, plan.relocation_map))) if type(ref) is not PlanBlockRef) + (helper, following)
    bound = BoundPatchPlan(
        plan, attempt, attempt.session_id, attempt.generation,
        MaturityEnvelope(ir=None, provider="test", provider_id=0),
        tuple((ref, serials[ref]) for ref in ordered_refs),
    )
    binding = observed_patch_binding(bound, ((helper, 9), (following, next_serial)))
    payload = InsnSnapshot(
        4, 0x401010, (), kind=InsnKind.MOV, raw_opcode=4, native_ea=0x401010,
        l=MopSnapshot(kind=OperandKind.REGISTER, reg=8, size=4),
        d=MopSnapshot(kind=OperandKind.REGISTER, reg=16, size=4),
    )
    tail = InsnSnapshot(
        -1, 0x401014, (), kind=InsnKind.GOTO,
        control_transfer_kind=ControlTransferKind.GOTO, is_unconditional_jump=True,
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=next_serial),
    )
    if drift == "native_goto":
        tail = replace(tail, opcode=55, raw_opcode=55)
    projected_block = BlockSnapshot(
        serial=9, block_type=0, succs=(next_serial,), preds=(), flags=0,
        start_ea=0x401010, insn_snapshots=(payload, tail),
        tail_opcode=tail.opcode, raw_tail_opcode=tail.raw_opcode,
        tail_kind=InsnKind.GOTO, kind=BlockKind.ONE_WAY,
    )
    live_payload = replace(payload, ea=source.func_ea, native_ea=source.func_ea)
    if drift == "payload":
        live_payload = replace(live_payload, opcode=5, raw_opcode=5)
    body = () if drift == "missing_payload" else (live_payload,)
    if drift == "extra_payload":
        body += (live_payload,)
    live = replace(
        projected_block, insn_snapshots=body,
        succs=(0,) if drift == "foreign_successor" else (next_serial,),
        tail_opcode=live_payload.opcode if body else None,
        raw_tail_opcode=live_payload.raw_opcode if body else None,
        tail_kind=InsnKind.MOV if body else None,
    )
    expected = producer_api.observe_inventory_block(projected_block, owner_ref=helper, owner_anchor_ea=0x401010)
    actual = producer_api.observe_inventory_block(live, owner_ref=helper, owner_anchor_ea=0x401010)
    kwargs = dict(block=live, observed=actual, projected=expected, owner_ref=helper, observed_patch_binding=binding, function_ea=source.func_ea)
    if drift is None:
        assert transaction_api._normalize_observed_plan_helper_allocation_origins(**kwargs) == expected
    else:
        with pytest.raises(ValueError):
            transaction_api._normalize_observed_plan_helper_allocation_origins(**kwargs)


def test_observe_inventory_block_preserves_raw_graph_start_ea() -> None:
    block = BlockSnapshot(
        serial=3,
        block_type=0,
        succs=(),
        preds=(),
        flags=0,
        start_ea=_BADADDR,
        insn_snapshots=(),
        kind=BlockKind.ZERO_WAY,
    )

    observed = producer_api.observe_inventory_block(
        block, owner_ref=None, owner_anchor_ea=None,
    )

    assert type(observed) is model.InventoryBlockObservation
    assert observed.graph_start_ea == _BADADDR


def test_projected_plan_helper_uses_minimum_exact_native_origin_when_start_is_badaddr() -> None:
    """A bound helper's copied native rows supply its stable site anchor."""
    from d810.ir.flowgraph import (
        FlowGraph,
        InsnKind,
        InsnSnapshot,
        MopSnapshot,
        OperandKind,
    )
    from d810.ir.maturity import MaturityEnvelope
    from d810.ir.semantics import ControlTransferKind
    from d810.transforms.cfg_transaction import TransactionAttemptId
    from d810.transforms.patch_binding import (
        BoundPatchPlan,
        ObservedPatchBinding,
        iter_refs,
        observed_patch_binding,
    )
    from d810.transforms.plan import PatchBlockSpec, PatchPlan, PatchRedirectGoto
    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest

    source, proposal, _exclusion, refs = __import__(
        "tests.unit.transforms.unflatten_authority.test_bind",
        fromlist=["_exact_fixture"],
    )._exact_fixture()
    helper_ref = PlanBlockRef(proposal.plan_id, "badaddr-origin-helper")
    originless_ref = PlanBlockRef(proposal.plan_id, "badaddr-originless-helper")
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("badaddr-helper-origin"),
        source_generation=1,
        steps=(PatchRedirectGoto(refs[0], refs[1], refs[2]),),
        source_coordinates=tuple((ref, serial) for serial, ref in refs.items()),
        new_blocks=(
            PatchBlockSpec(helper_ref, "insert_block", template_block=refs[0]),
            PatchBlockSpec(originless_ref, "insert_block", template_block=refs[0]),
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
    source_inventory = transaction_api._build_semantic_graph_inventory(
        source, proposal, plan, source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
    )
    helper = BlockSnapshot(
        serial=9, block_type=0, succs=(), preds=(), flags=0,
        start_ea=_BADADDR,
        insn_snapshots=(
            InsnSnapshot(1, _BADADDR, (), kind=InsnKind.NOP, raw_opcode=1,
                         native_ea=0x18003FF85),
            InsnSnapshot(2, _BADADDR, (), kind=InsnKind.NOP, raw_opcode=2,
                         native_ea=0x18003FF79),
        ),
        tail_opcode=2,
        raw_tail_opcode=2,
        tail_kind=InsnKind.NOP,
        kind=BlockKind.ZERO_WAY,
    )
    candidate = FlowGraph(
        {
            **source.blocks,
            9: helper,
            10: BlockSnapshot(
                serial=10, block_type=0, succs=(), preds=(), flags=0,
                start_ea=_BADADDR, insn_snapshots=(), kind=BlockKind.STOP,
            ),
        },
        source.entry_serial,
        source.func_ea,
    )

    anchored_inventory = transaction_api._build_semantic_graph_inventory(
        candidate, proposal, plan, source=False,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        source_subjects=source_inventory.subjects,
        planned_serials={helper_ref: 9},
    )

    row = next(item for item in anchored_inventory.blocks if item.serial == 9)
    assert row.block_ref == helper_ref
    assert row.anchor_ea == 0x18003FF79
    assert row.graph_start_ea == _BADADDR
    with pytest.raises(ValueError, match="originless planned helper requires exact observed binding"):
        transaction_api._build_semantic_graph_inventory(
            candidate, proposal, plan, source=False,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            source_subjects=source_inventory.subjects,
            planned_serials={helper_ref: 9, originless_ref: 10},
        )

    attempt = TransactionAttemptId(plan.plan_id, "originless-helper", 1, "exact")
    planned_serials = {helper_ref: 9, originless_ref: 10}
    source_coordinates = dict(plan.source_coordinates)
    encountered_refs = tuple(dict.fromkeys(iter_refs(
        (plan.steps, plan.new_blocks, plan.relocation_map),
    )))
    canonical_bindings = tuple(
        (
            ref,
            planned_serials[ref]
            if type(ref) is PlanBlockRef else source_coordinates[ref],
        )
        for ref in encountered_refs
        if type(ref) is not PlanBlockRef
    ) + tuple(planned_serials.items())
    bound_plan = BoundPatchPlan(
        plan, attempt, attempt.session_id, attempt.generation,
        MaturityEnvelope(ir=None, provider="test", provider_id=0),
        canonical_bindings,
    )
    observed_binding = observed_patch_binding(
        bound_plan, ((helper_ref, 9), (originless_ref, 10)),
    )

    # Hex-Rays assigns ``mba.entry_ea`` to instructions copied into a live
    # helper.  Those allocation coordinates are not native provenance.  The
    # exact observed PlanBlockRef occurrence must retain the already-bound
    # projected helper anchor/origins instead of trying to mint authority from
    # the rewritten instruction addresses.
    synthetic_allocation_helper = replace(
        helper,
        start_ea=0x18003FF79,
        native_start_ea=0x18003FF79,
        insn_snapshots=tuple(
            replace(row, ea=source.func_ea, native_ea=source.func_ea)
            for row in helper.insn_snapshots
        ),
    )
    synthetic_observation = producer_api.observe_inventory_block(
        synthetic_allocation_helper,
        owner_ref=helper_ref,
        owner_anchor_ea=0x18003FF79,
    )
    projected_helper_row = next(
        row for row in anchored_inventory.blocks if row.block_ref == helper_ref
    )
    normalized_observation = (
        transaction_api._normalize_observed_plan_helper_allocation_origins(
            block=synthetic_allocation_helper,
            observed=synthetic_observation,
            projected=projected_helper_row,
            owner_ref=helper_ref,
            observed_patch_binding=observed_binding,
            function_ea=source.func_ea,
        )
    )
    assert normalized_observation.anchor_ea == 0x18003FF79
    assert normalized_observation.native_instruction_eas == (
        0x18003FF79,
        0x18003FF85,
    )
    wrong_serial_binding = observed_patch_binding(
        bound_plan, ((helper_ref, 8), (originless_ref, 10)),
    )
    with pytest.raises(ValueError, match="exact observed patch binding"):
        transaction_api._normalize_observed_plan_helper_allocation_origins(
            block=synthetic_allocation_helper,
            observed=synthetic_observation,
            projected=projected_helper_row,
            owner_ref=helper_ref,
            observed_patch_binding=wrong_serial_binding,
            function_ea=source.func_ea,
        )
    with pytest.raises(ValueError, match="projected helper anchor"):
        transaction_api._normalize_observed_plan_helper_allocation_origins(
            block=synthetic_allocation_helper,
            observed=replace(synthetic_observation, anchor_ea=0x18003FF7A),
            projected=projected_helper_row,
            owner_ref=helper_ref,
            observed_patch_binding=observed_binding,
            function_ea=source.func_ea,
        )

    projected_tail_block = BlockSnapshot(
        serial=9,
        block_type=0,
        succs=(0,),
        preds=(),
        flags=0,
        start_ea=0x18003FF79,
        native_start_ea=0x18003FF79,
        insn_snapshots=(
            InsnSnapshot(
                1, _BADADDR, (), kind=InsnKind.NOP, raw_opcode=1,
                native_ea=0x18003FF79,
            ),
            InsnSnapshot(
                -1, _BADADDR, (), kind=InsnKind.GOTO, raw_opcode=None,
                native_ea=0x18003FF85,
                control_transfer_kind=ControlTransferKind.GOTO,
                d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=0),
            ),
        ),
        tail_opcode=-1,
        raw_tail_opcode=None,
        tail_kind=InsnKind.GOTO,
        kind=BlockKind.ONE_WAY,
    )
    projected_tail_row = producer_api.observe_inventory_block(
        projected_tail_block,
        owner_ref=helper_ref,
        owner_anchor_ea=0x18003FF79,
    )
    live_tail_block = replace(
        projected_tail_block,
        insn_snapshots=(
            replace(
                projected_tail_block.insn_snapshots[0],
                ea=source.func_ea,
                native_ea=source.func_ea,
            ),
            replace(
                projected_tail_block.insn_snapshots[1],
                opcode=0x42,
                raw_opcode=0x42,
                ea=source.func_ea,
                native_ea=source.func_ea,
                l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=0),
                d=None,
            ),
        ),
        tail_opcode=0x42,
        raw_tail_opcode=0x42,
    )
    live_tail_row = producer_api.observe_inventory_block(
        live_tail_block,
        owner_ref=helper_ref,
        owner_anchor_ea=0x18003FF79,
    )
    assert live_tail_row.instruction_observations[-1].instruction_ea is None
    normalized_tail_row = (
        transaction_api._normalize_observed_plan_helper_allocation_origins(
            block=live_tail_block,
            observed=live_tail_row,
            projected=projected_tail_row,
            owner_ref=helper_ref,
            observed_patch_binding=observed_binding,
            function_ea=source.func_ea,
        )
    )
    assert normalized_tail_row == projected_tail_row
    changed_body_block = replace(
        live_tail_block,
        insn_snapshots=(
            replace(live_tail_block.insn_snapshots[0], opcode=3, raw_opcode=3),
            live_tail_block.insn_snapshots[1],
        ),
    )
    changed_body_row = producer_api.observe_inventory_block(
        changed_body_block,
        owner_ref=helper_ref,
        owner_anchor_ea=0x18003FF79,
    )
    with pytest.raises(ValueError, match="body differs"):
        transaction_api._normalize_observed_plan_helper_allocation_origins(
            block=changed_body_block,
            observed=changed_body_row,
            projected=projected_tail_row,
            owner_ref=helper_ref,
            observed_patch_binding=observed_binding,
            function_ea=source.func_ea,
        )
    wrong_operand_target_block = replace(
        live_tail_block,
        insn_snapshots=(
            live_tail_block.insn_snapshots[0],
            replace(
                live_tail_block.insn_snapshots[1],
                l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=1),
            ),
        ),
    )
    # The CFG successor remains 0.  The raw GOTO operand is the only hostile
    # drift, and the closed inventory row intentionally does not persist it.
    wrong_operand_target_row = producer_api.observe_inventory_block(
        wrong_operand_target_block,
        owner_ref=helper_ref,
        owner_anchor_ea=0x18003FF79,
    )
    assert wrong_operand_target_row.successor_serials == (0,)
    with pytest.raises(ValueError, match="body differs"):
        transaction_api._normalize_observed_plan_helper_allocation_origins(
            block=wrong_operand_target_block,
            observed=wrong_operand_target_row,
            projected=projected_tail_row,
            owner_ref=helper_ref,
            observed_patch_binding=observed_binding,
            function_ea=source.func_ea,
        )
    shifted_binding = observed_patch_binding(
        bound_plan, ((helper_ref, 8), (originless_ref, 9)),
    )
    assert tuple(
        row for row in shifted_binding.bindings if type(row[0]) is not PlanBlockRef
    ) == tuple(
        row for row in bound_plan.bindings if type(row[0]) is not PlanBlockRef
    )
    assert tuple(
        row for row in shifted_binding.bindings if type(row[0]) is PlanBlockRef
    ) == ((helper_ref, 8), (originless_ref, 9))
    with pytest.raises(ValueError, match="canonical helpers"):
        observed_patch_binding(
            bound_plan, ((originless_ref, 9), (helper_ref, 8)),
        )
    with pytest.raises(ValueError, match="duplicate live serials"):
        observed_patch_binding(
            bound_plan, ((helper_ref, 8), (originless_ref, 8)),
        )
    source_namespace_serial = next(
        serial for ref, serial in bound_plan.bindings
        if type(ref) is not PlanBlockRef
    )
    cross_phase_overlap = observed_patch_binding(
        bound_plan,
        ((helper_ref, source_namespace_serial), (originless_ref, 10)),
    )
    assert (helper_ref, source_namespace_serial) in cross_phase_overlap.bindings
    source_ref, source_serial = next(
        row for row in bound_plan.bindings if type(row[0]) is not PlanBlockRef
    )
    with pytest.raises(ValueError, match="canonical source row"):
        ObservedPatchBinding(
            bound_plan,
            tuple(
                (ref, serial + 100 if ref == source_ref else serial)
                for ref, serial in observed_binding.bindings
            ),
        )
    source_bindings = tuple(
        row for row in canonical_bindings if type(row[0]) is not PlanBlockRef
    )
    assert source_bindings
    with pytest.raises(ValueError, match="reference order|exactly cover"):
        BoundPatchPlan(
            plan, attempt, attempt.session_id, attempt.generation,
            MaturityEnvelope(ir=None, provider="test", provider_id=0),
            source_bindings + ((originless_ref, 10), (helper_ref, 9)),
        )
    foreign_helper = PlanBlockRef(plan.plan_id, "foreign-observed-helper")
    with pytest.raises(ValueError, match="reference order|exactly cover"):
        BoundPatchPlan(
            plan, attempt, attempt.session_id, attempt.generation,
            MaturityEnvelope(ir=None, provider="test", provider_id=0),
            canonical_bindings + ((foreign_helper, 11),),
        )
    unrelated_source_ref = next(
        ref for ref in refs.values() if ref not in {row[0] for row in source_bindings}
    )
    with pytest.raises(ValueError, match="reference order|exactly cover"):
        BoundPatchPlan(
            plan, attempt, attempt.session_id, attempt.generation,
            MaturityEnvelope(ir=None, provider="test", provider_id=0),
            canonical_bindings + ((unrelated_source_ref, source_coordinates[unrelated_source_ref]),),
        )
    source_ref, source_serial = source_bindings[0]
    with pytest.raises(ValueError, match="source coordinate"):
        BoundPatchPlan(
            plan, attempt, attempt.session_id, attempt.generation,
            MaturityEnvelope(ir=None, provider="test", provider_id=0),
            tuple(
                (ref, serial + 100 if ref == source_ref else serial)
                for ref, serial in canonical_bindings
            ),
        )
    with pytest.raises(ValueError, match="only authorizes observed"):
        transaction_api._build_semantic_graph_inventory(
            candidate, proposal, plan, source=False,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            source_subjects=source_inventory.subjects,
            planned_serials=planned_serials,
            observed_patch_binding=observed_binding,
        )
    foreign_plan = replace(
        plan, snapshot_id=authority_id("foreign-observed-helper-plan"),
    )
    foreign_bound_plan = BoundPatchPlan(
        foreign_plan, attempt, attempt.session_id, attempt.generation,
        MaturityEnvelope(ir=None, provider="test", provider_id=0),
        canonical_bindings,
    )
    foreign_observed_binding = ObservedPatchBinding(
        foreign_bound_plan, foreign_bound_plan.bindings,
    )
    with pytest.raises(ValueError, match="foreign to inventory plan"):
        transaction_api._build_semantic_graph_inventory(
            candidate, proposal, plan, source=False,
            phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            source_subjects=source_inventory.subjects,
            planned_serials=planned_serials,
            observed_patch_binding=foreign_observed_binding,
        )
    with pytest.raises(ValueError, match="observed helper bindings differ"):
        transaction_api._build_semantic_graph_inventory(
            candidate, proposal, plan, source=False,
            phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            source_subjects=source_inventory.subjects,
            planned_serials={originless_ref: 10, helper_ref: 9},
            observed_patch_binding=observed_binding,
        )
    with pytest.raises(ValueError, match="requires exact observed binding"):
        transaction_api._build_semantic_graph_inventory(
            candidate, proposal, plan, source=False,
            phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            source_subjects=source_inventory.subjects,
            planned_serials=planned_serials,
        )

    def observed_with_originless_helper(block: BlockSnapshot):
        blocks = {**candidate.blocks, 10: block}
        for successor in block.succs:
            blocks[successor] = replace(
                blocks[successor],
                preds=tuple(sorted((*blocks[successor].preds, block.serial))),
            )
        return transaction_api._build_semantic_graph_inventory(
            FlowGraph(
                blocks,
                candidate.entry_serial,
                candidate.func_ea,
            ),
            proposal,
            plan,
            source=False,
            phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            source_subjects=source_inventory.subjects,
            planned_serials=planned_serials,
            observed_patch_binding=observed_binding,
        )

    with pytest.raises(ValueError, match="exact structural STOP"):
        observed_with_originless_helper(
            replace(candidate.blocks[10], kind=BlockKind.ZERO_WAY),
        )
    with pytest.raises(ValueError, match="exact structural STOP"):
        observed_with_originless_helper(
            replace(candidate.blocks[10], succs=(0,)),
        )
    with pytest.raises(ValueError, match="exact structural STOP"):
        observed_with_originless_helper(replace(
            candidate.blocks[10],
            insn_snapshots=(
                InsnSnapshot(3, _BADADDR, (), kind=InsnKind.NOP, raw_opcode=3),
            ),
            tail_opcode=3,
            raw_tail_opcode=3,
            tail_kind=InsnKind.NOP,
        ))
    with pytest.raises(ValueError, match="exact structural STOP"):
        observed_with_originless_helper(replace(
            candidate.blocks[10],
            insn_snapshots=(
                InsnSnapshot(
                    3, _BADADDR, (), kind=InsnKind.NOP, raw_opcode=3,
                    native_ea=0x18003FF79,
                ),
            ),
            tail_opcode=3,
            raw_tail_opcode=3,
            tail_kind=InsnKind.NOP,
        ))
    inventory = transaction_api._build_semantic_graph_inventory(
        candidate, proposal, plan, source=False,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        source_subjects=source_inventory.subjects,
        planned_serials=planned_serials,
        observed_patch_binding=observed_binding,
    )
    originless = next(item for item in inventory.blocks if item.serial == 10)
    assert originless.block_ref is None
    assert originless.anchor_ea is None
    assert not any(
        getattr(subject.locator, "block_ref", None) == originless_ref
        for subject in inventory.subjects
    )
    assert not any(binding.block_ref == originless_ref for binding in inventory.bindings)

    semantic_helper = replace(
        candidate.blocks[10],
        insn_snapshots=(
            InsnSnapshot(3, 0x18003FE00, (), kind=InsnKind.STORE, raw_opcode=3),
        ),
        tail_opcode=3,
        raw_tail_opcode=3,
        tail_kind=InsnKind.STORE,
    )
    with pytest.raises(
        ValueError, match="originless planned helper must be an exact structural STOP",
    ):
        observed_with_originless_helper(semantic_helper)


@pytest.mark.parametrize("instructions", ((), (None,)), ids=("empty", "invalid"))
def test_bound_plan_helper_without_exact_native_origins_stays_anchorless(
    instructions: tuple[object, ...],
) -> None:
    """A BADADDR helper cannot manufacture an anchor without copied origins."""
    from d810.ir.flowgraph import InsnKind, InsnSnapshot

    rows = (
        () if not instructions else (
            InsnSnapshot(1, _BADADDR, (), kind=InsnKind.NOP, raw_opcode=1),
        )
    )
    block = BlockSnapshot(
        serial=9, block_type=0, succs=(), preds=(), flags=0,
        start_ea=_BADADDR, insn_snapshots=rows, kind=BlockKind.ZERO_WAY,
    )

    assert transaction_api._bound_plan_helper_anchor_from_exact_origins(block) is None


def test_reachable_closure_empty_graph_has_explicit_zero_entry_policy() -> None:
    assert transaction_api._reachable_serials_from_blocks({}, 0) == frozenset()
    with pytest.raises((TypeError, ValueError)):
        transaction_api._reachable_serials_from_blocks({}, 1)
    with pytest.raises((TypeError, ValueError)):
        transaction_api._reachable_serials_from_blocks({}, True)

    class EntryInt(int):
        pass

    with pytest.raises((TypeError, ValueError)):
        transaction_api._reachable_serials_from_blocks({}, EntryInt(0))


def test_semantic_reachability_roots_every_bound_native_route_endpoint() -> None:
    """Indirect-dispatch routes remain obligations without raw CFG edges."""
    source, proposal, _exclusion, refs = __import__(
        "tests.unit.transforms.unflatten_authority.test_bind",
        fromlist=["_exact_fixture"],
    )._exact_fixture()
    detached = {
        serial: replace(block, succs=(), preds=())
        for serial, block in source.blocks.items()
    }

    reachable = transaction_api._semantic_reachable_serials(
        detached,
        entry_serial=source.entry_serial,
        serial_by_ref={ref: serial for serial, ref in refs.items()},
        proposal=proposal,
    )

    assert reachable == frozenset({0, 1, 2, 3})


def test_projected_semantic_reachability_does_not_reroot_dispatcher() -> None:
    """A route subject naming the dispatcher cannot keep it semantically live.

    A projected graph may legitimately omit a retired route endpoint, so the
    projected phase cannot require every source endpoint to remain bound.  It
    must nevertheless root every endpoint that *is* still present; otherwise
    an intact payload component is classified as unreachable merely because
    the portable graph has no physical dispatcher edge to it.
    """
    case = __import__(
        "tests.unit.transforms.unflatten_authority.test_bind",
        fromlist=["_task_15_two_arm_vertical_case"],
    )._task_15_two_arm_vertical_case()
    detached = {
        serial: replace(
            block,
            succs=() if serial == case.source_graph.entry_serial else block.succs,
            preds=tuple(
                pred
                for pred in block.preds
                if pred != case.source_graph.entry_serial
            ),
        )
        for serial, block in case.source_graph.blocks.items()
    }

    reachable = transaction_api._semantic_reachable_serials(
        detached,
        entry_serial=case.source_graph.entry_serial,
        serial_by_ref=case.source_inventory.serial_by_ref,
        proposal=case.proposal,
        require_all_semantic_roots=False,
    )

    # blk1 is both the typed route source and the dispatcher.  The projected
    # route view may retain its selected destination (blk4), but it must not
    # re-root blk1 and thereby manufacture residual dispatcher reachability.
    assert reachable == frozenset({0, 4})


def test_semantic_root_closure_stops_before_dispatcher_barrier() -> None:
    """A surviving payload root remains live without reviving its dispatcher."""
    blocks = {
        0: BlockSnapshot(
            serial=0, block_type=0, succs=(), preds=(), flags=0,
            start_ea=0x1000, insn_snapshots=(), kind=BlockKind.ZERO_WAY,
        ),
        1: BlockSnapshot(
            serial=1, block_type=0, succs=(2,), preds=(), flags=0,
            start_ea=0x1010, insn_snapshots=(), kind=BlockKind.ONE_WAY,
        ),
        2: BlockSnapshot(
            serial=2, block_type=0, succs=(3,), preds=(1,), flags=0,
            start_ea=0x1020, insn_snapshots=(), kind=BlockKind.ONE_WAY,
        ),
        3: BlockSnapshot(
            serial=3, block_type=0, succs=(), preds=(2,), flags=0,
            start_ea=0x1030, insn_snapshots=(), kind=BlockKind.ZERO_WAY,
        ),
    }

    reachable = transaction_api._reachable_serials_from_semantic_roots(
        blocks,
        roots=(1,),
        dispatcher_serial=2,
    )

    assert reachable == frozenset({1})


def test_full_candidate_builder_preserves_generated_goto_without_native_ea() -> None:
    from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
    from d810.ir.semantics import ControlTransferKind
    from d810.transforms.plan import PatchPlan, PatchRedirectGoto
    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest

    source, proposal, _exclusion, refs = __import__(
        "tests.unit.transforms.unflatten_authority.test_bind",
        fromlist=["_exact_fixture"],
    )._exact_fixture()
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("generated-goto-snapshot"),
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
    source_inventory = transaction_api._build_semantic_graph_inventory(
        source, proposal, plan, source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
    )
    generated = BlockSnapshot(
        4, 0, (), (), 0, 0xFFFFFFFFFFFFFFFF,
            (InsnSnapshot(
                0x42, 0xFFFFFFFFFFFFFFFF, (), kind=InsnKind.GOTO,
                raw_opcode=0x42,
                control_transfer_kind=ControlTransferKind.GOTO,
            ),),
            tail_opcode=0x42, raw_tail_opcode=0x42, tail_kind=InsnKind.GOTO,
            kind=BlockKind.UNKNOWN,
    )
    candidate_blocks = dict(source.blocks)
    candidate_blocks[4] = generated
    candidate = FlowGraph(candidate_blocks, source.entry_serial, source.func_ea)
    inventory = transaction_api._build_semantic_graph_inventory(
        candidate, proposal, plan, source=False,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        source_subjects=source_inventory.subjects,
    )
    row = next(item for item in inventory.blocks if item.serial == 4)
    assert row.transfer_ea is None
    assert row.instruction_observations[0].instruction_ea is None
    assert row.instruction_observations[0].control_transfer_kind is ControlTransferKind.GOTO
    assert all(
        item.source_transfer_ea is not None
        for item in inventory.topology
        if item.owner_serial != 4 and item.kind is model.TopologyIncidenceKind.SUCCESSOR
    )


def _redirected_call_candidate(
    *,
    redirect_target: int | None,
    generated_kind,
    generated_ea: int = 0xF000,
    owner_serial: int = 3,
    old_target_serial: int = 4,
    generated_operand_target: int | None = None,
):
    """Return an exact retained CALL owner with one backend-created tail."""
    from d810.ir.flowgraph import BlockKind, FlowGraph, InsnSnapshot, MopSnapshot, OperandKind
    from d810.ir.semantics import ControlTransferKind
    from d810.transforms.plan import PatchPlan, PatchRedirectGoto
    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest

    source, proposal, _exclusion, refs = __import__(
        "tests.unit.transforms.unflatten_authority.test_bind",
        fromlist=["_exact_fixture"],
    )._exact_fixture()
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("observed-redirect-native-origin"),
        source_generation=1,
        steps=(
            (PatchRedirectGoto(refs[0], refs[1], refs[1]),)
            if redirect_target is None
            else (
                PatchRedirectGoto(
                    refs[owner_serial],
                    refs[old_target_serial],
                    refs[redirect_target],
                ),
            )
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
    original = source.blocks[owner_serial]
    source_serials = dict(plan.source_coordinates)
    if redirect_target is None:
        generated_target_serial = source_serials[refs[1]]
    else:
        generated_target_serial = redirect_target
    generated = InsnSnapshot(
        0x55,
        generated_ea,
        (),
        l=MopSnapshot(
            kind=OperandKind.BLOCK,
            block_ref=(
                generated_target_serial
                if generated_operand_target is None
                else generated_operand_target
            ),
        ),
        kind=generated_kind,
        raw_opcode=0x55,
        control_transfer_kind=(
            ControlTransferKind.GOTO if generated_kind is model.InsnKind.GOTO else None
        ),
    )
    candidate_owner = replace(
        original,
        succs=(generated_target_serial,),
        insn_snapshots=(*original.insn_snapshots, generated),
        tail_opcode=generated.opcode,
        raw_tail_opcode=generated.raw_opcode,
        tail_kind=generated.kind,
        kind=BlockKind.ONE_WAY,
    )
    candidate_blocks = dict(source.blocks)
    old_target_serial = source_serials[refs[old_target_serial]]
    if old_target_serial != generated_target_serial:
        candidate_blocks[old_target_serial] = replace(
            source.blocks[old_target_serial],
            preds=tuple(
                predecessor
                for predecessor in source.blocks[old_target_serial].preds
                if predecessor != owner_serial
            ),
        )
    target = source.blocks[generated_target_serial]
    candidate_blocks[generated_target_serial] = replace(
        target,
        preds=tuple(sorted({*target.preds, owner_serial})),
    )
    candidate = FlowGraph(
        {**candidate_blocks, owner_serial: candidate_owner},
        source.entry_serial,
        source.func_ea,
    )
    return source, proposal, plan, candidate, owner_serial


def test_observed_inventory_excludes_only_plan_authorized_synthetic_redirect_from_native_identity() -> None:
    source, proposal, plan, candidate, owner_serial = _redirected_call_candidate(
        redirect_target=4, generated_kind=model.InsnKind.GOTO,
    )
    source_inventory = transaction_api._build_semantic_graph_inventory(
        source, proposal, plan, source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
    )

    inventory = transaction_api._build_semantic_graph_inventory(
        candidate, proposal, plan, source=False,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        source_subjects=source_inventory.subjects,
    )

    row = next(row for row in inventory.blocks if row.serial == owner_serial)
    assert row.native_instruction_eas == (0x4000,)
    assert tuple(item.instruction_ea for item in row.instruction_observations) == (
        0x4000,
        None,
    )
    assert row.transfer_ea is None
    assert row.successor_serials == (4,)


def test_observed_inventory_rejects_duplicated_native_origins_without_receipt() -> None:
    """A live second source row makes a purported union an ambiguous split."""
    from d810.ir.flowgraph import FlowGraph

    source, proposal, plan, candidate, owner_serial = _redirected_call_candidate(
        redirect_target=4,
        generated_kind=model.InsnKind.GOTO,
        owner_serial=2,
        old_target_serial=3,
    )
    source_inventory = transaction_api._build_semantic_graph_inventory(
        source, proposal, plan, source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
    )
    (redirect,) = plan.steps
    source_serials = dict(plan.source_coordinates)
    merged_source_serial = source_serials[redirect.new_target]
    merged_instructions = tuple(
        instruction
        for block in (
            candidate.blocks[owner_serial], source.blocks[merged_source_serial],
        )
        for instruction in block.insn_snapshots
        if instruction.control_transfer_kind is None
    )
    tail = merged_instructions[-1]
    ambiguous = FlowGraph(
        {
            **candidate.blocks,
            owner_serial: replace(
                candidate.blocks[owner_serial],
                insn_snapshots=merged_instructions,
                tail_opcode=tail.opcode,
                raw_tail_opcode=tail.raw_opcode,
                tail_kind=tail.kind,
            ),
        },
        candidate.entry_serial,
        candidate.func_ea,
    )

    with pytest.raises(ValueError, match="native identity instruction EAs"):
        transaction_api._build_semantic_graph_inventory(
            ambiguous,
            proposal,
            plan,
            source=False,
            phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            source_subjects=source_inventory.subjects,
            source_inventory=source_inventory,
        )


def test_observed_corridor_via_predicate_excludes_only_its_first_clone_goto_tail(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A corridor's retained via predecessor may carry one generated GOTO."""
    from d810.ir.flowgraph import FlowGraph, InsnKind, InsnSnapshot, MopSnapshot, OperandKind
    from d810.ir.semantics import ControlTransferKind
    from d810.transforms.plan import PatchEdgeSplitCorridor

    source, _proposal, _exclusion, refs = __import__(
        "tests.unit.transforms.unflatten_authority.test_bind",
        fromlist=["_exact_fixture"],
    )._exact_fixture()
    source = FlowGraph(source.blocks, source.entry_serial, 0xF000)
    owner_ref = refs[3]
    first_clone = PlanBlockRef("corridor", "first")
    second_clone = PlanBlockRef("corridor", "second")
    generated = InsnSnapshot(
        0x55, source.func_ea, (),
        l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=9),
        kind=InsnKind.GOTO,
        raw_opcode=0x55,
        control_transfer_kind=ControlTransferKind.GOTO,
    )
    block = replace(
        source.blocks[3],
        succs=(9,),
        insn_snapshots=(*source.blocks[3].insn_snapshots, generated),
        tail_opcode=generated.opcode,
        raw_tail_opcode=generated.raw_opcode,
        tail_kind=generated.kind,
        kind=BlockKind.ONE_WAY,
    )

    def corridor(*, via_pred=owner_ref, clone_block_ids=(first_clone, second_clone)):
        return PatchEdgeSplitCorridor(
            clone_block_ids=clone_block_ids,
            source_serial=owner_ref,
            via_pred=via_pred,
            old_target=refs[4],
            new_target=refs[4],
            clone_until=refs[4],
            corridor_serials=(owner_ref,),
        )

    plan = SimpleNamespace(
        source_coordinates=tuple((ref, serial) for serial, ref in refs.items()),
        steps=(corridor(),),
    )
    serial_by_ref = {owner_ref: 3, first_clone: 9, second_clone: 10, refs[4]: 4}
    assert transaction_api._observed_native_identity_origins(
        block,
        owner_ref=owner_ref,
        serial_by_ref=serial_by_ref,
        plan=plan,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        function_ea=source.func_ea,
    ) == source.func_ea

    for hostile_plan, hostile_block in (
        (SimpleNamespace(source_coordinates=plan.source_coordinates, steps=(
            corridor(via_pred=refs[0]),
        )), block),
        (SimpleNamespace(source_coordinates=plan.source_coordinates, steps=(
            corridor(), corridor(),
        )), block),
        (SimpleNamespace(source_coordinates=plan.source_coordinates, steps=(
            corridor(),
        )), replace(block, succs=(10,), insn_snapshots=(*block.insn_snapshots[:-1], replace(
            generated, l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=10),
        )))),
        (plan, replace(block, succs=(4,), insn_snapshots=(*block.insn_snapshots[:-1], replace(
            generated, l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=4),
        )))),
        (plan, replace(block, insn_snapshots=(*block.insn_snapshots[:-1], replace(
            generated, kind=InsnKind.NOP, control_transfer_kind=None,
        )))),
        (plan, replace(block, insn_snapshots=(*block.insn_snapshots[:-1], replace(
            generated, ea=0x1000,
        )))),
    ):
        assert transaction_api._observed_native_identity_origins(
            hostile_block,
            owner_ref=owner_ref,
            serial_by_ref=serial_by_ref,
            plan=hostile_plan,
            phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            function_ea=source.func_ea,
        ) is None
    messages = tuple(
        record.getMessage()
        for record in caplog.records
        if "generated-tail normalization declined" in record.getMessage()
    )
    assert len(messages) == 5
    assert any("reason=multiple-matching-steps" in message for message in messages)
    assert any("reason=successor-target-mismatch" in message for message in messages)
    assert any("reason=tail-is-not-unconditional-goto" in message for message in messages)
    assert all("step=PatchEdgeSplitCorridor target=9" in message for message in messages)
    assert all("succs=" in message and "tail_opcode=" in message for message in messages)
    assert all("NativeBlockRef(" not in message for message in messages)
    assert all("blk3@0x4000" in message for message in messages)
    assert all(record.levelname == "WARNING" for record in caplog.records)
    warning_count = len(caplog.records)
    assert transaction_api._observed_native_identity_origins(
        replace(block, insn_snapshots=(), tail_opcode=None, raw_tail_opcode=None, tail_kind=None),
        owner_ref=owner_ref,
        serial_by_ref=serial_by_ref,
        plan=plan,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        function_ea=source.func_ea,
    ) is None
    assert len(caplog.records) == warning_count


def test_observed_inventory_accepts_generated_redirect_allocation_at_function_entry() -> None:
    """A proven backend GOTO may carry the function-entry allocation EA."""

    source, proposal, plan, candidate, owner_serial = (
        _redirected_call_candidate(
            redirect_target=4,
            generated_kind=model.InsnKind.GOTO,
            generated_ea=0x5000,
        )
    )
    source_inventory = transaction_api._build_semantic_graph_inventory(
        source, proposal, plan, source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
    )

    inventory = transaction_api._build_semantic_graph_inventory(
        candidate, proposal, plan, source=False,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        source_subjects=source_inventory.subjects,
    )

    owner = next(row for row in inventory.blocks if row.serial == owner_serial)
    assert owner.native_instruction_eas == (0x4000,)
    assert tuple(
        row.instruction_ea for row in owner.instruction_observations
    ) == (0x4000, None)


def test_observed_inventory_prebinds_plan_owned_entry_tail_before_identity_assignment(
    monkeypatch,
) -> None:
    """A same-anchor decoy cannot hide the exact plan-owned entry owner.

    OLLVM appends one backend GOTO at ``mba.entry_ea`` to a native entry block.
    Identity assignment must validate that exact prepared redirect before the
    synthetic row is removed; otherwise the owner is unavailable to the very
    normalizer that proves the row synthetic.
    """
    from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph

    source, proposal, plan, candidate, owner_serial = _redirected_call_candidate(
        redirect_target=4,
        generated_kind=model.InsnKind.GOTO,
        generated_ea=0x5000,
    )
    decoy_serial = max(candidate.blocks) + 1
    decoy = BlockSnapshot(
        decoy_serial,
        0,
        (),
        (),
        0,
        0x4000,
        (),
        tail_opcode=0,
        kind=BlockKind.ZERO_WAY,
        tail_kind=None,
        raw_tail_opcode=0,
        native_start_ea=0x4000,
    )
    candidate = FlowGraph(
        {**candidate.blocks, decoy_serial: decoy},
        candidate.entry_serial,
        candidate.func_ea,
    )
    source_inventory = transaction_api._build_semantic_graph_inventory(
        source,
        proposal,
        plan,
        source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
    )
    materialization = transaction_api.capture_projected_route_materialization(
        candidate,
        generation=proposal.source_identity_catalog.generation,
    )
    owner_ref = next(
        ref for ref, serial in plan.source_coordinates if serial == owner_serial
    )
    assert owner_ref not in transaction_api._projected_serials(
        candidate,
        proposal,
        blocks=materialization.blocks,
        plan=plan,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    checked_owner_refs = []
    original = transaction_api._observed_native_identity_origins

    def counted(*args, **kwargs):
        if kwargs.get("owner_ref") == owner_ref:
            checked_owner_refs.append(owner_ref)
        return original(*args, **kwargs)

    monkeypatch.setattr(
        transaction_api,
        "_observed_native_identity_origins",
        counted,
    )

    observed = transaction_api._build_semantic_graph_inventory(
        candidate,
        proposal,
        plan,
        source=False,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        source_subjects=source_inventory.subjects,
        source_inventory=source_inventory,
    )

    owner = next(row for row in observed.blocks if row.serial == owner_serial)
    assert owner.block_ref == owner_ref
    assert owner.native_instruction_eas == (0x4000,)
    assert tuple(
        row.instruction_ea for row in owner.instruction_observations
    ) == (0x4000, None)
    assert checked_owner_refs == [owner_ref]


def test_observed_entry_tail_prebind_rejects_ambiguous_eligible_candidates() -> None:
    from d810.ir.flowgraph import FlowGraph

    source, proposal, plan, candidate, owner_serial = _redirected_call_candidate(
        redirect_target=4, generated_kind=model.InsnKind.GOTO, generated_ea=0x5000,
    )
    owner_ref = next(ref for ref, serial in plan.source_coordinates if serial == owner_serial)
    clone_serial = max(candidate.blocks) + 1
    clone = replace(candidate.blocks[owner_serial], serial=clone_serial, preds=())
    target = replace(candidate.blocks[4], preds=tuple(sorted((*candidate.blocks[4].preds, clone_serial))))
    ambiguous = FlowGraph(
        {**candidate.blocks, 4: target, clone_serial: clone},
        candidate.entry_serial, candidate.func_ea,
    )
    assert owner_ref not in transaction_api._projected_serials(
        ambiguous,
        proposal,
        plan=plan,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
    )


def test_observed_redirect_binding_consumes_the_normalized_native_origin_subset() -> None:
    """An authorized live GOTO may replace, rather than append to, a transfer."""
    from d810.ir.flowgraph import FlowGraph, InsnSnapshot, MopSnapshot, OperandKind
    from d810.ir.semantics import ControlTransferKind
    from d810.transforms.plan import PatchPlan, PatchRedirectGoto
    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest

    source, proposal, _exclusion, refs = __import__(
        "tests.unit.transforms.unflatten_authority.test_bind",
        fromlist=["_exact_fixture"],
    )._exact_fixture()
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("observed-redirect-replaced-transfer"),
        source_generation=1,
        steps=(PatchRedirectGoto(refs[0], refs[1], refs[4]),),
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
    source_inventory = transaction_api._build_semantic_graph_inventory(
        source, proposal, plan, source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
    )

    original = source.blocks[0]
    generated = InsnSnapshot(
        0x55,
        0xF000,
        (),
        l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=4),
        kind=model.InsnKind.GOTO,
        raw_opcode=0x55,
        control_transfer_kind=ControlTransferKind.GOTO,
    )
    candidate_owner = replace(
        original,
        succs=(4,),
        insn_snapshots=(original.insn_snapshots[0], generated),
        tail_opcode=generated.opcode,
        raw_tail_opcode=generated.raw_opcode,
        tail_kind=generated.kind,
        kind=BlockKind.ONE_WAY,
    )
    candidate_target = replace(source.blocks[4], preds=(0,))
    former_target = replace(
        source.blocks[1], preds=tuple(
            serial for serial in source.blocks[1].preds if serial != 0
        ),
    )
    candidate = FlowGraph(
        {
            **source.blocks,
            0: candidate_owner,
            1: former_target,
            4: candidate_target,
        },
        source.entry_serial,
        source.func_ea,
    )

    inventory = transaction_api._build_semantic_graph_inventory(
        candidate, proposal, plan, source=False,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        source_subjects=source_inventory.subjects,
    )

    row = next(row for row in inventory.blocks if row.serial == 0)
    binding = next(
        binding for binding in inventory.bindings
        if binding.subject.role is model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK
        and binding.subject.block_ref == refs[0]
    )
    assert row.native_instruction_eas == (0x1000,)
    assert binding.native_instruction_eas == row.native_instruction_eas


@pytest.mark.parametrize(
    ("redirect_target", "generated_kind", "generated_operand_target"),
    (
            (2, model.InsnKind.GOTO, 4),
            (None, model.InsnKind.GOTO, None),
            (4, model.InsnKind.NOP, None),
    ),
)
def test_observed_inventory_rejects_non_authorized_extra_native_origin(
    redirect_target, generated_kind, generated_operand_target, caplog,
) -> None:
    source, proposal, plan, candidate, _owner_serial = _redirected_call_candidate(
        redirect_target=redirect_target,
        generated_kind=generated_kind,
        generated_operand_target=generated_operand_target,
    )
    source_inventory = transaction_api._build_semantic_graph_inventory(
        source, proposal, plan, source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
    )

    with pytest.raises(ValueError, match="native identity instruction EAs"):
        transaction_api._build_semantic_graph_inventory(
            candidate, proposal, plan, source=False,
            phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            source_subjects=source_inventory.subjects,
        )

    messages = tuple(
        record.getMessage()
        for record in caplog.records
        if "observed unflatten native-origin mismatch" in record.getMessage()
    )
    assert len(messages) == 1
    message = messages[0]
    assert "blk3@0x4000" in message
    assert "supplied=" in message and "expected=" in message
    assert "block_kind=one_way" in message
    assert "preds=" in message and "succs=" in message
    assert "instructions=[" in message
    assert "step_descriptors=[" in message
    assert "function_entry=" in message
    assert "raw_origins_contain_function_entry=" in message
    assert "raw_instruction_eas_contain_function_entry=" in message
    assert "raw_native_eas_contain_function_entry=" in message
    assert "NativeBlockRef(" not in message
    assert "BlockSnapshot(" not in message
    assert "InsnSnapshot(" not in message
    assert len(message) < 2_048
    assert all(record.levelname == "WARNING" for record in caplog.records)


def test_projected_inventory_does_not_emit_observed_native_origin_diagnostic(
    caplog,
) -> None:
    """The raw live trace is reserved for the observed transaction boundary."""
    source, proposal, plan, candidate, _owner_serial = _redirected_call_candidate(
        redirect_target=2,
        generated_kind=model.InsnKind.GOTO,
        generated_operand_target=4,
    )
    source_inventory = transaction_api._build_semantic_graph_inventory(
        source, proposal, plan, source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
    )

    # Projected rebinding no longer grants source ownership to a block whose
    # native origins changed. The reachable CALL fails the effect gate before
    # a later native-identity mismatch check would run.
    with pytest.raises(
        ValueError, match="candidate reachable effects are missing subjects"
    ):
        transaction_api._build_semantic_graph_inventory(
            candidate, proposal, plan, source=False,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            source_subjects=source_inventory.subjects,
        )

    assert not any(
        "observed unflatten native-origin mismatch" in record.getMessage()
        for record in caplog.records
    )


def _relocated_stop_tail_receipt_case(*, wrong_target: bool = False, split_corridors: bool = False):
    """One exact corridor relocation with Hex-Rays' appended STOP GOTO."""
    from d810.ir.flowgraph import FlowGraph, InsnKind, InsnSnapshot, MopSnapshot, OperandKind
    from d810.ir.maturity import MaturityEnvelope
    from d810.ir.semantics import ControlTransferKind
    from d810.transforms.cfg_transaction import LogicalBlockRef, TransactionAttemptId
    from d810.transforms.patch_binding import BoundPatchPlan, iter_refs, observed_patch_binding
    from d810.transforms.plan import (
        PatchBlockSpec,
        PatchEdgeSplitCorridor,
        PatchPlan,
        PatchRelocationMap,
    )

    source, proposal, _exclusion, refs = __import__(
        "tests.unit.transforms.unflatten_authority.test_bind",
        fromlist=["_exact_fixture"],
    )._exact_fixture()
    owner_ref = refs[3]
    stop_ref = LogicalBlockRef(proposal.plan_id, "relocated-stop", 1)
    first_helper = PlanBlockRef(proposal.plan_id, "relocated-stop-first")
    second_helper = PlanBlockRef(proposal.plan_id, "relocated-stop-second")
    corridor_steps = (
        PatchEdgeSplitCorridor(
            (first_helper,), refs[0], refs[1], refs[2], refs[1], refs[1], (refs[1],),
        ),
        PatchEdgeSplitCorridor(
            (second_helper,), refs[0], refs[1], refs[2], refs[1], refs[1], (refs[1],),
        ),
    ) if split_corridors else (
        PatchEdgeSplitCorridor(
            (first_helper, second_helper), refs[0], refs[1], refs[2],
            refs[1], refs[1], (refs[1],),
        ),
    )
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("relocated-stop-tail"),
        source_generation=1,
        steps=corridor_steps,
        new_blocks=(
            PatchBlockSpec(first_helper, "insert_block", template_block=refs[0]),
            PatchBlockSpec(second_helper, "insert_block", template_block=refs[0]),
        ),
        relocation_map=PatchRelocationMap(
            ((first_helper, refs[1]), (second_helper, refs[1])), stop_ref,
        ),
        source_coordinates=((refs[0], 0), (refs[1], 1), (refs[2], 2), (owner_ref, 3), (stop_ref, 4)),
    )
    attempt = TransactionAttemptId(plan.plan_id, "relocated-stop", 1, "tail")
    source_coordinates = dict(plan.source_coordinates)
    bound = BoundPatchPlan(
        plan, attempt, attempt.session_id, attempt.generation,
        MaturityEnvelope(ir=None, provider="test", provider_id=0),
        tuple(
            (ref, source_coordinates[ref])
            for ref in dict.fromkeys(iter_refs((plan.steps, plan.new_blocks, plan.relocation_map)))
            if type(ref) is not PlanBlockRef
        ) + ((first_helper, 14), (second_helper, 15)),
    )
    binding = observed_patch_binding(bound, ((first_helper, 4), (second_helper, 5)))
    prefix = InsnSnapshot(7, 0x4000, (), kind=InsnKind.XDU, raw_opcode=7)
    source_owner = BlockSnapshot(
        3, 0, (4,), (), 0, 0x4000, (prefix,),
        tail_opcode=7, raw_tail_opcode=7, tail_kind=InsnKind.XDU,
        kind=BlockKind.ONE_WAY,
    )
    source_stop = BlockSnapshot(4, 0, (), (3,), 0, _BADADDR, (), kind=BlockKind.STOP)
    projected_owner = replace(source_owner, succs=(6,))
    projected_stop = replace(source_stop, serial=6, preds=(3,))
    function_ea = source.func_ea
    tail_target = 17 if wrong_target else 6
    tail = InsnSnapshot(
        8, function_ea, (),
        l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=tail_target),
        kind=InsnKind.GOTO, raw_opcode=8,
        control_transfer_kind=ControlTransferKind.GOTO,
        native_ea=function_ea,
    )
    observed_owner = replace(
        source_owner, succs=(tail_target,),
        insn_snapshots=(prefix, tail), tail_opcode=8, raw_tail_opcode=8,
        tail_kind=InsnKind.GOTO,
    )
    observed_stop = replace(source_stop, serial=6, preds=(3,))
    helper = BlockSnapshot(4, 0, (), (), 0, _BADADDR, (), kind=BlockKind.ZERO_WAY)
    helper_two = replace(helper, serial=5)
    source_graph = FlowGraph(
        {3: source_owner, 4: source_stop}, 3, function_ea,
    )
    projected_graph = FlowGraph(
        {3: projected_owner, 4: helper, 5: helper_two, 6: projected_stop},
        3,
        function_ea,
    )
    observed_graph = FlowGraph(
        {3: observed_owner, 4: helper, 5: helper_two, 6: observed_stop},
        3,
        function_ea,
    )
    source_rows = (
        producer_api.observe_inventory_block(source_graph.blocks[3], owner_ref=owner_ref, owner_anchor_ea=0x4000),
        producer_api.observe_inventory_block(source_graph.blocks[4], owner_ref=stop_ref, owner_anchor_ea=None),
    )
    projected_rows = (
        producer_api.observe_inventory_block(projected_graph.blocks[3], owner_ref=owner_ref, owner_anchor_ea=0x4000),
        producer_api.observe_inventory_block(projected_graph.blocks[4], owner_ref=first_helper, owner_anchor_ea=None),
        producer_api.observe_inventory_block(projected_graph.blocks[5], owner_ref=second_helper, owner_anchor_ea=None),
        # The source logical STOP is displaced by helper allocation.  The
        # projected inventory deliberately records its shifted structural row
        # as ownerless; it is not a surviving logical identity.
        producer_api.observe_inventory_block(projected_graph.blocks[6], owner_ref=None, owner_anchor_ea=None),
    )
    return SimpleNamespace(
        source_graph=source_graph,
        projected_graph=projected_graph,
        observed_graph=observed_graph,
        blocks=observed_graph.blocks, plan=plan,
        source_rows=source_rows, projected_rows=projected_rows,
        observed_patch_binding=binding,
        planned_serials={first_helper: 4, second_helper: 5},
        function_ea=function_ea, owner_ref=owner_ref,
    )


def test_observed_relocated_stop_tail_receipt_mints_only_exact_corridor_case() -> None:
    case = _relocated_stop_tail_receipt_case()

    receipts = transaction_api._mint_observed_relocated_stop_tail_receipts(
        blocks=case.blocks,
        plan=case.plan,
        source_rows=case.source_rows,
        projected_rows=case.projected_rows,
        observed_patch_binding=case.observed_patch_binding,
        planned_serials=case.planned_serials,
        function_ea=case.function_ea,
    )

    assert len(receipts) == 1
    assert receipts[0].owner_ref == case.owner_ref
    assert receipts[0].observed_owner_serial == 3
    assert receipts[0].synthetic_tail_origin == case.function_ea
    assert receipts[0].observed_patch_binding is case.observed_patch_binding
    raw_owner = producer_api.observe_inventory_block(
        case.observed_graph.blocks[3],
        owner_ref=case.owner_ref,
        owner_anchor_ea=0x4000,
    )
    normalized_owner = transaction_api._normalize_observed_relocated_stop_tail_origin(
        raw_owner,
        receipt=receipts[0],
        observed_patch_binding=case.observed_patch_binding,
    )
    assert raw_owner.native_instruction_eas == (0x4000, case.function_ea)
    assert normalized_owner.native_instruction_eas == (0x4000,)
    assert normalized_owner.instruction_observations[0] == raw_owner.instruction_observations[0]
    assert normalized_owner.instruction_observations[-1].instruction_kind is model.InsnKind.GOTO
    assert normalized_owner.instruction_observations[-1].instruction_ea is None
    assert normalized_owner.transfer_ea is None
    assert normalized_owner.successor_serials == (6,)
    assert case.observed_graph.blocks[6].preds == (3,)

    foreign_equal_binding = replace(case.observed_patch_binding)
    assert foreign_equal_binding == case.observed_patch_binding
    assert foreign_equal_binding is not case.observed_patch_binding
    with pytest.raises(ValueError, match="binding occurrence"):
        transaction_api._consume_observed_relocated_stop_tail_receipt(
            receipts[0],
            observed_patch_binding=foreign_equal_binding,
            owner_ref=case.owner_ref,
            observed_owner_serial=3,
        )
    with pytest.raises(ValueError, match="owner occurrence"):
        transaction_api._consume_observed_relocated_stop_tail_receipt(
            receipts[0],
            observed_patch_binding=case.observed_patch_binding,
            owner_ref=case.owner_ref,
            observed_owner_serial=20,
        )
    exact_prebound = {case.owner_ref: 3}
    transaction_api._admit_relocated_stop_tail_owner(exact_prebound, receipts[0])
    assert exact_prebound == {case.owner_ref: 3}
    foreign_ref = case.plan.source_coordinates[0][0]
    with pytest.raises(ValueError, match="overlaps another identity"):
        transaction_api._admit_relocated_stop_tail_owner(
            {case.owner_ref: 20}, receipts[0],
        )
    with pytest.raises(ValueError, match="overlaps another identity"):
        transaction_api._admit_relocated_stop_tail_owner(
            {foreign_ref: 3}, receipts[0],
        )


def test_observed_relocated_stop_tail_receipt_accepts_ordered_multi_corridor_helpers() -> None:
    case = _relocated_stop_tail_receipt_case(split_corridors=True)

    receipts = transaction_api._mint_observed_relocated_stop_tail_receipts(
        blocks=case.blocks,
        plan=case.plan,
        source_rows=case.source_rows,
        projected_rows=case.projected_rows,
        observed_patch_binding=case.observed_patch_binding,
        planned_serials=case.planned_serials,
        function_ea=case.function_ea,
    )

    assert len(receipts) == 1


def test_observed_relocated_stop_tail_receipt_rejects_rebound_projected_stop() -> None:
    """A relocated STOP is an ownerless projected structural row, never a rebinding."""
    case = _relocated_stop_tail_receipt_case()
    rebound_stop = replace(
        case.projected_rows[-1],
        block_ref=case.plan.relocation_map.source_stop,
    )

    assert transaction_api._mint_observed_relocated_stop_tail_receipts(
        blocks=case.blocks,
        plan=case.plan,
        source_rows=case.source_rows,
        projected_rows=(*case.projected_rows[:-1], rebound_stop),
        observed_patch_binding=case.observed_patch_binding,
        planned_serials=case.planned_serials,
        function_ea=case.function_ea,
    ) == ()


@pytest.mark.parametrize("mutation", ("duplicate", "reordered", "foreign"))
def test_relocated_stop_helper_ownership_rejects_non_bijective_corridor_groups(
    mutation: str,
) -> None:
    case = _relocated_stop_tail_receipt_case()
    (corridor,) = case.plan.steps
    helpers = tuple(case.planned_serials)
    if mutation == "duplicate":
        clone_ids = (helpers[0], helpers[0], helpers[1])
    elif mutation == "reordered":
        clone_ids = tuple(reversed(helpers))
    else:
        clone_ids = (*helpers, PlanBlockRef(case.plan.plan_id, "foreign-helper"))
    malformed = replace(case.plan, steps=(replace(corridor, clone_block_ids=clone_ids),))

    assert not transaction_api._has_exact_relocated_stop_helper_ownership(
        malformed,
        helpers,
    )


@pytest.mark.parametrize("wrong_target", (True,))
def test_observed_relocated_stop_tail_receipt_rejects_wrong_tail_target(wrong_target: bool) -> None:
    case = _relocated_stop_tail_receipt_case(wrong_target=wrong_target)

    assert transaction_api._mint_observed_relocated_stop_tail_receipts(
        blocks=case.blocks,
        plan=case.plan,
        source_rows=case.source_rows,
        projected_rows=case.projected_rows,
        observed_patch_binding=case.observed_patch_binding,
        planned_serials=case.planned_serials,
        function_ea=case.function_ea,
    ) == ()


def test_observed_relocated_stop_tail_receipt_rejects_projected_prefix_drift() -> None:
    case = _relocated_stop_tail_receipt_case()
    projected_owner = case.projected_rows[0]
    drifted_instruction = replace(
        projected_owner.instruction_observations[0], opcode=0x77,
    )
    drifted_rows = (
        replace(
            projected_owner,
            instruction_observations=(drifted_instruction,),
            tail_opcode=0x77,
            raw_tail_opcode=7,
        ),
        *case.projected_rows[1:],
    )

    assert transaction_api._mint_observed_relocated_stop_tail_receipts(
        blocks=case.blocks,
        plan=case.plan,
        source_rows=case.source_rows,
        projected_rows=drifted_rows,
        observed_patch_binding=case.observed_patch_binding,
        planned_serials=case.planned_serials,
        function_ea=case.function_ea,
    ) == ()


@pytest.mark.parametrize("mutation", ("helper_interval", "helper_order", "stop_relocation"))
def test_observed_relocated_stop_tail_receipt_rejects_wrong_allocation_relation(
    mutation: str,
) -> None:
    case = _relocated_stop_tail_receipt_case()
    planned_serials = case.planned_serials
    projected_rows = case.projected_rows
    if mutation == "helper_interval":
        first, second = tuple(planned_serials)
        planned_serials = {first: 5, second: 6}
    elif mutation == "helper_order":
        first, second = tuple(planned_serials.items())
        planned_serials = {second[0]: second[1], first[0]: first[1]}
    else:
        projected_rows = (*projected_rows[:-1], replace(projected_rows[-1], serial=7))

    assert transaction_api._mint_observed_relocated_stop_tail_receipts(
        blocks=case.blocks,
        plan=case.plan,
        source_rows=case.source_rows,
        projected_rows=projected_rows,
        observed_patch_binding=case.observed_patch_binding,
        planned_serials=planned_serials,
        function_ea=case.function_ea,
    ) == ()


@pytest.mark.parametrize(
    "mutation",
    ("malformed_tail", "nonterminal_stop", "prefix_drift", "missing_helper"),
)
def test_observed_relocated_stop_tail_receipt_rejects_any_unsealed_shape(
    mutation: str,
) -> None:
    case = _relocated_stop_tail_receipt_case()
    blocks = dict(case.blocks)
    if mutation == "malformed_tail":
        tail = blocks[3].insn_snapshots[-1]
        blocks[3] = replace(
            blocks[3],
            insn_snapshots=(*blocks[3].insn_snapshots[:-1], replace(
                tail, kind=model.InsnKind.NOP, control_transfer_kind=None,
            )),
        )
    elif mutation == "nonterminal_stop":
        blocks[6] = replace(blocks[6], kind=BlockKind.ZERO_WAY)
    elif mutation == "prefix_drift":
        prefix = blocks[3].insn_snapshots[0]
        blocks[3] = replace(
            blocks[3], insn_snapshots=(replace(prefix, opcode=99), *blocks[3].insn_snapshots[1:]),
        )
    elif mutation == "missing_helper":
        blocks.pop(4)
    assert transaction_api._mint_observed_relocated_stop_tail_receipts(
        blocks=blocks,
        plan=case.plan,
        source_rows=case.source_rows,
        projected_rows=case.projected_rows,
        observed_patch_binding=case.observed_patch_binding,
        planned_serials=case.planned_serials,
        function_ea=case.function_ea,
    ) == ()


def _topology_inventory(*, topology: tuple[model.InventoryTopologyIncidence, ...]) -> model.SemanticGraphInventory:
    ref1 = PlanBlockRef("topology", "one")
    ref2 = PlanBlockRef("topology", "two")
    block1 = model.InventoryBlockObservation(
        1, ref1, 0x1000, (0x1000, 0x1004), (), (2,), None,
        (
            model.InventoryInstructionObservation(0, 0x1000, 1, 0, model.InsnKind.NOP, None, False, None, raw_opcode=1),
            model.InventoryInstructionObservation(1, 0x1004, 2, 0, model.InsnKind.NOP, None, False, None, raw_opcode=2),
        ),
        tail_opcode=2, raw_tail_opcode=2, tail_kind=model.InsnKind.NOP,
    )
    block2 = model.InventoryBlockObservation(
        2, ref2, 0x2000, (0x2000,), (1,), (), None,
        (model.InventoryInstructionObservation(0, 0x2000, 3, 0, model.InsnKind.NOP, None, False, None, raw_opcode=3),),
        tail_opcode=3, raw_tail_opcode=3, tail_kind=model.InsnKind.NOP,
    )
    subjects = tuple(sorted((
        _subject_factory(
            model.SemanticSubjectRef,
            kind=model.SemanticSubjectKind.BLOCK,
            role=model.SemanticSubjectRole.SOURCE_ENTRY,
            block_ref=ref1, anchor_ea=0x1000,
            locator=model.BlockSubjectLocator(ref1, 0x1000),
        ),
        _subject_factory(
            model.SemanticSubjectRef,
            kind=model.SemanticSubjectKind.BLOCK,
            role=model.SemanticSubjectRole.DISPATCHER_ENTRY,
            block_ref=ref2, anchor_ea=0x2000,
            locator=model.BlockSubjectLocator(ref2, 0x2000),
        ),
    ), key=lambda item: item.subject_id))
    phase = model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
    fingerprint = authority_id("topology-graph")
    blocks = (block1, block2)
    closure = (1, 2)
    bindings = tuple(
        model.PhaseSubjectBinding(
            subject, phase, None, fingerprint, 3,
            model.SubjectBindingStatus.MISSING, None, None, (), subject.role,
        )
        for subject in subjects
    )
    digest = semantic_graph_inventory_digest(
        phase, fingerprint, 3, blocks, subjects, bindings, (), (), topology, closure,
        1, tuple(item.subject_id for item in subjects), 0,
    )
    return model.SemanticGraphInventory(
        phase, fingerprint, 3, blocks, subjects, bindings, (), (), topology, digest,
        closure,
        1,
        tuple(item.subject_id for item in subjects),
        0,
    )


def test_raw_topology_incidence_requires_both_reciprocal_rows_and_anchor() -> None:
    successor = model.InventoryTopologyIncidence(
        model.TopologyIncidenceKind.SUCCESSOR, 1, 2, None,
    )
    predecessor = model.InventoryTopologyIncidence(
        model.TopologyIncidenceKind.PREDECESSOR, 2, 1, None,
    )
    inventory = _topology_inventory(topology=(predecessor, successor))
    assert {(row.kind, row.owner_serial, row.peer_serial) for row in inventory.topology} == {
        (model.TopologyIncidenceKind.SUCCESSOR, 1, 2),
        (model.TopologyIncidenceKind.PREDECESSOR, 2, 1),
    }
    with pytest.raises(ValueError, match="topology incidence"):
        _topology_inventory(topology=(successor,))
    with pytest.raises(ValueError, match="topology incidence"):
        _topology_inventory(topology=(predecessor,))
    with pytest.raises(ValueError, match="transfer"):
        _topology_inventory(topology=(
            predecessor,
            model.InventoryTopologyIncidence(
                model.TopologyIncidenceKind.SUCCESSOR, 1, 2, 0xDEAD,
            ),
        ))
