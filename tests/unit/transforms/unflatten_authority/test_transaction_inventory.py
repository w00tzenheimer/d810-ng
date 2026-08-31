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
    *, redirect_target: int | None, generated_kind, generated_ea: int = 0xF000,
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
    owner_serial = 3
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("observed-redirect-native-origin"),
        source_generation=1,
        steps=(
            (PatchRedirectGoto(refs[0], refs[1], refs[1]),)
            if redirect_target is None
            else (PatchRedirectGoto(refs[owner_serial], refs[4], refs[redirect_target]),)
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
    generated = InsnSnapshot(
        0x55,
        generated_ea,
        (),
        l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=4),
        kind=generated_kind,
        raw_opcode=0x55,
        control_transfer_kind=(
            ControlTransferKind.GOTO if generated_kind is model.InsnKind.GOTO else None
        ),
    )
    candidate_owner = replace(
        original,
        succs=(4,),
        insn_snapshots=(*original.insn_snapshots, generated),
        tail_opcode=generated.opcode,
        raw_tail_opcode=generated.raw_opcode,
        tail_kind=generated.kind,
        kind=BlockKind.ONE_WAY,
    )
    candidate_target = replace(source.blocks[4], preds=(owner_serial,))
    candidate = FlowGraph(
        {**source.blocks, owner_serial: candidate_owner, 4: candidate_target},
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
    ("redirect_target", "generated_kind"),
    (
        (2, model.InsnKind.GOTO),
        (None, model.InsnKind.GOTO),
        (4, model.InsnKind.NOP),
    ),
)
def test_observed_inventory_rejects_non_authorized_extra_native_origin(
    redirect_target, generated_kind,
) -> None:
    source, proposal, plan, candidate, _owner_serial = _redirected_call_candidate(
        redirect_target=redirect_target, generated_kind=generated_kind,
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
