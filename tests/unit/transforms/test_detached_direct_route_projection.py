"""Off-side projection of one prepared direct semantic route."""

from __future__ import annotations

from dataclasses import replace

import pytest

from d810.ir.flowgraph import BlockKind, InsnKind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.transforms.canonical_semantic_fragment import (
    plan_detached_reference_direct_route,
)
from d810.transforms.cfg_transaction import PlanBlockRef
from d810.transforms.detached_direct_route_projection import (
    DetachedDirectRouteProjectionRejected,
    project_detached_direct_route,
)
from d810.transforms.fragment_plan import FragmentBlockRole
from d810.transforms.prepared_native_body import (
    PreparedNativeBlockFact,
    PreparedNativeBodyFact,
    PreparedNativeBodyFactSnapshot,
    PreparedNativeEdgeFact,
    PreparedNativeInstructionFact,
    PreparedNormalizationWorkItemSnapshot,
)
from tests.unit.transforms.test_canonical_semantic_fragment import (
    _detached_reference_direct_route_case,
)


def _prepared_body_fact(plan) -> PreparedNativeBodyFact:
    (native_body,) = plan.native_bodies
    operations_by_source = {
        block_id: tuple(
            operation
            for operation in plan.operations
            if operation.source_block_id == block_id
        )
        for block_id in native_body.block_ids
    }
    predecessors = {block_id: [] for block_id in native_body.block_ids}
    for source_id, operations in operations_by_source.items():
        for operation in operations:
            for edge in operation.edges:
                if edge.target_block_id in predecessors:
                    predecessors[edge.target_block_id].append(source_id)

    corridor_instruction_eas = {
        "native@0x40BB3A": (0x40BB3A, 0x40BB44, 0x40BB4B),
        "native@0x40BB51": (0x40BB51, 0x40BB63),
    }
    blocks = []
    for block_id in native_body.block_ids:
        block = plan.block(block_id)
        operations = operations_by_source[block_id]
        successors = tuple(
            PreparedNativeEdgeFact(edge.role, edge.target_block_id)
            for operation in operations
            for edge in operation.edges
        )
        kind = {
            0: BlockKind.ZERO_WAY,
            1: BlockKind.ONE_WAY,
            2: BlockKind.TWO_WAY,
        }.get(len(successors), BlockKind.N_WAY)
        if block_id in native_body.terminal_block_ids:
            terminator_ea = block.semantic_anchor_ea
            terminator_kind = InsnKind.RET
        elif len(successors) == 2:
            (operation,) = operations
            terminator_ea = operation.predicate_anchor_ea
            terminator_kind = InsnKind.COND_JUMP
        elif len(successors) == 1:
            terminator_ea = block.semantic_anchor_ea
            terminator_kind = InsnKind.GOTO
        else:
            terminator_ea = None
            terminator_kind = InsnKind.UNKNOWN
        instruction_eas = corridor_instruction_eas.get(
            block_id,
            (block.semantic_anchor_ea,),
        )
        if terminator_ea is not None and terminator_ea not in instruction_eas:
            instruction_eas = (*instruction_eas, terminator_ea)
        instructions = tuple(
            PreparedNativeInstructionFact(
                instruction_id=f"{block_id}:{index}",
                native_ea=int(instruction_ea),
                opcode=0x100 + index,
                kind=(
                    terminator_kind if instruction_ea == terminator_ea else InsnKind.MOV
                ),
                operand_shape=(),
                writes_condition_codes=False,
            )
            for index, instruction_ea in enumerate(instruction_eas)
        )
        blocks.append(
            PreparedNativeBlockFact(
                block_id=block_id,
                semantic_anchor_ea=block.semantic_anchor_ea,
                stable_identity=block.stable_identity,
                block_flags=0,
                kind=kind,
                successors=successors,
                predecessor_block_ids=tuple(predecessors[block_id]),
                terminator_ea=terminator_ea,
                terminator_kind=terminator_kind,
                instructions=instructions,
            )
        )
    return PreparedNativeBodyFact(
        plan_id=plan.plan_id,
        body_id=native_body.body_id,
        native_ranges=native_body.native_ranges,
        entry_block_ids=native_body.entry_block_ids,
        terminal_block_ids=native_body.terminal_block_ids,
        blocks=tuple(blocks),
    )


def _case():
    normalization_plan, evidence, authority, reference_route = (
        _detached_reference_direct_route_case()
    )
    detached_plan = plan_detached_reference_direct_route(
        normalization_plan,
        evidence,
        reference_route,
        normalization_authority=authority,
    )
    assert detached_plan is not None
    prepared_body = _prepared_body_fact(normalization_plan)
    (native_body,) = normalization_plan.native_bodies
    suffix = "root@0x40BB51"
    work_item_plan_id = f"{normalization_plan.plan_id}:{suffix}"
    work_item_body_id = f"{native_body.body_id}:{suffix}"
    scope = normalization_plan.work_item_scope
    assert scope is not None
    work_item_plan = replace(
        normalization_plan,
        plan_id=work_item_plan_id,
        atomic_group_id=f"{normalization_plan.atomic_group_id}:{suffix}",
        blocks=tuple(
            replace(block, native_body_id=work_item_body_id)
            if block.role is FragmentBlockRole.IMPORTED
            else block
            for block in normalization_plan.blocks
        ),
        work_item_scope=replace(scope, work_item_id=work_item_plan_id),
        native_bodies=(replace(native_body, body_id=work_item_body_id),),
    )
    work_item_authority = replace(authority, work_item_id=work_item_plan_id)
    prepared_body = replace(
        prepared_body,
        plan_id=work_item_plan_id,
        body_id=work_item_body_id,
    )
    return (
        normalization_plan,
        detached_plan,
        PreparedNormalizationWorkItemSnapshot(
            source_plan_id=normalization_plan.plan_id,
            source_atomic_group_id=normalization_plan.atomic_group_id,
            work_item_plan=work_item_plan,
            authority=work_item_authority,
            prepared_bodies=PreparedNativeBodyFactSnapshot(
                plan_id=work_item_plan_id,
                evidence_generation=work_item_authority.evidence_generation,
                snapshot_id="preopt:g3:prepared-body",
                bodies=(prepared_body,),
            ),
        ),
    )


def _block_at(projection, native_ea: int):
    matches = tuple(
        block
        for block in projection.graph.blocks.values()
        if block.native_start_ea == native_ea
    )
    assert len(matches) == 1
    return matches[0]


def test_detached_direct_route_projects_both_raw_arms_to_one_portable_goto() -> None:
    normalization_plan, detached_plan, prepared_work_item = _case()

    projection = project_detached_direct_route(
        normalization_plan,
        detached_plan,
        prepared_work_item,
    )

    source = _block_at(projection, 0x40BB51)
    target = _block_at(projection, 0x40ACF3)
    assert projection.plan_id == detached_plan.plan_id
    assert projection.snapshot_id == "preopt:g3:prepared-body"
    assert projection.graph.entry_serial == source.serial
    assert source.kind is BlockKind.ONE_WAY
    assert source.tail_kind is InsnKind.GOTO
    assert source.tail is not None
    assert source.tail.kind is InsnKind.GOTO
    assert source.tail.ea == 0x40BB63
    assert source.succs == (target.serial,)
    assert set(target.preds) >= {source.serial}
    assert projection.focus_refs == (
        PlanBlockRef(detached_plan.plan_id, "native@0x40BB51"),
        PlanBlockRef(detached_plan.plan_id, "native@0x40ACF3"),
        PlanBlockRef(detached_plan.plan_id, "native@0x40BB3A"),
    )
    assert projection.graph.metadata == {
        "projection_kind": "detached_direct_route",
        "normalization_plan_id": normalization_plan.plan_id,
        "prepared_work_item_plan_id": prepared_work_item.work_item_plan.plan_id,
        "prepared_work_item_revision": 1,
        "detached_plan_id": detached_plan.plan_id,
        "evidence_generation": 3,
        "native_body_id": prepared_work_item.prepared_bodies.bodies[0].body_id,
        "reference_route_id": "rhad:0x40A560:flow_route:0x40BB63",
        "source_block_id": "native@0x40BB51",
        "source_owner_ea": 0x40BB51,
        "rewrite_anchor_ea": 0x40BB63,
        "target_block_id": "native@0x40ACF3",
        "direct_target_ea": 0x40ACF3,
        "superseded_operation_id": "native-body-edge@0x40BB51",
        "superseded_edge_roles": (
            SemanticEdgeRole.CONDITIONAL_TAKEN.value,
            SemanticEdgeRole.CONDITIONAL_FALLTHROUGH.value,
        ),
        "projected_operation_id": detached_plan.operation.operation_id,
        "projected_terminator": InsnKind.GOTO.value,
        "projected_edge_roles": (SemanticEdgeRole.DIRECT.value,),
        "corridor_block_ids": (
            "native@0x40BB3A",
            "native@0x40BB51",
        ),
        "corridor_owner_eas": (0x40BB3A, 0x40BB51),
        "proof_corridor_instruction_eas": (0x40BB44, 0x40BB4B, 0x40BB63),
        "live_mutation_started": False,
        "publication_eligible": False,
        "receipt_created": False,
    }


def test_detached_direct_route_rejects_partial_prepared_arm_supersession() -> None:
    normalization_plan, detached_plan, prepared_work_item = _case()
    (prepared_body,) = prepared_work_item.prepared_bodies.bodies
    source = prepared_body.block(detached_plan.source_block.block_id)
    partial = replace(
        source,
        kind=BlockKind.ONE_WAY,
        successors=(
            PreparedNativeEdgeFact(
                SemanticEdgeRole.CONDITIONAL_TAKEN,
                source.successors[0].target_block_id,
            ),
        ),
    )
    prepared_body = replace(
        prepared_body,
        blocks=tuple(
            partial if block.block_id == partial.block_id else block
            for block in prepared_body.blocks
        ),
    )
    prepared_work_item = replace(
        prepared_work_item,
        prepared_bodies=replace(
            prepared_work_item.prepared_bodies,
            bodies=(prepared_body,),
        ),
    )

    with pytest.raises(DetachedDirectRouteProjectionRejected) as exc_info:
        project_detached_direct_route(
            normalization_plan,
            detached_plan,
            prepared_work_item,
        )

    rejection = exc_info.value
    assert rejection.reason_code == "prepared_source_raw_operation_drift"
    assert rejection.anchor_ea == 0x40BB63
    assert rejection.live_mutation_started is False
    assert rejection.failure_phase == "projection"
