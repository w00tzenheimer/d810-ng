"""Off-side projection of one prepared direct semantic route."""

from __future__ import annotations

from dataclasses import replace

import pytest

from d810.ir.flowgraph import BlockKind, InsnKind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.transforms.canonical_semantic_fragment import (
    CanonicalSemanticFragmentRejected,
    compile_receipted_prepared_topology,
    plan_detached_reference_direct_route,
    validate_receipted_prepared_topology_scope,
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
                boundary_exit_eas=(),
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


def _preserved_source_case():
    normalization_plan, detached_plan, prepared_work_item = _case()
    source_id = detached_plan.source_block.block_id
    source_operations = tuple(
        operation
        for operation in normalization_plan.operations
        if operation.source_block_id == source_id
    )
    assert len(source_operations) == 1
    (raw_operation,) = source_operations
    (complete_body,) = normalization_plan.native_bodies
    normalization_plan = replace(
        normalization_plan,
        operations=tuple(
            operation
            for operation in normalization_plan.operations
            if operation is not raw_operation
        ),
        native_bodies=(
            replace(
                complete_body,
                proof_ids=tuple(
                    proof_id
                    for proof_id in complete_body.proof_ids
                    if proof_id != raw_operation.operation_id
                ),
                preserved_native_transfer_block_ids=(source_id,),
            ),
        ),
    )
    work_item_plan = prepared_work_item.work_item_plan
    (work_body,) = work_item_plan.native_bodies
    work_item_plan = replace(
        work_item_plan,
        operations=tuple(
            operation
            for operation in work_item_plan.operations
            if operation.source_block_id != source_id
        ),
        native_bodies=(
            replace(
                work_body,
                proof_ids=tuple(
                    proof_id
                    for proof_id in work_body.proof_ids
                    if proof_id != raw_operation.operation_id
                ),
                preserved_native_transfer_block_ids=(source_id,),
            ),
        ),
    )
    (prepared_body,) = prepared_work_item.prepared_bodies.bodies
    prepared_work_item = replace(
        prepared_work_item,
        work_item_plan=work_item_plan,
        prepared_bodies=replace(
            prepared_work_item.prepared_bodies,
            bodies=(
                replace(
                    prepared_body,
                    preserved_native_transfer_block_ids=(source_id,),
                ),
            ),
        ),
    )
    return (
        normalization_plan,
        detached_plan,
        prepared_work_item,
        raw_operation,
        prepared_body,
    )


def test_receipted_prepared_topology_compiles_preserved_edge_operation() -> None:
    (
        normalization_plan,
        detached_plan,
        prepared_work_item,
        raw_operation,
        prepared_body,
    ) = _preserved_source_case()
    source_id = detached_plan.source_block.block_id

    compiled = compile_receipted_prepared_topology(
        normalization_plan,
        prepared_work_item,
    )

    synthesized = tuple(
        operation
        for operation in compiled.operations
        if operation.source_block_id == source_id
    )
    assert len(synthesized) == 1
    assert synthesized[0].edges == raw_operation.edges
    assert synthesized[0].predicate_anchor_ea == (
        prepared_body.block(source_id).terminator_ea
    )
    (compiled_body,) = compiled.native_bodies
    assert source_id not in compiled_body.preserved_native_transfer_block_ids
    assert synthesized[0].operation_id in compiled_body.proof_ids


def test_receipted_prepared_topology_compiles_one_boundary_exit() -> None:
    (
        normalization_plan,
        detached_plan,
        prepared_work_item,
        raw_operation,
        _prepared_body,
    ) = _preserved_source_case()
    source_id = detached_plan.source_block.block_id
    target_id = raw_operation.edges[0].target_block_id
    target_ea = normalization_plan.block(target_id).semantic_anchor_ea
    (prepared_body,) = prepared_work_item.prepared_bodies.bodies
    prepared_work_item = replace(
        prepared_work_item,
        prepared_bodies=replace(
            prepared_work_item.prepared_bodies,
            bodies=(
                replace(
                    prepared_body,
                    blocks=tuple(
                        replace(
                            block,
                            kind=BlockKind.ZERO_WAY,
                            successors=(),
                            boundary_exit_eas=(target_ea,),
                            terminator_kind=InsnKind.INDIRECT_JUMP,
                        )
                        if block.block_id == source_id
                        else block
                        for block in prepared_body.blocks
                    ),
                ),
            ),
        ),
    )

    compiled = compile_receipted_prepared_topology(
        normalization_plan,
        prepared_work_item,
    )

    synthesized = tuple(
        operation
        for operation in compiled.operations
        if operation.source_block_id == source_id
    )
    assert len(synthesized) == 1
    assert synthesized[0].predicate_anchor_ea is None
    assert tuple(
        (edge.role, edge.target_block_id) for edge in synthesized[0].edges
    ) == ((SemanticEdgeRole.DIRECT, target_id),)


def test_receipted_prepared_topology_rejects_untyped_boundary_roles() -> None:
    (
        normalization_plan,
        detached_plan,
        prepared_work_item,
        raw_operation,
        _prepared_body,
    ) = _preserved_source_case()
    source_id = detached_plan.source_block.block_id
    boundary_exit_eas = tuple(
        sorted(
            normalization_plan.block(edge.target_block_id).semantic_anchor_ea
            for edge in raw_operation.edges
        )
    )
    (prepared_body,) = prepared_work_item.prepared_bodies.bodies
    prepared_work_item = replace(
        prepared_work_item,
        prepared_bodies=replace(
            prepared_work_item.prepared_bodies,
            bodies=(
                replace(
                    prepared_body,
                    blocks=tuple(
                        replace(
                            block,
                            kind=BlockKind.ZERO_WAY,
                            successors=(),
                            boundary_exit_eas=boundary_exit_eas,
                            terminator_kind=InsnKind.INDIRECT_JUMP,
                        )
                        if block.block_id == source_id
                        else block
                        for block in prepared_body.blocks
                    ),
                ),
            ),
        ),
    )

    compiled = compile_receipted_prepared_topology(
        normalization_plan,
        prepared_work_item,
    )
    (scoped_fact,) = (
        block
        for block in prepared_work_item.prepared_bodies.bodies[0].blocks
        if block.block_id == source_id
    )
    with pytest.raises(CanonicalSemanticFragmentRejected) as exc_info:
        validate_receipted_prepared_topology_scope(
            normalization_plan,
            compiled,
            normalization_plan,
            receipt_snapshot_ids=(prepared_work_item.prepared_bodies.snapshot_id,),
            prepared_block_facts={source_id: scoped_fact},
        )

    assert exc_info.value.reason_code == (
        "prepared_topology_boundary_role_unsupported"
    )
    assert exc_info.value.payload["boundary_exit_eas"] == tuple(
        f"0x{ea:X}" for ea in boundary_exit_eas
    )


def test_receipted_prepared_topology_compiles_call_fallthrough() -> None:
    (
        normalization_plan,
        detached_plan,
        prepared_work_item,
        raw_operation,
        _prepared_body,
    ) = _preserved_source_case()
    source_id = detached_plan.source_block.block_id
    source = normalization_plan.block(source_id)
    (source_range,) = source.stable_identity.native_ranges.intervals
    target_id = next(
        edge.target_block_id
        for edge in raw_operation.edges
        if normalization_plan.block(edge.target_block_id).semantic_anchor_ea
        == source_range.end_ea
    )
    (prepared_body,) = prepared_work_item.prepared_bodies.bodies
    prepared_work_item = replace(
        prepared_work_item,
        prepared_bodies=replace(
            prepared_work_item.prepared_bodies,
            bodies=(
                replace(
                    prepared_body,
                    blocks=tuple(
                        replace(
                            block,
                            kind=BlockKind.ZERO_WAY,
                            successors=(),
                            boundary_exit_eas=(),
                            terminator_kind=InsnKind.CALL,
                            instructions=tuple(
                                replace(instruction, kind=InsnKind.CALL)
                                if instruction.native_ea == block.terminator_ea
                                else instruction
                                for instruction in block.instructions
                            ),
                        )
                        if block.block_id == source_id
                        else block
                        for block in prepared_body.blocks
                    ),
                ),
            ),
        ),
    )

    compiled = compile_receipted_prepared_topology(
        normalization_plan,
        prepared_work_item,
    )

    synthesized = tuple(
        operation
        for operation in compiled.operations
        if operation.source_block_id == source_id
    )
    assert len(synthesized) == 1
    assert tuple(
        (edge.role, edge.target_block_id) for edge in synthesized[0].edges
    ) == ((SemanticEdgeRole.CALL_FALLTHROUGH, target_id),)


def test_receipted_prepared_topology_retypes_direct_call_successor() -> None:
    (
        normalization_plan,
        detached_plan,
        prepared_work_item,
        raw_operation,
        _prepared_body,
    ) = _preserved_source_case()
    source_id = detached_plan.source_block.block_id
    target_id = raw_operation.edges[0].target_block_id
    (prepared_body,) = prepared_work_item.prepared_bodies.bodies
    prepared_work_item = replace(
        prepared_work_item,
        prepared_bodies=replace(
            prepared_work_item.prepared_bodies,
            bodies=(
                replace(
                    prepared_body,
                    blocks=tuple(
                        replace(
                            block,
                            kind=BlockKind.ONE_WAY,
                            successors=(
                                PreparedNativeEdgeFact(
                                    SemanticEdgeRole.DIRECT,
                                    target_id,
                                ),
                            ),
                            boundary_exit_eas=(),
                            terminator_kind=InsnKind.CALL,
                            instructions=tuple(
                                replace(instruction, kind=InsnKind.CALL)
                                if instruction.native_ea == block.terminator_ea
                                else instruction
                                for instruction in block.instructions
                            ),
                        )
                        if block.block_id == source_id
                        else block
                        for block in prepared_body.blocks
                    ),
                ),
            ),
        ),
    )

    compiled = compile_receipted_prepared_topology(
        normalization_plan,
        prepared_work_item,
    )

    (synthesized,) = tuple(
        operation
        for operation in compiled.operations
        if operation.source_block_id == source_id
    )
    assert tuple(
        (edge.role, edge.target_block_id) for edge in synthesized.edges
    ) == ((SemanticEdgeRole.CALL_FALLTHROUGH, target_id),)


def test_receipted_prepared_topology_rejects_unknown_preserved_sink() -> None:
    (
        normalization_plan,
        detached_plan,
        prepared_work_item,
        _raw_operation,
        _prepared_body,
    ) = _preserved_source_case()
    source_id = detached_plan.source_block.block_id
    (prepared_body,) = prepared_work_item.prepared_bodies.bodies
    prepared_work_item = replace(
        prepared_work_item,
        prepared_bodies=replace(
            prepared_work_item.prepared_bodies,
            bodies=(
                replace(
                    prepared_body,
                    blocks=tuple(
                        replace(
                            block,
                            kind=BlockKind.ZERO_WAY,
                            successors=(),
                            boundary_exit_eas=(),
                            terminator_kind=InsnKind.UNKNOWN,
                        )
                        if block.block_id == source_id
                        else block
                        for block in prepared_body.blocks
                    ),
                ),
            ),
        ),
    )

    compiled = compile_receipted_prepared_topology(
        normalization_plan,
        prepared_work_item,
    )
    (scoped_fact,) = (
        block
        for block in prepared_work_item.prepared_bodies.bodies[0].blocks
        if block.block_id == source_id
    )
    with pytest.raises(CanonicalSemanticFragmentRejected) as exc_info:
        validate_receipted_prepared_topology_scope(
            normalization_plan,
            compiled,
            normalization_plan,
            receipt_snapshot_ids=(prepared_work_item.prepared_bodies.snapshot_id,),
            prepared_block_facts={source_id: scoped_fact},
        )

    assert exc_info.value.reason_code == "prepared_topology_transfer_role_unsupported"
    assert exc_info.value.payload == {
        "block_id": source_id,
        "terminator_ea": f"0x{prepared_body.block(source_id).terminator_ea:X}",
        "terminator_kind": InsnKind.UNKNOWN.value,
        "instruction_kinds": tuple(
            instruction.kind.value
            for instruction in prepared_body.block(source_id).instructions
        ),
        "receipt_snapshot_ids": (
            prepared_work_item.prepared_bodies.snapshot_id,
        ),
    }


def test_receipted_prepared_topology_preserves_evidence_only_return_carrier() -> None:
    (
        normalization_plan,
        detached_plan,
        prepared_work_item,
        _raw_operation,
        _prepared_body,
    ) = _preserved_source_case()
    source_id = detached_plan.source_block.block_id
    (prepared_body,) = prepared_work_item.prepared_bodies.bodies
    prepared_work_item = replace(
        prepared_work_item,
        prepared_bodies=replace(
            prepared_work_item.prepared_bodies,
            bodies=(
                replace(
                    prepared_body,
                    blocks=tuple(
                        replace(
                            block,
                            kind=BlockKind.ZERO_WAY,
                            successors=(),
                            boundary_exit_eas=(),
                            terminator_kind=InsnKind.RET,
                            instructions=(
                                replace(
                                    next(
                                        instruction
                                        for instruction in block.instructions
                                        if instruction.native_ea
                                        == block.terminator_ea
                                    ),
                                    kind=InsnKind.RET,
                                ),
                            ),
                        )
                        if block.block_id == source_id
                        else block
                        for block in prepared_body.blocks
                    ),
                ),
            ),
        ),
    )

    compiled = compile_receipted_prepared_topology(
        normalization_plan,
        prepared_work_item,
    )

    assert compiled == normalization_plan
    (compiled_body,) = compiled.native_bodies
    assert source_id in compiled_body.preserved_native_transfer_block_ids


def test_receipted_prepared_topology_scope_rejects_uncompiled_source() -> None:
    (
        normalization_plan,
        _detached_plan,
        prepared_work_item,
        _raw_operation,
        _prepared_body,
    ) = _preserved_source_case()

    with pytest.raises(CanonicalSemanticFragmentRejected) as exc_info:
        validate_receipted_prepared_topology_scope(
            normalization_plan,
            normalization_plan,
            normalization_plan,
            receipt_snapshot_ids=(prepared_work_item.prepared_bodies.snapshot_id,),
            prepared_block_facts={},
        )

    assert exc_info.value.reason_code == (
        "prepared_normalization_topology_coverage_missing"
    )
    assert exc_info.value.payload["uncompiled_block_ids"] == (
        "native@0x40BB51",
    )
    assert exc_info.value.payload["receipt_snapshot_ids"] == (
        prepared_work_item.prepared_bodies.snapshot_id,
    )


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
