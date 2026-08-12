"""Live Hex-Rays realization of portable semantic fragment plans."""

from __future__ import annotations

from dataclasses import dataclass, field, replace

import ida_hexrays

from d810.core.logging import getLogger

logger = getLogger("d810.semantic_fragment_backend")

from d810.core.typing import Mapping, Protocol, TYPE_CHECKING, runtime_checkable
from d810.hexrays.ir.exact_data_flow import (
    find_exact_storage_access_eas,
    find_reaching_defs_for_reg_use_in_projection,
    find_reaching_defs_for_stkvar_use_in_projection,
    find_uses_reached_by_reg_definition_in_projection,
    find_uses_reached_by_stkvar_definition_in_projection,
    instruction_storage_access_roles,
)
from d810.hexrays.ir.exact_value_ranges import (
    ExactValueRangeQueryUnavailable,
    prove_exact_unsigned_range,
)
from d810.hexrays.ir.flag_queries import (
    ConditionCodeQueryUnavailable,
    condition_code_write_eas,
    instruction_writes_condition_codes,
)
from d810.hexrays.mutation.ir_translator import capture_mop_snapshot
from d810.hexrays.opcode_lift import (
    branch_opcode_for_predicate,
    branch_predicate_from_opcode,
    predicate_from_opcode,
    value_op_from_opcode,
)
from d810.hexrays.ir.logical_block_proxy import (
    LogicalBlockProxy,
    LogicalBlockVersion,
)
from d810.hexrays.ir.semantic_edge import (
    LogicalSemanticEdge,
    LogicalSemanticEdgeOperation,
)
from d810.hexrays.mutation.semantic_fragment_inventory import (
    SemanticFragmentRootInventory,
    SemanticFragmentRootInventoryItem,
    semantic_fragment_root_group_id,
)
from d810.hexrays.mutation.semantic_fragment_preparation import (
    PreparedConstantMaterializationFact,
    PreparedNativeBodyPreparation,
    PreparedNativeBodyPayload,
    PreparedReturnCarrierConstruction,
    PreparedSemanticFragment,
    SemanticFragmentRealizationPayload,
    SemanticFragmentSnapshotAuthority,
    SemanticFragmentSnapshotPreparation,
    sdk_instruction_kind,
    sdk_instruction_operand_shape,
    sdk_owned_call,
)
from d810.ir.block_identity import (
    BlockHandleProvenance,
    stable_block_identity_covers,
)
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import BlockKind, InsnKind, InsnSnapshot
from d810.ir.predicate_expressions import exact_branch_predicate_kind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.semantics import PredicateKind, inverted_predicate_kind
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.transforms.cfg_transaction import PlanBlockRef
from d810.transforms.fragment_plan import (
    FragmentAbsoluteConstantMaterialization,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentConstantPublicationEnvelope,
    FragmentComputedBranchNormalization,
    FragmentConditionalSelectEnvelope,
    FragmentImportedConditionalSelectEnvelope,
    FragmentNativeBody,
    FragmentOperation,
    FragmentPlan,
    FragmentRangeObservation,
    FragmentReferencedImportedConditionalSelectEnvelope,
    FragmentReturnCarrier,
    FragmentReturnSource,
    FragmentSetccFallthroughDelivery,
    FragmentSetccIndexedTableNormalization,
    superseded_direct_transfer_carrier_block_ids,
    superseded_referenced_conditional_carrier_block_ids,
    FragmentReturnSourceKind,
    FragmentTerminalReturn,
)
from d810.transforms.fragment_projection import (
    FragmentCloneSourceInstruction,
    FragmentCloneSourceInstructions,
    FragmentProjectionBlockInput,
    FragmentProjectionFailure,
    FragmentProjectionInput,
    fragment_cfg_projection,
    project_fragment,
)
from d810.transforms.contract import CfgContract, CfgContractViolationError
from d810.transforms.fragment_validation import (
    FragmentBindingState,
    FragmentValidationPostcondition,
    PublishedFragmentGraphObservation,
    PublishedFragmentObservation,
    ProjectedDataFlowRelation,
    ProjectedFallthroughHelper,
    ProjectedFragment,
    ProjectedFragmentBlock,
    ProjectedIdentityBinding,
    ProjectedRangeFact,
    ProjectedRootFallthroughHelper,
    ProjectedTerminalEffectDiagnostic,
    validate_published_fragment_projection,
)
from d810.transforms.prepared_native_body import (
    PreparedNativeBodyFact,
    PreparedNativeInstructionFact,
)

if TYPE_CHECKING:
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier


_BADADDR = 0xFFFFFFFFFFFFFFFF


def _iter_block_instructions(block):
    instruction = block.head
    while instruction is not None:
        yield instruction
        if instruction is block.tail:
            break
        instruction = instruction.next


def _primitive_shape_contains(
    shape: object,
    marker: tuple[object, ...],
) -> bool:
    if shape == marker:
        return True
    return isinstance(shape, tuple) and any(
        _primitive_shape_contains(item, marker) for item in shape
    )


def _prepared_flag_write(instruction: object) -> bool | None:
    try:
        return bool(instruction_writes_condition_codes(instruction))
    except ConditionCodeQueryUnavailable:
        return None


def _require_add_absolute_envelope(
    materialization: FragmentAbsoluteConstantMaterialization,
    facts: tuple[object, ...],
) -> None:
    """Prove the exact GENERATED lowering whose load may be replaced."""
    if (
        materialization.publication_envelope
        is not FragmentConstantPublicationEnvelope.GENERATED_ABSOLUTE_LOAD
    ):
        raise SemanticFragmentBackendRejected(
            "add_absolute publication envelope differs from reference evidence",
            reason_code="constant_materialization_envelope_mismatch",
            anchor_ea=materialization.instruction_ea,
            payload={"materialization_id": materialization.materialization_id},
        )
    expected_opcodes = (
        int(ida_hexrays.m_mov),
        int(ida_hexrays.m_mov),
        int(ida_hexrays.m_ldx),
        int(ida_hexrays.m_cfadd),
        int(ida_hexrays.m_ofadd),
        int(ida_hexrays.m_add),
        int(ida_hexrays.m_setz),
        int(ida_hexrays.m_setp),
        int(ida_hexrays.m_sets),
        int(ida_hexrays.m_mov),
    )
    if len(facts) != len(expected_opcodes) or tuple(
        int(getattr(fact, "opcode", -1)) for fact in facts
    ) != expected_opcodes:
        raise SemanticFragmentBackendRejected(
            "add_absolute GENERATED opcode envelope differs from reference evidence",
            reason_code="constant_materialization_envelope_mismatch",
            anchor_ea=materialization.instruction_ea,
            payload={"materialization_id": materialization.materialization_id},
        )
    shapes = tuple(getattr(fact, "operand_shape", ()) for fact in facts)
    if any(len(shape) != 3 for shape in shapes):
        raise SemanticFragmentBackendRejected(
            "add_absolute GENERATED operand envelope is incomplete",
            reason_code="constant_materialization_operand_mismatch",
            anchor_ea=materialization.instruction_ea,
            payload={"materialization_id": materialization.materialization_id},
        )
    left = tuple(shape[0] for shape in shapes)
    right = tuple(shape[1] for shape in shapes)
    destination = tuple(shape[2] for shape in shapes)
    dataflow_matches = (
        left[2] == destination[0]
        and right[2] == destination[1]
        and left[3] == left[4] == left[5] == destination[2]
        and right[3] == right[4] == right[5]
        and left[6] == left[7] == left[8] == left[9] == destination[5]
        and destination[9] == right[3]
        and _primitive_shape_contains(
            left[1],
            ("global", int(materialization.data_ea)),
        )
        and _primitive_shape_contains(right[6], ("number", 0))
        and _primitive_shape_contains(right[7], ("number", 0))
        and _primitive_shape_contains(
            destination[9],
            ("register", int(materialization.destination_storage.offset)),
        )
    )
    expected_sizes = (
        (destination[0], 2),
        (destination[1], 4),
        (destination[2], 4),
        (destination[3], 1),
        (destination[4], 1),
        (destination[5], 4),
        (destination[6], 1),
        (destination[7], 1),
        (destination[8], 1),
        (destination[9], 4),
    )
    sizes_match = all(
        isinstance(shape, tuple) and len(shape) >= 2 and int(shape[1]) == size
        for shape, size in expected_sizes
    )
    if not dataflow_matches or not sizes_match:
        raise SemanticFragmentBackendRejected(
            "add_absolute GENERATED data-flow envelope differs from reference evidence",
            reason_code="constant_materialization_dataflow_mismatch",
            anchor_ea=materialization.instruction_ea,
            payload={"materialization_id": materialization.materialization_id},
        )


def _require_mov_absolute_envelope(
    materialization: FragmentAbsoluteConstantMaterialization,
    facts: tuple[object, ...],
) -> None:
    """Prove one exact GENERATED absolute load delivered by a plain move."""
    if (
        materialization.publication_envelope
        is FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_MOVE
    ):
        if len(facts) != 1 or int(getattr(facts[0], "opcode", -1)) != int(
            ida_hexrays.m_mov
        ):
            raise SemanticFragmentBackendRejected(
                "mov_absolute imported opcode differs from reference evidence",
                reason_code="constant_materialization_envelope_mismatch",
                anchor_ea=materialization.instruction_ea,
                payload={"materialization_id": materialization.materialization_id},
            )
        shape = getattr(facts[0], "operand_shape", ())
        if (
            len(shape) != 3
            or not _primitive_shape_contains(
                shape[0],
                ("global", int(materialization.data_ea)),
            )
            or not _primitive_shape_contains(
                shape[2],
                ("register", int(materialization.destination_storage.offset)),
            )
            or not isinstance(shape[2], tuple)
            or len(shape[2]) < 2
            or int(shape[2][1]) != materialization.destination_width_bits // 8
        ):
            raise SemanticFragmentBackendRejected(
                "mov_absolute imported data flow differs from reference evidence",
                reason_code="constant_materialization_dataflow_mismatch",
                anchor_ea=materialization.instruction_ea,
                payload={"materialization_id": materialization.materialization_id},
            )
        return
    if (
        materialization.publication_envelope
        is not FragmentConstantPublicationEnvelope.GENERATED_ABSOLUTE_LOAD
    ):
        raise SemanticFragmentBackendRejected(
            "mov_absolute publication envelope differs from reference evidence",
            reason_code="constant_materialization_envelope_mismatch",
            anchor_ea=materialization.instruction_ea,
            payload={"materialization_id": materialization.materialization_id},
        )
    expected_opcodes = (
        int(ida_hexrays.m_mov),
        int(ida_hexrays.m_mov),
        int(ida_hexrays.m_ldx),
        int(ida_hexrays.m_mov),
    )
    if len(facts) != len(expected_opcodes) or tuple(
        int(getattr(fact, "opcode", -1)) for fact in facts
    ) != expected_opcodes:
        raise SemanticFragmentBackendRejected(
            "mov_absolute GENERATED opcode envelope differs from reference evidence",
            reason_code="constant_materialization_envelope_mismatch",
            anchor_ea=materialization.instruction_ea,
            payload={"materialization_id": materialization.materialization_id},
        )
    shapes = tuple(getattr(fact, "operand_shape", ()) for fact in facts)
    if any(len(shape) != 3 for shape in shapes):
        raise SemanticFragmentBackendRejected(
            "mov_absolute GENERATED operand envelope is incomplete",
            reason_code="constant_materialization_operand_mismatch",
            anchor_ea=materialization.instruction_ea,
            payload={"materialization_id": materialization.materialization_id},
        )
    left = tuple(shape[0] for shape in shapes)
    right = tuple(shape[1] for shape in shapes)
    destination = tuple(shape[2] for shape in shapes)
    dataflow_matches = (
        left[2] == destination[0]
        and right[2] == destination[1]
        and left[3] == destination[2]
        and _primitive_shape_contains(
            left[1],
            ("global", int(materialization.data_ea)),
        )
        and _primitive_shape_contains(
            destination[3],
            ("register", int(materialization.destination_storage.offset)),
        )
    )
    expected_sizes = (
        (destination[0], 2),
        (destination[1], materialization.source_width_bits // 8),
        (destination[2], materialization.source_width_bits // 8),
        (destination[3], materialization.destination_width_bits // 8),
    )
    sizes_match = all(
        isinstance(shape, tuple) and len(shape) >= 2 and int(shape[1]) == size
        for shape, size in expected_sizes
    )
    if not dataflow_matches or not sizes_match:
        raise SemanticFragmentBackendRejected(
            "mov_absolute GENERATED data-flow envelope differs from reference evidence",
            reason_code="constant_materialization_dataflow_mismatch",
            anchor_ea=materialization.instruction_ea,
            payload={"materialization_id": materialization.materialization_id},
        )


def _require_movzx_absolute_envelope(
    materialization: FragmentAbsoluteConstantMaterialization,
    facts: tuple[object, ...],
) -> None:
    """Prove one exact imported byte materialization from native movzx evidence."""
    expected_opcode = {
        FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_BYTE_MOVE: int(
            ida_hexrays.m_mov
        ),
        FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_BYTE_ZERO_EXTEND: int(
            ida_hexrays.m_xdu
        ),
    }.get(materialization.publication_envelope)
    if expected_opcode is None:
        raise SemanticFragmentBackendRejected(
            "movzx_absolute publication envelope differs from reference evidence",
            reason_code="constant_materialization_envelope_mismatch",
            anchor_ea=materialization.instruction_ea,
            payload={"materialization_id": materialization.materialization_id},
        )
    if len(facts) != 1 or int(getattr(facts[0], "opcode", -1)) != expected_opcode:
        raise SemanticFragmentBackendRejected(
            "movzx_absolute GENERATED opcode envelope differs from reference evidence",
            reason_code="constant_materialization_envelope_mismatch",
            anchor_ea=materialization.instruction_ea,
            payload={"materialization_id": materialization.materialization_id},
        )
    shape = getattr(facts[0], "operand_shape", ())
    if len(shape) != 3:
        raise SemanticFragmentBackendRejected(
            "movzx_absolute GENERATED operand envelope is incomplete",
            reason_code="constant_materialization_operand_mismatch",
            anchor_ea=materialization.instruction_ea,
            payload={"materialization_id": materialization.materialization_id},
        )
    if (
        not _primitive_shape_contains(
            shape[0],
            ("global", int(materialization.data_ea)),
        )
        or not _primitive_shape_contains(
            shape[2],
            ("register", int(materialization.destination_storage.offset)),
        )
        or not isinstance(shape[0], tuple)
        or len(shape[0]) < 2
        or int(shape[0][1]) != materialization.source_width_bits // 8
        or not isinstance(shape[2], tuple)
        or len(shape[2]) < 2
        or int(shape[2][1])
        != (
            materialization.source_width_bits // 8
            if materialization.publication_envelope
            is FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_BYTE_MOVE
            else materialization.destination_width_bits // 8
        )
    ):
        raise SemanticFragmentBackendRejected(
            "movzx_absolute GENERATED data-flow envelope differs from reference evidence",
            reason_code="constant_materialization_dataflow_mismatch",
            anchor_ea=materialization.instruction_ea,
            payload={"materialization_id": materialization.materialization_id},
        )


def _require_xor_absolute_envelope(
    materialization: FragmentAbsoluteConstantMaterialization,
    facts: tuple[object, ...],
) -> None:
    """Prove one exact imported byte XOR before replacing its left operand."""
    if (
        materialization.publication_envelope
        is not FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_BYTE_XOR
        or len(facts) != 1
        or int(getattr(facts[0], "opcode", -1)) != int(ida_hexrays.m_xor)
    ):
        raise SemanticFragmentBackendRejected(
            "xor_absolute imported opcode envelope differs from reference evidence",
            reason_code="constant_materialization_envelope_mismatch",
            anchor_ea=materialization.instruction_ea,
            payload={"materialization_id": materialization.materialization_id},
        )
    fact = facts[0]
    shape = getattr(fact, "operand_shape", ())
    left = shape[0] if len(shape) == 3 else ()
    right = shape[1] if len(shape) == 3 else ()
    destination = shape[2] if len(shape) == 3 else ()
    byte_shapes = all(
        isinstance(operand, tuple)
        and len(operand) >= 2
        and int(operand[1]) == materialization.source_width_bits // 8
        for operand in (left, right, destination)
    )
    if (
        len(shape) != 3
        or materialization.source_width_bits != 8
        or materialization.destination_width_bits != 8
        or not byte_shapes
        or not _primitive_shape_contains(
            left,
            ("global", int(materialization.data_ea)),
        )
        or not _primitive_shape_contains(
            right,
            ("register", int(materialization.destination_storage.offset)),
        )
        or right != destination
        or getattr(fact, "writes_condition_codes", None) is not False
    ):
        raise SemanticFragmentBackendRejected(
            "xor_absolute imported data flow differs from reference evidence",
            reason_code="constant_materialization_dataflow_mismatch",
            anchor_ea=materialization.instruction_ea,
            payload={"materialization_id": materialization.materialization_id},
        )


def _require_constant_materialization_envelope(
    materialization: FragmentAbsoluteConstantMaterialization,
    facts: tuple[object, ...],
) -> None:
    if materialization.consumer_operation is ValueOpKind.ADD:
        _require_add_absolute_envelope(materialization, facts)
        return
    if materialization.consumer_operation is ValueOpKind.MOVE:
        if (
            materialization.publication_envelope
            in {
                FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_BYTE_MOVE,
                FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_BYTE_ZERO_EXTEND,
            }
        ):
            _require_movzx_absolute_envelope(materialization, facts)
            return
        _require_mov_absolute_envelope(materialization, facts)
        return
    if materialization.consumer_operation is ValueOpKind.XOR:
        _require_xor_absolute_envelope(materialization, facts)
        return
    raise SemanticFragmentBackendRejected(
        "constant materialization consumer lacks immutable preflight support",
        reason_code="constant_materialization_consumer_unsupported",
        anchor_ea=materialization.instruction_ea,
        payload={"materialization_id": materialization.materialization_id},
    )


def _prepare_constant_materializations(
    plan: FragmentPlan,
    live_by_id: Mapping[str, object],
    native_body_facts: tuple[PreparedNativeBodyFact, ...],
) -> tuple[PreparedConstantMaterializationFact, ...]:
    """Capture exact serial-free constant envelopes while the gateway is idle."""
    imported_block_facts = {
        block.block_id: block
        for body in native_body_facts
        for block in body.blocks
        if plan.block(block.block_id).materialization
        is FragmentBlockMaterialization.IMPORT_NATIVE
    }
    prepared: list[PreparedConstantMaterializationFact] = []
    for materialization in plan.constant_materializations:
        live = live_by_id.get(materialization.source_block_id)
        if live is not None:
            source_rows = tuple(
                PreparedNativeInstructionFact(
                    instruction_id=(
                        f"{materialization.materialization_id}:source:{index}"
                    ),
                    native_ea=int(instruction.ea),
                    opcode=int(instruction.opcode),
                    kind=sdk_instruction_kind(int(instruction.opcode)),
                    operand_shape=sdk_instruction_operand_shape(instruction),
                    writes_condition_codes=_prepared_flag_write(instruction),
                )
                for index, instruction in enumerate(_iter_block_instructions(live))
            )
        else:
            imported = imported_block_facts.get(materialization.source_block_id)
            if imported is None:
                raise SemanticFragmentBackendRejected(
                    "constant materialization source lacks immutable authority",
                    reason_code="constant_materialization_source_missing",
                    anchor_ea=materialization.instruction_ea,
                    payload={"materialization_id": materialization.materialization_id},
                )
            source_rows = tuple(imported.instructions)
        indexes = tuple(
            index
            for index, instruction in enumerate(source_rows)
            if instruction.native_ea == materialization.instruction_ea
        )
        expected_envelope_length = {
            (
                ValueOpKind.ADD,
                FragmentConstantPublicationEnvelope.GENERATED_ABSOLUTE_LOAD,
            ): 10,
            (
                ValueOpKind.MOVE,
                FragmentConstantPublicationEnvelope.GENERATED_ABSOLUTE_LOAD,
            ): 4,
            (
                ValueOpKind.MOVE,
                FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_MOVE,
            ): 1,
            (
                ValueOpKind.MOVE,
                FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_BYTE_MOVE,
            ): 1,
            (
                ValueOpKind.MOVE,
                FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_BYTE_ZERO_EXTEND,
            ): 1,
            (
                ValueOpKind.XOR,
                FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_BYTE_XOR,
            ): 1,
        }.get(
            (
                materialization.consumer_operation,
                materialization.publication_envelope,
            )
        )
        if expected_envelope_length is None:
            raise SemanticFragmentBackendRejected(
                "constant materialization consumer lacks immutable preflight support",
                reason_code="constant_materialization_consumer_unsupported",
                anchor_ea=materialization.instruction_ea,
                payload={"materialization_id": materialization.materialization_id},
            )
        if (
            len(indexes) != expected_envelope_length
            or not indexes
            or indexes
            != tuple(range(indexes[0], indexes[0] + expected_envelope_length))
        ):
            raise SemanticFragmentBackendRejected(
                "constant materialization lacks one exact contiguous envelope: "
                f"expected_length={expected_envelope_length} "
                f"matched_indexes={indexes} source_row_count={len(source_rows)}",
                reason_code="constant_materialization_envelope_missing",
                anchor_ea=materialization.instruction_ea,
                payload={"materialization_id": materialization.materialization_id},
            )
        facts = tuple(
            PreparedNativeInstructionFact(
                instruction_id=f"{materialization.materialization_id}:{offset}",
                native_ea=instruction.native_ea,
                opcode=instruction.opcode,
                kind=instruction.kind,
                operand_shape=instruction.operand_shape,
                writes_condition_codes=instruction.writes_condition_codes,
            )
            for offset, instruction in enumerate(
                source_rows[indexes[0] : indexes[-1] + 1]
            )
        )
        _require_constant_materialization_envelope(materialization, facts)
        load_offset = (
            0
            if materialization.publication_envelope
            in {
                FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_MOVE,
                FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_BYTE_MOVE,
                FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_BYTE_ZERO_EXTEND,
                FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_BYTE_XOR,
            }
            else 2
        )
        prepared.append(
            PreparedConstantMaterializationFact(
                materialization_id=materialization.materialization_id,
                source_block_id=materialization.source_block_id,
                instruction_ea=materialization.instruction_ea,
                envelope_start_instruction_index=indexes[0],
                load_instruction_index=indexes[0] + load_offset,
                consumer_operation=materialization.consumer_operation,
                publication_envelope=materialization.publication_envelope,
                envelope=facts,
            )
        )
    return tuple(prepared)


def _reobserve_constant_materializations(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    native_body_facts: tuple[PreparedNativeBodyFact, ...],
) -> tuple[PreparedConstantMaterializationFact, ...]:
    if not plan.constant_materializations:
        return ()
    if _generated_graph_free(modifier):
        live_by_id = generated_plan_live_bindings(modifier, plan)
    else:
        live_by_id: dict[str, object] = {}
        gateway = _gateway(modifier)
        for materialization in plan.constant_materializations:
            block = plan.block(materialization.source_block_id)
            if (
                block.materialization
                is not FragmentBlockMaterialization.REUSE_PUBLISHED
                or block.stable_identity is None
            ):
                raise SemanticFragmentBackendRejected(
                    "constant materialization requires a published source block",
                    reason_code="constant_materialization_source_unpublished",
                    anchor_ea=materialization.instruction_ea,
                    payload={
                        "materialization_id": materialization.materialization_id
                    },
                )
            rebound = gateway.identity_index.rebind_identity(block.stable_identity)
            if rebound.block is None:
                raise SemanticFragmentBackendRejected(
                    "constant materialization source no longer rebinds uniquely",
                    reason_code="constant_materialization_source_stale",
                    anchor_ea=materialization.instruction_ea,
                    payload={
                        "materialization_id": materialization.materialization_id
                    },
                )
            live_by_id[block.block_id] = modifier.mba.get_mblock(
                int(rebound.block.serial)
            )
    return _prepare_constant_materializations(plan, live_by_id, native_body_facts)


def _capture_predicate_insn_snapshot(instruction) -> InsnSnapshot:
    """Lift only portable operands, avoiding provenance-owned mop clones."""
    opcode = int(instruction.opcode)
    branch_predicate = branch_predicate_from_opcode(opcode)
    return InsnSnapshot(
        opcode=opcode,
        ea=int(instruction.ea),
        operands=(),
        l=capture_mop_snapshot(instruction.l),
        r=capture_mop_snapshot(instruction.r),
        d=capture_mop_snapshot(instruction.d),
        value_op_kind=value_op_from_opcode(opcode),
        predicate_kind=predicate_from_opcode(opcode),
        branch_predicate=branch_predicate,
        is_conditional_jump=branch_predicate is not None,
    )


class SemanticFragmentBackendRejected(RuntimeError):
    """The live backend cannot realize a plan without guessing."""

    def __init__(
        self,
        message: str,
        *,
        reason_code: str | None = None,
        anchor_ea: int | None = None,
        payload: Mapping[str, object] | None = None,
    ) -> None:
        super().__init__(str(message))
        normalized_reason = None if reason_code is None else str(reason_code).strip()
        if reason_code is not None and not normalized_reason:
            raise ValueError("semantic backend rejection reason must not be empty")
        self.reason_code = normalized_reason
        self.anchor_ea = None if anchor_ea is None else int(anchor_ea)
        self.payload = dict(payload or {})


def _setcc_indexed_table_branch_opcode(
    normalization: FragmentSetccIndexedTableNormalization,
) -> int:
    """Return the exact boolean branch selected by typed predicate evidence."""
    if normalization.predicate_kind not in {
        PredicateKind.EQ,
        PredicateKind.NE,
        PredicateKind.SLT,
        PredicateKind.SGE,
    }:
        raise SemanticFragmentBackendRejected(
            "setcc indexed-table normalization has an unsupported predicate",
            reason_code="setcc_indexed_table_predicate_unsupported",
            anchor_ea=int(normalization.table_evidence.setcc_ea),
            payload={"predicate_kind": normalization.predicate_kind.value},
        )
    predicate_true_opcode = (
        int(ida_hexrays.m_jnz)
        if normalization.predicate_kind in {PredicateKind.EQ, PredicateKind.SLT}
        else int(ida_hexrays.m_jz)
    )
    if int(normalization.table_evidence.true_index) == 1:
        return predicate_true_opcode
    return (
        int(ida_hexrays.m_jz)
        if predicate_true_opcode == int(ida_hexrays.m_jnz)
        else int(ida_hexrays.m_jnz)
    )


def _preflight_generated_operation_vocabulary(plan: FragmentPlan) -> None:
    """Reject unsupported graph-free operations before live mutation opens."""
    for operation in plan.operations:
        normalization = operation.computed_branch_normalization
        if not isinstance(normalization, FragmentSetccIndexedTableNormalization):
            continue
        try:
            _setcc_indexed_table_branch_opcode(normalization)
        except SemanticFragmentBackendRejected as exc:
            raise FragmentProjectionFailure(
                FragmentValidationPostcondition.OPERATION_TOPOLOGY,
                operation.operation_id,
                str(exc),
            ) from exc


def _generated_setcc_predecessor_block_ids(
    plan: FragmentPlan,
    target_block_id: str,
) -> tuple[str, ...]:
    """Return every typed setcc graph owner that reaches one target."""
    predecessors: list[str] = []
    for operation in plan.operations:
        normalization = operation.computed_branch_normalization
        if not isinstance(normalization, FragmentSetccIndexedTableNormalization):
            continue
        for edge in operation.edges:
            if edge.target_block_id != target_block_id:
                continue
            predecessor_id = operation.source_block_id
            if (
                edge.role is SemanticEdgeRole.CONDITIONAL_FALLTHROUGH
                and normalization.fallthrough_delivery
                is FragmentSetccFallthroughDelivery.PLANNED_HELPER
            ):
                predecessor_id = f"fallthrough-helper:{operation.operation_id}"
            if predecessor_id not in predecessors:
                predecessors.append(predecessor_id)
    return tuple(predecessors)


@dataclass(frozen=True, slots=True)
class SemanticFragmentRuntimeBinding:
    """One exact logical version used by a live fragment transaction."""

    block_id: str
    proxy: LogicalBlockProxy
    version: LogicalBlockVersion
    state: FragmentBindingState
    creation_ref: PlanBlockRef | None = None


@dataclass(frozen=True, slots=True)
class SemanticFragmentRootEdgeBinding:
    """One serial-free incoming edge whose root authority will change."""

    edge_id: str
    root_block_id: str
    predecessor: SemanticFragmentRuntimeBinding
    original: SemanticFragmentRuntimeBinding
    replacement: SemanticFragmentRuntimeBinding
    role: SemanticEdgeRole
    requires_helper: bool
    publication_helper: SemanticFragmentRuntimeBinding | None = None


@dataclass(frozen=True, slots=True)
class SemanticFragmentRootPublicationGroup:
    """One predecessor-atomic root authority change."""

    group_id: str
    predecessor: SemanticFragmentRuntimeBinding
    edges: tuple[SemanticFragmentRootEdgeBinding, ...]
    original_predecessor_type: int
    original_predecessor_flags: int
    original_conditional_opcode: int | None = None
    original_call_opcode: int | None = None
    original_taken: SemanticFragmentRuntimeBinding | None = None
    original_fallthrough: SemanticFragmentRuntimeBinding | None = None

    @property
    def conditional(self) -> bool:
        return self.original_conditional_opcode is not None

    @property
    def call_fallthrough(self) -> bool:
        return self.original_call_opcode is not None


@dataclass(slots=True)
class SemanticFragmentRootPublicationToken:
    """Complete rollback authority captured before the first root write."""

    plan_id: str
    atomic_group_id: str
    groups: tuple[SemanticFragmentRootPublicationGroup, ...]
    attempted_group_ids: list[str] = field(default_factory=list)

    def group(self, group_id: str) -> SemanticFragmentRootPublicationGroup:
        for group in self.groups:
            if group.group_id == group_id:
                return group
        raise SemanticFragmentBackendRejected(
            f"root publication token has no group {group_id!r}"
        )


@dataclass(frozen=True, slots=True)
class SemanticConstantMaterializationRollback:
    """Exact SDK snapshot for one rollback-capable published instruction edit."""

    materialization_id: str
    source_block_id: str
    instruction_ea: int
    instruction_index: int
    original_instruction: object


@dataclass(slots=True)
class SemanticFragmentBackendState:
    """Transaction-local serial-free bindings for one staged fragment."""

    plan_id: str
    atomic_group_id: str
    bindings: dict[str, SemanticFragmentRuntimeBinding] = field(default_factory=dict)
    staged_block_ids: list[str] = field(default_factory=list)
    fallthrough_helpers: list[ProjectedFallthroughHelper] = field(default_factory=list)
    root_fallthrough_helpers: list[ProjectedRootFallthroughHelper] = field(
        default_factory=list
    )
    instruction_origins_by_block_id: dict[str, dict[int, int]] = field(
        default_factory=dict
    )
    predicate_live_eas_by_operation_id: dict[str, int] = field(default_factory=dict)
    detached_operation_ids: set[str] = field(default_factory=set)
    projection: ProjectedFragment | None = None
    preflight_projection: ProjectedFragment | None = None
    clone_source_instructions_by_block_id: dict[
        str,
        FragmentCloneSourceInstructions,
    ] = field(default_factory=dict)
    return_carrier_constructions: dict[
        str,
        PreparedReturnCarrierConstruction,
    ] = field(default_factory=dict)
    return_carrier_operands: dict[str, object] = field(default_factory=dict)
    materialized_native_body_ids: set[str] = field(default_factory=set)
    constant_materialization_rollbacks: list[
        SemanticConstantMaterializationRollback
    ] = field(default_factory=list)

    def binding(self, block_id: str) -> SemanticFragmentRuntimeBinding:
        try:
            return self.bindings[str(block_id)]
        except KeyError as exc:
            raise SemanticFragmentBackendRejected(
                f"fragment block {block_id!r} has no live logical binding"
            ) from exc

    def live_instruction_ea(self, block_id: str, native_ea: int) -> int:
        """Resolve one portable native anchor to its transaction-local live EA."""
        matches = self.live_instruction_eas(block_id, native_ea)
        if len(matches) > 1:
            raise SemanticFragmentBackendRejected(
                f"fragment instruction origin is ambiguous at "
                f"{block_id}@0x{int(native_ea):X}"
            )
        return int(matches[0])

    def live_instruction_eas(self, block_id: str, native_ea: int) -> tuple[int, ...]:
        """Resolve every lowered live instruction owned by one native anchor."""
        native_ea = int(native_ea)
        matches = tuple(
            live_ea
            for live_ea, candidate_native_ea in self.instruction_origins_by_block_id.get(
                str(block_id),
                {},
            ).items()
            if int(candidate_native_ea) == native_ea
        )
        return (native_ea,) if not matches else tuple(sorted(int(ea) for ea in matches))

    def live_operation_predicate_ea(
        self,
        operation: FragmentOperation,
    ) -> int:
        """Resolve a predicate through its typed materialization binding."""
        if operation.predicate_anchor_ea is None:
            raise SemanticFragmentBackendRejected(
                f"fragment operation {operation.operation_id!r} has no predicate"
            )
        if operation.storage_predicate_materialization is None:
            return self.live_instruction_ea(
                operation.source_block_id,
                operation.predicate_anchor_ea,
            )
        try:
            live_ea = int(
                self.predicate_live_eas_by_operation_id[operation.operation_id]
            )
        except KeyError as exc:
            raise SemanticFragmentBackendRejected(
                f"fragment operation {operation.operation_id!r} lacks its "
                "typed live predicate binding"
            ) from exc
        native_ea = self.instruction_origins_by_block_id.get(
            operation.source_block_id,
            {},
        ).get(live_ea)
        if native_ea != int(operation.predicate_anchor_ea):
            raise SemanticFragmentBackendRejected(
                f"fragment operation {operation.operation_id!r} live "
                "predicate binding changed"
            )
        return live_ea


@runtime_checkable
class SemanticNativeBodyMaterializer(Protocol):
    """Backend adapter that populates one gateway-owned native body staging context."""

    def prepare_native_body(
        self,
        *,
        plan: FragmentPlan,
        native_body: FragmentNativeBody,
    ) -> PreparedNativeBodyPreparation:
        """Prove and prepare one body without mutating the destination MBA."""

    def stage_native_body(
        self,
        *,
        context: "SemanticNativeBodyStagingContext",
        native_body: FragmentNativeBody,
        preparation: PreparedNativeBodyPreparation,
    ) -> None:
        """Stage one already-prepared body without recovering semantic intent."""


@dataclass(slots=True)
class SemanticNativeBodyStagingContext:
    """Gateway-owned staging surface for one closed imported native body."""

    _modifier: DeferredGraphModifier
    plan: FragmentPlan
    native_body: FragmentNativeBody
    reference_version: LogicalBlockVersion
    state: SemanticFragmentBackendState
    transaction_id: str
    _receipt_count: int
    _identity_generation: int
    _staged_block_ids: list[str] = field(default_factory=list)
    _populated_block_ids: list[str] = field(default_factory=list)

    def stage_block(self, block_id: str):
        """Create, bind, and return one unpublished imported-native block."""
        block_id = str(block_id)
        if block_id not in self.native_body.block_ids:
            raise SemanticFragmentBackendRejected(
                f"native body {self.native_body.body_id!r} does not own "
                f"fragment block {block_id!r}"
            )
        if block_id in self._staged_block_ids:
            raise SemanticFragmentBackendRejected(
                f"native body block {block_id!r} was staged more than once"
            )
        block = self.plan.block(block_id)
        if (
            block.role is not FragmentBlockRole.IMPORTED
            or block.materialization is not FragmentBlockMaterialization.IMPORT_NATIVE
            or block.native_body_id != self.native_body.body_id
            or block.stable_identity is None
        ):
            raise SemanticFragmentBackendRejected(
                f"fragment block {block_id!r} is not an imported member of "
                f"native body {self.native_body.body_id!r}"
            )

        version = self._modifier._stage_imported_native_semantic_block(
            reference_version=self.reference_version,
            stable_identity=block.stable_identity,
            plan_ref=PlanBlockRef(self.plan.plan_id, block_id),
        )
        if (
            version.handle.provenance is not BlockHandleProvenance.IMPORTED_NATIVE
            or version.handle.stable_identity != block.stable_identity
        ):
            raise SemanticFragmentBackendRejected(
                f"native body block {block_id!r} received the wrong logical identity"
            )
        gateway = _gateway(self._modifier)
        proxy = gateway.identity_index.logical_proxy_for_handle(version.handle)
        if proxy is None:
            raise SemanticFragmentBackendRejected(
                f"native body block {block_id!r} has no logical proxy"
            )
        if proxy.resolve() is not None:
            raise SemanticFragmentBackendRejected(
                f"native body block {block_id!r} exposed published authority"
            )
        if proxy.resolve(transaction_id=self.transaction_id) is not version:
            raise SemanticFragmentBackendRejected(
                f"native body block {block_id!r} lacks its staged logical version"
            )
        binding = SemanticFragmentRuntimeBinding(
            block_id=block_id,
            proxy=proxy,
            version=version,
            state=FragmentBindingState.STAGED,
        )
        self.state.bindings[block_id] = binding
        self.state.staged_block_ids.append(block_id)
        self._staged_block_ids.append(block_id)
        return _live_block_for_binding(self._modifier, binding)

    def populate_block(
        self,
        *,
        block_id: str,
        instructions: tuple[tuple[int, object], ...],
        block_flags: int,
    ) -> None:
        """Populate one staged block through the central mutation backend."""
        block_id = str(block_id)
        if block_id not in self._staged_block_ids:
            raise SemanticFragmentBackendRejected(
                f"native body population references unstaged block {block_id!r}"
            )
        if block_id in self._populated_block_ids:
            raise SemanticFragmentBackendRejected(
                f"native body block {block_id!r} was populated more than once"
            )
        origin_bindings = self._modifier._populate_imported_native_semantic_block(
            version=self.state.binding(block_id).version,
            instructions=instructions,
            block_flags=int(block_flags),
        )
        for live_ea, native_ea in origin_bindings:
            self.bind_instruction_origin(
                block_id=block_id,
                live_ea=live_ea,
                native_ea=native_ea,
            )
        self._populated_block_ids.append(block_id)

    def generated_live_serial(self, block_id: str) -> int:
        """Resolve one staged block for graph-free operand binding."""
        if not _generated_graph_free(self._modifier):
            raise SemanticFragmentBackendRejected(
                "generated live serials require the graph-free profile"
            )
        return int(
            _live_block_for_binding(
                self._modifier,
                self.state.binding(str(block_id)),
            ).serial
        )

    def bind_instruction_origin(
        self,
        *,
        block_id: str,
        live_ea: int,
        native_ea: int,
    ) -> None:
        """Bind one verifier-safe live instruction EA to its portable native origin."""
        block_id = str(block_id)
        live_ea = int(live_ea)
        native_ea = int(native_ea)
        if block_id not in self._staged_block_ids:
            raise SemanticFragmentBackendRejected(
                f"native body instruction origin references unstaged block {block_id!r}"
            )
        block = self.plan.block(block_id)
        identity = block.stable_identity
        if (
            identity is None
            or live_ea < 0
            or live_ea >= _BADADDR
            or native_ea < 0
            or native_ea >= _BADADDR
            or not identity.native_ranges.contains(native_ea)
        ):
            raise SemanticFragmentBackendRejected(
                f"native body instruction origin is outside {block_id!r}"
            )
        live_block = _live_block_for_binding(
            self._modifier,
            self.state.binding(block_id),
        )
        matching_instructions = tuple(
            instruction
            for instruction in _iter_block_instructions(live_block)
            if int(getattr(instruction, "ea", -1) or -1) == live_ea
        )
        if len(matching_instructions) != 1:
            raise SemanticFragmentBackendRejected(
                f"native body live instruction is ambiguous at {block_id}@0x{live_ea:X}"
            )
        origins = self.state.instruction_origins_by_block_id.setdefault(
            block_id,
            {},
        )
        if live_ea in origins:
            raise SemanticFragmentBackendRejected(
                f"native body instruction origin was bound more than once at "
                f"{block_id}@0x{native_ea:X}"
            )
        origins[live_ea] = native_ea

    def bind_operation_predicate(self, *, operation_id: str) -> None:
        """Bind one synthesized branch by operation, not by shared native EA."""
        operation = self.plan.operation(str(operation_id))
        block_id = operation.source_block_id
        if (
            operation.storage_predicate_materialization is None
            or block_id not in self.native_body.block_ids
            or block_id not in self._populated_block_ids
        ):
            raise SemanticFragmentBackendRejected(
                f"native body cannot bind predicate operation {operation_id!r}"
            )
        live_block = _live_block_for_binding(
            self._modifier,
            self.state.binding(block_id),
        )
        branch = live_block.tail
        live_ea = None if branch is None else int(getattr(branch, "ea", -1) or -1)
        origins = self.state.instruction_origins_by_block_id.get(
            block_id,
            {},
        )
        if (
            branch is None
            or live_ea is None
            or live_ea < 0
            or not ida_hexrays.is_mcode_jcond(int(branch.opcode))
            or origins.get(live_ea) != int(operation.predicate_anchor_ea)
            or operation.operation_id in self.state.predicate_live_eas_by_operation_id
            or live_ea in self.state.predicate_live_eas_by_operation_id.values()
        ):
            raise SemanticFragmentBackendRejected(
                f"native body synthesized predicate binding changed for "
                f"{operation.operation_id!r} at {block_id}"
            )
        self.state.predicate_live_eas_by_operation_id[operation.operation_id] = live_ea

    def materialize_direct_transfer(self, *, operation_id: str) -> None:
        """Bind one already-prepared direct route while its body is unpublished."""
        operation = self.plan.operation(str(operation_id))
        source_block_id = operation.source_block_id
        rewrite = operation.direct_transfer_rewrite
        if (
            rewrite is None
            or source_block_id not in self.native_body.block_ids
            or source_block_id not in self._populated_block_ids
            or operation.operation_id not in self.native_body.proof_ids
            or len(operation.edges) != 1
            or operation.edges[0].role is not SemanticEdgeRole.DIRECT
            or operation.operation_id in self.state.detached_operation_ids
        ):
            raise SemanticFragmentBackendRejected(
                f"native body cannot materialize direct operation {operation_id!r}"
            )
        target_block_id = operation.edges[0].target_block_id
        source_binding = self.state.binding(source_block_id)
        target_binding = self.state.binding(target_block_id)
        source = _live_block_for_binding(self._modifier, source_binding)
        tail = source.tail
        live_anchor_ea = None if tail is None else int(getattr(tail, "ea", -1) or -1)
        origins = self.state.instruction_origins_by_block_id.get(
            source_block_id,
            {},
        )
        if (
            tail is None
            or live_anchor_ea is None
            or live_anchor_ea < 0
            or int(tail.opcode) != int(ida_hexrays.m_goto)
            or origins.get(live_anchor_ea) != int(rewrite.rewrite_anchor_ea)
        ):
            raise SemanticFragmentBackendRejected(
                "native body prepared direct transfer changed before binding; "
                f"operation={operation.operation_id!r} "
                f"source={source_block_id!r}@0x{int(rewrite.rewrite_anchor_ea):X}"
            )
        self._modifier._bind_prepared_imported_direct_transfer(
            source_version=source_binding.version,
            target_version=target_binding.version,
            rewrite_anchor_ea=live_anchor_ea,
        )
        self.state.detached_operation_ids.add(operation.operation_id)

    def validate_complete(self) -> None:
        """Reject partial bodies or materializers that changed publication authority."""
        if tuple(self._staged_block_ids) != self.native_body.block_ids:
            raise SemanticFragmentBackendRejected(
                f"native body {self.native_body.body_id!r} staged blocks "
                f"{tuple(self._staged_block_ids)!r}, expected "
                f"{self.native_body.block_ids!r}"
            )
        for block_id in self._staged_block_ids:
            live_block = _live_block_for_binding(
                self._modifier,
                self.state.binding(block_id),
            )
            stable_identity = self.plan.block(block_id).stable_identity
            live_eas = tuple(
                int(getattr(instruction, "ea", -1) or -1)
                for instruction in _iter_block_instructions(live_block)
            )
            bound_live_eas = set(
                self.state.instruction_origins_by_block_id.get(block_id, {})
            )
            if (
                len(set(live_eas)) != len(live_eas)
                or any(live_ea < 0 or live_ea >= _BADADDR for live_ea in live_eas)
                or set(live_eas) != bound_live_eas
            ):
                raise SemanticFragmentBackendRejected(
                    f"native body {self.native_body.body_id!r} has an "
                    f"unbound live instruction in {block_id!r}"
                )
            for live_ea, native_ea in self.state.instruction_origins_by_block_id.get(
                block_id,
                {},
            ).items():
                mapped_ea = int(self._modifier.mba.map_fict_ea(int(live_ea)))
                if mapped_ea != int(native_ea):
                    raise SemanticFragmentBackendRejected(
                        "native body live instruction changed portable origin before "
                        f"semantic validation: {block_id}@0x{int(native_ea):X} "
                        f"live=0x{int(live_ea):X} mapped=0x{mapped_ea:X}"
                    )
                if (
                    stable_identity is None
                    or not stable_identity.native_ranges.contains(int(native_ea))
                ):
                    raise SemanticFragmentBackendRejected(
                        "native body instruction origin changed outside portable "
                        f"ownership: {block_id}@0x{int(native_ea):X} "
                        f"live=0x{int(live_ea):X}"
                    )
        expected_predicate_operations = {
            operation.operation_id
            for operation in self.plan.operations
            if (
                operation.source_block_id in self.native_body.block_ids
                and operation.storage_predicate_materialization is not None
            )
        }
        if any(
            operation_id not in self.state.predicate_live_eas_by_operation_id
            for operation_id in expected_predicate_operations
        ):
            raise SemanticFragmentBackendRejected(
                f"native body {self.native_body.body_id!r} has an unbound "
                "synthesized predicate"
            )
        expected_direct_operations = {
            operation.operation_id
            for operation in self.plan.operations
            if (
                operation.source_block_id in self.native_body.block_ids
                and operation.direct_transfer_rewrite is not None
            )
        }
        realized_direct_operations = (
            self.state.detached_operation_ids & expected_direct_operations
        )
        if realized_direct_operations != expected_direct_operations:
            raise SemanticFragmentBackendRejected(
                f"native body {self.native_body.body_id!r} has an unbound "
                "detached direct transfer"
            )
        gateway = _gateway(self._modifier)
        if gateway.active_batch_id != self.transaction_id:
            raise SemanticFragmentBackendRejected(
                "native body materializer changed the active fragment transaction"
            )
        if len(gateway.receipts) != self._receipt_count:
            raise SemanticFragmentBackendRejected(
                "native body materializer issued an independent mutation receipt"
            )
        if gateway.identity_index.generation != self._identity_generation:
            raise SemanticFragmentBackendRejected(
                "native body materializer changed published identity generation"
            )


def _gateway(modifier: DeferredGraphModifier):
    gateway = modifier._mutation_gateway
    if gateway is None or not gateway.active:
        raise SemanticFragmentBackendRejected(
            "semantic fragment staging requires an active mutation gateway"
        )
    return gateway


def _transaction_id(modifier: DeferredGraphModifier) -> str:
    gateway = _gateway(modifier)
    batch_id = gateway.active_batch_id
    if batch_id is None:
        raise SemanticFragmentBackendRejected(
            "semantic fragment staging has no active transaction id"
        )
    return batch_id


def _native_body_materializer(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
) -> SemanticNativeBodyMaterializer | None:
    if not plan.native_bodies:
        return None
    materializer = modifier._semantic_native_body_materializer
    if materializer is None:
        raise SemanticFragmentBackendRejected(
            "fragment plan requires an imported native-body materializer"
        )
    if not isinstance(materializer, SemanticNativeBodyMaterializer):
        raise TypeError(
            "semantic native-body materializer does not satisfy its backend protocol"
        )
    return materializer


def _prepare_native_bodies(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
) -> tuple[tuple[str, PreparedNativeBodyPreparation], ...]:
    """Prepare every native body before the first destination-MBA mutation."""
    materializer = _native_body_materializer(modifier, plan)
    if materializer is None:
        return ()
    prepare = materializer.prepare_native_body
    if _generated_graph_free(modifier):
        prepare_generated = getattr(
            materializer,
            "prepare_generated_native_body",
            None,
        )
        if not callable(prepare_generated):
            raise SemanticFragmentBackendRejected(
                "GENERATED native body materializer lacks graph-free preparation"
            )
        prepare = prepare_generated
    preparations = tuple(
        (
            native_body.body_id,
            prepare(
                plan=plan,
                native_body=native_body,
            ),
        )
        for native_body in plan.native_bodies
    )
    if any(
        not isinstance(preparation, PreparedNativeBodyPreparation)
        for _body_id, preparation in preparations
    ):
        raise SemanticFragmentBackendRejected(
            "native-body materializer returned malformed preparation facts"
        )
    return preparations


def _stage_native_bodies(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    *,
    reference_version: LogicalBlockVersion,
    preparations: tuple[tuple[str, PreparedNativeBodyPreparation], ...],
    native_body_id: str,
) -> None:
    if not plan.native_bodies:
        if preparations:
            raise SemanticFragmentBackendRejected(
                "native-body preparations exist for a plan without native bodies"
            )
        return
    materializer = _native_body_materializer(modifier, plan)
    assert materializer is not None
    preparation_by_body_id = dict(preparations)
    if len(preparation_by_body_id) != len(preparations) or set(
        preparation_by_body_id
    ) != {native_body.body_id for native_body in plan.native_bodies}:
        raise SemanticFragmentBackendRejected(
            "native-body preparations do not match the fragment plan"
        )
    gateway = _gateway(modifier)
    transaction_id = _transaction_id(modifier)
    native_body = next(
        (item for item in plan.native_bodies if item.body_id == native_body_id),
        None,
    )
    if native_body is None:
        raise SemanticFragmentBackendRejected(
            f"semantic PatchStep names unknown native body {native_body_id!r}"
        )
    if native_body_id in state.materialized_native_body_ids:
        return
    context = SemanticNativeBodyStagingContext(
        _modifier=modifier,
        plan=plan,
        native_body=native_body,
        reference_version=reference_version,
        state=state,
        transaction_id=transaction_id,
        _receipt_count=len(gateway.receipts),
        _identity_generation=gateway.identity_index.generation,
    )
    if _generated_graph_free(modifier):
        stage_generated = getattr(
            materializer,
            "stage_generated_native_body",
            None,
        )
        if not callable(stage_generated):
            raise SemanticFragmentBackendRejected(
                "GENERATED native body materializer lacks graph-free staging"
            )
        stage_generated(
            context=context,
            native_body=native_body,
            preparation=preparation_by_body_id[native_body.body_id],
        )
    else:
        materializer.stage_native_body(
            context=context,
            native_body=native_body,
            preparation=preparation_by_body_id[native_body.body_id],
        )
    context.validate_complete()
    state.materialized_native_body_ids.add(native_body_id)


def _materialize_constant_materializations(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    step: object,
    prepared_facts: tuple[PreparedConstantMaterializationFact, ...],
) -> None:
    from d810.transforms.plan import PatchFragmentConstantMaterializations
    from d810.transforms.prepared_native_body import PreparedNativeInstructionFact

    if not isinstance(step, PatchFragmentConstantMaterializations):
        raise TypeError("constant materialization requires its typed PatchStep")
    fact_by_id = {fact.materialization_id: fact for fact in prepared_facts}
    if tuple(fact_by_id) != tuple(
        item.materialization_id for item in step.materializations
    ):
        raise SemanticFragmentBackendRejected(
            "constant PatchStep differs from immutable materialization facts",
            reason_code="constant_materialization_fact_mismatch",
        )
    gateway = _gateway(modifier)
    for materialization, source_ref in zip(
        step.materializations,
        step.source_refs,
    ):
        if any(
            rollback.materialization_id == materialization.materialization_id
            for rollback in state.constant_materialization_rollbacks
        ):
            raise SemanticFragmentBackendRejected(
                "constant materialization was applied more than once",
                reason_code="constant_materialization_duplicate",
                anchor_ea=materialization.instruction_ea,
            )
        fact = fact_by_id[materialization.materialization_id]
        if fact.consumer_operation is not materialization.consumer_operation:
            raise SemanticFragmentBackendRejected(
                "constant immutable fact differs from its typed consumer",
                reason_code="constant_materialization_fact_mismatch",
                anchor_ea=materialization.instruction_ea,
            )
        if fact.publication_envelope is not materialization.publication_envelope:
            raise SemanticFragmentBackendRejected(
                "constant immutable fact differs from its publication envelope",
                reason_code="constant_materialization_fact_mismatch",
                anchor_ea=materialization.instruction_ea,
            )
        binding = state.binding(source_ref.local_block_id)
        block = _live_block_for_binding(modifier, binding)
        rows = tuple(_iter_block_instructions(block))
        instruction_origins = state.instruction_origins_by_block_id.get(
            materialization.source_block_id,
            {},
        )
        if fact.load_instruction_index >= len(rows):
            raise SemanticFragmentBackendRejected(
                "constant load index escaped the published source block",
                reason_code="constant_materialization_index_stale",
                anchor_ea=materialization.instruction_ea,
            )
        live_envelope = tuple(
            PreparedNativeInstructionFact(
                instruction_id=f"{materialization.materialization_id}:{offset}",
                native_ea=int(
                    instruction_origins.get(int(instruction.ea), int(instruction.ea))
                ),
                opcode=int(instruction.opcode),
                kind=sdk_instruction_kind(int(instruction.opcode)),
                operand_shape=sdk_instruction_operand_shape(instruction),
                writes_condition_codes=_prepared_flag_write(instruction),
            )
            for offset, instruction in enumerate(
                rows[
                    fact.envelope_start_instruction_index :
                    fact.envelope_start_instruction_index + len(fact.envelope)
                ]
            )
        )
        if live_envelope != fact.envelope:
            raise SemanticFragmentBackendRejected(
                "constant envelope changed after immutable preflight: "
                f"materialization={materialization.materialization_id!r} "
                f"expected_length={len(fact.envelope)} "
                f"actual_length={len(live_envelope)}",
                reason_code="constant_materialization_prewrite_mismatch",
                anchor_ea=materialization.instruction_ea,
            )
        original = ida_hexrays.minsn_t(rows[fact.load_instruction_index])
        live_instruction_ea = int(rows[fact.load_instruction_index].ea)
        state.constant_materialization_rollbacks.append(
            SemanticConstantMaterializationRollback(
                materialization_id=materialization.materialization_id,
                source_block_id=materialization.source_block_id,
                instruction_ea=live_instruction_ea,
                instruction_index=fact.load_instruction_index,
                original_instruction=original,
            )
        )
        gateway._record_fragment_mutation_started(plan)
        replacement_value_size = (
            materialization.destination_width_bits
            if materialization.publication_envelope
            is FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_BYTE_ZERO_EXTEND
            else materialization.source_width_bits
        ) // 8
        is_left_global_xor = (
            materialization.publication_envelope
            is FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_BYTE_XOR
        )
        if is_left_global_xor:
            modifier.replace_instruction_left_global_with_constant_now(
                block,
                instruction_index=fact.load_instruction_index,
                expected_ea=live_instruction_ea,
                expected_opcode=int(ida_hexrays.m_xor),
                expected_data_ea=materialization.data_ea,
                constant_value=materialization.constant_value,
                value_size=replacement_value_size,
            )
        else:
            modifier.replace_instruction_with_constant_now(
                block,
                instruction_index=fact.load_instruction_index,
                expected_ea=live_instruction_ea,
                expected_opcode=int(
                    {
                        FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_MOVE: (
                            ida_hexrays.m_mov
                        ),
                        FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_BYTE_MOVE: (
                            ida_hexrays.m_mov
                        ),
                        FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_BYTE_ZERO_EXTEND: (
                            ida_hexrays.m_xdu
                        ),
                    }.get(materialization.publication_envelope, ida_hexrays.m_ldx)
                ),
                constant_value=materialization.constant_value,
                value_size=replacement_value_size,
            )
        applied = tuple(_iter_block_instructions(block))[
            fact.load_instruction_index
        ]
        applied_shape = sdk_instruction_operand_shape(applied)
        envelope_load_index = (
            fact.load_instruction_index - fact.envelope_start_instruction_index
        )
        original_shape = fact.envelope[envelope_load_index].operand_shape
        expected_destination = original_shape[2]
        replacement_matches = (
            (
                int(applied.opcode) == int(ida_hexrays.m_xor)
                and _primitive_shape_contains(
                    applied_shape[0],
                    ("number", int(materialization.constant_value)),
                )
                and applied_shape[1] == original_shape[1]
                and applied_shape[2] == expected_destination
            )
            if is_left_global_xor
            else (
                int(applied.opcode) == int(ida_hexrays.m_mov)
                and _primitive_shape_contains(
                    applied_shape[0],
                    ("number", int(materialization.constant_value)),
                )
                and applied_shape[2] == expected_destination
            )
        )
        if not replacement_matches:
            raise SemanticFragmentBackendRejected(
                "constant replacement differs from the compiled materialization",
                reason_code="constant_materialization_postwrite_mismatch",
                anchor_ea=materialization.instruction_ea,
            )
        gateway.record_semantic_fragment_constant_materialization(
            materialization_id=materialization.materialization_id,
            block=binding.version.handle,
        )


def _rollback_constant_materializations(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
) -> None:
    for rollback in reversed(state.constant_materialization_rollbacks):
        binding = state.binding(rollback.source_block_id)
        block = _live_block_for_binding(modifier, binding)
        modifier.restore_instruction_from_snapshot_now(
            block,
            instruction_index=rollback.instruction_index,
            expected_ea=rollback.instruction_ea,
            expected_opcode=(
                int(ida_hexrays.m_xor)
                if int(rollback.original_instruction.opcode) == int(ida_hexrays.m_xor)
                else int(ida_hexrays.m_mov)
            ),
            original=rollback.original_instruction,
        )
    state.constant_materialization_rollbacks.clear()


def _published_binding(
    modifier: DeferredGraphModifier,
    block_id: str,
    stable_identity,
    *,
    preflight_projection: ProjectedFragment | None = None,
) -> SemanticFragmentRuntimeBinding:
    gateway = _gateway(modifier)
    if _generated_graph_free(modifier):
        if preflight_projection is None:
            raise SemanticFragmentBackendRejected(
                "GENERATED published binding lacks immutable projection authority"
            )
        expected = next(
            (
                binding
                for binding in preflight_projection.identity_bindings
                if binding.block_id == str(block_id)
            ),
            None,
        )
        if expected is None:
            raise SemanticFragmentBackendRejected(
                f"GENERATED fragment block {block_id!r} lacks projected binding authority"
            )
        matches: list[tuple[object, object]] = []
        for serial in range(int(modifier.mba.qty)):
            handle = gateway.identity_index.handle_for_serial(serial)
            proxy = gateway.identity_index.logical_proxy_for_handle(handle)
            if proxy is None or proxy.proxy_token != expected.logical_owner_id:
                continue
            version = proxy.resolve()
            if version is not None:
                matches.append((proxy, version))
        if len(matches) != 1:
            raise SemanticFragmentBackendRejected(
                f"GENERATED fragment block {block_id!r} does not retain one "
                "projected logical owner"
            )
        proxy, version = matches[0]
        if (
            version.version_id.version != expected.version
            or version.generation != expected.generation
        ):
            raise SemanticFragmentBackendRejected(
                f"GENERATED fragment block {block_id!r} changed projected version"
            )
        return SemanticFragmentRuntimeBinding(
            block_id=str(block_id),
            proxy=proxy,
            version=version,
            state=FragmentBindingState.PUBLISHED,
        )
    rebound = gateway.identity_index.rebind_identity(stable_identity)
    if rebound.block is None:
        raise SemanticFragmentBackendRejected(
            f"fragment block {block_id!r} does not rebind uniquely"
        )
    proxy = gateway.identity_index.logical_proxy_for_handle(rebound.block.handle)
    if proxy is None:
        raise SemanticFragmentBackendRejected(
            f"fragment block {block_id!r} has no logical proxy"
        )
    version = proxy.resolve()
    if version is None:
        raise SemanticFragmentBackendRejected(
            f"fragment block {block_id!r} has no published version"
        )
    return SemanticFragmentRuntimeBinding(
        block_id=str(block_id),
        proxy=proxy,
        version=version,
        state=FragmentBindingState.PUBLISHED,
    )


def _live_block_for_binding(
    modifier: DeferredGraphModifier,
    binding: SemanticFragmentRuntimeBinding,
):
    gateway = _gateway(modifier)
    bound = gateway.identity_index.resolve_logical_version(
        binding.version,
        transaction_id=_transaction_id(modifier),
    )
    if bound is None:
        raise SemanticFragmentBackendRejected(
            f"fragment block {binding.block_id!r} has no transaction-local physical version"
        )
    block = modifier.mba.get_mblock(int(bound.serial))
    if block is None:
        raise SemanticFragmentBackendRejected(
            f"fragment block {binding.block_id!r} is absent from the live MBA"
        )
    return block


def _clone_replacement(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    replacement_block,
    *,
    source_block_id: str,
    plan_ref: PlanBlockRef,
) -> None:
    original_binding = state.binding(source_block_id)
    if _generated_graph_free(modifier):
        gateway = _gateway(modifier)
        original_live = _live_block_for_binding(modifier, original_binding)
        # The GENERATED route rewrites the already-live root in place.  Its
        # portable plan identity names the owned corridor, while the current
        # Hex-Rays handle can legitimately cover a larger physical block.
        # Stage a new logical version of that exact handle; manufacturing a
        # narrower handle would violate the proxy's stable-identity lineage.
        replacement_handle = original_binding.version.handle
        staged = gateway.stage_replacement(
            original=original_binding.version.handle,
            replacement=replacement_handle,
            returned_serial=int(original_live.serial),
        )
        creation_ref = None
    else:
        staged = modifier._stage_detached_semantic_replacement(
            original_version=original_binding.version,
            plan_ref=plan_ref,
        )
        creation_ref = plan_ref

    state.bindings[replacement_block.block_id] = SemanticFragmentRuntimeBinding(
        block_id=replacement_block.block_id,
        proxy=original_binding.proxy,
        version=staged,
        state=FragmentBindingState.STAGED,
        creation_ref=creation_ref,
    )
    state.staged_block_ids.append(replacement_block.block_id)


def _orient_conditional_select_branch(
    branch: object,
    *,
    observed_predicate: PredicateKind,
    intended_predicate: PredicateKind,
    label: str,
) -> None:
    """Orient one cloned select-skip branch to its semantic handler edge."""
    if int(branch.opcode) != int(ida_hexrays.m_jcnd):
        branch_opcode = branch_opcode_for_predicate(intended_predicate)
        if branch_opcode is None:
            raise SemanticFragmentBackendRejected(
                "live conditional-select predicate has no Hex-Rays branch "
                f"opcode; {label}"
            )
        branch.opcode = int(branch_opcode)
        return

    if observed_predicate is intended_predicate:
        return
    if inverted_predicate_kind(observed_predicate) is not intended_predicate:
        raise SemanticFragmentBackendRejected(
            "live conditional-select truthiness predicate cannot be "
            f"oriented exactly; {label}"
        )

    expression = None if int(branch.l.t) != int(ida_hexrays.mop_d) else branch.l.d
    if (
        expression is not None
        and int(expression.opcode) == int(ida_hexrays.m_lnot)
        and int(expression.l.t) == int(ida_hexrays.mop_d)
    ):
        oriented_condition = ida_hexrays.mop_t()
        oriented_condition.assign(expression.l)
        if int(oriented_condition.t) == int(ida_hexrays.mop_z):
            raise SemanticFragmentBackendRejected(
                "live conditional-select inner predicate could not be "
                f"cloned independently; {label}"
            )
        branch.l.assign(oriented_condition)
        return

    condition_size = int(getattr(branch.l, "size", 0) or 1)
    branch.opcode = int(ida_hexrays.m_jz)
    branch.r.make_number(0, condition_size, int(branch.ea))


def _live_entry_reachable_serials(mba: object) -> frozenset[int]:
    reachable: set[int] = set()
    pending = [0]
    quantity = int(getattr(mba, "qty", 0) or 0)
    while pending:
        serial = pending.pop()
        if serial in reachable or not 0 <= serial < quantity:
            continue
        block = mba.get_mblock(serial)
        if block is None:
            continue
        reachable.add(serial)
        pending.extend(
            int(successor)
            for successor in block.succset
            if int(successor) not in reachable
        )
    return frozenset(reachable)


def _normalize_conditional_select_replacement(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    operation,
) -> None:
    """Rewrite one proven live conditional-select only on its detached clone."""
    normalization = operation.computed_branch_normalization
    envelope = (
        None if normalization is None else normalization.conditional_select_envelope
    )
    if normalization is None or envelope is None:
        return
    if isinstance(envelope, FragmentImportedConditionalSelectEnvelope):
        return
    if not isinstance(envelope, FragmentConditionalSelectEnvelope):
        raise SemanticFragmentBackendRejected(
            "conditional-select normalization has no recognized backend owner"
        )
    if _generated_graph_free(modifier):
        _normalize_generated_conditional_select_replacement(
            modifier,
            plan,
            state,
            operation,
        )
        return
    source_plan_block = plan.block(operation.source_block_id)
    original_block_id = source_plan_block.replaces_block_id
    if original_block_id is None:
        raise SemanticFragmentBackendRejected(
            "conditional-select normalization source has no replaced original"
        )
    original = _live_block_for_binding(
        modifier,
        state.binding(original_block_id),
    )
    replacement = _live_block_for_binding(
        modifier,
        state.binding(operation.source_block_id),
    )
    selected = _live_block_for_binding(
        modifier,
        state.binding(envelope.selected_value_block_id),
    )
    join = _live_block_for_binding(
        modifier,
        state.binding(envelope.join_block_id),
    )
    label = (
        f"operation={operation.operation_id!r} "
        f"source=blk{int(original.serial)}@0x{int(original.start):X} "
        f"predicate=0x{int(envelope.predicate_ea):X} "
        f"selected=blk{int(selected.serial)}@0x{int(selected.start):X} "
        f"join=blk{int(join.serial)}@0x{int(join.start):X} "
        f"transfer=0x{int(normalization.unresolved_transfer_ea):X}"
    )
    original_instructions = tuple(_iter_block_instructions(original))
    replacement_instructions = tuple(_iter_block_instructions(replacement))
    selected_instructions = tuple(_iter_block_instructions(selected))
    original_tail = original.tail
    replacement_tail = replacement.tail
    join_tail = join.tail
    observed_predicate = exact_branch_predicate_kind(
        tuple(
            _capture_predicate_insn_snapshot(instruction)
            for instruction in original_instructions
        ),
        condition_producer_ea=int(normalization.condition_producer_ea),
    )
    replacement_predicate = exact_branch_predicate_kind(
        tuple(
            _capture_predicate_insn_snapshot(instruction)
            for instruction in replacement_instructions
        ),
        condition_producer_ea=int(normalization.condition_producer_ea),
    )
    explicit_target = (
        None
        if original_tail is None or int(original_tail.d.t) != int(ida_hexrays.mop_b)
        else int(original_tail.d.b)
    )
    original_successors = tuple(int(value) for value in original.succset)
    nonexplicit_targets = tuple(
        serial
        for serial in original_successors
        if explicit_target is not None and serial != explicit_target
    )
    semantic_true_target = None
    if observed_predicate is normalization.predicate_kind:
        semantic_true_target = explicit_target
    elif (
        observed_predicate is not None
        and inverted_predicate_kind(observed_predicate) is normalization.predicate_kind
        and len(nonexplicit_targets) == 1
    ):
        semantic_true_target = nonexplicit_targets[0]
    entry_reachable = _live_entry_reachable_serials(modifier.mba)
    condition_indexes = tuple(
        index
        for index, instruction in enumerate(replacement_instructions)
        if int(instruction.ea) == int(normalization.condition_producer_ea)
    )
    cut_indexes = tuple(
        index
        for index, instruction in enumerate(replacement_instructions)
        if int(instruction.ea) == int(operation.predicate_anchor_ea)
    )
    if (
        int(original.type) != int(ida_hexrays.BLT_2WAY)
        or set(original_successors) != {int(selected.serial), int(join.serial)}
        or explicit_target is None
        or len(nonexplicit_targets) != 1
        or original.nextb is None
        or int(original.nextb.serial) != nonexplicit_targets[0]
        or observed_predicate is not envelope.observed_predicate_kind
        or semantic_true_target != int(selected.serial)
        or original_tail is None
        or int(original_tail.ea) != int(envelope.predicate_ea)
        or replacement_tail is None
        or int(replacement_tail.ea) != int(envelope.predicate_ea)
        or replacement_predicate is not envelope.observed_predicate_kind
        or tuple(
            (int(instruction.ea), int(instruction.opcode))
            for instruction in replacement_instructions
        )
        != tuple(
            (int(instruction.ea), int(instruction.opcode))
            for instruction in original_instructions
        )
        or int(selected.type) != int(ida_hexrays.BLT_1WAY)
        or tuple(int(value) for value in selected.succset) != (int(join.serial),)
        or tuple(
            int(value)
            for value in selected.predset
            if int(value) in entry_reachable
        )
        != (int(original.serial),)
        or selected.nextb is None
        or int(selected.nextb.serial) != int(join.serial)
        or len(selected_instructions) != 1
        or value_op_from_opcode(int(selected_instructions[0].opcode))
        is not ValueOpKind.MOVE
        or int(selected_instructions[0].ea) != int(envelope.predicate_ea)
        or {
            int(value)
            for value in join.predset
            if int(value) in entry_reachable
        }
        != {int(original.serial), int(selected.serial)}
        or int(join.type) != int(ida_hexrays.BLT_0WAY)
        or join_tail is None
        or int(join_tail.opcode) != int(ida_hexrays.m_ijmp)
        or int(join_tail.ea) != int(normalization.unresolved_transfer_ea)
        or not condition_indexes
        or len(cut_indexes) != 1
        or max(condition_indexes) >= cut_indexes[0]
    ):
        raise SemanticFragmentBackendRejected(
            "live conditional-select envelope changed before detached "
            f"normalization; {label}; "
            f"original_type={int(original.type)} "
            f"original_succs={original_successors!r} "
            f"explicit={explicit_target!r} nonexplicit={nonexplicit_targets!r} "
            f"original_next={None if original.nextb is None else int(original.nextb.serial)} "
            f"observed={observed_predicate!r} expected={normalization.predicate_kind!r} "
            f"envelope_observed={envelope.observed_predicate_kind!r} "
            f"semantic_true={semantic_true_target!r} "
            f"selected_type={int(selected.type)} selected_succs={tuple(int(value) for value in selected.succset)!r} "
            f"selected_preds={tuple(int(value) for value in selected.predset)!r} "
            f"selected_reachable_preds={tuple(int(value) for value in selected.predset if int(value) in entry_reachable)!r} "
            f"selected_next={None if selected.nextb is None else int(selected.nextb.serial)} "
            f"join_type={int(join.type)} join_preds={tuple(int(value) for value in join.predset)!r} "
            f"join_reachable_preds={tuple(int(value) for value in join.predset if int(value) in entry_reachable)!r} "
            f"condition_indexes={condition_indexes!r} cut_indexes={cut_indexes!r} "
            f"replacement_count={len(replacement_instructions)}"
        )
    branch = ida_hexrays.minsn_t(replacement_tail)
    branch.ea = int(operation.predicate_anchor_ea)
    _orient_conditional_select_branch(
        branch,
        observed_predicate=observed_predicate,
        intended_predicate=normalization.predicate_kind,
        label=label,
    )
    modifier.replace_instruction_suffix_now(
        replacement,
        cut_ea=int(operation.predicate_anchor_ea),
        replacement=branch,
    )


def _replace_generated_instructions(
    modifier: DeferredGraphModifier,
    block: object,
    instructions: tuple[object, ...],
) -> None:
    modifier.replace_all_instructions_now(
        block,
        instructions,
        mark_dirty=False,
    )


def _normalize_generated_conditional_select_replacement(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    operation: FragmentOperation,
) -> None:
    """Normalize the exact GENERATED cmov-select corridor in place."""
    normalization = operation.computed_branch_normalization
    envelope = (
        None if normalization is None else normalization.conditional_select_envelope
    )
    if normalization is None or not isinstance(
        envelope,
        FragmentConditionalSelectEnvelope,
    ):
        raise SemanticFragmentBackendRejected(
            "GENERATED normalization requires a conditional-select envelope"
        )
    source_plan = plan.block(operation.source_block_id)
    original_id = str(source_plan.replaces_block_id)
    original = _live_block_for_binding(modifier, state.binding(original_id))
    replacement = _live_block_for_binding(
        modifier,
        state.binding(operation.source_block_id),
    )
    selected = _live_block_for_binding(
        modifier,
        state.binding(envelope.selected_value_block_id),
    )
    join = _live_block_for_binding(
        modifier,
        state.binding(envelope.join_block_id),
    )
    source_rows = tuple(_iter_block_instructions(original))
    selected_rows = tuple(_iter_block_instructions(selected))
    observed = exact_branch_predicate_kind(
        tuple(_capture_predicate_insn_snapshot(row) for row in source_rows),
        condition_producer_ea=int(normalization.condition_producer_ea),
    )
    cut_indexes = tuple(
        index
        for index, row in enumerate(source_rows)
        if int(row.ea) == int(operation.predicate_anchor_ea)
    )
    producer_indexes = tuple(
        index
        for index, row in enumerate(source_rows)
        if int(row.ea) == int(normalization.condition_producer_ea)
    )
    if (
        int(original.serial) != int(replacement.serial)
        or original.nextb is None
        or int(original.nextb.serial) != int(selected.serial)
        or selected.nextb is None
        or int(selected.nextb.serial) != int(join.serial)
        or original.tail is None
        or int(original.tail.ea) != int(envelope.predicate_ea)
        or not ida_hexrays.is_mcode_jcond(int(original.tail.opcode))
        or len(selected_rows) != 1
        or value_op_from_opcode(int(selected_rows[0].opcode)) is not ValueOpKind.MOVE
        or int(selected_rows[0].ea) != int(envelope.predicate_ea)
        or join.tail is None
        or int(join.tail.opcode) != int(ida_hexrays.m_ijmp)
        or int(join.tail.ea) != int(normalization.unresolved_transfer_ea)
        or observed is not envelope.observed_predicate_kind
        or len(cut_indexes) != 1
        or not producer_indexes
        or max(producer_indexes) >= cut_indexes[0]
    ):
        raise SemanticFragmentBackendRejected(
            "GENERATED conditional-select corridor changed before normalization; "
            f"original=blk{int(original.serial)}@0x{int(original.start):X} "
            f"replacement=blk{int(replacement.serial)}@0x{int(replacement.start):X} "
            f"selected=blk{int(selected.serial)}@0x{int(selected.start):X} "
            f"join=blk{int(join.serial)}@0x{int(join.start):X} "
            f"next=({None if original.nextb is None else int(original.nextb.serial)},"
            f"{None if selected.nextb is None else int(selected.nextb.serial)}) "
            f"tails=({None if original.tail is None else (int(original.tail.ea), int(original.tail.opcode))},"
            f"{None if join.tail is None else (int(join.tail.ea), int(join.tail.opcode))}) "
            f"selected_rows={tuple((int(row.ea), int(row.opcode)) for row in selected_rows)!r} "
            f"observed={observed!r} cuts={cut_indexes!r} producers={producer_indexes!r}"
        )
    branch = ida_hexrays.minsn_t(original.tail)
    branch.ea = int(operation.predicate_anchor_ea)
    removal_index = cut_indexes[0]
    if observed is normalization.predicate_kind:
        pass
    elif (
        observed is PredicateKind.SGE
        and normalization.predicate_kind is PredicateKind.SLT
        and int(branch.opcode) == int(ida_hexrays.m_jcnd)
        and int(branch.l.t) == int(ida_hexrays.mop_d)
        and int(branch.l.d.opcode) == int(ida_hexrays.m_lnot)
        and int(branch.l.d.l.t) == int(ida_hexrays.mop_d)
    ):
        oriented = ida_hexrays.mop_t()
        oriented.assign(branch.l.d.l)
        branch.l.assign(oriented)
    elif (
        observed is PredicateKind.SGE
        and normalization.predicate_kind is PredicateKind.SLT
        and len(source_rows) >= 3
        and int(branch.opcode) == int(ida_hexrays.m_jcnd)
        and value_op_from_opcode(int(source_rows[-3].opcode)) is ValueOpKind.XOR
        and value_op_from_opcode(int(source_rows[-2].opcode)) is ValueOpKind.LNOT
        and source_rows[-2].l.equal_mops(
            source_rows[-3].d,
            int(ida_hexrays.EQ_IGNSIZE),
        )
        and source_rows[-2].d.equal_mops(
            branch.l,
            int(ida_hexrays.EQ_IGNSIZE),
        )
    ):
        # The sequential lowering writes the complemented truth value back to
        # the same temporary consumed by jcnd.  Preserve the exact SF xor OF
        # producer, remove only the lnot, and retain the branch operand.
        removal_index = len(source_rows) - 2
    else:
        raise SemanticFragmentBackendRejected(
            "GENERATED conditional-select predicate cannot be oriented exactly"
        )
    _gateway(modifier)._record_fragment_mutation_started(plan)
    cut = source_rows[removal_index]
    modifier.replace_instruction_suffix_from_index_now(
        original,
        cut_index=removal_index,
        expected_ea=int(cut.ea),
        expected_opcode=int(cut.opcode),
        replacement=branch,
        mark_dirty=False,
    )
    modifier.configure_block_now(
        original,
        flags=int(original.flags) | int(ida_hexrays.MBL_PROP),
    )


def _clone_source_instruction_evidence(
    *,
    block_id: str,
    source_block_id: str,
    instructions,
) -> FragmentCloneSourceInstructions:
    return FragmentCloneSourceInstructions(
        block_id=str(block_id),
        source_block_id=str(source_block_id),
        instructions=tuple(
            FragmentCloneSourceInstruction(
                native_ea=int(getattr(instruction, "ea", -1)),
                opcode=int(getattr(instruction, "opcode", -1)),
                kind=sdk_instruction_kind(int(getattr(instruction, "opcode", -1))),
                destination_is_discardable=(
                    int(getattr(getattr(instruction, "d", None), "t", -1))
                    in {
                        int(ida_hexrays.mop_z),
                        int(ida_hexrays.mop_r),
                    }
                ),
                operand_shape=sdk_instruction_operand_shape(instruction),
            )
            for instruction in instructions
        ),
    )


def _normalize_storage_predicate_replacement(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    operation: FragmentOperation,
) -> None:
    predicate = operation.storage_predicate_materialization
    if predicate is None:
        return
    source_plan_block = plan.block(operation.source_block_id)
    if (
        source_plan_block.materialization
        is not FragmentBlockMaterialization.CLONE_PUBLISHED
        or source_plan_block.replaces_block_id is None
    ):
        raise SemanticFragmentBackendRejected(
            "replacement storage predicate lacks clone-owned source authority"
        )
    original_block_id = str(source_plan_block.replaces_block_id)
    expected = state.clone_source_instructions_by_block_id.get(
        operation.source_block_id
    )
    if expected is None or expected.source_block_id != original_block_id:
        raise SemanticFragmentBackendRejected(
            "replacement storage predicate lacks immutable clone-source evidence"
        )
    original = _live_block_for_binding(
        modifier,
        state.binding(original_block_id),
    )
    replacement = _live_block_for_binding(
        modifier,
        state.binding(operation.source_block_id),
    )
    for candidate in (original, replacement):
        observed = _clone_source_instruction_evidence(
            block_id=operation.source_block_id,
            source_block_id=original_block_id,
            instructions=tuple(_iter_block_instructions(candidate)),
        )
        if observed != expected:
            raise SemanticFragmentBackendRejected(
                "replacement storage predicate clone source changed after preflight"
            )

    live_ea = int(modifier.mba.alloc_fict_ea(int(operation.predicate_anchor_ea)))
    branch = ida_hexrays.minsn_t(live_ea)
    branch.opcode = int(ida_hexrays.m_jz)
    branch.l.assign(
        _storage_operand(
            modifier.mba,
            predicate.storage_identity,
            width=predicate.width,
        )
    )
    branch.r.make_number(
        int(predicate.compare_constant),
        int(predicate.width),
        int(operation.predicate_anchor_ea),
    )
    branch.d.erase()
    modifier.replace_instruction_tail_after_anchor_now(
        replacement,
        retained_ea=int(predicate.cut_after_ea),
        replacement=branch,
    )
    _bind_synthesized_instruction_origin(
        state,
        block_id=operation.source_block_id,
        live_ea=live_ea,
        native_ea=int(operation.predicate_anchor_ea),
    )
    if operation.operation_id in state.predicate_live_eas_by_operation_id:
        raise SemanticFragmentBackendRejected(
            "replacement storage predicate was materialized more than once"
        )
    state.predicate_live_eas_by_operation_id[operation.operation_id] = live_ea


def _normalize_replacement_operations(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    operations: tuple[FragmentOperation, ...],
) -> None:
    for operation in operations:
        if operation.storage_predicate_materialization is not None:
            _normalize_storage_predicate_replacement(
                modifier,
                plan,
                state,
                operation,
            )
            continue
        normalization = operation.computed_branch_normalization
        if isinstance(normalization, FragmentComputedBranchNormalization) and (
            normalization.conditional_select_envelope is None
        ):
            _normalize_imported_computed_branch(
                modifier,
                plan,
                state,
                operation,
            )
            continue
        if normalization is None or normalization.conditional_select_envelope is None:
            continue
        _normalize_conditional_select_replacement(
            modifier,
            plan,
            state,
            operation,
        )


def _normalize_imported_computed_branch(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    operation: FragmentOperation,
) -> None:
    """Orient an imported conditional to its portable predicate contract."""
    normalization = operation.computed_branch_normalization
    source_plan_block = plan.block(operation.source_block_id)
    if (
        not isinstance(normalization, FragmentComputedBranchNormalization)
        or normalization.conditional_select_envelope is not None
        or source_plan_block.materialization
        is not FragmentBlockMaterialization.IMPORT_NATIVE
    ):
        raise SemanticFragmentBackendRejected(
            "envelope-free computed normalization requires an imported source"
        )
    if operation.roles != {
        SemanticEdgeRole.CONDITIONAL_TAKEN,
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
    }:
        raise SemanticFragmentBackendRejected(
            "imported computed normalization requires two conditional edges"
        )

    source = _live_block_for_binding(
        modifier,
        state.binding(operation.source_block_id),
    )
    instructions = tuple(_iter_block_instructions(source))
    tail = source.tail
    predicate_ea = state.live_operation_predicate_ea(operation)
    producer_eas = state.live_instruction_eas(
        operation.source_block_id,
        normalization.condition_producer_ea,
    )
    snapshots = tuple(_capture_predicate_insn_snapshot(row) for row in instructions)
    observed_predicates = {
        predicate
        for producer_ea in producer_eas
        if (
            predicate := exact_branch_predicate_kind(
                snapshots,
                condition_producer_ea=producer_ea,
            )
        )
        is not None
    }
    observed_predicate = (
        next(iter(observed_predicates))
        if len(observed_predicates) == 1
        else None
    )
    if (
        tail is None
        or not ida_hexrays.is_mcode_jcond(int(tail.opcode))
        or int(tail.ea) != int(predicate_ea)
        or not any(int(row.ea) in producer_eas for row in instructions)
        or observed_predicate is None
        or (
            observed_predicate is not normalization.predicate_kind
            and inverted_predicate_kind(observed_predicate)
            is not normalization.predicate_kind
        )
    ):
        raise SemanticFragmentBackendRejected(
            "imported computed branch cannot be oriented exactly; "
            f"operation={operation.operation_id!r} "
            f"source=blk{int(source.serial)}@0x{int(source.start):X} "
            f"predicate=0x{int(predicate_ea):X} "
            f"producers={tuple(hex(int(ea)) for ea in producer_eas)!r} "
            f"observed={observed_predicate!r} "
            f"intended={normalization.predicate_kind!r}"
        )
    if observed_predicate is normalization.predicate_kind:
        return

    branch = ida_hexrays.minsn_t(tail)
    _orient_conditional_select_branch(
        branch,
        observed_predicate=observed_predicate,
        intended_predicate=normalization.predicate_kind,
        label=f"operation={operation.operation_id!r}",
    )
    modifier.replace_instruction_suffix_now(
        source,
        cut_ea=int(predicate_ea),
        replacement=branch,
    )


def _create_empty_block(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    block,
    *,
    reference_version: LogicalBlockVersion,
    plan_ref: PlanBlockRef,
) -> None:
    staged = modifier._stage_empty_semantic_block(
        reference_version=reference_version,
        plan_ref=plan_ref,
    )
    gateway = _gateway(modifier)
    proxy = gateway.identity_index.logical_proxy_for_handle(staged.handle)
    if proxy is None:
        raise SemanticFragmentBackendRejected(
            f"synthetic fragment block {block.block_id!r} has no logical proxy"
        )
    state.bindings[block.block_id] = SemanticFragmentRuntimeBinding(
        block_id=block.block_id,
        proxy=proxy,
        version=staged,
        state=FragmentBindingState.STAGED,
        creation_ref=plan_ref,
    )
    state.staged_block_ids.append(block.block_id)


def _realize_operations(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    operation_steps: tuple[object, ...],
) -> None:
    from d810.transforms.plan import PatchFragmentOperation

    if _generated_graph_free(modifier):
        _realize_generated_graph_free_operations(
            modifier,
            plan,
            state,
            operation_steps,
        )
        return

    detached_capable_operation_ids = {
        operation.operation_id
        for operation in plan.operations
        if (
            operation.direct_transfer_rewrite is not None
            and plan.block(operation.source_block_id).role is FragmentBlockRole.IMPORTED
        )
    }
    if not state.detached_operation_ids <= detached_capable_operation_ids:
        raise SemanticFragmentBackendRejected(
            "detached native-body lowering consumed an ineligible operation"
        )
    for item in operation_steps:
        if not isinstance(item, PatchFragmentOperation):
            raise SemanticFragmentBackendRejected(
                "semantic operation realization requires typed PatchSteps"
            )
        operation = item.operation
        helper_plan_ref = item.fallthrough_helper_ref
        if operation.operation_id in state.detached_operation_ids:
            continue
        source = state.binding(operation.source_block_id)
        direct_rewrite = operation.direct_transfer_rewrite
        direct_rewrite_anchor_ea = (
            state.live_instruction_ea(
                operation.source_block_id,
                direct_rewrite.rewrite_anchor_ea,
            )
            if direct_rewrite is not None
            and len(operation.edges) == 1
            and operation.edges[0].role is SemanticEdgeRole.DIRECT
            else None
        )
        helper_version = modifier._realize_semantic_edge_operation(
            LogicalSemanticEdgeOperation(
                source=source.proxy,
                edges=tuple(
                    LogicalSemanticEdge(
                        role=edge.role,
                        target=state.binding(edge.target_block_id).proxy,
                    )
                    for edge in operation.edges
                ),
                predicate_anchor_ea=(
                    None
                    if operation.predicate_anchor_ea is None
                    else state.live_operation_predicate_ea(operation)
                ),
                rewrite_anchor_ea=direct_rewrite_anchor_ea,
                description=f"fragment operation {operation.operation_id}",
            ),
            helper_plan_ref=helper_plan_ref,
        )
        _register_operation_fallthrough_helper(
            modifier,
            state,
            operation,
            helper_plan_ref=helper_plan_ref,
            helper_version=helper_version,
        )


def _register_operation_fallthrough_helper(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    operation: FragmentOperation,
    *,
    helper_plan_ref: PlanBlockRef | None,
    helper_version: LogicalBlockVersion | None,
) -> None:
    """Bind one helper created by the existing semantic-edge participant."""
    helper_edges = tuple(
        edge
        for edge in operation.edges
        if edge.role
        in {
            SemanticEdgeRole.CALL_FALLTHROUGH,
            SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
        }
    )
    if not helper_edges:
        if helper_version is not None:
            raise SemanticFragmentBackendRejected(
                "semantic fragment operation unexpectedly created a helper"
            )
        return
    if (
        len(helper_edges) != 1
        or helper_plan_ref is None
        or helper_version is None
    ):
        raise SemanticFragmentBackendRejected(
            "semantic fallthrough operation did not create exactly one planned helper"
        )
    helper_block_id = f"fallthrough-helper:{operation.operation_id}"
    if helper_plan_ref.local_block_id != helper_block_id:
        raise SemanticFragmentBackendRejected(
            "semantic fallthrough helper plan authority does not match its operation"
        )
    if helper_block_id in state.bindings:
        raise SemanticFragmentBackendRejected(
            f"semantic fallthrough helper id collision: {helper_block_id!r}"
        )
    gateway = _gateway(modifier)
    helper_proxy = gateway.identity_index.logical_proxy_for_handle(
        helper_version.handle
    )
    if helper_proxy is None:
        raise SemanticFragmentBackendRejected(
            "semantic fallthrough helper has no logical proxy"
        )
    state.bindings[helper_block_id] = SemanticFragmentRuntimeBinding(
        block_id=helper_block_id,
        proxy=helper_proxy,
        version=helper_version,
        state=FragmentBindingState.STAGED,
        creation_ref=helper_plan_ref,
    )
    state.staged_block_ids.append(helper_block_id)
    state.fallthrough_helpers.append(
        ProjectedFallthroughHelper(
            helper_block_id=helper_block_id,
            operation_id=operation.operation_id,
            source_block_id=operation.source_block_id,
            semantic_target_block_id=helper_edges[0].target_block_id,
        )
    )


def _realize_generated_setcc_indexed_table_operation(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    operation: FragmentOperation,
    normalization: FragmentSetccIndexedTableNormalization,
    *,
    fallthrough_helper_ref: PlanBlockRef | None,
) -> None:
    """Bind one prepared setcc-table route without rebuilding the graph."""
    evidence = normalization.table_evidence
    edge_by_role = {edge.role: edge for edge in operation.edges}
    taken_edge = edge_by_role.get(SemanticEdgeRole.CONDITIONAL_TAKEN)
    fallthrough_edge = edge_by_role.get(SemanticEdgeRole.CONDITIONAL_FALLTHROUGH)
    source_plan_block = plan.block(operation.source_block_id)
    source_body = next(
        (
            body
            for body in plan.native_bodies
            if body.body_id == source_plan_block.native_body_id
        ),
        None,
    )
    reference_authority = operation.reference_route_authority
    taken_binding = (
        None if taken_edge is None else state.bindings.get(taken_edge.target_block_id)
    )
    fallthrough_binding = (
        None
        if fallthrough_edge is None
        else state.bindings.get(fallthrough_edge.target_block_id)
    )
    source_binding = state.bindings.get(operation.source_block_id)
    source = (
        None
        if source_binding is None
        else _live_block_for_binding(modifier, source_binding)
    )
    taken = (
        None
        if taken_binding is None
        else _live_block_for_binding(modifier, taken_binding)
    )
    fallthrough = (
        None
        if fallthrough_binding is None
        else _live_block_for_binding(modifier, fallthrough_binding)
    )
    source_rows = () if source is None else tuple(_iter_block_instructions(source))
    source_tail = None if source is None else source.tail
    source_tail_live_ea = None if source_tail is None else int(source_tail.ea)
    source_tail_native_ea = (
        None
        if source_tail_live_ea is None
        else state.instruction_origins_by_block_id.get(
            operation.source_block_id,
            {},
        ).get(source_tail_live_ea)
    )
    reference_targets = (
        (None, None)
        if reference_authority is None
        else (
            reference_authority.semantic_route.true_target_ea,
            reference_authority.semantic_route.false_target_ea,
        )
    )
    evidence_targets = (
        evidence.true_entry.decoded_target_ea,
        evidence.false_entry.decoded_target_ea,
    )
    delivery_targets = (
        None
        if taken_edge is None or fallthrough_edge is None
        else (
            plan.block(taken_edge.target_block_id).semantic_anchor_ea,
            plan.block(fallthrough_edge.target_block_id).semantic_anchor_ea,
        )
    )
    expected_opcode = _setcc_indexed_table_branch_opcode(normalization)
    fallthrough_delivery = normalization.fallthrough_delivery
    physical_fallthrough = (
        fallthrough_delivery is FragmentSetccFallthroughDelivery.PHYSICAL_ADJACENCY
    )
    planned_fallthrough = (
        fallthrough_delivery is FragmentSetccFallthroughDelivery.PLANNED_HELPER
    )
    failed_obligations = tuple(
        name
        for name, passed in (
            (
                "typed_fallthrough_delivery",
                physical_fallthrough or planned_fallthrough,
            ),
            (
                "fallthrough_helper_authority",
                (physical_fallthrough and fallthrough_helper_ref is None)
                or (planned_fallthrough and fallthrough_helper_ref is not None),
            ),
            (
                "source_imported_native_body",
                source_plan_block.materialization
                is FragmentBlockMaterialization.IMPORT_NATIVE
                and source_body is not None,
            ),
            (
                "source_body_operation_proof",
                source_body is not None
                and operation.operation_id in source_body.proof_ids,
            ),
            ("reference_authority_present", reference_authority is not None),
            ("reference_targets_match_table", reference_targets == evidence_targets),
            ("delivery_targets_match_table", delivery_targets == evidence_targets),
            ("conditional_taken_edge_present", taken_edge is not None),
            ("conditional_fallthrough_edge_present", fallthrough_edge is not None),
            ("source_bound", source is not None),
            ("taken_bound", taken is not None),
            ("fallthrough_bound", fallthrough is not None),
            ("source_tail_present", source_tail is not None),
            (
                "source_tail_conditional",
                source_tail is not None
                and ida_hexrays.is_mcode_jcond(int(source_tail.opcode)),
            ),
            (
                "predicate_anchor_exact",
                source_tail_native_ea == int(operation.predicate_anchor_ea),
            ),
            (
                "predicate_orientation_exact",
                source_tail is not None and int(source_tail.opcode) == expected_opcode,
            ),
            ("source_suffix_nonempty", bool(source_rows)),
            (
                "false-target fallthrough",
                not physical_fallthrough
                or (
                    source is not None
                    and fallthrough is not None
                    and source.nextb is not None
                    and int(source.nextb.serial) == int(fallthrough.serial)
                ),
            ),
        )
        if not passed
    )
    if failed_obligations:
        raise SemanticFragmentBackendRejected(
            "GENERATED setcc indexed-table false-target fallthrough preflight "
            "failed before write; "
            f"operation_id={operation.operation_id!r} "
            f"failed_obligations={failed_obligations!r}"
        )
    assert source is not None
    assert source_tail is not None
    assert taken is not None
    assert fallthrough is not None
    assert source_binding is not None
    assert taken_binding is not None
    assert fallthrough_binding is not None
    if planned_fallthrough:
        assert fallthrough_helper_ref is not None
        helper_version = modifier._realize_semantic_edge_operation(
            LogicalSemanticEdgeOperation(
                source=source_binding.proxy,
                edges=(
                    LogicalSemanticEdge(
                        role=taken_edge.role,
                        target=taken_binding.proxy,
                    ),
                    LogicalSemanticEdge(
                        role=fallthrough_edge.role,
                        target=fallthrough_binding.proxy,
                    ),
                ),
                predicate_anchor_ea=state.live_operation_predicate_ea(operation),
                description=f"fragment operation {operation.operation_id}",
            ),
            helper_plan_ref=fallthrough_helper_ref,
        )
        _register_operation_fallthrough_helper(
            modifier,
            state,
            operation,
            helper_plan_ref=fallthrough_helper_ref,
            helper_version=helper_version,
        )
        return
    source_branch = ida_hexrays.minsn_t(source_tail)
    source_branch.d.make_blkref(int(taken.serial))
    modifier.replace_instruction_suffix_from_index_now(
        source,
        cut_index=len(source_rows) - 1,
        expected_ea=int(source_tail.ea),
        expected_opcode=int(source_tail.opcode),
        replacement=source_branch,
        mark_dirty=False,
    )
    modifier.configure_block_now(
        source,
        block_type=int(ida_hexrays.BLT_NONE),
        flags=int(source.flags) | int(ida_hexrays.MBL_PROP),
    )
    gateway = _gateway(modifier)
    gateway.record_edge_redirect(
        source=source_binding.version.handle,
        target=taken_binding.version.handle,
    )
    gateway.record_edge_redirect(
        source=source_binding.version.handle,
        target=fallthrough_binding.version.handle,
    )


def _realize_generated_graph_free_operations(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    operation_steps: tuple[object, ...],
) -> None:
    from d810.transforms.plan import PatchFragmentOperation

    gateway = _gateway(modifier)
    detached_capable_operation_ids = {
        operation.operation_id
        for operation in plan.operations
        if (
            operation.direct_transfer_rewrite is not None
            and plan.block(operation.source_block_id).role is FragmentBlockRole.IMPORTED
        )
    }
    if not state.detached_operation_ids <= detached_capable_operation_ids:
        raise SemanticFragmentBackendRejected(
            "GENERATED detached native-body lowering consumed an ineligible operation"
        )
    for step in operation_steps:
        if not isinstance(step, PatchFragmentOperation):
            raise SemanticFragmentBackendRejected(
                "GENERATED operation requires a typed PatchStep"
            )
        operation = step.operation
        if operation.operation_id in state.detached_operation_ids:
            if step.fallthrough_helper_ref is not None:
                raise SemanticFragmentBackendRejected(
                    "GENERATED detached direct route cannot allocate a helper"
                )
            continue
        normalization = operation.computed_branch_normalization
        if isinstance(normalization, FragmentSetccIndexedTableNormalization):
            _realize_generated_setcc_indexed_table_operation(
                modifier,
                plan,
                state,
                operation,
                normalization,
                fallthrough_helper_ref=step.fallthrough_helper_ref,
            )
            continue
        envelope = (
            None if normalization is None else normalization.conditional_select_envelope
        )
        edge_by_role = {edge.role: edge for edge in operation.edges}
        if not isinstance(
            envelope,
            (
                FragmentConditionalSelectEnvelope,
                FragmentReferencedImportedConditionalSelectEnvelope,
            ),
        ) or set(edge_by_role) != {
            SemanticEdgeRole.CONDITIONAL_TAKEN,
            SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
        }:
            raise SemanticFragmentBackendRejected(
                "GENERATED profile admits only the proven conditional-select route"
            )
        source = _live_block_for_binding(
            modifier,
            state.binding(operation.source_block_id),
        )
        selected_binding = state.binding(envelope.selected_value_block_id)
        selected = _live_block_for_binding(modifier, selected_binding)
        join = _live_block_for_binding(
            modifier,
            state.binding(envelope.join_block_id),
        )
        taken_binding = state.binding(
            edge_by_role[SemanticEdgeRole.CONDITIONAL_TAKEN].target_block_id
        )
        fallthrough_binding = state.binding(
            edge_by_role[SemanticEdgeRole.CONDITIONAL_FALLTHROUGH].target_block_id
        )
        taken = _live_block_for_binding(modifier, taken_binding)
        fallthrough = _live_block_for_binding(modifier, fallthrough_binding)
        source_predicate_live_ea = state.live_operation_predicate_ea(operation)
        selected_value_native_ea = (
            int(envelope.predicate_ea)
            if isinstance(envelope, FragmentConditionalSelectEnvelope)
            else int(envelope.selected_value_ea)
        )
        selected_value_live_ea = state.live_instruction_ea(
            envelope.selected_value_block_id,
            selected_value_native_ea,
        )
        join_transfer_live_ea = state.live_instruction_ea(
            envelope.join_block_id,
            int(normalization.unresolved_transfer_ea),
        )
        corridor_obligations = (
            ("source_tail_present", source.tail is not None),
            (
                "source_tail_conditional",
                source.tail is not None
                and ida_hexrays.is_mcode_jcond(int(source.tail.opcode)),
            ),
            (
                "predicate_anchor_exact",
                source.tail is not None
                and int(source.tail.ea) == source_predicate_live_ea,
            ),
            ("source_next_present", source.nextb is not None),
            (
                "selected_physically_adjacent",
                source.nextb is not None
                and int(source.nextb.serial) == int(selected.serial),
            ),
            ("selected_next_present", selected.nextb is not None),
            (
                "join_physically_adjacent",
                selected.nextb is not None
                and int(selected.nextb.serial) == int(join.serial),
            ),
        )
        failed_corridor_obligations = tuple(
            name for name, passed in corridor_obligations if not passed
        )
        if failed_corridor_obligations:
            raise SemanticFragmentBackendRejected(
                "GENERATED normalized corridor changed before route binding; "
                f"operation_id={operation.operation_id!r} "
                f"failed_obligations={failed_corridor_obligations!r} "
                f"source=blk{int(source.serial)}@0x{int(source.start):X} "
                f"selected=blk{int(selected.serial)}@0x{int(selected.start):X} "
                f"join=blk{int(join.serial)}@0x{int(join.start):X} "
                f"source_next={None if source.nextb is None else int(source.nextb.serial)} "
                f"selected_next={None if selected.nextb is None else int(selected.nextb.serial)}"
            )
        source_branch = ida_hexrays.minsn_t(source.tail)
        source_branch.d.make_blkref(int(taken.serial))
        selected_goto = ida_hexrays.minsn_t(selected_value_live_ea)
        selected_goto.opcode = int(ida_hexrays.m_goto)
        selected_goto.l.make_blkref(int(fallthrough.serial))
        join_goto = ida_hexrays.minsn_t(join_transfer_live_ea)
        join_goto.opcode = int(ida_hexrays.m_goto)
        join_goto.l.make_blkref(int(taken.serial))
        source_rows = tuple(_iter_block_instructions(source))
        modifier.replace_instruction_suffix_from_index_now(
            source,
            cut_index=len(source_rows) - 1,
            expected_ea=int(source.tail.ea),
            expected_opcode=int(source.tail.opcode),
            replacement=source_branch,
            mark_dirty=False,
        )
        _replace_generated_instructions(modifier, selected, (selected_goto,))
        _replace_generated_instructions(modifier, join, (join_goto,))
        state.instruction_origins_by_block_id[envelope.selected_value_block_id] = {
            selected_value_live_ea: selected_value_native_ea
        }
        state.instruction_origins_by_block_id[envelope.join_block_id] = {
            join_transfer_live_ea: int(normalization.unresolved_transfer_ea)
        }
        for block in (source, selected, join):
            modifier.configure_block_now(
                block,
                block_type=int(ida_hexrays.BLT_NONE),
                flags=int(block.flags) | int(ida_hexrays.MBL_PROP),
            )
        gateway.record_generated_existing_fallthrough_helper(
            operation_id=operation.operation_id,
            block=selected_binding.version.handle,
        )
        gateway.record_edge_redirect(
            source=state.binding(operation.source_block_id).version.handle,
            target=taken_binding.version.handle,
        )
        gateway.record_edge_redirect(
            source=state.binding(operation.source_block_id).version.handle,
            target=fallthrough_binding.version.handle,
        )


def _block_kind(block_type: int) -> BlockKind:
    return {
        int(ida_hexrays.BLT_NONE): BlockKind.NONE,
        int(ida_hexrays.BLT_STOP): BlockKind.STOP,
        int(ida_hexrays.BLT_XTRN): BlockKind.EXTERNAL,
        int(ida_hexrays.BLT_0WAY): BlockKind.ZERO_WAY,
        int(ida_hexrays.BLT_1WAY): BlockKind.ONE_WAY,
        int(ida_hexrays.BLT_2WAY): BlockKind.TWO_WAY,
        int(ida_hexrays.BLT_NWAY): BlockKind.N_WAY,
    }.get(int(block_type), BlockKind.UNKNOWN)


def _instruction_eas(
    block,
    instruction_origins: dict[int, int] | None = None,
) -> tuple[int, ...]:
    instruction_origins = instruction_origins or {}
    result: list[int] = []
    for instruction in _iter_block_instructions(block):
        live_ea = int(getattr(instruction, "ea", -1) or -1)
        ea = int(instruction_origins.get(live_ea, live_ea))
        if 0 <= ea < _BADADDR and ea not in result:
            result.append(ea)
    return tuple(result)


def _projected_terminator(
    block,
    instruction_origins: dict[int, int] | None = None,
) -> tuple[int | None, InsnKind]:
    """Project the closing live instruction into native, serial-free semantics."""
    tail = getattr(block, "tail", None)
    if tail is None:
        return None, InsnKind.UNKNOWN
    instruction_origins = instruction_origins or {}
    live_ea = int(getattr(tail, "ea", -1) or -1)
    native_ea = int(instruction_origins.get(live_ea, live_ea))
    if not 0 <= native_ea < _BADADDR:
        return None, InsnKind.UNKNOWN
    opcode = int(getattr(tail, "opcode", -1))
    kind = InsnKind.UNKNOWN
    if opcode == int(ida_hexrays.m_goto):
        kind = InsnKind.GOTO
    elif ida_hexrays.is_mcode_jcond(opcode):
        kind = InsnKind.COND_JUMP
    elif opcode == int(ida_hexrays.m_ijmp):
        kind = InsnKind.INDIRECT_JUMP
    elif opcode == int(ida_hexrays.m_jtbl):
        kind = InsnKind.TABLE_JUMP
    elif opcode in {int(ida_hexrays.m_call), int(ida_hexrays.m_icall)}:
        kind = InsnKind.CALL
    elif sdk_owned_call(tail) is not None:
        kind = InsnKind.CALL
    elif opcode == int(ida_hexrays.m_ret):
        kind = InsnKind.RET
    return native_ea, kind


_RETURN_CARRIER_OPCODES = {
    ValueOpKind.MOVE: int(ida_hexrays.m_mov),
    ValueOpKind.ZEXT: int(ida_hexrays.m_xdu),
    ValueOpKind.SEXT: int(ida_hexrays.m_xds),
}


def _return_mreg() -> int:
    try:
        return int(ida_hexrays.reg2mreg(0))
    except Exception as exc:
        raise SemanticFragmentBackendRejected(
            "Hex-Rays return-register identity is unavailable"
        ) from exc


def _native_instruction_rows(
    state: SemanticFragmentBackendState,
    block_id: str,
    block,
) -> tuple[tuple[int, object], ...]:
    origins = state.instruction_origins_by_block_id.get(str(block_id), {})
    rows: list[tuple[int, object]] = []
    for instruction in _iter_block_instructions(block):
        live_ea = int(getattr(instruction, "ea", -1) or -1)
        native_ea = int(origins.get(live_ea, live_ea))
        if 0 <= native_ea < _BADADDR:
            rows.append((native_ea, instruction))
    return tuple(rows)


def _bind_synthesized_instruction_origin(
    state: SemanticFragmentBackendState,
    *,
    block_id: str,
    live_ea: int,
    native_ea: int,
) -> None:
    block_id = str(block_id)
    live_ea = int(live_ea)
    native_ea = int(native_ea)
    origins = state.instruction_origins_by_block_id.setdefault(block_id, {})
    if live_ea in origins or native_ea in origins.values():
        raise SemanticFragmentBackendRejected(
            f"semantic fragment instruction origin is ambiguous at "
            f"{block_id}@0x{native_ea:X}"
        )
    origins[live_ea] = native_ea


def _storage_operand(
    mba,
    storage: StorageIdentity,
    *,
    width: int,
):
    operand = ida_hexrays.mop_t()
    if storage.kind is StorageIdentityKind.GLOBAL:
        operand.make_gvar(int(storage.offset))
    elif storage.kind is StorageIdentityKind.STACK:
        try:
            vd_offset = int(mba.stkoff_ida2vd(int(storage.offset)))
        except Exception as exc:
            raise SemanticFragmentBackendRejected(
                "fragment return stack source cannot bind to the live MBA"
            ) from exc
        operand.make_stkvar(mba, vd_offset)
    else:
        raise SemanticFragmentBackendRejected(
            "fragment return source has unsupported storage identity"
        )
    operand.size = int(width)
    return operand


def _return_source_operand(
    mba,
    source: FragmentReturnSource,
    *,
    live_ea: int,
):
    operand = ida_hexrays.mop_t()
    if source.kind is FragmentReturnSourceKind.CONSTANT:
        operand.make_number(
            int(source.constant),
            int(source.width),
            int(live_ea),
        )
        return operand

    storage = source.storage_identity
    if storage is None:
        raise SemanticFragmentBackendRejected(
            "fragment return source lost its storage identity"
        )
    inner = _storage_operand(mba, storage, width=source.width)
    if source.kind is FragmentReturnSourceKind.STORAGE_VALUE:
        operand.assign(inner)
        return operand
    if source.kind is not FragmentReturnSourceKind.ADDRESS_OF_STORAGE:
        raise SemanticFragmentBackendRejected(
            "fragment return source has unsupported portable kind"
        )
    try:
        address = ida_hexrays.mop_addr_t(
            inner,
            int(source.width),
            int(source.width),
        )
        operand.assign(address)
        operand.size = int(source.width)
    except Exception as exc:
        raise SemanticFragmentBackendRejected(
            "fragment return address source cannot be materialized"
        ) from exc
    return operand


def _prepared_operand_shape(
    operand: object,
    source: FragmentReturnSource,
) -> tuple[object, ...]:
    """Return immutable primitive shape for one prepared carrier operand."""
    storage = source.storage_identity
    return (
        source.kind.value,
        int(source.width),
        None if storage is None else storage.kind.value,
        None if storage is None else int(storage.offset),
        None if source.constant is None else int(source.constant),
        int(getattr(operand, "t", -1)),
        int(getattr(operand, "size", 0)),
    )


def _stack_identity_from_operand(mba, operand) -> StorageIdentity | None:
    stack_ref = getattr(operand, "s", None)
    if stack_ref is None:
        return None
    try:
        ida_offset = int(mba.stkoff_vd2ida(int(stack_ref.off)))
    except Exception:
        return None
    if ida_offset < 0:
        return None
    return StorageIdentity(StorageIdentityKind.STACK, ida_offset)


def _storage_identity_from_operand(mba, operand) -> StorageIdentity | None:
    operand_type = int(getattr(operand, "t", -1))
    if operand_type == int(ida_hexrays.mop_v):
        offset = int(getattr(operand, "g", -1))
        if offset < 0:
            return None
        return StorageIdentity(StorageIdentityKind.GLOBAL, offset)
    if operand_type == int(ida_hexrays.mop_S):
        return _stack_identity_from_operand(mba, operand)
    return None


def _observed_return_source(mba, operand) -> FragmentReturnSource | None:
    operand_type = int(getattr(operand, "t", -1))
    width = int(getattr(operand, "size", 0))
    try:
        if operand_type == int(ida_hexrays.mop_n):
            number = getattr(operand, "nnn", None)
            if number is None:
                return None
            return FragmentReturnSource(
                kind=FragmentReturnSourceKind.CONSTANT,
                width=width,
                constant=int(number.value),
            )
        storage = _storage_identity_from_operand(mba, operand)
        if storage is not None:
            return FragmentReturnSource(
                kind=FragmentReturnSourceKind.STORAGE_VALUE,
                width=width,
                storage_identity=storage,
            )
        if operand_type != int(ida_hexrays.mop_a):
            return None
        address = getattr(operand, "a", None)
        inner = None if address is None else getattr(address, "v", None)
        if inner is None:
            inner = address
        storage = _storage_identity_from_operand(mba, inner)
        if storage is None:
            return None
        return FragmentReturnSource(
            kind=FragmentReturnSourceKind.ADDRESS_OF_STORAGE,
            width=width,
            storage_identity=storage,
        )
    except (TypeError, ValueError):
        return None


def _diagnose_return_carrier(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    planned: FragmentReturnCarrier,
    block,
) -> tuple[FragmentReturnCarrier | None, str]:
    rows = _native_instruction_rows(state, planned.block_id, block)
    state_block = (
        block
        if planned.state_write_block_id == planned.block_id
        else _live_block_for_binding(
            modifier,
            state.binding(planned.state_write_block_id),
        )
    )
    state_rows = _native_instruction_rows(
        state,
        planned.state_write_block_id,
        state_block,
    )
    carrier_matches = tuple(
        index
        for index, (native_ea, _instruction) in enumerate(rows)
        if native_ea == planned.carrier_ea
    )
    same_block = planned.state_write_block_id == planned.block_id
    if len(carrier_matches) == 1:
        carrier_index = carrier_matches[0]
        state_matches = tuple(
            index
            for index, (native_ea, _instruction) in enumerate(state_rows)
            if native_ea == planned.state_write_ea
            and (not same_block or index < carrier_index)
        )
    else:
        carrier_index = -1
        state_matches = ()
    if len(state_matches) != 1 or len(carrier_matches) != 1:
        row_coordinates = tuple(
            (
                hex(native_ea),
                hex(int(getattr(instruction, "ea", -1) or -1)),
                int(getattr(instruction, "opcode", -1)),
            )
            for native_ea, instruction in rows
        )
        return (
            None,
            f"anchor_cardinality state_before_carrier={len(state_matches)} "
            f"carrier={len(carrier_matches)} rows={row_coordinates!r}",
        )
    state_index = state_matches[0]
    instruction = rows[carrier_index][1]
    operation = value_op_from_opcode(int(getattr(instruction, "opcode", -1)))
    destination = getattr(instruction, "d", None)
    right = getattr(instruction, "r", None)
    if operation not in _RETURN_CARRIER_OPCODES:
        return (
            None,
            f"unsupported_opcode={int(getattr(instruction, 'opcode', -1))}",
        )
    if destination is None:
        return None, "destination_missing"
    destination_type = int(getattr(destination, "t", -1))
    if destination_type != int(ida_hexrays.mop_r):
        return None, f"destination_type={destination_type}"
    destination_register = int(getattr(destination, "r", -1))
    expected_register = _return_mreg()
    if destination_register != expected_register:
        return (
            None,
            f"destination_register={destination_register} expected={expected_register}",
        )
    destination_width = int(getattr(destination, "size", 0))
    if destination_width <= 0:
        return None, f"destination_width={destination_width}"
    right_type = int(getattr(right, "t", -1)) if right is not None else -1
    if right_type != int(ida_hexrays.mop_z):
        return None, f"right_operand_type={right_type}"
    source = _observed_return_source(modifier.mba, getattr(instruction, "l", None))
    if source is None:
        left = getattr(instruction, "l", None)
        return (
            None,
            f"source_unavailable type={int(getattr(left, 't', -1))} "
            f"width={int(getattr(left, 'size', 0))}",
        )
    try:
        return (
            FragmentReturnCarrier(
                carrier_id=planned.carrier_id,
                block_id=planned.block_id,
                state_write_block_id=planned.state_write_block_id,
                state_write_ea=state_rows[state_index][0],
                carrier_ea=rows[carrier_index][0],
                operation=operation,
                source=source,
                return_width=int(destination.size),
                corridor_instruction_eas=(
                    tuple(
                        native_ea
                        for native_ea, _instruction in rows[
                            state_index : carrier_index + 1
                        ]
                    )
                    if same_block
                    else planned.corridor_instruction_eas
                ),
            ),
            "matched",
        )
    except (TypeError, ValueError) as exc:
        return None, f"portable_carrier_rejected={type(exc).__name__}"


def _observe_return_carrier(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    planned: FragmentReturnCarrier,
    block,
) -> FragmentReturnCarrier | None:
    observed, _reason = _diagnose_return_carrier(
        modifier,
        state,
        planned,
        block,
    )
    return observed


def _project_return_carriers(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    live_by_id: dict[str, object],
) -> tuple[FragmentReturnCarrier, ...]:
    observed: list[FragmentReturnCarrier] = []
    for planned in plan.return_carriers:
        block = live_by_id.get(planned.block_id)
        if block is None:
            continue
        carrier = _observe_return_carrier(modifier, state, planned, block)
        if carrier is not None:
            observed.append(carrier)
    return tuple(observed)


def _project_terminal_effect_diagnostics(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    live_by_id: dict[str, object],
) -> tuple[ProjectedTerminalEffectDiagnostic, ...]:
    diagnostics: list[ProjectedTerminalEffectDiagnostic] = []
    for planned in plan.return_carriers:
        block = live_by_id.get(planned.block_id)
        if block is None:
            diagnostics.append(
                ProjectedTerminalEffectDiagnostic(
                    effect_id=planned.carrier_id,
                    reason="live_block_missing",
                )
            )
            continue
        carrier, reason = _diagnose_return_carrier(
            modifier,
            state,
            planned,
            block,
        )
        if carrier is None:
            diagnostics.append(
                ProjectedTerminalEffectDiagnostic(
                    effect_id=planned.carrier_id,
                    reason=reason,
                )
            )
    return tuple(diagnostics)


def _observe_terminal_return(
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    planned: FragmentTerminalReturn,
    block,
    observed_carriers: tuple[FragmentReturnCarrier, ...],
) -> FragmentTerminalReturn | None:
    rows = _native_instruction_rows(state, planned.block_id, block)
    matches = tuple(
        index
        for index, (native_ea, _instruction) in enumerate(rows)
        if native_ea == planned.instruction_ea
    )
    if len(matches) != 1 or matches[0] != len(rows) - 1:
        return None
    instruction = rows[matches[0]][1]
    if (
        int(getattr(instruction, "opcode", -1)) != int(ida_hexrays.m_ret)
        or any(
            int(getattr(getattr(instruction, slot, None), "t", -1))
            != int(ida_hexrays.mop_z)
            for slot in ("l", "r", "d")
        )
        or int(block.type) != int(ida_hexrays.BLT_0WAY)
        or tuple(int(value) for value in block.succset)
    ):
        return None

    carrier_by_id = {carrier.carrier_id: carrier for carrier in observed_carriers}
    linked_routes = tuple(
        route for route in plan.terminal_routes if route.return_id == planned.return_id
    )
    linked_carriers = tuple(
        carrier_by_id.get(route.carrier_id) for route in linked_routes
    )
    if (
        not linked_carriers
        or any(carrier is None for carrier in linked_carriers)
        or len({carrier.return_width for carrier in linked_carriers if carrier}) != 1
    ):
        return None
    return_width = next(
        carrier.return_width for carrier in linked_carriers if carrier is not None
    )
    try:
        return FragmentTerminalReturn(
            return_id=planned.return_id,
            block_id=planned.block_id,
            instruction_ea=rows[matches[0]][0],
            return_width=return_width,
        )
    except (TypeError, ValueError):
        return None


def _project_terminal_returns(
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    live_by_id: dict[str, object],
    observed_carriers: tuple[FragmentReturnCarrier, ...],
) -> tuple[FragmentTerminalReturn, ...]:
    observed: list[FragmentTerminalReturn] = []
    for planned in plan.terminal_returns:
        block = live_by_id.get(planned.block_id)
        if block is None:
            continue
        terminal_return = _observe_terminal_return(
            plan,
            state,
            planned,
            block,
            observed_carriers,
        )
        if terminal_return is not None:
            observed.append(terminal_return)
    return tuple(observed)


def _materialize_return_carrier(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    planned: FragmentReturnCarrier,
) -> None:
    block = _live_block_for_binding(modifier, state.binding(planned.block_id))
    rows = _native_instruction_rows(state, planned.block_id, block)
    carrier_matches = tuple(
        instruction
        for native_ea, instruction in rows
        if native_ea == planned.carrier_ea
    )
    if carrier_matches:
        observed = _observe_return_carrier(modifier, state, planned, block)
        if len(carrier_matches) != 1 or observed != planned:
            raise SemanticFragmentBackendRejected(
                f"fragment return carrier conflicts at "
                f"{planned.block_id}@0x{planned.carrier_ea:X}"
            )
        carrier_matches[0].set_persistent()
        return

    same_block = planned.state_write_block_id == planned.block_id
    prefix = planned.corridor_instruction_eas[:-1]
    prefix_rows = rows
    if not same_block:
        state_block = _live_block_for_binding(
            modifier,
            state.binding(planned.state_write_block_id),
        )
        prefix_rows = _native_instruction_rows(
            state,
            planned.state_write_block_id,
            state_block,
        )
    prefix_positions: list[int] = []
    for native_ea in prefix:
        matches = tuple(
            index
            for index, (candidate_ea, _instruction) in enumerate(prefix_rows)
            if candidate_ea == native_ea
        )
        if len(matches) != 1:
            raise SemanticFragmentBackendRejected(
                f"fragment return corridor is ambiguous at "
                f"{planned.state_write_block_id}@0x{native_ea:X}"
            )
        prefix_positions.append(matches[0])
    if same_block and any(
        following != current + 1
        for current, following in zip(prefix_positions, prefix_positions[1:])
    ):
        raise SemanticFragmentBackendRejected(
            f"fragment return corridor is not contiguous in {planned.block_id!r}"
        )

    live_ea = int(modifier.mba.alloc_fict_ea(planned.carrier_ea))
    try:
        construction = state.return_carrier_constructions[planned.carrier_id]
        if (
            construction.source != planned.source
            or construction.return_width != planned.return_width
        ):
            raise SemanticFragmentBackendRejected(
                "prepared return-carrier construction differs from the plan"
            )
        instruction = ida_hexrays.minsn_t(live_ea)
        instruction.opcode = _RETURN_CARRIER_OPCODES[planned.operation]
        source = state.return_carrier_operands[planned.carrier_id]
        instruction.l.assign(source)
        instruction.r.erase()
        instruction.d.make_reg(construction.return_mreg, planned.return_width)
        instruction.set_persistent()
        modifier.insert_instruction_now(
            block,
            instruction,
            rows[prefix_positions[-1]][1] if same_block else None,
        )
    except Exception as exc:
        if isinstance(exc, SemanticFragmentBackendRejected):
            raise
        raise SemanticFragmentBackendRejected(
            f"fragment return carrier could not be synthesized at "
            f"{planned.block_id}@0x{planned.carrier_ea:X}"
        ) from exc
    _bind_synthesized_instruction_origin(
        state,
        block_id=planned.block_id,
        live_ea=live_ea,
        native_ea=planned.carrier_ea,
    )
    modifier.mark_blocks_dirty_now(block)
    if _observe_return_carrier(modifier, state, planned, block) != planned:
        raise SemanticFragmentBackendRejected(
            f"fragment return carrier failed live observation at "
            f"{planned.block_id}@0x{planned.carrier_ea:X}"
        )


def _materialize_terminal_return(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    planned: FragmentTerminalReturn,
) -> None:
    block = _live_block_for_binding(modifier, state.binding(planned.block_id))
    if tuple(int(value) for value in block.succset):
        raise SemanticFragmentBackendRejected(
            f"fragment terminal return block {planned.block_id!r} has successors"
        )
    rows = _native_instruction_rows(state, planned.block_id, block)
    matches = tuple(
        index
        for index, (native_ea, _instruction) in enumerate(rows)
        if native_ea == planned.instruction_ea
    )
    if len(matches) > 1 or (matches and matches[0] != len(rows) - 1):
        raise SemanticFragmentBackendRejected(
            f"fragment terminal return is ambiguous at "
            f"{planned.block_id}@0x{planned.instruction_ea:X}"
        )
    if matches:
        instruction = rows[matches[0]][1]
    else:
        tail = block.tail
        if tail is not None and (
            ida_hexrays.is_mcode_jcond(int(tail.opcode))
            or int(tail.opcode)
            in {
                int(ida_hexrays.m_goto),
                int(ida_hexrays.m_ijmp),
                int(ida_hexrays.m_jtbl),
                int(ida_hexrays.m_call),
                int(ida_hexrays.m_icall),
                int(ida_hexrays.m_ret),
            }
        ):
            raise SemanticFragmentBackendRejected(
                f"fragment terminal return cannot append after a closing "
                f"instruction in {planned.block_id!r}"
            )
        live_ea = int(modifier.mba.alloc_fict_ea(planned.instruction_ea))
        instruction = ida_hexrays.minsn_t(live_ea)
        modifier.insert_instruction_now(block, instruction, block.tail)
        _bind_synthesized_instruction_origin(
            state,
            block_id=planned.block_id,
            live_ea=live_ea,
            native_ea=planned.instruction_ea,
        )
    instruction.opcode = int(ida_hexrays.m_ret)
    instruction.l.erase()
    instruction.r.erase()
    instruction.d.erase()
    modifier.configure_block_now(
        block,
        block_type=int(ida_hexrays.BLT_0WAY),
        flags=(
            int(block.flags) & ~int(ida_hexrays.MBL_GOTO) & ~int(ida_hexrays.MBL_CALL)
        ),
    )
    modifier.mark_blocks_dirty_now(block)
    observed_carriers = _project_return_carriers(
        modifier,
        plan,
        state,
        {
            carrier.block_id: _live_block_for_binding(
                modifier,
                state.binding(carrier.block_id),
            )
            for carrier in plan.return_carriers
        },
    )
    if (
        _observe_terminal_return(
            plan,
            state,
            planned,
            block,
            observed_carriers,
        )
        != planned
    ):
        raise SemanticFragmentBackendRejected(
            f"fragment terminal return failed live observation at "
            f"{planned.block_id}@0x{planned.instruction_ea:X}"
        )


def _materialize_terminal_effects(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
) -> None:
    if plan.return_carriers:
        modifier.refine_transient_terminal_return_type_now(
            tuple(carrier.return_width for carrier in plan.return_carriers),
        )
    gateway = _gateway(modifier)
    for carrier in plan.return_carriers:
        _materialize_return_carrier(modifier, state, carrier)
        gateway.record_semantic_fragment_return_carrier(
            carrier_id=carrier.carrier_id,
            block=state.binding(carrier.block_id).version.handle,
        )
    for terminal_return in plan.terminal_returns:
        _materialize_terminal_return(
            modifier,
            plan,
            state,
            terminal_return,
        )
        gateway.record_semantic_fragment_terminal_return(
            return_id=terminal_return.return_id,
            block=state.binding(terminal_return.block_id).version.handle,
        )


def _site_instruction_matches(
    state: SemanticFragmentBackendState,
    live_by_id: dict[str, object],
    site,
    *,
    context: str,
):
    block = live_by_id.get(site.block_id)
    if block is None:
        raise SemanticFragmentBackendRejected(
            f"{context} {site.site_id!r} has no live block"
        )
    matches = []
    origins = state.instruction_origins_by_block_id.get(str(site.block_id), {})
    instruction = block.head
    while instruction is not None:
        live_ea = int(getattr(instruction, "ea", -1) or -1)
        native_ea = int(origins.get(live_ea, live_ea))
        if native_ea == int(site.instruction_ea):
            matches.append(instruction)
        if instruction is block.tail:
            break
        instruction = instruction.next
    return block, tuple(matches)


def _exact_site_instruction(
    state: SemanticFragmentBackendState,
    live_by_id: dict[str, object],
    site,
    *,
    context: str,
):
    block, matches = _site_instruction_matches(
        state,
        live_by_id,
        site,
        context=context,
    )
    if len(matches) != 1:
        raise SemanticFragmentBackendRejected(
            f"{context} {site.site_id!r} is ambiguous at "
            f"{site.block_id}@0x{int(site.instruction_ea):X}: "
            f"observed {len(matches)} top-level instructions"
        )
    return block, matches[0]


def _require_logical_flag_producer(
    state: SemanticFragmentBackendState,
    live_by_id: dict[str, object],
    site,
) -> None:
    _block, matches = _site_instruction_matches(
        state,
        live_by_id,
        site,
        context="flag-corridor producer",
    )
    if not matches:
        raise SemanticFragmentBackendRejected(
            f"flag-corridor producer {site.site_id!r} is missing at "
            f"{site.block_id}@0x{int(site.instruction_ea):X}"
        )
    try:
        writer_count = sum(
            instruction_writes_condition_codes(instruction) for instruction in matches
        )
    except ConditionCodeQueryUnavailable as exc:
        raise SemanticFragmentBackendRejected(
            f"flag-corridor producer {site.site_id!r} cannot be classified at "
            f"{site.block_id}@0x{int(site.instruction_ea):X}"
        ) from exc
    if writer_count == 0:
        raise SemanticFragmentBackendRejected(
            f"flag-corridor producer {site.site_id!r} is not a condition-code "
            f"writer at {site.block_id}@0x{int(site.instruction_ea):X}"
        )


def _require_flag_corridor_sites(
    state: SemanticFragmentBackendState,
    plan: FragmentPlan,
    live_by_id: dict[str, object],
) -> None:
    for corridor in plan.flag_corridors:
        _require_logical_flag_producer(
            state,
            live_by_id,
            corridor.producer,
        )
        _exact_site_instruction(
            state,
            live_by_id,
            corridor.consumer,
            context="flag-corridor consumer",
        )


def _project_flag_writes(
    state: SemanticFragmentBackendState,
    plan: FragmentPlan,
    live_by_id: dict[str, object],
) -> dict[str, frozenset[int]]:
    result = {block_id: frozenset() for block_id in live_by_id}
    if not plan.flag_corridors:
        return result
    _require_flag_corridor_sites(state, plan, live_by_id)
    for block_id, block in live_by_id.items():
        try:
            observations = condition_code_write_eas(block)
        except ConditionCodeQueryUnavailable as exc:
            raise SemanticFragmentBackendRejected(
                f"condition-code writes cannot be observed for {block_id}"
            ) from exc
        origins = state.instruction_origins_by_block_id.get(str(block_id), {})
        result[block_id] = frozenset(
            int(origins.get(int(live_ea), int(live_ea))) for live_ea in observations
        )
    return result


def _project_value_ranges(
    state: SemanticFragmentBackendState,
    plan: FragmentPlan,
    live_by_id: dict[str, object],
) -> tuple[ProjectedRangeFact, ...]:
    facts: list[ProjectedRangeFact] = []
    for assumption in plan.value_range_assumptions:
        site = assumption.site
        block, instruction = _exact_site_instruction(
            state,
            live_by_id,
            site,
            context="value-range site",
        )
        storage = site.storage_identity
        if storage is None:
            raise SemanticFragmentBackendRejected(
                f"value-range site {site.site_id!r} has no portable storage identity"
            )
        try:
            proof = prove_exact_unsigned_range(
                block,
                instruction,
                storage,
                site.width,
                at_end=(
                    assumption.observation is FragmentRangeObservation.AFTER_INSTRUCTION
                ),
                required_lo=assumption.lo,
                required_hi=assumption.hi,
            )
        except ExactValueRangeQueryUnavailable as exc:
            raise SemanticFragmentBackendRejected(
                f"value range cannot be observed at "
                f"{site.block_id}@0x{int(site.instruction_ea):X}"
            ) from exc
        if proof is not None:
            facts.append(
                ProjectedRangeFact(
                    site_id=site.site_id,
                    value_id=site.value_id,
                    observation=assumption.observation,
                    lo=proof.lo,
                    hi=proof.hi,
                )
            )
    return tuple(facts)


def _unowned_endpoint(modifier: DeferredGraphModifier, serial: int) -> str:
    block = modifier.mba.get_mblock(int(serial))
    if block is not None:
        for candidate in (
            int(getattr(block, "start", -1) or -1),
            int(getattr(getattr(block, "head", None), "ea", -1) or -1),
        ):
            if 0 <= candidate < _BADADDR:
                return f"unowned:blk{int(serial)}@0x{candidate:X}"
    return "unowned@unknown-ea"


def _live_data_flow_site_binding(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    site,
    live_block,
    *,
    role: str,
    require_definition: bool,
) -> tuple[int, int, StorageIdentityKind]:
    storage = site.storage_identity
    if storage is None:
        raise SemanticFragmentBackendRejected(
            f"data-flow {role} {site.site_id!r} has no portable storage identity"
        )
    register: int | None = None
    stack_offset: int | None = None
    if storage.kind is StorageIdentityKind.REGISTER:
        register = int(storage.offset)
        identifier = register
    elif storage.kind is StorageIdentityKind.STACK:
        try:
            stack_offset = int(modifier.mba.stkoff_ida2vd(int(storage.offset)))
        except Exception as exc:
            raise SemanticFragmentBackendRejected(
                f"data-flow {role} {site.site_id!r} stack identity cannot bind "
                "to the live MBA"
            ) from exc
        identifier = stack_offset
    else:
        raise SemanticFragmentBackendRejected(
            f"data-flow {role} {site.site_id!r} has unsupported storage namespace "
            f"{storage.kind.name.lower()}"
        )

    native_ea = int(site.instruction_ea)
    origin_matches = tuple(
        int(live_ea)
        for live_ea, candidate_native_ea in state.instruction_origins_by_block_id.get(
            str(site.block_id),
            {},
        ).items()
        if int(candidate_native_ea) == native_ea
    )
    physical_native_matches = tuple(
        native_ea
        for instruction in _iter_block_instructions(live_block)
        if int(getattr(instruction, "ea", -1)) == native_ea
    )
    candidate_eas = tuple(dict.fromkeys((*origin_matches, *physical_native_matches)))
    if len(candidate_eas) == 1:
        return (int(candidate_eas[0]), int(identifier), storage.kind)
    matches = find_exact_storage_access_eas(
        modifier.mba,
        int(live_block.serial),
        candidate_eas,
        register=register,
        stack_offset=stack_offset,
        size=int(site.width),
        require_definition=require_definition,
    )
    if len(matches) > 1:
        raise SemanticFragmentBackendRejected(
            f"data-flow {role} {site.site_id!r} has ambiguous live storage "
            f"access at {site.block_id}@0x{native_ea:X}"
        )
    if not matches:
        raise SemanticFragmentBackendRejected(
            f"data-flow {role} {site.site_id!r} has no exact live storage "
            f"access at {site.block_id}@0x{native_ea:X}"
        )
    return (int(matches[0]), int(identifier), storage.kind)


def _query_reaching_definitions(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    site,
    live_block,
    predecessor_serials_by_block: Mapping[int, tuple[int, ...]],
):
    live_instruction_ea, identifier, storage_kind = _live_data_flow_site_binding(
        modifier,
        state,
        site,
        live_block,
        role="use",
        require_definition=False,
    )
    if storage_kind is StorageIdentityKind.REGISTER:
        return find_reaching_defs_for_reg_use_in_projection(
            modifier.mba,
            int(live_block.serial),
            live_instruction_ea,
            identifier,
            int(site.width),
            predecessor_serials_by_block,
        )
    if storage_kind is StorageIdentityKind.STACK:
        return find_reaching_defs_for_stkvar_use_in_projection(
            modifier.mba,
            int(live_block.serial),
            live_instruction_ea,
            identifier,
            int(site.width),
            predecessor_serials_by_block,
        )
    raise AssertionError("live data-flow binding accepted an unsupported namespace")


def _query_reached_uses(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    site,
    live_block,
    successor_serials_by_block: Mapping[int, tuple[int, ...]],
):
    live_instruction_ea, identifier, storage_kind = _live_data_flow_site_binding(
        modifier,
        state,
        site,
        live_block,
        role="definition",
        require_definition=True,
    )
    if storage_kind is StorageIdentityKind.REGISTER:
        return find_uses_reached_by_reg_definition_in_projection(
            modifier.mba,
            int(live_block.serial),
            live_instruction_ea,
            identifier,
            int(site.width),
            successor_serials_by_block,
        )
    if storage_kind is StorageIdentityKind.STACK:
        return find_uses_reached_by_stkvar_definition_in_projection(
            modifier.mba,
            int(live_block.serial),
            live_instruction_ea,
            identifier,
            int(site.width),
            successor_serials_by_block,
        )
    raise AssertionError("live data-flow binding accepted an unsupported namespace")


def _require_unambiguous_observed_anchors(
    modifier: DeferredGraphModifier,
    observations,
    ids_by_serial: dict[int, str],
    *,
    role: str,
) -> None:
    seen: set[tuple[int, int]] = set()
    for observation in observations:
        coordinate = (int(observation.block_serial), int(observation.ins_ea))
        if coordinate not in seen:
            seen.add(coordinate)
            continue
        endpoint = ids_by_serial.get(coordinate[0])
        if endpoint is None:
            endpoint = _unowned_endpoint(modifier, coordinate[0])
        raise SemanticFragmentBackendRejected(
            f"data-flow {role} observation is ambiguous at "
            f"{endpoint}@0x{coordinate[1]:X}"
        )


def _observed_site_id(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    observation,
    candidates,
    ids_by_serial: dict[int, str],
    *,
    storage,
    width: int,
    role: str,
) -> str:
    block_serial = int(observation.block_serial)
    live_instruction_ea = int(observation.ins_ea)
    block_id = ids_by_serial.get(block_serial)
    instruction_ea = int(
        state.instruction_origins_by_block_id.get(str(block_id), {}).get(
            live_instruction_ea,
            live_instruction_ea,
        )
    )
    matches = tuple(
        site
        for site in candidates
        if block_id == site.block_id
        and instruction_ea == int(site.instruction_ea)
        and storage == site.storage_identity
        and int(width) == int(site.width)
    )
    endpoint = (
        block_id if block_id is not None else _unowned_endpoint(modifier, block_serial)
    )
    if len(matches) > 1:
        raise SemanticFragmentBackendRejected(
            f"planned data-flow {role} is ambiguous at {endpoint}@0x{instruction_ea:X}"
        )
    if matches:
        return matches[0].site_id
    return f"unplanned-{role}:{storage.key}:{endpoint}@0x{instruction_ea:X}"


def _project_data_flow_relations(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    live_by_id: dict[str, object],
    ids_by_serial: dict[int, str],
    predecessor_serials_by_block: Mapping[int, tuple[int, ...]],
    successor_serials_by_block: Mapping[int, tuple[int, ...]],
    *,
    defer_materialized_predicate_uses: bool = False,
    prepared_instruction_rows_by_block_id: (
        Mapping[str, tuple[tuple[int, object], ...]] | None
    ) = None,
) -> tuple[ProjectedDataFlowRelation, ...]:
    prepared_instruction_rows_by_block_id = (
        {}
        if prepared_instruction_rows_by_block_id is None
        else prepared_instruction_rows_by_block_id
    )

    def prepared_site_is_exact(obligation, site, *, role: str) -> bool:
        instruction_rows = prepared_instruction_rows_by_block_id.get(site.block_id)
        if instruction_rows is None:
            return False
        storage = site.storage_identity
        if storage is None:
            raise SemanticFragmentBackendRejected(
                f"prepared data-flow {role} {site.site_id!r} is unbound"
            )
        register: int | None = None
        stack_offset: int | None = None
        if storage.kind is StorageIdentityKind.REGISTER:
            register = int(storage.offset)
        elif storage.kind is StorageIdentityKind.STACK:
            try:
                stack_offset = int(modifier.mba.stkoff_ida2vd(int(storage.offset)))
            except Exception as exc:
                raise SemanticFragmentBackendRejected(
                    f"prepared data-flow {role} {site.site_id!r} stack identity "
                    "cannot bind to the live MBA"
                ) from exc
        else:
            raise SemanticFragmentBackendRejected(
                f"prepared data-flow {role} {site.site_id!r} has unsupported "
                f"storage namespace {storage.kind.name.lower()}"
            )
        native_anchor_rows = tuple(
            instruction
            for native_ea, instruction in instruction_rows
            if int(native_ea) == int(site.instruction_ea)
        )
        role_index = 1 if role == "definition" else 0
        role_matches = tuple(
            instruction
            for instruction in native_anchor_rows
            if instruction_storage_access_roles(
                instruction,
                register=register,
                stack_offset=stack_offset,
                size=int(site.width),
            )[role_index]
        )
        match_count = len(role_matches)
        if match_count != 1:
            raise SemanticFragmentBackendRejected(
                f"prepared data-flow {role} {site.site_id!r} has "
                f"{match_count} exact storage accesses across "
                f"{len(native_anchor_rows)} instruction anchors "
                f"(obligation_id={obligation.obligation_id!r}, "
                f"block_id={site.block_id!r}, "
                f"instruction_ea=0x{int(site.instruction_ea):X}, "
                f"value_id={site.value_id!r})",
                reason_code=f"prepared_data_flow_{role}_anchor_mismatch",
                anchor_ea=site.instruction_ea,
                payload={
                    "obligation_id": obligation.obligation_id,
                    "site_id": site.site_id,
                    "site_role": role,
                    "block_id": site.block_id,
                    "instruction_ea": site.instruction_ea,
                    "value_id": site.value_id,
                    "match_count": match_count,
                    "native_anchor_count": len(native_anchor_rows),
                },
            )
        return True

    relations: set[ProjectedDataFlowRelation] = set()
    for obligation in plan.data_flow_obligations:
        definition = obligation.definition
        storage = definition.storage_identity
        if storage is None:
            raise SemanticFragmentBackendRejected(
                f"data-flow definition {definition.site_id!r} is unbound"
            )
        definition_block = live_by_id.get(definition.block_id)
        definition_is_prepared = bool(
            definition_block is None
            and prepared_site_is_exact(
                obligation,
                definition,
                role="definition",
            )
        )
        if definition_block is None and not definition_is_prepared:
            raise SemanticFragmentBackendRejected(
                f"data-flow definition {definition.site_id!r} has no live block "
                f"(obligation_id={obligation.obligation_id!r}, "
                f"block_id={definition.block_id!r}, "
                f"instruction_ea=0x{int(definition.instruction_ea):X}, "
                f"value_id={definition.value_id!r})",
                reason_code="data_flow_definition_block_missing",
                anchor_ea=definition.instruction_ea,
                payload={
                    "obligation_id": obligation.obligation_id,
                    "site_id": definition.site_id,
                    "site_role": "definition",
                    "block_id": definition.block_id,
                    "instruction_ea": definition.instruction_ea,
                    "value_id": definition.value_id,
                },
            )
        reached_uses = (
            ()
            if definition_is_prepared
            else tuple(
                _query_reached_uses(
                    modifier,
                    state,
                    definition,
                    definition_block,
                    successor_serials_by_block,
                )
            )
        )
        _require_unambiguous_observed_anchors(
            modifier,
            reached_uses,
            ids_by_serial,
            role="use",
        )
        for observed_use in reached_uses:
            use_site_id = _observed_site_id(
                modifier,
                state,
                observed_use,
                obligation.uses,
                ids_by_serial,
                storage=storage,
                width=definition.width,
                role="use",
            )
            relations.add(
                ProjectedDataFlowRelation(
                    value_id=definition.value_id,
                    definition_site_id=definition.site_id,
                    use_site_id=use_site_id,
                    use_def_observed=False,
                    def_use_observed=True,
                )
            )

        for use in obligation.uses:
            if defer_materialized_predicate_uses and any(
                operation.source_block_id == use.block_id
                and operation.predicate_anchor_ea == use.instruction_ea
                and operation.storage_predicate_materialization is not None
                and operation.storage_predicate_materialization.storage_identity
                == use.storage_identity
                and operation.storage_predicate_materialization.width == use.width
                and plan.block(operation.source_block_id).materialization
                is FragmentBlockMaterialization.CLONE_PUBLISHED
                for operation in plan.operations
            ):
                continue
            use_block = live_by_id.get(use.block_id)
            if use_block is None and prepared_site_is_exact(
                obligation,
                use,
                role="use",
            ):
                continue
            if use_block is None:
                raise SemanticFragmentBackendRejected(
                    f"data-flow use {use.site_id!r} has no live block "
                    f"(obligation_id={obligation.obligation_id!r}, "
                    f"block_id={use.block_id!r}, "
                    f"instruction_ea=0x{int(use.instruction_ea):X}, "
                    f"value_id={use.value_id!r})",
                    reason_code="data_flow_use_block_missing",
                    anchor_ea=use.instruction_ea,
                    payload={
                        "obligation_id": obligation.obligation_id,
                        "site_id": use.site_id,
                        "site_role": "use",
                        "block_id": use.block_id,
                        "instruction_ea": use.instruction_ea,
                        "value_id": use.value_id,
                    },
                )
            reaching_definitions = tuple(
                _query_reaching_definitions(
                    modifier,
                    state,
                    use,
                    use_block,
                    predecessor_serials_by_block,
                )
            )
            _require_unambiguous_observed_anchors(
                modifier,
                reaching_definitions,
                ids_by_serial,
                role="definition",
            )
            for observed_definition in reaching_definitions:
                definition_site_id = _observed_site_id(
                    modifier,
                    state,
                    observed_definition,
                    (definition,),
                    ids_by_serial,
                    storage=storage,
                    width=use.width,
                    role="definition",
                )
                relations.add(
                    ProjectedDataFlowRelation(
                        value_id=definition.value_id,
                        definition_site_id=definition_site_id,
                        use_site_id=use.site_id,
                        use_def_observed=True,
                        def_use_observed=False,
                    )
                )
    return tuple(
        sorted(
            relations,
            key=lambda relation: (
                relation.value_id,
                relation.definition_site_id,
                relation.use_site_id,
                relation.use_def_observed,
                relation.def_use_observed,
            ),
        )
    )


def _projected_live_serial_topology(
    live_by_id: Mapping[str, object],
    successors_by_id: Mapping[str, list[str]],
) -> tuple[dict[int, tuple[int, ...]], dict[int, tuple[int, ...]]]:
    """Collapse instruction-free projected helpers into live block edges."""
    serial_by_id = {
        str(block_id): int(block.serial) for block_id, block in live_by_id.items()
    }
    successors_by_serial: dict[int, tuple[int, ...]] = {}
    for block_id, serial in serial_by_id.items():
        live_successors: list[int] = []
        pending = list(successors_by_id.get(block_id, ()))
        visited_helpers: set[str] = set()
        while pending:
            successor_id = str(pending.pop(0))
            successor_serial = serial_by_id.get(successor_id)
            if successor_serial is not None:
                if successor_serial not in live_successors:
                    live_successors.append(successor_serial)
                continue
            if successor_id in visited_helpers:
                continue
            visited_helpers.add(successor_id)
            pending.extend(successors_by_id.get(successor_id, ()))
        successors_by_serial[serial] = tuple(live_successors)

    predecessor_lists = {serial: [] for serial in successors_by_serial}
    for source_serial, successor_serials in successors_by_serial.items():
        for successor_serial in successor_serials:
            predecessors = predecessor_lists.setdefault(successor_serial, [])
            if source_serial not in predecessors:
                predecessors.append(source_serial)
    predecessors_by_serial = {
        serial: tuple(predecessors)
        for serial, predecessors in predecessor_lists.items()
    }
    return (predecessors_by_serial, successors_by_serial)


def _observe_generated_graph_free_fragment(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
) -> ProjectedFragment:
    """Validate exact live operands, then return the immutable projection."""
    projection = state.preflight_projection
    if projection is None:
        raise SemanticFragmentBackendRejected(
            "GENERATED observation lacks immutable preflight authority"
        )
    superseded_carrier_ids = superseded_direct_transfer_carrier_block_ids(
        plan
    ) | superseded_referenced_conditional_carrier_block_ids(plan)
    planned_setcc_graph_block_ids = {
        block_id
        for operation in plan.operations
        if (
            isinstance(
                operation.computed_branch_normalization,
                FragmentSetccIndexedTableNormalization,
            )
            and operation.computed_branch_normalization.fallthrough_delivery
            is FragmentSetccFallthroughDelivery.PLANNED_HELPER
        )
        for block_id in (
            operation.source_block_id,
            *(edge.target_block_id for edge in operation.edges),
        )
    }
    imported_serials_by_block_id: dict[str, int] = {}
    superseded_carrier_serials: set[int] = set()
    preserved_native_transfer_block_ids = {
        block_id
        for native_body in plan.native_bodies
        for block_id in native_body.preserved_native_transfer_block_ids
    }
    for block in plan.blocks:
        binding = state.bindings.get(block.block_id)
        if binding is None:
            continue
        live = _live_block_for_binding(modifier, binding)
        if block.materialization is FragmentBlockMaterialization.IMPORT_NATIVE:
            origins = state.instruction_origins_by_block_id.get(block.block_id, {})
            live_rows = tuple(_iter_block_instructions(live))
            graph_shape_owned = block.block_id in planned_setcc_graph_block_ids
            if block.block_id not in superseded_carrier_ids and (
                (
                    not graph_shape_owned
                    and (
                        int(live.type) != int(ida_hexrays.BLT_NONE)
                        or tuple(int(value) for value in live.succset)
                        or tuple(int(value) for value in live.predset)
                    )
                )
                or len(origins) != len(live_rows)
                or set(origins) != {int(row.ea) for row in live_rows}
            ):
                raise SemanticFragmentBackendRejected(
                    f"GENERATED imported block {block.block_id!r} changed shape"
                )
            imported_serials_by_block_id[block.block_id] = int(live.serial)
            if block.block_id in superseded_carrier_ids:
                superseded_carrier_serials.add(int(live.serial))
    for operation in plan.operations:
        if operation.operation_id in state.detached_operation_ids:
            rewrite = operation.direct_transfer_rewrite
            edge = operation.edges[0] if len(operation.edges) == 1 else None
            source = _live_block_for_binding(
                modifier,
                state.binding(operation.source_block_id),
            )
            target = (
                None
                if edge is None
                else _live_block_for_binding(
                    modifier,
                    state.binding(edge.target_block_id),
                )
            )
            tail_live_ea = None if source.tail is None else int(source.tail.ea)
            tail_native_ea = (
                None
                if tail_live_ea is None
                else state.instruction_origins_by_block_id.get(
                    operation.source_block_id,
                    {},
                ).get(tail_live_ea)
            )
            failed_obligations = tuple(
                name
                for name, passed in (
                    ("rewrite_present", rewrite is not None),
                    ("direct_edge_present", edge is not None),
                    (
                        "edge_role_direct",
                        edge is not None and edge.role is SemanticEdgeRole.DIRECT,
                    ),
                    ("target_bound", target is not None),
                    ("tail_present", source.tail is not None),
                    (
                        "rewrite_anchor_exact",
                        rewrite is not None
                        and tail_native_ea == int(rewrite.rewrite_anchor_ea),
                    ),
                    (
                        "tail_direct",
                        source.tail is not None
                        and int(source.tail.opcode) == int(ida_hexrays.m_goto),
                    ),
                    (
                        "target_operand_bound",
                        target is not None
                        and source.tail is not None
                        and int(source.tail.l.t) == int(ida_hexrays.mop_b)
                        and int(source.tail.l.b) == int(target.serial),
                    ),
                    ("graph_free_type", int(source.type) == int(ida_hexrays.BLT_NONE)),
                )
                if not passed
            )
            if failed_obligations:
                raise SemanticFragmentBackendRejected(
                    "GENERATED detached direct route failed exact live observation; "
                    f"failed_obligations={failed_obligations!r} "
                    f"source=blk{int(source.serial)}@0x{int(source.start):X} "
                    f"tail_native_ea={None if tail_native_ea is None else hex(int(tail_native_ea))} "
                    f"tail_opcode={None if source.tail is None else int(source.tail.opcode)} "
                    f"tail_l_type={None if source.tail is None else int(source.tail.l.t)} "
                    f"tail_l_block={None if source.tail is None else int(source.tail.l.b)} "
                    f"target_serial={None if target is None else int(target.serial)} "
                    f"block_type={int(source.type)}"
                )
            continue
        normalization = operation.computed_branch_normalization
        edge_by_role = {edge.role: edge for edge in operation.edges}
        source = _live_block_for_binding(
            modifier,
            state.binding(operation.source_block_id),
        )
        if isinstance(normalization, FragmentSetccIndexedTableNormalization):
            if set(edge_by_role) != {
                SemanticEdgeRole.CONDITIONAL_TAKEN,
                SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
            }:
                raise SemanticFragmentBackendRejected(
                    "GENERATED setcc route has invalid semantic edge roles"
                )
            taken = _live_block_for_binding(
                modifier,
                state.binding(
                    edge_by_role[SemanticEdgeRole.CONDITIONAL_TAKEN].target_block_id
                ),
            )
            fallthrough = _live_block_for_binding(
                modifier,
                state.binding(
                    edge_by_role[
                        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH
                    ].target_block_id
                ),
            )
            expected_opcode = _setcc_indexed_table_branch_opcode(normalization)
            source_predicate_live_ea = state.live_operation_predicate_ea(operation)
            common_failed_obligations = tuple(
                name
                for name, passed in (
                    ("source_tail_present", source.tail is not None),
                    (
                        "predicate_orientation_exact",
                        source.tail is not None
                        and int(source.tail.opcode) == expected_opcode,
                    ),
                    (
                        "predicate_anchor_exact",
                        source.tail is not None
                        and int(source.tail.ea) == source_predicate_live_ea,
                    ),
                    (
                        "taken_operand_block_ref",
                        source.tail is not None
                        and int(source.tail.d.t) == int(ida_hexrays.mop_b),
                    ),
                    (
                        "taken_operand_exact",
                        source.tail is not None
                        and int(source.tail.d.b) == int(taken.serial),
                    ),
                )
                if not passed
            )
            delivery_failed_obligations: tuple[str, ...]
            if (
                normalization.fallthrough_delivery
                is FragmentSetccFallthroughDelivery.PHYSICAL_ADJACENCY
            ):
                delivery_failed_obligations = tuple(
                    name
                    for name, passed in (
                        (
                            "physical_false_target",
                            source.nextb is not None
                            and int(source.nextb.serial) == int(fallthrough.serial),
                        ),
                        (
                            "graph_free_source_type",
                            int(source.type) == int(ida_hexrays.BLT_NONE),
                        ),
                    )
                    if not passed
                )
            else:
                helper_id = f"fallthrough-helper:{operation.operation_id}"
                helper_binding = state.bindings.get(helper_id)
                helper = (
                    None
                    if helper_binding is None
                    else _live_block_for_binding(modifier, helper_binding)
                )
                helper_tail = None if helper is None else helper.tail
                taken_predecessor_ids = _generated_setcc_predecessor_block_ids(
                    plan,
                    edge_by_role[
                        SemanticEdgeRole.CONDITIONAL_TAKEN
                    ].target_block_id,
                )
                fallthrough_predecessor_ids = (
                    _generated_setcc_predecessor_block_ids(
                        plan,
                        edge_by_role[
                            SemanticEdgeRole.CONDITIONAL_FALLTHROUGH
                        ].target_block_id,
                    )
                )
                taken_predecessor_serials = tuple(
                    int(
                        _live_block_for_binding(
                            modifier,
                            state.binding(block_id),
                        ).serial
                    )
                    for block_id in taken_predecessor_ids
                )
                fallthrough_predecessor_serials = tuple(
                    int(
                        _live_block_for_binding(
                            modifier,
                            state.binding(block_id),
                        ).serial
                    )
                    for block_id in fallthrough_predecessor_ids
                )
                delivery_failed_obligations = tuple(
                    name
                    for name, passed in (
                        ("planned_helper_bound", helper is not None),
                        (
                            "planned_helper_adjacent",
                            helper is not None
                            and source.nextb is not None
                            and int(source.nextb.serial) == int(helper.serial),
                        ),
                        (
                            "planned_source_two_way",
                            int(source.type) == int(ida_hexrays.BLT_2WAY),
                        ),
                        (
                            "planned_source_successors",
                            helper is not None
                            and tuple(int(value) for value in source.succset)
                            == (int(helper.serial), int(taken.serial)),
                        ),
                        (
                            "planned_helper_one_way",
                            helper is not None
                            and int(helper.type) == int(ida_hexrays.BLT_1WAY),
                        ),
                        (
                            "planned_helper_goto",
                            helper_tail is not None
                            and int(helper_tail.opcode) == int(ida_hexrays.m_goto)
                            and int(helper_tail.l.t) == int(ida_hexrays.mop_b)
                            and int(helper_tail.l.b) == int(fallthrough.serial),
                        ),
                        (
                            "planned_helper_successor",
                            helper is not None
                            and tuple(int(value) for value in helper.succset)
                            == (int(fallthrough.serial),),
                        ),
                        (
                            "planned_helper_predecessor",
                            helper is not None
                            and tuple(int(value) for value in helper.predset)
                            == (int(source.serial),),
                        ),
                        (
                            "planned_taken_predecessor",
                            tuple(sorted(int(value) for value in taken.predset))
                            == tuple(sorted(taken_predecessor_serials)),
                        ),
                        (
                            "planned_fallthrough_predecessor",
                            helper is not None
                            and tuple(
                                sorted(int(value) for value in fallthrough.predset)
                            )
                            == tuple(sorted(fallthrough_predecessor_serials)),
                        ),
                    )
                    if not passed
                )
            failed_obligations = (
                *common_failed_obligations,
                *delivery_failed_obligations,
            )
            if failed_obligations:
                raise SemanticFragmentBackendRejected(
                    "GENERATED setcc route failed exact live observation; "
                    f"operation_id={operation.operation_id!r} "
                    f"failed_obligations={failed_obligations!r}"
                )
        else:
            envelope = (
                None
                if normalization is None
                else normalization.conditional_select_envelope
            )
            if not isinstance(
                envelope,
                (
                    FragmentConditionalSelectEnvelope,
                    FragmentReferencedImportedConditionalSelectEnvelope,
                ),
            ):
                raise SemanticFragmentBackendRejected(
                    "GENERATED observation found an unsupported operation"
                )
            selected = _live_block_for_binding(
                modifier,
                state.binding(envelope.selected_value_block_id),
            )
            join = _live_block_for_binding(
                modifier,
                state.binding(envelope.join_block_id),
            )
            taken = _live_block_for_binding(
                modifier,
                state.binding(
                    edge_by_role[SemanticEdgeRole.CONDITIONAL_TAKEN].target_block_id
                ),
            )
            fallthrough = _live_block_for_binding(
                modifier,
                state.binding(
                    edge_by_role[
                        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH
                    ].target_block_id
                ),
            )
            source_predicate_live_ea = state.live_operation_predicate_ea(operation)
            selected_value_native_ea = (
                int(envelope.predicate_ea)
                if isinstance(envelope, FragmentConditionalSelectEnvelope)
                else int(envelope.selected_value_ea)
            )
            selected_value_live_ea = state.live_instruction_ea(
                envelope.selected_value_block_id,
                selected_value_native_ea,
            )
            join_transfer_live_ea = state.live_instruction_ea(
                envelope.join_block_id,
                int(normalization.unresolved_transfer_ea),
            )
            selected_rows = tuple(_iter_block_instructions(selected))
            join_rows = tuple(_iter_block_instructions(join))
            if (
                source.tail is None
                or not ida_hexrays.is_mcode_jcond(int(source.tail.opcode))
                or int(source.tail.ea) != source_predicate_live_ea
                or int(source.tail.d.t) != int(ida_hexrays.mop_b)
                or int(source.tail.d.b) != int(taken.serial)
                or source.nextb is None
                or int(source.nextb.serial) != int(selected.serial)
                or selected.nextb is None
                or int(selected.nextb.serial) != int(join.serial)
                or len(selected_rows) != 1
                or int(selected_rows[0].ea) != selected_value_live_ea
                or int(selected_rows[0].opcode) != int(ida_hexrays.m_goto)
                or int(selected_rows[0].l.t) != int(ida_hexrays.mop_b)
                or int(selected_rows[0].l.b) != int(fallthrough.serial)
                or len(join_rows) != 1
                or int(join_rows[0].ea) != join_transfer_live_ea
                or int(join_rows[0].opcode) != int(ida_hexrays.m_goto)
                or int(join_rows[0].l.t) != int(ida_hexrays.mop_b)
                or int(join_rows[0].l.b) != int(taken.serial)
                or any(
                    int(block.type) != int(ida_hexrays.BLT_NONE)
                    for block in (source, selected, join)
                )
            ):
                raise SemanticFragmentBackendRejected(
                    "GENERATED conditional route failed exact live observation"
                )
        _predecessors, successors, _kinds = _generated_structural_serial_topology(
            modifier
        )
        reachable: set[int] = set()
        pending = [int(source.serial)]
        while pending:
            serial = pending.pop()
            if serial in reachable:
                continue
            reachable.add(serial)
            pending.extend(successors.get(serial, ()))
        reference_authority = operation.reference_route_authority
        closure_block_ids = (
            ()
            if reference_authority is None
            else reference_authority.imported_closure_block_ids
        )
        missing_closure_bindings = tuple(
            block_id
            for block_id in closure_block_ids
            if block_id not in imported_serials_by_block_id
        )
        if not closure_block_ids or missing_closure_bindings:
            raise SemanticFragmentBackendRejected(
                "GENERATED conditional route lacks typed imported closure; "
                f"operation_id={operation.operation_id!r} "
                f"missing_block_ids={missing_closure_bindings!r}"
            )
        required_reachable_serials = {
            imported_serials_by_block_id[block_id] for block_id in closure_block_ids
        } - superseded_carrier_serials - {
            imported_serials_by_block_id[block_id]
            for block_id in closure_block_ids
            if block_id in preserved_native_transfer_block_ids
        }
        if not required_reachable_serials.issubset(reachable):
            missing = tuple(sorted(required_reachable_serials - reachable))
            raise SemanticFragmentBackendRejected(
                "GENERATED imported closure is not structurally reachable: "
                f"serials={missing!r}"
            )
    return projection


def _project_fragment(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    *,
    simulate_root_publication: bool = True,
) -> ProjectedFragment:
    if _generated_graph_free(modifier):
        return _observe_generated_graph_free_fragment(modifier, plan, state)
    root_helper_ids = {
        helper.helper_block_id for helper in state.root_fallthrough_helpers
    }
    fallthrough_helper_ids = {
        helper.helper_block_id for helper in state.fallthrough_helpers
    }
    structural_direct_targets = {
        operation.source_block_id: operation.edges[0].target_block_id
        for operation in plan.operations
        if (
            len(operation.edges) == 1
            and operation.edges[0].role is SemanticEdgeRole.DIRECT
            and operation.direct_transfer_rewrite is None
            and plan.block(operation.source_block_id).materialization
            in {
                FragmentBlockMaterialization.CLONE_PUBLISHED,
                FragmentBlockMaterialization.IMPORT_NATIVE,
            }
        )
    }
    projection_bindings = dict(state.bindings)
    live_by_id = {}
    for block_id, binding in projection_bindings.items():
        live = _try_live_block_for_binding(modifier, binding)
        if live is None:
            if block_id not in root_helper_ids:
                raise SemanticFragmentBackendRejected(
                    f"fragment block {block_id!r} has no live physical version"
                )
            continue
        live_by_id[block_id] = live
    if state.preflight_projection is None:
        raise SemanticFragmentBackendRejected(
            "staged semantic fragment lacks immutable preflight authority"
        )
    gateway = _gateway(modifier)
    transaction_id = _transaction_id(modifier)
    for expected_binding in state.preflight_projection.identity_bindings:
        block_id = expected_binding.block_id
        if block_id in projection_bindings:
            continue
        matches: list[tuple[object, object, object]] = []
        for serial in range(int(modifier.mba.qty)):
            handle = gateway.identity_index.handle_for_serial(serial)
            proxy = gateway.identity_index.logical_proxy_for_handle(handle)
            if proxy is None or proxy.proxy_token != expected_binding.logical_owner_id:
                continue
            version = proxy.resolve(transaction_id=transaction_id)
            bound = (
                None
                if version is None
                else gateway.identity_index.resolve_logical_version(
                    version,
                    transaction_id=transaction_id,
                )
            )
            live = None if bound is None else modifier.mba.get_mblock(int(bound.serial))
            if live is not None and bound is not None and version is not None:
                matches.append((live, proxy, version))
        if len(matches) != 1:
            raise SemanticFragmentBackendRejected(
                f"full staged CFG block {block_id!r} lacks immutable "
                "transaction-local authority"
            )
        live, proxy, version = matches[0]
        if version.version_id.version != expected_binding.version:
            raise SemanticFragmentBackendRejected(
                f"full staged CFG block {block_id!r} changed logical version"
            )
        projection_bindings[block_id] = SemanticFragmentRuntimeBinding(
            block_id=block_id,
            proxy=proxy,
            version=version,
            state=FragmentBindingState.PUBLISHED,
        )
        live_by_id[block_id] = live
    represented_serials = {int(block.serial) for block in live_by_id.values()}
    for serial in range(int(modifier.mba.qty)):
        if serial in represented_serials:
            continue
        block = modifier.mba.get_mblock(serial)
        anchor_ea = int(getattr(block, "start", 0) or 0)
        raise SemanticFragmentBackendRejected(
            f"staged SDK produced unwitnessed blk{serial}@0x{anchor_ea:X}"
        )
    ids_by_serial: dict[int, str] = {}
    for block_id, block in live_by_id.items():
        serial = int(block.serial)
        if serial in ids_by_serial:
            raise SemanticFragmentBackendRejected(
                "two fragment block ids resolve to one physical version"
            )
        ids_by_serial[serial] = block_id

    successors: dict[str, list[str]] = {}
    predecessors: dict[str, list[str]] = {}
    kinds: dict[str, BlockKind] = {}
    physical_positions: dict[str, int] = {}
    adjacent_fallthrough_target_ids: dict[str, str | None] = {}
    instruction_eas: dict[str, tuple[int, ...]] = {}
    terminator_eas: dict[str, int | None] = {}
    terminator_kinds: dict[str, InsnKind] = {}
    for block_id, block in live_by_id.items():
        block_kind = _block_kind(int(block.type))
        raw_successors = tuple(int(serial) for serial in block.succset)
        if block_kind is BlockKind.ZERO_WAY and raw_successors:
            stop = (
                modifier.mba.get_mblock(raw_successors[0])
                if len(raw_successors) == 1
                else None
            )
            if (
                stop is None
                or int(stop.type) != int(ida_hexrays.BLT_STOP)
                or int(stop.serial) != int(modifier.mba.qty) - 1
            ):
                raise SemanticFragmentBackendRejected(
                    f"zero-way successor bookkeeping is malformed for {block_id!r}"
                )
        successors[block_id] = (
            []
            if block_kind is BlockKind.ZERO_WAY
            else [
                ids_by_serial.get(
                    int(serial),
                    _unowned_endpoint(modifier, int(serial)),
                )
                for serial in raw_successors
            ]
        )
        predecessors[block_id] = [
            ids_by_serial.get(
                int(serial),
                _unowned_endpoint(modifier, int(serial)),
            )
            for serial in block.predset
        ]
        kinds[block_id] = block_kind
        physical_positions[block_id] = int(block.serial)
        next_block = getattr(block, "nextb", None)
        adjacent_fallthrough_target_ids[block_id] = (
            None
            if block_kind is not BlockKind.TWO_WAY or next_block is None
            else ids_by_serial.get(
                int(next_block.serial),
                _unowned_endpoint(modifier, int(next_block.serial)),
            )
        )
        instruction_origins = state.instruction_origins_by_block_id.get(
            block_id,
            {},
        )
        instruction_eas[block_id] = _instruction_eas(block, instruction_origins)
        (
            terminator_eas[block_id],
            terminator_kinds[block_id],
        ) = _projected_terminator(block, instruction_origins)
        if block_id in fallthrough_helper_ids:
            helper_instructions = tuple(_iter_block_instructions(block))
            if (
                block_kind is not BlockKind.ONE_WAY
                or len(raw_successors) != 1
                or len(helper_instructions) != 1
                or int(helper_instructions[0].opcode) != int(ida_hexrays.m_goto)
                or not int(block.flags) & int(ida_hexrays.MBL_GOTO)
            ):
                raise SemanticFragmentBackendRejected(
                    f"planned fallthrough helper {block_id!r} lost its exact "
                    "synthetic goto shape"
                )
            instruction_eas[block_id] = ()
            terminator_eas[block_id] = None
            terminator_kinds[block_id] = InsnKind.GOTO
        structural_target_id = structural_direct_targets.get(block_id)
        if structural_target_id is not None:
            direct_instructions = tuple(_iter_block_instructions(block))
            direct_tail = None if not direct_instructions else direct_instructions[-1]
            live_tail_ea = (
                None
                if direct_tail is None
                else int(getattr(direct_tail, "ea", -1) or -1)
            )
            if live_tail_ea is not None and live_tail_ea not in instruction_origins:
                target = live_by_id.get(structural_target_id)
                expected = state.preflight_projection.block(block_id)
                native_goto_retained = bool(
                    expected.terminator_ea is not None
                    and expected.terminator_kind is InsnKind.GOTO
                    and live_tail_ea == int(expected.terminator_ea)
                )
                exact_goto_shape = bool(
                    target is not None
                    and block_kind is BlockKind.ONE_WAY
                    and tuple(raw_successors) == (int(target.serial),)
                    and direct_tail is not None
                    and int(direct_tail.opcode) == int(ida_hexrays.m_goto)
                    and int(getattr(direct_tail.l, "t", -1))
                    == int(ida_hexrays.mop_b)
                    and int(getattr(direct_tail.l, "b", -1))
                    == int(target.serial)
                    and bool(int(block.flags) & int(ida_hexrays.MBL_GOTO))
                )
                if native_goto_retained and exact_goto_shape:
                    continue
                prefix_live_eas = tuple(
                    int(getattr(instruction, "ea", -1) or -1)
                    for instruction in direct_instructions[:-1]
                )
                source_materialization = plan.block(block_id).materialization
                if (
                    source_materialization
                    is FragmentBlockMaterialization.CLONE_PUBLISHED
                ):
                    prefix_has_exact_origins = (
                        prefix_live_eas == expected.instruction_eas
                    )
                    projected_prefix_eas = expected.instruction_eas
                else:
                    prefix_has_exact_origins = all(
                        ea in instruction_origins for ea in prefix_live_eas
                    )
                    projected_prefix_eas = tuple(
                        dict.fromkeys(
                            int(instruction_origins[ea])
                            for ea in prefix_live_eas
                            if ea in instruction_origins
                        )
                    )
                if (
                    not exact_goto_shape
                    or not prefix_has_exact_origins
                    or expected.terminator_ea is not None
                    or expected.terminator_kind is not InsnKind.GOTO
                ):
                    raise SemanticFragmentBackendRejected(
                        f"planned structural direct transfer {block_id!r} lost "
                        "its exact synthetic goto shape; "
                        f"target_bound={target is not None} "
                        f"kind={block_kind.value} "
                        f"successors={tuple(raw_successors)!r} "
                        f"target_serial={None if target is None else int(target.serial)!r} "
                        f"tail_opcode={None if direct_tail is None else int(direct_tail.opcode)!r} "
                        f"tail_ea={live_tail_ea!r} "
                        f"tail_l_type={None if direct_tail is None else int(getattr(direct_tail.l, 't', -1))!r} "
                        f"tail_l_block={None if direct_tail is None else int(getattr(direct_tail.l, 'b', -1))!r} "
                        f"flags=0x{int(block.flags):X} "
                        f"goto_flag=0x{int(ida_hexrays.MBL_GOTO):X} "
                        f"prefix_origins={prefix_live_eas!r} "
                        f"known_origins={tuple(sorted(instruction_origins))!r} "
                        f"expected_terminator=({expected.terminator_ea!r}, "
                        f"{expected.terminator_kind.value})"
                    )
                instruction_eas[block_id] = projected_prefix_eas
                terminator_eas[block_id] = None
                terminator_kinds[block_id] = InsnKind.GOTO
    flag_write_eas = _project_flag_writes(state, plan, live_by_id)

    if simulate_root_publication:
        for root_id in plan.roots:
            replacement = plan.block(root_id)
            original_id = str(replacement.replaces_block_id)
            for predecessor_id in tuple(predecessors[original_id]):
                if predecessor_id not in successors:
                    raise SemanticFragmentBackendRejected(
                        "root predecessor is outside the closed fragment projection"
                    )
                role = _incoming_root_edge_role(
                    live_by_id[predecessor_id],
                    live_by_id[original_id],
                )
                requires_helper = _root_edge_requires_helper(
                    live_by_id[predecessor_id],
                    live_by_id[original_id],
                    role,
                )
                predecessors[original_id].remove(predecessor_id)
                projected_target_id = root_id
                if requires_helper:
                    matching_helpers = tuple(
                        helper
                        for helper in state.root_fallthrough_helpers
                        if helper.source_block_id == predecessor_id
                        and helper.root_block_id == root_id
                    )
                    if len(matching_helpers) != 1:
                        raise SemanticFragmentBackendRejected(
                            "physical root fallthrough lacks one reserved helper"
                        )
                    helper = matching_helpers[0]
                    helper_id = helper.helper_block_id
                    insertion_position = physical_positions[predecessor_id] + 1
                    for block_id, position in tuple(physical_positions.items()):
                        if position >= insertion_position:
                            physical_positions[block_id] = position + 1
                    kinds[helper_id] = BlockKind.ONE_WAY
                    physical_positions[helper_id] = insertion_position
                    adjacent_fallthrough_target_ids[helper_id] = None
                    instruction_eas[helper_id] = ()
                    terminator_eas[helper_id] = None
                    terminator_kinds[helper_id] = InsnKind.UNKNOWN
                    flag_write_eas[helper_id] = frozenset()
                    successors[helper_id] = [root_id]
                    predecessors[helper_id] = [predecessor_id]
                    predecessors[root_id].append(helper_id)
                    projected_target_id = helper_id
                    if kinds[predecessor_id] is BlockKind.TWO_WAY:
                        adjacent_fallthrough_target_ids[predecessor_id] = helper_id
                else:
                    predecessors[root_id].append(predecessor_id)
                successors[predecessor_id] = [
                    projected_target_id if target_id == original_id else target_id
                    for target_id in successors[predecessor_id]
                ]

    entry_ids = tuple(
        block_id for block_id, block in live_by_id.items() if int(block.serial) == 0
    )
    if len(entry_ids) != 1:
        raise SemanticFragmentBackendRejected(
            "fragment plan must own exactly one projected function entry"
        )

    projected_blocks = tuple(
        ProjectedFragmentBlock(
            block_id=block_id,
            kind=kinds[block_id],
            successors=tuple(successors[block_id]),
            predecessors=tuple(predecessors[block_id]),
            physical_position=physical_positions[block_id],
            adjacent_fallthrough_target_id=(adjacent_fallthrough_target_ids[block_id]),
            terminator_ea=terminator_eas[block_id],
            terminator_kind=terminator_kinds[block_id],
            instruction_eas=instruction_eas[block_id],
            flag_write_eas=flag_write_eas[block_id],
        )
        for block_id in successors
    )
    plan_blocks_by_id = {block.block_id: block for block in plan.blocks}
    projected_bindings: list[ProjectedIdentityBinding] = []
    for binding in projection_bindings.values():
        physical_identity = binding.version.handle.stable_identity
        planned = plan_blocks_by_id.get(binding.block_id)
        projected_identity = physical_identity
        if planned is not None:
            planned_identity = planned.stable_identity
            if (planned_identity is None and physical_identity is not None) or (
                planned_identity is not None
                and (
                    physical_identity is None
                    or not stable_block_identity_covers(
                        physical_identity,
                        planned_identity,
                    )
                )
            ):
                raise SemanticFragmentBackendRejected(
                    f"physical identity for {binding.block_id!r} does not cover "
                    "plan identity"
                )
            projected_identity = planned_identity
        projected_bindings.append(
            ProjectedIdentityBinding(
                block_id=binding.block_id,
                logical_owner_id=binding.proxy.proxy_token,
                version=binding.version.version_id.version,
                generation=binding.version.generation,
                state=binding.state,
                stable_identity=projected_identity,
                previous_version=(
                    None
                    if binding.version.predecessor_version_id is None
                    else binding.version.predecessor_version_id.version
                ),
            )
        )
    (
        predecessor_serials_by_block,
        successor_serials_by_block,
    ) = _projected_live_serial_topology(live_by_id, successors)
    data_flow_relations = _project_data_flow_relations(
        modifier,
        plan,
        state,
        live_by_id,
        ids_by_serial,
        predecessor_serials_by_block,
        successor_serials_by_block,
    )
    value_ranges = _project_value_ranges(state, plan, live_by_id)
    return_carriers = _project_return_carriers(
        modifier,
        plan,
        state,
        live_by_id,
    )
    terminal_effect_diagnostics = _project_terminal_effect_diagnostics(
        modifier,
        plan,
        state,
        live_by_id,
    )
    terminal_returns = _project_terminal_returns(
        plan,
        state,
        live_by_id,
        return_carriers,
    )
    return ProjectedFragment(
        entry_block_id=entry_ids[0],
        blocks=projected_blocks,
        identity_bindings=tuple(projected_bindings),
        fallthrough_helpers=tuple(state.fallthrough_helpers),
        root_fallthrough_helpers=tuple(state.root_fallthrough_helpers),
        return_carriers=return_carriers,
        terminal_returns=terminal_returns,
        terminal_effect_diagnostics=terminal_effect_diagnostics,
        data_flow_relations=data_flow_relations,
        value_ranges=value_ranges,
    )


def _try_live_block_for_binding(
    modifier: DeferredGraphModifier,
    binding: SemanticFragmentRuntimeBinding,
):
    gateway = _gateway(modifier)
    bound = gateway.identity_index.resolve_logical_version(
        binding.version,
        transaction_id=_transaction_id(modifier),
    )
    if bound is None:
        return None
    block = modifier.mba.get_mblock(int(bound.serial))
    if block is None:
        raise SemanticFragmentBackendRejected(
            f"fragment block {binding.block_id!r} is absent from the live MBA"
        )
    return block


def _binding_for_live_serial(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    serial: int,
) -> SemanticFragmentRuntimeBinding:
    matches = tuple(
        binding
        for binding in state.bindings.values()
        if (
            (live := _try_live_block_for_binding(modifier, binding)) is not None
            and int(live.serial) == int(serial)
        )
    )
    if len(matches) != 1:
        raise SemanticFragmentBackendRejected(
            "root predecessor is not owned by exactly one fragment binding"
        )
    return matches[0]


def _incoming_root_edge_role(predecessor, original) -> SemanticEdgeRole:
    successors = tuple(int(value) for value in predecessor.succset)
    original_serial = int(original.serial)
    if successors == (original_serial,):
        tail = predecessor.tail
        if tail is not None and int(tail.opcode) in {
            int(ida_hexrays.m_call),
            int(ida_hexrays.m_icall),
        }:
            if (
                predecessor.nextb is None
                or int(predecessor.nextb.serial) != original_serial
            ):
                raise SemanticFragmentBackendRejected(
                    "call root predecessor physical fallthrough is not adjacent"
                )
            return SemanticEdgeRole.CALL_FALLTHROUGH
        return SemanticEdgeRole.DIRECT
    tail = predecessor.tail
    if (
        len(successors) != 2
        or tail is None
        or not ida_hexrays.is_mcode_jcond(int(tail.opcode))
        or getattr(tail, "d", None) is None
        or int(tail.d.t) != int(ida_hexrays.mop_b)
    ):
        raise SemanticFragmentBackendRejected(
            "root predecessor is not a supported one-way or conditional edge"
        )
    taken_serial = int(tail.d.b)
    fallthroughs = tuple(
        successor for successor in successors if successor != taken_serial
    )
    if taken_serial not in successors or len(fallthroughs) != 1:
        raise SemanticFragmentBackendRejected(
            "root predecessor conditional topology is inconsistent"
        )
    if original_serial == taken_serial:
        return SemanticEdgeRole.CONDITIONAL_TAKEN
    if original_serial != fallthroughs[0]:
        raise SemanticFragmentBackendRejected(
            "root predecessor does not target its declared original"
        )
    if predecessor.nextb is None or int(predecessor.nextb.serial) != original_serial:
        raise SemanticFragmentBackendRejected(
            "root predecessor physical fallthrough is not adjacent"
        )
    return SemanticEdgeRole.CONDITIONAL_FALLTHROUGH


def _root_edge_requires_helper(
    predecessor,
    original,
    role: SemanticEdgeRole,
) -> bool:
    if role in {
        SemanticEdgeRole.CALL_FALLTHROUGH,
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
    }:
        return True
    if role is not SemanticEdgeRole.DIRECT:
        return False

    tail = predecessor.tail
    if tail is not None and int(tail.opcode) == int(ida_hexrays.m_goto):
        left = getattr(tail, "l", None)
        if (
            left is None
            or int(left.t) != int(ida_hexrays.mop_b)
            or int(left.b) != int(original.serial)
        ):
            raise SemanticFragmentBackendRejected(
                "direct root predecessor goto does not target its original"
            )
        return False
    if tail is not None and (
        ida_hexrays.is_mcode_jcond(int(tail.opcode))
        or int(tail.opcode)
        in {
            int(ida_hexrays.m_ijmp),
            int(ida_hexrays.m_jtbl),
            int(ida_hexrays.m_ret),
        }
    ):
        raise SemanticFragmentBackendRejected(
            "direct root predecessor has an unsupported closing transfer"
        )
    if predecessor.nextb is None or int(predecessor.nextb.serial) != int(
        original.serial
    ):
        raise SemanticFragmentBackendRejected(
            "implicit direct root fallthrough is not physically adjacent"
        )
    return True


def _generated_graph_free(modifier: DeferredGraphModifier) -> bool:
    from d810.hexrays.mutation.semantic_fragment_profile import (
        SemanticFragmentPublicationProfile,
    )

    return (
        modifier.semantic_fragment_publication_profile
        is SemanticFragmentPublicationProfile.GENERATED_GRAPH_FREE
    )


def _generated_structural_serial_topology(
    modifier: DeferredGraphModifier,
) -> tuple[
    dict[int, tuple[int, ...]],
    dict[int, tuple[int, ...]],
    dict[int, BlockKind],
]:
    """Project GENERATED control flow without asking Hex-Rays for a graph."""
    quantity = int(modifier.mba.qty)
    stop_serial = quantity - 1
    serials_by_start: dict[int, list[int]] = {}
    for serial in range(quantity):
        block = modifier.mba.get_mblock(serial)
        if block is None:
            raise SemanticFragmentBackendRejected(
                f"GENERATED structural projection lost block serial {serial}"
            )
        serials_by_start.setdefault(int(block.start), []).append(serial)

    def local_address_target(operand: object) -> int | None:
        candidates = tuple(serials_by_start.get(int(operand.g), ()))
        if len(candidates) > 1:
            raise SemanticFragmentBackendRejected(
                "GENERATED address target has ambiguous local block authority"
            )
        return None if not candidates else int(candidates[0])

    successors: dict[int, tuple[int, ...]] = {}
    kinds: dict[int, BlockKind] = {}
    for serial in range(quantity):
        block = modifier.mba.get_mblock(serial)
        if block is None:
            raise SemanticFragmentBackendRejected(
                f"GENERATED structural projection lost block serial {serial}"
            )
        if serial == stop_serial or int(block.type) == int(ida_hexrays.BLT_STOP):
            successors[serial] = ()
            kinds[serial] = BlockKind.STOP
            continue
        tail = block.tail
        projected: list[int] = []
        if tail is None:
            projected.append(serial + 1)
        else:
            opcode = int(tail.opcode)
            if opcode == int(ida_hexrays.m_goto):
                if int(tail.l.t) == int(ida_hexrays.mop_b):
                    projected.append(int(tail.l.b))
                elif int(tail.l.t) == int(ida_hexrays.mop_v):
                    target = local_address_target(tail.l)
                    if target is not None:
                        projected.append(target)
                else:
                    raise SemanticFragmentBackendRejected(
                        f"GENERATED goto lacks block authority in "
                        f"blk{serial}@0x{int(block.start):X}"
                    )
            elif ida_hexrays.is_mcode_jcond(opcode):
                taken_target: int | None = None
                if int(tail.d.t) == int(ida_hexrays.mop_b):
                    taken_target = int(tail.d.b)
                elif int(tail.d.t) == int(ida_hexrays.mop_v):
                    taken_target = local_address_target(tail.d)
                elif int(tail.d.t) != int(ida_hexrays.mop_v):
                    raise SemanticFragmentBackendRejected(
                        f"GENERATED conditional lacks block authority in "
                        f"blk{serial}@0x{int(block.start):X}"
                    )
                # Before Hex-Rays builds the CFG, native conditional targets
                # outside the owned fragment remain address operands.  They
                # are boundary exits, not missing internal block authority;
                # only the physically adjacent fallthrough is locally
                # projectable.  Plan-owned conditionals are observed below
                # with exact mop_b destinations after realization.
                projected.append(serial + 1)
                if taken_target is not None:
                    projected.append(taken_target)
            elif opcode not in {
                int(ida_hexrays.m_ijmp),
                int(ida_hexrays.m_jtbl),
                int(ida_hexrays.m_ret),
            }:
                projected.append(serial + 1)
        normalized = tuple(
            dict.fromkeys(target for target in projected if 0 <= int(target) < quantity)
        )
        successors[serial] = normalized
        kinds[serial] = {
            0: BlockKind.ZERO_WAY,
            1: BlockKind.ONE_WAY,
            2: BlockKind.TWO_WAY,
        }.get(len(normalized), BlockKind.N_WAY)
    predecessor_lists: dict[int, list[int]] = {serial: [] for serial in range(quantity)}
    for source, targets in successors.items():
        for target in targets:
            predecessor_lists[target].append(source)
    predecessors = {
        serial: tuple(values) for serial, values in predecessor_lists.items()
    }
    return predecessors, successors, kinds


def generated_plan_live_bindings(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
) -> dict[str, object]:
    """Bind graph-free corridor roles from native anchors plus physical order."""
    gateway = modifier._mutation_gateway
    if gateway is None:
        raise SemanticFragmentBackendRejected(
            "GENERATED binding requires a mutation gateway"
        )
    live_by_id: dict[str, object] = {}
    for root_id in plan.roots:
        replacement = plan.block(root_id)
        original_id = str(replacement.replaces_block_id)
        original = plan.block(original_id)
        rebound = gateway.identity_index.rebind_native_ea(
            int(original.semantic_anchor_ea)
        )
        if rebound.block is None:
            raise SemanticFragmentBackendRejected(
                f"GENERATED source {original_id!r} does not bind uniquely"
            )
        live = modifier.mba.get_mblock(int(rebound.block.serial))
        if live is None:
            raise SemanticFragmentBackendRejected(
                f"GENERATED source {original_id!r} is absent"
            )
        live_by_id[original_id] = live
    for operation in plan.operations:
        normalization = operation.computed_branch_normalization
        envelope = (
            None if normalization is None else normalization.conditional_select_envelope
        )
        if not isinstance(envelope, FragmentConditionalSelectEnvelope):
            continue
        source_plan = plan.block(operation.source_block_id)
        source = live_by_id.get(str(source_plan.replaces_block_id))
        selected = None if source is None else source.nextb
        join = None if selected is None else selected.nextb
        if selected is None or join is None:
            raise SemanticFragmentBackendRejected(
                "GENERATED conditional-select corridor lost physical adjacency"
            )
        if int(envelope.predicate_ea) not in _instruction_eas(selected) or int(
            normalization.unresolved_transfer_ea
        ) not in _instruction_eas(join):
            raise SemanticFragmentBackendRejected(
                "GENERATED conditional-select physical roles changed"
            )
        live_by_id[envelope.selected_value_block_id] = selected
        live_by_id[envelope.join_block_id] = join
    for planned in plan.blocks:
        if (
            planned.materialization is not FragmentBlockMaterialization.REUSE_PUBLISHED
            or planned.block_id in live_by_id
        ):
            continue
        rebound = gateway.identity_index.rebind_native_ea(
            int(planned.semantic_anchor_ea)
        )
        if rebound.block is None:
            raise SemanticFragmentBackendRejected(
                f"GENERATED block {planned.block_id!r} does not bind uniquely"
            )
        live = modifier.mba.get_mblock(int(rebound.block.serial))
        if live is None:
            raise SemanticFragmentBackendRejected(
                f"GENERATED block {planned.block_id!r} is absent"
            )
        live_by_id[planned.block_id] = live
    serials = tuple(int(block.serial) for block in live_by_id.values())
    if len(set(serials)) != len(serials):
        raise SemanticFragmentBackendRejected(
            "GENERATED plan roles alias one physical block"
        )
    return live_by_id


def plan_semantic_fragment_root_inventory(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
) -> SemanticFragmentRootInventory:
    """Inspect all incoming root roles without retaining live coordinates."""
    gateway = modifier._mutation_gateway
    if gateway is None or gateway.active:
        raise SemanticFragmentBackendRejected(
            "root inventory requires an idle mutation gateway"
        )
    generated_live_by_id = (
        generated_plan_live_bindings(modifier, plan)
        if _generated_graph_free(modifier)
        else None
    )
    live_by_id = {}
    ids_by_serial: dict[int, str] = {}
    for block in plan.blocks:
        if block.materialization is not FragmentBlockMaterialization.REUSE_PUBLISHED:
            continue
        if block.stable_identity is None:
            continue
        rebound = (
            gateway.identity_index.rebind_identity(block.stable_identity)
            if generated_live_by_id is None
            else None
        )
        if generated_live_by_id is None and rebound.block is None:
            raise SemanticFragmentBackendRejected(
                f"root inventory block {block.block_id!r} does not rebind uniquely"
            )
        live = (
            modifier.mba.get_mblock(int(rebound.block.serial))
            if generated_live_by_id is None
            else generated_live_by_id.get(block.block_id)
        )
        if live is None:
            raise SemanticFragmentBackendRejected(
                f"root inventory block {block.block_id!r} is absent from the MBA"
            )
        if int(live.serial) in ids_by_serial:
            existing_block_id = ids_by_serial[int(live.serial)]
            existing_block = plan.block(existing_block_id)
            physical_label = f"blk{int(live.serial)}@0x{int(live.start):X}"
            raise SemanticFragmentBackendRejected(
                f"root inventory blocks {existing_block_id!r} and "
                f"{block.block_id!r} map to {physical_label}",
                reason_code="root_inventory_physical_version_alias",
                anchor_ea=int(live.start),
                payload={
                    "atomic_group_id": plan.atomic_group_id,
                    "colliding_anchor_ea": (f"0x{int(block.semantic_anchor_ea):X}"),
                    "colliding_block_id": block.block_id,
                    "colliding_identity": block.stable_identity.to_dict(),
                    "existing_anchor_ea": (
                        f"0x{int(existing_block.semantic_anchor_ea):X}"
                    ),
                    "existing_block_id": existing_block_id,
                    "existing_identity": (existing_block.stable_identity.to_dict()),
                    "physical_block": physical_label,
                    "plan_id": plan.plan_id,
                },
            )
        live_by_id[block.block_id] = live
        ids_by_serial[int(live.serial)] = block.block_id

    generated_predecessors = None
    if _generated_graph_free(modifier):
        generated_predecessors, generated_successors, _generated_kinds = (
            _generated_structural_serial_topology(modifier)
        )

    items: list[SemanticFragmentRootInventoryItem] = []
    for root_block_id in plan.roots:
        original_block_id = str(plan.block(root_block_id).replaces_block_id)
        original = live_by_id.get(original_block_id)
        if original is None:
            raise SemanticFragmentBackendRejected(
                f"root inventory lacks original {original_block_id!r}"
            )
        predecessor_serials = (
            tuple(int(value) for value in original.predset)
            if generated_predecessors is None
            else generated_predecessors[int(original.serial)]
        )
        if not predecessor_serials:
            raise SemanticFragmentBackendRejected(
                f"root inventory original {original_block_id!r} has no predecessors"
            )
        for predecessor_serial in predecessor_serials:
            predecessor_block_id = ids_by_serial.get(predecessor_serial)
            predecessor = modifier.mba.get_mblock(predecessor_serial)
            if predecessor_block_id is None or predecessor is None:
                raise SemanticFragmentBackendRejected(
                    "root inventory predecessor is outside the closed fragment plan"
                )
            if generated_predecessors is None:
                role = _incoming_root_edge_role(predecessor, original)
                requires_helper = _root_edge_requires_helper(
                    predecessor,
                    original,
                    role,
                )
            else:
                if generated_successors[predecessor_serial] != (int(original.serial),):
                    raise SemanticFragmentBackendRejected(
                        "GENERATED root predecessor is not an exact direct edge"
                    )
                tail = predecessor.tail
                if (
                    tail is None
                    or int(tail.opcode) != int(ida_hexrays.m_goto)
                    or (
                        (
                            int(tail.l.t) == int(ida_hexrays.mop_b)
                            and int(tail.l.b) != int(original.serial)
                        )
                        or (
                            int(tail.l.t) == int(ida_hexrays.mop_v)
                            and int(tail.l.g)
                            != int(plan.block(original_block_id).semantic_anchor_ea)
                        )
                        or int(tail.l.t)
                        not in {
                            int(ida_hexrays.mop_b),
                            int(ida_hexrays.mop_v),
                        }
                    )
                ):
                    raise SemanticFragmentBackendRejected(
                        "GENERATED root authority requires an explicit goto"
                    )
                role = SemanticEdgeRole.DIRECT
                requires_helper = False
            items.append(
                SemanticFragmentRootInventoryItem(
                    edge_id=(f"{root_block_id}:{predecessor_block_id}:{role.value}"),
                    root_block_id=root_block_id,
                    original_block_id=original_block_id,
                    predecessor_block_id=predecessor_block_id,
                    role=role,
                    requires_helper=requires_helper,
                )
            )
    return SemanticFragmentRootInventory(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
        items=tuple(items),
    )


def snapshot_semantic_fragment_inputs(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
) -> SemanticFragmentSnapshotPreparation:
    """Capture immutable projection authority before opening a live batch."""
    gateway = modifier._mutation_gateway
    if gateway is None:
        raise SemanticFragmentBackendRejected(
            "semantic fragment snapshot requires a mutation gateway"
        )
    if gateway.active or modifier._semantic_fragment_state is not None:
        raise SemanticFragmentBackendRejected(
            "semantic fragment snapshots require an idle mutation gateway"
        )

    _preflight_generated_operation_vocabulary(plan)

    try:
        preparations = _prepare_native_bodies(modifier, plan)
    except SemanticFragmentBackendRejected as exc:
        if plan.return_carriers:
            postcondition = FragmentValidationPostcondition.RETURN_CARRIER_INTEGRITY
            subject_id = plan.return_carriers[0].carrier_id
        elif plan.terminal_returns:
            postcondition = FragmentValidationPostcondition.TERMINAL_RETURN_INTEGRITY
            subject_id = plan.terminal_returns[0].return_id
        else:
            postcondition = FragmentValidationPostcondition.GRAPH_CLOSURE
            subject_id = "native-body-preparation"
        raise FragmentProjectionFailure(
            postcondition,
            subject_id,
            str(exc),
        ) from exc

    carrier_constructions: list[PreparedReturnCarrierConstruction] = []
    carrier_payloads: list[tuple[str, object]] = []
    for carrier in plan.return_carriers:
        try:
            operand = _return_source_operand(
                modifier.mba,
                carrier.source,
                live_ea=carrier.carrier_ea,
            )
            return_mreg = _return_mreg()
        except SemanticFragmentBackendRejected as exc:
            raise FragmentProjectionFailure(
                FragmentValidationPostcondition.RETURN_CARRIER_INTEGRITY,
                carrier.carrier_id,
                str(exc),
            ) from exc
        carrier_constructions.append(
            PreparedReturnCarrierConstruction(
                carrier_id=carrier.carrier_id,
                source=carrier.source,
                return_width=carrier.return_width,
                return_mreg=return_mreg,
                operand_shape=_prepared_operand_shape(operand, carrier.source),
            )
        )
        carrier_payloads.append((carrier.carrier_id, operand))

    generated_live_by_id = (
        generated_plan_live_bindings(modifier, plan)
        if _generated_graph_free(modifier)
        else None
    )
    live_by_id: dict[str, object] = {}
    binding_by_id: dict[str, ProjectedIdentityBinding] = {}
    ids_by_serial: dict[int, str] = {}
    for planned in plan.blocks:
        if planned.materialization is not FragmentBlockMaterialization.REUSE_PUBLISHED:
            continue
        rebound = (
            gateway.identity_index.rebind_identity(planned.stable_identity)
            if generated_live_by_id is None
            else None
        )
        if generated_live_by_id is None and rebound.block is None:
            raise FragmentProjectionFailure(
                FragmentValidationPostcondition.IDENTITY_OWNERSHIP,
                planned.block_id,
                f"snapshot block {planned.block_id!r} does not rebind uniquely",
            )
        live = (
            modifier.mba.get_mblock(int(rebound.block.serial))
            if generated_live_by_id is None
            else generated_live_by_id.get(planned.block_id)
        )
        if live is None:
            raise FragmentProjectionFailure(
                FragmentValidationPostcondition.IDENTITY_OWNERSHIP,
                planned.block_id,
                f"snapshot block {planned.block_id!r} is absent from the MBA",
            )
        serial = int(live.serial)
        if serial in ids_by_serial:
            anchor = int(live.start)
            raise FragmentProjectionFailure(
                FragmentValidationPostcondition.IDENTITY_OWNERSHIP,
                planned.block_id,
                f"snapshot blocks {ids_by_serial[serial]!r} and "
                f"{planned.block_id!r} alias blk{serial}@0x{anchor:X}",
            )
        live_handle = gateway.identity_index.handle_for_serial(serial)
        proxy = gateway.identity_index.logical_proxy_for_handle(live_handle)
        version = None if proxy is None else proxy.resolve()
        if proxy is None or version is None:
            raise FragmentProjectionFailure(
                FragmentValidationPostcondition.IDENTITY_OWNERSHIP,
                planned.block_id,
                f"snapshot block {planned.block_id!r} lacks published authority",
            )
        physical_identity = version.handle.stable_identity
        if generated_live_by_id is None and (
            planned.stable_identity is None
            or physical_identity is None
            or not stable_block_identity_covers(
                physical_identity,
                planned.stable_identity,
            )
        ):
            raise FragmentProjectionFailure(
                FragmentValidationPostcondition.IDENTITY_OWNERSHIP,
                planned.block_id,
                f"physical identity for {planned.block_id!r} does not cover "
                "plan identity",
            )
        live_by_id[planned.block_id] = live
        ids_by_serial[serial] = planned.block_id
        binding_by_id[planned.block_id] = ProjectedIdentityBinding(
            block_id=planned.block_id,
            logical_owner_id=proxy.proxy_token,
            version=version.version_id.version,
            generation=version.generation,
            state=FragmentBindingState.PUBLISHED,
            stable_identity=planned.stable_identity,
            previous_version=(
                None
                if version.predecessor_version_id is None
                else version.predecessor_version_id.version
            ),
        )

    for serial in range(int(modifier.mba.qty)):
        if serial in ids_by_serial:
            continue
        handle = gateway.identity_index.handle_for_serial(serial)
        live = modifier.mba.get_mblock(serial)
        proxy = (
            None
            if handle is None
            else gateway.identity_index.logical_proxy_for_handle(handle)
        )
        version = None if proxy is None else proxy.resolve()
        if live is None or proxy is None or version is None:
            raise FragmentProjectionFailure(
                FragmentValidationPostcondition.IDENTITY_OWNERSHIP,
                f"function-block:{serial}",
                "full CFG snapshot block lacks published authority",
            )
        block_id = f"function-block:{proxy.proxy_token}"
        if block_id in live_by_id:
            raise FragmentProjectionFailure(
                FragmentValidationPostcondition.IDENTITY_OWNERSHIP,
                block_id,
                "full CFG snapshot block id collides with plan authority",
            )
        live_by_id[block_id] = live
        ids_by_serial[serial] = block_id
        binding_by_id[block_id] = ProjectedIdentityBinding(
            block_id=block_id,
            logical_owner_id=proxy.proxy_token,
            version=version.version_id.version,
            generation=version.generation,
            state=FragmentBindingState.PUBLISHED,
            stable_identity=version.handle.stable_identity,
            previous_version=(
                None
                if version.predecessor_version_id is None
                else version.predecessor_version_id.version
            ),
        )

    if 0 not in ids_by_serial:
        raise FragmentProjectionFailure(
            FragmentValidationPostcondition.IDENTITY_OWNERSHIP,
            "function-entry",
            "snapshot function entry lacks published authority",
        )
    entry_block_id = ids_by_serial[0]
    try:
        constant_materializations = _prepare_constant_materializations(
            plan,
            live_by_id,
            tuple(preparation.fact for _body_id, preparation in preparations),
        )
    except SemanticFragmentBackendRejected as exc:
        materialization_id = str(
            exc.payload.get("materialization_id")
            or (
                plan.constant_materializations[0].materialization_id
                if plan.constant_materializations
                else "constant-materialization"
            )
        )
        raise FragmentProjectionFailure(
            FragmentValidationPostcondition.USE_DEF_INTEGRITY,
            materialization_id,
            str(exc),
        ) from exc

    generated_topology = (
        _generated_structural_serial_topology(modifier)
        if _generated_graph_free(modifier)
        else None
    )
    blocks: list[FragmentProjectionBlockInput] = []
    for block_id, live in live_by_id.items():
        writes = frozenset()
        if plan.flag_corridors:
            try:
                writes = frozenset(int(ea) for ea in condition_code_write_eas(live))
            except ConditionCodeQueryUnavailable as exc:
                raise FragmentProjectionFailure(
                    FragmentValidationPostcondition.FLAG_CORRIDOR_INTEGRITY,
                    plan.flag_corridors[0].corridor_id,
                    f"condition-code writes cannot be snapshotted for {block_id}",
                ) from exc
        kind = (
            _block_kind(int(live.type))
            if generated_topology is None
            else generated_topology[2][int(live.serial)]
        )
        raw_successors = (
            tuple(int(serial) for serial in live.succset)
            if generated_topology is None
            else generated_topology[1][int(live.serial)]
        )
        if kind is BlockKind.ZERO_WAY:
            successors: tuple[str, ...] = ()
            if raw_successors:
                stop = (
                    modifier.mba.get_mblock(raw_successors[0])
                    if len(raw_successors) == 1
                    else None
                )
                if (
                    stop is None
                    or int(stop.type) != int(ida_hexrays.BLT_STOP)
                    or int(stop.serial) != int(modifier.mba.qty) - 1
                ):
                    raise FragmentProjectionFailure(
                        FragmentValidationPostcondition.GRAPH_CLOSURE,
                        block_id,
                        f"zero-way successor bookkeeping is malformed for {block_id!r}",
                    )
        else:
            successors = tuple(ids_by_serial[int(serial)] for serial in raw_successors)
        next_block = getattr(live, "nextb", None)
        instruction_eas = _instruction_eas(live, None)
        terminator_ea, terminator_kind = _projected_terminator(live, None)
        blocks.append(
            FragmentProjectionBlockInput(
                block_id=block_id,
                kind=kind,
                successors=successors,
                predecessors=tuple(
                    ids_by_serial[int(serial)]
                    for serial in (
                        live.predset
                        if generated_topology is None
                        else generated_topology[0][int(live.serial)]
                    )
                ),
                physical_position=int(live.serial),
                adjacent_fallthrough_target_id=(
                    None
                    if kind is not BlockKind.TWO_WAY or next_block is None
                    else ids_by_serial[int(next_block.serial)]
                ),
                terminator_ea=terminator_ea,
                terminator_kind=terminator_kind,
                instruction_eas=instruction_eas,
                flag_write_eas=writes,
            )
        )

    preparation_by_body_id = dict(preparations)
    prepared_instruction_rows_by_block: dict[
        str,
        tuple[tuple[int, object], ...],
    ] = {}
    next_position = (
        max(
            (block.physical_position for block in blocks),
            default=-1,
        )
        + 1
    )
    for planned in plan.blocks:
        if planned.materialization is not FragmentBlockMaterialization.IMPORT_NATIVE:
            continue
        preparation = preparation_by_body_id.get(str(planned.native_body_id))
        if preparation is None:
            raise FragmentProjectionFailure(
                FragmentValidationPostcondition.GRAPH_CLOSURE,
                planned.block_id,
                "imported block lacks immutable native-body preparation",
            )
        fact = preparation.fact.block(planned.block_id)
        fact_block_ids = tuple(block.block_id for block in preparation.fact.blocks)
        fact_index = fact_block_ids.index(planned.block_id)
        next_fact_block_id = (
            None
            if fact_index + 1 >= len(fact_block_ids)
            else fact_block_ids[fact_index + 1]
        )
        adjacent_fallthrough_target_id = (
            fact.successors[0].target_block_id
            if fact.kind is BlockKind.TWO_WAY
            and fact.successors
            and fact.successors[0].target_block_id == next_fact_block_id
            else None
        )
        payload_rows = {
            block_id: (block_flags, instruction_rows)
            for block_id, block_flags, instruction_rows in preparation.payload.rows
        }
        _block_flags, instruction_rows = payload_rows[planned.block_id]
        instruction_rows = tuple(instruction_rows)
        prepared_instruction_rows_by_block[planned.block_id] = instruction_rows
        instruction_eas = tuple(
            dict.fromkeys(
                int(native_ea) for native_ea, _instruction in instruction_rows
            )
        )
        if fact.terminator_ea is not None:
            if (
                fact.terminator_kind is InsnKind.CALL
                and fact.terminator_ea in instruction_eas
            ):
                instruction_eas = instruction_eas[
                    : instruction_eas.index(fact.terminator_ea) + 1
                ]
            elif not instruction_eas or instruction_eas[-1] != fact.terminator_ea:
                instruction_eas = (*instruction_eas, fact.terminator_ea)
        blocks.append(
            FragmentProjectionBlockInput(
                block_id=planned.block_id,
                kind=fact.kind,
                successors=tuple(edge.target_block_id for edge in fact.successors),
                predecessors=fact.predecessor_block_ids,
                physical_position=next_position,
                adjacent_fallthrough_target_id=(adjacent_fallthrough_target_id),
                terminator_ea=fact.terminator_ea,
                terminator_kind=fact.terminator_kind,
                instruction_eas=instruction_eas,
                flag_write_eas=(
                    frozenset(
                        instruction.native_ea
                        for instruction in fact.instructions
                        if instruction.writes_condition_codes is True
                    )
                    if plan.flag_corridors
                    else frozenset()
                ),
            )
        )
        next_position += 1

    clone_source_instructions: list[FragmentCloneSourceInstructions] = []
    for planned in plan.blocks:
        if planned.materialization is not FragmentBlockMaterialization.CLONE_PUBLISHED:
            continue
        source_block_id = str(planned.replaces_block_id)
        source = live_by_id.get(source_block_id)
        if source is None:
            raise FragmentProjectionFailure(
                FragmentValidationPostcondition.IDENTITY_OWNERSHIP,
                planned.block_id,
                "clone-source instruction evidence lacks its published source",
            )
        source_rows = tuple(
            (
                int(getattr(instruction, "ea", -1) or -1),
                instruction,
            )
            for instruction in _iter_block_instructions(source)
        )
        prepared_instruction_rows_by_block[planned.block_id] = source_rows
        clone_source_instructions.append(
            FragmentCloneSourceInstructions(
                block_id=planned.block_id,
                source_block_id=source_block_id,
                instructions=tuple(
                    FragmentCloneSourceInstruction(
                        native_ea=native_ea,
                        opcode=int(getattr(instruction, "opcode", -1)),
                        kind=sdk_instruction_kind(
                            int(getattr(instruction, "opcode", -1))
                        ),
                        destination_is_discardable=(
                            int(getattr(getattr(instruction, "d", None), "t", -1))
                            in {
                                int(ida_hexrays.mop_z),
                                int(ida_hexrays.mop_r),
                            }
                        ),
                        operand_shape=sdk_instruction_operand_shape(instruction),
                    )
                    for native_ea, instruction in source_rows
                ),
            )
        )

    analysis_live_by_id = dict(live_by_id)
    analysis_ids_by_serial = dict(ids_by_serial)
    for planned in plan.blocks:
        if planned.role is not FragmentBlockRole.REPLACEMENT:
            continue
        original_id = str(planned.replaces_block_id)
        original_live = live_by_id.get(original_id)
        if original_live is not None:
            analysis_live_by_id[planned.block_id] = original_live
            analysis_ids_by_serial[int(original_live.serial)] = planned.block_id
    analysis_state = SemanticFragmentBackendState(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
    )
    live_flag_corridors = tuple(
        corridor
        for corridor in plan.flag_corridors
        if corridor.producer.block_id in analysis_live_by_id
        and corridor.consumer.block_id in analysis_live_by_id
    )
    if live_flag_corridors:
        try:
            _require_flag_corridor_sites(
                analysis_state,
                replace(plan, flag_corridors=live_flag_corridors),
                analysis_live_by_id,
            )
        except SemanticFragmentBackendRejected as exc:
            raise FragmentProjectionFailure(
                FragmentValidationPostcondition.FLAG_CORRIDOR_INTEGRITY,
                live_flag_corridors[0].corridor_id,
                str(exc),
            ) from exc

    predecessor_serials = {
        int(live.serial): (
            tuple(int(value) for value in live.predset)
            if generated_topology is None
            else generated_topology[0][int(live.serial)]
        )
        for live in analysis_live_by_id.values()
    }
    successor_serials = {
        int(live.serial): (
            tuple(int(value) for value in live.succset)
            if generated_topology is None
            else generated_topology[1][int(live.serial)]
        )
        for live in analysis_live_by_id.values()
    }
    try:
        data_flow = _project_data_flow_relations(
            modifier,
            plan,
            analysis_state,
            analysis_live_by_id,
            analysis_ids_by_serial,
            predecessor_serials,
            successor_serials,
            defer_materialized_predicate_uses=True,
            prepared_instruction_rows_by_block_id={
                block_id: instruction_rows
                for block_id, instruction_rows in (
                    prepared_instruction_rows_by_block.items()
                )
                if plan.block(block_id).materialization
                is FragmentBlockMaterialization.IMPORT_NATIVE
            },
        )
    except SemanticFragmentBackendRejected as exc:
        subject_id = str(
            exc.payload.get("obligation_id")
            or (
                plan.data_flow_obligations[0].obligation_id
                if plan.data_flow_obligations
                else "data-flow-evidence"
            )
        )
        raise FragmentProjectionFailure(
            FragmentValidationPostcondition.USE_DEF_INTEGRITY,
            subject_id,
            str(exc),
        ) from exc
    try:
        ranges = _project_value_ranges(
            analysis_state,
            plan,
            analysis_live_by_id,
        )
    except SemanticFragmentBackendRejected as exc:
        subject_id = (
            plan.value_range_assumptions[0].assumption_id
            if plan.value_range_assumptions
            else "value-range-evidence"
        )
        raise FragmentProjectionFailure(
            FragmentValidationPostcondition.VALUE_RANGE_PROVEN,
            subject_id,
            str(exc),
        ) from exc

    verified_carriers: list[FragmentReturnCarrier] = []
    terminal_diagnostics: list[ProjectedTerminalEffectDiagnostic] = []
    for carrier in plan.return_carriers:
        rows = prepared_instruction_rows_by_block.get(carrier.block_id, ())
        state_rows = prepared_instruction_rows_by_block.get(
            carrier.state_write_block_id,
            (),
        )
        state_matches = tuple(
            index
            for index, (ea, _instruction) in enumerate(state_rows)
            if int(ea) == carrier.state_write_ea
        )
        carrier_matches = tuple(
            (index, instruction)
            for index, (ea, instruction) in enumerate(rows)
            if int(ea) == carrier.carrier_ea
        )
        block_identity = plan.block(carrier.block_id).stable_identity
        can_insert = bool(
            len(state_matches) == 1
            and not carrier_matches
            and block_identity is not None
            and carrier.carrier_ea in block_identity.exact_instruction_eas
        )
        existing_matches = bool(
            len(state_matches) == 1
            and len(carrier_matches) == 1
            and (
                carrier.state_write_block_id != carrier.block_id
                or state_matches[0] < carrier_matches[0][0]
            )
            and value_op_from_opcode(int(carrier_matches[0][1].opcode))
            is carrier.operation
        )
        if can_insert or existing_matches:
            verified_carriers.append(carrier)
        else:
            terminal_diagnostics.append(
                ProjectedTerminalEffectDiagnostic(
                    effect_id=carrier.carrier_id,
                    reason=(
                        "prepared carrier anchors or operation do not fit atomically"
                    ),
                )
            )

    verified_returns: list[FragmentTerminalReturn] = []
    closing_opcodes = {
        int(ida_hexrays.m_ijmp),
        int(ida_hexrays.m_jtbl),
        int(ida_hexrays.m_call),
        int(ida_hexrays.m_icall),
        int(ida_hexrays.m_ret),
    }
    for terminal in plan.terminal_returns:
        rows = prepared_instruction_rows_by_block.get(terminal.block_id, ())
        matches = tuple(
            (index, instruction)
            for index, (ea, instruction) in enumerate(rows)
            if int(ea) == terminal.instruction_ea
        )
        block_identity = plan.block(terminal.block_id).stable_identity
        tail_opcode = None if not rows else int(rows[-1][1].opcode)
        can_insert = bool(
            not matches
            and block_identity is not None
            and terminal.instruction_ea in block_identity.exact_instruction_eas
            and (
                tail_opcode is None
                or (
                    not ida_hexrays.is_mcode_jcond(tail_opcode)
                    and tail_opcode not in closing_opcodes
                    and tail_opcode != int(ida_hexrays.m_goto)
                )
            )
        )
        rewritable_tail = bool(
            len(matches) == 1
            and matches[0][0] == len(rows) - 1
            and int(matches[0][1].opcode) == int(ida_hexrays.m_goto)
        )
        existing_return = bool(
            len(matches) == 1
            and matches[0][0] == len(rows) - 1
            and int(matches[0][1].opcode) == int(ida_hexrays.m_ret)
        )
        if can_insert or rewritable_tail or existing_return:
            verified_returns.append(terminal)
        else:
            terminal_diagnostics.append(
                ProjectedTerminalEffectDiagnostic(
                    effect_id=terminal.return_id,
                    reason=("prepared terminal return opcode or placement is invalid"),
                )
            )

    projection_input = FragmentProjectionInput(
        snapshot_id=(
            f"semantic-fragment:{gateway.session_id}:"
            f"{gateway.generation}:{plan.plan_id}"
        ),
        entry_block_id=entry_block_id,
        blocks=tuple(blocks),
        identity_bindings=tuple(binding_by_id.values()),
        data_flow_relations=data_flow,
        value_ranges=ranges,
        return_carriers=tuple(verified_carriers),
        terminal_returns=tuple(verified_returns),
        terminal_effect_diagnostics=tuple(terminal_diagnostics),
        clone_source_instructions=tuple(clone_source_instructions),
    )
    return SemanticFragmentSnapshotPreparation(
        authority=SemanticFragmentSnapshotAuthority(
            plan_id=plan.plan_id,
            atomic_group_id=plan.atomic_group_id,
            session_id=gateway.session_id,
            generation=gateway.generation,
            projection_input=projection_input,
            native_bodies=tuple(
                preparation.fact for _body_id, preparation in preparations
            ),
            constant_materializations=constant_materializations,
            return_carrier_constructions=tuple(carrier_constructions),
        ),
        payload=SemanticFragmentRealizationPayload(
            native_body_rows=tuple(
                (preparation.fact.body_id, preparation.payload.rows)
                for _body_id, preparation in preparations
            ),
            return_carrier_operands=tuple(carrier_payloads),
        ),
    )


def _reserve_root_fallthrough_helpers(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    root_steps: tuple[object, ...],
) -> None:
    from d810.transforms.plan import PatchFragmentRootPublication

    gateway = _gateway(modifier)
    for step in root_steps:
        if not isinstance(step, PatchFragmentRootPublication):
            raise SemanticFragmentBackendRejected(
                "root helper reservation requires typed PatchSteps"
            )
        helper_block_id = step.fallthrough_helper_id
        if helper_block_id is None:
            continue
        if step.fallthrough_helper_ref is None or step.predecessor_ref is None:
            raise SemanticFragmentBackendRejected(
                "root helper PatchStep lacks typed authority"
            )
        predecessor_block_id = step.predecessor_ref.local_block_id
        root_block_id = step.root_ref.local_block_id
        if helper_block_id in state.bindings:
            raise SemanticFragmentBackendRejected(
                f"root fallthrough helper id collision: {helper_block_id!r}"
            )
        attempt = gateway.current_transaction_attempt
        if attempt is None:
            raise SemanticFragmentBackendRejected(
                "root helper reservation has no transaction attempt"
            )
        reservation = gateway.reserve_plan_block(
            attempt,
            step.fallthrough_helper_ref,
        )
        staged = reservation.logical_version
        handle = staged.handle
        proxy = gateway.identity_index.logical_proxy_for_handle(handle)
        if proxy is None:
            raise SemanticFragmentBackendRejected(
                "reserved root fallthrough helper has no logical proxy"
            )
        state.bindings[helper_block_id] = SemanticFragmentRuntimeBinding(
            block_id=helper_block_id,
            proxy=proxy,
            version=staged,
            state=FragmentBindingState.STAGED,
            creation_ref=step.fallthrough_helper_ref,
        )
        state.root_fallthrough_helpers.append(
            ProjectedRootFallthroughHelper(
                helper_block_id=helper_block_id,
                source_block_id=predecessor_block_id,
                root_block_id=root_block_id,
            )
        )


def _group_semantic_fragment_root_edges(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    edges: tuple[SemanticFragmentRootEdgeBinding, ...],
) -> tuple[SemanticFragmentRootPublicationGroup, ...]:
    """Capture complete predecessor authority before any root is published."""
    edges_by_predecessor: dict[str, list[SemanticFragmentRootEdgeBinding]] = {}
    for edge in edges:
        edges_by_predecessor.setdefault(edge.predecessor.block_id, []).append(edge)

    groups: list[SemanticFragmentRootPublicationGroup] = []
    for predecessor_block_id, grouped_edges in edges_by_predecessor.items():
        predecessor_binding = grouped_edges[0].predecessor
        if any(
            edge.predecessor.version is not predecessor_binding.version
            for edge in grouped_edges
        ):
            raise SemanticFragmentBackendRejected(
                "root publication group has inconsistent predecessor authority"
            )
        if any(
            edge.requires_helper != (edge.publication_helper is not None)
            for edge in grouped_edges
        ):
            raise SemanticFragmentBackendRejected(
                "root publication helper authority differs from its inventory"
            )
        predecessor = _live_block_for_binding(modifier, predecessor_binding)
        roles = frozenset(edge.role for edge in grouped_edges)
        conditional_roles = {
            SemanticEdgeRole.CONDITIONAL_TAKEN,
            SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
        }
        if roles == {SemanticEdgeRole.CALL_FALLTHROUGH}:
            if len(grouped_edges) != 1:
                raise SemanticFragmentBackendRejected(
                    "call root publication group contains multiple edges"
                )
            tail = predecessor.tail
            successors = tuple(int(value) for value in predecessor.succset)
            if (
                int(predecessor.nsucc()) != 1
                or tail is None
                or int(tail.opcode)
                not in {
                    int(ida_hexrays.m_call),
                    int(ida_hexrays.m_icall),
                }
                or predecessor.nextb is None
                or tuple(successors) != (int(predecessor.nextb.serial),)
            ):
                raise SemanticFragmentBackendRejected(
                    "call root publication group lost its physical fallthrough"
                )
            original_fallthrough = _binding_for_live_serial(
                modifier,
                state,
                successors[0],
            )
            if grouped_edges[0].original.version is not original_fallthrough.version:
                raise SemanticFragmentBackendRejected(
                    "call root edge does not match its captured fallthrough"
                )
            groups.append(
                SemanticFragmentRootPublicationGroup(
                    group_id=semantic_fragment_root_group_id(predecessor_block_id),
                    predecessor=predecessor_binding,
                    edges=tuple(grouped_edges),
                    original_predecessor_type=int(predecessor.type),
                    original_predecessor_flags=int(predecessor.flags),
                    original_call_opcode=int(tail.opcode),
                    original_fallthrough=original_fallthrough,
                )
            )
            continue
        if roles == {SemanticEdgeRole.DIRECT}:
            if len(grouped_edges) != 1:
                raise SemanticFragmentBackendRejected(
                    "direct root publication group contains multiple edges"
                )
            groups.append(
                SemanticFragmentRootPublicationGroup(
                    group_id=semantic_fragment_root_group_id(predecessor_block_id),
                    predecessor=predecessor_binding,
                    edges=tuple(grouped_edges),
                    original_predecessor_type=int(predecessor.type),
                    original_predecessor_flags=int(predecessor.flags),
                )
            )
            continue
        if (
            not roles.issubset(conditional_roles)
            or len(grouped_edges) > 2
            or len(roles) != len(grouped_edges)
        ):
            raise SemanticFragmentBackendRejected(
                "conditional root publication group must contain at most one "
                "taken edge and one fallthrough edge"
            )
        tail = predecessor.tail
        successors = tuple(int(value) for value in predecessor.succset)
        if (
            int(predecessor.nsucc()) != 2
            or tail is None
            or not ida_hexrays.is_mcode_jcond(int(tail.opcode))
            or getattr(tail, "d", None) is None
            or int(tail.d.t) != int(ida_hexrays.mop_b)
        ):
            raise SemanticFragmentBackendRejected(
                "conditional root publication group lost its original predicate"
            )
        taken_serial = int(tail.d.b)
        fallthrough_serials = tuple(
            successor for successor in successors if successor != taken_serial
        )
        if taken_serial not in successors or len(fallthrough_serials) != 1:
            raise SemanticFragmentBackendRejected(
                "conditional root publication group has inconsistent arms"
            )
        fallthrough_serial = int(fallthrough_serials[0])
        if (
            predecessor.nextb is None
            or int(predecessor.nextb.serial) != fallthrough_serial
        ):
            raise SemanticFragmentBackendRejected(
                "conditional root publication group lacks physical fallthrough"
            )
        original_taken = _binding_for_live_serial(
            modifier,
            state,
            taken_serial,
        )
        original_fallthrough = _binding_for_live_serial(
            modifier,
            state,
            fallthrough_serial,
        )
        for edge in grouped_edges:
            expected_original = (
                original_taken
                if edge.role is SemanticEdgeRole.CONDITIONAL_TAKEN
                else original_fallthrough
            )
            if edge.original.version is not expected_original.version:
                raise SemanticFragmentBackendRejected(
                    "conditional root edge does not match its captured arm"
                )
        groups.append(
            SemanticFragmentRootPublicationGroup(
                group_id=semantic_fragment_root_group_id(predecessor_block_id),
                predecessor=predecessor_binding,
                edges=tuple(grouped_edges),
                original_predecessor_type=int(predecessor.type),
                original_predecessor_flags=int(predecessor.flags),
                original_conditional_opcode=int(tail.opcode),
                original_taken=original_taken,
                original_fallthrough=original_fallthrough,
            )
        )
    return tuple(groups)


def prepare_semantic_fragment_root_publication(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    inventory: SemanticFragmentRootInventory,
) -> SemanticFragmentRootPublicationToken:
    """Capture every incoming root edge before exposing any staged version."""
    state = modifier._semantic_fragment_state
    if state is None:
        raise SemanticFragmentBackendRejected("semantic fragment is not staged")
    if state.plan_id != plan.plan_id or state.atomic_group_id != plan.atomic_group_id:
        raise SemanticFragmentBackendRejected(
            "staged semantic fragment does not match root publication request"
        )
    if (
        inventory.plan_id != plan.plan_id
        or inventory.atomic_group_id != plan.atomic_group_id
    ):
        raise SemanticFragmentBackendRejected(
            "root inventory does not match the staged fragment"
        )

    edges: list[SemanticFragmentRootEdgeBinding] = []
    for root_block_id in plan.roots:
        replacement = state.binding(root_block_id)
        original_block_id = str(plan.block(root_block_id).replaces_block_id)
        original = state.binding(original_block_id)
        original_live = _live_block_for_binding(modifier, original)
        replacement_live = _live_block_for_binding(modifier, replacement)
        replacement_predecessors = tuple(
            _binding_for_live_serial(
                modifier,
                state,
                int(predecessor_serial),
            )
            for predecessor_serial in replacement_live.predset
        )
        if any(
            predecessor.state is FragmentBindingState.PUBLISHED
            for predecessor in replacement_predecessors
        ):
            raise SemanticFragmentBackendRejected(
                f"replacement root {root_block_id!r} is already exposed "
                "to published authority"
            )
        predecessor_serials = tuple(int(value) for value in original_live.predset)
        if not predecessor_serials:
            raise SemanticFragmentBackendRejected(
                f"owned original {original_block_id!r} has no incoming root authority"
            )
        for predecessor_serial in predecessor_serials:
            predecessor = _binding_for_live_serial(
                modifier,
                state,
                predecessor_serial,
            )
            if predecessor.state is not FragmentBindingState.PUBLISHED:
                raise SemanticFragmentBackendRejected(
                    "root predecessor must be a published logical version"
                )
            predecessor_live = _live_block_for_binding(modifier, predecessor)
            role = _incoming_root_edge_role(predecessor_live, original_live)
            requires_helper = _root_edge_requires_helper(
                predecessor_live,
                original_live,
                role,
            )
            publication_helper = None
            if requires_helper:
                matching_helpers = tuple(
                    helper
                    for helper in state.root_fallthrough_helpers
                    if helper.source_block_id == predecessor.block_id
                    and helper.root_block_id == root_block_id
                )
                if len(matching_helpers) != 1:
                    raise SemanticFragmentBackendRejected(
                        "physical root fallthrough lacks one reserved helper"
                    )
                publication_helper = state.binding(matching_helpers[0].helper_block_id)
            edge_id = f"{root_block_id}:{predecessor.block_id}:{role.value}"
            edges.append(
                SemanticFragmentRootEdgeBinding(
                    edge_id=edge_id,
                    root_block_id=root_block_id,
                    predecessor=predecessor,
                    original=original,
                    replacement=replacement,
                    role=role,
                    requires_helper=requires_helper,
                    publication_helper=publication_helper,
                )
            )
    edge_ids = tuple(edge.edge_id for edge in edges)
    if len(set(edge_ids)) != len(edge_ids):
        raise SemanticFragmentBackendRejected(
            "semantic fragment root publication contains duplicate edges"
        )
    actual_inventory = tuple(
        (
            edge.edge_id,
            edge.root_block_id,
            edge.predecessor.block_id,
            edge.role,
            edge.requires_helper,
        )
        for edge in edges
    )
    planned_inventory = tuple(
        (
            item.edge_id,
            item.root_block_id,
            item.predecessor_block_id,
            item.role,
            item.requires_helper,
        )
        for item in inventory.items
    )
    if actual_inventory != planned_inventory:
        raise SemanticFragmentBackendRejected(
            "live root ownership changed after the publication inventory"
        )
    unsupported = tuple(
        edge
        for edge in edges
        if edge.role
        not in {
            SemanticEdgeRole.CALL_FALLTHROUGH,
            SemanticEdgeRole.DIRECT,
            SemanticEdgeRole.CONDITIONAL_TAKEN,
            SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
        }
    )
    if unsupported:
        raise SemanticFragmentBackendRejected(
            "root publication requires a supported predecessor-atomic lowering"
        )
    groups = _group_semantic_fragment_root_edges(
        modifier,
        state,
        tuple(edges),
    )
    grouped_edge_ids = tuple(edge.edge_id for group in groups for edge in group.edges)
    if set(grouped_edge_ids) != set(edge_ids) or len(grouped_edge_ids) != len(edge_ids):
        raise SemanticFragmentBackendRejected(
            "root publication groups do not cover the complete edge inventory"
        )
    return SemanticFragmentRootPublicationToken(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
        groups=groups,
    )


def observe_published_semantic_fragment_graph(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
) -> PublishedFragmentGraphObservation:
    """Observe the actual live graph without projecting another root rewrite."""
    state = modifier._semantic_fragment_state
    if state is None:
        raise SemanticFragmentBackendRejected("semantic fragment is not staged")
    projection = _project_fragment(
        modifier,
        plan,
        state,
        simulate_root_publication=False,
    )
    validation = validate_published_fragment_projection(plan, projection)
    outcomes_by_subject: dict[str, list] = {}
    for outcome in validation.outcomes:
        outcomes_by_subject.setdefault(outcome.subject_id, []).append(outcome)

    published_roots = []
    for root_block_id in plan.roots:
        original_block_id = str(plan.block(root_block_id).replaces_block_id)
        if not projection.block(original_block_id).predecessors and bool(
            projection.block(root_block_id).predecessors
        ):
            published_roots.append(root_block_id)

    observable_operations = []
    for operation in plan.operations:
        relevant = outcomes_by_subject.get(operation.operation_id, ())
        required_topology = {
            FragmentValidationPostcondition.OPERATION_TOPOLOGY,
        }
        if operation.roles.intersection(
            {
                SemanticEdgeRole.CALL_FALLTHROUGH,
                SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
            }
        ):
            required_topology.add(FragmentValidationPostcondition.FALLTHROUGH_TOPOLOGY)
        topology = tuple(
            outcome
            for outcome in relevant
            if outcome.postcondition in required_topology
        )
        if (
            len(topology) == len(required_topology)
            and {outcome.postcondition for outcome in topology} == required_topology
            and all(outcome.passed for outcome in topology)
        ):
            observable_operations.append(operation)

    observable_return_carriers = tuple(
        carrier
        for carrier in projection.return_carriers
        if any(
            outcome.postcondition
            is FragmentValidationPostcondition.RETURN_CARRIER_INTEGRITY
            and outcome.subject_id == carrier.carrier_id
            and outcome.passed
            for outcome in validation.outcomes
        )
    )
    observable_terminal_returns = tuple(
        terminal_return
        for terminal_return in projection.terminal_returns
        if any(
            outcome.postcondition
            is FragmentValidationPostcondition.TERMINAL_RETURN_INTEGRITY
            and outcome.subject_id == terminal_return.return_id
            and outcome.passed
            for outcome in validation.outcomes
        )
    )
    semantics = PublishedFragmentObservation(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
        published_root_ids=tuple(published_roots),
        observable_operations=tuple(observable_operations),
        semantic_outcomes=validation.outcomes,
        fallthrough_helpers=projection.fallthrough_helpers,
        root_fallthrough_helpers=projection.root_fallthrough_helpers,
        observable_return_carriers=observable_return_carriers,
        observable_terminal_returns=observable_terminal_returns,
    )
    return PublishedFragmentGraphObservation(
        projection=projection,
        semantics=semantics,
    )


def realize_semantic_patch_plan(
    modifier: DeferredGraphModifier,
    patch_plan: object,
    prepared_fragment: PreparedSemanticFragment,
) -> ProjectedFragment:
    """Realize operation-granular semantic PatchSteps without publishing roots."""
    from d810.transforms.plan import PatchPlan

    if not isinstance(patch_plan, PatchPlan) or patch_plan.semantic_contract is None:
        raise TypeError("semantic fragment realization requires a contracted PatchPlan")
    plan = patch_plan.semantic_contract.fragment_plan
    if modifier._semantic_fragment_state is not None:
        raise RuntimeError("a semantic fragment is already staged")
    if not isinstance(prepared_fragment, PreparedSemanticFragment):
        raise SemanticFragmentBackendRejected(
            "semantic fragment realization requires prepared fragment authority"
        )
    authority = prepared_fragment.authority
    gateway = _gateway(modifier)
    if (
        authority.plan_id != plan.plan_id
        or authority.atomic_group_id != plan.atomic_group_id
        or authority.attempt_id.plan_id != plan.plan_id
        or authority.attempt_id.session_id != gateway.session_id
        or authority.attempt_id.generation != gateway.generation
        or authority.session_id != gateway.session_id
        or authority.generation != gateway.generation
        or authority.snapshot_id != authority.snapshot.projection_input.snapshot_id
        or authority.cfg_projection.plan_id != plan.plan_id
        or authority.cfg_projection.snapshot_id != authority.snapshot_id
        or gateway._active_fragment_plan is not plan
        or gateway._active_prepared_semantic_fragment is not prepared_fragment
        or gateway.active_batch_id != authority.attempt_id.attempt_id
        or gateway._active_fragment_snapshot_id != authority.snapshot_id
        or gateway._active_fragment_root_inventory_signature
        != authority.root_inventory_signature
    ):
        raise SemanticFragmentBackendRejected(
            "semantic fragment realization authority is foreign or stale"
        )
    if authority.attempt_id in modifier._consumed_semantic_fragment_attempts:
        raise SemanticFragmentBackendRejected(
            "semantic fragment realization authority was already consumed"
        )
    try:
        expected_projection = project_fragment(
            plan,
            authority.snapshot.projection_input,
            authority.root_inventory,
        )
        expected_cfg_projection = fragment_cfg_projection(
            plan,
            authority.snapshot.projection_input,
            expected_projection,
        )
        CfgContract().verify_projection(expected_cfg_projection, scope="full")
    except (FragmentProjectionFailure, CfgContractViolationError) as exc:
        raise SemanticFragmentBackendRejected(
            "semantic fragment realization authority cannot be reproduced"
        ) from exc
    if (
        authority.projection != expected_projection
        or authority.cfg_projection != expected_cfg_projection
    ):
        raise SemanticFragmentBackendRejected(
            "semantic fragment realization authority projection was forged"
        )
    expected_constant_ids = tuple(
        item.materialization_id for item in plan.constant_materializations
    )
    prepared_constant_ids = tuple(
        item.materialization_id
        for item in authority.snapshot.constant_materializations
    )
    if prepared_constant_ids != expected_constant_ids:
        raise SemanticFragmentBackendRejected(
            "prepared constant materialization inventory differs from the plan",
            reason_code="constant_materialization_inventory_mismatch",
        )
    try:
        live_constant_materializations = _reobserve_constant_materializations(
            modifier,
            plan,
            authority.snapshot.native_bodies,
        )
    except SemanticFragmentBackendRejected:
        raise
    except Exception as exc:
        raise SemanticFragmentBackendRejected(
            "constant materialization live evidence cannot be re-observed",
            reason_code="constant_materialization_reobservation_failed",
        ) from exc
    if live_constant_materializations != authority.snapshot.constant_materializations:
        raise SemanticFragmentBackendRejected(
            "constant materialization live evidence differs from immutable preflight",
            reason_code="constant_materialization_preflight_mismatch",
        )

    fact_by_body_id = {fact.body_id: fact for fact in authority.snapshot.native_bodies}
    try:
        preparations = tuple(
            (
                body_id,
                PreparedNativeBodyPreparation(
                    fact=fact_by_body_id[body_id],
                    payload=PreparedNativeBodyPayload(
                        plan_id=plan.plan_id,
                        body_id=body_id,
                        rows=rows,
                    ),
                ),
            )
            for body_id, rows in prepared_fragment.payload.native_body_rows
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise SemanticFragmentBackendRejected(
            "prepared native realization payload diverges from facts"
        ) from exc
    for _body_id, preparation in preparations:
        try:
            native_body = next(
                body
                for body in plan.native_bodies
                if body.body_id == preparation.fact.body_id
            )
            preparation.assert_authority(plan=plan, native_body=native_body)
        except (StopIteration, TypeError, ValueError) as exc:
            raise SemanticFragmentBackendRejected(
                "prepared native realization payload diverges from facts"
            ) from exc
        for fact_block, payload_row in zip(
            preparation.fact.blocks,
            preparation.payload.rows,
        ):
            _block_id, block_flags, instructions = payload_row
            if fact_block.block_flags != int(block_flags) or len(
                fact_block.instructions
            ) != len(instructions):
                raise SemanticFragmentBackendRejected(
                    "prepared native realization payload diverges from facts"
                )
            for fact, (native_ea, instruction) in zip(
                fact_block.instructions,
                instructions,
            ):
                try:
                    writes_flags = instruction_writes_condition_codes(instruction)
                except ConditionCodeQueryUnavailable:
                    writes_flags = None
                if (
                    fact.native_ea != int(native_ea)
                    or fact.opcode != int(instruction.opcode)
                    or fact.operand_shape != sdk_instruction_operand_shape(instruction)
                    or fact.writes_condition_codes != writes_flags
                ):
                    raise SemanticFragmentBackendRejected(
                        "prepared native realization payload diverges from facts"
                    )

    construction_by_id = {
        item.carrier_id: item
        for item in authority.snapshot.return_carrier_constructions
    }
    operand_by_id = dict(prepared_fragment.payload.return_carrier_operands)
    if set(construction_by_id) != set(operand_by_id):
        raise SemanticFragmentBackendRejected(
            "prepared return-carrier payload diverges from facts"
        )
    for carrier_id, construction in construction_by_id.items():
        operand = operand_by_id[carrier_id]
        if (
            _prepared_operand_shape(operand, construction.source)
            != construction.operand_shape
        ):
            raise SemanticFragmentBackendRejected(
                "prepared return-carrier payload diverges from facts"
            )

    modifier._consumed_semantic_fragment_attempts.add(authority.attempt_id)
    state = SemanticFragmentBackendState(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
        preflight_projection=authority.projection,
        clone_source_instructions_by_block_id={
            evidence.block_id: evidence
            for evidence in authority.snapshot.projection_input.clone_source_instructions
        },
        return_carrier_constructions=construction_by_id,
        return_carrier_operands=operand_by_id,
    )
    modifier._semantic_fragment_state = state
    try:
        from d810.transforms.plan import (
            PatchFragmentBlockMaterialization,
            PatchFragmentConstantMaterializations,
            PatchFragmentOperation,
            PatchFragmentOperationNormalization,
            PatchFragmentRootPublication,
            PatchFragmentTerminalEffects,
        )

        computed_branches_normalized = False
        constants_materialized = False
        terminal_effects_materialized = False
        root_helpers_reserved = False
        root_steps = tuple(
            step
            for step in patch_plan.steps
            if isinstance(step, PatchFragmentRootPublication)
        )
        for step in patch_plan.steps:
            if isinstance(step, PatchFragmentBlockMaterialization):
                block = step.block
                if step.materialization is FragmentBlockMaterialization.REUSE_PUBLISHED:
                    state.bindings[block.block_id] = _published_binding(
                        modifier,
                        block.block_id,
                        block.stable_identity,
                        preflight_projection=state.preflight_projection,
                    )
                elif (
                    step.materialization is FragmentBlockMaterialization.CLONE_PUBLISHED
                ):
                    if step.source_ref is None:
                        raise SemanticFragmentBackendRejected(
                            "clone PatchStep lacks source authority"
                        )
                    _clone_replacement(
                        modifier,
                        state,
                        block,
                        source_block_id=step.source_ref.local_block_id,
                        plan_ref=step.block_ref,
                    )
                elif step.materialization is FragmentBlockMaterialization.IMPORT_NATIVE:
                    if step.native_body_id is None:
                        raise SemanticFragmentBackendRejected(
                            "native-body PatchStep lacks body authority"
                        )
                    _stage_native_bodies(
                        modifier,
                        plan,
                        state,
                        reference_version=state.binding(plan.roots[0]).version,
                        preparations=preparations,
                        native_body_id=step.native_body_id,
                    )
                    state.binding(block.block_id)
                elif step.materialization is FragmentBlockMaterialization.CREATE_EMPTY:
                    _create_empty_block(
                        modifier,
                        state,
                        block,
                        reference_version=state.binding(plan.roots[0]).version,
                        plan_ref=step.block_ref,
                    )
            elif isinstance(step, PatchFragmentConstantMaterializations):
                if constants_materialized:
                    raise SemanticFragmentBackendRejected(
                        "semantic PatchPlan duplicated constant materializations"
                    )
                _materialize_constant_materializations(
                    modifier,
                    plan,
                    state,
                    step,
                    authority.snapshot.constant_materializations,
                )
                constants_materialized = True
            elif isinstance(step, PatchFragmentOperationNormalization):
                if computed_branches_normalized:
                    raise SemanticFragmentBackendRejected(
                        "semantic PatchPlan duplicated operation normalization"
                    )
                _normalize_replacement_operations(
                    modifier,
                    plan,
                    state,
                    step.operations,
                )
                computed_branches_normalized = True
            elif isinstance(step, PatchFragmentOperation):
                _realize_operations(modifier, plan, state, (step,))
            elif isinstance(step, PatchFragmentTerminalEffects):
                if terminal_effects_materialized:
                    raise SemanticFragmentBackendRejected(
                        "semantic PatchPlan duplicated terminal effects"
                    )
                terminal_plan = replace(
                    plan,
                    return_carriers=step.return_carriers,
                    terminal_returns=step.terminal_returns,
                    terminal_routes=step.terminal_routes,
                )
                _materialize_terminal_effects(modifier, terminal_plan, state)
                terminal_effects_materialized = True
            elif isinstance(step, PatchFragmentRootPublication):
                if _generated_graph_free(modifier):
                    continue
                if not root_helpers_reserved:
                    _reserve_root_fallthrough_helpers(
                        modifier,
                        state,
                        root_steps,
                    )
                    root_helpers_reserved = True
            else:
                raise SemanticFragmentBackendRejected(
                    f"unsupported semantic PatchStep {type(step).__name__}"
                )
        gateway._record_fragment_plan_bindings(
            plan,
            tuple(
                dict.fromkeys(
                    (
                        *(
                            (
                                PlanBlockRef(plan.plan_id, block.block_id),
                                state.binding(block.block_id).version,
                            )
                            for block in plan.blocks
                        ),
                        *(
                            (binding.creation_ref, binding.version)
                            for binding in state.bindings.values()
                            if binding.creation_ref is not None
                            and _try_live_block_for_binding(modifier, binding)
                            is not None
                        ),
                    )
                )
            ),
        )
        projection = _project_fragment(modifier, plan, state)
        state.projection = projection
        return projection
    except Exception:
        if gateway.mutation_started:
            raise
        try:
            discard_staged_semantic_fragment(modifier, plan)
        except Exception as cleanup_error:
            cleanup_error.d810_semantic_stage_cleanup_failed = True
            raise
        raise


def observe_staged_semantic_fragment(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
) -> ProjectedFragment:
    """Re-observe one staged fragment from the live MBA without publishing roots."""
    state = modifier._semantic_fragment_state
    if (
        state is None
        or state.plan_id != plan.plan_id
        or state.atomic_group_id != plan.atomic_group_id
    ):
        raise SemanticFragmentBackendRejected(
            "staged semantic fragment observation lacks exact plan authority"
        )
    return _project_fragment(modifier, plan, state)


@dataclass(frozen=True, slots=True)
class _SemanticTerminalFinalizationSnapshot:
    terminal: FragmentTerminalReturn
    block: object
    tail_copy: object
    live_ea: int
    block_type: int
    successors: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class _SemanticCommitFinalizationSnapshot:
    instruction_addresses: tuple[tuple[object, int], ...]
    instruction_origins_by_block_id: tuple[
        tuple[str, tuple[tuple[int, int], ...]], ...
    ]
    predicate_live_eas_by_operation_id: tuple[tuple[str, int], ...]
    constant_materialization_rollbacks: tuple[
        SemanticConstantMaterializationRollback, ...
    ]
    terminals: tuple[_SemanticTerminalFinalizationSnapshot, ...]
    stop: object | None
    stop_predecessors: tuple[int, ...]


def _snapshot_semantic_commit_finalization(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
) -> _SemanticCommitFinalizationSnapshot:
    """Prevalidate and snapshot all active authority before finalization."""
    stop = None
    terminal_snapshots: list[_SemanticTerminalFinalizationSnapshot] = []
    terminal_authorities: set[tuple[str, int]] = set()
    if plan.terminal_returns:
        quantity = int(getattr(modifier.mba, "qty", 0) or 0)
        stop = None if quantity < 1 else modifier.mba.get_mblock(quantity - 1)
        if stop is None or int(stop.type) != int(ida_hexrays.BLT_STOP):
            raise SemanticFragmentBackendRejected(
                "semantic fragment terminal finalization requires the canonical "
                "BLT_STOP"
            )
        seen_terminal_blocks: set[str] = set()
        for terminal in plan.terminal_returns:
            if terminal.block_id in seen_terminal_blocks:
                raise SemanticFragmentBackendRejected(
                    "semantic fragment finalization contains duplicate terminal "
                    f"authority: block={terminal.block_id!r}"
                )
            seen_terminal_blocks.add(terminal.block_id)
            block = _live_block_for_binding(
                modifier,
                state.binding(terminal.block_id),
            )
            live_ea = state.live_instruction_ea(
                terminal.block_id,
                terminal.instruction_ea,
            )
            origins = state.instruction_origins_by_block_id.get(
                terminal.block_id,
                {},
            )
            tail = block.tail
            if (
                origins.get(int(live_ea)) != int(terminal.instruction_ea)
                or tail is None
                or int(tail.ea) != int(live_ea)
                or int(tail.opcode) != int(ida_hexrays.m_ret)
                or int(block.type) != int(ida_hexrays.BLT_0WAY)
                or tuple(int(value) for value in block.succset)
            ):
                raise SemanticFragmentBackendRejected(
                    "semantic fragment terminal changed after postpublication "
                    f"validation: return={terminal.return_id!r} "
                    f"block={terminal.block_id!r}@0x{int(terminal.instruction_ea):X} "
                    f"live=0x{int(live_ea):X}"
                )
            terminal_snapshots.append(
                _SemanticTerminalFinalizationSnapshot(
                    terminal=terminal,
                    block=block,
                    tail_copy=ida_hexrays.minsn_t(tail),
                    live_ea=int(live_ea),
                    block_type=int(block.type),
                    successors=tuple(int(value) for value in block.succset),
                )
            )
            terminal_authorities.add((terminal.block_id, int(live_ea)))

    # A terminal return is removed from its block during commit finalization.
    # Retaining its live SWIG proxy here would leave compensation holding a
    # potentially dangling object.  Terminal snapshots own a deep instruction
    # copy; the generic address snapshot is therefore strictly nonterminal.
    instruction_addresses: list[tuple[object, int]] = []
    for block_id, origins in sorted(state.instruction_origins_by_block_id.items()):
        block = _live_block_for_binding(modifier, state.binding(block_id))
        instructions_by_ea: dict[int, list[object]] = {}
        for instruction in _iter_block_instructions(block):
            instructions_by_ea.setdefault(int(instruction.ea), []).append(instruction)
        for live_ea in origins:
            live_ea = int(live_ea)
            matches = instructions_by_ea.get(live_ea, ())
            if len(matches) != 1:
                raise SemanticFragmentBackendRejected(
                    "semantic fragment commit snapshot found ambiguous live "
                    f"authority: block={block_id!r} live=0x{live_ea:X} "
                    f"matches={len(matches)}"
                )
            if (block_id, live_ea) in terminal_authorities:
                continue
            instruction_addresses.append((matches[0], live_ea))

    return _SemanticCommitFinalizationSnapshot(
        instruction_addresses=tuple(instruction_addresses),
        instruction_origins_by_block_id=tuple(
            (
                str(block_id),
                tuple(
                    sorted(
                        (int(live_ea), int(native_ea))
                        for live_ea, native_ea in origins.items()
                    )
                ),
            )
            for block_id, origins in sorted(
                state.instruction_origins_by_block_id.items()
            )
        ),
        predicate_live_eas_by_operation_id=tuple(
            sorted(
                (str(operation_id), int(live_ea))
                for operation_id, live_ea in state.predicate_live_eas_by_operation_id.items()
            )
        ),
        constant_materialization_rollbacks=tuple(
            state.constant_materialization_rollbacks
        ),
        terminals=tuple(terminal_snapshots),
        stop=stop,
        stop_predecessors=(
            () if stop is None else tuple(int(value) for value in stop.predset)
        ),
    )


def _replace_serial_collection(values: object, serials: tuple[int, ...]) -> None:
    values.clear()
    for serial in serials:
        values.push_back(int(serial))


def _restore_semantic_commit_finalization(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    snapshot: _SemanticCommitFinalizationSnapshot,
) -> None:
    """Restore active MBA/state authority while retaining allocator history."""
    for terminal_snapshot in snapshot.terminals:
        modifier._restore_semantic_terminal_finalization_now(
            block=terminal_snapshot.block,
            tail_copy=terminal_snapshot.tail_copy,
            live_ea=terminal_snapshot.live_ea,
            block_type=terminal_snapshot.block_type,
            successors=terminal_snapshot.successors,
        )

    for instruction, live_ea in snapshot.instruction_addresses:
        instruction.setaddr(int(live_ea))

    modifier._restore_semantic_stop_finalization_now(
        stop=snapshot.stop,
        predecessors=snapshot.stop_predecessors,
    )

    state.instruction_origins_by_block_id = {
        block_id: dict(origins)
        for block_id, origins in snapshot.instruction_origins_by_block_id
    }
    state.predicate_live_eas_by_operation_id = dict(
        snapshot.predicate_live_eas_by_operation_id
    )
    state.constant_materialization_rollbacks = list(
        snapshot.constant_materialization_rollbacks
    )

    for instruction, live_ea in snapshot.instruction_addresses:
        if int(instruction.ea) != int(live_ea):
            raise SemanticFragmentBackendRejected(
                "semantic fragment commit compensation could not restore an "
                f"instruction address: live=0x{int(live_ea):X}"
            )
    for terminal_snapshot in snapshot.terminals:
        block = terminal_snapshot.block
        tail = block.tail
        if (
            tail is None
            or int(tail.ea) != int(terminal_snapshot.live_ea)
            or int(tail.opcode) != int(ida_hexrays.m_ret)
            or int(block.type) != int(terminal_snapshot.block_type)
            or tuple(int(value) for value in block.succset)
            != terminal_snapshot.successors
        ):
            raise SemanticFragmentBackendRejected(
                "semantic fragment commit compensation could not restore terminal "
                f"shape: return={terminal_snapshot.terminal.return_id!r}"
            )


def _rebind_semantic_instruction_addresses_for_commit(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
) -> None:
    """Move tracked semantics onto verifier-owned EAs after postvalidation."""
    pending: list[tuple[str, object, object, int, int]] = []
    seen_live_eas: set[int] = set()
    for block_id in sorted(state.instruction_origins_by_block_id):
        origins = state.instruction_origins_by_block_id[block_id]
        if not origins:
            continue
        block = _live_block_for_binding(modifier, state.binding(block_id))
        plan_block = plan.block(block_id)
        identity = plan_block.stable_identity
        instructions_by_ea: dict[int, list[object]] = {}
        for instruction in _iter_block_instructions(block):
            instructions_by_ea.setdefault(int(instruction.ea), []).append(instruction)
        for live_ea, native_ea in sorted(origins.items()):
            live_ea = int(live_ea)
            native_ea = int(native_ea)
            mapped_ea = int(modifier.mba.map_fict_ea(live_ea))
            matches = instructions_by_ea.get(live_ea, ())
            if (
                live_ea in seen_live_eas
                or mapped_ea != native_ea
                or len(matches) != 1
                or (
                    identity is not None
                    and not identity.native_ranges.contains(native_ea)
                )
            ):
                raise SemanticFragmentBackendRejected(
                    "semantic fragment instruction provenance changed before "
                    f"commit finalization: {block_id}@0x{native_ea:X} "
                    f"live=0x{live_ea:X} mapped=0x{mapped_ea:X} "
                    f"matches={len(matches)}"
                )
            seen_live_eas.add(live_ea)
            pending.append((block_id, block, matches[0], live_ea, native_ea))

    entry_ea = int(modifier.mba.entry_ea)
    for block_id, block, _instruction, _old_live_ea, native_ea in pending:
        if not int(block.start) <= entry_ea < int(block.end):
            raise SemanticFragmentBackendRejected(
                "semantic fragment destination block does not own the commit "
                f"anchor: {block_id}@0x{native_ea:X} entry=0x{entry_ea:X} "
                f"block=[0x{int(block.start):X},0x{int(block.end):X})"
            )
    rebound_by_block_id: dict[str, dict[int, int]] = {
        block_id: {}
        for block_id, origins in state.instruction_origins_by_block_id.items()
        if origins
    }
    rebound_live_eas: dict[int, int] = {}
    for block_id, _block, instruction, old_live_ea, native_ea in pending:
        new_live_ea = int(modifier.mba.alloc_fict_ea(entry_ea))
        if (
            new_live_ea < 0
            or new_live_ea >= _BADADDR
            or new_live_ea in rebound_live_eas.values()
            or int(modifier.mba.map_fict_ea(new_live_ea)) != entry_ea
        ):
            raise SemanticFragmentBackendRejected(
                "semantic fragment could not allocate a verifier-owned commit "
                f"address: {block_id}@0x{native_ea:X} live=0x{new_live_ea:X}"
            )
        instruction.setaddr(new_live_ea)
        rebound_by_block_id[block_id][new_live_ea] = native_ea
        rebound_live_eas[old_live_ea] = new_live_ea

    for block_id, origins in rebound_by_block_id.items():
        state.instruction_origins_by_block_id[block_id] = origins
    for operation_id, live_ea in tuple(
        state.predicate_live_eas_by_operation_id.items()
    ):
        try:
            state.predicate_live_eas_by_operation_id[operation_id] = (
                rebound_live_eas[int(live_ea)]
            )
        except KeyError as exc:
            raise SemanticFragmentBackendRejected(
                "semantic fragment predicate lost its origin during commit "
                f"finalization: operation={operation_id!r} live=0x{int(live_ea):X}"
            ) from exc
    state.constant_materialization_rollbacks = [
        replace(
            rollback,
            instruction_ea=rebound_live_eas.get(
                int(rollback.instruction_ea),
                int(rollback.instruction_ea),
            ),
        )
        for rollback in state.constant_materialization_rollbacks
    ]

    for block_id, origins in rebound_by_block_id.items():
        block = _live_block_for_binding(modifier, state.binding(block_id))
        identity = plan.block(block_id).stable_identity
        instructions_by_ea: dict[int, list[object]] = {}
        for instruction in _iter_block_instructions(block):
            instructions_by_ea.setdefault(int(instruction.ea), []).append(instruction)
        for live_ea, native_ea in origins.items():
            if (
                int(modifier.mba.map_fict_ea(int(live_ea))) != entry_ea
                or not int(block.start) <= entry_ea < int(block.end)
                or len(instructions_by_ea.get(int(live_ea), ())) != 1
                or (
                    identity is not None
                    and not identity.native_ranges.contains(int(native_ea))
                )
            ):
                raise SemanticFragmentBackendRejected(
                    "semantic fragment commit address is outside destination "
                    f"ownership: {block_id}@0x{int(native_ea):X} "
                    f"live=0x{int(live_ea):X} entry=0x{entry_ea:X} "
                    f"block=[0x{int(block.start):X},0x{int(block.end):X})"
                )


def _apply_semantic_fragment_commit_finalization(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
) -> None:
    """Apply one fully prevalidated semantic commit batch."""
    _rebind_semantic_instruction_addresses_for_commit(modifier, plan, state)
    if not plan.terminal_returns:
        return

    quantity = int(getattr(modifier.mba, "qty", 0) or 0)
    stop = None if quantity < 1 else modifier.mba.get_mblock(quantity - 1)
    if stop is None or int(stop.type) != int(ida_hexrays.BLT_STOP):
        raise SemanticFragmentBackendRejected(
            "semantic fragment terminal finalization requires the canonical BLT_STOP"
        )

    for terminal in plan.terminal_returns:
        block = _live_block_for_binding(
            modifier,
            state.binding(terminal.block_id),
        )
        live_ea = state.live_instruction_ea(
            terminal.block_id,
            terminal.instruction_ea,
        )
        tail = block.tail
        if (
            tail is None
            or int(tail.ea) != int(live_ea)
            or int(tail.opcode) != int(ida_hexrays.m_ret)
            or int(block.type) != int(ida_hexrays.BLT_0WAY)
            or tuple(int(value) for value in block.succset)
        ):
            raise SemanticFragmentBackendRejected(
                "semantic fragment terminal changed after postpublication "
                f"validation: return={terminal.return_id!r} "
                f"block={terminal.block_id!r}@0x{int(terminal.instruction_ea):X} "
                f"live=0x{int(live_ea):X}"
            )
        if not modifier._canonicalize_semantic_terminal_return_now(
            block=block,
            stop=stop,
        ):
            raise SemanticFragmentBackendRejected(
                "semantic fragment terminal canonicalization failed after "
                f"postpublication validation: return={terminal.return_id!r} "
                f"block={terminal.block_id!r}@0x{int(terminal.instruction_ea):X}"
            )
        remaining_return = any(
            int(instruction.opcode) == int(ida_hexrays.m_ret)
            for instruction in _iter_block_instructions(block)
        )
        if (
            remaining_return
            or int(block.type) != int(ida_hexrays.BLT_1WAY)
            or tuple(int(value) for value in block.succset) != (int(stop.serial),)
            or int(block.serial)
            not in tuple(int(value) for value in stop.predset)
        ):
            raise SemanticFragmentBackendRejected(
                "semantic fragment terminal canonicalization produced an invalid "
                f"STOP edge: return={terminal.return_id!r} "
                f"block={terminal.block_id!r}@0x{int(terminal.instruction_ea):X}"
            )
        removed_origin = state.instruction_origins_by_block_id[
            terminal.block_id
        ].pop(int(live_ea), None)
        if removed_origin != int(terminal.instruction_ea):
            raise SemanticFragmentBackendRejected(
                "semantic fragment terminal lost active provenance during commit "
                f"finalization: return={terminal.return_id!r} "
                f"live=0x{int(live_ea):X}"
            )


def finalize_semantic_fragment_for_commit(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
) -> None:
    """Make plan-owned semantics verifier-safe as one compensated batch."""
    state = modifier._semantic_fragment_state
    if (
        state is None
        or state.plan_id != plan.plan_id
        or state.atomic_group_id != plan.atomic_group_id
    ):
        raise SemanticFragmentBackendRejected(
            "semantic fragment commit finalization has no matching staged state"
        )
    snapshot = _snapshot_semantic_commit_finalization(modifier, plan, state)
    try:
        _apply_semantic_fragment_commit_finalization(
            modifier,
            plan,
            state,
        )
    except Exception as error:
        try:
            _restore_semantic_commit_finalization(modifier, state, snapshot)
        except Exception as restore_error:
            raise SemanticFragmentBackendRejected(
                "semantic fragment commit finalization and compensation both "
                f"failed: primary={error!r}; compensation={restore_error!r}"
            ) from restore_error
        raise


def discard_staged_semantic_fragment(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
) -> None:
    """Remove every unpublished physical version staged for ``plan``."""
    state = modifier._semantic_fragment_state
    if state is None:
        return
    if state.plan_id != plan.plan_id or state.atomic_group_id != plan.atomic_group_id:
        raise RuntimeError("staged semantic fragment does not match discard request")
    try:
        _rollback_constant_materializations(modifier, state)
        modifier._discard_detached_semantic_versions(
            tuple(
                state.binding(block_id).version for block_id in state.staged_block_ids
            )
        )
    finally:
        modifier._semantic_fragment_state = None


__all__ = [
    "SemanticFragmentBackendRejected",
    "SemanticFragmentBackendState",
    "SemanticFragmentRootEdgeBinding",
    "SemanticFragmentRootPublicationGroup",
    "SemanticFragmentRootPublicationToken",
    "SemanticNativeBodyMaterializer",
    "SemanticNativeBodyStagingContext",
    "discard_staged_semantic_fragment",
    "finalize_semantic_fragment_for_commit",
    "realize_semantic_patch_plan",
    "observe_staged_semantic_fragment",
    "observe_published_semantic_fragment_graph",
    "plan_semantic_fragment_root_inventory",
    "prepare_semantic_fragment_root_publication",
    "snapshot_semantic_fragment_inputs",
]
