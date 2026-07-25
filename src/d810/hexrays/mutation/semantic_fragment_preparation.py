"""Immutable semantic facts separated from backend-local realization payloads."""

from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.core.typing import Mapping
from d810.hexrays.ir.flag_queries import (
    ConditionCodeQueryUnavailable,
    instruction_writes_condition_codes,
)
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.flowgraph import BlockKind, InsnKind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.transforms.fragment_plan import FragmentNativeBody, FragmentPlan


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if not value.strip():
        raise ValueError(f"{label} must not be blank")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{label} must be an integer")
    if value < 0:
        raise ValueError(f"{label} must be non-negative")
    return value


def _unique(values: tuple[str, ...], label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


def _primitive_tree(value: object) -> bool:
    if isinstance(value, (str, int, bool, type(None))):
        return True
    return isinstance(value, tuple) and all(_primitive_tree(item) for item in value)


def sdk_operand_shape(operand: object, *, depth: int = 3) -> tuple[object, ...]:
    """Project an SDK operand into primitive shape without block coordinates."""
    operand_type = int(getattr(operand, "t", -1))
    size = int(getattr(operand, "size", 0))
    detail: object | None = None
    if operand_type == int(ida_hexrays.mop_r):
        detail = ("register", int(getattr(operand, "r", -1)))
    elif operand_type == int(ida_hexrays.mop_n):
        detail = (
            "number",
            int(getattr(getattr(operand, "nnn", None), "value", 0)),
        )
    elif operand_type in {int(ida_hexrays.mop_S), int(ida_hexrays.mop_str)}:
        detail = ("stack", int(getattr(getattr(operand, "s", None), "off", 0)))
    elif operand_type == int(ida_hexrays.mop_v):
        detail = ("global", int(getattr(operand, "g", 0)))
    elif operand_type == int(ida_hexrays.mop_b):
        detail = ("block-reference",)
    elif operand_type == int(ida_hexrays.mop_l):
        local = getattr(operand, "l", None)
        detail = (
            "local",
            int(getattr(local, "idx", -1)),
            int(getattr(local, "off", 0)),
        )
    elif operand_type == int(ida_hexrays.mop_d) and depth > 0:
        nested = getattr(operand, "d", None)
        detail = (
            "nested",
            int(getattr(nested, "opcode", -1)),
            sdk_operand_shape(getattr(nested, "l", None), depth=depth - 1),
            sdk_operand_shape(getattr(nested, "r", None), depth=depth - 1),
            sdk_operand_shape(getattr(nested, "d", None), depth=depth - 1),
        )
    elif operand_type == int(ida_hexrays.mop_a) and depth > 0:
        detail = (
            "address",
            sdk_operand_shape(getattr(operand, "a", None), depth=depth - 1),
        )
    elif operand_type == int(ida_hexrays.mop_f) and depth > 0:
        detail = (
            "arguments",
            tuple(
                sdk_operand_shape(argument, depth=depth - 1)
                for argument in getattr(getattr(operand, "f", None), "args", ())
            ),
        )
    return (operand_type, size, detail)


def sdk_instruction_operand_shape(instruction: object) -> tuple[object, ...]:
    return tuple(
        sdk_operand_shape(getattr(instruction, slot, None)) for slot in ("l", "r", "d")
    )


def sdk_instruction_kind(opcode: int) -> InsnKind:
    """Lift the backend opcode needed by immutable preparation facts."""
    opcode = int(opcode)
    direct = {
        int(ida_hexrays.m_nop): InsnKind.NOP,
        int(ida_hexrays.m_mov): InsnKind.MOV,
        int(ida_hexrays.m_ldx): InsnKind.LOAD,
        int(ida_hexrays.m_stx): InsnKind.STORE,
        int(ida_hexrays.m_xdu): InsnKind.XDU,
        int(ida_hexrays.m_xds): InsnKind.XDS,
        int(ida_hexrays.m_add): InsnKind.ADD,
        int(ida_hexrays.m_sub): InsnKind.SUB,
        int(ida_hexrays.m_and): InsnKind.AND,
        int(ida_hexrays.m_mul): InsnKind.MUL,
        int(ida_hexrays.m_goto): InsnKind.GOTO,
        int(ida_hexrays.m_ijmp): InsnKind.INDIRECT_JUMP,
        int(ida_hexrays.m_jtbl): InsnKind.TABLE_JUMP,
        int(ida_hexrays.m_call): InsnKind.CALL,
        int(ida_hexrays.m_icall): InsnKind.CALL,
        int(ida_hexrays.m_ret): InsnKind.RET,
    }
    kind = direct.get(opcode)
    if kind is not None:
        return kind
    if ida_hexrays.is_mcode_jcond(opcode):
        return InsnKind.COND_JUMP
    return InsnKind.UNKNOWN


def _writes_condition_codes(instruction: object) -> bool | None:
    try:
        return bool(instruction_writes_condition_codes(instruction))
    except ConditionCodeQueryUnavailable:
        return None


@dataclass(frozen=True, slots=True)
class PreparedNativeInstructionFact:
    """Portable semantic shape of one prepared SDK instruction."""

    instruction_id: str
    native_ea: int
    opcode: int
    kind: InsnKind
    operand_shape: tuple[object, ...]
    writes_condition_codes: bool | None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "instruction_id",
            _identifier(self.instruction_id, "instruction id"),
        )
        object.__setattr__(
            self,
            "native_ea",
            _nonnegative_int(self.native_ea, "prepared instruction EA"),
        )
        object.__setattr__(
            self,
            "opcode",
            _nonnegative_int(self.opcode, "prepared instruction opcode"),
        )
        if not isinstance(self.kind, InsnKind):
            raise TypeError("prepared instruction kind must be portable")
        operand_shape = tuple(self.operand_shape)
        if not _primitive_tree(operand_shape):
            raise TypeError("prepared operand shape must contain only primitives")
        object.__setattr__(self, "operand_shape", operand_shape)
        if self.writes_condition_codes not in {True, False, None}:
            raise TypeError("prepared flag fact must be bool or None")


@dataclass(frozen=True, slots=True)
class PreparedNativeEdgeFact:
    """Plan-local, serial-free projected successor."""

    role: SemanticEdgeRole
    target_block_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.role, SemanticEdgeRole):
            raise TypeError("prepared edge requires a semantic role")
        object.__setattr__(
            self,
            "target_block_id",
            _identifier(self.target_block_id, "prepared edge target"),
        )


@dataclass(frozen=True, slots=True)
class PreparedNativeBlockFact:
    """Immutable identity, instruction, and projected-topology authority."""

    block_id: str
    semantic_anchor_ea: int
    stable_identity: StableBlockIdentity
    block_flags: int
    kind: BlockKind
    successors: tuple[PreparedNativeEdgeFact, ...]
    predecessor_block_ids: tuple[str, ...]
    terminator_ea: int | None
    terminator_kind: InsnKind
    instructions: tuple[PreparedNativeInstructionFact, ...]

    def __post_init__(self) -> None:
        block_id = _identifier(self.block_id, "prepared block id")
        semantic_anchor_ea = _nonnegative_int(
            self.semantic_anchor_ea,
            "prepared block semantic anchor",
        )
        if not isinstance(self.stable_identity, StableBlockIdentity):
            raise TypeError("prepared block requires stable native identity")
        if not self.stable_identity.native_ranges.contains(semantic_anchor_ea):
            raise ValueError("prepared block anchor escapes stable identity")
        if not isinstance(self.block_flags, int) or isinstance(self.block_flags, bool):
            raise TypeError("prepared block flags must be an integer")
        if not isinstance(self.kind, BlockKind):
            raise TypeError("prepared block kind must be portable")
        successors = tuple(self.successors)
        if any(not isinstance(edge, PreparedNativeEdgeFact) for edge in successors):
            raise TypeError("prepared block contains an invalid edge")
        predecessor_block_ids = tuple(
            _identifier(value, "prepared predecessor")
            for value in self.predecessor_block_ids
        )
        _unique(predecessor_block_ids, "prepared predecessor ids")
        expected_successors = {
            BlockKind.ZERO_WAY: 0,
            BlockKind.ONE_WAY: 1,
            BlockKind.TWO_WAY: 2,
        }.get(self.kind)
        if expected_successors is not None and len(successors) != expected_successors:
            raise ValueError("prepared block kind and successor count differ")
        terminator_ea = (
            None
            if self.terminator_ea is None
            else _nonnegative_int(self.terminator_ea, "prepared terminator EA")
        )
        if not isinstance(self.terminator_kind, InsnKind):
            raise TypeError("prepared terminator kind must be portable")
        instructions = tuple(self.instructions)
        if any(
            not isinstance(instruction, PreparedNativeInstructionFact)
            for instruction in instructions
        ):
            raise TypeError("prepared block instructions must be typed facts")
        _unique(
            tuple(instruction.instruction_id for instruction in instructions),
            "prepared instruction ids",
        )
        object.__setattr__(self, "block_id", block_id)
        object.__setattr__(self, "semantic_anchor_ea", semantic_anchor_ea)
        object.__setattr__(self, "successors", successors)
        object.__setattr__(self, "predecessor_block_ids", predecessor_block_ids)
        object.__setattr__(self, "terminator_ea", terminator_ea)
        object.__setattr__(self, "instructions", instructions)


@dataclass(frozen=True, slots=True)
class PreparedNativeBodyFact:
    """Complete portable authority for one prepared native body."""

    plan_id: str
    body_id: str
    native_ranges: tuple[NativeEaInterval, ...]
    entry_block_ids: tuple[str, ...]
    terminal_block_ids: tuple[str, ...]
    blocks: tuple[PreparedNativeBlockFact, ...]
    direct_transfer_operation_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "plan_id", _identifier(self.plan_id, "plan id"))
        object.__setattr__(self, "body_id", _identifier(self.body_id, "body id"))
        native_ranges = tuple(self.native_ranges)
        if not native_ranges or any(
            not isinstance(native_range, NativeEaInterval)
            for native_range in native_ranges
        ):
            raise TypeError("prepared body requires typed native ranges")
        entry_block_ids = tuple(
            _identifier(value, "prepared entry block") for value in self.entry_block_ids
        )
        terminal_block_ids = tuple(
            _identifier(value, "prepared terminal block")
            for value in self.terminal_block_ids
        )
        blocks = tuple(self.blocks)
        if any(not isinstance(block, PreparedNativeBlockFact) for block in blocks):
            raise TypeError("prepared body blocks must be typed facts")
        block_ids = tuple(block.block_id for block in blocks)
        _unique(block_ids, "prepared block ids")
        if not set(entry_block_ids + terminal_block_ids) <= set(block_ids):
            raise ValueError("prepared entry or terminal block is outside the body")
        direct_transfer_operation_ids = tuple(
            _identifier(value, "prepared direct-transfer operation")
            for value in self.direct_transfer_operation_ids
        )
        _unique(
            direct_transfer_operation_ids,
            "prepared direct-transfer operation ids",
        )
        object.__setattr__(self, "native_ranges", native_ranges)
        object.__setattr__(self, "entry_block_ids", entry_block_ids)
        object.__setattr__(self, "terminal_block_ids", terminal_block_ids)
        object.__setattr__(self, "blocks", blocks)
        object.__setattr__(
            self,
            "direct_transfer_operation_ids",
            direct_transfer_operation_ids,
        )

    def block(self, block_id: str) -> PreparedNativeBlockFact:
        for block in self.blocks:
            if block.block_id == str(block_id):
                return block
        raise KeyError(block_id)

    @property
    def payload_signature(self) -> tuple[object, ...]:
        return tuple(
            (
                block.block_id,
                block.block_flags,
                tuple(
                    (
                        instruction.native_ea,
                        instruction.opcode,
                        instruction.operand_shape,
                    )
                    for instruction in block.instructions
                ),
            )
            for block in self.blocks
        )


@dataclass(frozen=True, slots=True)
class PreparedNativeBodyPayload:
    """Backend-local SDK objects used only during eventual realization."""

    plan_id: str
    body_id: str
    rows: tuple[tuple[str, int, tuple[tuple[int, object], ...]], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "plan_id", _identifier(self.plan_id, "plan id"))
        object.__setattr__(self, "body_id", _identifier(self.body_id, "body id"))
        rows = tuple(self.rows)
        block_ids: list[str] = []
        normalized: list[tuple[str, int, tuple[tuple[int, object], ...]]] = []
        for row in rows:
            if not isinstance(row, tuple) or len(row) != 3:
                raise TypeError("prepared payload rows must be block triples")
            block_id, block_flags, instructions = row
            block_id = _identifier(block_id, "payload block id")
            if not isinstance(block_flags, int) or isinstance(block_flags, bool):
                raise TypeError("payload block flags must be an integer")
            instruction_rows = tuple(instructions)
            for instruction_row in instruction_rows:
                if not isinstance(instruction_row, tuple) or len(instruction_row) != 2:
                    raise TypeError("payload instructions must be native-EA pairs")
                native_ea, instruction = instruction_row
                _nonnegative_int(native_ea, "payload instruction EA")
                if not hasattr(instruction, "opcode"):
                    raise TypeError("payload instruction must be an SDK instruction")
            block_ids.append(block_id)
            normalized.append((block_id, int(block_flags), instruction_rows))
        _unique(tuple(block_ids), "payload block ids")
        object.__setattr__(self, "rows", tuple(normalized))

    @property
    def semantic_signature(self) -> tuple[object, ...]:
        """Recompute the primitive signature to detect mutable payload drift."""
        return tuple(
            (
                block_id,
                block_flags,
                tuple(
                    (
                        int(native_ea),
                        int(instruction.opcode),
                        sdk_instruction_operand_shape(instruction),
                    )
                    for native_ea, instruction in instructions
                ),
            )
            for block_id, block_flags, instructions in self.rows
        )


def _operations_by_source(plan: FragmentPlan) -> Mapping[str, tuple[object, ...]]:
    source_ids = tuple(
        dict.fromkeys(operation.source_block_id for operation in plan.operations)
    )
    return {
        source_id: tuple(
            operation
            for operation in plan.operations
            if operation.source_block_id == source_id
        )
        for source_id in source_ids
    }


def _predecessors(
    native_body: FragmentNativeBody,
    operations_by_source: Mapping[str, tuple[object, ...]],
) -> dict[str, tuple[str, ...]]:
    predecessors: dict[str, list[str]] = {
        block_id: [] for block_id in native_body.block_ids
    }
    for source_block_id in native_body.block_ids:
        for operation in operations_by_source.get(source_block_id, ()):
            for edge in operation.edges:
                if edge.target_block_id in predecessors:
                    predecessors[edge.target_block_id].append(source_block_id)
    return {
        block_id: tuple(source_ids) for block_id, source_ids in predecessors.items()
    }


def _projected_terminator(
    *,
    plan: FragmentPlan,
    native_body: FragmentNativeBody,
    block_id: str,
    operations: tuple[object, ...],
    instructions: tuple[PreparedNativeInstructionFact, ...],
) -> tuple[int | None, InsnKind]:
    if block_id in native_body.terminal_block_ids:
        planned_returns = tuple(
            terminal
            for terminal in plan.terminal_returns
            if terminal.block_id == block_id
        )
        if len(planned_returns) == 1:
            return int(planned_returns[0].instruction_ea), InsnKind.RET
        if instructions and instructions[-1].kind is InsnKind.RET:
            return instructions[-1].native_ea, InsnKind.RET
        return None, InsnKind.RET
    if len(operations) != 1:
        return None, InsnKind.UNKNOWN
    operation = operations[0]
    if operation.direct_transfer_rewrite is not None:
        return (
            int(operation.direct_transfer_rewrite.rewrite_anchor_ea),
            InsnKind.GOTO,
        )
    if len(operation.edges) == 2:
        return int(operation.predicate_anchor_ea), InsnKind.COND_JUMP
    if operation.edges[0].role is SemanticEdgeRole.CALL_FALLTHROUGH:
        if instructions and instructions[-1].kind is InsnKind.CALL:
            return instructions[-1].native_ea, InsnKind.CALL
        return None, InsnKind.CALL
    if instructions and instructions[-1].kind is InsnKind.GOTO:
        return instructions[-1].native_ea, InsnKind.GOTO
    return None, InsnKind.GOTO


def build_prepared_native_body(
    *,
    plan: FragmentPlan,
    native_body: FragmentNativeBody,
    rows: tuple[tuple[str, int, tuple[tuple[int, object], ...]], ...],
    direct_transfer_operation_ids: tuple[str, ...] = (),
) -> PreparedNativeBodyPreparation:
    """Build immutable facts beside, never from, mutable payload authority."""
    operations_by_source = _operations_by_source(plan)
    predecessors = _predecessors(native_body, operations_by_source)
    payload = PreparedNativeBodyPayload(
        plan_id=plan.plan_id,
        body_id=native_body.body_id,
        rows=rows,
    )
    row_by_block_id = {row[0]: row for row in payload.rows}
    if tuple(row_by_block_id) != native_body.block_ids:
        raise ValueError("prepared payload block order differs from native body")
    expected_direct_transfer_ids = tuple(
        operation.operation_id
        for block_id in native_body.block_ids
        for operation in operations_by_source.get(block_id, ())
        if operation.direct_transfer_rewrite is not None
    )
    if tuple(direct_transfer_operation_ids) != expected_direct_transfer_ids:
        raise ValueError("prepared direct-transfer authority differs from the plan")
    blocks: list[PreparedNativeBlockFact] = []
    for block_id in native_body.block_ids:
        plan_block = plan.block(block_id)
        if not isinstance(plan_block.stable_identity, StableBlockIdentity):
            raise TypeError("prepared native block requires stable identity")
        _row_block_id, block_flags, instruction_rows = row_by_block_id[block_id]
        instructions = tuple(
            PreparedNativeInstructionFact(
                instruction_id=f"{block_id}:{index}",
                native_ea=int(native_ea),
                opcode=int(instruction.opcode),
                kind=sdk_instruction_kind(int(instruction.opcode)),
                operand_shape=sdk_instruction_operand_shape(instruction),
                writes_condition_codes=_writes_condition_codes(instruction),
            )
            for index, (native_ea, instruction) in enumerate(instruction_rows)
        )
        operations = operations_by_source.get(block_id, ())
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
        terminator_ea, terminator_kind = _projected_terminator(
            plan=plan,
            native_body=native_body,
            block_id=block_id,
            operations=operations,
            instructions=instructions,
        )
        blocks.append(
            PreparedNativeBlockFact(
                block_id=block_id,
                semantic_anchor_ea=int(plan_block.semantic_anchor_ea),
                stable_identity=plan_block.stable_identity,
                block_flags=block_flags,
                kind=kind,
                successors=successors,
                predecessor_block_ids=predecessors[block_id],
                terminator_ea=terminator_ea,
                terminator_kind=terminator_kind,
                instructions=instructions,
            )
        )
    return PreparedNativeBodyPreparation(
        fact=PreparedNativeBodyFact(
            plan_id=plan.plan_id,
            body_id=native_body.body_id,
            native_ranges=tuple(native_body.native_ranges),
            entry_block_ids=tuple(native_body.entry_block_ids),
            terminal_block_ids=tuple(native_body.terminal_block_ids),
            blocks=tuple(blocks),
            direct_transfer_operation_ids=expected_direct_transfer_ids,
        ),
        payload=payload,
    )


@dataclass(frozen=True, slots=True)
class PreparedNativeBodyPreparation:
    """Semantic/projection facts and separately scoped backend SDK payload."""

    fact: PreparedNativeBodyFact
    payload: PreparedNativeBodyPayload

    def __post_init__(self) -> None:
        if not isinstance(self.fact, PreparedNativeBodyFact):
            raise TypeError("native preparation fact must be typed")
        if not isinstance(self.payload, PreparedNativeBodyPayload):
            raise TypeError("native preparation payload must be typed")
        if (self.fact.plan_id, self.fact.body_id) != (
            self.payload.plan_id,
            self.payload.body_id,
        ):
            raise ValueError("native preparation fact and payload scope differ")
        if tuple(block.block_id for block in self.fact.blocks) != tuple(
            row[0] for row in self.payload.rows
        ):
            raise ValueError("native preparation payload blocks differ from facts")
        self.assert_payload_consistent()

    def assert_payload_consistent(self) -> None:
        if self.fact.payload_signature != self.payload.semantic_signature:
            raise ValueError(
                "native preparation payload differs from instruction facts"
            )

    def assert_authority(
        self,
        *,
        plan: FragmentPlan,
        native_body: FragmentNativeBody,
    ) -> None:
        """Reject reuse after plan, body, or mutable payload drift."""
        self.assert_payload_consistent()
        if (self.fact.plan_id, self.fact.body_id) != (
            plan.plan_id,
            native_body.body_id,
        ):
            raise ValueError("native preparation scope differs from staging authority")
        if (
            self.fact.native_ranges != native_body.native_ranges
            or self.fact.entry_block_ids != native_body.entry_block_ids
            or self.fact.terminal_block_ids != native_body.terminal_block_ids
            or tuple(block.block_id for block in self.fact.blocks)
            != native_body.block_ids
        ):
            raise ValueError("native preparation body authority changed before staging")
        operations_by_source = _operations_by_source(plan)
        predecessors = _predecessors(native_body, operations_by_source)
        expected_direct_transfer_ids = tuple(
            operation.operation_id
            for block_id in native_body.block_ids
            for operation in operations_by_source.get(block_id, ())
            if operation.direct_transfer_rewrite is not None
        )
        if self.fact.direct_transfer_operation_ids != expected_direct_transfer_ids:
            raise ValueError("native preparation direct-transfer authority drifted")
        for block_fact in self.fact.blocks:
            plan_block = plan.block(block_fact.block_id)
            operations = operations_by_source.get(block_fact.block_id, ())
            expected_successors = tuple(
                PreparedNativeEdgeFact(edge.role, edge.target_block_id)
                for operation in operations
                for edge in operation.edges
            )
            expected_kind = {
                0: BlockKind.ZERO_WAY,
                1: BlockKind.ONE_WAY,
                2: BlockKind.TWO_WAY,
            }.get(len(expected_successors), BlockKind.N_WAY)
            expected_terminator = _projected_terminator(
                plan=plan,
                native_body=native_body,
                block_id=block_fact.block_id,
                operations=operations,
                instructions=block_fact.instructions,
            )
            if (
                block_fact.semantic_anchor_ea != plan_block.semantic_anchor_ea
                or block_fact.stable_identity != plan_block.stable_identity
                or block_fact.successors != expected_successors
                or block_fact.predecessor_block_ids != predecessors[block_fact.block_id]
                or block_fact.kind is not expected_kind
                or (block_fact.terminator_ea, block_fact.terminator_kind)
                != expected_terminator
            ):
                raise ValueError("native preparation projected authority drifted")


__all__ = [
    "PreparedNativeBlockFact",
    "PreparedNativeBodyFact",
    "PreparedNativeBodyPayload",
    "PreparedNativeBodyPreparation",
    "PreparedNativeEdgeFact",
    "PreparedNativeInstructionFact",
    "build_prepared_native_body",
    "sdk_instruction_kind",
    "sdk_instruction_operand_shape",
    "sdk_operand_shape",
]
