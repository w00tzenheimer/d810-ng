"""Immutable semantic facts separated from backend-local realization payloads."""

from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Mapping
from d810.hexrays.ir.flag_queries import (
    ConditionCodeQueryUnavailable,
    instruction_writes_condition_codes,
)
from d810.hexrays.mutation.semantic_fragment_inventory import (
    SemanticFragmentRootInventory,
)
from d810.ir.block_identity import StableBlockIdentity
from d810.ir.flowgraph import BlockKind, InsnKind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.transforms.cfg_transaction import CfgProjection, TransactionAttemptId
from d810.transforms.fragment_plan import (
    FragmentNativeBody,
    FragmentPlan,
    FragmentReturnSource,
)
from d810.transforms.fragment_projection import FragmentProjectionInput
from d810.transforms.fragment_validation import ProjectedFragment
from d810.transforms.prepared_native_body import (
    PreparedNativeBlockFact,
    PreparedNativeBodyFact,
    PreparedNativeEdgeFact,
    PreparedNativeInstructionFact,
)


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


def sdk_operand_shape(operand: object, *, depth: int = 3) -> tuple[object, ...]:
    """Project an SDK operand into primitive shape without block coordinates."""
    import ida_hexrays

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
    import ida_hexrays

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


def sdk_owned_call(owner: object | None) -> object | None:
    """Return one top-level or nested call owned by an SDK instruction."""
    import ida_hexrays

    if owner is None:
        return None
    pending = [owner]
    visited: set[int] = set()
    calls: list[object] = []
    while pending:
        instruction = pending.pop()
        identity = id(instruction)
        if identity in visited:
            continue
        visited.add(identity)
        if int(getattr(instruction, "opcode", -1)) in {
            int(ida_hexrays.m_call),
            int(ida_hexrays.m_icall),
        }:
            calls.append(instruction)
        for operand_name in ("l", "r", "d"):
            operand = getattr(instruction, operand_name, None)
            if (
                operand is not None
                and int(getattr(operand, "t", -1)) == int(ida_hexrays.mop_d)
                and getattr(operand, "d", None) is not None
            ):
                pending.append(operand.d)
    return calls[0] if len(calls) == 1 else None


def _writes_condition_codes(instruction: object) -> bool | None:
    try:
        return bool(instruction_writes_condition_codes(instruction))
    except ConditionCodeQueryUnavailable:
        return None


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
    instruction_rows: tuple[tuple[int, object], ...],
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
        call_owner_eas = tuple(
            int(native_ea)
            for native_ea, instruction in instruction_rows
            if sdk_owned_call(instruction) is not None
        )
        if len(call_owner_eas) != 1:
            raise ValueError("prepared call fallthrough requires one exact call owner")
        return call_owner_eas[0], InsnKind.CALL
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
            instruction_rows=instruction_rows,
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
        instruction_rows_by_block_id = {
            block_id: tuple(instruction_rows)
            for block_id, _block_flags, instruction_rows in self.payload.rows
        }
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
                instruction_rows=instruction_rows_by_block_id[block_fact.block_id],
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


@dataclass(frozen=True, slots=True)
class PreparedReturnCarrierConstruction:
    """Portable return-carrier construction facts captured before mutation."""

    carrier_id: str
    source: FragmentReturnSource
    return_width: int
    return_mreg: int
    operand_shape: tuple[object, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "carrier_id",
            _identifier(self.carrier_id, "carrier id"),
        )
        if not isinstance(self.source, FragmentReturnSource):
            raise TypeError("prepared carrier source must be portable")
        object.__setattr__(
            self,
            "return_width",
            _nonnegative_int(self.return_width, "return width"),
        )
        object.__setattr__(
            self,
            "return_mreg",
            _nonnegative_int(self.return_mreg, "return mreg"),
        )
        if self.return_width == 0:
            raise ValueError("prepared carrier width must be positive")
        object.__setattr__(self, "operand_shape", tuple(self.operand_shape))


@dataclass(frozen=True, slots=True)
class SemanticFragmentRealizationPayload:
    """Backend-local SDK payload with no semantic authority."""

    native_body_rows: tuple[
        tuple[str, tuple[tuple[str, int, tuple[tuple[int, object], ...]], ...]],
        ...,
    ]
    return_carrier_operands: tuple[tuple[str, object], ...]

    def __post_init__(self) -> None:
        native_body_rows = tuple(self.native_body_rows)
        return_carrier_operands = tuple(self.return_carrier_operands)
        body_ids = tuple(
            _identifier(str(body_id), "payload body id")
            for body_id, _rows in native_body_rows
        )
        carrier_ids = tuple(
            _identifier(str(carrier_id), "payload carrier id")
            for carrier_id, _operand in return_carrier_operands
        )
        _unique(body_ids, "payload body ids")
        _unique(carrier_ids, "payload carrier ids")
        object.__setattr__(self, "native_body_rows", native_body_rows)
        object.__setattr__(
            self,
            "return_carrier_operands",
            return_carrier_operands,
        )


@dataclass(frozen=True, slots=True)
class SemanticFragmentSnapshotAuthority:
    """Immutable live-MBA evidence captured while the gateway is idle."""

    plan_id: str
    atomic_group_id: str
    session_id: str
    generation: int
    projection_input: FragmentProjectionInput
    native_bodies: tuple[PreparedNativeBodyFact, ...]
    return_carrier_constructions: tuple[PreparedReturnCarrierConstruction, ...]

    def __post_init__(self) -> None:
        for name in ("plan_id", "atomic_group_id", "session_id"):
            object.__setattr__(
                self,
                name,
                _identifier(getattr(self, name), name),
            )
        object.__setattr__(
            self,
            "generation",
            _nonnegative_int(self.generation, "snapshot generation"),
        )
        if not isinstance(self.projection_input, FragmentProjectionInput):
            raise TypeError("snapshot authority requires typed projection input")
        native_bodies = tuple(self.native_bodies)
        carrier_constructions = tuple(self.return_carrier_constructions)
        if any(not isinstance(body, PreparedNativeBodyFact) for body in native_bodies):
            raise TypeError("snapshot native bodies must be typed facts")
        if any(body.plan_id != self.plan_id for body in native_bodies):
            raise ValueError("snapshot native body belongs to another plan")
        if any(
            not isinstance(item, PreparedReturnCarrierConstruction)
            for item in carrier_constructions
        ):
            raise TypeError("snapshot return carriers must be typed facts")
        _unique(tuple(body.body_id for body in native_bodies), "native body ids")
        _unique(
            tuple(item.carrier_id for item in carrier_constructions),
            "return carrier ids",
        )
        object.__setattr__(self, "native_bodies", native_bodies)
        object.__setattr__(
            self,
            "return_carrier_constructions",
            carrier_constructions,
        )


@dataclass(frozen=True, slots=True)
class SemanticFragmentSnapshotPreparation:
    """Immutable snapshot authority paired with non-authoritative SDK payload."""

    authority: SemanticFragmentSnapshotAuthority
    payload: SemanticFragmentRealizationPayload

    def __post_init__(self) -> None:
        if not isinstance(self.authority, SemanticFragmentSnapshotAuthority):
            raise TypeError("semantic snapshot requires typed authority")
        if not isinstance(self.payload, SemanticFragmentRealizationPayload):
            raise TypeError("semantic snapshot requires typed realization payload")
        body_ids = tuple(body.body_id for body in self.authority.native_bodies)
        payload_body_ids = tuple(
            body_id for body_id, _rows in self.payload.native_body_rows
        )
        carrier_ids = tuple(
            item.carrier_id for item in self.authority.return_carrier_constructions
        )
        payload_carrier_ids = tuple(
            carrier_id for carrier_id, _operand in self.payload.return_carrier_operands
        )
        if body_ids != payload_body_ids or carrier_ids != payload_carrier_ids:
            raise ValueError("semantic snapshot payload keysets differ from facts")


@dataclass(frozen=True, slots=True)
class PreparedSemanticFragmentAuthority:
    """Exact, single-use authority for one preflighted realization attempt."""

    plan_id: str
    atomic_group_id: str
    session_id: str
    generation: int
    snapshot_id: str
    attempt_id: TransactionAttemptId
    root_inventory: SemanticFragmentRootInventory
    snapshot: SemanticFragmentSnapshotAuthority
    projection: ProjectedFragment
    cfg_projection: CfgProjection

    def __post_init__(self) -> None:
        for name in ("plan_id", "atomic_group_id", "session_id", "snapshot_id"):
            object.__setattr__(
                self,
                name,
                _identifier(getattr(self, name), name),
            )
        generation = _nonnegative_int(
            self.generation,
            "prepared fragment generation",
        )
        object.__setattr__(self, "generation", generation)
        if not isinstance(self.attempt_id, TransactionAttemptId):
            raise TypeError("prepared fragment attempt must be typed")
        if not isinstance(self.root_inventory, SemanticFragmentRootInventory):
            raise TypeError("prepared fragment root inventory must be typed")
        if not isinstance(self.snapshot, SemanticFragmentSnapshotAuthority):
            raise TypeError("prepared fragment snapshot must be typed")
        if not isinstance(self.projection, ProjectedFragment):
            raise TypeError("prepared fragment projection must be typed")
        if not isinstance(self.cfg_projection, CfgProjection):
            raise TypeError("prepared fragment CFG projection must be typed")
        if (
            self.attempt_id.plan_id != self.plan_id
            or self.attempt_id.session_id != self.session_id
            or self.attempt_id.generation != generation
            or self.snapshot.plan_id != self.plan_id
            or self.snapshot.atomic_group_id != self.atomic_group_id
            or self.snapshot.session_id != self.session_id
            or self.snapshot.generation != generation
            or self.snapshot.projection_input.snapshot_id != self.snapshot_id
            or self.root_inventory.plan_id != self.plan_id
            or self.root_inventory.atomic_group_id != self.atomic_group_id
            or self.cfg_projection.plan_id != self.plan_id
            or self.cfg_projection.snapshot_id != self.snapshot_id
        ):
            raise ValueError("prepared fragment authority scope is inconsistent")

    @property
    def root_inventory_signature(
        self,
    ) -> tuple[tuple[str, str, str, str, str, bool], ...]:
        return tuple(
            (
                item.edge_id,
                item.root_block_id,
                item.original_block_id,
                item.predecessor_block_id,
                item.role.value,
                item.requires_helper,
            )
            for item in self.root_inventory.items
        )


@dataclass(frozen=True, slots=True)
class PreparedSemanticFragment:
    """Preflight authority plus backend payload for one exact attempt."""

    authority: PreparedSemanticFragmentAuthority
    payload: SemanticFragmentRealizationPayload

    def __post_init__(self) -> None:
        if not isinstance(self.authority, PreparedSemanticFragmentAuthority):
            raise TypeError("prepared semantic fragment requires typed authority")
        if not isinstance(self.payload, SemanticFragmentRealizationPayload):
            raise TypeError("prepared semantic fragment requires typed payload")
        body_ids = tuple(body.body_id for body in self.authority.snapshot.native_bodies)
        payload_body_ids = tuple(
            body_id for body_id, _rows in self.payload.native_body_rows
        )
        carrier_ids = tuple(
            item.carrier_id
            for item in self.authority.snapshot.return_carrier_constructions
        )
        payload_carrier_ids = tuple(
            carrier_id for carrier_id, _operand in self.payload.return_carrier_operands
        )
        if body_ids != payload_body_ids or carrier_ids != payload_carrier_ids:
            raise ValueError("prepared fragment payload keysets differ from facts")


__all__ = [
    "PreparedNativeBodyPayload",
    "PreparedNativeBodyPreparation",
    "PreparedReturnCarrierConstruction",
    "PreparedSemanticFragment",
    "PreparedSemanticFragmentAuthority",
    "SemanticFragmentRealizationPayload",
    "SemanticFragmentSnapshotAuthority",
    "SemanticFragmentSnapshotPreparation",
    "build_prepared_native_body",
    "sdk_instruction_kind",
    "sdk_instruction_operand_shape",
    "sdk_operand_shape",
]
