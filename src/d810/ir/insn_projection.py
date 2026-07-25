"""Projection from the Hex-Rays-shaped ``InsnSnapshot`` onto the portable
expression/value/location/statement substrate (first cut of ``llr-lxas``).

``InsnSnapshot`` is a hybrid: topology + ``kind``/``branch_predicate`` are
portable, but its operands are still ``l``/``r``/``d`` ``MopSnapshot``s phrased
in Hex-Rays operand-position taxonomy.  The destination of the IR convergence is
for analyses to read a portable *statement* (``d810.ir.statements.Assignment``
over ``d810.ir.{expressions,value_refs,locations}``) instead of those operands.

Current scope: a behaviour-exact projection of the **MOV opcode family** into a
portable ``target := value`` assignment.  Extend opcode-family-by-family as each
analysis stops needing the live operand shape; do NOT preload the whole
microcode operation space (see ``d810.ir.semantics`` for the planned families).

Lossy by design: an operand the substrate cannot yet represent (an lvar, a
nested sub-expression) projects to ``None`` for that half, never to a wrong
value.  A stack operand whose offset is unknown projects to a
:class:`~d810.ir.locations.WeakStackSlot` (LiSA-style weak identifier), so the
imprecision is explicit rather than dropped.  Callers consume only the half
they need.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from d810.ir.expressions import Add, And, Const, ExprRef, Move, Mul, Sub, ValueOpKind
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.ir.instructions import (
    Instruction,
    InstructionControl,
    InstructionEffect,
    InstructionEffectKind,
    InstructionMemoryAccess,
    InstructionMemoryAccessKind,
    InstructionSwitchCase,
)
from d810.ir.locations import (
    RegisterLocation,
    StackSlot,
    StorageLocation,
    WeakStackSlot,
)
from d810.ir.semantics import ControlTransferKind, OperationKind
from d810.ir.statements import Assignment, ConditionalBranch
from d810.ir.value_refs import DefinitionRef
from d810.ir.varnode import Space, Varnode, varnode_from_mop_snapshot

__all__ = [
    "InstructionProjection",
    "iter_operand_exprs",
    "operand_kinds",
    "operand_stack_offsets",
    "operand_stack_refs",
    "operand_storages",
    "primary_source_operand_kind",
    "primary_source_storage",
    "project_assignment",
    "project_conditional_branch",
    "project_instruction",
    "project_instruction_sequence",
    "project_operand_expr",
    "result_storage",
]


def _instruction_attrs(insn: InsnSnapshot) -> dict[str, object]:
    """Provenance attrs for the canonical instruction projection."""
    attrs = dict(insn.opcode_attrs)
    attrs["ea"] = int(insn.ea)
    if insn.display_text:
        attrs["display_text"] = str(insn.display_text)
    # Portable backend-neutral instruction kind (provenance only).  The
    # operation enum collapses distinct branch kinds (e.g. m_jnz/m_jz
    # EQUALITY_JUMP and m_jcnd COND_JUMP both become
    # ControlTransferKind.CONDITIONAL_BRANCH), so analyses that must keep the
    # original InsnKind distinction read it from here.
    if insn.kind is not InsnKind.UNKNOWN:
        attrs.setdefault("snapshot_kind", insn.kind.value)
    raw_opcode = insn.raw_opcode if insn.raw_opcode is not None else insn.opcode
    if raw_opcode >= 0:
        attrs.setdefault("raw_opcode_int", int(raw_opcode))
    address_refs = _address_stack_refs_from_operands(insn)
    if address_refs:
        attrs["address_stack_refs"] = address_refs
    address_consts = _address_const_values_from_operands(insn)
    if address_consts:
        attrs["address_const_values"] = address_consts
    return attrs


def _address_stack_refs_from_mop(
    mop: MopSnapshot | None,
) -> tuple[int, ...]:
    """Return stack identities used inside address operands."""
    if mop is None:
        return ()
    refs: list[int] = []
    if mop.kind is OperandKind.ADDRESS:
        refs.extend(int(offset) for offset in mop.stack_refs)
    for child in (mop.sub_l, mop.sub_r, *mop.args):
        refs.extend(_address_stack_refs_from_mop(child))
    return tuple(dict.fromkeys(refs))


def _address_stack_refs_from_operands(insn: InsnSnapshot) -> tuple[int, ...]:
    refs: list[int] = []
    for mop in (insn.l, insn.r, insn.d):
        refs.extend(_address_stack_refs_from_mop(mop))
    return tuple(dict.fromkeys(refs))


def _address_const_values_from_mop(
    mop: MopSnapshot | None,
    *,
    in_address: bool = False,
) -> tuple[int, ...]:
    """Return constants used inside address operands."""
    if mop is None:
        return ()
    values: list[int] = []
    if in_address and mop.kind is OperandKind.NUMBER and mop.value is not None:
        values.append(int(mop.value))
    child_in_address = in_address or mop.kind is OperandKind.ADDRESS
    for child in (mop.sub_l, mop.sub_r, *mop.args):
        values.extend(
            _address_const_values_from_mop(child, in_address=child_in_address)
        )
    return tuple(dict.fromkeys(values))


def _address_const_values_from_operands(insn: InsnSnapshot) -> tuple[int, ...]:
    values: list[int] = []
    for mop in (insn.l, insn.r, insn.d):
        values.extend(_address_const_values_from_mop(mop))
    return tuple(dict.fromkeys(values))


def _operation_of(insn: InsnSnapshot) -> OperationKind:
    """Return the semantic operation for ``insn``.

    The order is intentional: branches use ``ControlTransferKind`` as their
    operation and keep predicate details in ``Instruction.control``; set*
    materializations have no transfer kind, so their ``PredicateKind`` becomes
    the operation.  Raw opcode attrs are never consulted here.
    """
    if insn.control_transfer_kind is not None:
        return insn.control_transfer_kind
    if insn.call_kind is not None:
        return insn.call_kind
    if insn.predicate_kind is not None:
        return insn.predicate_kind
    if insn.value_op_kind is not None:
        return insn.value_op_kind
    return ValueOpKind.VENDOR


class _VarnodeProjector:
    """Instruction-local ``MopSnapshot`` to ``Varnode`` projection.

    S1's public adapter preserves identity-key behavior and deliberately maps
    SUBINSN to UNKNOWN.  Instruction projection needs a richer statement-local
    view: nested SUBINSN trees become deterministic TEMP varnodes and their
    leaves are exposed as additional inputs.
    """

    def __init__(self) -> None:
        self._next_temp = 0
        self._subinsn_temps: dict[int, Varnode] = {}

    def one(self, mop: MopSnapshot | None) -> Varnode | None:
        if mop is None:
            return None
        if mop.kind is OperandKind.SUBINSN:
            key = id(mop)
            existing = self._subinsn_temps.get(key)
            if existing is not None:
                return existing
            temp = Varnode(Space.TEMP, self._next_temp, int(mop.size or 0))
            self._subinsn_temps[key] = temp
            self._next_temp += 1
            return temp
        vn = varnode_from_mop_snapshot(mop)
        if vn is None or vn.space is Space.UNKNOWN:
            return None
        return vn

    def input_nodes(self, mop: MopSnapshot | None) -> tuple[Varnode, ...]:
        if mop is None:
            return ()
        if mop.kind is OperandKind.ARG_LIST:
            return tuple(node for arg in mop.args for node in self.input_nodes(arg))
        if mop.kind is OperandKind.SUBINSN:
            nodes: list[Varnode] = []
            temp = self.one(mop)
            if temp is not None:
                nodes.append(temp)
            child_nodes = (*self.input_nodes(mop.sub_l), *self.input_nodes(mop.sub_r))
            if child_nodes:
                nodes.extend(child_nodes)
            else:
                nodes.extend(_stack_ref_nodes(mop))
            return tuple(nodes)
        vn = self.one(mop)
        return (vn,) if vn is not None else ()


_SUBINSN_VALUE_OPS = {
    InsnKind.MOV: ValueOpKind.MOVE,
    InsnKind.ADD: ValueOpKind.ADD,
    InsnKind.SUB: ValueOpKind.SUB,
    InsnKind.AND: ValueOpKind.AND,
    InsnKind.MUL: ValueOpKind.MUL,
}


def _stack_ref_nodes(mop: MopSnapshot) -> tuple[Varnode, ...]:
    """Expose lifted stack-ref evidence from opaque nested operands."""
    size = int(mop.size or 0)
    return tuple(Varnode(Space.STACK, int(offset), size) for offset in mop.stack_refs)


def _subinsn_value_op(mop: MopSnapshot) -> ValueOpKind:
    if mop.sub_value_op_kind is not None:
        return mop.sub_value_op_kind
    return _SUBINSN_VALUE_OPS.get(mop.sub_kind, ValueOpKind.VENDOR)


class _SequenceProjector:
    """Instruction-local lowering of nested SUBINSN operands to temp defs."""

    def __init__(self, parent: InsnSnapshot) -> None:
        self._parent = parent
        self._next_temp = 0
        self._subinsn_temps: dict[int, Varnode] = {}
        self._subinsn_lowered: set[int] = set()
        self.instructions: list[Instruction] = []

    def one(self, mop: MopSnapshot | None) -> Varnode | None:
        if mop is None:
            return None
        if mop.kind is OperandKind.SUBINSN:
            return self._ensure_subinsn(mop)
        vn = varnode_from_mop_snapshot(mop)
        if vn is None or vn.space is Space.UNKNOWN:
            return None
        return vn

    def input_nodes(self, mop: MopSnapshot | None) -> tuple[Varnode, ...]:
        if mop is not None and mop.kind is OperandKind.ARG_LIST:
            return tuple(node for arg in mop.args for node in self.input_nodes(arg))
        vn = self.one(mop)
        return (vn,) if vn is not None else ()

    def lower_sources_for(self, insn: InsnSnapshot) -> None:
        for mop in _source_operands_for_instruction(insn):
            self.one(mop)

    def _ensure_subinsn(self, mop: MopSnapshot) -> Varnode:
        key = id(mop)
        if key in self._subinsn_lowered:
            return self._subinsn_temps[key]
        self._subinsn_lowered.add(key)
        left = self.one(mop.sub_l)
        right = self.one(mop.sub_r)
        temp = self._subinsn_temps.get(key)
        if temp is None:
            temp = Varnode(Space.TEMP, self._next_temp, self._infer_temp_size(mop))
            self._subinsn_temps[key] = temp
            self._next_temp += 1
        operation = _subinsn_value_op(mop)
        if operation is ValueOpKind.MOVE:
            inputs = tuple(vn for vn in (left,) if vn is not None)
        else:
            inputs = tuple(vn for vn in (left, right) if vn is not None)
        if not inputs:
            inputs = _stack_ref_nodes(mop)
        attrs = _instruction_attrs(self._parent)
        attrs["nested_sub_kind"] = (
            mop.sub_kind.value if mop.sub_kind is not None else None
        )
        attrs["nested_sub_value_op_kind"] = (
            mop.sub_value_op_kind.value if mop.sub_value_op_kind is not None else None
        )
        if operation is ValueOpKind.VENDOR:
            attrs["unsupported_nested_sub_kind"] = attrs["nested_sub_kind"]
        self.instructions.append(
            Instruction(
                operation=operation,
                inputs=inputs,
                result=temp,
                attrs=attrs,
                input_exprs=(_value_of(mop.sub_l), _value_of(mop.sub_r)),
                operand_expr_fragments=(
                    iter_operand_exprs(mop.sub_l) + iter_operand_exprs(mop.sub_r)
                ),
            )
        )
        return temp

    def _infer_temp_size(self, mop: MopSnapshot) -> int:
        if int(mop.size or 0) > 0:
            return int(mop.size)
        child_sizes = [
            int(child.size or 0)
            for child in (mop.sub_l, mop.sub_r)
            if child is not None and int(child.size or 0) > 0
        ]
        return max(child_sizes) if child_sizes else 0


def _source_operands_for_instruction(
    insn: InsnSnapshot,
) -> tuple[MopSnapshot | None, ...]:
    if insn.control_transfer_kind is ControlTransferKind.CONDITIONAL_BRANCH:
        return (insn.l, insn.r)
    if insn.control_transfer_kind is ControlTransferKind.TABLE_BRANCH:
        return (insn.l, insn.r)
    if insn.control_transfer_kind in {
        ControlTransferKind.GOTO,
        ControlTransferKind.INDIRECT_BRANCH,
        ControlTransferKind.RETURN,
    }:
        return (insn.l, insn.r)
    if insn.call_kind is not None:
        call_operands = [insn.l, insn.r]
        if insn.d is not None and insn.d.kind is OperandKind.ARG_LIST:
            call_operands.append(insn.d)
        return tuple(call_operands)
    if insn.value_op_kind is ValueOpKind.STORE:
        return (insn.l, insn.r, insn.d)
    if insn.value_op_kind is not None or insn.predicate_kind is not None:
        return (insn.l, insn.r)
    return (insn.l, insn.r)


def _instruction_result(
    insn: InsnSnapshot, projector: _VarnodeProjector
) -> Varnode | None:
    if insn.control_transfer_kind is not None:
        return None
    if insn.value_op_kind is ValueOpKind.STORE:
        return None
    if (
        insn.value_op_kind is not None
        or insn.predicate_kind is not None
        or insn.call_kind is not None
    ):
        if (
            insn.call_kind is not None
            and insn.d is not None
            and insn.d.kind is OperandKind.ARG_LIST
        ):
            return None
        return projector.one(insn.d)
    return None


def _switch_cases_from(insn: InsnSnapshot) -> tuple[InstructionSwitchCase, ...]:
    for mop in (insn.l, insn.r, insn.d):
        if mop is None or not mop.switch_cases:
            continue
        return tuple(
            InstructionSwitchCase(values=tuple(values), target=target)
            for values, target in mop.switch_cases
        )
    return ()


def _block_target_from(mop: MopSnapshot | None) -> int | None:
    if mop is None or mop.kind is not OperandKind.BLOCK or mop.block_ref is None:
        return None
    return int(mop.block_ref)


def _first_varnode(
    projector: _VarnodeProjector,
    *mops: MopSnapshot | None,
) -> Varnode | None:
    for mop in mops:
        vn = projector.one(mop)
        if vn is not None:
            return vn
    return None


def _call_args_from(
    insn: InsnSnapshot, projector: _VarnodeProjector
) -> tuple[Varnode, ...]:
    args: list[Varnode] = []
    for mop in (insn.r, insn.d):
        if mop is None or mop.kind is not OperandKind.ARG_LIST:
            continue
        args.extend(projector.input_nodes(mop))
    return tuple(args)


def _instruction_control(
    insn: InsnSnapshot,
    projector: _VarnodeProjector,
) -> InstructionControl | None:
    transfer = insn.control_transfer_kind
    if transfer is ControlTransferKind.CONDITIONAL_BRANCH:
        return InstructionControl(
            transfer=transfer,
            predicate=insn.predicate_kind,
            target=_block_target_from(insn.d),
        )
    if transfer is ControlTransferKind.TABLE_BRANCH:
        return InstructionControl(
            transfer=transfer, switch_cases=_switch_cases_from(insn)
        )
    if transfer is ControlTransferKind.GOTO:
        return InstructionControl(transfer=transfer, target=_block_target_from(insn.l))
    if transfer is ControlTransferKind.INDIRECT_BRANCH:
        return InstructionControl(
            transfer=transfer,
            indirect_target=_first_varnode(projector, insn.l, insn.r),
        )
    if transfer is ControlTransferKind.RETURN:
        return InstructionControl(
            transfer=transfer,
            return_value=_first_varnode(projector, insn.l, insn.r),
        )
    if insn.call_kind is not None:
        return InstructionControl(
            call_kind=insn.call_kind,
            call_target=_first_varnode(projector, insn.l, insn.r),
            call_args=_call_args_from(insn, projector),
        )
    return None


def _instruction_effects(
    insn: InsnSnapshot,
    projector: _VarnodeProjector,
) -> tuple[InstructionEffect, ...]:
    if insn.call_kind is not None:
        return (
            InstructionEffect(
                kind=InstructionEffectKind.CALL,
                target=_first_varnode(projector, insn.l, insn.r),
                value=projector.one(insn.d),
                args=_call_args_from(insn, projector),
            ),
        )
    if insn.value_op_kind is ValueOpKind.STORE:
        return (
            InstructionEffect(
                kind=InstructionEffectKind.STORE,
                target=projector.one(insn.d),
                segment=projector.one(insn.r),
                value=projector.one(insn.l),
            ),
        )
    return ()


_DIRECT_CELL_SPACES = frozenset({Space.STACK, Space.GLOBAL, Space.LVAR, Space.TEMP})


def _memory_access_kind(
    target: Varnode | None,
    segment: Varnode | None,
) -> InstructionMemoryAccessKind:
    if target is None:
        return InstructionMemoryAccessKind.UNKNOWN
    if segment is not None:
        return InstructionMemoryAccessKind.INDIRECT
    if target.space in _DIRECT_CELL_SPACES:
        return InstructionMemoryAccessKind.DIRECT_CELL
    return InstructionMemoryAccessKind.INDIRECT


def _instruction_memory_access(
    insn: InsnSnapshot,
    projector: _VarnodeProjector,
) -> InstructionMemoryAccess | None:
    if insn.value_op_kind is ValueOpKind.LOAD:
        target = projector.one(insn.r)
        segment = projector.one(insn.l)
        return InstructionMemoryAccess(
            kind=_memory_access_kind(target, segment),
            target=target,
            segment=segment,
            width=int(insn.d.size) if insn.d is not None else None,
        )
    if insn.value_op_kind is ValueOpKind.STORE:
        target = projector.one(insn.d)
        segment = projector.one(insn.r)
        value = projector.one(insn.l)
        return InstructionMemoryAccess(
            kind=_memory_access_kind(target, segment),
            target=target,
            segment=segment,
            value=value,
            width=int(insn.l.size) if insn.l is not None else None,
        )
    return None


def project_instruction(insn: InsnSnapshot) -> Instruction:
    """Project ``InsnSnapshot`` to the canonical portable ``Instruction``.

    Semantic operation comes only from already-lifted vocabulary fields.  Raw
    backend opcode integer/name and lift-stage details stay in provenance attrs.
    """
    projector = _VarnodeProjector()
    inputs = tuple(
        node
        for mop in _source_operands_for_instruction(insn)
        for node in projector.input_nodes(mop)
    )
    result = _instruction_result(insn, projector)
    return Instruction(
        operation=_operation_of(insn),
        inputs=inputs,
        result=result,
        effects=_instruction_effects(insn, projector),
        control=_instruction_control(insn, projector),
        memory=_instruction_memory_access(insn, projector),
        attrs=_instruction_attrs(insn),
        input_exprs=(_value_of(insn.l), _value_of(insn.r)),
        operand_expr_fragments=(
            iter_operand_exprs(insn.l) + iter_operand_exprs(insn.r)
        ),
    )


def project_instruction_sequence(insn: InsnSnapshot) -> tuple[Instruction, ...]:
    """Project ``insn`` and explicit temp producers for nested SUBINSNs.

    ``project_instruction()`` intentionally preserves the legacy single-record
    view where nested operands expose both a root temp and leaf dependencies.
    LLVM-shaped consumers need a flat instruction stream instead: each nested
    pure sub-expression is emitted as a temp-producing instruction before the
    parent, and the parent consumes only the root temp.
    """
    projector = _SequenceProjector(insn)
    projector.lower_sources_for(insn)
    parent = Instruction(
        operation=_operation_of(insn),
        inputs=tuple(
            node
            for mop in _source_operands_for_instruction(insn)
            for node in projector.input_nodes(mop)
        ),
        result=_instruction_result(insn, projector),
        effects=_instruction_effects(insn, projector),
        control=_instruction_control(insn, projector),
        memory=_instruction_memory_access(insn, projector),
        attrs=_instruction_attrs(insn),
        input_exprs=(_value_of(insn.l), _value_of(insn.r)),
        operand_expr_fragments=(
            iter_operand_exprs(insn.l) + iter_operand_exprs(insn.r)
        ),
    )
    return (*projector.instructions, parent)


class InstructionProjection:
    """Explicit projection of a block's Hex-Rays-shaped instruction snapshots
    onto the portable canonical ``Instruction`` stream.

    ``BlockSnapshot.insn_snapshots`` is lift provenance.  The portable
    ``Instruction`` stream is a *projection* of that provenance, not stored
    block state, so it is produced here -- through an explicitly named entry
    point -- rather than exposed as a ``BlockSnapshot`` attribute.  Homing it in
    the projection layer also keeps ``d810.ir.flowgraph`` a leaf the projection
    consumes (the projection imports flowgraph, never the reverse).
    """

    __slots__ = ()

    @classmethod
    def from_block(cls, block: BlockSnapshot) -> tuple[Instruction, ...]:
        """Canonical portable instruction stream for ``block``."""
        return tuple(
            instruction
            for insn in block.insn_snapshots
            for instruction in project_instruction_sequence(insn)
        )

    @classmethod
    def from_flowgraph(cls, graph: FlowGraph) -> Mapping[int, tuple[Instruction, ...]]:
        """Canonical portable instruction stream keyed by block serial."""
        return MappingProxyType(
            {serial: cls.from_block(block) for serial, block in graph.blocks.items()}
        )


def _location_of(mop: MopSnapshot | None) -> StorageLocation | None:
    """Portable storage location for a stack/register operand, else ``None``.

    A stack operand with an unrecovered offset becomes a ``WeakStackSlot``
    rather than ``None`` -- imprecise, but still a stack write.
    """
    if mop is None:
        return None
    size = int(mop.size or 0)
    if mop.kind is OperandKind.STACK:
        if mop.stkoff is None:
            return WeakStackSlot(size=size)
        return StackSlot(offset=int(mop.stkoff), size=size)
    if mop.kind is OperandKind.REGISTER and mop.reg is not None:
        return RegisterLocation(register_id=int(mop.reg), size=size)
    return None


# Nested-operation families currently lifted from a mop_d sub-instruction.
# Extend on demand as analyses need more (m_or/m_xor/m_shl/... map to new
# ir.expressions nodes); unmapped sub-ops project to None (lossy, never wrong).
_BINOP_NODES = {
    InsnKind.ADD: Add,
    InsnKind.SUB: Sub,
    InsnKind.AND: And,
    InsnKind.MUL: Mul,
}


def _value_of(mop: MopSnapshot | None) -> ExprRef | None:
    """Portable value expression for a source operand, else ``None``.

    A ``mop_d`` (SUBINSN) operand recurses into its nested sub-operation
    (``(var & mask)`` -> ``And(Move(...), Const(...))``), so analyses can read
    the compared/computed expression *structure* (ticket llr-lxas).
    """
    if mop is None:
        return None
    if mop.kind is OperandKind.NUMBER:
        return Const(value=int(mop.value)) if mop.value is not None else None
    if mop.kind is OperandKind.SUBINSN:
        node = _BINOP_NODES.get(mop.sub_kind)
        if node is None:
            return None
        left = _value_of(mop.sub_l)
        right = _value_of(mop.sub_r)
        if left is None or right is None:
            return None
        return node(left=left, right=right)
    location = _location_of(mop)
    return (
        Move(source=DefinitionRef(location=location)) if location is not None else None
    )


def project_operand_expr(mop: MopSnapshot | None) -> ExprRef | None:
    """Project a lifted operand snapshot to a portable expression, if supported."""
    return _value_of(mop)


def iter_operand_exprs(mop: MopSnapshot | None) -> tuple[ExprRef, ...]:
    """Return projected expression fragments contained in an operand tree.

    Unsupported wrapper nodes stay provenance-only, but any supported child
    expression below them is still exposed to portable analyses.
    """
    if mop is None:
        return ()
    exprs: list[ExprRef] = []
    expr = project_operand_expr(mop)
    if expr is not None:
        exprs.append(expr)
    if mop.kind is OperandKind.SUBINSN:
        exprs.extend(iter_operand_exprs(mop.sub_l))
        exprs.extend(iter_operand_exprs(mop.sub_r))
    return tuple(exprs)


def project_assignment(insn: InsnSnapshot) -> Assignment | None:
    """Project a MOV-family ``InsnSnapshot`` to a portable assignment.

    Returns ``None`` for non-MOV instructions or when neither operand projects.
    ``value`` is a :class:`~d810.ir.expressions.Const` exactly when the source
    is a number operand, so callers that need the moved constant can test
    ``isinstance(a.value, Const)`` with the same selectivity as the live
    ``insn.l.kind is OperandKind.NUMBER`` guard it replaces.
    """
    instruction = project_instruction(insn)
    if instruction.operation is not ValueOpKind.MOVE:
        return None
    value = _value_of(insn.l)
    target_location = _location_of(insn.d)
    target = (
        DefinitionRef(location=target_location) if target_location is not None else None
    )
    if value is None and target is None:
        return None
    return Assignment(target=target, value=value)


def _storage_view(mop: MopSnapshot | None) -> Varnode | WeakStackSlot | None:
    """Portable storage view for a lifted operand snapshot.

    Returns a canonical :class:`~d810.ir.varnode.Varnode` for register /
    stack-known / lvar / const operands.  A stack operand whose concrete offset
    was not recovered (``stkoff is None``) collapses to ``Varnode(UNKNOWN)`` in
    :func:`varnode_from_mop_snapshot`; here it instead becomes the explicit
    LiSA-style :class:`~d810.ir.locations.WeakStackSlot`, so accept-on-unknown
    stack consumers keep "stack write, unknown offset" rather than losing the
    fact.  ``None`` for a missing operand.
    """
    if mop is None:
        return None
    if mop.kind is OperandKind.STACK and mop.stkoff is None:
        return WeakStackSlot(size=int(mop.size or 0))
    return varnode_from_mop_snapshot(mop)


def result_storage(insn: InsnSnapshot) -> Varnode | WeakStackSlot | None:
    """Portable storage view of the instruction's result/dest operand."""
    return _storage_view(insn.d)


def primary_source_storage(insn: InsnSnapshot) -> Varnode | WeakStackSlot | None:
    """Portable storage view of the instruction's primary source operand."""
    return _storage_view(insn.l)


def primary_source_operand_kind(insn: InsnSnapshot) -> OperandKind | None:
    """Return the portable :class:`OperandKind` of the primary source operand.

    Lift-boundary accessor (``d810.ir`` reads the backend-shaped operand slot;
    portable analyses must not).  Returns the ``insn.l`` operand kind, or
    ``None`` when there is no source operand.  This exposes the source-operand
    *classification* (e.g. ``NUMBER`` vs ``ADDRESS`` vs a value-producing
    operand) that the ``Varnode`` storage view deliberately collapses to
    ``Space.UNKNOWN`` -- the only canonical signal a carrier-source classifier
    needs to keep a constant / pointer / expression source apart.
    """
    return insn.l.kind if insn.l is not None else None


def operand_kinds(
    insn: InsnSnapshot,
) -> tuple[OperandKind | None, OperandKind | None, OperandKind | None]:
    """Return the portable :class:`OperandKind` of the ``l``/``r``/``d`` slots.

    Lift-boundary accessor (``d810.ir`` reads the backend-shaped operand slot;
    portable analyses must not).  Each entry is the operand's portable
    ``OperandKind`` (or ``None`` for an absent slot).  Pairs with
    :func:`operand_storages` so a portable analysis can keep apart operand
    *classifications* the ``Varnode`` storage view collapses -- e.g. an ``LVAR``
    destination (which :func:`~d810.ir.varnode.varnode_from_mop_snapshot`
    promotes to a ``Space.STACK`` view when a frame offset was lifted) from a
    genuine ``STACK`` destination -- preserving the exact ``kind``-gated
    behaviour of the legacy ``_is_stack_operand`` / ``_is_register_operand``
    destination locator.
    """
    return (
        insn.l.kind if insn.l is not None else None,
        insn.r.kind if insn.r is not None else None,
        insn.d.kind if insn.d is not None else None,
    )


def operand_storages(
    insn: InsnSnapshot,
) -> tuple[Varnode | WeakStackSlot | None, ...]:
    """Portable storage views of the ``l``/``r``/``d`` operand slots, in order."""
    return (_storage_view(insn.l), _storage_view(insn.r), _storage_view(insn.d))


def _mop_stack_offset(mop: MopSnapshot | None) -> int | None:
    """Stack offset an operand references: direct STACK, ADDRESS-of-stack, or a
    sole ``stack_ref``.  ``None`` otherwise.

    Mirrors the legacy ``_stack_offset_from_address`` operand decode exactly: a
    direct ``STACK`` operand yields its ``stkoff``; an ``ADDRESS`` operand
    recurses into its inner operand (``sub_l``) and otherwise falls back to a
    unique ``stack_ref``; any operand carrying exactly one ``stack_ref`` yields
    it.  This is the structural ADDRESS / ``stack_refs`` information the
    ``Varnode`` storage view deliberately collapses to ``Space.UNKNOWN``, so the
    alias-resolution analyses read it from this named lift-boundary accessor
    instead of the raw operand slot.
    """
    if mop is None:
        return None
    vn = varnode_from_mop_snapshot(mop)
    if vn is not None and vn.space is Space.STACK:
        return int(vn.offset)
    if mop.kind is OperandKind.ADDRESS:
        inner = mop.sub_l
        if inner is not None:
            return _mop_stack_offset(inner)
        refs = tuple(mop.stack_refs or ())
        if len(refs) == 1:
            return int(refs[0])
    refs = tuple(mop.stack_refs or ())
    if len(refs) == 1:
        return int(refs[0])
    return None


def operand_stack_refs(
    insn: InsnSnapshot,
) -> tuple[frozenset[int], frozenset[int], frozenset[int]]:
    """Per-slot set of stack offsets each ``l``/``r``/``d`` operand references.

    Lift-boundary accessor (``d810.ir`` reads the backend-shaped operand slot;
    portable analyses must not).  Each entry is the operand's ``stack_refs`` set
    (the stack offsets flattened from its possibly-nested operand tree -- a
    direct stack cell, or every stack leaf of a compared sub-expression), so a
    portable analysis can membership-test ``state_var_stkoff in refs`` exactly as
    the legacy ``insn.l.stack_refs`` / ``insn.r.stack_refs`` read did, including
    operands that reference several stack slots.  Empty set for an absent slot.
    """
    return (
        frozenset(
            int(off) for off in (insn.l.stack_refs if insn.l is not None else ())
        ),
        frozenset(
            int(off) for off in (insn.r.stack_refs if insn.r is not None else ())
        ),
        frozenset(
            int(off) for off in (insn.d.stack_refs if insn.d is not None else ())
        ),
    )


def operand_stack_offsets(
    insn: InsnSnapshot,
) -> tuple[int | None, int | None, int | None]:
    """Per-slot referenced stack offset for the ``l``/``r``/``d`` operands.

    Lift-boundary accessor (``d810.ir`` reads the backend-shaped operand slot;
    portable analyses must not).  Each entry is the stack offset the operand
    *names* -- a direct stack cell, the address of a stack cell, or a sole
    lifted ``stack_ref`` -- exactly as the legacy
    ``_stack_offset_from_address`` decode produced, or ``None`` when the operand
    references no single stack slot.  Lets alias-resolution analyses recover a
    state write performed through ``&state_slot`` materialized in a register
    without decoding the ADDRESS / ``stack_refs`` operand tree themselves.
    """
    return (
        _mop_stack_offset(insn.l),
        _mop_stack_offset(insn.r),
        _mop_stack_offset(insn.d),
    )


def project_conditional_branch(
    insn: InsnSnapshot,
    *,
    taken: int | None = None,
    fallthrough: int | None = None,
) -> ConditionalBranch | None:
    """Project a conditional-jump ``InsnSnapshot`` to a portable branch.

    Returns ``None`` for non-conditional-jump instructions.  ``predicate`` is the
    already-portable :class:`~d810.ir.semantics.PredicateKind` carried on the
    snapshot (may be ``None``); ``lhs``/``rhs`` are the compared operands as
    value expressions.  ``taken``/``fallthrough`` are the two CFG-edge serials,
    supplied by the caller (the snapshot itself does not carry block topology).
    """
    if not getattr(insn, "is_conditional_jump", False):
        return None
    return ConditionalBranch(
        predicate=insn.branch_predicate,
        lhs=_value_of(insn.l),
        rhs=_value_of(insn.r),
        taken=taken,
        fallthrough=fallthrough,
    )
