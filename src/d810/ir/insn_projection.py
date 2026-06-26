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

import json
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
from d810.ir.locations import RegisterLocation, StackSlot, StorageLocation, WeakStackSlot
from d810.ir.semantics import ControlTransferKind, OperationKind
from d810.ir.statements import Assignment, ConditionalBranch
from d810.ir.value_refs import DefinitionRef
from d810.ir.varnode import Space, Varnode, varnode_from_mop_snapshot

__all__ = [
    "InstructionProjection",
    "iter_operand_exprs",
    "operand_storages",
    "parse_diag_meta_operand",
    "primary_source_storage",
    "project_assignment",
    "project_conditional_branch",
    "project_diag_instruction",
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
        values.extend(_address_const_values_from_mop(child, in_address=child_in_address))
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
            return tuple(
                node
                for arg in mop.args
                for node in self.input_nodes(arg)
            )
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
            return tuple(
                node
                for arg in mop.args
                for node in self.input_nodes(arg)
            )
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
        attrs["nested_sub_kind"] = mop.sub_kind.value if mop.sub_kind is not None else None
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


def _source_operands_for_instruction(insn: InsnSnapshot) -> tuple[MopSnapshot | None, ...]:
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


def _instruction_result(insn: InsnSnapshot, projector: _VarnodeProjector) -> Varnode | None:
    if insn.control_transfer_kind is not None:
        return None
    if insn.value_op_kind is ValueOpKind.STORE:
        return None
    if (
        insn.value_op_kind is not None
        or insn.predicate_kind is not None
        or insn.call_kind is not None
    ):
        if insn.call_kind is not None and insn.d is not None and insn.d.kind is OperandKind.ARG_LIST:
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


def _call_args_from(insn: InsnSnapshot, projector: _VarnodeProjector) -> tuple[Varnode, ...]:
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
        return InstructionControl(transfer=transfer, switch_cases=_switch_cases_from(insn))
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
    def from_flowgraph(
        cls, graph: FlowGraph
    ) -> Mapping[int, tuple[Instruction, ...]]:
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
    return Move(source=DefinitionRef(location=location)) if location is not None else None


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
    target = DefinitionRef(location=target_location) if target_location is not None else None
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


def operand_storages(
    insn: InsnSnapshot,
) -> tuple[Varnode | WeakStackSlot | None, ...]:
    """Portable storage views of the ``l``/``r``/``d`` operand slots, in order."""
    return (_storage_view(insn.l), _storage_view(insn.r), _storage_view(insn.d))


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


# ---------------------------------------------------------------------------
# Diag-DB row -> canonical Instruction lift (llr-3b41 S0 spike).
#
# The production diag ``meta`` JSON (built by
# ``d810.hexrays.mba_serializer._instruction_operands_meta`` /
# ``_mop_to_meta``) is a recursive operand tree keyed by ``l`` / ``r`` / ``d``.
# It is isomorphic to ``MopSnapshot`` / ``InsnSnapshot``, so a diag row (a
# ``d810.core.observability_models.InstructionSnapshot`` or the equivalent
# SQLite row) can be projected onto the SAME canonical ``Instruction`` the live
# block path produces -- without any Hex-Rays import.  This stays in ``d810.ir``
# (a leaf below ``d810.analyses`` / ``d810.hexrays``), so it must reach for no
# layer above it; the int->OperandKind map below is kept in lock-step with the
# serializer's ``mop.t`` (``_mop_type_name``) source by literal value.
# ---------------------------------------------------------------------------

# ``type_num`` is ``int(mop.t)`` from the serializer; the values below MUST
# track the Hex-Rays ``mopt_t`` enum the serializer reads (see
# ``hexrays.hpp`` ``mop_z..mop_sc`` 0..15 and ``_mop_type_name``).
_TYPE_NUM_TO_OPERAND_KIND: Mapping[int, OperandKind] = MappingProxyType(
    {
        0: OperandKind.EMPTY,      # mop_z
        1: OperandKind.REGISTER,   # mop_r
        2: OperandKind.NUMBER,     # mop_n
        3: OperandKind.STRING,     # mop_str
        4: OperandKind.SUBINSN,    # mop_d
        5: OperandKind.STACK,      # mop_S
        6: OperandKind.GLOBAL,     # mop_v
        7: OperandKind.BLOCK,      # mop_b
        8: OperandKind.ARG_LIST,   # mop_f
        9: OperandKind.LVAR,       # mop_l
        10: OperandKind.ADDRESS,   # mop_a
        11: OperandKind.HELPER,    # mop_h
        12: OperandKind.CASE_LIST, # mop_c
        13: OperandKind.FP_CONST,  # mop_fn
        14: OperandKind.PAIR,      # mop_p
        15: OperandKind.SCATTERED, # mop_sc
    }
)

# opcode_name (diag string) -> portable InsnKind.  Accepts both the Hex-Rays
# ``m_*`` spelling captured by the serializer and the portable enum spellings,
# so a diag row resolves to the same semantic operation the live path infers.
_OPCODE_NAME_TO_INSN_KIND: Mapping[str, InsnKind] = MappingProxyType(
    {
        "m_mov": InsnKind.MOV,
        "mov": InsnKind.MOV,
        "m_ldx": InsnKind.LOAD,
        "load": InsnKind.LOAD,
        "m_stx": InsnKind.STORE,
        "store": InsnKind.STORE,
        "m_add": InsnKind.ADD,
        "add": InsnKind.ADD,
        "m_sub": InsnKind.SUB,
        "sub": InsnKind.SUB,
        "m_and": InsnKind.AND,
        "and": InsnKind.AND,
        "m_mul": InsnKind.MUL,
        "mul": InsnKind.MUL,
        "m_xdu": InsnKind.XDU,
        "xdu": InsnKind.XDU,
        "m_xds": InsnKind.XDS,
        "xds": InsnKind.XDS,
        "m_goto": InsnKind.GOTO,
        "goto": InsnKind.GOTO,
        "m_ret": InsnKind.RET,
        "ret": InsnKind.RET,
    }
)


def _coerce_global_ea(value: object) -> int | None:
    """Coerce a serializer ``global_ea`` field (``"0x%x"`` string) to int."""
    if value is None:
        return None
    if isinstance(value, int):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def parse_diag_meta_operand(meta_node: Mapping | None) -> MopSnapshot | None:
    """Project one diag ``meta`` operand node onto a portable ``MopSnapshot``.

    ``meta_node`` is one ``l`` / ``r`` / ``d`` (or nested ``sub_instruction`` /
    ``sub_operand`` / ``args``) dict produced by the serializer's
    ``_mop_to_meta``.  Recurses through ``sub_instruction`` (mop_d) and
    ``sub_operand`` (mop_a); ``args`` (mop_f) lists become nested portable
    operands.  Returns ``None`` for an empty / absent node.
    """
    if not isinstance(meta_node, Mapping):
        return None
    type_num = meta_node.get("type_num")
    if type_num is None:
        return None
    type_num = int(type_num)
    kind = _TYPE_NUM_TO_OPERAND_KIND.get(type_num, OperandKind.UNKNOWN)
    if kind is OperandKind.EMPTY:
        return None
    size = int(meta_node.get("size") or 0)

    value = meta_node.get("value")
    register = meta_node.get("register")
    stkoff = meta_node.get("stkoff")
    block_num = meta_node.get("block_num")
    lvar_idx = meta_node.get("lvar_idx")
    gaddr = _coerce_global_ea(meta_node.get("global_ea"))

    sub_l: MopSnapshot | None = None
    sub_r: MopSnapshot | None = None
    sub_kind: InsnKind | None = None
    sub_value_op_kind: ValueOpKind | None = None
    if kind is OperandKind.SUBINSN:
        sub_insn = meta_node.get("sub_instruction")
        if isinstance(sub_insn, Mapping):
            sub_kind = _OPCODE_NAME_TO_INSN_KIND.get(
                str(sub_insn.get("opcode_name") or "")
            )
            if sub_kind is not None:
                sub_value_op_kind = _SUBINSN_VALUE_OPS.get(sub_kind)
            sub_l = parse_diag_meta_operand(sub_insn.get("l"))
            sub_r = parse_diag_meta_operand(sub_insn.get("r"))
    elif kind is OperandKind.ADDRESS:
        # mop_a wraps a single inner operand under ``sub_operand``.
        sub_l = parse_diag_meta_operand(meta_node.get("sub_operand"))

    args: tuple[MopSnapshot, ...] = ()
    if kind is OperandKind.ARG_LIST:
        raw_args = meta_node.get("args")
        if isinstance(raw_args, (list, tuple)):
            args = tuple(
                arg
                for arg in (parse_diag_meta_operand(node) for node in raw_args)
                if arg is not None
            )

    stack_refs = _collect_stack_refs(kind, stkoff, sub_l, sub_r, args)

    return MopSnapshot(
        t=type_num,
        size=size,
        value=int(value) if value is not None else None,
        stkoff=int(stkoff) if stkoff is not None else None,
        reg=int(register) if register is not None else None,
        block_ref=int(block_num) if block_num is not None else None,
        gaddr=gaddr,
        lvar_off=int(lvar_idx) if lvar_idx is not None else None,
        stack_refs=stack_refs,
        kind=kind,
        sub_kind=sub_kind,
        sub_value_op_kind=sub_value_op_kind,
        sub_l=sub_l,
        sub_r=sub_r,
        args=args,
    )


def _collect_stack_refs(
    kind: OperandKind,
    stkoff: object,
    sub_l: MopSnapshot | None,
    sub_r: MopSnapshot | None,
    args: tuple[MopSnapshot, ...],
) -> tuple[int, ...]:
    """Flatten stack offsets reachable from a (possibly nested) operand."""
    refs: list[int] = []
    if kind is OperandKind.STACK and stkoff is not None:
        refs.append(int(stkoff))
    for child in (sub_l, sub_r, *args):
        if child is not None:
            refs.extend(child.stack_refs)
            if child.kind is OperandKind.STACK and child.stkoff is not None:
                refs.append(int(child.stkoff))
    return tuple(dict.fromkeys(refs))


def _row_field(row: object, name: str) -> object:
    """Read ``name`` from a diag row (dataclass attr or mapping key)."""
    if isinstance(row, Mapping):
        return row.get(name)
    return getattr(row, name, None)


def _row_int(row: object, name: str) -> int | None:
    value = _row_field(row, name)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _row_value(row: object, hex_name: str, i64_name: str, plain_name: str) -> int | None:
    """Coerce a diag value field to int across both row origins.

    DB-origin rows carry a dual ``*_hex`` (``"0x%x"`` string) + ``*_i64`` pair;
    the in-memory ``observability_models.InstructionSnapshot`` carries a single
    plain ``*`` int.  The hex column is authoritative for unsigned 64-bit
    fidelity; fall back to the i64 column then the plain field.
    """
    hex_value = _row_field(row, hex_name)
    if isinstance(hex_value, str) and hex_value:
        try:
            return int(hex_value, 0)
        except ValueError:
            pass
    i64_value = _row_field(row, i64_name)
    if i64_value is not None:
        try:
            return int(i64_value)
        except (TypeError, ValueError):
            pass
    return _row_int(row, plain_name)


def _diag_meta_payload(row: object) -> Mapping[str, object]:
    raw = _row_field(row, "meta")
    if isinstance(raw, Mapping):
        return raw
    if isinstance(raw, str) and raw:
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError):
            return {}
        return payload if isinstance(payload, Mapping) else {}
    return {}


def diag_row_has_operand_tree(row: object) -> bool:
    """Return whether ``row`` carries a parseable diag ``meta`` operand tree.

    A production DB-replay / ``observability_models.InstructionSnapshot`` row may
    carry a recursive ``_instruction_operands_meta``-shaped ``meta`` JSON whose
    ``l`` / ``r`` / ``d`` nodes project to portable operands.  Such *meta-rich*
    rows can be lifted faithfully via :func:`project_diag_instruction`.

    A *meta-less* row -- one whose ``meta`` is absent / empty / carries only
    attrs (e.g. ``{"byte_index": 1}``) with no operand tree -- returns ``False``
    so callers keep reading the flat ``src_l_*`` / ``dest_*`` fields (the
    canonical projection only reads the operand tree, never the flat fields, so
    routing a meta-less row through it would drop those facts).
    """
    meta = _diag_meta_payload(row)
    if not meta:
        return False
    return any(
        parse_diag_meta_operand(meta.get(slot)) is not None
        for slot in ("l", "r", "d")
    )


def project_diag_instruction(row: object) -> Instruction:
    """Project a production diag instruction row onto the canonical
    ``Instruction``.

    ``row`` is a ``d810.core.observability_models.InstructionSnapshot`` (or the
    equivalent SQLite ``instructions`` row -- dataclass *or* mapping).  Flat
    fields plus the recursive ``meta`` ``l`` / ``r`` / ``d`` operand tree are
    rebuilt into an :class:`~d810.ir.flowgraph.InsnSnapshot`, then projected
    through the existing :func:`project_instruction` machinery so the result is
    byte-for-byte the canonical projection the live block path produces.
    """
    meta = _diag_meta_payload(row)
    l = parse_diag_meta_operand(meta.get("l"))
    r = parse_diag_meta_operand(meta.get("r"))
    d = parse_diag_meta_operand(meta.get("d"))

    opcode_name = str(_row_field(row, "opcode_name") or "")
    kind = _OPCODE_NAME_TO_INSN_KIND.get(opcode_name, InsnKind.UNKNOWN)
    opcode = _row_int(row, "opcode")
    if opcode is None:
        opcode = -1
    ea = _row_int(row, "ea")
    if ea is None:
        ea = 0
    dstr = str(_row_field(row, "dstr") or "")

    opcode_attrs = {"raw_opcode_name": opcode_name} if opcode_name else {}

    insn = InsnSnapshot(
        opcode=opcode,
        ea=ea,
        operands=(),
        display_text=dstr,
        l=l,
        r=r,
        d=d,
        kind=kind,
        opcode_attrs=opcode_attrs,
    )
    return project_instruction(insn)
