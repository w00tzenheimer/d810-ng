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

from d810.ir.expressions import Add, And, Const, ExprRef, Move, Sub, ValueOpKind
from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
from d810.ir.instructions import (
    Instruction,
    InstructionControl,
    InstructionEffect,
    InstructionEffectKind,
    InstructionSwitchCase,
)
from d810.ir.locations import RegisterLocation, StackSlot, StorageLocation, WeakStackSlot
from d810.ir.semantics import ControlTransferKind, OperationKind
from d810.ir.statements import Assignment, ConditionalBranch
from d810.ir.value_refs import DefinitionRef
from d810.ir.varnode import Space, Varnode, varnode_from_mop_snapshot

__all__ = [
    "project_assignment",
    "project_conditional_branch",
    "project_instruction",
    "project_instruction_sequence",
]


def _instruction_attrs(insn: InsnSnapshot) -> dict[str, object]:
    """Provenance attrs for the canonical instruction projection."""
    attrs = dict(insn.opcode_attrs)
    attrs["ea"] = int(insn.ea)
    raw_opcode = insn.raw_opcode if insn.raw_opcode is not None else insn.opcode
    if raw_opcode >= 0:
        attrs.setdefault("raw_opcode_int", int(raw_opcode))
    return attrs


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
        if mop.kind is OperandKind.SUBINSN:
            nodes: list[Varnode] = []
            temp = self.one(mop)
            if temp is not None:
                nodes.append(temp)
            nodes.extend(self.input_nodes(mop.sub_l))
            nodes.extend(self.input_nodes(mop.sub_r))
            return tuple(nodes)
        vn = self.one(mop)
        return (vn,) if vn is not None else ()


_SUBINSN_VALUE_OPS = {
    InsnKind.MOV: ValueOpKind.MOVE,
    InsnKind.ADD: ValueOpKind.ADD,
    InsnKind.SUB: ValueOpKind.SUB,
    InsnKind.AND: ValueOpKind.AND,
}


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
        return (insn.l, insn.r)
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


def _instruction_control(
    insn: InsnSnapshot,
    projector: _VarnodeProjector,
) -> InstructionControl | None:
    transfer = insn.control_transfer_kind
    if transfer is ControlTransferKind.CONDITIONAL_BRANCH:
        return InstructionControl(transfer=transfer, predicate=insn.predicate_kind)
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
        attrs=_instruction_attrs(insn),
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
        attrs=_instruction_attrs(insn),
    )
    return (*projector.instructions, parent)


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
