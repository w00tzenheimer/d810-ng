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

from d810.ir.expressions import Const, ExprRef, Move
from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
from d810.ir.locations import RegisterLocation, StackSlot, StorageLocation, WeakStackSlot
from d810.ir.statements import Assignment
from d810.ir.value_refs import DefinitionRef

__all__ = ["project_assignment"]


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


def _value_of(mop: MopSnapshot | None) -> ExprRef | None:
    """Portable value expression for a source operand, else ``None``."""
    if mop is None:
        return None
    if mop.kind is OperandKind.NUMBER:
        return Const(value=int(mop.value)) if mop.value is not None else None
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
    if insn.kind is not InsnKind.MOV:
        return None
    value = _value_of(insn.l)
    target_location = _location_of(insn.d)
    target = DefinitionRef(location=target_location) if target_location is not None else None
    if value is None and target is None:
        return None
    return Assignment(target=target, value=value)
