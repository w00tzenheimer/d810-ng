"""Projection from the Hex-Rays-shaped ``InsnSnapshot`` onto the portable
expression/value/location substrate (proof-of-shape, first cut of ``llr-lxas``).

``InsnSnapshot`` is a hybrid: topology + ``kind``/``branch_predicate`` are
portable, but its operands are still ``l``/``r``/``d`` ``MopSnapshot``s phrased
in Hex-Rays operand-position taxonomy.  The destination of the IR convergence is
for analyses to read a portable *operation* (``d810.ir.{expressions,value_refs,
locations}``) instead of those operands.

This module is the first wire-up: a behaviour-exact projection of the **MOV
opcode family** into a portable ``(target, value)`` assignment over the existing
substrate types.  It is deliberately narrow -- one family, no new core substrate
type (``LiftedAssignment`` is the minimal statement-level wrapper that a full
lift would eventually promote into ``d810.ir``).  Extend opcode-family-by-family
as each analysis stops needing the live operand shape; do NOT preload the whole
microcode operation space (see ``d810.ir.semantics`` for the planned families).

Lossy by design: an operand the substrate cannot yet represent (an unknown
stack offset, an lvar, a nested sub-expression) projects to ``None`` for that
half, never to a wrong value.  Callers consume only the half they need.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.ir.expressions import Const, ExprRef, Move
from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
from d810.ir.locations import RegisterLocation, StackSlot, StorageLocation
from d810.ir.value_refs import DefinitionRef, ValueRef

__all__ = ["LiftedAssignment", "project_assignment"]


@dataclass(frozen=True)
class LiftedAssignment:
    """A portable ``target := value`` produced by projecting one instruction.

    Either half may be ``None`` when the corresponding operand falls outside
    the portable substrate's current vocabulary (the projection is lossy, never
    lossy-into-a-wrong-value).
    """

    target: ValueRef | None
    value: ExprRef | None


def _location_of(mop: MopSnapshot | None) -> StorageLocation | None:
    """Portable storage location for a stack/register operand, else ``None``."""
    if mop is None:
        return None
    size = int(mop.size or 0)
    if mop.kind is OperandKind.STACK and mop.stkoff is not None:
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


def project_assignment(insn: InsnSnapshot) -> LiftedAssignment | None:
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
    return LiftedAssignment(target=target, value=value)
