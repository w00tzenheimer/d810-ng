"""Portable statement substrate (VEX ``Ist_*`` / LiSA ``Assignment`` level).

The expression layer (``d810.ir.expressions``, the ``IRExpr`` /
``SymbolicExpression`` level) describes *values*; this layer describes the
*effect* of an instruction -- which target a value is bound to.

Microcode at ``MMAT_GLBOPT1`` is not SSA, so the target is a storage *location*
(a :class:`~d810.ir.value_refs.DefinitionRef` over a
:class:`~d810.ir.locations.StorageLocation`), namespace-dispatched the way VEX
splits ``Ist_WrTmp`` (temp) / ``Ist_Put`` (register) / ``Ist_Store`` (memory) --
unified here into one node because ``d810.ir.locations`` already unifies those
namespaces.  ``TemporaryRef`` / ``SSAValueRef`` targets stay available for a
future SSA pass without changing this node.

Minimum viable scope: ``Assignment`` (``target := value``).  Extend with
control-transfer / call / guard statements on demand -- do NOT preload the
statement universe (see ``d810.ir.semantics`` for the planned families).
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.ir.expressions import ExprRef
from d810.ir.value_refs import ValueRef

__all__ = ["Assignment"]


@dataclass(frozen=True)
class Assignment:
    """A portable ``target := value`` produced by lifting one instruction.

    Either half may be ``None`` when the corresponding operand falls outside
    the portable substrate's current vocabulary: the lift is lossy, never
    lossy-into-a-wrong-value.  A reader consumes only the half it needs.
    """

    target: ValueRef | None
    value: ExprRef | None
