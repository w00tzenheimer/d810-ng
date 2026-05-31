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
from d810.ir.semantics import PredicateKind
from d810.ir.value_refs import ValueRef

__all__ = ["Assignment", "ConditionalBranch"]


@dataclass(frozen=True)
class Assignment:
    """A portable ``target := value`` produced by lifting one instruction.

    Either half may be ``None`` when the corresponding operand falls outside
    the portable substrate's current vocabulary: the lift is lossy, never
    lossy-into-a-wrong-value.  A reader consumes only the half it needs.
    """

    target: ValueRef | None
    value: ExprRef | None


@dataclass(frozen=True)
class ConditionalBranch:
    """A portable two-way conditional control transfer (the control-flow analog
    of :class:`Assignment`).

    ``compare(predicate, lhs, rhs)`` then transfer to ``taken`` (predicate true)
    or ``fallthrough`` (false).  Microcode fuses compare+branch into one ``m_jcc``
    tail, so the operands ride here directly rather than via a separate boolean
    value -- LLVM/VEX split that (``icmp``+``br`` / ``CmpEQ``+``Ist_Exit``); LiSA
    and the fused microcode shape keep it together (predicate on the transfer,
    successors as the two CFG edges).  Any field may be ``None`` when the operand
    or edge is not (yet) recoverable.

    ``lhs``/``rhs`` are the SYNTACTIC operand expressions.  Do NOT use them as the
    variable-IDENTITY key for grouping comparisons -- that is a separate
    (already-portable) layer, ``d810.ir.mop_identity.mop_snapshot_key``, the
    LiSA-style *Identifier* / LLVM Value-identity / VEX guest-offset.  An audit
    (ticket llr-lxas) confirmed on sub_7FFD that re-keying off these expressions
    via ``DefinitionRef(StackSlot(off, size))`` would regress: it is size-AWARE
    (52% of stack slots are accessed at >1 width -> one state variable would
    split into several) and cannot represent the lvar / nested-``mop_d`` operands
    that ``mop_snapshot_key`` keys.  Identity and expression are complementary
    layers; keep them separate.
    """

    predicate: PredicateKind | None
    lhs: ExprRef | None
    rhs: ExprRef | None
    taken: int | None = None
    fallthrough: int | None = None
