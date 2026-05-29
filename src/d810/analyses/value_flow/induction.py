"""Portable induction-variable analysis.

Ports the additive induction classifier (``x = x +/- c``) from
``recon.facts.collectors.induction_carrier._classify_induction_update`` /
``_signed_step`` (lines 232-330) to the analyses layer, cfg-free: opcodes are
matched by string forms plus the portable ``ir.expressions.ValueOpKind`` names,
never ``from d810.cfg.flowgraph import InsnKind`` (an upward analyses->cfg edge).

The recon collector classified ONE instruction at a time.  ``analyze_loop`` adds
the loop dimension with an OPTIMISTIC (union) meet across a loop's blocks: a
candidate discovered in any loop block survives at the loop head.  A
bottom-absorbing intersection would wipe a loop-head candidate that is absent on
the loop's entry edge -- the same lattice-polarity trap behind the LS6
``state_write`` kill-on-unresolved bug.

Net-new and unwired (Landing Sequence LS8 S5).
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Iterable, Mapping, Optional, Protocol
from d810.ir.confidence import FactConfidence
from d810.ir.expressions import ValueOpKind

__all__ = [
    "InductionVariableAnalysis",
    "InductionVariableFact",
    "InstructionView",
]

# Opcode forms accepted for the additive families.  cfg-free: Hex-Rays mnemonic
# ("m_add"), generic ("op_12"), and the portable ValueOpKind name ("ADD").
_ADD_OPCODES = frozenset({"m_add", "op_12", ValueOpKind.ADD.name})
_SUB_OPCODES = frozenset({"m_sub", "op_13", ValueOpKind.SUB.name})


def _signed_step(value: int) -> int:
    """Interpret a possibly-64-bit-unsigned immediate as signed.

    Ported verbatim from ``recon.facts.collectors.induction_carrier``.
    """
    value = int(value)
    if value > 0x7FFFFFFFFFFFFFFF:
        return value - (1 << 64)
    return value


class InstructionView(Protocol):
    """Structural view of one instruction the classifier reads.

    Callers / backends supply concrete views (e.g. snapshot rows); only these
    fields are consumed.  Mirrors the recon ``_InstructionView`` subset.
    """

    block_serial: int
    opcode_name: str
    dest_stkoff: Optional[int]
    src_l_stkoff: Optional[int]
    src_l_value: Optional[int]
    src_r_stkoff: Optional[int]
    src_r_value: Optional[int]


@dataclass(frozen=True)
class InductionVariableFact:
    """An additive induction variable: the stack variable at ``dest_stkoff``
    changes by ``step`` each update (``source_side`` records which operand held
    the step constant)."""

    dest_stkoff: int
    step: int
    source_side: str
    block_serial: int
    confidence: FactConfidence = FactConfidence(1.0)


class InductionVariableAnalysis:
    """Classifies additive induction-variable updates and aggregates them over a
    loop with an optimistic union meet."""

    def classify_update(
        self, insn: InstructionView
    ) -> Optional[InductionVariableFact]:
        """Classify one instruction as an additive self-update, or return None.

        Ports ``_classify_induction_update``: ``x = x + c`` (either operand
        order) and ``x = x - c`` (left operand only)."""
        if insn.dest_stkoff is None:
            return None
        opcode = insn.opcode_name
        if opcode in _ADD_OPCODES:
            if insn.src_l_stkoff == insn.dest_stkoff and insn.src_r_value is not None:
                return InductionVariableFact(
                    insn.dest_stkoff,
                    _signed_step(insn.src_r_value),
                    "right",
                    insn.block_serial,
                )
            if insn.src_r_stkoff == insn.dest_stkoff and insn.src_l_value is not None:
                return InductionVariableFact(
                    insn.dest_stkoff,
                    _signed_step(insn.src_l_value),
                    "left",
                    insn.block_serial,
                )
        if opcode in _SUB_OPCODES:
            if insn.src_l_stkoff == insn.dest_stkoff and insn.src_r_value is not None:
                return InductionVariableFact(
                    insn.dest_stkoff,
                    -_signed_step(insn.src_r_value),
                    "right",
                    insn.block_serial,
                )
        return None

    def collect_block(
        self, insns: Iterable[InstructionView]
    ) -> dict[int, InductionVariableFact]:
        """Induction facts for one block, keyed by ``dest_stkoff``."""
        facts: dict[int, InductionVariableFact] = {}
        for insn in insns:
            fact = self.classify_update(insn)
            if fact is not None:
                facts[fact.dest_stkoff] = fact
        return facts

    def merge(
        self, states: Iterable[Mapping[int, InductionVariableFact]]
    ) -> dict[int, InductionVariableFact]:
        """Optimistic UNION meet over per-block induction facts.

        A candidate found on ANY incoming edge survives.  This is deliberately
        NOT a bottom-absorbing intersection: intersecting at a loop head would
        wipe a candidate that the loop's entry edge does not carry (the LS6
        ``state_write`` kill-on-unresolved class of bug)."""
        merged: dict[int, InductionVariableFact] = {}
        for state in states:
            for offset, fact in state.items():
                merged.setdefault(offset, fact)
        return merged

    def analyze_loop(
        self, blocks: Mapping[int, Iterable[InstructionView]]
    ) -> dict[int, InductionVariableFact]:
        """All induction facts across a loop's blocks (union of per-block facts).

        ``blocks`` maps block serial -> that block's instruction views; the loop
        head having no update does not erase a body block's induction fact.
        """
        return self.merge(self.collect_block(insns) for insns in blocks.values())
