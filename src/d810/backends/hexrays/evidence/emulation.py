"""Hex-Rays :class:`EmulationCapability` over the live block-stepper (S4 B).

The concrete precision oracle the concolic refiner consumes (ticket ``llr-1szn``,
epic ``llr-7ouc``).  It wraps the existing portable block-stepper
(:func:`d810.analyses.value_flow.state_write.forward_eval_insn`, exposed as
``bst_analysis._forward_eval_insn``) so it can prove the exact constant a live
microcode block writes to the dispatcher state variable -- including MBA /
opaque-XOR next-state writes that span several instructions, which a
single-instruction reference emulator cannot fold.

Soundness is the whole point: this capability is **prove-exact-or-abstain**.  It
returns an :class:`ExactResult` *only* when the block-stepper resolves a concrete
state-var write from a fully-known operand environment; on any miss
(unresolved operand, no state write found, an exception) it returns
:class:`Abstain`.  An :class:`ExactResult` is still cross-checked against the
abstract floor by
:func:`d810.analyses.data_flow.concolic.concrete_refiner.fold_exact` before it is
ever trusted, so even a wrong fold costs only precision, never correctness.

Lives in ``backends/hexrays`` (a layer above the portable concolic package) and
imports the protocol downward -- exactly the split the
``EmulationCapability`` docstring anticipates.  Not portable (touches the live
``mba`` / ``minsn_t``); that is why it sits in the vendor backend.
"""
from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.core.logging import getLogger
from d810.core.typing import Optional

from d810.analyses.data_flow.concolic.emulation import (
    Abstain,
    ConcreteStore,
    EmulationOutcome,
    ExactResult,
    InsnRef,
    Unsupported,
)
from d810.analyses.data_flow.concolic.refs import LocationRef
from d810.evaluator.hexrays_microcode.emulator import (
    MicroCodeEnvironment,
    MicroCodeInterpreter,
)

logger = getLogger(__name__)

__all__ = ["HexRaysBlockEmulator"]


@dataclass(frozen=True)
class HexRaysBlockEmulator:
    """``EmulationCapability`` proving a live block's concrete next-state write.

    ``mba`` is the live function microcode; ``state_var_stkoff`` is the dispatcher
    state-variable frame offset; ``state_cell`` is the :class:`LocationRef` the
    abstract analysis tracks for that variable (so the emitted
    :class:`ExactResult` keys the same cell the refiner folds into).

    ``eval_block`` steps the block via the portable
    :func:`forward_eval_insn` core (through ``bst_analysis._forward_eval_insn``,
    which carries the Hex-Rays seams) seeding the forward maps from ``store``
    where the operands map to known stack/register locations.  It NEVER asserts a
    wrong :class:`ExactResult`: a state-var constant is returned only when the
    block-stepper resolves one, else :class:`Abstain`.
    """

    mba: object
    state_var_stkoff: int
    state_cell: LocationRef
    state_var_lvar_idx: Optional[int] = None

    # -- EmulationCapability ----------------------------------------------
    def eval_insn(self, insn: InsnRef, store: ConcreteStore) -> EmulationOutcome:
        """Single portable ``InsnRef`` evaluation is not modeled by this backend.

        The block-stepper is block-granular (a next-state write can span several
        instructions); a single ``InsnRef`` carries no live ``minsn_t`` to step.
        Stay abstract rather than risk an unsound single-op fold.
        """
        return Unsupported("HexRaysBlockEmulator models whole live blocks, not InsnRef")

    def eval_block(self, block: object, store: ConcreteStore) -> EmulationOutcome:
        """Prove the concrete state-var constant ``block`` writes, or abstain.

        Resolves the block's FIRST state-variable write by stepping the live block
        with the Hex-Rays microcode interpreter over a fresh environment.  The
        interpreter resolves each unresolved operand through its DEF-USE chain
        history (the "historical environment") -- so an opaque ``state = reg_a ^
        reg_b`` whose operands are defined in OTHER blocks folds from those blocks'
        definitions (ticket llr-a93i).  This is the fix for the empty-seed catch-22:
        the abstract fixpoint's predecessor-OUT seed is empty at exactly the ``⊥``
        back-edge the concrete leg is consulted on, so the old store-seeded
        block-stepper could never fold; the live UD-chain history can.  ``store`` is
        now advisory -- the live history is authoritative, so an empty store no
        longer forces an abstain.

        NEVER a wrong fold: the interpreter yields ``None`` for an operand whose
        reaching definition is not a unique constant, so a multi-path-ambiguous
        next-state abstains rather than guessing.
        """
        if block is None:
            return Abstain("no live block")
        write_insn = self._find_first_state_write(block)
        if write_insn is None or getattr(write_insn, "d", None) is None:
            return Abstain("no state-var write in block")
        try:
            interpreter = MicroCodeInterpreter(symbolic_mode=False)
            env = MicroCodeEnvironment()
            resolved: Optional[int] = None
            insn = getattr(block, "head", None)
            while insn is not None:
                ok = interpreter.eval_instruction(
                    block, insn, environment=env, raise_exception=False
                )
                if insn.ea == write_insn.ea and insn.opcode == write_insn.opcode:
                    if ok:
                        value = env.lookup(write_insn.d, raise_exception=False)
                        if value is None:
                            value = interpreter.eval_mop(
                                write_insn.d, environment=env, raise_exception=False
                            )
                        if value is not None:
                            resolved = int(value)
                    break
                insn = getattr(insn, "next", None)
        except Exception:  # noqa: BLE001 — interpreter failure means "cannot prove" -> abstain
            logger.debug(
                "HexRaysBlockEmulator: history eval raised; abstaining", exc_info=True
            )
            return Abstain("history eval raised")
        if resolved is None:
            return Abstain("emulator+history could not resolve state-var write")
        return ExactResult({self.state_cell: int(resolved) & 0xFFFFFFFFFFFFFFFF})

    # -- internal ----------------------------------------------------------
    def _find_first_state_write(self, block: object):
        """The first instruction in ``block`` whose destination IS the state var.

        Matches a direct write to the dispatcher state slot (``mop_S`` at
        ``state_var_stkoff``) or the state lvar (``mop_l`` at
        ``state_var_lvar_idx``).  Returns the ``minsn_t`` or ``None``.  (The
        ``m_stx`` store form is not matched here -- it abstains, which is sound.)
        """
        insn = getattr(block, "head", None)
        while insn is not None:
            d = getattr(insn, "d", None)
            if d is not None and self._mop_is_state_var(d):
                return insn
            insn = getattr(insn, "next", None)
        return None

    def _mop_is_state_var(self, mop: object) -> bool:
        """True when ``mop`` denotes the dispatcher state variable (stack or lvar)."""
        try:
            t = mop.t
            if t == ida_hexrays.mop_S:
                return int(mop.s.off) == int(self.state_var_stkoff)
            if t == ida_hexrays.mop_l and self.state_var_lvar_idx is not None:
                return int(mop.l.idx) == int(self.state_var_lvar_idx)
        except Exception:  # noqa: BLE001 — defensive mop access -> treat as not-the-state-var
            return False
        return False
