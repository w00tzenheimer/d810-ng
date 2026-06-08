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

from d810.core.logging import getLogger
from d810.core.typing import Dict, Optional

from d810.analyses.data_flow.concolic.emulation import (
    Abstain,
    ConcreteStore,
    EmulationOutcome,
    ExactResult,
    InsnRef,
    Unsupported,
)
from d810.analyses.data_flow.concolic.refs import LocationKind, LocationRef
from d810.backends.hexrays.evidence import bst_analysis

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

        Seeds the forward stack/register maps from ``store`` (only cells whose
        :class:`LocationRef` is a concrete stack slot / register are usable), then
        steps every instruction of the live block accumulating the maps.  The
        first resolved state-var write is the exact next-state constant.
        """
        if block is None:
            return Abstain("no live block")
        stk_map, reg_map = self._seed_maps(store)
        resolved: Optional[int] = None
        try:
            insn = getattr(block, "head", None)
            while insn is not None:
                value = bst_analysis._forward_eval_insn(
                    insn,
                    stk_map,
                    reg_map,
                    self.state_var_stkoff,
                    mba=self.mba,
                    state_var_lvar_idx=self.state_var_lvar_idx,
                )
                if value is not None and resolved is None:
                    resolved = int(value)
                insn = getattr(insn, "next", None)
        except Exception:  # noqa: BLE001 — a stepper failure means "cannot prove" -> abstain
            logger.debug("HexRaysBlockEmulator: block-step raised; abstaining", exc_info=True)
            return Abstain("block-step raised")
        if resolved is None:
            return Abstain("no resolvable state-var write in block")
        return ExactResult({self.state_cell: int(resolved) & 0xFFFFFFFFFFFFFFFF})

    # -- internal ----------------------------------------------------------
    def _seed_maps(
        self, store: ConcreteStore
    ) -> "tuple[Dict[int, int], Dict[int, int]]":
        """Project the concrete store's resolved cells into stack/register maps.

        Only :class:`LocationKind.STACK` / :class:`LocationKind.REGISTER` cells
        carry into the block-stepper's ``stk_map`` / ``reg_map``; the stepper
        treats an absent slot as unknown (which is the sound abstain trigger).
        """
        stk_map: Dict[int, int] = {}
        reg_map: Dict[int, int] = {}
        for loc, value in store.cells.items():
            if value is None:
                continue
            if loc.kind is LocationKind.STACK:
                stk_map[int(loc.key)] = int(value)
            elif loc.kind is LocationKind.REGISTER:
                reg_map[int(loc.key)] = int(value)
        return stk_map, reg_map
