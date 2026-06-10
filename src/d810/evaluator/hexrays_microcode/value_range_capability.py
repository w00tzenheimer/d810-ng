"""Hex-Rays implementation of :class:`d810.capabilities.ValRangeCapability`.

The unifying surface over the three live value-range modules:

* :mod:`d810.evaluator.hexrays_microcode.valranges` -- IDA-native
  ``mblock_t.get_valranges`` queries + ``IntervalDispatcher`` probing (PRIMARY);
* :mod:`d810.evaluator.hexrays_microcode.valrange_dataflow` -- the hand-rolled
  forward value-range fixpoint (FALLBACK, computed lazily once per instance when
  IDA's native ranges are unavailable at the current maturity);
* the existing ``ValrangeResolutionStrategy`` consumer pattern in
  ``backends/hexrays/evidence/valrange_resolution.py`` (this capability is the
  factored-out service it -- and the unflatten ``RecoverStateTransitions`` domain --
  call through).

Lives in the evaluator layer (like ``HexRaysUseDefSafetyBackend``) because every
method needs live ``ida_hexrays`` access.  The portable Protocol + ``ValRange``
result type live in :mod:`d810.capabilities.value_range`.
"""
from __future__ import annotations

import ida_hexrays

from d810.core import logging
from d810.capabilities.value_range import ValRange
from d810.evaluator.hexrays_microcode.valranges import (
    resolve_state_via_valrange_probe,
)
from d810.evaluator.hexrays_microcode.valrange_dataflow import (
    _resolve_singleton,
    run_valrange_fixpoint,
)
from d810.analyses.data_flow.exceptions import FixpointDidNotConverge

logger = logging.getLogger("D810.capability.value_range")

__all__ = ["HexRaysValRangeCapability"]


class HexRaysValRangeCapability:
    """Resolve state-variable value ranges over a live ``ida_hexrays.mba_t``.

    Structurally satisfies :class:`d810.capabilities.ValRangeCapability`.
    """

    def __init__(self, mba, *, state_var_size: int = 4) -> None:
        self._mba = mba
        self._state_var_size = int(state_var_size)
        # Lazily computed custom-fixpoint result (the valrange_dataflow fallback).
        self._fixpoint_in_states = None
        self._fixpoint_attempted = False

    # ------------------------------------------------------------------
    # Native get_valranges helpers (primary source)
    # ------------------------------------------------------------------

    def _native_valrng(self, block_serial: int, stkoff: int, at_insn, size: int):
        """Return a non-empty, non-all-values ``valrng_t`` for the stack operand, or ``None``."""
        blk = self._mba.get_mblock(int(block_serial))
        if blk is None:
            return None
        try:
            vivl = ida_hexrays.vivl_t()
            vivl.set_stkoff(int(stkoff), int(size))
            vr = ida_hexrays.valrng_t(int(size))
            anchor = at_insn if at_insn is not None else blk.head
            for vr_flag in (
                ida_hexrays.VR_EXACT,
                ida_hexrays.VR_AT_START,
                ida_hexrays.VR_AT_END,
            ):
                if (
                    blk.get_valranges(vr, vivl, anchor, vr_flag)
                    and not vr.empty()
                    and not vr.all_values()
                ):
                    return vr
        except Exception:  # noqa: BLE001 — value-range query is best-effort
            return None
        return None

    # ------------------------------------------------------------------
    # ValRangeCapability surface
    # ------------------------------------------------------------------

    def resolve_state_value(
        self, block_serial: int, state_var_stkoff: int, *, at_insn=None
    ) -> int | None:
        size = self._state_var_size
        vr = self._native_valrng(block_serial, state_var_stkoff, at_insn, size)
        if vr is not None:
            ok, val = vr.cvt_to_single_value()
            if ok:
                return int(val)
        # Fallback: the custom forward value-range fixpoint (valrange_dataflow).
        return self._fixpoint_state_value(block_serial, state_var_stkoff, at_insn)

    def probe_dispatcher_target(
        self, block_serial: int, state_var_stkoff: int, dispatcher, *, at_insn=None
    ) -> int | None:
        blk = self._mba.get_mblock(int(block_serial))
        if blk is None:
            return None
        return resolve_state_via_valrange_probe(
            blk,
            int(state_var_stkoff),
            dispatcher,
            insn=at_insn,
            stkoff_size=self._state_var_size,
        )

    def state_value_range(
        self, block_serial: int, state_var_stkoff: int, *, at_insn=None
    ) -> ValRange | None:
        size = self._state_var_size
        vr = self._native_valrng(block_serial, state_var_stkoff, at_insn, size)
        if vr is None:
            return None
        ok, val = vr.cvt_to_single_value()
        if ok:
            return ValRange(lo=int(val), hi=int(val), width=size)
        # A non-singleton native range has no clean portable [lo, hi] accessor on
        # ``valrng_t``; only the singleton case is bounded portably for now. A
        # bounded multi-value range is future work (walk the valrng sub-ranges).
        return None

    # ------------------------------------------------------------------
    # Custom-fixpoint fallback (valrange_dataflow)
    # ------------------------------------------------------------------

    def _fixpoint_state_value(self, block_serial: int, state_var_stkoff: int, at_insn) -> int | None:
        """Resolve via the hand-rolled forward value-range fixpoint when native fails."""
        in_states = self._ensure_fixpoint()
        if in_states is None:
            return None
        env = in_states.get(int(block_serial))
        if not env:
            return None
        try:
            mop = self._stack_state_mop(state_var_stkoff)
            if mop is None:
                return None
            return _resolve_singleton(mop, env)
        except Exception:  # noqa: BLE001 — fallback is best-effort
            logger.debug("valrange fixpoint fallback failed", exc_info=True)
            return None

    def _ensure_fixpoint(self):
        if self._fixpoint_attempted:
            return self._fixpoint_in_states
        self._fixpoint_attempted = True
        try:
            # Fail closed: a non-converged fixpoint yields unsound partial states
            # (substrate-purity rule R1). Resolution is soundness-critical here, so
            # we never read a partial result — we drop the fallback instead.
            result = run_valrange_fixpoint(self._mba, raise_on_nonconvergence=True)
            self._fixpoint_in_states = getattr(result, "in_states", None)
        except FixpointDidNotConverge:
            logger.debug("valrange fixpoint did not converge; fallback disabled")
            self._fixpoint_in_states = None
        except Exception:  # noqa: BLE001 — fixpoint fallback is best-effort
            logger.debug("run_valrange_fixpoint failed", exc_info=True)
            self._fixpoint_in_states = None
        return self._fixpoint_in_states

    def _stack_state_mop(self, stkoff: int):
        """Build a stack ``mop_t`` for the state variable so the fixpoint env can be queried."""
        try:
            mop = ida_hexrays.mop_t()
            mop.make_stkvar(self._mba, int(stkoff))
            mop.size = self._state_var_size
            return mop
        except Exception:  # noqa: BLE001
            return None
