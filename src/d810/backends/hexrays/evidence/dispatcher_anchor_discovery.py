"""Selector-anchored ``DispatcherAnchors`` discovery (P2, ticket llr-8wq9).

The Slice 5 ``EmulationDispatcherResolver._discover`` picks the state variable as
the stack slot self-``OP``-updated in the MOST blocks. That heuristic is correct
for the XOR machine (``abc_xor_dispatch``), whose state var genuinely IS the
dominant self-``xor``-updated slot, but it MIS-IDENTIFIES the state var on an
identity ``switch(state)`` machine (``high_fan_in_pattern``): there ``state`` is
written by plain ``mov #const`` in most arms (``state = 3; state = 4; ...``) --
which ``_as_self_update`` (requires ``state OP #const``) does NOT count -- while
``result`` is updated by ``result += / *= / -=`` in nearly every arm, so
``result`` becomes the dominant self-update slot and is wrongly picked. The
dispatcher is ``switch(state)``, never ``switch(result)``.

This module fixes that by anchoring on the dispatcher *selector* -- the operand
the dispatcher actually compares/switches on -- not the dominant self-update slot.
It produces the engine-neutral P1 :class:`DispatcherAnchors` (design §6 step 1),
which the concolic engine consumes instead of re-running the broken heuristic.

Selector resolution priority (each grounded in existing code):

1. ``m_jtbl`` head (switch_case_ollvm, high_fan_in after Hex-Rays lowers ``switch``
   to a jump table): the state var is the SWITCHED value ``entry_blk.tail.l`` --
   exactly the operand ``computed_state_transition_evidence._resolve_dispatcher_
   case_value`` reads. Resolve it to a stack slot (through an ``xdu`` widening if
   present). ``var_8`` is selected, never ``result``.
2. Equality-chain head (Hodur-style): the compared operand, already surfaced in
   ``prelim.state_var_stkoff`` by the equality-chain resolver.
3. Fallback to Slice 5 ``_discover`` ONLY when no jtbl/eq selector is present --
   preserving the XOR path (whose selector is a computed ``m_xor`` temporary, not a
   direct slot compare, so the "dominant self-update slot" IS correct there).

IDA-dependent (reads live ``mba`` + ``ida_hexrays`` opcode/mop constants) -> lives
in the Hex-Rays backend; the contract it emits is portable.
"""
from __future__ import annotations

import ida_hexrays

from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap
from d810.analyses.control_flow.machine_recovery_engine import DispatcherAnchors
from d810.backends.hexrays.evidence.emulation_dispatcher_resolver import (
    EmulationDispatcherResolver,
)
from d810.core.logging import getLogger
from d810.ir.flowgraph import FlowGraph

logger = getLogger("D810.analyses.dispatcher_anchor_discovery")

__all__ = ["discover_anchors"]


def _resolve_mop_to_stkoff(
    mba: ida_hexrays.mba_t, mop: ida_hexrays.mop_t | None
) -> tuple[int | None, int | None]:
    """Resolve a selector operand to ``(stkoff, lvar_idx)``.

    The switched value is commonly a sub-register widening of the state slot
    (``jtbl xdu.4(var_8.1), ...``). Peel one ``xdu``/``xds`` wrapper, then read a
    direct ``mop_S`` (stack) or ``mop_l`` (local var) leaf. Returns ``(None, None)``
    when the operand is neither (e.g. a computed temporary) so the caller can fall
    back to the next selector strategy.
    """
    if mop is None:
        return None, None
    # Peel a single widening wrapper: the jtbl/compare reads xdu.N(state.M).
    if mop.t == ida_hexrays.mop_d and mop.d is not None:
        inner = mop.d
        if inner.opcode in (ida_hexrays.m_xdu, ida_hexrays.m_xds, ida_hexrays.m_low):
            if inner.l is not None:
                mop = inner.l
    if mop.t == ida_hexrays.mop_S and mop.s is not None:
        return int(mop.s.off), None
    if mop.t == ida_hexrays.mop_l and mop.l is not None:
        return None, int(mop.l.idx)
    return None, None


def _jtbl_selector_stkoff(
    mba: ida_hexrays.mba_t, entry: int
) -> tuple[int | None, int | None]:
    """If the entry block tail is ``m_jtbl``, return the switched value's slot.

    The switched value is ``entry_blk.tail.l`` -- the SAME operand
    ``_resolve_dispatcher_case_value`` (computed_state_transition_evidence.py:96)
    reads to map case labels to targets. This is the dispatcher selector, never the
    accumulator ``result``.
    """
    entry_blk = mba.get_mblock(int(entry))
    if entry_blk is None or entry_blk.tail is None:
        return None, None
    if entry_blk.tail.opcode != ida_hexrays.m_jtbl:
        return None, None
    return _resolve_mop_to_stkoff(mba, entry_blk.tail.l)


def discover_anchors(
    mba: ida_hexrays.mba_t,
    graph: FlowGraph,
    prelim: StateDispatcherMap | None,
) -> DispatcherAnchors | None:
    """Selector-anchored :class:`DispatcherAnchors` for the concolic engine.

    The state var is the COMPARED/SWITCHED operand, not the most-self-updated slot
    (that is the bug in ``EmulationDispatcherResolver._discover``). ``prelim`` is the
    static-shape recovery (``recover_dispatcher`` / ``build_dispatch_map_any_kind``
    result) that already located the dispatcher entry + (for equality chains) the
    compared slot; the engine consumes anchors computed here rather than re-running
    the broken heuristic.

    Returns ``None`` when no dispatcher entry can be anchored (the engine then
    abstains). ``live_mba`` carries the bound microcode opaquely so the portable
    contract never imports IDA.
    """
    entry: int | None = None
    stkoff: int | None = None
    lvar_idx: int | None = None
    initial_states: tuple[int, ...] = ()

    if prelim is not None:
        entry = (
            int(prelim.dispatcher_entry_block)
            if prelim.dispatcher_entry_block is not None
            else None
        )
        stkoff = (
            int(prelim.state_var_stkoff)
            if prelim.state_var_stkoff is not None
            else None
        )
        lvar_idx = prelim.state_var_lvar_idx
        if prelim.initial_state is not None:
            initial_states = (int(prelim.initial_state),)

    # Strategy 1: m_jtbl head -> switched operand is the selector (fixes high_fan_in
    # / switch_case_ollvm mis-ID). Overrides the prelim slot ONLY when the jtbl
    # selector resolves to a concrete slot, so it never shadows a good equality slot.
    if entry is not None:
        jt_off, jt_idx = _jtbl_selector_stkoff(mba, entry)
        if jt_off is not None or jt_idx is not None:
            logger.info(
                "anchor: jtbl selector at entry=%d -> stkoff=%s lvar_idx=%s "
                "(prelim stkoff=%s)",
                entry,
                ("0x%x" % jt_off) if jt_off is not None else None,
                jt_idx,
                ("0x%x" % stkoff) if stkoff is not None else None,
            )
            stkoff, lvar_idx = jt_off, jt_idx

    # Strategy 2: equality-chain selector already in prelim.state_var_stkoff -- kept
    # as-is from the prelim copy above (no jtbl override happened).

    # Strategy 3: fallback to Slice 5 dominant-self-update discovery ONLY when no
    # direct selector slot was found (preserves the XOR machine, whose selector is a
    # computed m_xor temporary -- there the dominant self-update slot is correct).
    if entry is None or (stkoff is None and lvar_idx is None):
        disc = EmulationDispatcherResolver(mba=mba)._discover(graph)
        if disc is not None:
            logger.info(
                "anchor: fallback dominant-self-update entry=%d stkoff=0x%x init=0x%x",
                disc.entry,
                disc.stkoff,
                disc.initial_state,
            )
            entry = int(disc.entry)
            stkoff = int(disc.stkoff)
            lvar_idx = None
            if not initial_states:
                initial_states = (int(disc.initial_state),)

    if entry is None:
        return None

    return DispatcherAnchors(
        dispatcher_entry_block=int(entry),
        state_var_stkoff=stkoff,
        state_var_lvar_idx=lvar_idx,
        initial_states=initial_states,
        live_mba=mba,
    )
