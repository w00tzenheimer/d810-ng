"""Live switch-table dispatcher adapter.

The portable analyzer lives in ``d810.recon.flow.switch_table_analysis`` and
operates on ``FlowGraph`` snapshots. This module owns the live Hex-Rays
boundary needed by existing optimizer consumers that still require a live
``mop_t`` state variable.
"""
from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.core.logging import getLogger
from d810.hexrays.mutation.ir_translator import lift
from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap
from d810.recon.flow.switch_table_analysis import analyze_switch_table_flow_graph

logger = getLogger("D810.switch_table_adapter")


@dataclass(frozen=True)
class SwitchTableLiveResult:
    """Switch-table dispatcher evidence plus live state-variable operand."""

    state_dispatcher_map: StateDispatcherMap
    state_var_mop: object


def _extract_state_var_mop(
    mop: object,
    state_var_stkoff: int,
) -> object | None:
    """Recursively find the live root ``mop_S`` operand."""
    if mop.t == ida_hexrays.mop_S:
        return mop if int(mop.s.off) == int(state_var_stkoff) else None

    if mop.t == ida_hexrays.mop_d:
        inner = mop.d
        dispatch_expr_opcodes = frozenset({
            ida_hexrays.m_and,
            ida_hexrays.m_or,
            ida_hexrays.m_xor,
            ida_hexrays.m_sub,
        })
        if inner.opcode in dispatch_expr_opcodes:
            result = _extract_state_var_mop(inner.l, state_var_stkoff)
            if result is not None:
                return result
            return _extract_state_var_mop(inner.r, state_var_stkoff)
        copy_opcodes = frozenset({
            ida_hexrays.m_mov,
            ida_hexrays.m_xdu,
            ida_hexrays.m_xds,
        })
        if inner.opcode in copy_opcodes:
            return _extract_state_var_mop(inner.l, state_var_stkoff)

    return None


def _find_state_var_mop_from_mba(
    mba: object,
    *,
    dispatcher_serial: int,
    state_var_stkoff: int,
) -> object | None:
    try:
        block = mba.get_mblock(int(dispatcher_serial))
    except Exception:
        return None
    tail = getattr(block, "tail", None)
    if tail is None or getattr(tail, "opcode", None) != ida_hexrays.m_jtbl:
        return None
    return _extract_state_var_mop(tail.l, state_var_stkoff)


def analyze_switch_table_dispatcher(
    mba: object,
) -> SwitchTableLiveResult | None:
    """Lift an MBA, run portable switch-table analysis, and recover live mop."""
    flow_graph = lift(mba)
    result = analyze_switch_table_flow_graph(flow_graph)
    if result is None:
        return None

    dispatch_map = result.state_dispatcher_map
    state_var_mop = _find_state_var_mop_from_mba(
        mba,
        dispatcher_serial=dispatch_map.dispatcher_entry_block,
        state_var_stkoff=dispatch_map.state_var_stkoff,
    )
    if state_var_mop is None:
        logger.debug(
            "switch-table dispatcher at blk[%d]: could not recover live state mop",
            dispatch_map.dispatcher_entry_block,
        )
        return None

    return SwitchTableLiveResult(
        state_dispatcher_map=dispatch_map,
        state_var_mop=state_var_mop,
    )
