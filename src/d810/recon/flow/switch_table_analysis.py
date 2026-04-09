"""Switch-table dispatcher analysis.

Extracts handler maps from ``m_jtbl`` switch tables. The IDA-dependent
``analyze_switch_table_dispatcher()`` walks the MBA; the pure-logic
``build_handler_map_from_cases()`` constructs the shared IR.
"""
from __future__ import annotations

from d810.core.logging import getLogger
from d810.recon.flow.dispatcher_detection import DispatcherType
from d810.recon.flow.dispatcher_handler_map import DispatcherHandlerMap

logger = getLogger("D810.recon.switch_table")


def build_handler_map_from_cases(
    cases: list[tuple[int, int]],
    dispatcher_serial: int,
    dispatcher_blocks: frozenset[int],
    state_var_stkoff: int,
    initial_state: int | None = None,
) -> DispatcherHandlerMap:
    """Build a DispatcherHandlerMap from (case_value, target_serial) pairs.

    Pure logic -- no IDA dependency.  Self-loop targets (pointing back to a
    dispatcher block) are skipped.  When multiple case values map to the
    same target, the first case value wins.
    """
    handler_state_map: dict[int, int] = {}
    for case_value, target_serial in cases:
        if target_serial in dispatcher_blocks:
            continue
        if target_serial not in handler_state_map:
            handler_state_map[target_serial] = case_value
    return DispatcherHandlerMap(
        handler_state_map=handler_state_map,
        dispatcher_serial=dispatcher_serial,
        dispatcher_blocks=dispatcher_blocks,
        state_var_stkoff=state_var_stkoff,
        source=DispatcherType.SWITCH_TABLE,
        initial_state=initial_state,
    )


def _extract_stkoff_from_mop(mop: object) -> int | None:
    """Recursively extract stack offset from an mop_t."""
    import ida_hexrays

    if mop.t == ida_hexrays.mop_S:
        return mop.s.off

    if mop.t == ida_hexrays.mop_d:
        inner = mop.d
        _DISPATCH_EXPR_OPCODES = frozenset({
            ida_hexrays.m_and,
            ida_hexrays.m_or,
            ida_hexrays.m_xor,
            ida_hexrays.m_sub,
        })
        if inner.opcode in _DISPATCH_EXPR_OPCODES:
            result = _extract_stkoff_from_mop(inner.l)
            if result is not None:
                return result
            return _extract_stkoff_from_mop(inner.r)
        _COPY_OPCODES = frozenset({
            ida_hexrays.m_mov,
            ida_hexrays.m_xdu,
            ida_hexrays.m_xds,
        })
        if inner.opcode in _COPY_OPCODES:
            return _extract_stkoff_from_mop(inner.l)

    return None


def _find_state_var_stkoff(jtbl_insn: object) -> int | None:
    """Trace m_jtbl left operand backward to find state variable stack offset.

    Handles direct stack refs (``mop_S``), compound dispatch expressions like
    ``v3 & 0xF`` (``mop_d`` wrapping ``m_and``), and copy chains.
    """
    return _extract_stkoff_from_mop(jtbl_insn.l)


def _extract_state_var_mop(mop: object) -> object | None:
    """Recursively find the root mop_S operand."""
    import ida_hexrays

    if mop.t == ida_hexrays.mop_S:
        return mop

    if mop.t == ida_hexrays.mop_d:
        inner = mop.d
        _DISPATCH_EXPR_OPCODES = frozenset({
            ida_hexrays.m_and,
            ida_hexrays.m_or,
            ida_hexrays.m_xor,
            ida_hexrays.m_sub,
        })
        if inner.opcode in _DISPATCH_EXPR_OPCODES:
            result = _extract_state_var_mop(inner.l)
            if result is not None:
                return result
            return _extract_state_var_mop(inner.r)
        _COPY_OPCODES = frozenset({
            ida_hexrays.m_mov,
            ida_hexrays.m_xdu,
            ida_hexrays.m_xds,
        })
        if inner.opcode in _COPY_OPCODES:
            return _extract_state_var_mop(inner.l)

    return None


def _find_state_var_mop(jtbl_insn: object) -> object | None:
    """Return the live ``mop_t`` for the state variable used by m_jtbl."""
    return _extract_state_var_mop(jtbl_insn.l)


def _extract_cases_from_mcases(
    mcases_mop: object,
    dispatcher_serial: int,
) -> list[tuple[int, int]]:
    """Extract (case_value, target_serial) pairs from an mcases_t operand.

    Default cases (empty value list) are skipped.
    """
    cases: list[tuple[int, int]] = []
    mcases = mcases_mop.c
    for values, target in zip(mcases.values, mcases.targets):
        if target == dispatcher_serial:
            continue
        if len(values) == 0:
            continue
        cases.append((values[0], target))
    return cases


def analyze_switch_table_dispatcher(mba: object) -> DispatcherHandlerMap | None:
    """Walk MBA looking for m_jtbl dispatchers and extract handler maps.

    Scans all blocks for ``m_jtbl`` tail instructions. For the first
    qualifying switch (>= 2 cases after filtering), extracts the case-target
    mapping and identifies the state variable.

    Returns:
        ``DispatcherHandlerMap`` if a switch-table dispatcher was found,
        None otherwise.
    """
    import ida_hexrays

    for serial in range(mba.qty):
        blk = mba.get_mblock(serial)
        if blk.tail is None or blk.tail.opcode != ida_hexrays.m_jtbl:
            continue

        stkoff = _find_state_var_stkoff(blk.tail)
        if stkoff is None:
            logger.debug(
                "m_jtbl at blk[%d]: could not identify state variable stkoff",
                serial,
            )
            continue

        cases = _extract_cases_from_mcases(blk.tail.r, serial)
        if len(cases) < 2:
            logger.debug(
                "m_jtbl at blk[%d]: too few cases (%d), skipping",
                serial,
                len(cases),
            )
            continue

        dispatcher_blocks = frozenset({serial})
        handler_map = build_handler_map_from_cases(
            cases=cases,
            dispatcher_serial=serial,
            dispatcher_blocks=dispatcher_blocks,
            state_var_stkoff=stkoff,
        )

        logger.info(
            "Switch-table dispatcher at blk[%d]: %d handlers, stkoff=0x%X",
            serial,
            len(handler_map.handler_state_map),
            stkoff,
        )
        return handler_map

    return None


def get_switch_table_state_var_mop(mba: object) -> object | None:
    """Find the live ``mop_t`` for the state variable used by the switch dispatcher.

    Scans MBA for m_jtbl blocks and returns the root mop_S.
    """
    import ida_hexrays

    for serial in range(mba.qty):
        blk = mba.get_mblock(serial)
        if blk.tail is None or blk.tail.opcode != ida_hexrays.m_jtbl:
            continue
        mop = _find_state_var_mop(blk.tail)
        if mop is not None:
            return mop
    return None
