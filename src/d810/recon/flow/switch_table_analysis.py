"""Switch-table dispatcher analysis.

Extracts handler maps from ``m_jtbl`` switch tables. The IDA-dependent
``analyze_switch_table_dispatcher()`` walks the MBA; the pure-logic
``build_handler_map_from_cases()`` constructs the shared IR.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.recon.flow.dispatcher_detection import DispatcherType
from d810.recon.flow.dispatcher_handler_map import DispatcherHandlerMap

logger = getLogger("D810.recon.switch_table")


@dataclass(frozen=True)
class SwitchTableResult:
    """Bundled result from switch-table dispatcher analysis.

    Couples the handler map with the live state variable mop so that
    consumers don't need a second MBA scan.
    """

    handler_map: DispatcherHandlerMap
    state_var_mop: object  # ida_hexrays.mop_t


def build_handler_map_from_cases(
    cases: list[tuple[int, int]],
    dispatcher_serial: int,
    dispatcher_blocks: frozenset[int],
    state_var_stkoff: int,
    initial_state: int | None = None,
) -> DispatcherHandlerMap | None:
    """Build a DispatcherHandlerMap from (case_value, target_serial) pairs.

    Pure logic -- no IDA dependency.  Self-loop targets (pointing back to a
    dispatcher block) are skipped.  Aliased targets (multiple case values
    mapping to the same handler) cause rejection (returns None) because
    the lossy collapse would drop valid incoming/final states from
    ``handler_state_map`` and miss transitions.  Full alias support is
    deferred to Phase 2.
    """
    handler_state_map: dict[int, int] = {}
    aliases_found: list[tuple[int, int]] = []
    for case_value, target_serial in cases:
        if target_serial in dispatcher_blocks:
            continue
        if target_serial not in handler_state_map:
            handler_state_map[target_serial] = case_value
        else:
            aliases_found.append((case_value, target_serial))
    if aliases_found:
        logger.info(
            "build_handler_map_from_cases: rejecting switch with %d aliased "
            "case(s): %s (Phase 2 needed for alias support)",
            len(aliases_found),
            [(hex(cv), s) for cv, s in aliases_found],
        )
        return None
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


def analyze_switch_table_dispatcher(mba: object) -> SwitchTableResult | None:
    """Walk MBA looking for m_jtbl dispatchers and extract handler maps.

    Scans all blocks for ``m_jtbl`` tail instructions. For the first
    qualifying switch (>= 2 cases after filtering), extracts the case-target
    mapping, identifies the state variable, and returns both the handler map
    and the live ``mop_t`` in a single ``SwitchTableResult``.

    Returns:
        ``SwitchTableResult`` if a switch-table dispatcher was found,
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

        state_var_mop = _find_state_var_mop(blk.tail)
        if state_var_mop is None:
            logger.debug(
                "m_jtbl at blk[%d]: could not find state variable mop",
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
        if handler_map is None:
            continue

        logger.info(
            "Switch-table dispatcher at blk[%d]: %d handlers, stkoff=0x%X",
            serial,
            len(handler_map.handler_state_map),
            stkoff,
        )
        return SwitchTableResult(handler_map=handler_map, state_var_mop=state_var_mop)

    return None
