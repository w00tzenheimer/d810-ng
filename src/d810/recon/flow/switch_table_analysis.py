"""Switch-table dispatcher analysis.

Extracts exact state-dispatcher rows from ``m_jtbl`` switch tables. The
IDA-dependent ``analyze_switch_table_dispatcher()`` walks the MBA; the
pure-logic ``build_state_dispatcher_map_from_cases()`` constructs the shared
shape-neutral state-machine IR.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.recon.flow.dispatcher_detection import DispatcherType
from d810.recon.flow.dispatcher_map import (
    StateDispatcherMap,
    StateDispatcherRow,
)

logger = getLogger("D810.recon.switch_table")


@dataclass(frozen=True)
class SwitchTableResult:
    """Bundled result from switch-table dispatcher analysis.

    Couples the exact dispatcher map with the live state variable mop so that
    consumers don't need a second MBA scan.
    """

    state_dispatcher_map: StateDispatcherMap
    state_var_mop: object  # ida_hexrays.mop_t


def build_state_dispatcher_map_from_cases(
    cases: list[tuple[int | None, int]],
    dispatcher_serial: int,
    dispatcher_blocks: frozenset[int],
    state_var_stkoff: int,
    initial_state: int | None = None,
) -> StateDispatcherMap:
    """Build exact state-dispatcher rows from switch case targets.

    Pure logic -- no IDA dependency. Exact case aliases and dispatcher
    self-loops are preserved in ``StateDispatcherMap.rows``. A default case
    (``case_value is None``) is represented separately because it is not an
    exact state-constant row.
    """
    target_counts: dict[int, int] = {}
    for case_value, target_serial in cases:
        if case_value is not None and int(target_serial) not in dispatcher_blocks:
            target = int(target_serial)
            target_counts[target] = target_counts.get(target, 0) + 1

    rows: list[StateDispatcherRow] = []
    default_target: int | None = None
    default_kind: str | None = None
    for case_value, target_serial in cases:
        target = int(target_serial)
        if case_value is None:
            default_target = target
            default_kind = (
                "dispatcher_default_self_loop"
                if target in dispatcher_blocks else "dispatcher_default"
            )
            continue
        state_const = int(case_value) & 0xFFFFFFFFFFFFFFFF
        if target in dispatcher_blocks:
            row_kind = "dispatcher_self_loop"
            branch_kind = "switch_self_loop"
        elif target_counts.get(target, 0) > 1:
            row_kind = "handler_alias"
            branch_kind = "switch_case_alias"
        else:
            row_kind = "handler"
            branch_kind = "switch_case"
        rows.append(
            StateDispatcherRow(
                state_const=state_const,
                target_block=target,
                dispatcher_block=int(dispatcher_serial),
                compare_block=int(dispatcher_serial),
                branch_kind=branch_kind,
                source=DispatcherType.SWITCH_TABLE,
                confidence=1.0,
                row_kind=row_kind,
            )
        )
    return StateDispatcherMap(
        rows=tuple(rows),
        dispatcher_entry_block=int(dispatcher_serial),
        dispatcher_blocks=dispatcher_blocks,
        state_var_stkoff=state_var_stkoff,
        state_var_lvar_idx=None,
        source=DispatcherType.SWITCH_TABLE,
        initial_state=initial_state,
        default_target_block=default_target,
        default_row_kind=default_kind,
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
) -> list[tuple[int | None, int]]:
    """Extract (case_value, target_serial) pairs from an mcases_t operand.

    Default cases are represented as ``(None, target_serial)``.
    """
    cases: list[tuple[int | None, int]] = []
    mcases = mcases_mop.c
    for values, target in zip(mcases.values, mcases.targets):
        if len(values) == 0:
            cases.append((None, target))
            continue
        for value in values:
            cases.append((value, target))
    return cases


def _maturity_label(mba: object) -> str:
    value = getattr(mba, "maturity", None)
    if value is None:
        return "unknown"
    try:
        import ida_hexrays  # type: ignore[import-untyped]

        for name in dir(ida_hexrays):
            if (
                name.startswith("MMAT_")
                and int(getattr(ida_hexrays, name)) == int(value)
            ):
                return name
    except Exception:
        pass
    return str(value)


def _block_successors(block: object) -> tuple[int, ...]:
    try:
        return tuple(int(block.succ(index)) for index in range(int(block.nsucc())))
    except Exception:
        return ()


def _block_predecessors(block: object) -> tuple[int, ...]:
    try:
        return tuple(int(block.pred(index)) for index in range(int(block.npred())))
    except Exception:
        return ()


def _conditional_jump_opcodes() -> frozenset[int]:
    try:
        import ida_hexrays  # type: ignore[import-untyped]

        return frozenset(
            int(getattr(ida_hexrays, name))
            for name in (
                "m_jnz",
                "m_jz",
                "m_ja",
                "m_jae",
                "m_jb",
                "m_jbe",
                "m_jg",
                "m_jge",
                "m_jl",
                "m_jle",
            )
            if getattr(ida_hexrays, name, None) is not None
        )
    except Exception:
        return frozenset(range(43, 53))


def _mop_const_value(mop: object | None) -> int | None:
    if mop is None:
        return None
    nnn = getattr(mop, "nnn", None)
    if nnn is not None:
        value = getattr(nnn, "value", None)
        if value is not None:
            return int(value)
    value = getattr(mop, "value", None)
    if value is not None:
        return int(value)
    return None


def _mop_contains_stkoff(
    mop: object | None,
    state_var_stkoff: int,
    mba: object,
    *,
    visited: set[int] | None = None,
) -> bool:
    if mop is None:
        return False
    if visited is None:
        visited = set()
    identity = id(mop)
    if identity in visited:
        return False
    visited.add(identity)

    stack_ref = getattr(mop, "s", None)
    if stack_ref is not None and getattr(stack_ref, "off", None) == state_var_stkoff:
        return True
    if getattr(mop, "stkoff", None) == state_var_stkoff:
        return True

    lvar_ref = getattr(mop, "l", None)
    lvar_idx = getattr(lvar_ref, "idx", None) if lvar_ref is not None else None
    if lvar_idx is not None:
        try:
            if mba.vars[int(lvar_idx)].location.stkoff() == state_var_stkoff:
                return True
        except Exception:
            pass

    for attr in ("a", "d", "l", "r"):
        child = getattr(mop, attr, None)
        if child is not None and _mop_contains_stkoff(
            child,
            state_var_stkoff,
            mba,
            visited=visited,
        ):
            return True
    return False


def _guard_compares_state_to_terminal(
    mba: object,
    block: object,
    *,
    state_var_stkoff: int,
    case_values: frozenset[int],
) -> bool:
    tail = getattr(block, "tail", None)
    if tail is None:
        return False
    opcode = getattr(tail, "opcode", None)
    if opcode not in _conditional_jump_opcodes():
        return False

    left = getattr(tail, "l", None)
    right = getattr(tail, "r", None)
    left_is_state = _mop_contains_stkoff(left, state_var_stkoff, mba)
    right_is_state = _mop_contains_stkoff(right, state_var_stkoff, mba)
    if left_is_state == right_is_state:
        return False
    const_mop = right if left_is_state else left
    const_value = _mop_const_value(const_mop)
    if const_value is None:
        return False
    return (int(const_value) & 0xFFFFFFFFFFFFFFFF) not in case_values


def find_switch_loop_guard_blocks(
    mba: object,
    dispatcher_serial: int,
    *,
    state_var_stkoff: int,
    case_values: frozenset[int],
) -> frozenset[int]:
    """Return loop guards that route into a switch-table dispatcher.

    Source-level ``while (state != terminal) switch (state)`` shapes have two
    dispatcher blocks in microcode: a two-way loop guard and the ``m_jtbl``
    table.  Only accept a predecessor guard when it compares the same state
    variable against a terminal value outside the exact switch rows.
    """

    try:
        dispatcher = mba.get_mblock(int(dispatcher_serial))
    except Exception:
        return frozenset()
    if dispatcher is None:
        return frozenset()

    guards: set[int] = set()
    for pred_serial in _block_predecessors(dispatcher):
        try:
            pred_block = mba.get_mblock(int(pred_serial))
        except Exception:
            pred_block = None
        if pred_block is None:
            continue
        succs = _block_successors(pred_block)
        if (
            len(succs) == 2
            and int(dispatcher_serial) in succs
            and len(_block_predecessors(pred_block)) >= 2
            and _guard_compares_state_to_terminal(
                mba,
                pred_block,
                state_var_stkoff=state_var_stkoff,
                case_values=case_values,
            )
        ):
            guards.add(int(pred_serial))
    return frozenset(guards)


def _observe_state_dispatcher_map(
    mba: object,
    dispatch_map: StateDispatcherMap,
) -> None:
    try:
        from d810.recon.observability import observe_state_dispatcher_rows

        observe_state_dispatcher_rows(
            func_ea=int(getattr(mba, "entry_ea", 0) or 0),
            maturity=_maturity_label(mba),
            dispatcher_entry_block=dispatch_map.dispatcher_entry_block,
            dispatcher_kind=dispatch_map.source.name,
            rows=dispatch_map.rows,
        )
    except Exception:
        logger.debug(
            "switch-table state dispatcher observation failed",
            exc_info=True,
        )


def analyze_switch_table_dispatcher(mba: object) -> SwitchTableResult | None:
    """Walk MBA looking for m_jtbl dispatchers and extract exact rows.

    Scans all blocks for ``m_jtbl`` tail instructions. For the first
    qualifying switch (>= 2 cases after filtering), extracts the case-target
    mapping, identifies the state variable, and returns both the exact
    state-dispatcher map and the live ``mop_t`` in a single
    ``SwitchTableResult``.

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

        case_values = frozenset(
            int(case_value) & 0xFFFFFFFFFFFFFFFF
            for case_value, _target in cases
            if case_value is not None
        )
        dispatcher_blocks = frozenset({
            serial,
            *find_switch_loop_guard_blocks(
                mba,
                serial,
                state_var_stkoff=stkoff,
                case_values=case_values,
            ),
        })
        state_dispatcher_map = build_state_dispatcher_map_from_cases(
            cases=cases,
            dispatcher_serial=serial,
            dispatcher_blocks=dispatcher_blocks,
            state_var_stkoff=stkoff,
        )
        _observe_state_dispatcher_map(mba, state_dispatcher_map)
        handler_map = state_dispatcher_map.to_dispatcher_handler_map()

        logger.info(
            "Switch-table dispatcher at blk[%d]: %d handlers, stkoff=0x%X",
            serial,
            len(handler_map.handler_state_map),
            stkoff,
        )
        return SwitchTableResult(
            state_dispatcher_map=state_dispatcher_map,
            state_var_mop=state_var_mop,
        )

    return None
