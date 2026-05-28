"""Switch-table dispatcher analysis.

Extracts exact state-dispatcher rows from portable ``FlowGraph`` switch-table
snapshots. Live Hex-Rays adapters live above recon and call
``analyze_switch_table_flow_graph()`` after lifting an MBA.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnKind, MopSnapshot
from d810.core.logging import getLogger
from d810.recon.flow.dispatcher_kind import DispatcherType
from d810.recon.flow.dispatcher_map import (
    StateDispatcherMap,
    StateDispatcherRow,
)

logger = getLogger("D810.recon.switch_table")


@dataclass(frozen=True)
class SwitchTableResult:
    """Bundled result from switch-table dispatcher analysis.

    Couples the exact dispatcher map with the portable operand snapshot for
    the state variable used by the table jump.
    """

    state_dispatcher_map: StateDispatcherMap
    state_var_operand: MopSnapshot


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


def _find_state_var_stkoff(
    operand: MopSnapshot | None,
) -> int | None:
    """Return the stack offset referenced by a table-jump state operand."""
    if operand is None:
        return None
    if operand.stack_refs:
        return int(operand.stack_refs[0])
    if operand.stkoff is not None:
        return int(operand.stkoff)
    return None


def _extract_cases_from_switch_operand(
    switch_operand: MopSnapshot | None,
    dispatcher_serial: int,
) -> list[tuple[int | None, int]]:
    """Extract ``(case_value, target_serial)`` pairs from switch cases.

    Default cases are represented as ``(None, target_serial)``. The
    ``dispatcher_serial`` parameter keeps the helper signature aligned with
    the previous live-MBA version and makes call sites self-documenting.
    """
    cases: list[tuple[int | None, int]] = []
    _ = dispatcher_serial
    if switch_operand is None:
        return cases
    for values, target in switch_operand.switch_cases:
        if len(values) == 0:
            cases.append((None, int(target)))
            continue
        for value in values:
            cases.append((int(value), int(target)))
    return cases


def _maturity_label(flow_graph: FlowGraph) -> str:
    # Prefer the provider-neutral stage fields (E2d); fall back to the
    # E2b maturity aliases for hand-built fixtures that only set those.
    value = flow_graph.metadata.get("producer_stage_name") or flow_graph.metadata.get(
        "maturity_name"
    )
    if value:
        return str(value)
    value = flow_graph.metadata.get("producer_stage_id")
    if value is None:
        value = flow_graph.metadata.get("maturity")
    return "unknown" if value is None else str(value)


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
    mop: MopSnapshot | None,
    state_var_stkoff: int,
) -> bool:
    if mop is None:
        return False
    if int(state_var_stkoff) in {int(ref) for ref in mop.stack_refs}:
        return True
    if mop.stkoff is not None and int(mop.stkoff) == int(state_var_stkoff):
        return True
    return False


def _guard_compares_state_to_terminal(
    block: BlockSnapshot,
    *,
    state_var_stkoff: int,
    case_values: frozenset[int],
) -> bool:
    tail = block.tail
    if tail is None:
        return False
    if not tail.is_conditional_jump:
        return False

    left = tail.l
    right = tail.r
    left_is_state = _mop_contains_stkoff(left, state_var_stkoff)
    right_is_state = _mop_contains_stkoff(right, state_var_stkoff)
    if left_is_state == right_is_state:
        return False
    const_mop = right if left_is_state else left
    const_value = _mop_const_value(const_mop)
    if const_value is None:
        return False
    return (int(const_value) & 0xFFFFFFFFFFFFFFFF) not in case_values


def find_switch_loop_guard_blocks(
    flow_graph: FlowGraph,
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

    dispatcher = flow_graph.get_block(int(dispatcher_serial))
    if dispatcher is None:
        return frozenset()

    guards: set[int] = set()
    for pred_serial in dispatcher.preds:
        pred_block = flow_graph.get_block(int(pred_serial))
        if pred_block is None:
            continue
        succs = pred_block.succs
        if (
            len(succs) == 2
            and int(dispatcher_serial) in succs
            and len(pred_block.preds) >= 2
            and _guard_compares_state_to_terminal(
                pred_block,
                state_var_stkoff=state_var_stkoff,
                case_values=case_values,
            )
        ):
            guards.add(int(pred_serial))
    return frozenset(guards)


def _observe_state_dispatcher_map(
    flow_graph: FlowGraph,
    dispatch_map: StateDispatcherMap,
) -> None:
    try:
        from d810.recon.observability import observe_state_dispatcher_rows

        observe_state_dispatcher_rows(
            func_ea=int(flow_graph.func_ea),
            maturity=_maturity_label(flow_graph),
            dispatcher_entry_block=dispatch_map.dispatcher_entry_block,
            dispatcher_kind=dispatch_map.source.name,
            rows=dispatch_map.rows,
        )
    except Exception:
        logger.debug(
            "switch-table state dispatcher observation failed",
            exc_info=True,
        )


def analyze_switch_table_flow_graph(
    flow_graph: FlowGraph,
) -> SwitchTableResult | None:
    """Walk a portable CFG snapshot and extract exact switch dispatcher rows.

    Scans all blocks for table-jump tail instructions. For the first
    qualifying switch (>= 2 cases after filtering), extracts the case-target
    mapping, identifies the state variable, and returns the exact
    state-dispatcher map with the portable state-variable operand snapshot.

    Returns:
        ``SwitchTableResult`` if a switch-table dispatcher was found,
        None otherwise.
    """
    for serial, blk in sorted(flow_graph.blocks.items()):
        if blk.tail is None or blk.tail_kind is not InsnKind.TABLE_JUMP:
            continue

        state_var_operand = blk.tail.l
        stkoff = _find_state_var_stkoff(state_var_operand)
        if stkoff is None:
            logger.debug(
                "table jump at blk[%d]: could not identify state variable stkoff",
                serial,
            )
            continue

        cases = _extract_cases_from_switch_operand(blk.tail.r, serial)
        if len(cases) < 2:
            logger.debug(
                "table jump at blk[%d]: too few cases (%d), skipping",
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
                flow_graph,
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
        _observe_state_dispatcher_map(flow_graph, state_dispatcher_map)
        handler_map = state_dispatcher_map.to_dispatcher_handler_map()

        logger.info(
            "Switch-table dispatcher at blk[%d]: %d handlers, stkoff=0x%X",
            serial,
            len(handler_map.handler_state_map),
            stkoff,
        )
        return SwitchTableResult(
            state_dispatcher_map=state_dispatcher_map,
            state_var_operand=state_var_operand,
        )

    return None
