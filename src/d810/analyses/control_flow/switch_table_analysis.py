"Switch-table dispatcher analysis.\n\nExtracts exact state-dispatcher rows from portable ``FlowGraph`` switch-table\nsnapshots. Live Hex-Rays adapters live above preanalysis and call\n``analyze_switch_table_flow_graph()`` after lifting an MBA.\n\nd81-qlal -- canonical Instruction port.  The operand reads no longer touch the\nbackend-shaped ``InsnSnapshot`` operand slots (``.l`` / ``.r`` / ``.d``).  Each\ntail :class:`~d810.ir.flowgraph.InsnSnapshot` is projected through\n:func:`~d810.ir.insn_projection.project_instruction` to the canonical\n:class:`~d810.ir.instructions.Instruction`, and:\n\n* the switch case-target pairs (was ``blk.tail.r.switch_cases``) are read off\n  ``Instruction.control.switch_cases``;\n* the table-jump state variable (was ``blk.tail.l`` -> ``stack_refs`` / ``stkoff``\n  / ``size``) is read off ``Instruction.inputs`` -- a ``Varnode`` in the STACK\n  identity space (the projection exposes the SUBINSN/stack-ref state operand as a\n  ``Varnode(Space.STACK, offset, size)`` input);\n* the loop-guard compare operands (was ``tail.l`` / ``tail.r``) are read off the\n  canonical slot-aligned storage views (``operand_storages`` -> ``l`` / ``r``):\n  a ``NUMBER`` operand projects to a ``Varnode(Space.CONST, value, size)`` and a\n  stack operand to a ``Varnode(Space.STACK, offset, size)``.\n\nSTRUCTURAL block topology stays direct -- ``flow_graph.get_block`` /\n``BlockSnapshot.tail`` / ``.succs`` / ``.preds`` / ``.tail_kind`` /\n``.is_conditional_jump`` are portable model surfaces, not operand slots.\n"

from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.value_flow.induction_carrier import _const_value_from_varnode
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
from d810.ir.insn_projection import operand_storages, project_instruction
from d810.ir.locations import WeakStackSlot
from d810.ir.varnode import Space, Varnode
from d810.core.logging import getLogger
from d810.core.typing import Callable
from d810.capabilities.dispatcher import RouterKind, TableProvenance
from d810.analyses.control_flow.dispatcher_resolution import (
    StateDispatcherMap,
    StateDispatcherRow,
)

logger = getLogger("D810.analyses.control_flow.switch_table")

# Diag sink for observed dispatcher rows. A pure analyses module must not import
# the diagnostics-layer observability wrapper; the live caller injects the real
# ``observe_state_dispatcher_rows`` sink and tests/fixtures default to no-op
# (dissolution, llr-lyly).
ObserveDispatcherRows = Callable[..., None]


@dataclass(frozen=True)
class SwitchTableResult:
    """Bundled result from switch-table dispatcher analysis.

    Couples the exact dispatcher map with the canonical operand identity
    (:class:`~d810.ir.varnode.Varnode`) of the state variable used by the table
    jump -- a typeless ``(space, offset, size)`` slice, not a backend operand
    snapshot.
    """

    state_dispatcher_map: StateDispatcherMap
    state_var_operand: Varnode


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
                if target in dispatcher_blocks
                else "dispatcher_default"
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
                router_kind=RouterKind.TABLE,
                confidence=1.0,
                row_kind=row_kind,
                table_provenance=TableProvenance.SWITCH,
            )
        )
    return StateDispatcherMap(
        rows=tuple(rows),
        dispatcher_entry_block=int(dispatcher_serial),
        dispatcher_blocks=dispatcher_blocks,
        state_var_stkoff=state_var_stkoff,
        state_var_lvar_idx=None,
        router_kind=RouterKind.TABLE,
        initial_state=initial_state,
        default_target_block=default_target,
        default_row_kind=default_kind,
        table_provenance=TableProvenance.SWITCH,
    )


def _find_table_jump_state_var(insn: InsnSnapshot) -> Varnode | None:
    """Return the canonical STACK state-variable operand of a table jump.

    Read off the canonical ``Instruction.inputs`` for the table-branch tail:
    the projection exposes the (possibly SUBINSN-wrapped) state operand's stack
    reference as a ``Varnode(Space.STACK, offset, size)`` input, never from the
    raw ``insn.l`` operand slot.  The first STACK input is the table state
    variable (matching the previous ``stack_refs[0]`` / ``stkoff`` read).
    """
    for value in project_instruction(insn).inputs:
        if value.space is Space.STACK:
            return value
    return None


def _extract_cases_from_switch_control(
    insn: InsnSnapshot,
    dispatcher_serial: int,
) -> list[tuple[int | None, int]]:
    """Extract ``(case_value, target_serial)`` pairs from switch cases.

    Default cases are represented as ``(None, target_serial)``.  The case-target
    pairs are read off the canonical ``Instruction.control.switch_cases`` (was
    ``insn.r.switch_cases``); the ``dispatcher_serial`` parameter keeps the
    helper signature aligned with the previous live-MBA version and makes call
    sites self-documenting.
    """
    cases: list[tuple[int | None, int]] = []
    _ = dispatcher_serial
    control = project_instruction(insn).control
    if control is None:
        return cases
    for case in control.switch_cases:
        if len(case.values) == 0:
            cases.append((None, int(case.target)))
            continue
        for value in case.values:
            cases.append((int(value), int(case.target)))
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


def _storage_const_value(storage: Varnode | WeakStackSlot | None) -> int | None:
    """Return the numeric constant for a CONST storage view, else ``None``.

    ``storage`` is a canonical ``operand_storages`` view (a ``Varnode`` for a
    numeric operand projects to ``Space.CONST``; a ``WeakStackSlot`` / ``None``
    carries no constant), so the const test matches the previous
    ``varnode_from_mop_snapshot(...) is CONST`` / ``mop.value`` read.
    """
    if not isinstance(storage, Varnode):
        return None
    return _const_value_from_varnode(storage)


def _storage_contains_stkoff(
    storage: Varnode | WeakStackSlot | None,
    state_var_stkoff: int,
) -> bool:
    """Return whether a STACK storage view references ``state_var_stkoff``.

    ``storage`` is a canonical ``operand_storages`` view: a stack operand
    projects to ``Varnode(Space.STACK, offset, size)`` whose ``offset`` is the
    state-var stack offset (matching the previous ``stack_refs`` / ``stkoff``
    read on the lifted operand snapshot).
    """
    if not isinstance(storage, Varnode) or storage.space is not Space.STACK:
        return False
    return int(storage.offset) == int(state_var_stkoff)


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

    left, right, _dest = operand_storages(tail)
    left_is_state = _storage_contains_stkoff(left, state_var_stkoff)
    right_is_state = _storage_contains_stkoff(right, state_var_stkoff)
    if left_is_state == right_is_state:
        return False
    const_storage = right if left_is_state else left
    const_value = _storage_const_value(const_storage)
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
    observe_dispatcher_rows: ObserveDispatcherRows | None,
) -> None:
    if observe_dispatcher_rows is None:
        return
    try:
        observe_dispatcher_rows(
            func_ea=int(flow_graph.func_ea),
            maturity=_maturity_label(flow_graph),
            dispatcher_entry_block=dispatch_map.dispatcher_entry_block,
            dispatcher_kind=dispatch_map.router_kind.name,
            rows=dispatch_map.rows,
        )
    except Exception:
        logger.debug(
            "switch-table state dispatcher observation failed",
            exc_info=True,
        )


def analyze_switch_table_flow_graph(
    flow_graph: FlowGraph,
    *,
    observe_dispatcher_rows: ObserveDispatcherRows | None = None,
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

        state_var_node = _find_table_jump_state_var(blk.tail)
        if state_var_node is None:
            logger.debug(
                "table jump at blk[%d]: could not identify state variable stkoff",
                serial,
            )
            continue

        stkoff = int(state_var_node.offset)
        state_var_operand = Varnode(
            Space.STACK,
            stkoff,
            int(state_var_node.size or 0),
        )

        cases = _extract_cases_from_switch_control(blk.tail, serial)
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
        dispatcher_blocks = frozenset(
            {
                serial,
                *find_switch_loop_guard_blocks(
                    flow_graph,
                    serial,
                    state_var_stkoff=stkoff,
                    case_values=case_values,
                ),
            }
        )
        state_dispatcher_map = build_state_dispatcher_map_from_cases(
            cases=cases,
            dispatcher_serial=serial,
            dispatcher_blocks=dispatcher_blocks,
            state_var_stkoff=stkoff,
        )
        _observe_state_dispatcher_map(
            flow_graph, state_dispatcher_map, observe_dispatcher_rows
        )
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
