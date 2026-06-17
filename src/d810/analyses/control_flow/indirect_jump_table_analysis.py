"""Tigress indirect jump-table dispatcher analysis.

The live Hex-Rays MBA for Tigress computed-goto samples may expose only the
table-copy stub and final ``m_ijmp`` block, while the native function bytes
still contain the label bodies.  This module records that calibrated table as
shape-neutral dispatcher evidence without pretending missing native labels are
live MBA blocks.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.capabilities.dispatcher import RouterKind
from d810.ir.flowgraph import FlowGraph
from d810.analyses.control_flow.dispatcher_resolution import (
    StateDispatcherMap,
    StateDispatcherRow,
)


@dataclass(frozen=True)
class IndirectJumpTableEntry:
    """One decoded indirect table entry."""

    state_const: int
    target_ea: int
    target_block: int | None = None


@dataclass(frozen=True)
class IndirectJumpTableResult:
    """Bundled result from indirect jump-table analysis."""

    state_dispatcher_map: StateDispatcherMap
    entries: tuple[IndirectJumpTableEntry, ...]
    missing_target_count: int


def build_state_dispatcher_map_from_indirect_entries(
    entries: tuple[IndirectJumpTableEntry, ...],
    *,
    dispatcher_serial: int,
    dispatcher_blocks: frozenset[int],
    state_var_stkoff: int | None,
    initial_state: int | None = None,
    table_address: int | None = None,
) -> StateDispatcherMap:
    """Build exact state-dispatcher rows from decoded indirect table entries."""
    rows: list[StateDispatcherRow] = []
    for table_index, entry in enumerate(entries):
        has_target_block = entry.target_block is not None
        row_kind = "handler" if has_target_block else "missing_mba_target"
        branch_kind = (
            "indirect_jump_table"
            if has_target_block else "indirect_jump_table_missing_target"
        )
        rows.append(
            StateDispatcherRow(
                state_const=int(entry.state_const) & 0xFFFFFFFFFFFFFFFF,
                target_block=(
                    int(entry.target_block)
                    if entry.target_block is not None else -1
                ),
                dispatcher_block=int(dispatcher_serial),
                compare_block=None,
                branch_kind=branch_kind,
                router_kind=RouterKind.INDIRECT_TABLE,
                confidence=1.0,
                row_kind=row_kind,
                payload={
                    "table_index": int(table_index),
                    "target_ea_hex": (
                        f"0x{int(entry.target_ea) & 0xFFFFFFFFFFFFFFFF:016x}"
                    ),
                    "target_ea_i64": int(entry.target_ea),
                    "target_materialized": bool(has_target_block),
                    "table_address_hex": (
                        None
                        if table_address is None else
                        f"0x{int(table_address) & 0xFFFFFFFFFFFFFFFF:016x}"
                    ),
                },
            )
        )
    return StateDispatcherMap(
        rows=tuple(rows),
        dispatcher_entry_block=int(dispatcher_serial),
        dispatcher_blocks=frozenset(int(block) for block in dispatcher_blocks),
        state_var_stkoff=state_var_stkoff,
        state_var_lvar_idx=None,
        router_kind=RouterKind.INDIRECT_TABLE,
        initial_state=initial_state,
        default_target_block=None,
        default_row_kind=None,
    )


def _find_dispatcher_serial_by_ea(flow_graph: FlowGraph, ea: int | None) -> int | None:
    if ea is None:
        return None
    return _find_mba_block_for_instruction_ea(flow_graph, int(ea))


def _find_mba_block_for_instruction_ea(flow_graph: FlowGraph, target_ea: int) -> int | None:
    target = int(target_ea)
    for serial, blk in flow_graph.blocks.items():
        if int(blk.start_ea) == target:
            return int(serial)
        tail = blk.tail
        if tail is not None and int(tail.ea) == target:
            return int(serial)
        for insn in blk.insn_snapshots:
            if int(insn.ea) == target:
                return int(serial)
    return None


def _find_mba_block_for_ea(flow_graph: FlowGraph, target_ea: int) -> int | None:
    return _find_mba_block_for_instruction_ea(flow_graph, target_ea)


def _find_mba_block_for_target_interval(
    flow_graph: FlowGraph,
    target_ea: int,
    next_target_ea: int | None,
) -> int | None:
    """Find a block whose first instruction belongs to a native label.

    Hex-Rays may fold the setup instructions at a computed-goto label into
    call arguments, leaving no micro-instruction with the exact label EA.  The
    label is still represented by the first later instruction before the next
    table label.
    """
    target = int(target_ea)
    interval_end = int(next_target_ea) if next_target_ea is not None else None
    best: tuple[int, int] | None = None
    for serial, blk in flow_graph.blocks.items():
        for insn in blk.insn_snapshots:
            ea = int(insn.ea)
            if ea > target and (interval_end is None or ea < interval_end):
                candidate = (ea, int(serial))
                if best is None or candidate < best:
                    best = candidate
                break
    return None if best is None else int(best[1])


__all__ = [
    "IndirectJumpTableEntry",
    "IndirectJumpTableResult",
    "build_state_dispatcher_map_from_indirect_entries",
]
