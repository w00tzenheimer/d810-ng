"""Tigress indirect jump-table dispatcher analysis.

The live Hex-Rays MBA for Tigress computed-goto samples may expose only the
table-copy stub and final ``m_ijmp`` block, while the native function bytes
still contain the label bodies.  This module records that calibrated table as
shape-neutral dispatcher evidence without pretending missing native labels are
live MBA blocks.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.recon.flow.dispatcher_detection import DispatcherType
from d810.recon.flow.dispatcher_map import (
    StateDispatcherMap,
    StateDispatcherRow,
)

logger = getLogger("D810.recon.indirect_jump_table")


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


def _parse_int(value: object, *, default: int | None = None) -> int | None:
    if value is None:
        return default
    if isinstance(value, int):
        return int(value)
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return default


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
                source=DispatcherType.INDIRECT_JUMP,
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
        source=DispatcherType.INDIRECT_JUMP,
        initial_state=initial_state,
        default_target_block=None,
        default_row_kind=None,
    )


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


def _function_key(mba: object) -> str:
    return f"0x{int(getattr(mba, 'entry_ea', 0) or 0):x}"


def _config_for_function(
    mba: object,
    goto_table_info: Mapping[str, object],
) -> Mapping[str, object] | None:
    key = _function_key(mba).lower()
    for raw_func_ea, raw_config in goto_table_info.items():
        if str(raw_func_ea).lower() != key:
            continue
        if isinstance(raw_config, Mapping):
            return raw_config
    return None


def _find_ijmp_dispatcher_serial(mba: object) -> int | None:
    import ida_hexrays  # type: ignore[import-untyped]

    for serial in range(int(getattr(mba, "qty", 0) or 0)):
        blk = mba.get_mblock(serial)
        tail = getattr(blk, "tail", None)
        if tail is not None and int(tail.opcode) == int(ida_hexrays.m_ijmp):
            return int(serial)
    return None


def _find_mba_block_for_ea(mba: object, target_ea: int) -> int | None:
    target = int(target_ea)
    for serial in range(int(getattr(mba, "qty", 0) or 0)):
        blk = mba.get_mblock(serial)
        start = int(getattr(blk, "start", 0) or 0)
        end = int(getattr(blk, "end", 0) or 0)
        if start == target:
            return int(serial)
        if start <= target < end:
            return int(serial)
    return None


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
            "indirect jump-table state dispatcher observation failed",
            exc_info=True,
        )


def analyze_tigress_indirect_dispatcher_from_config(
    mba: object,
    goto_table_info: Mapping[str, object],
) -> IndirectJumpTableResult | None:
    """Decode configured Tigress indirect table rows for the current MBA."""
    cfg = _config_for_function(mba, goto_table_info)
    if cfg is None:
        return None
    dispatcher_serial = _find_ijmp_dispatcher_serial(mba)
    if dispatcher_serial is None:
        logger.debug("Tigress indirect config matched but no m_ijmp block was found")
        return None

    table_address = _parse_int(cfg.get("table_address"))
    table_count = _parse_int(cfg.get("table_nb_elt"), default=0)
    if table_address is None or not table_count:
        logger.debug("Tigress indirect config missing table address/count")
        return None

    initial_state = _parse_int(cfg.get("initial_state"))
    state_var_stkoff = _parse_int(
        cfg.get("state_var_stkoff"),
        default=_parse_int(cfg.get("stack_table_offset")),
    )
    state_base = _parse_int(cfg.get("state_base"), default=1) or 1

    import ida_bytes  # type: ignore[import-untyped]

    entries: list[IndirectJumpTableEntry] = []
    for index in range(int(table_count)):
        target_ea = int(ida_bytes.get_qword(int(table_address) + index * 8))
        entries.append(
            IndirectJumpTableEntry(
                state_const=int(state_base) + index,
                target_ea=target_ea,
                target_block=_find_mba_block_for_ea(mba, target_ea),
            )
        )

    dispatch_map = build_state_dispatcher_map_from_indirect_entries(
        tuple(entries),
        dispatcher_serial=dispatcher_serial,
        dispatcher_blocks=frozenset({dispatcher_serial}),
        state_var_stkoff=state_var_stkoff,
        initial_state=initial_state,
        table_address=int(table_address),
    )
    _observe_state_dispatcher_map(mba, dispatch_map)
    missing = sum(1 for entry in entries if entry.target_block is None)
    logger.info(
        "Tigress indirect dispatcher at blk[%d]: rows=%d missing_mba_targets=%d",
        dispatcher_serial,
        len(entries),
        missing,
    )
    return IndirectJumpTableResult(
        state_dispatcher_map=dispatch_map,
        entries=tuple(entries),
        missing_target_count=missing,
    )


__all__ = [
    "IndirectJumpTableEntry",
    "IndirectJumpTableResult",
    "analyze_tigress_indirect_dispatcher_from_config",
    "build_state_dispatcher_map_from_indirect_entries",
]
