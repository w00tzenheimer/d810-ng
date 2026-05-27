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
from d810.recon.flow.dispatcher_kind import DispatcherType
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


def _find_dispatcher_serial_by_ea(mba: object, ea: int | None) -> int | None:
    if ea is None:
        return None
    return _find_mba_block_for_instruction_ea(mba, int(ea))


def _find_materialized_dispatcher_serial(mba: object) -> int | None:
    best_serial = None
    best_preds = -1
    for serial in range(int(getattr(mba, "qty", 0) or 0)):
        blk = mba.get_mblock(serial)
        try:
            pred_count = int(blk.npred())
        except Exception:
            pred_count = 0
        if pred_count > best_preds:
            best_serial = int(serial)
            best_preds = pred_count
    return best_serial


def _find_mba_block_for_instruction_ea(mba: object, target_ea: int) -> int | None:
    target = int(target_ea)
    for serial in range(int(getattr(mba, "qty", 0) or 0)):
        blk = mba.get_mblock(serial)
        start = int(getattr(blk, "start", 0) or 0)
        if start == target:
            return int(serial)
        tail = getattr(blk, "tail", None)
        if tail is not None and int(getattr(tail, "ea", -1)) == target:
            return int(serial)
        insn = getattr(blk, "head", None)
        while insn is not None:
            try:
                if int(getattr(insn, "ea", -1)) == target:
                    return int(serial)
            except Exception:
                pass
            insn = getattr(insn, "next", None)
    return None


def _find_mba_block_for_ea(mba: object, target_ea: int) -> int | None:
    return _find_mba_block_for_instruction_ea(mba, target_ea)


def _find_mba_block_for_target_interval(
    mba: object,
    target_ea: int,
    next_target_ea: int | None,
) -> int | None:
    """Find a block whose first live instruction belongs to a native label.

    Hex-Rays may fold the setup instructions at a computed-goto label into
    call arguments, leaving no micro-instruction with the exact label EA.  The
    label is still represented by the first later instruction before the next
    table label.
    """
    target = int(target_ea)
    interval_end = int(next_target_ea) if next_target_ea is not None else None
    best: tuple[int, int] | None = None
    for serial in range(int(getattr(mba, "qty", 0) or 0)):
        blk = mba.get_mblock(serial)
        insn = getattr(blk, "head", None)
        while insn is not None:
            try:
                ea = int(getattr(insn, "ea", -1))
            except Exception:
                insn = getattr(insn, "next", None)
                continue
            if ea > target and (interval_end is None or ea < interval_end):
                candidate = (ea, int(serial))
                if best is None or candidate < best:
                    best = candidate
                break
            insn = getattr(insn, "next", None)
    return None if best is None else int(best[1])


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
    dispatch_jump_ea = _parse_int(cfg.get("dispatch_jump_ea"))
    dispatcher_serial = (
        _find_ijmp_dispatcher_serial(mba)
        if dispatch_jump_ea is None else
        _find_dispatcher_serial_by_ea(mba, dispatch_jump_ea)
    )
    if dispatcher_serial is None:
        dispatcher_serial = _find_ijmp_dispatcher_serial(mba)
    if dispatcher_serial is None and bool(cfg.get("materialized_targets", False)):
        dispatcher_serial = _find_materialized_dispatcher_serial(mba)
    if dispatcher_serial is None:
        logger.debug(
            "Tigress indirect config matched but no dispatcher block was found"
        )
        return None

    table_address = _parse_int(cfg.get("table_address"))
    table_count = _parse_int(cfg.get("table_nb_elt"), default=0)
    if table_address is None or not table_count:
        logger.debug("Tigress indirect config missing table address/count")
        return None

    initial_state = _parse_int(cfg.get("initial_state"))
    state_var_stkoff = _parse_int(cfg.get("state_var_stkoff"))
    state_base = _parse_int(cfg.get("state_base"), default=1) or 1

    import ida_bytes  # type: ignore[import-untyped]

    raw_targets = tuple(
        int(ida_bytes.get_qword(int(table_address) + index * 8))
        for index in range(int(table_count))
    )
    unique_targets = sorted({target for target in raw_targets if target})
    next_target_by_ea = {
        int(target): (
            int(unique_targets[index + 1])
            if index + 1 < len(unique_targets) else
            None
        )
        for index, target in enumerate(unique_targets)
    }
    entries: list[IndirectJumpTableEntry] = []
    for index, target_ea in enumerate(raw_targets):
        target_block = _find_mba_block_for_ea(mba, target_ea)
        if target_block is None:
            target_block = _find_mba_block_for_target_interval(
                mba,
                target_ea,
                next_target_by_ea.get(int(target_ea)),
            )
        entries.append(
            IndirectJumpTableEntry(
                state_const=int(state_base) + index,
                target_ea=target_ea,
                target_block=target_block,
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
