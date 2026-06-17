"""Live Tigress indirect jump-table dispatcher analysis."""
from __future__ import annotations

from collections.abc import Mapping

from d810.core.logging import getLogger
from d810.hexrays.mutation.ir_translator import lift
from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap
from d810.analyses.control_flow.indirect_jump_table_analysis import (
    IndirectJumpTableEntry,
    IndirectJumpTableResult,
    _find_dispatcher_serial_by_ea,
    _find_mba_block_for_ea,
    _find_mba_block_for_target_interval,
    build_state_dispatcher_map_from_indirect_entries,
)

logger = getLogger("D810.optimizers.indirect_jump_table")

from d810.hexrays.preanalysis.indirect_jump_discovery import (
    DiscoveredIndirectJumpTable,
    discover_indirect_jump_table,
)



def _parse_int(value: object, *, default: int | None = None) -> int | None:
    if value is None:
        return default
    if isinstance(value, int):
        return int(value)
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return default


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


def _observe_state_dispatcher_map(
    mba: object,
    dispatch_map: StateDispatcherMap,
) -> None:
    try:
        from d810.core.observability_recon import observe_state_dispatcher_rows

        observe_state_dispatcher_rows(
            func_ea=int(getattr(mba, "entry_ea", 0) or 0),
            maturity=_maturity_label(mba),
            dispatcher_entry_block=dispatch_map.dispatcher_entry_block,
            dispatcher_kind=dispatch_map.router_kind.name,
            rows=dispatch_map.rows,
        )
    except Exception:
        logger.debug(
            "indirect jump-table state dispatcher observation failed",
            exc_info=True,
        )



def _config_table_targets_in_function(
    mba: object,
    table_address: int | None,
    table_count: int | None,
) -> bool:
    """Return True when configured table reads in-function code pointers.

    A rebuild that shifts the binary leaves configured ``table_address`` values
    pointing at garbage; in that case discovery must take over.  We accept the
    configured table only when its leading entry is owned by the function being
    decompiled.
    """
    if not table_address or not table_count:
        return False
    try:
        import ida_bytes  # type: ignore[import-untyped]
        import ida_funcs  # type: ignore[import-untyped]

        func = ida_funcs.get_func(int(getattr(mba, "entry_ea", 0) or 0))
        if func is None:
            return False
        first = int(ida_bytes.get_qword(int(table_address)))
        return int(func.start_ea) <= first < int(func.end_ea)
    except Exception:
        logger.debug("config table validity probe failed", exc_info=True)
        return False


def _resolve_indirect_layout(
    mba: object,
    cfg: Mapping[str, object] | None,
) -> tuple[int | None, int, int | None, DiscoveredIndirectJumpTable | None]:
    """Resolve effective ``(table_address, table_count, dispatch_jump_ea)``.

    Configured values are an OPTIONAL override: when present *and* still valid
    for the function being decompiled they win; otherwise the layout is
    discovered structurally from the indirect jump's table operand.
    """
    cfg_table_address = (
        _parse_int(cfg.get("table_address")) if cfg is not None else None
    )
    cfg_table_count = (
        _parse_int(cfg.get("table_nb_elt"), default=0) if cfg is not None else 0
    )
    cfg_dispatch_jump_ea = (
        _parse_int(cfg.get("dispatch_jump_ea")) if cfg is not None else None
    )
    if _config_table_targets_in_function(mba, cfg_table_address, cfg_table_count):
        return cfg_table_address, int(cfg_table_count or 0), cfg_dispatch_jump_ea, None

    function_ea = int(getattr(mba, "entry_ea", 0) or 0)
    discovered = discover_indirect_jump_table(function_ea)
    if discovered is None:
        # No structural table; fall back to whatever config provided (may be
        # None -> caller treats as "missing").
        return cfg_table_address, int(cfg_table_count or 0), cfg_dispatch_jump_ea, None
    return (
        discovered.table_address,
        int(discovered.table_count),
        discovered.dispatch_jump_ea,
        discovered,
    )


def analyze_tigress_indirect_dispatcher_from_config(
    mba: object,
    goto_table_info: Mapping[str, object],
) -> IndirectJumpTableResult | None:
    """Decode Tigress indirect table rows for the current MBA.

    Configured ``goto_table_info`` is an OPTIONAL override.  When no config key
    matches the function being decompiled (or the configured table address is
    stale after a rebuild), the table layout is recovered structurally from the
    indirect jump's table operand, so the engine fires address-agnostically.
    """
    cfg = _config_for_function(mba, goto_table_info)
    # Lift once at the HIGH boundary; the portable EA-lookup helpers consume
    # the FlowGraph snapshot (llr-zeyu upstream-lift).
    flow_graph = lift(mba)

    table_address, table_count, dispatch_jump_ea, discovered = (
        _resolve_indirect_layout(mba, cfg)
    )
    if table_address is None or not table_count:
        logger.debug("Tigress indirect: no configured or discovered table layout")
        return None

    dispatcher_serial = (
        _find_ijmp_dispatcher_serial(mba)
        if dispatch_jump_ea is None else
        _find_dispatcher_serial_by_ea(flow_graph, dispatch_jump_ea)
    )
    if dispatcher_serial is None:
        dispatcher_serial = _find_ijmp_dispatcher_serial(mba)
    # After the unflatten indirect prepass MATERIALIZES the computed-goto label
    # bodies (I1.5), the m_ijmp is GONE (direct flow; no m_jtbl either) and the
    # configured ``dispatch_jump_ea`` no longer names a block tail -- so both
    # lookups above return None.  Recognition must still succeed (llr-tm3i):
    # fall back to the materialized hub when materialization happened, which is
    # signalled by EITHER an explicit config flag OR a structural discovery
    # (``discovered is not None`` -- the table was recovered from the binary,
    # which only the materializing unflatten indirect config runs).  This is the
    # address-agnostic path: a config whose key drifted after a rebuild yields
    # ``cfg is None`` yet still discovers + materializes the table.
    if dispatcher_serial is None and (
        discovered is not None
        or (cfg is not None and bool(cfg.get("materialized_targets", False)))
    ):
        dispatcher_serial = _find_materialized_dispatcher_serial(mba)
    if dispatcher_serial is None:
        logger.debug(
            "Tigress indirect layout resolved but no dispatcher block was found"
        )
        return None

    initial_state = _parse_int(cfg.get("initial_state")) if cfg is not None else None
    state_var_stkoff = (
        _parse_int(cfg.get("state_var_stkoff")) if cfg is not None else None
    )
    state_base = (
        (_parse_int(cfg.get("state_base"), default=1) or 1)
        if cfg is not None
        else 1
    )
    # Backfill state-machine parameters from structural discovery when config
    # omits them (no matching config entry, or partial override).
    if discovered is not None:
        if initial_state is None and discovered.initial_state is not None:
            initial_state = int(discovered.initial_state)
        if state_var_stkoff is None and discovered.state_var_stkoff is not None:
            state_var_stkoff = int(discovered.state_var_stkoff)
    if discovered is not None:
        logger.info(
            "Tigress indirect dispatcher discovered structurally for 0x%X: "
            "table=0x%X count=%d dispatch_jump=0x%X source=%s",
            int(getattr(mba, "entry_ea", 0) or 0),
            int(table_address),
            int(table_count),
            int(dispatch_jump_ea or 0),
            discovered.source,
        )

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
        target_block = _find_mba_block_for_ea(flow_graph, target_ea)
        if target_block is None:
            target_block = _find_mba_block_for_target_interval(
                flow_graph,
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
    "analyze_tigress_indirect_dispatcher_from_config",
]
