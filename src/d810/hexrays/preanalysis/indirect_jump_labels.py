"""Materialize computed-goto label targets before Hex-Rays builds an MBA.

Tigress indirect flattening copies a native label table to the stack and then
dispatches with ``ijmp`` through that stack slot.  IDA may keep the native label
bodies outside the function graph used by Hex-Rays, so the resulting MBA only
contains the table-copy stub and final indirect jump.  This module performs the
IDA-specific preanalysis needed to make those labels visible to Hex-Rays.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from d810.core.logging import getLogger

logger = getLogger("D810.hexrays.preanalysis.indirect_jump_labels")

from d810.hexrays.preanalysis.indirect_jump_discovery import (
    discover_indirect_jump_table,
)


@dataclass(frozen=True)
class IndirectLabelMaterializationPlan:
    """Native label range to attach to a function before decompile."""

    function_ea: int
    label_start: int
    label_end: int
    table_address: int
    table_count: int
    target_eas: tuple[int, ...]


@dataclass(frozen=True)
class IndirectLabelMaterializationResult:
    """Outcome from one configured indirect-label materialization attempt."""

    function_ea: int
    table_address: int | None
    table_count: int
    label_start: int | None
    label_end: int | None
    target_count: int
    materialized_target_count: int
    dispatch_jump_ea: int | None
    jump_xref_count: int
    switch_info_installed: bool
    appended_tail: bool
    success: bool
    reason: str
    boundary_flow_xref_count: int = 0
    resolved_state_xref_count: int = 0


def _parse_int(value: object, *, default: int | None = None) -> int | None:
    if value is None:
        return default
    if isinstance(value, int):
        return int(value)
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return default


def plan_indirect_label_materialization(
    *,
    function_ea: int,
    table_address: int,
    target_eas: Sequence[int],
    configured_label_start: int | None = None,
    configured_label_end: int | None = None,
    discovered_function_end: int | None = None,
    discovered_next_function_start: int | None = None,
) -> IndirectLabelMaterializationPlan | None:
    """Plan the native label range represented by a computed-goto table."""
    unique_targets = tuple(sorted({int(target) for target in target_eas if target}))
    if not unique_targets:
        return None
    label_start = int(configured_label_start or min(unique_targets))
    if configured_label_end is not None:
        label_end = int(configured_label_end)
    elif discovered_function_end is not None and int(discovered_function_end) > max(unique_targets):
        label_end = int(discovered_function_end)
    elif (
        discovered_next_function_start is not None
        and int(discovered_next_function_start) > max(unique_targets)
    ):
        label_end = int(discovered_next_function_start)
    else:
        return None
    if label_end <= label_start:
        return None
    return IndirectLabelMaterializationPlan(
        function_ea=int(function_ea),
        label_start=label_start,
        label_end=label_end,
        table_address=int(table_address),
        table_count=len(tuple(target_eas)),
        target_eas=unique_targets,
    )


def _target_owner_matches(func: object, target_ea: int) -> bool:
    try:
        import ida_funcs  # type: ignore[import-untyped]

        owner = ida_funcs.get_func(int(target_ea))
        return (
            owner is not None
            and int(getattr(owner, "start_ea", -1)) == int(getattr(func, "start_ea", -2))
        )
    except Exception:
        return False


def _count_materialized_targets(
    func: object,
    targets: Sequence[int],
) -> int:
    return sum(1 for target in targets if _target_owner_matches(func, int(target)))


def _read_table_targets(table_address: int, table_count: int) -> tuple[int, ...]:
    import ida_bytes  # type: ignore[import-untyped]

    return tuple(
        int(ida_bytes.get_qword(int(table_address) + index * 8))
        for index in range(int(table_count))
    )


def _discover_next_function_start(function_ea: int) -> int | None:
    try:
        import ida_funcs  # type: ignore[import-untyped]

        next_func = ida_funcs.get_next_func(int(function_ea))
        if next_func is None:
            return None
        return int(getattr(next_func, "start_ea", 0) or 0) or None
    except Exception:
        return None


def _create_target_instructions(targets: Sequence[int]) -> None:
    import idaapi  # type: ignore[import-untyped]

    for target in sorted({int(target) for target in targets}):
        try:
            idaapi.create_insn(target)
        except Exception:
            logger.debug("failed creating instruction at 0x%X", target, exc_info=True)


def _find_indirect_jump_ea(start: int, end: int) -> int | None:
    import ida_bytes  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]
    import idc  # type: ignore[import-untyped]

    ea = int(start)
    stop = int(end)
    badaddr = int(getattr(idaapi, "BADADDR", -1))
    while ea != badaddr and ea < stop:
        mnemonic = str(idc.print_insn_mnem(ea) or "").lower()
        operand = str(idc.print_operand(ea, 0) or "").lower()
        if mnemonic == "jmp" and operand:
            if operand.startswith(("loc_", "sub_", "0x")):
                pass
            elif operand.startswith(("qword ptr", "cs:", "ds:")):
                pass
            else:
                return ea
        next_ea = int(ida_bytes.next_head(ea, stop))
        if next_ea == badaddr or next_ea <= ea:
            break
        ea = next_ea
    return None


def _add_jump_target_crefs(dispatch_jump_ea: int | None, targets: Sequence[int]) -> int:
    if dispatch_jump_ea is None:
        return 0
    try:
        import ida_xref  # type: ignore[import-untyped]

        count = 0
        for target in sorted({int(target) for target in targets}):
            if ida_xref.add_cref(
                int(dispatch_jump_ea),
                target,
                ida_xref.fl_JN | ida_xref.XREF_USER,
            ):
                count += 1
        return count
    except Exception:
        logger.debug(
            "failed adding indirect jump target code references from 0x%X",
            int(dispatch_jump_ea),
            exc_info=True,
        )
        return 0


def _add_user_cref_with_fallback(source_ea: int, target_ea: int) -> bool:
    """Add an analysis-only code reference using the narrowest accepted kind."""
    import ida_xref  # type: ignore[import-untyped]

    flags = (
        ida_xref.fl_JN,
        ida_xref.fl_CF,
        ida_xref.fl_F,
    )
    for flag in flags:
        try:
            if ida_xref.add_cref(
                int(source_ea),
                int(target_ea),
                int(flag) | ida_xref.XREF_USER,
            ):
                return True
        except Exception:
            logger.debug(
                "failed adding indirect-label cref 0x%X -> 0x%X flags=0x%X",
                int(source_ea),
                int(target_ea),
                int(flag),
                exc_info=True,
            )
    return False


def _flowchart_block_starts(func: object) -> frozenset[int]:
    try:
        import ida_gdl  # type: ignore[import-untyped]

        return frozenset(int(block.start_ea) for block in ida_gdl.FlowChart(func))
    except Exception:
        logger.debug("failed reading function flowchart", exc_info=True)
        return frozenset()


def _add_missing_label_boundary_flow_crefs(
    func: object,
    targets: Sequence[int],
) -> int:
    """Force block boundaries for table labels hidden after no-fallthrough jumps."""
    try:
        import ida_bytes  # type: ignore[import-untyped]
        import idaapi  # type: ignore[import-untyped]
        import idc  # type: ignore[import-untyped]

        func_start = int(getattr(func, "start_ea", 0) or 0)
        badaddr = int(getattr(idaapi, "BADADDR", -1))
        count = 0
        for target in sorted({int(target) for target in targets}):
            prev_ea = int(ida_bytes.prev_head(target, func_start))
            if prev_ea == badaddr or prev_ea >= target:
                continue
            next_ea = int(ida_bytes.next_head(prev_ea, target + 16))
            if next_ea != target:
                continue
            mnemonic = str(idc.print_insn_mnem(prev_ea) or "").lower()
            if mnemonic != "jmp":
                continue
            if _add_user_cref_with_fallback(prev_ea, target):
                count += 1
        return count
    except Exception:
        logger.debug("failed adding boundary flow xrefs", exc_info=True)
        return 0


def _matches_rsp_state_write(ea: int, state_var_stkoff: int) -> int | None:
    try:
        import ida_bytes  # type: ignore[import-untyped]

        if int(ida_bytes.get_byte(ea)) != 0xC7:
            return None
        if int(ida_bytes.get_byte(ea + 1)) != 0x44:
            return None
        if int(ida_bytes.get_byte(ea + 2)) != 0x24:
            return None
        if int(ida_bytes.get_byte(ea + 3)) != (int(state_var_stkoff) & 0xFF):
            return None
        return int(ida_bytes.get_dword(ea + 4)) & 0xFFFFFFFF
    except Exception:
        return None


def _find_following_jump_ea(start_ea: int, stop_ea: int) -> int | None:
    try:
        import ida_bytes  # type: ignore[import-untyped]
        import idaapi  # type: ignore[import-untyped]
        import idc  # type: ignore[import-untyped]

        badaddr = int(getattr(idaapi, "BADADDR", -1))
        ea = int(ida_bytes.next_head(int(start_ea), int(stop_ea)))
        local_stop = min(int(stop_ea), int(start_ea) + 0x80)
        while ea != badaddr and ea < local_stop:
            mnemonic = str(idc.print_insn_mnem(ea) or "").lower()
            if mnemonic == "jmp":
                return int(ea)
            next_ea = int(ida_bytes.next_head(ea, int(stop_ea)))
            if next_ea == badaddr or next_ea <= ea:
                break
            ea = next_ea
    except Exception:
        logger.debug(
            "failed finding following jump after 0x%X",
            int(start_ea),
            exc_info=True,
        )
    return None


def _add_resolved_state_write_crefs(
    *,
    function_ea: int,
    label_end: int,
    targets: Sequence[int],
    state_base: int,
    state_var_stkoff: int | None,
) -> int:
    if state_var_stkoff is None:
        return 0
    try:
        import idaapi  # type: ignore[import-untyped]

        target_by_state = {
            int(state_base) + index: int(target)
            for index, target in enumerate(tuple(targets))
        }
        badaddr = int(getattr(idaapi, "BADADDR", -1))
        added_edges: set[tuple[int, int]] = set()
        ea = int(function_ea)
        stop = int(label_end)
        while ea != badaddr and ea + 8 <= stop:
            state_value = _matches_rsp_state_write(ea, int(state_var_stkoff))
            if state_value is not None:
                target = target_by_state.get(int(state_value))
                if target is None:
                    logger.debug(
                        "Tigress indirect state write has no table target: "
                        "state=0x%X write=0x%X",
                        int(state_value) & 0xFFFFFFFF,
                        int(ea),
                    )
                    ea += 1
                    continue
                jump_ea = _find_following_jump_ea(ea, stop)
                added = False
                if jump_ea is not None:
                    added = _add_user_cref_with_fallback(jump_ea, int(target))
                if not added:
                    added = _add_user_cref_with_fallback(ea, int(target))
                logger.debug(
                    "Tigress indirect resolved state edge state=0x%X "
                    "write=0x%X jump=%s target=0x%X added=%s",
                    int(state_value) & 0xFFFFFFFF,
                    int(ea),
                    "<none>" if jump_ea is None else f"0x{int(jump_ea):X}",
                    int(target) if target is not None else -1,
                    added,
                )
                if added:
                    added_edges.add((int(ea), int(target)))
                ea += 8
                continue
            ea += 1
        return len(added_edges)
    except Exception:
        logger.debug("failed adding resolved state-write xrefs", exc_info=True)
        return 0


def _install_switch_info(
    *,
    dispatch_jump_ea: int | None,
    function_ea: int,
    switch_start_ea: int | None,
    table_address: int,
    table_count: int,
    state_base: int,
) -> bool:
    if dispatch_jump_ea is None:
        return False
    try:
        import ida_nalt  # type: ignore[import-untyped]
        import idaapi  # type: ignore[import-untyped]

        si = ida_nalt.switch_info_t()
        si.clear()
        si.flags = ida_nalt.SWI_USER | ida_nalt.SWI_ELBASE
        si.jumps = int(table_address)
        si.ncases = int(table_count)
        si.defjump = int(getattr(idaapi, "BADADDR", -1))
        si.startea = int(switch_start_ea or dispatch_jump_ea or function_ea)
        si.expr_ea = int(dispatch_jump_ea)
        si.lowcase = int(state_base)
        si.set_elbase(0)
        si.set_jtable_element_size(8)
        si.set_jtable_size(int(table_count))
        ida_nalt.set_switch_info(int(dispatch_jump_ea), si)
        check = ida_nalt.switch_info_t()
        return bool(ida_nalt.get_switch_info(check, int(dispatch_jump_ea)))
    except Exception:
        logger.debug(
            "failed installing switch_info_t for indirect jump at 0x%X",
            int(dispatch_jump_ea),
            exc_info=True,
        )
        return False


def _append_tail(func: object, start: int, end: int) -> bool:
    try:
        import ida_funcs  # type: ignore[import-untyped]

        append = getattr(ida_funcs, "append_func_tail", None)
        if append is not None:
            return bool(append(func, int(start), int(end)))
    except Exception:
        logger.debug("ida_funcs.append_func_tail failed", exc_info=True)
    try:
        import idaapi  # type: ignore[import-untyped]

        append = getattr(idaapi, "append_func_tail", None)
        if append is not None:
            return bool(append(func, int(start), int(end)))
    except Exception:
        logger.debug("idaapi.append_func_tail failed", exc_info=True)
    return False


def _reanalyze_range(function_ea: int, start: int, end: int) -> None:
    import idaapi  # type: ignore[import-untyped]

    try:
        if hasattr(idaapi, "plan_and_wait"):
            idaapi.plan_and_wait(int(start), int(end))
    except Exception:
        logger.debug("plan_and_wait failed for 0x%X..0x%X", start, end, exc_info=True)
    try:
        import ida_funcs  # type: ignore[import-untyped]

        func = ida_funcs.get_func(int(function_ea))
        if func is not None:
            try:
                ida_funcs.reanalyze_function(func, int(start), int(end), True)
            except TypeError:
                ida_funcs.reanalyze_function(func)
    except Exception:
        logger.debug("reanalyze_function failed for 0x%X", function_ea, exc_info=True)
    try:
        idaapi.auto_wait()
    except Exception:
        logger.debug("auto_wait failed after indirect-label materialization", exc_info=True)
    try:
        if hasattr(idaapi, "mark_cfunc_dirty"):
            idaapi.mark_cfunc_dirty(int(function_ea), False)
    except Exception:
        logger.debug("mark_cfunc_dirty failed for 0x%X", function_ea, exc_info=True)


def materialize_indirect_label_targets(
    *,
    function_ea: int,
    table_address: int,
    table_count: int,
    label_start: int | None = None,
    label_end: int | None = None,
    dispatch_jump_ea: int | None = None,
    switch_start_ea: int | None = None,
    install_switch_info: bool = False,
    state_base: int = 1,
    state_var_stkoff: int | None = None,
) -> IndirectLabelMaterializationResult:
    """Attach configured computed-goto label bodies to their owning function."""
    import ida_funcs  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    function_ea = int(function_ea)
    table_address = int(table_address)
    table_count = int(table_count)
    if table_count <= 0:
        return IndirectLabelMaterializationResult(
            function_ea=function_ea,
            table_address=table_address,
            table_count=table_count,
            label_start=None,
            label_end=None,
            target_count=0,
            materialized_target_count=0,
            dispatch_jump_ea=None,
            jump_xref_count=0,
            switch_info_installed=False,
            appended_tail=False,
            success=False,
            reason="empty_table",
        )

    func = ida_funcs.get_func(function_ea) or idaapi.get_func(function_ea)
    if func is None:
        try:
            idaapi.add_func(function_ea)
        except Exception:
            logger.debug("add_func failed for 0x%X", function_ea, exc_info=True)
        func = ida_funcs.get_func(function_ea) or idaapi.get_func(function_ea)
    if func is None:
        return IndirectLabelMaterializationResult(
            function_ea=function_ea,
            table_address=table_address,
            table_count=table_count,
            label_start=None,
            label_end=None,
            target_count=0,
            materialized_target_count=0,
            dispatch_jump_ea=None,
            jump_xref_count=0,
            switch_info_installed=False,
            appended_tail=False,
            success=False,
            reason="missing_function",
        )

    targets = _read_table_targets(table_address, table_count)
    discovered_end = int(getattr(func, "end_ea", 0) or 0) or None
    plan = plan_indirect_label_materialization(
        function_ea=function_ea,
        table_address=table_address,
        target_eas=targets,
        configured_label_start=label_start,
        configured_label_end=label_end,
        discovered_function_end=discovered_end,
        discovered_next_function_start=_discover_next_function_start(function_ea),
    )
    if plan is None:
        return IndirectLabelMaterializationResult(
            function_ea=function_ea,
            table_address=table_address,
            table_count=table_count,
            label_start=None,
            label_end=None,
            target_count=len(tuple(targets)),
            materialized_target_count=_count_materialized_targets(func, targets),
            dispatch_jump_ea=None,
            jump_xref_count=0,
            switch_info_installed=False,
            appended_tail=False,
            success=False,
            reason="unbounded_label_range",
        )

    _create_target_instructions(plan.target_eas)
    indirect_jump_ea = (
        int(dispatch_jump_ea)
        if dispatch_jump_ea is not None else
        _find_indirect_jump_ea(function_ea, plan.label_end)
    )
    jump_xref_count = _add_jump_target_crefs(indirect_jump_ea, plan.target_eas)
    resolved_state_xref_count = _add_resolved_state_write_crefs(
        function_ea=function_ea,
        label_end=plan.label_end,
        targets=targets,
        state_base=int(state_base),
        state_var_stkoff=state_var_stkoff,
    )
    switch_info_installed = False
    if install_switch_info:
        switch_info_installed = _install_switch_info(
            dispatch_jump_ea=indirect_jump_ea,
            function_ea=function_ea,
            switch_start_ea=switch_start_ea,
            table_address=table_address,
            table_count=table_count,
            state_base=int(state_base),
        )
    before = _count_materialized_targets(func, plan.target_eas)
    appended_tail = False
    if before < len(plan.target_eas):
        appended_tail = _append_tail(func, plan.label_start, plan.label_end)
    _reanalyze_range(function_ea, plan.label_start, plan.label_end)

    func = ida_funcs.get_func(function_ea) or idaapi.get_func(function_ea)
    boundary_flow_xref_count = 0
    if func is not None:
        boundary_flow_xref_count = _add_missing_label_boundary_flow_crefs(
            func,
            plan.target_eas,
        )
        if boundary_flow_xref_count:
            _reanalyze_range(function_ea, plan.label_start, plan.label_end)
            refreshed_state_xref_count = _add_resolved_state_write_crefs(
                function_ea=function_ea,
                label_end=plan.label_end,
                targets=targets,
                state_base=int(state_base),
                state_var_stkoff=state_var_stkoff,
            )
            if refreshed_state_xref_count:
                resolved_state_xref_count = max(
                    resolved_state_xref_count,
                    refreshed_state_xref_count,
                )
                _reanalyze_range(function_ea, plan.label_start, plan.label_end)
            func = ida_funcs.get_func(function_ea) or idaapi.get_func(function_ea)
    after = _count_materialized_targets(func, plan.target_eas) if func is not None else 0
    success = after == len(plan.target_eas)
    reason = "materialized" if success else "targets_still_missing"
    logger.info(
        "Tigress indirect label materialization 0x%X: targets=%d materialized=%d "
        "range=0x%X..0x%X dispatch_jump=%s jump_xrefs=%d "
        "resolved_state_xrefs=%d appended_tail=%s boundary_flow_xrefs=%d "
        "switch_info=%s reason=%s",
        function_ea,
        len(plan.target_eas),
        after,
        plan.label_start,
        plan.label_end,
        "<none>" if indirect_jump_ea is None else f"0x{indirect_jump_ea:X}",
        jump_xref_count,
        resolved_state_xref_count,
        appended_tail,
        boundary_flow_xref_count,
        switch_info_installed,
        reason,
    )
    return IndirectLabelMaterializationResult(
        function_ea=function_ea,
        table_address=table_address,
        table_count=table_count,
        label_start=plan.label_start,
        label_end=plan.label_end,
        target_count=len(plan.target_eas),
        materialized_target_count=after,
        dispatch_jump_ea=indirect_jump_ea,
        jump_xref_count=jump_xref_count,
        switch_info_installed=switch_info_installed,
        appended_tail=appended_tail,
        success=success,
        reason=reason,
        boundary_flow_xref_count=boundary_flow_xref_count,
        resolved_state_xref_count=resolved_state_xref_count,
    )


def _config_for_function_ea(
    goto_table_info: Mapping[str, object],
    function_ea: int,
) -> Mapping[str, object] | None:
    """Return the config entry whose key matches *function_ea*, if any."""
    key = int(function_ea)
    for raw_function_ea, raw_config in goto_table_info.items():
        if not isinstance(raw_config, Mapping):
            continue
        parsed = _parse_int(raw_function_ea)
        if parsed is not None and int(parsed) == key:
            return raw_config
    return None


def _config_table_valid_for_function(
    function_ea: int,
    table_address: int | None,
    table_count: int | None,
) -> bool:
    """True when configured table reads in-function code pointers for *function_ea*."""
    if not table_address or not table_count:
        return False
    try:
        import ida_bytes  # type: ignore[import-untyped]
        import ida_funcs  # type: ignore[import-untyped]

        func = ida_funcs.get_func(int(function_ea))
        if func is None:
            return False
        first = int(ida_bytes.get_qword(int(table_address)))
        return int(func.start_ea) <= first < int(func.end_ea)
    except Exception:
        return False


def materialize_indirect_label_targets_for_function(
    function_ea: int,
    goto_table_info: Mapping[str, object] | None = None,
) -> IndirectLabelMaterializationResult | None:
    """Materialize one function's indirect labels, config-or-discovery.

    Resolves the table layout from a matching config entry when present and
    valid for *function_ea*; otherwise discovers it structurally.  Returns
    ``None`` when the function is not an indirect-table dispatcher (no
    register-indirect jump with a resolvable in-function table), keeping the
    prepass behavior-neutral for every other function.
    """
    info = goto_table_info if isinstance(goto_table_info, Mapping) else {}
    cfg = _config_for_function_ea(info, int(function_ea))
    cfg_table_address = _parse_int(cfg.get("table_address")) if cfg is not None else None
    cfg_table_count = (
        _parse_int(cfg.get("table_nb_elt"), default=0) if cfg is not None else 0
    )
    if _config_table_valid_for_function(
        int(function_ea), cfg_table_address, cfg_table_count
    ):
        return materialize_indirect_label_targets(
            function_ea=int(function_ea),
            table_address=int(cfg_table_address),
            table_count=int(cfg_table_count),
            label_start=_parse_int(cfg.get("label_start")),
            label_end=_parse_int(
                cfg.get("label_end"),
                default=_parse_int(cfg.get("function_end")),
            ),
            dispatch_jump_ea=_parse_int(cfg.get("dispatch_jump_ea")),
            switch_start_ea=_parse_int(cfg.get("switch_start_ea")),
            install_switch_info=bool(cfg.get("install_switch_info", False)),
            state_base=_parse_int(cfg.get("state_base"), default=1) or 1,
            state_var_stkoff=_parse_int(cfg.get("state_var_stkoff")),
        )

    discovered = discover_indirect_jump_table(int(function_ea))
    if discovered is None:
        return None
    state_base = (_parse_int(cfg.get("state_base"), default=1) or 1) if cfg else 1
    state_var_stkoff = _parse_int(cfg.get("state_var_stkoff")) if cfg else None
    install_switch = bool(cfg.get("install_switch_info", False)) if cfg else False
    return materialize_indirect_label_targets(
        function_ea=int(discovered.function_ea),
        table_address=int(discovered.table_address),
        table_count=int(discovered.table_count),
        label_start=int(discovered.label_start),
        label_end=int(discovered.label_end),
        dispatch_jump_ea=int(discovered.dispatch_jump_ea),
        switch_start_ea=int(discovered.dispatch_jump_ea),
        install_switch_info=install_switch,
        state_base=int(state_base),
        state_var_stkoff=state_var_stkoff,
    )


def materialize_discovered_indirect_label_targets(
    goto_table_info: Mapping[str, object] | None = None,
) -> tuple[IndirectLabelMaterializationResult, ...]:
    """Discover and materialize every indirect-table dispatcher in the database.

    Address-agnostic configure-time prepass: scans all functions for the
    register-indirect jump-table signature and materializes the recovered label
    bodies, so the engine fires without per-binary configured addresses even
    after a rebuild shifts the binary.  Behavior-neutral for any function that
    is not a real indirect-table dispatcher (discovery returns ``None``).

    Configured ``goto_table_info`` (if any) supplies per-function state-machine
    overrides (state base / slot) when a config entry matches a discovered EA.
    """
    results: list[IndirectLabelMaterializationResult] = []
    try:
        import idautils  # type: ignore[import-untyped]
    except Exception:
        logger.debug("idautils unavailable; skipping indirect discovery scan")
        return ()
    info = goto_table_info if isinstance(goto_table_info, Mapping) else {}
    seen: set[int] = set()
    for function_ea in idautils.Functions():
        key = int(function_ea)
        if key in seen:
            continue
        seen.add(key)
        try:
            result = materialize_indirect_label_targets_for_function(key, info)
        except Exception:
            logger.debug(
                "discovery-scan materialization failed for 0x%X",
                key,
                exc_info=True,
            )
            continue
        if result is not None:
            results.append(result)
    logger.info(
        "Tigress indirect discovery scan materialized %d dispatcher(s)",
        len(results),
    )
    return tuple(results)


def materialize_indirect_label_targets_from_config(
    goto_table_info: Mapping[str, object],
) -> tuple[IndirectLabelMaterializationResult, ...]:
    """Materialize all configured Tigress indirect target-label ranges."""
    results: list[IndirectLabelMaterializationResult] = []
    for raw_function_ea, raw_config in goto_table_info.items():
        if not isinstance(raw_config, Mapping):
            continue
        function_ea = _parse_int(raw_function_ea)
        table_address = _parse_int(raw_config.get("table_address"))
        table_count = _parse_int(raw_config.get("table_nb_elt"), default=0)
        if function_ea is None or table_address is None or not table_count:
            logger.warning(
                "Skipping malformed indirect-label materialization config for %r",
                raw_function_ea,
            )
            continue
        results.append(
            materialize_indirect_label_targets(
                function_ea=function_ea,
                table_address=table_address,
                table_count=int(table_count),
                label_start=_parse_int(raw_config.get("label_start")),
                label_end=_parse_int(
                    raw_config.get("label_end"),
                    default=_parse_int(raw_config.get("function_end")),
                ),
                dispatch_jump_ea=_parse_int(raw_config.get("dispatch_jump_ea")),
                switch_start_ea=_parse_int(raw_config.get("switch_start_ea")),
                install_switch_info=bool(raw_config.get("install_switch_info", False)),
                state_base=_parse_int(raw_config.get("state_base"), default=1) or 1,
                state_var_stkoff=_parse_int(raw_config.get("state_var_stkoff")),
            )
        )
    return tuple(results)


# --- Pre-decompile materialization registry --------------------------------
#
# The indirect engine registers its ``goto_table_info`` here at project-load
# time; the decompilation ``prolog`` hook then materializes labels for the
# function being decompiled BEFORE its MBA is built.  Materializing at prolog
# (rather than mid-optimization) lets the very first MBA build see the computed
# crefs, so the recovered label bodies are present for lowering in a single
# ``decompile`` call.  Registration is behavior-neutral: discovery returns
# ``None`` for any function that is not a real indirect-table dispatcher.

_INDIRECT_MATERIALIZATION_REGISTERED = False
_INDIRECT_MATERIALIZATION_GOTO_TABLE: dict = {}
_INDIRECT_MATERIALIZED_FUNCTION_EAS: set[int] = set()


def register_indirect_materialization(goto_table_info: Mapping[str, object]) -> None:
    """Register the indirect engine's table info for prolog-time materialization."""
    global _INDIRECT_MATERIALIZATION_REGISTERED, _INDIRECT_MATERIALIZATION_GOTO_TABLE
    _INDIRECT_MATERIALIZATION_REGISTERED = True
    _INDIRECT_MATERIALIZATION_GOTO_TABLE = dict(goto_table_info or {})
    _INDIRECT_MATERIALIZED_FUNCTION_EAS.clear()


def reset_indirect_materialization() -> None:
    """Clear the prolog-time materialization registration."""
    global _INDIRECT_MATERIALIZATION_REGISTERED, _INDIRECT_MATERIALIZATION_GOTO_TABLE
    _INDIRECT_MATERIALIZATION_REGISTERED = False
    _INDIRECT_MATERIALIZATION_GOTO_TABLE = {}
    _INDIRECT_MATERIALIZED_FUNCTION_EAS.clear()


def run_indirect_materialization_for_function(
    function_ea: int,
) -> IndirectLabelMaterializationResult | None:
    """Materialize indirect labels for *function_ea* if registered (idempotent).

    Called from the decompilation prolog hook.  Returns ``None`` (no-op) unless
    the indirect engine is active and the function is a real indirect-table
    dispatcher.  Each function EA is materialized at most once per registration.
    """
    if not _INDIRECT_MATERIALIZATION_REGISTERED:
        return None
    key = int(function_ea)
    if key in _INDIRECT_MATERIALIZED_FUNCTION_EAS:
        return None
    _INDIRECT_MATERIALIZED_FUNCTION_EAS.add(key)
    try:
        result = materialize_indirect_label_targets_for_function(
            key,
            _INDIRECT_MATERIALIZATION_GOTO_TABLE,
        )
    except Exception:
        logger.warning(
            "prolog-time indirect materialization failed for 0x%X",
            key,
            exc_info=True,
        )
        return None
    if result is not None:
        logger.info(
            "Tigress indirect prolog materialization 0x%X: success=%s "
            "targets=%d/%d jump_xrefs=%d reason=%s",
            result.function_ea,
            result.success,
            result.materialized_target_count,
            result.target_count,
            result.jump_xref_count,
            result.reason,
        )
    return result


__all__ = [
    "IndirectLabelMaterializationPlan",
    "IndirectLabelMaterializationResult",
    "materialize_indirect_label_targets",
    "materialize_discovered_indirect_label_targets",
    "materialize_indirect_label_targets_for_function",
    "register_indirect_materialization",
    "reset_indirect_materialization",
    "run_indirect_materialization_for_function",
    "materialize_indirect_label_targets_from_config",
    "plan_indirect_label_materialization",
]
