"""Structural discovery of Tigress indirect jump-table dispatchers.

Tigress computed-goto flattening lowers to a native ``jmp reg`` (``m_ijmp``)
that indexes a qword label table.  The table base, entry count, dispatch jump
address, and label bounds are all derivable from *binary structure* — no
per-binary configured addresses are required.  This module recovers those
fields so the indirect engine fires across rebuilds that shift addresses.

Discovery order for the table base:

1. ``ida_nalt.get_switch_info`` on the indirect-jump EA.  When IDA already
   built a switch for the computed goto this is exact (``swi.jumps`` /
   ``swi.ncases``).
2. Operand decode fallback: scan the function for the ``lea reg, <o_mem>``
   (or ``mov reg, <o_mem>``) instruction whose memory operand addresses a
   qword array of in-function code pointers.  This is the table the dispatch
   copies onto the stack before indexing it with the state variable.

The entry count is bounded structurally: walk table entries while each qword
points inside the owning function; stop at the first out-of-range / non-code /
next-function pointer (Tigress packs string/data immediately after the table).
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from d810.core.logging import getLogger

logger = getLogger("D810.hexrays.preanalysis.indirect_jump_discovery")


@dataclass(frozen=True)
class DiscoveredIndirectJumpTable:
    """Structurally recovered indirect jump-table layout for one function."""

    function_ea: int
    dispatch_jump_ea: int
    table_address: int
    table_count: int
    target_eas: tuple[int, ...]
    label_start: int
    label_end: int
    source: str  # "switch_info" | "operand_decode"
    state_var_stkoff: int | None = None
    initial_state: int | None = None
    stack_table_offset: int | None = None


def _ea_owned_by_function(target_ea: int, func_start: int, func_end: int) -> bool:
    """Pure predicate: is *target_ea* inside the function's owned range?

    Uses the function's owned ``[start, end)`` interval.  Tigress label bodies
    all live inside the function, so an in-range pointer is a valid entry while
    the first out-of-range pointer (string/data after the table) terminates the
    structural walk.
    """
    return int(func_start) <= int(target_ea) < int(func_end)


def bound_table_count(
    raw_qwords: Sequence[int],
    *,
    func_start: int,
    func_end: int,
    max_entries: int,
) -> int:
    """Return the count of leading qwords that point inside the function.

    Pure logic (no IDA): consumes already-read qword entries and stops at the
    first entry outside the owned function range.  ``max_entries`` caps the walk
    so a degenerate table never explodes.
    """
    count = 0
    for index, qword in enumerate(raw_qwords):
        if index >= int(max_entries):
            break
        if not qword:
            break
        if not _ea_owned_by_function(int(qword), func_start, func_end):
            break
        count += 1
    return count


def _read_qword(ea: int) -> int:
    import ida_bytes  # type: ignore[import-untyped]

    return int(ida_bytes.get_qword(int(ea)))


def _func_bounds(function_ea: int) -> tuple[int, int] | None:
    try:
        import ida_funcs  # type: ignore[import-untyped]

        func = ida_funcs.get_func(int(function_ea))
        if func is None:
            return None
        return int(func.start_ea), int(func.end_ea)
    except Exception:
        logger.debug("failed reading func bounds for 0x%X", function_ea, exc_info=True)
        return None


def _find_reg_indirect_jump_ea(func_start: int, func_end: int) -> int | None:
    """Locate the native register-indirect ``jmp reg`` inside the function."""
    try:
        import ida_bytes  # type: ignore[import-untyped]
        import ida_ua  # type: ignore[import-untyped]
        import idaapi  # type: ignore[import-untyped]
        import idc  # type: ignore[import-untyped]

        badaddr = int(getattr(idaapi, "BADADDR", -1))
        o_reg = int(getattr(idaapi, "o_reg", 1))
        ea = int(func_start)
        while ea != badaddr and ea < int(func_end):
            mnem = str(idc.print_insn_mnem(ea) or "").lower()
            if mnem == "jmp":
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, ea) and int(insn.ops[0].type) == o_reg:
                    return int(ea)
            next_ea = int(ida_bytes.next_head(ea, int(func_end)))
            if next_ea == badaddr or next_ea <= ea:
                break
            ea = next_ea
    except Exception:
        logger.debug("failed scanning for register indirect jump", exc_info=True)
    return None


def _table_base_from_switch_info(dispatch_jump_ea: int) -> tuple[int, int] | None:
    """Return ``(table_address, ncases)`` if IDA already built a switch."""
    try:
        import ida_nalt  # type: ignore[import-untyped]

        si = ida_nalt.switch_info_t()
        if not ida_nalt.get_switch_info(si, int(dispatch_jump_ea)):
            return None
        table_address = int(getattr(si, "jumps", 0) or 0)
        ncases = int(si.get_jtable_size())
        if not table_address or ncases <= 0:
            return None
        return table_address, ncases
    except Exception:
        logger.debug(
            "switch_info table discovery failed for 0x%X",
            int(dispatch_jump_ea),
            exc_info=True,
        )
        return None


def _table_base_from_operand_decode(
    func_start: int,
    func_end: int,
) -> int | None:
    """Recover the table base by decoding the ``lea/mov reg, <o_mem>`` feeder.

    Scans the function for any instruction whose memory operand addresses a
    qword array of in-function code pointers.  The first such operand whose
    leading entry is owned by the function is the label table the dispatch
    copies onto the stack.
    """
    try:
        import ida_bytes  # type: ignore[import-untyped]
        import ida_ua  # type: ignore[import-untyped]
        import idaapi  # type: ignore[import-untyped]

        badaddr = int(getattr(idaapi, "BADADDR", -1))
        o_mem = int(getattr(idaapi, "o_mem", 2))
        o_imm = int(getattr(idaapi, "o_imm", 5))
        ea = int(func_start)
        best: int | None = None
        while ea != badaddr and ea < int(func_end):
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, ea):
                for op in insn.ops:
                    op_type = int(op.type)
                    if op_type == 0:
                        break
                    if op_type not in (o_mem, o_imm):
                        continue
                    candidate = int(op.addr) if op_type == o_mem else int(op.value)
                    if candidate <= 0:
                        continue
                    first = int(ida_bytes.get_qword(candidate))
                    if _ea_owned_by_function(first, func_start, func_end):
                        # Confirm at least two leading entries are in-function so
                        # a stray code pointer cannot masquerade as a table.
                        second = int(ida_bytes.get_qword(candidate + 8))
                        if _ea_owned_by_function(second, func_start, func_end):
                            best = candidate
                            break
            if best is not None:
                return best
            next_ea = int(ida_bytes.next_head(ea, int(func_end)))
            if next_ea == badaddr or next_ea <= ea:
                break
            ea = next_ea
    except Exception:
        logger.debug("operand-decode table discovery failed", exc_info=True)
    return None


def _recover_stack_table_offset(dispatch_jump_ea: int, func_start: int) -> int | None:
    """Recover the stack displacement of the copied table from the index load.

    Walks back from the indirect jump for the ``mov reg, [rsp + idx*8 + disp]``
    that loads the dispatch target; ``disp`` is the on-stack copy of the label
    table.  Returns ``None`` when no such index load is found.
    """
    try:
        import ida_bytes  # type: ignore[import-untyped]
        import ida_ua  # type: ignore[import-untyped]
        import idaapi  # type: ignore[import-untyped]

        badaddr = int(getattr(idaapi, "BADADDR", -1))
        o_displ = int(getattr(idaapi, "o_displ", 4))
        o_phrase = int(getattr(idaapi, "o_phrase", 3))
        ea = int(dispatch_jump_ea)
        for _ in range(24):
            prev = int(ida_bytes.prev_head(ea, int(func_start)))
            if prev == badaddr or prev >= ea:
                break
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, prev):
                for op in insn.ops:
                    if int(op.type) == 0:
                        break
                    if int(op.type) in (o_displ, o_phrase) and int(op.addr) > 0:
                        # Index-scaled stack load: a SIB with index reg present.
                        return int(op.addr)
            ea = prev
    except Exception:
        logger.debug("stack table offset recovery failed", exc_info=True)
    return None


def _recover_state_init(
    func_start: int,
    func_end: int,
    stack_table_offset: int | None,
) -> tuple[int | None, int | None]:
    """Recover ``(state_var_stkoff, initial_state)`` from the prologue.

    Tigress initializes the state variable with the first
    ``mov dword [rsp+disp], imm32`` in the function; ``disp`` is the state slot
    and ``imm32`` the initial state.  The state slot is distinct from the copied
    table slot, so a write to ``stack_table_offset`` is skipped.
    """
    try:
        import ida_bytes  # type: ignore[import-untyped]
        import idaapi  # type: ignore[import-untyped]

        badaddr = int(getattr(idaapi, "BADADDR", -1))
        ea = int(func_start)
        scan_end = min(int(func_end), int(func_start) + 0x100)
        while ea != badaddr and ea + 8 <= scan_end:
            # Encoding: C7 44 24 <disp8> <imm32>  =  mov dword [rsp+disp8], imm32
            if (
                int(ida_bytes.get_byte(ea)) == 0xC7
                and int(ida_bytes.get_byte(ea + 1)) == 0x44
                and int(ida_bytes.get_byte(ea + 2)) == 0x24
            ):
                disp = int(ida_bytes.get_byte(ea + 3))
                imm = int(ida_bytes.get_dword(ea + 4)) & 0xFFFFFFFF
                if stack_table_offset is None or disp != int(stack_table_offset):
                    return disp, imm
            nxt = int(ida_bytes.next_head(ea, scan_end))
            if nxt == badaddr or nxt <= ea:
                break
            ea = nxt
    except Exception:
        logger.debug("state init recovery failed", exc_info=True)
    return None, None


def discover_indirect_jump_table(
    function_ea: int,
    *,
    max_entries: int = 4096,
) -> DiscoveredIndirectJumpTable | None:
    """Recover the indirect jump-table layout for *function_ea* structurally.

    Returns ``None`` when the function has no register-indirect jump with a
    resolvable in-function qword table, so callers stay behavior-neutral on
    every function that is not an indirect-table dispatcher.
    """
    bounds = _func_bounds(function_ea)
    if bounds is None:
        return None
    func_start, func_end = bounds

    dispatch_jump_ea = _find_reg_indirect_jump_ea(func_start, func_end)
    if dispatch_jump_ea is None:
        return None

    source = "switch_info"
    table_address: int | None = None
    declared_count = 0
    switch_info = _table_base_from_switch_info(dispatch_jump_ea)
    if switch_info is not None:
        table_address, declared_count = switch_info

    if table_address is None:
        source = "operand_decode"
        table_address = _table_base_from_operand_decode(func_start, func_end)
    if table_address is None:
        return None

    walk_cap = min(int(max_entries), int(declared_count) or int(max_entries))
    raw = tuple(
        _read_qword(int(table_address) + index * 8)
        for index in range(int(walk_cap) + 1)
    )
    table_count = bound_table_count(
        raw,
        func_start=func_start,
        func_end=func_end,
        max_entries=walk_cap,
    )
    if table_count <= 0:
        return None
    if declared_count and declared_count < table_count:
        table_count = int(declared_count)

    target_eas = tuple(raw[index] for index in range(table_count))
    unique_targets = sorted({int(t) for t in target_eas if t})
    if not unique_targets:
        return None
    label_start = int(min(unique_targets))
    label_end = int(func_end)
    if label_end <= label_start:
        return None

    stack_table_offset = _recover_stack_table_offset(dispatch_jump_ea, func_start)
    state_var_stkoff, initial_state = _recover_state_init(
        func_start, func_end, stack_table_offset
    )

    logger.info(
        "Tigress indirect discovery 0x%X: dispatch_jump=0x%X table=0x%X "
        "count=%d range=0x%X..0x%X source=%s state_stkoff=%s initial_state=%s "
        "stack_table_offset=%s",
        int(function_ea),
        int(dispatch_jump_ea),
        int(table_address),
        int(table_count),
        label_start,
        label_end,
        source,
        "<none>" if state_var_stkoff is None else f"0x{state_var_stkoff:X}",
        "<none>" if initial_state is None else f"0x{initial_state:X}",
        "<none>" if stack_table_offset is None else f"0x{stack_table_offset:X}",
    )
    return DiscoveredIndirectJumpTable(
        function_ea=int(function_ea),
        dispatch_jump_ea=int(dispatch_jump_ea),
        table_address=int(table_address),
        table_count=int(table_count),
        target_eas=tuple(int(t) for t in target_eas),
        label_start=label_start,
        label_end=label_end,
        source=source,
        state_var_stkoff=state_var_stkoff,
        initial_state=initial_state,
        stack_table_offset=stack_table_offset,
    )


__all__ = [
    "DiscoveredIndirectJumpTable",
    "bound_table_count",
    "discover_indirect_jump_table",
]
