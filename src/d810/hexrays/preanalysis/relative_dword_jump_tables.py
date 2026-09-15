"""Path-sensitive native proof for x64 relative dword jump tables.

This pre-Hex capability handles the narrow form::

    movsxd rax, dword ptr [r15+rax*4]
    add    rax, r15
    ...                    ; no write to rax/r15
    jmp    rax

The table-base register is proved over the native CFG.  Disconnected writes do
not taint the result, while any reachable predecessor disagreement does.  The
module only discovers evidence; publication remains owned by the existing
manager-selected indirect-label metadata transaction.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import re

from d810.core.logging import getLogger
from d810.core.typing import Iterable

logger = getLogger("d810.hexrays.preanalysis.relative_dword_jump_tables")


@dataclass(frozen=True, slots=True)
class NativeRegisterBlock:
    """Portable block facts used by the constant proof."""

    start_ea: int
    end_ea: int
    successor_eas: tuple[int, ...]
    writes: tuple[tuple[int, int | None], ...] = ()


@dataclass(frozen=True, slots=True)
class RelativeDwordJumpTableProof:
    function_ea: int
    load_ea: int
    jump_ea: int
    table_ea: int
    index_lower_bound: int
    index_upper_bound: int
    index_authority: str
    target_eas: tuple[int, ...]


def prove_register_constants_at_sites(
    blocks: Iterable[NativeRegisterBlock],
    *,
    entry_ea: int,
    site_eas: Iterable[int],
) -> dict[int, int | None]:
    """Return the path-sensitive constant immediately before each site.

    ``None`` means reachable but non-constant.  Sites absent from the result
    are unreachable in the supplied graph.  A write value of ``None`` is Top.
    """

    by_start = {int(block.start_ea): block for block in blocks}
    sites = {int(ea) for ea in site_eas}
    incoming: dict[int, int | None] = {int(entry_ea): None}
    queue = deque([int(entry_ea)])
    queued = {int(entry_ea)}
    observations: dict[int, list[int | None]] = {}

    def join(old: int | None, new: int | None) -> int | None:
        if old is not None and new is not None and old == new:
            return old
        return None

    while queue:
        block_ea = queue.popleft()
        queued.discard(block_ea)
        block = by_start.get(block_ea)
        if block is None:
            continue
        value = incoming[block_ea]
        writes = iter(sorted(block.writes))
        current_write = next(writes, None)
        relevant_sites = sorted(
            ea for ea in sites if block.start_ea <= ea < block.end_ea
        )
        for site_ea in relevant_sites:
            while current_write is not None and current_write[0] < site_ea:
                value = current_write[1]
                current_write = next(writes, None)
            observations.setdefault(site_ea, []).append(value)
        while current_write is not None:
            value = current_write[1]
            current_write = next(writes, None)

        for successor_ea in block.successor_eas:
            successor_ea = int(successor_ea)
            if successor_ea not in by_start:
                continue
            if successor_ea not in incoming:
                incoming[successor_ea] = value
                changed = True
            else:
                merged = join(incoming[successor_ea], value)
                changed = merged != incoming[successor_ea]
                incoming[successor_ea] = merged
            if changed and successor_ea not in queued:
                queue.append(successor_ea)
                queued.add(successor_ea)

    return {
        site_ea: (
            values[0]
            if values and values[0] is not None and all(v == values[0] for v in values)
            else None
        )
        for site_ea, values in observations.items()
    }


def reaching_register_writes(
    blocks: Iterable[NativeRegisterBlock],
    *,
    entry_ea: int,
    site_ea: int,
) -> tuple[tuple[int, int | None], ...]:
    """Return the nearest R15 write on every structural predecessor path."""

    block_rows = tuple(blocks)
    by_start = {int(block.start_ea): block for block in block_rows}
    predecessors: dict[int, set[int]] = {start: set() for start in by_start}
    for block in block_rows:
        for successor_ea in block.successor_eas:
            if int(successor_ea) in predecessors:
                predecessors[int(successor_ea)].add(int(block.start_ea))
    containing = next(
        (
            block
            for block in block_rows
            if int(block.start_ea) <= int(site_ea) < int(block.end_ea)
        ),
        None,
    )
    if containing is None:
        return ()

    found: set[tuple[int, int | None]] = set()
    pending = deque([(int(containing.start_ea), int(site_ea))])
    visited: set[tuple[int, int]] = set()
    while pending:
        block_ea, before_ea = pending.popleft()
        state_key = (block_ea, before_ea)
        if state_key in visited:
            continue
        visited.add(state_key)
        block = by_start[block_ea]
        prior_writes = tuple(
            row for row in block.writes if int(row[0]) < int(before_ea)
        )
        if prior_writes:
            found.add(prior_writes[-1])
            continue
        if block_ea == int(entry_ea):
            found.add((int(entry_ea), None))
            continue
        parents = predecessors.get(block_ea, set())
        if not parents:
            found.add((block_ea, None))
            continue
        for parent_ea in parents:
            pending.append((parent_ea, by_start[parent_ea].end_ea))
    return tuple(
        sorted(found, key=lambda row: (row[0], -1 if row[1] is None else row[1]))
    )


def _canonical_operand(ea: int, operand_index: int) -> str:
    import idc  # type: ignore[import-untyped]

    return "".join(str(idc.print_operand(ea, operand_index) or "").lower().split())


def _instruction_mnemonic(ea: int) -> str:
    import idaapi  # type: ignore[import-untyped]

    return str(idaapi.print_insn_mnem(ea) or "").lower()


def _is_r15_destination(rendered_operand: str) -> bool:
    """Recognize R15 writes from IDA's rendered destination operand.

    IDA's processor-specific ``op_t.reg`` identifiers are not stable register
    identities when passed back through ``get_reg_name`` with an imposed
    width.  In particular, an R10 destination was observed being returned as
    R15.  The canonical rendered destination is already the authority used by
    the surrounding instruction-shape matcher.
    """

    return rendered_operand in {"r15", "r15d", "r15w", "r15b"}


_GPR_ALIASES_BY_FULL_WIDTH = {
    "rax": ("rax", "eax", "ax", "al", "ah"),
    "rbx": ("rbx", "ebx", "bx", "bl", "bh"),
    "rcx": ("rcx", "ecx", "cx", "cl", "ch"),
    "rdx": ("rdx", "edx", "dx", "dl", "dh"),
    "rsi": ("rsi", "esi", "si", "sil"),
    "rdi": ("rdi", "edi", "di", "dil"),
    "rbp": ("rbp", "ebp", "bp", "bpl"),
    "rsp": ("rsp", "esp", "sp", "spl"),
    **{
        f"r{index}": (
            f"r{index}",
            f"r{index}d",
            f"r{index}w",
            f"r{index}b",
        )
        for index in range(8, 16)
    },
}
_FULL_WIDTH_GPRS = frozenset(_GPR_ALIASES_BY_FULL_WIDTH)
_FULL_WIDTH_GPR_BY_ALIAS = {
    alias: full_width
    for full_width, aliases in _GPR_ALIASES_BY_FULL_WIDTH.items()
    for alias in aliases
}


def _record_r15_effect(
    writes: list[tuple[int, int | None]],
    saved_r15: dict[str, int],
    *,
    ea: int,
    mnemonic: str,
    destination: str,
    source: str,
    changed_operands: tuple[str, ...],
    changed_r15: bool,
    value: int | None,
) -> None:
    """Record one instruction's net R15 effect within a basic block.

    A full-width ``mov scratch, r15`` followed by ``mov r15, scratch`` is a
    proven local restore only while ``scratch`` remains unmodified.  The saved
    history index lets the restore discard intervening R15 mutations without
    assuming anything about the incoming value.
    """

    for operand in changed_operands:
        full_width = _FULL_WIDTH_GPR_BY_ALIAS.get(operand)
        if full_width is not None:
            saved_r15.pop(full_width, None)
    if (
        mnemonic == "mov"
        and source == "r15"
        and destination in _FULL_WIDTH_GPRS
        and destination != "r15"
    ):
        saved_r15[destination] = len(writes)
    if not changed_r15:
        return
    restore_index = (
        saved_r15.get(source) if mnemonic == "mov" and destination == "r15" else None
    )
    if restore_index is not None:
        del writes[restore_index:]
        return
    writes.append((int(ea), value))


def _changed_operand_names(ea: int, instruction: object) -> tuple[str, ...]:
    import idaapi  # type: ignore[import-untyped]

    features = int(instruction.get_canon_feature())
    return tuple(
        _canonical_operand(ea, index)
        for index in range(6)
        if int(getattr(idaapi, f"CF_CHG{index + 1}", 0)) & features
    )


_R15_RELATIVE_DWORD_RE = re.compile(
    r"(?:ds:)?\((?P<symbol>jpt_[a-z0-9_]+)-(?P<anchor>[0-9a-f]+)h\)"
    r"\[r15\+rax\*4\]$"
)


def _is_r15_relative_dword_load(ea: int) -> bool:
    import ida_name  # type: ignore[import-untyped]

    source = _canonical_operand(ea, 1)
    if source in {"dwordptr[r15+rax*4]", "[r15+rax*4]"}:
        return True
    match = _R15_RELATIVE_DWORD_RE.fullmatch(source)
    if match is None:
        return False
    anchor = int(match.group("anchor"), 16)
    return str(ida_name.get_name(anchor) or "").lower() == match.group("symbol")


def _validated_switch_table_count(
    *,
    expected_table_ea: int,
    switch_table_ea: int,
    table_count: int,
    element_size: int,
    lowcase: int,
    sparse: bool,
    indirect: bool,
) -> int | None:
    """Validate the exact index domain carried by native switch metadata."""

    count = int(table_count)
    if (
        int(switch_table_ea) != int(expected_table_ea)
        or count < 2
        or count > 0x100
        or int(element_size) != 4
        or int(lowcase) != 0
        or bool(sparse)
        or bool(indirect)
    ):
        return None
    return count


def _switch_table_count(jump_ea: int, table_ea: int) -> int | None:
    import ida_nalt  # type: ignore[import-untyped]

    switch = ida_nalt.switch_info_t()
    if not ida_nalt.get_switch_info(switch, int(jump_ea)):
        return None
    return _validated_switch_table_count(
        expected_table_ea=int(table_ea),
        switch_table_ea=int(switch.jumps),
        table_count=int(switch.get_jtable_size()),
        element_size=int(switch.get_jtable_element_size()),
        lowcase=int(switch.get_lowcase()),
        sparse=bool(switch.is_sparse()),
        indirect=bool(switch.is_indirect()),
    )


def _changed_r15_value(ea: int, instruction: object) -> tuple[bool, int | None]:
    """Return whether the instruction changes R15 and its proven value."""
    import ida_name  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    change_flags = tuple(
        int(getattr(idaapi, f"CF_CHG{index}", 0)) for index in range(1, 7)
    )
    features = int(instruction.get_canon_feature())
    for index, flag in enumerate(change_flags):
        if not flag or not features & flag:
            continue
        operand = instruction.ops[index]
        if operand.type != idaapi.o_reg:
            continue
        rendered = _canonical_operand(ea, index)
        if not _is_r15_destination(rendered):
            continue
        if (
            index == 0
            and rendered == "r15"
            and str(idaapi.print_insn_mnem(ea) or "").lower() == "lea"
        ):
            source = instruction.ops[1]
            target = int(getattr(source, "addr", 0) or 0)
            target_name = str(ida_name.get_name(target) or "")
            if target and target_name.lower().startswith("jpt_"):
                return True, target
        return True, None
    return False, None


def _native_blocks_and_candidates(
    function_ea: int,
) -> tuple[tuple[NativeRegisterBlock, ...], tuple[tuple[int, int], ...]]:
    import ida_bytes  # type: ignore[import-untyped]
    import ida_funcs  # type: ignore[import-untyped]
    import ida_gdl  # type: ignore[import-untyped]
    import ida_nalt  # type: ignore[import-untyped]
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    function = ida_funcs.get_func(int(function_ea))
    if function is None:
        return (), ()
    blocks: list[NativeRegisterBlock] = []
    candidates: list[tuple[int, int]] = []
    badaddr = int(getattr(idaapi, "BADADDR", -1))
    for block in ida_gdl.FlowChart(function, flags=ida_gdl.FC_PREDS):
        instructions: list[tuple[int, object]] = []
        writes: list[tuple[int, int | None]] = []
        saved_r15: dict[str, int] = {}
        ea = int(block.start_ea)
        while ea != badaddr and ea < int(block.end_ea):
            instruction = ida_ua.insn_t()
            size = int(ida_ua.decode_insn(instruction, ea))
            if size <= 0:
                break
            instructions.append((ea, instruction))
            changed, value = _changed_r15_value(ea, instruction)
            _record_r15_effect(
                writes,
                saved_r15,
                ea=ea,
                mnemonic=_instruction_mnemonic(ea),
                destination=_canonical_operand(ea, 0),
                source=_canonical_operand(ea, 1),
                changed_operands=_changed_operand_names(ea, instruction),
                changed_r15=changed,
                value=value,
            )
            ea = int(ida_bytes.next_head(ea, int(block.end_ea)))

        blocks.append(
            NativeRegisterBlock(
                start_ea=int(block.start_ea),
                end_ea=int(block.end_ea),
                successor_eas=tuple(
                    int(successor.start_ea) for successor in block.succs()
                ),
                writes=tuple(writes),
            )
        )

    # Discovery deliberately scans the entire function extent.  Before the
    # missing computed edges are published, IDA's FlowChart can omit exactly
    # the disconnected tail whose jump-table proof is needed.
    jmp_rax_sites = 0
    switch_sites = 0
    missing_switch_sites: list[int] = []
    add_matches = 0
    ea = int(function.start_ea)
    while ea != badaddr and ea < int(function.end_ea):
        if (
            str(idaapi.print_insn_mnem(ea) or "").lower() == "jmp"
            and _canonical_operand(ea, 0) == "rax"
        ):
            jmp_rax_sites += 1
            switch = ida_nalt.switch_info_t()
            if ida_nalt.get_switch_info(switch, ea):
                switch_sites += 1
            else:
                missing_switch_sites.append(ea)
            cursor = int(ida_bytes.prev_head(ea, int(function.start_ea)))
            tail_eas: list[int] = []
            add_ea = None
            for _ in range(8):
                if cursor == badaddr or cursor < int(function.start_ea):
                    break
                mnemonic = str(idaapi.print_insn_mnem(cursor) or "").lower()
                if mnemonic == "nop":
                    cursor = int(ida_bytes.prev_head(cursor, int(function.start_ea)))
                    continue
                if (
                    mnemonic == "add"
                    and _canonical_operand(cursor, 0) == "rax"
                    and _canonical_operand(cursor, 1) == "r15"
                ):
                    add_ea = cursor
                    break
                tail_eas.append(cursor)
                cursor = int(ida_bytes.prev_head(cursor, int(function.start_ea)))
            if add_ea is not None:
                add_matches += 1
                load_ea = int(ida_bytes.prev_head(add_ea, int(function.start_ea)))
                logger.info(
                    "relative-dword candidate prefix: jump=0x%X add=0x%X "
                    "load=0x%X mnemonic=%s dst=%s src=%s",
                    ea,
                    add_ea,
                    load_ea,
                    str(idaapi.print_insn_mnem(load_ea) or "").lower(),
                    _canonical_operand(load_ea, 0),
                    _canonical_operand(load_ea, 1),
                )
                if (
                    load_ea != badaddr
                    and str(idaapi.print_insn_mnem(load_ea) or "").lower() == "movsxd"
                    and _canonical_operand(load_ea, 0) == "rax"
                    and _is_r15_relative_dword_load(load_ea)
                ):
                    unsafe_tail = False
                    for tail_ea in tail_eas:
                        tail_instruction = ida_ua.insn_t()
                        if ida_ua.decode_insn(tail_instruction, tail_ea) <= 0:
                            unsafe_tail = True
                            break
                        changed, _value = _changed_r15_value(tail_ea, tail_instruction)
                        if changed or _canonical_operand(tail_ea, 0) == "rax":
                            unsafe_tail = True
                            break
                    if not unsafe_tail:
                        candidates.append((load_ea, ea))
        ea = int(ida_bytes.next_head(ea, int(function.end_ea)))
    logger.info(
        "relative-dword jump-table discovery: func=0x%X "
        "jmp_rax=%d switch_info=%d missing_switches=%s "
        "add_base=%d candidates=%d flow_blocks=%d",
        int(function_ea),
        jmp_rax_sites,
        switch_sites,
        ",".join(f"0x{ea:X}" for ea in missing_switch_sites) or "none",
        add_matches,
        len(candidates),
        len(blocks),
    )
    return tuple(blocks), tuple(sorted(set(candidates)))


def _decode_named_relative_table(
    function_ea: int,
    table_ea: int,
    table_count: int,
) -> tuple[int, ...] | None:
    import ida_bytes  # type: ignore[import-untyped]
    import ida_funcs  # type: ignore[import-untyped]
    import ida_name  # type: ignore[import-untyped]

    function = ida_funcs.get_func(int(function_ea))
    if function is None:
        return None
    table_name = str(ida_name.get_name(int(table_ea)) or "")
    if not table_name.lower().startswith("jpt_"):
        return None
    count = int(table_count)
    if count < 2 or count > 0x100:
        return None
    targets: list[int] = []
    for index in range(count):
        raw = int(ida_bytes.get_dword(int(table_ea) + index * 4))
        delta = raw - 0x100000000 if raw & 0x80000000 else raw
        target = int(table_ea) + delta
        owner = ida_funcs.get_func(target)
        if (
            owner is None
            or int(owner.start_ea) != int(function.start_ea)
            or not ida_bytes.is_code(ida_bytes.get_full_flags(target))
        ):
            return None
        targets.append(target)
    unique = tuple(dict.fromkeys(targets))
    return unique if len(unique) >= 2 else None


def prove_relative_dword_jump_tables(
    function_ea: int,
) -> tuple[RelativeDwordJumpTableProof, ...]:
    """Discover only fully path-proven x64 R15 relative jump tables."""
    try:
        blocks, candidates = _native_blocks_and_candidates(int(function_ea))
        constants = prove_register_constants_at_sites(
            blocks,
            entry_ea=int(function_ea),
            site_eas=(load_ea for load_ea, _jump_ea in candidates),
        )
    except Exception:
        logger.exception(
            "relative-dword jump-table proof failed: func=0x%X",
            int(function_ea),
        )
        raise
    logger.info(
        "relative-dword path constants: func=0x%X sites=%s",
        int(function_ea),
        ",".join(
            f"0x{site:X}=" + ("top" if value is None else f"0x{value:X}")
            for site, value in sorted(constants.items())
        )
        or "none",
    )
    for load_ea, _jump_ea in candidates:
        if constants.get(load_ea) is not None:
            continue
        reaching = reaching_register_writes(
            blocks,
            entry_ea=int(function_ea),
            site_ea=int(load_ea),
        )
        logger.info(
            "relative-dword unresolved reaching writes: load=0x%X rows=%s",
            int(load_ea),
            ",".join(
                f"0x{writer_ea:X}="
                + ("top" if value is None else f"0x{value:X}")
                + "["
                + _instruction_mnemonic(writer_ea)
                + ":"
                + _canonical_operand(writer_ea, 0)
                + ","
                + _canonical_operand(writer_ea, 1)
                + "]"
                for writer_ea, value in reaching
            )
            or "none",
        )
    proofs: list[RelativeDwordJumpTableProof] = []
    for load_ea, jump_ea in candidates:
        table_ea = constants.get(load_ea)
        if table_ea is None:
            continue
        table_count = _switch_table_count(int(jump_ea), int(table_ea))
        if table_count is None:
            logger.info(
                "relative-dword table rejected without exact switch domain: "
                "jump=0x%X table=0x%X",
                int(jump_ea),
                int(table_ea),
            )
            continue
        try:
            targets = _decode_named_relative_table(
                int(function_ea),
                int(table_ea),
                int(table_count),
            )
        except Exception:
            logger.exception(
                "relative-dword table decode failed: func=0x%X load=0x%X table=0x%X",
                int(function_ea),
                int(load_ea),
                int(table_ea),
            )
            raise
        if targets is None:
            continue
        proofs.append(
            RelativeDwordJumpTableProof(
                function_ea=int(function_ea),
                load_ea=int(load_ea),
                jump_ea=int(jump_ea),
                table_ea=int(table_ea),
                index_lower_bound=0,
                index_upper_bound=int(table_count) - 1,
                index_authority="ida_switch_info_exact",
                target_eas=targets,
            )
        )
    logger.info(
        "relative-dword jump-table proof: func=0x%X candidates=%d "
        "reachable_sites=%d proven=%d",
        int(function_ea),
        len(candidates),
        len(constants),
        len(proofs),
    )
    return tuple(proofs)


__all__ = [
    "NativeRegisterBlock",
    "RelativeDwordJumpTableProof",
    "prove_register_constants_at_sites",
    "reaching_register_writes",
    "prove_relative_dword_jump_tables",
]
