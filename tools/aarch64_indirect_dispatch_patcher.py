"""Patch AArch64 table-based indirect dispatchers in IDA.

This helper is intentionally an IDA-side preprocessing tool, not a normal
microcode rule.  Some protectors split one logical function into many small
IDA functions and jump between them with patterns like:

    index = *(key_table + off) ^ key
    target = *(target_table + index * 8) + addend
    br target

or:

    cmp state, CONST
    csel index, TRUE_INDEX, FALSE_INDEX, cond
    target = *(target_table + index * 8) + addend
    br target

When the target block is outside the current Hex-Rays mba, d810's regular
IndirectBranchResolver cannot convert it into an internal m_goto.  This tool
patches the IDB bytes to direct AArch64 branches first, then can merge the
discovered continuation functions into the root function.

Default mode is dry-run.

IDA usage:

    import sys
    sys.path.append(r"C:\\Program Files\\IDA Professional 9.2\\plugins\\d810-ng")
    from tools.aarch64_indirect_dispatch_patcher import run

    # Show what would be changed for the current function:
    run(0x2C630)

    # Apply patches and merge continuation functions:
    run(0x2C630, apply=True, merge=True)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

try:
    import ida_auto
    import ida_bytes
    import ida_funcs
    import ida_lines
    import ida_ua
    import idaapi
    import idc
except Exception:  # pragma: no cover - imported outside IDA for inspection.
    ida_auto = None
    ida_bytes = None
    ida_funcs = None
    ida_lines = None
    ida_ua = None
    idaapi = None
    idc = None


PTR_SIZE = 8
NOP = 0xD503201F
MAX_BRANCH_FUNCTIONS = 128

COND_CODES = {
    "EQ": 0x0,
    "NE": 0x1,
    "CS": 0x2,
    "HS": 0x2,
    "CC": 0x3,
    "LO": 0x3,
    "MI": 0x4,
    "PL": 0x5,
    "VS": 0x6,
    "VC": 0x7,
    "HI": 0x8,
    "LS": 0x9,
    "GE": 0xA,
    "LT": 0xB,
    "GT": 0xC,
    "LE": 0xD,
}


@dataclass(frozen=True)
class DispatchPatch:
    """One resolved indirect dispatcher patch."""

    ea: int
    end_ea: int
    kind: str
    target: int
    false_target: int | None = None
    cond: str | None = None
    br_ea: int | None = None
    detail: str = ""

    @property
    def targets(self) -> tuple[int, ...]:
        if self.false_target is None:
            return (self.target,)
        return (self.target, self.false_target)

    def summary(self) -> str:
        if self.kind == "conditional":
            return (
                f"0x{self.ea:x}: B.{self.cond} 0x{self.target:x}; "
                f"B 0x{self.false_target:x}  ({self.detail})"
            )
        return f"0x{self.ea:x}: B 0x{self.target:x}  ({self.detail})"


@dataclass(frozen=True)
class PatchPlan:
    """Dry-run/apply plan for one logical function cluster."""

    root_ea: int
    patches: tuple[DispatchPatch, ...]
    function_ranges: tuple[tuple[int, int, str], ...]
    merge_start: int | None
    merge_end: int | None

    def print(self) -> None:
        print(f"AArch64 indirect dispatch plan for 0x{self.root_ea:x}")
        print(f"  patches: {len(self.patches)}")
        for patch in self.patches:
            print(f"  - {patch.summary()}")
        print(f"  continuation functions: {len(self.function_ranges)}")
        for start, end, name in self.function_ranges:
            print(f"  - 0x{start:x}..0x{end:x} {name}")
        if self.merge_start is not None and self.merge_end is not None:
            print(f"  merge range: 0x{self.merge_start:x}..0x{self.merge_end:x}")


def _require_ida() -> None:
    if ida_bytes is None or ida_funcs is None or idc is None:
        raise RuntimeError("This helper must run inside IDA Python.")


def _decode(ea: int):
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) <= 0:
        return None
    return insn


def _op(ea: int, n: int):
    insn = _decode(ea)
    if insn is None:
        return None
    return insn.ops[n]


def _mnem(ea: int) -> str:
    return (idc.print_insn_mnem(ea) or "").upper()


def _line(ea: int) -> str:
    return ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or "")


def _reg(ea: int, n: int) -> int | None:
    op = _op(ea, n)
    if op is None or op.type != ida_ua.o_reg:
        return None
    return int(op.reg)


def _operand_text(ea: int, n: int) -> str:
    return (idc.print_operand(ea, n) or "").upper()


def _imm(ea: int, n: int) -> int | None:
    op = _op(ea, n)
    if op is None or op.type != ida_ua.o_imm:
        return None
    return int(idc.get_operand_value(ea, n)) & 0xFFFFFFFFFFFFFFFF


def _mov_imm(ea: int) -> tuple[int, int] | None:
    if _mnem(ea) != "MOV":
        return None
    dst = _reg(ea, 0)
    value = _imm(ea, 1)
    if dst is None or value is None:
        return None
    return dst, value


def _adr_value(ea: int) -> tuple[int, int] | None:
    if _mnem(ea) not in {"ADR", "ADRL", "ADRP"}:
        return None
    dst = _reg(ea, 0)
    if dst is None:
        return None
    value = int(idc.get_operand_value(ea, 1))
    if value in (-1, idaapi.BADADDR):
        return None
    return dst, value


def _displ(ea: int, n: int) -> tuple[int, int] | None:
    op = _op(ea, n)
    if op is None or op.type != ida_ua.o_displ:
        return None
    return int(op.phrase), int(op.addr)


def _heads(start_ea: int, end_ea: int) -> Iterable[int]:
    ea = start_ea
    while ea != idaapi.BADADDR and ea < end_ea:
        yield ea
        next_ea = ida_bytes.next_head(ea, end_ea)
        if next_ea == idaapi.BADADDR or next_ea <= ea:
            break
        ea = next_ea


def _prev_heads(ea: int, min_ea: int, limit: int) -> list[int]:
    result: list[int] = []
    cur = ea
    for _ in range(limit):
        prev = ida_bytes.prev_head(cur, min_ea)
        if prev == idaapi.BADADDR or prev < min_ea:
            break
        result.append(prev)
        cur = prev
    return result


def _find_prev_adr(ea: int, min_ea: int, reg: int, limit: int = 40) -> int | None:
    for prev in _prev_heads(ea, min_ea, limit):
        adr = _adr_value(prev)
        if adr is not None and adr[0] == reg:
            return adr[1]
    return None


def _find_prev_mov_value(
    ea: int,
    min_ea: int,
    reg: int,
    *,
    limit: int = 20,
) -> int | None:
    # IDA reports WZR/XZR as a register. Treat it as constant zero.
    if "ZR" in _reg_name(reg):
        return 0
    for prev in _prev_heads(ea, min_ea, limit):
        mov = _mov_imm(prev)
        if mov is not None and mov[0] == reg:
            return mov[1]
    return None


def _reg_name(reg: int) -> str:
    # ``get_reg_name`` accepts byte size; 8 gives X registers when possible.
    try:
        return idaapi.get_reg_name(reg, 8).upper()
    except Exception:
        return str(reg)


def _sign_extend_u32(value: int) -> int:
    value &= 0xFFFFFFFF
    if value & 0x80000000:
        return value - 0x100000000
    return value


def _read_u32(ea: int) -> int | None:
    data = ida_bytes.get_bytes(ea, 4)
    if data is None or len(data) != 4:
        return None
    return int.from_bytes(data, "little", signed=False)


def _read_u64(ea: int) -> int | None:
    data = ida_bytes.get_bytes(ea, 8)
    if data is None or len(data) != 8:
        return None
    return int.from_bytes(data, "little", signed=False)


def _table_target(table_ea: int, index: int, addend: int) -> int | None:
    if index < 0:
        return None
    raw = _read_u64(table_ea + index * PTR_SIZE)
    if raw is None:
        return None
    return (raw + addend) & 0xFFFFFFFFFFFFFFFF


def _target_is_code(ea: int) -> bool:
    if ea in (None, idaapi.BADADDR):
        return False
    flags = ida_bytes.get_flags(ea)
    return ida_bytes.is_code(flags)


def _parse_tail_table_load(
    br_ea: int,
    min_ea: int,
) -> tuple[int, int, int, int] | None:
    """Return (table_ea, addend, index_reg, madd_ea) for a BR table tail."""

    if _mnem(br_ea) != "BR":
        return None
    br_reg = _reg(br_ea, 0)
    if br_reg is None:
        return None

    prev = _prev_heads(br_ea, min_ea, 12)
    add_ea = next(
        (
            ea
            for ea in prev
            if _mnem(ea) == "ADD"
            and _reg(ea, 0) == br_reg
            and _reg(ea, 1) == br_reg
        ),
        None,
    )
    if add_ea is None:
        return None
    addend_reg = _reg(add_ea, 2)
    if addend_reg is None:
        return None
    addend = _find_prev_mov_value(add_ea, min_ea, addend_reg, limit=4)
    if addend is None:
        return None

    ldr_ea = next(
        (
            ea
            for ea in _prev_heads(add_ea, min_ea, 6)
            if _mnem(ea) == "LDR" and _reg(ea, 0) == br_reg
        ),
        None,
    )
    if ldr_ea is None:
        return None

    madd_ea = next(
        (
            ea
            for ea in _prev_heads(ldr_ea, min_ea, 8)
            if _mnem(ea) == "MADD" and _reg(ea, 0) == br_reg
        ),
        None,
    )
    if madd_ea is None:
        return None

    index_reg = _reg(madd_ea, 1)
    scale_reg = _reg(madd_ea, 2)
    base_reg = _reg(madd_ea, 3)
    if index_reg is None or scale_reg is None or base_reg is None:
        return None

    scale = _find_prev_mov_value(madd_ea, min_ea, scale_reg, limit=4)
    if scale != PTR_SIZE:
        return None

    table_ea = _find_prev_adr(madd_ea, min_ea, base_reg)
    if table_ea is None:
        return None

    return table_ea, addend, index_reg, madd_ea


def _resolve_constant_dispatch(
    br_ea: int,
    min_ea: int,
) -> DispatchPatch | None:
    parsed = _parse_tail_table_load(br_ea, min_ea)
    if parsed is None:
        return None
    table_ea, addend, index_reg, madd_ea = parsed

    eor_ea = next(
        (
            ea
            for ea in _prev_heads(madd_ea, min_ea, 12)
            if _mnem(ea) == "EOR" and _reg(ea, 0) == index_reg
        ),
        None,
    )
    if eor_ea is None:
        return None

    key_reg = _reg(eor_ea, 2)
    if key_reg is None:
        return None
    xor_key = _find_prev_mov_value(eor_ea, min_ea, key_reg, limit=4)
    if xor_key is None:
        return None

    ldr_ea = next(
        (
            ea
            for ea in _prev_heads(eor_ea, min_ea, 8)
            if _mnem(ea) == "LDR" and _reg(ea, 0) == index_reg
        ),
        None,
    )
    if ldr_ea is None:
        return None

    disp = _displ(ldr_ea, 1)
    if disp is None:
        return None
    key_base_reg, key_off = disp
    key_table_ea = _find_prev_adr(ldr_ea, min_ea, key_base_reg)
    if key_table_ea is None:
        return None

    raw_key = _read_u32(key_table_ea + key_off)
    if raw_key is None:
        return None
    index = _sign_extend_u32(raw_key ^ xor_key)
    target = _table_target(table_ea, index, addend)
    if target is None or not _target_is_code(target):
        return None

    return DispatchPatch(
        ea=ldr_ea,
        end_ea=br_ea + 4,
        kind="constant",
        target=target,
        br_ea=br_ea,
        detail=(
            f"table=0x{table_ea:x} index={index} "
            f"key_table=0x{key_table_ea:x}+0x{key_off:x}"
        ),
    )


def _resolve_conditional_dispatch(
    br_ea: int,
    min_ea: int,
) -> DispatchPatch | None:
    parsed = _parse_tail_table_load(br_ea, min_ea)
    if parsed is None:
        return None
    table_ea, addend, index_reg, madd_ea = parsed

    csel_ea = next(
        (
            ea
            for ea in _prev_heads(madd_ea, min_ea, 16)
            if _mnem(ea) == "CSEL" and _reg(ea, 0) == index_reg
        ),
        None,
    )
    if csel_ea is None:
        return None

    true_reg = _reg(csel_ea, 1)
    false_reg = _reg(csel_ea, 2)
    cond = _operand_text(csel_ea, 3)
    if true_reg is None or false_reg is None or cond not in COND_CODES:
        return None

    true_index = _find_prev_mov_value(csel_ea, min_ea, true_reg, limit=8)
    false_index = _find_prev_mov_value(csel_ea, min_ea, false_reg, limit=8)
    if true_index is None or false_index is None:
        return None

    true_target = _table_target(table_ea, int(true_index), addend)
    false_target = _table_target(table_ea, int(false_index), addend)
    if (
        true_target is None
        or false_target is None
        or not _target_is_code(true_target)
        or not _target_is_code(false_target)
    ):
        return None

    cmp_ea = next(
        (
            ea
            for ea in _prev_heads(csel_ea, min_ea, 8)
            if _mnem(ea) in {"CMP", "CMN", "TST"}
        ),
        None,
    )
    if cmp_ea is None:
        return None

    patch_ea = cmp_ea + 4
    return DispatchPatch(
        ea=patch_ea,
        end_ea=br_ea + 4,
        kind="conditional",
        target=true_target,
        false_target=false_target,
        cond=cond,
        br_ea=br_ea,
        detail=(
            f"table=0x{table_ea:x} true_index={int(true_index)} "
            f"false_index={int(false_index)}"
        ),
    )


def _resolve_dispatch_at_br(br_ea: int, func_start: int) -> DispatchPatch | None:
    return _resolve_conditional_dispatch(br_ea, func_start) or _resolve_constant_dispatch(
        br_ea, func_start
    )


def _function_range(ea: int) -> tuple[int, int, str] | None:
    func = ida_funcs.get_func(ea)
    if func is None:
        return None
    return int(func.start_ea), int(func.end_ea), ida_funcs.get_func_name(func.start_ea)


def _scan_function_for_patches(func_start: int, func_end: int) -> list[DispatchPatch]:
    patches: list[DispatchPatch] = []
    for ea in _heads(func_start, func_end):
        if _mnem(ea) != "BR":
            continue
        patch = _resolve_dispatch_at_br(ea, func_start)
        if patch is not None:
            patches.append(patch)
    return patches


def build_plan(root_ea: int, max_functions: int = MAX_BRANCH_FUNCTIONS) -> PatchPlan:
    """Build a dry-run plan by recursively following resolved BR targets."""

    _require_ida()
    root = ida_funcs.get_func(root_ea)
    if root is None:
        raise RuntimeError(f"0x{root_ea:x} is not inside a function")

    root_start = int(root.start_ea)
    queue = [root_start]
    seen: set[int] = set()
    patches: dict[tuple[int, int], DispatchPatch] = {}
    ranges: dict[int, tuple[int, int, str]] = {}

    while queue and len(seen) < max_functions:
        func_start = queue.pop(0)
        if func_start in seen:
            continue
        seen.add(func_start)

        func_range = _function_range(func_start)
        if func_range is None:
            continue
        ranges[func_range[0]] = func_range

        for patch in _scan_function_for_patches(func_range[0], func_range[1]):
            patches[(patch.ea, patch.br_ea or patch.end_ea)] = patch
            for target in patch.targets:
                target_range = _function_range(target)
                if target_range is None:
                    continue
                if target_range[0] not in seen and target_range[0] not in queue:
                    queue.append(target_range[0])

    merge_start = None
    merge_end = None
    if ranges:
        merge_start = root_start
        merge_end = max(end for _, end, _ in ranges.values())

    return PatchPlan(
        root_ea=root_start,
        patches=tuple(sorted(patches.values(), key=lambda patch: patch.ea)),
        function_ranges=tuple(sorted(ranges.values())),
        merge_start=merge_start,
        merge_end=merge_end,
    )


def _encode_b(ea: int, target: int) -> int:
    delta = target - ea
    if delta % 4 != 0:
        raise ValueError(f"unaligned branch target 0x{target:x} from 0x{ea:x}")
    imm = delta // 4
    if imm < -(1 << 25) or imm >= (1 << 25):
        raise ValueError(f"B target out of range: 0x{ea:x} -> 0x{target:x}")
    return 0x14000000 | (imm & 0x03FFFFFF)


def _encode_b_cond(ea: int, target: int, cond: str) -> int:
    delta = target - ea
    if delta % 4 != 0:
        raise ValueError(f"unaligned conditional branch target 0x{target:x}")
    imm = delta // 4
    if imm < -(1 << 18) or imm >= (1 << 18):
        raise ValueError(f"B.{cond} target out of range: 0x{ea:x} -> 0x{target:x}")
    return 0x54000000 | ((imm & 0x7FFFF) << 5) | COND_CODES[cond]


def _patch_word(ea: int, word: int) -> None:
    ida_bytes.patch_bytes(ea, int(word & 0xFFFFFFFF).to_bytes(4, "little"))
    ida_ua.create_insn(ea)


def _nop_range(start_ea: int, end_ea: int) -> None:
    ea = start_ea
    while ea < end_ea:
        _patch_word(ea, NOP)
        ea += 4


def apply_patch(patch: DispatchPatch) -> None:
    """Apply one patch to the IDB."""

    _require_ida()
    if patch.kind == "conditional":
        if patch.false_target is None or patch.cond is None:
            raise ValueError("conditional patch is missing false target or condition")
        _patch_word(patch.ea, _encode_b_cond(patch.ea, patch.target, patch.cond))
        _patch_word(patch.ea + 4, _encode_b(patch.ea + 4, patch.false_target))
        _nop_range(patch.ea + 8, patch.end_ea)
    elif patch.kind == "constant":
        _patch_word(patch.ea, _encode_b(patch.ea, patch.target))
        _nop_range(patch.ea + 4, patch.end_ea)
    else:
        raise ValueError(f"unknown patch kind: {patch.kind}")

    idaapi.set_cmt(patch.ea, f"D810 AArch64 dispatch patch: {patch.summary()}", False)


def apply_patches(plan: PatchPlan) -> None:
    """Apply all patches from a plan."""

    for patch in plan.patches:
        apply_patch(patch)
    if plan.patches:
        start = min(patch.ea for patch in plan.patches)
        end = max(patch.end_ea for patch in plan.patches)
        ida_auto.plan_and_wait(start, end)


def merge_continuation_functions(plan: PatchPlan) -> bool:
    """Merge discovered continuation functions into the root function.

    This deletes the small continuation function definitions and extends the
    root function range.  Callers should only use this after reviewing the
    dry-run plan.
    """

    _require_ida()
    if plan.merge_start is None or plan.merge_end is None:
        return False

    root = ida_funcs.get_func(plan.root_ea)
    if root is None:
        return False

    for start, _, _ in sorted(plan.function_ranges, reverse=True):
        if start == plan.root_ea:
            continue
        func = ida_funcs.get_func(start)
        if func is not None and int(func.start_ea) == start:
            ida_funcs.del_func(start)

    ok = ida_funcs.set_func_end(plan.root_ea, plan.merge_end)
    ida_auto.plan_and_wait(plan.merge_start, plan.merge_end)
    return bool(ok)


def run(
    root_ea: int | None = None,
    *,
    apply: bool = False,
    merge: bool = False,
    max_functions: int = MAX_BRANCH_FUNCTIONS,
) -> PatchPlan:
    """Build, print, and optionally apply a patch plan.

    Args:
        root_ea: Function entry or any EA inside the root function.  If omitted,
            IDA's current screen EA is used.
        apply: Patch IDB bytes when True.  Defaults to dry-run.
        merge: Merge continuation functions into the root after patching.
        max_functions: Recursion cap for discovered continuation functions.
    """

    _require_ida()
    if root_ea is None:
        root_ea = idc.get_screen_ea()

    plan = build_plan(int(root_ea), max_functions=max_functions)
    plan.print()

    if apply:
        apply_patches(plan)
        print(f"Applied {len(plan.patches)} dispatch patches.")
    else:
        print("Dry-run only. Pass apply=True to patch IDB bytes.")

    if merge:
        if not apply:
            print("merge=True requested, but apply=False; merge was skipped.")
        else:
            ok = merge_continuation_functions(plan)
            print(f"Continuation merge: {'ok' if ok else 'failed/skipped'}")

    return plan


if __name__ == "__main__":
    run()
