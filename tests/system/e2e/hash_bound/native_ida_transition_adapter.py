"""Pristine-IDB adapter for the test-only native transition oracle."""

from __future__ import annotations

import re

import ida_bytes
import ida_funcs
import ida_gdl
import ida_idp
import ida_ua
import idautils
import idc

from tests.system.e2e.hash_bound.native_transition_oracle import (
    NativeCfgBlock,
    NativeInstruction,
)


def _compact_operand(ea: int, operand_index: int) -> str:
    return "".join(str(idc.print_operand(ea, operand_index) or "").lower().split())


_REGISTER_TOKEN = re.compile(
    r"\b(?:r(?:1[0-5]|[8-9])(?:d|w|b)?|"
    r"(?:r|e)?(?:ax|bx|cx|dx|si|di|bp|sp)|"
    r"[abcd][lh]|sil|dil|bpl|spl)\b"
)


def _register_family(token: str) -> str:
    token = token.lower()
    extended = re.fullmatch(r"r(1[0-5]|[8-9])(?:d|w|b)?", token)
    if extended is not None:
        return "r" + extended.group(1)
    families = {
        "rax": {"rax", "eax", "ax"},
        "rbx": {"rbx", "ebx", "bx"},
        "rcx": {"rcx", "ecx", "cx"},
        "rdx": {"rdx", "edx", "dx"},
        "rsi": {"rsi", "esi", "si"},
        "rdi": {"rdi", "edi", "di"},
        "rbp": {"rbp", "ebp", "bp"},
        "rsp": {"rsp", "esp", "sp"},
    }
    for family, aliases in families.items():
        if token in aliases:
            return family
    byte_families = {
        "al": "rax",
        "ah": "rax",
        "bl": "rbx",
        "bh": "rbx",
        "cl": "rcx",
        "ch": "rcx",
        "dl": "rdx",
        "dh": "rdx",
        "sil": "rsi",
        "dil": "rdi",
        "bpl": "rbp",
        "spl": "rsp",
    }
    return byte_families[token]


def _operand_registers(ea: int, operand_index: int) -> set[str]:
    return {
        _register_family(match.group(0))
        for match in _REGISTER_TOKEN.finditer(_compact_operand(ea, operand_index))
    }


def _selector_depends_on_block_live_in(
    instruction_eas: tuple[int, ...], state_write_ea: int
) -> bool:
    """Conservatively slice the selector value backward within one block."""

    try:
        write_index = instruction_eas.index(int(state_write_ea))
    except ValueError:
        return True
    tracked: set[str] = set()
    stack_value_live_in = False

    def dependencies(ea: int, instruction: ida_ua.insn_t) -> set[str]:
        nonlocal stack_value_live_in
        feature = int(instruction.get_canon_feature())
        used: set[str] = set()
        for index in range(4):
            use_flag = getattr(ida_idp, f"CF_USE{index + 1}", 0)
            if not feature & int(use_flag):
                continue
            operand = instruction.ops[index]
            rendered = _compact_operand(ea, index)
            if int(operand.type) == int(ida_ua.o_reg):
                used.update(_operand_registers(ea, index))
            elif str(ida_ua.print_insn_mnem(ea) or "").lower() == "lea":
                used.update(_operand_registers(ea, index))
            elif "[rsp" in rendered or "[rbp" in rendered:
                stack_value_live_in = True
        return used

    write = ida_ua.insn_t()
    if int(ida_ua.decode_insn(write, int(state_write_ea))) <= 0:
        return True
    tracked.update(dependencies(int(state_write_ea), write))
    meaningful_instructions = 0
    for ea in reversed(instruction_eas[:write_index]):
        if not tracked:
            return stack_value_live_in
        if int(state_write_ea) - int(ea) > 0x100:
            return True
        if int(ida_bytes.get_byte(int(ea))) == 0x90:
            continue
        meaningful_instructions += 1
        if meaningful_instructions > 64:
            return True
        instruction = ida_ua.insn_t()
        if int(ida_ua.decode_insn(instruction, int(ea))) <= 0:
            return True
        feature = int(instruction.get_canon_feature())
        defined: set[str] = set()
        for index in range(4):
            change_flag = getattr(ida_idp, f"CF_CHG{index + 1}", 0)
            if not feature & int(change_flag):
                continue
            operand = instruction.ops[index]
            if (
                int(operand.type) == int(ida_ua.o_reg)
                and int(ida_ua.get_dtype_size(operand.dtype)) >= 4
            ):
                defined.update(_operand_registers(int(ea), index))
        if not tracked.intersection(defined):
            continue
        tracked.difference_update(defined)
        tracked.update(dependencies(int(ea), instruction))
    return bool(tracked or stack_value_live_in)


def _writes_selector(
    ea: int,
    *,
    selector_stack_displacement: int,
    selector_width: int,
) -> bool:
    instruction = ida_ua.insn_t()
    if int(ida_ua.decode_insn(instruction, ea)) <= 0:
        return False
    destination = instruction.ops[0]
    return bool(
        int(instruction.get_canon_feature()) & int(ida_idp.CF_CHG1)
        and int(destination.type) == int(ida_ua.o_displ)
        and int(destination.addr) == int(selector_stack_displacement)
        and int(ida_ua.get_dtype_size(destination.dtype)) == int(selector_width)
        and _compact_operand(ea, 0).startswith("[rsp")
    )


def _has_observable_effect(
    ea: int,
    *,
    selector_stack_displacement: int,
    selector_width: int,
) -> bool:
    instruction = ida_ua.insn_t()
    if int(ida_ua.decode_insn(instruction, ea)) <= 0:
        return True
    mnemonic = str(ida_ua.print_insn_mnem(ea) or "").lower()
    if ida_idp.is_call_insn(instruction) or mnemonic.startswith(("ret", "int", "ud")):
        return True
    rendered = str(idc.generate_disasm_line(ea, 0) or "").strip().lower()
    if rendered.startswith("lock "):
        return True
    if not int(instruction.get_canon_feature()) & int(ida_idp.CF_CHG1):
        return False
    destination = _compact_operand(ea, 0)
    return "[" in destination and not _writes_selector(
        ea,
        selector_stack_displacement=selector_stack_displacement,
        selector_width=selector_width,
    )


def capture_native_selector_cfg(
    function_ea: int,
    *,
    selector_stack_displacement: int,
    selector_width: int,
) -> tuple[NativeCfgBlock, ...]:
    """Capture native blocks without consulting D810 recovery evidence."""

    function = ida_funcs.get_func(int(function_ea))
    if function is None:
        raise ValueError(f"no native function at 0x{int(function_ea):X}")
    blocks: list[NativeCfgBlock] = []
    for flow_block in ida_gdl.FlowChart(function, flags=ida_gdl.FC_PREDS):
        instruction_eas = tuple(
            int(ea)
            for ea in idautils.Heads(int(flow_block.start_ea), int(flow_block.end_ea))
            if ida_bytes.is_code(ida_bytes.get_full_flags(int(ea)))
        )
        blocks.append(
            NativeCfgBlock(
                start_ea=int(flow_block.start_ea),
                instruction_eas=instruction_eas,
                successor_eas=tuple(
                    sorted(int(successor.start_ea) for successor in flow_block.succs())
                ),
                selector_write_eas=tuple(
                    ea
                    for ea in instruction_eas
                    if _writes_selector(
                        ea,
                        selector_stack_displacement=selector_stack_displacement,
                        selector_width=selector_width,
                    )
                ),
                observable_effect_eas=tuple(
                    ea
                    for ea in instruction_eas
                    if _has_observable_effect(
                        ea,
                        selector_stack_displacement=selector_stack_displacement,
                        selector_width=selector_width,
                    )
                ),
                selector_live_in_write_eas=tuple(
                    ea
                    for ea in instruction_eas
                    if _writes_selector(
                        ea,
                        selector_stack_displacement=selector_stack_displacement,
                        selector_width=selector_width,
                    )
                    and _selector_depends_on_block_live_in(instruction_eas, ea)
                ),
            )
        )
    return tuple(sorted(blocks, key=lambda block: block.start_ea))


def capture_exact_native_instructions(
    function_ea: int,
) -> tuple[NativeInstruction, ...]:
    function = ida_funcs.get_func(int(function_ea))
    if function is None:
        raise ValueError(f"no native function at 0x{int(function_ea):X}")
    instructions: list[NativeInstruction] = []
    for ea in idautils.Heads(int(function.start_ea), int(function.end_ea)):
        if not ida_bytes.is_code(ida_bytes.get_full_flags(int(ea))):
            continue
        instruction = ida_ua.insn_t()
        size = int(ida_ua.decode_insn(instruction, int(ea)))
        if size <= 0:
            continue
        data = ida_bytes.get_bytes(int(ea), size)
        if data is None or len(data) != size:
            raise ValueError(f"cannot read native instruction at 0x{int(ea):X}")
        instructions.append(NativeInstruction(int(ea), bytes(data)))
    return tuple(instructions)


__all__ = ["capture_exact_native_instructions", "capture_native_selector_cfg"]
