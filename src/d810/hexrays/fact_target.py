"""Hex-Rays adapters for portable fact collectors."""
from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays


def _opcode_name(opcode: int) -> str:
    if opcode == ida_hexrays.m_add:
        return "m_add"
    if opcode == ida_hexrays.m_sub:
        return "m_sub"
    if opcode == ida_hexrays.m_stx:
        return "m_stx"
    if opcode == ida_hexrays.m_mov:
        return "m_mov"
    return f"op_{int(opcode)}"


def _stack_offset(mop: object | None) -> int | None:
    if getattr(mop, "t", None) == ida_hexrays.mop_S:
        return int(mop.s.off)
    return None


def _mop_type_name(mop: object | None) -> str | None:
    mop_type = getattr(mop, "t", None)
    if mop_type == ida_hexrays.mop_S:
        return "mop_S"
    if mop_type == ida_hexrays.mop_n:
        return "mop_n"
    if mop_type == ida_hexrays.mop_d:
        return "mop_d"
    if mop_type == ida_hexrays.mop_r:
        return "mop_r"
    if mop_type == ida_hexrays.mop_b:
        return "mop_b"
    return None


def _const_value(mop: object | None) -> int | None:
    if getattr(mop, "t", None) == ida_hexrays.mop_n:
        return int(mop.nnn.value)
    return None


def mba_to_fact_target(mba: object) -> object:
    """Adapt a live ``mba_t`` to the neutral block/instruction fact shape."""
    blocks = {}
    qty = int(getattr(mba, "qty", 0) or 0)
    for block_index in range(qty):
        blk = mba.get_mblock(block_index)
        if blk is None:
            continue
        instructions = []
        insn = getattr(blk, "head", None)
        insn_index = 0
        while insn is not None:
            try:
                dstr = insn.dstr()
            except Exception:
                dstr = ""
            left = getattr(insn, "l", None)
            right = getattr(insn, "r", None)
            dest = getattr(insn, "d", None)
            instructions.append(
                SimpleNamespace(
                    index=insn_index,
                    ea=int(getattr(insn, "ea", 0) or 0),
                    opcode_name=_opcode_name(int(getattr(insn, "opcode", -1))),
                    dest_type=_mop_type_name(dest),
                    dest_stkoff=_stack_offset(dest),
                    dest_size=getattr(dest, "size", None),
                    src_l_type=_mop_type_name(left),
                    src_l_stkoff=_stack_offset(left),
                    src_l_value=_const_value(left),
                    src_r_type=_mop_type_name(right),
                    src_r_stkoff=_stack_offset(right),
                    src_r_value=_const_value(right),
                    dstr=str(dstr),
                )
            )
            insn = getattr(insn, "next", None)
            insn_index += 1
        block_serial = int(getattr(blk, "serial", block_index))
        blocks[block_serial] = SimpleNamespace(
            serial=block_serial,
            instructions=tuple(instructions),
        )
    return SimpleNamespace(blocks=blocks)
