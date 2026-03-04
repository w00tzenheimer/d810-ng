"""Read-only CFG topology query functions.

This module contains pure query functions that inspect control flow graph
topology without modifying it. Split from cfg_utils.py as part of the
CFG Pass Pipeline refactor (Phase 1).
"""
from __future__ import annotations

import ida_hexrays

from d810.hexrays.utils.hexrays_helpers import CONDITIONAL_JUMP_OPCODES


def is_conditional_jump(blk: ida_hexrays.mblock_t) -> bool:
    if (blk is not None) and (blk.tail is not None):
        return blk.tail.opcode in CONDITIONAL_JUMP_OPCODES
    return False


def is_indirect_jump(blk: ida_hexrays.mblock_t) -> bool:
    if (blk is not None) and (blk.tail is not None):
        return blk.tail.opcode == ida_hexrays.m_ijmp
    return False


def get_block_serials_by_address(mba: ida_hexrays.mbl_array_t, address: int) -> list[int]:
    blk_serial_list = []
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk.start == address:
            blk_serial_list.append(i)
    return blk_serial_list


def get_block_serials_by_address_range(mba: ida_hexrays.mbl_array_t, address: int) -> list[int]:
    blk_serial_list = []
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk.start <= address <= blk.end:
            blk_serial_list.append(i)
    return blk_serial_list


def _serial_in_predset(blk: "ida_hexrays.mblock_t", serial: int) -> bool:
    """Check if *serial* is already present in *blk*'s predset."""
    for i in range(blk.predset.size()):
        if blk.predset[i] == serial:
            return True
    return False


__all__ = [
    "is_conditional_jump",
    "is_indirect_jump",
    "get_block_serials_by_address",
    "get_block_serials_by_address_range",
    "_serial_in_predset",
]
