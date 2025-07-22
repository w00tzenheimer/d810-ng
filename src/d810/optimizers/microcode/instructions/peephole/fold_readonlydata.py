from __future__ import annotations

import logging

import ida_hexrays
import ida_segment
import idaapi

import d810._compat as _compat
from d810.optimizers.microcode.instructions.peephole.handler import (
    PeepholeSimplificationRule,
)

peephole_logger = logging.getLogger("D810.optimizer")


class FoldReadonlyDataRule(PeepholeSimplificationRule):
    DESCRIPTION = (
        "Fold constant loads from .rodata array. "
        "Example: Replaces ldx from constant .rodata offset with ldc if value is readable."
    )

    maturities = [
        ida_hexrays.MMAT_GLBOPT2,
    ]

    @_compat.override
    def check_and_replace(
        self, blk: ida_hexrays.mblock_t | None, ins: ida_hexrays.minsn_t
    ) -> ida_hexrays.minsn_t | None:

        if ins.opcode != ida_hexrays.m_ldx:
            return None

        if ins.l.t != ida_hexrays.mop_S or ins.r.t != ida_hexrays.mop_n:
            return None

        seg = ida_segment.get_segm_by_name(".rodata")
        if not seg:
            return None

        if (
            ins.l.s.start_ea + ins.r.nnn.value < seg.start_ea
            or ins.l.s.start_ea + ins.r.nnn.value >= seg.end_ea
        ):
            return None

        addr = ins.l.s.start_ea + ins.r.nnn.value
        size = ins.d.size
        if size == 4:  # Example for dword
            value = idaapi.get_dword(addr)
            if value != idaapi.BADADDR:
                ins.opcode = ida_hexrays.m_ldc
                ins.l.make_number(value, size)
                ins.r.erase()
                return ins
        return None
