from __future__ import annotations

"""fold_readonlydata.py

A peephole rule that replaces loads from a *provably read-only* table (typically
located in `.rdata` / `.rodata`) with an immediate load (`ldc`).
It works for for only one microcode pattern Hex-Rays emits:

1. Direct displacement load
   ldx  &($sym).8, #off        ──▶  ldc  #value

By eliminating the table look-up, we unlock many more constant-folding
opportunities in later optimisation stages.
"""

""" TODO:

Add support for indirect load through a temporary register
   mov  &($sym).8, rax.8
   xdu  [ds:(rax.8+#off)].1 …   ──▶  ldc  #value
   
def _ea_from_indirect_load(
    self, blk: ida_hexrays.mblock_t | None, ins: ida_hexrays.minsn_t
) -> Optional[int]:
    # Handle loads where base address is in a register that earlier got
    # its value from   mov &sym → reg   inside the **same basic block**.
    # Expect operand of the form  [ reg + const ]  in DS segment.
    if ins.l.t != ida_hexrays.mop_b:
        return None
    mop_b = ins.l  # memory operand
    # if mop_b.fpc != ida_hexrays.segm_ds:
    #     return None  # only DS for now
    # Base must be a register (stored as mop_v) and displacement constant.
    if mop_b.b.t != ida_hexrays.mop_v:
        return None
    base_reg = mop_b.b
    if mop_b.i.t != ida_hexrays.mop_n:
        return None
    disp = mop_b.i.nnn.value

    # Look for defining instruction of *base_reg* in the current block.
    if blk is None:
        return None
    def_ins = ida_hexrays.find_defins(blk, ins, base_reg)
    if def_ins is None or def_ins.opcode != ida_hexrays.m_mov:
        return None
    # Must be  mov  &($sym).8, base_reg
    if def_ins.l.t != ida_hexrays.mop_S:
        return None
    base_ea = def_ins.l.s.start_ea
    return base_ea + disp
"""


from typing import Optional

import ida_hexrays
import ida_segment
import idaapi

import d810._compat as _compat
from d810.conf.loggers import getLogger
from d810.optimizers.microcode.instructions.peephole.handler import (
    PeepholeSimplificationRule,
)

peephole_logger = getLogger(__name__)


class FoldReadonlyDataRule(PeepholeSimplificationRule):
    """Replace constant table look-ups by immediates."""

    DESCRIPTION = (
        "Fold constant loads from .rodata array. "
        "Example: Replaces ldx from constant .rodata offset with ldc if value is readable."
    )

    # Run in many maturity stages so we catch the pattern early or late
    maturities = [ida_hexrays.MMAT_LOCOPT, ida_hexrays.MMAT_CALLS]

    # --------------------------------------------------------------------- #
    # Helper functions                                                      #
    # --------------------------------------------------------------------- #

    @staticmethod
    def _segment_is_read_only(addr: int) -> bool:
        seg = ida_segment.getseg(addr)
        if seg is None:
            return False
        # A read-only segment has READ perm but no WRITE perm.
        return (seg.perm & idaapi.SEGPERM_READ) and not (
            seg.perm & idaapi.SEGPERM_WRITE
        )

    @staticmethod
    def _fetch_constant(addr: int, size: int) -> Optional[int]:
        """Read *size* bytes at *addr* and return them as int."""

        if size == 1:
            val = idaapi.get_byte(addr)
        elif size == 2:
            val = idaapi.get_word(addr)
        elif size == 4:
            val = idaapi.get_dword(addr)
        elif size == 8:
            val = idaapi.get_qword(addr)
        else:
            return None
        return None if val == idaapi.BADADDR else val

    # ------------------------------------------------------------------ #
    # Main peephole implementation                                      #
    # ------------------------------------------------------------------ #

    @_compat.override
    def check_and_replace(
        self, blk: ida_hexrays.mblock_t | None, ins: ida_hexrays.minsn_t
    ) -> ida_hexrays.minsn_t | None:
        """Try to rewrite *ins*.  Return modified instruction or None."""

        # Attempt the **direct displacement** form first ------------------ #
        ea = self._ea_from_direct_load(ins)
        if ea is None:
            return None

        # We have an effective address.  Is it really read-only?
        if not self._segment_is_read_only(ea):
            return None

        # Fetch the literal constant.
        value = self._fetch_constant(ea, ins.d.size)
        if value is None:
            return None

        # ------------------------------------------------------------------
        # Build a brand-new `ldc` instruction so that we do not mutate *ins* in
        # place (Hex-Rays validator dislikes opcode changes in-situ).
        # ------------------------------------------------------------------
        new_ins = ida_hexrays.minsn_t(ins.ea)
        new_ins.opcode = ida_hexrays.m_ldc

        cst = ida_hexrays.mop_t()
        cst.make_number(value, ins.d.size)
        new_ins.l = cst

        # Keep original destination when it is a legal l-value, otherwise erase.
        new_ins.d = ida_hexrays.mop_t()
        if ins.d and ins.d.t in {
            ida_hexrays.mop_r,
            ida_hexrays.mop_l,
            ida_hexrays.mop_S,
            ida_hexrays.mop_v,
        }:
            new_ins.d.assign(ins.d)
        else:
            new_ins.d.erase()
        new_ins.d.size = ins.d.size

        # r operand is empty for ldc
        new_ins.r = ida_hexrays.mop_t()
        new_ins.r.erase()
        new_ins.r.size = ins.d.size

        return new_ins

    # ------------------------------------------------------------------ #
    # EA reconstruction helpers                                           #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _ea_from_direct_load(ins: ida_hexrays.minsn_t) -> Optional[int]:
        """Reconstruct EA for the common direct-displacement variants Hex-Rays
        can emit for an `ldx` table look-up.
        Returns the effective address or *None* if the pattern is not matched.
        Supported forms::

            ldx  &sym , #off
            ldx  ds ,  add(&sym , #off)
        """

        if ins.opcode != ida_hexrays.m_ldx:
            return None

        # ------------------------------------------------------------------
        #  Variant A:   ldx  &sym , #off
        # ------------------------------------------------------------------
        if ins.l.t == ida_hexrays.mop_S and ins.r.t == ida_hexrays.mop_n:
            base = ins.l.s.start_ea
            off = ins.r.nnn.value
            return base + off

        # ------------------------------------------------------------------
        #  Variant B:   ldx  ds , add(&sym , #off)
        # ------------------------------------------------------------------
        if ins.l.t == ida_hexrays.mop_r and ins.r.t == ida_hexrays.mop_d:
            add_ins = ins.r.d  # underlying micro-instruction of the mop_d
            if add_ins.opcode != ida_hexrays.m_add:
                return None
            # Expect one operand to be "&sym" (mop_a) and the other a constant.
            # Hex-Rays usually puts the address on the left, constant on right
            # but we handle both orders just in case.
            adr_op, cnst_op = add_ins.l, add_ins.r
            if adr_op.t != ida_hexrays.mop_a or cnst_op.t != ida_hexrays.mop_n:
                # swap and try again
                if (
                    add_ins.r.t == ida_hexrays.mop_a
                    and add_ins.l.t == ida_hexrays.mop_n
                ):
                    adr_op, cnst_op = add_ins.r, add_ins.l
                else:
                    return None
            # adr_op is mop_a  →  resolve the inner symbol.
            inner = adr_op.a
            if inner.t == ida_hexrays.mop_v:
                base = inner.g
            elif inner.t == ida_hexrays.mop_S:
                base = inner.s.start_ea
            else:
                return None
            off = cnst_op.nnn.value
            return base + off

        return None
