from __future__ import annotations

import typing

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

error:

.text:00000001800066D5 C38 48 8B 05 0E 36 06 00                  mov     rax, cs:_qword_1802D2C99+2                                  ; jumptable 0000000180004869 case 134
.text:00000001800066DC C38 48 89 84 24 00 06 00 00               mov     [rsp+0C38h+var_638], rax
.text:0000000180006B2B C38 48 8B 84 24 00 06 00 00               mov     rax, [rsp+0C38h+var_638]
.text:0000000180006B66 C38 48 89 84 24 A8 05 00 00               mov     [rsp+0C38h+var_690], rax
.text:0000000180006B7E C38 48 8B 84 24 A8 05 00 00               mov     rax, [rsp+0C38h+var_690]
.text:0000000180006B8E C38 48 89 84 24 A0 05 00 00               mov     [rsp+0C38h+var_698], rax
.text:0000000180006BA6 C38 48 8B 84 24 A0 05 00 00               mov     rax, [rsp+0C38h+var_698]
.text:0000000180006BAE C38 48 8B 80 20 03 00 00                  mov     rax, [rax+320h]
.text:0000000180006BB5 C38 48 89 84 24 98 05 00 00               mov     [rsp+0C38h+var_6A0], rax

this becomes: `(__ROL8__(MEMORY[0xB10000007FFE03FD]...)` which is obviously wrong.
"""


from typing import Optional

import ida_hexrays
import ida_segment
import idaapi

import d810.core.typing as typing
from d810.core import getLogger
from d810.hexrays.hexrays_helpers import extract_literal_from_mop
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

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        super().__init__(*args, **kwargs)
        # Run where the IR is stable enough to rewrite `ldx` forms safely.
        self.maturities = [
            ida_hexrays.MMAT_LOCOPT,
            ida_hexrays.MMAT_CALLS,
            getattr(ida_hexrays, "MMAT_GLBOPT1", ida_hexrays.MMAT_CALLS),
        ]
        # Configuration for segment permission checking
        # On Mach-O binaries (macOS/iOS), __const segments often have R+X
        # permissions even though they contain read-only data. Set this to
        # True to allow folding from segments that are R+!W (ignoring X).
        self._allow_executable: bool = False

    def configure(self, kwargs: dict) -> None:
        """Configure rule from project settings."""
        super().configure(kwargs)
        # Allow configuration via project config:
        # "allow_executable_readonly": true
        self._allow_executable = kwargs.get("allow_executable_readonly", False)

    # --------------------------------------------------------------------- #
    # Helper functions                                                      #
    # --------------------------------------------------------------------- #

    def _segment_is_read_only(self, addr: int) -> bool:
        """Check if segment at addr is suitable for constant folding.

        By default, requires R+!W+!X (strict read-only data).
        With allow_executable_readonly=True, allows R+!W (ignoring X bit).
        This is useful for Mach-O binaries where __const has R+X permissions.
        """
        seg = ida_segment.getseg(addr)
        if seg is None:
            return False
        perms = seg.perm
        has_read = bool(perms & idaapi.SEGPERM_READ)
        has_write = bool(perms & idaapi.SEGPERM_WRITE)
        has_exec = bool(perms & idaapi.SEGPERM_EXEC)

        # Must be readable and not writable
        if not has_read or has_write:
            return False

        # If we allow executable segments (for Mach-O), ignore the X bit
        if self._allow_executable:
            return True

        # Default strict check: no execute permission
        return not has_exec

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

    @typing.override
    def check_and_replace(
        self, blk: ida_hexrays.mblock_t | None, ins: ida_hexrays.minsn_t
    ) -> ida_hexrays.minsn_t | None:
        """Try to rewrite *ins*.  Return modified instruction or None."""

        # Attempt the **direct displacement** form first ------------------ #
        ea = self._ea_from_direct_load(ins)
        folded_from_mov = False
        if ea is None:
            # Try folding readonly globals used as plain values inside
            # expression trees (e.g., nested under mop_d). Do NOT fold top-level
            # mov of addresses (e.g., function pointers / IAT entries) into
            # immediates – that breaks call-site rendering.
            expr_folded = self._fold_readonly_operands_in_expr(ins)
            return expr_folded

        # We have an effective address for a memory load.  Is it really read-only?
        if ea is None:
            return None
        if not self._segment_is_read_only(ea):
            return None

        # Compute the immediate value from memory contents at the EA.
        # Use the destination size when available, otherwise try source size.
        load_size = ins.d.size if (ins.d and ins.d.size) else ins.l.size
        if not load_size:
            return None
        value = self._fetch_constant(ea, load_size)
        if value is None:
            return None

        # ------------------------------------------------------------------
        # Build the replacement instruction. For true `ldx` loads, use
        # `ldc #imm, dst`.
        # ------------------------------------------------------------------
        new_ins = ida_hexrays.minsn_t(ins.ea)
        new_ins.opcode = ida_hexrays.m_ldc

        cst = ida_hexrays.mop_t()
        # Use unsigned constant form to avoid unexpected sign-extension.
        if load_size in (1, 2, 4, 8) and value < 0:
            value &= (1 << (load_size * 8)) - 1
        cst.make_number(value, load_size)
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
        new_ins.d.size = load_size

        # r operand must be empty
        new_ins.r = ida_hexrays.mop_t()
        new_ins.r.erase()
        # do not set size on an empty operand

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

    @staticmethod
    def _ea_from_simple_mov_load(ins: ida_hexrays.minsn_t) -> Optional[int]:
        """Resolve EA for early `mov`-based memory loads.

        Pattern handled (typically seen at pre-optimized maturity)::

            mov  $_qword_xxx@?.8, rX.8

        Where the left operand is a direct reference to a global/readonly
        location (represented as `mop_v` or `mop_S`).
        """

        if ins.opcode != ida_hexrays.m_mov:
            return None

        # Source must be a direct global/addr operand; destination is ignored
        # here (the caller will validate size and build the `ldc`).
        src = ins.l
        if src is None:
            return None

        if src.t == ida_hexrays.mop_v:
            return src.g
        if src.t == ida_hexrays.mop_S:
            # Only accept true address-bearing symbols. In pre-optimized IR,
            # `mop_S` can also denote stack variables (`stkvar_ref_t`) which do
            # not have an EA and must be ignored.
            start_ea = getattr(src.s, "start_ea", None)
            if start_ea is not None:
                return start_ea
            return None

        return None

    # ------------------------------------------------------------------ #
    # Expression tree folding                                            #
    # ------------------------------------------------------------------ #
    def _fold_readonly_operands_in_expr(
        self, ins: ida_hexrays.minsn_t
    ) -> ida_hexrays.minsn_t | None:
        """Return a copy of `ins` with any `mop_v`/`mop_S` operands that
        reside in a read-only segment replaced by numeric immediates.

        Only folds values used as r-values; addresses (`mop_a`) are not touched.
        """

        # Clone the instruction shallowly via operand assignment
        new_ins = ida_hexrays.minsn_t(ins.ea)
        new_ins.opcode = ins.opcode
        new_ins.l = ida_hexrays.mop_t()
        new_ins.l.assign(ins.l)
        new_ins.r = ida_hexrays.mop_t()
        new_ins.r.assign(ins.r)
        new_ins.d = ida_hexrays.mop_t()
        new_ins.d.assign(ins.d)

        changed = False
        changed |= self._fold_readonly_inplace(new_ins.l)
        # Avoid folding the call target of call-like instructions. Folding a
        # function pointer (e.g., IAT/vtable) into an immediate can confuse the
        # decompiler into emitting spurious MEMORY[ea](...) calls.
        m_icall = getattr(ida_hexrays, "m_icall", None)
        if new_ins.opcode in (ida_hexrays.m_call, m_icall):
            pass
        else:
            changed |= self._fold_readonly_inplace(new_ins.r)
        # do not touch destination

        return new_ins if changed else None

    def _fold_readonly_inplace(self, op: ida_hexrays.mop_t) -> bool:
        """Recursively fold `op` if it references a readonly global.

        Returns True if the operand (or any nested operand) was modified.
        """
        if not op:
            return False

        # Nested expression: recurse into its operands
        if op.t == ida_hexrays.mop_d:
            inner: ida_hexrays.minsn_t = op.d
            # Handle zero/sign-extend of a memory byte/word into an immediate when
            # the effective address can be resolved to &sym + const in a RO segment.
            if inner.opcode in (ida_hexrays.m_xdu, ida_hexrays.m_xds):
                src = inner.l
                ea = None
                mem_size = getattr(src, "size", 0) or 0

                # Case 1: mop_b (memory operand with base+index)
                if src and getattr(src, "t", None) == ida_hexrays.mop_b:
                    ea = self._ea_from_mop_b(src)

                # Case 2: mop_v (direct global variable reference like $unk_CAEB.1)
                # These represent direct reads from global addresses.
                elif src and getattr(src, "t", None) == ida_hexrays.mop_v:
                    ea = src.g

                if ea is not None and self._segment_is_read_only(ea):
                    out_size = (
                        getattr(op, "size", 0) or getattr(inner, "size", 0) or 0
                    )
                    if mem_size in (1, 2, 4, 8) and out_size in (1, 2, 4, 8):
                        val = self._fetch_constant(ea, mem_size)
                        if val is not None:
                            # Apply sign/zero extension
                            if inner.opcode == ida_hexrays.m_xds:
                                sign_bit = 1 << (mem_size * 8 - 1)
                                if val & sign_bit:
                                    val = val - (1 << (mem_size * 8))
                            mask = (1 << (out_size * 8)) - 1
                            folded = val & mask
                            op.make_number(folded, out_size)
                            return True
            # Otherwise, recurse into sub-operands of the inner instruction
            return self._fold_readonly_inplace(inner.l) or self._fold_readonly_inplace(
                inner.r
            )

        # Address-of or pointer-like forms are not folded here
        if op.t in {ida_hexrays.mop_a, ida_hexrays.mop_b}:
            return False

        size = op.size if getattr(op, "size", 0) else 0

        # Do NOT fold plain symbolic addresses (mop_v/mop_S) into immediates.
        # Those represent address values, not memory contents. Actual memory
        # reads go through mop_b (handled above via xdu/xds) or ldx paths.
        if op.t in (ida_hexrays.mop_v, ida_hexrays.mop_S):
            return False

        return False

    # ------------------------------------------------------------------ #
    # mop_b EA reconstruction                                            #
    # ------------------------------------------------------------------ #
    def _ea_from_mop_b(self, mop_b: ida_hexrays.mop_t) -> Optional[int]:
        """Try to reconstruct EA from a memory operand (mop_b).

        Handles patterns like [ds:( &sym + const )] or when the base is an add()
        expression that combines an address-of operand with a constant.
        """
        try:
            b = mop_b.b
            i = mop_b.i
        except Exception:
            return None

        def _addr_from_mop_a(mop_a: ida_hexrays.mop_t) -> Optional[int]:
            inner = mop_a.a
            if inner is None:
                return None
            if inner.t == ida_hexrays.mop_v:
                return inner.g
            if inner.t == ida_hexrays.mop_S:
                return getattr(inner.s, "start_ea", None)
            return None

        def _const_from_mop(m: ida_hexrays.mop_t) -> Optional[int]:
            if m is None:
                return 0
            if m.t == ida_hexrays.mop_n:
                return m.nnn.value
            lits = extract_literal_from_mop(m)
            if lits and len(lits) == 1:
                return lits[0][0]
            return None

        # Case 1: base is address-of symbol, optional constant in index
        if b and b.t == ida_hexrays.mop_a:
            base = _addr_from_mop_a(b)
            if base is None:
                return None
            off = _const_from_mop(i)
            if off is None:
                return None
            return base + off

        # Case 2: base is an add() expression combining &sym and const
        if b and b.t == ida_hexrays.mop_d and b.d and b.d.opcode == ida_hexrays.m_add:
            add_ins = b.d
            left, right = add_ins.l, add_ins.r
            # Try both orders to find (&sym, const)
            if left and left.t == ida_hexrays.mop_a:
                base = _addr_from_mop_a(left)
                if base is not None:
                    off = _const_from_mop(right)
                    if off is not None:
                        return base + off
            if right and right.t == ida_hexrays.mop_a:
                base = _addr_from_mop_a(right)
                if base is not None:
                    off = _const_from_mop(left)
                    if off is not None:
                        return base + off

        # Not a supported form
        return None
