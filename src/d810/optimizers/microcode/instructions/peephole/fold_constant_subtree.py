from __future__ import annotations

import ida_hexrays

from d810.core import typing
from d810.core import getLogger
from d810.hexrays.expr.ast import AstBase
from d810.hexrays.ir.minsn_utils import minsn_to_ast
from d810.hexrays.utils.hexrays_formatters import (
    format_mop_t,
    opcode_to_string,
    sanitize_ea,
)
from d810.hexrays.utils.hexrays_helpers import AND_TABLE
from d810.optimizers.microcode.instructions.peephole.handler import (
    PeepholeSimplificationRule,
)
from d810.optimizers.microcode.instructions.peephole.normalise_helpers import (
    _eval_subtree,
    _fold_bottom_up,
)

logger = getLogger(__name__)

# Opcodes where it is not safe to replace the whole instruction with m_ldc.
# Control-flow instructions must be left alone.
_SKIP_OPCODES: frozenset[int] = frozenset(
    {
        ida_hexrays.m_goto,
        ida_hexrays.m_jcnd,
        ida_hexrays.m_jnz,
        ida_hexrays.m_jz,
        ida_hexrays.m_jae,
        ida_hexrays.m_jb,
        ida_hexrays.m_ja,
        ida_hexrays.m_jbe,
        ida_hexrays.m_jg,
        ida_hexrays.m_jge,
        ida_hexrays.m_jl,
        ida_hexrays.m_jle,
        ida_hexrays.m_jtbl,
        ida_hexrays.m_ijmp,
        ida_hexrays.m_call,
        ida_hexrays.m_icall,
        ida_hexrays.m_ret,
        ida_hexrays.m_push,
        ida_hexrays.m_pop,
        ida_hexrays.m_ldx,
        ida_hexrays.m_stx,
    }
)

# Flag-producing opcodes: their destination is always 1 byte (the flag), but
# the source operands can be wider.  Replacing the whole instruction with
# ``m_ldc #value, dst`` would use ``dst_size`` (1) for the constant but the
# folded value was computed from wider operands, producing a size mismatch
# that causes INTERR 50832 in IDA's verifier.
# These opcodes must fall through to the partial-fold path which
# reconstructs the instruction from the folded AST, preserving sizes.
#
# The carry/overflow/sign computations below share that exact shape and were
# missing from this set.  On VM_DecryptPacket that let 46 of 111 rewrites turn
# ``ofadd #0x5506EB47.4, #0xBB16AAD0.4, of.1`` into ``ldc #0x17.1, of.1`` --
# ``bits`` is derived from ``dst_size`` (1), so the value is evaluated 8-bit
# wide and is BOTH the wrong overflow result and a size mismatch.  The verifier
# reported it at an unrelated ``xdu`` downstream, and the failure rolled back
# the whole constant-simplification bundle, so its sibling FoldReadonlyDataRule
# never inlined a single global.
_SET_OPCODES: frozenset[int] = frozenset(
    {
        ida_hexrays.m_setz,
        ida_hexrays.m_setnz,
        ida_hexrays.m_setae,
        ida_hexrays.m_setb,
        ida_hexrays.m_seta,
        ida_hexrays.m_setbe,
        ida_hexrays.m_setg,
        ida_hexrays.m_setge,
        ida_hexrays.m_setl,
        ida_hexrays.m_setle,
        ida_hexrays.m_setp,
        ida_hexrays.m_sets,
        ida_hexrays.m_seto,
        ida_hexrays.m_cfadd,
        ida_hexrays.m_ofadd,
        ida_hexrays.m_cfshl,
        ida_hexrays.m_cfshr,
    }
)


# Shift opcodes: the verifier requires the shift-AMOUNT operand to be exactly
# one byte -- ``verify.cpp`` raises ``INTERR 50835`` for ``m_shl``/``m_shr``/
# ``m_sar`` whenever ``r.size != 1`` (and ``INTERR 52118`` when a ``mop_n``
# amount exceeds the shift mask).  ``create_minsn`` rebuilds the partially
# folded tree at ``dst_size``, so a folded shift amount comes back at the
# DESTINATION width instead of its own.  On VM_DecryptPacket that produced
#
#     shr %var_3F8.4, #0x6F57001.4, %var_61C.4
#
# from an amount expression whose every operand was ``.1`` -- wrong size (trips
# 50835) and wrong value (evaluated 32-bit wide; the true 8-bit result is 1).
# The same clamp already exists in ``FoldReadonlyDataRule``.
_SHIFT_OPCODES: frozenset[int] = frozenset(
    {
        ida_hexrays.m_shl,
        ida_hexrays.m_shr,
        ida_hexrays.m_sar,
    }
)


def _clamp_shift_amount(ins: "ida_hexrays.minsn_t | None", depth: int = 0) -> None:
    """Narrow every folded shift amount back to the one byte the verifier demands.

    Recursive: ``create_minsn`` commonly buries the shift one level down inside a
    ``mop_d`` (``and (%var_6B4.4 <<l #5.4), #0x2000.4, eax.4``), so the outer
    opcode is ``m_and`` / ``m_bnot`` and a top-level-only check never fires.  The
    verifier walks sub-instructions too, so every nesting level must be clamped.
    """
    if ins is None or depth > 12:
        return
    if ins.opcode in _SHIFT_OPCODES:
        r = ins.r
        if r is not None and r.t == ida_hexrays.mop_n and r.size != 1:
            r.make_number(r.nnn.value & 0xFF, 1)
    for slot in ("l", "r", "d"):
        operand = getattr(ins, slot, None)
        if (
            operand is not None
            and operand.t == ida_hexrays.mop_d
            and operand.d is not None
        ):
            _clamp_shift_amount(operand.d, depth + 1)


class ConstantSubtreeFoldRule(PeepholeSimplificationRule):
    """Fold constant subtrees bottom-up (handles nested ROL/XOR/SBox chains).

    Converts the instruction to an AST, calls _fold_bottom_up to recursively
    constant-fold every node whose children are all constants, then emits a
    replacement m_mov / m_ldc when the entire source expression collapses.

    This rule is intentionally run *after* FoldReadonlyDataRule so that memory
    loads from read-only tables have already been replaced by immediates before
    we attempt algebraic folding.
    """

    DESCRIPTION = (
        "Fold constant subtrees bottom-up (handles nested ROL/XOR/SBox chains)"
    )
    CATEGORY = "Constant Folding"

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        super().__init__(*args, **kwargs)
        # Run after FoldReadonlyDataRule (MMAT_PREOPTIMIZED) has turned
        # read-only table loads into immediates. GLBOPT2/GLBOPT3 are safe —
        # the unflattener does not run there (uses CALLS/GLBOPT1/GLBOPT2).
        self.maturities = [
            ida_hexrays.MMAT_LOCOPT,
            ida_hexrays.MMAT_CALLS,
            getattr(ida_hexrays, "MMAT_GLBOPT1", ida_hexrays.MMAT_CALLS),
            getattr(ida_hexrays, "MMAT_GLBOPT2", ida_hexrays.MMAT_CALLS),
            getattr(ida_hexrays, "MMAT_GLBOPT3", ida_hexrays.MMAT_CALLS),
        ]

    @typing.override
    def check_and_replace(
        self, blk: ida_hexrays.mblock_t | None, ins: ida_hexrays.minsn_t
    ) -> ida_hexrays.minsn_t | None:
        """Try to fold *ins* to a constant.  Return replacement or None."""

        if ins.opcode in _SKIP_OPCODES:
            return None

        # We need a destination to emit a meaningful replacement.
        if ins.d is None or ins.d.t not in {
            ida_hexrays.mop_r,
            ida_hexrays.mop_l,
            ida_hexrays.mop_S,
            ida_hexrays.mop_v,
        }:
            return None

        dst_size: int = ins.d.size
        if dst_size not in AND_TABLE:
            return None

        bits: int = dst_size * 8

        # Build AST for the whole instruction.
        ast: AstBase | None = minsn_to_ast(ins)
        if ast is None:
            return None

        # Attempt bottom-up constant folding.
        try:
            folded, changed = _fold_bottom_up(ast, bits, blk=blk, ins=ins)
        except Exception as exc:
            return None

        if not changed:
            return None

        # Check whether the entire expression collapsed to a constant.
        value: int | None = _eval_subtree(folded, bits, blk=blk, ins=ins)

        if value is not None and ins.opcode not in _SET_OPCODES:
            # Whole expression is constant — emit m_ldc #value, dst
            mask = AND_TABLE[dst_size]
            value &= mask

            new_ins = ida_hexrays.minsn_t(sanitize_ea(ins.ea))
            new_ins.opcode = ida_hexrays.m_ldc

            cst = ida_hexrays.mop_t()
            cst.make_number(value, dst_size)
            new_ins.l = cst

            new_ins.d = ida_hexrays.mop_t()
            new_ins.d.assign(ins.d)
            new_ins.d.size = dst_size

            new_ins.r = ida_hexrays.mop_t()
            new_ins.r.erase()

            return new_ins

        # Partial fold: a sub-expression was simplified to a constant but the
        # outer expression still contains variables.  Rebuild the instruction
        # from the partially-folded AST so that subsequent passes see a
        # simpler expression (e.g., a plain constant operand instead of a deep
        # ROL/XOR chain).
        #
        # Safety: skip partial folding for xdu/xds wrapping SET/comparison
        # opcodes.  create_minsn on such trees produces size-mismatched
        # instructions that trigger INTERR 50832.  The outer instruction's
        # opcode is checked in _SET_OPCODES above; here we additionally guard
        # against xdu/xds whose folded child is a SET node, and against
        # _SET_OPCODES themselves — create_minsn on partially-folded set/cmp
        # trees produces size-mismatched instructions (INTERR 50832).
        if (
            ins.opcode in (ida_hexrays.m_xdu, ida_hexrays.m_xds)
            or ins.opcode in _SET_OPCODES
        ):
            return None

        if not folded.is_node():
            # Folded to a leaf but _eval_subtree said non-constant — shouldn't
            # happen, but bail out safely to avoid corrupting the CFG.
            return None

        try:
            dst_mop = ida_hexrays.mop_t()
            dst_mop.assign(ins.d)
            dst_mop.size = dst_size
            new_ins = folded.create_minsn(sanitize_ea(ins.ea), dst_mop)
            _clamp_shift_amount(new_ins)
            return new_ins
        except Exception as exc:
            return None
