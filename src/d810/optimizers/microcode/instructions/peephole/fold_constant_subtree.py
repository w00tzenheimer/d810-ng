from __future__ import annotations

import ida_hexrays

from d810.core import typing
from d810.core import getLogger
from d810.expr.ast import AstBase, minsn_to_ast
from d810.hexrays.hexrays_formatters import format_mop_t, opcode_to_string, sanitize_ea
from d810.hexrays.hexrays_helpers import AND_TABLE
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
_SKIP_OPCODES: frozenset[int] = frozenset({
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
})


class ConstantSubtreeFoldRule(PeepholeSimplificationRule):
    """Fold constant subtrees bottom-up (handles nested ROL/XOR/SBox chains).

    Converts the instruction to an AST, calls _fold_bottom_up to recursively
    constant-fold every node whose children are all constants, then emits a
    replacement m_mov / m_ldc when the entire source expression collapses.

    This rule is intentionally run *after* FoldReadonlyDataRule so that memory
    loads from read-only tables have already been replaced by immediates before
    we attempt algebraic folding.
    """

    DESCRIPTION = "Fold constant subtrees bottom-up (handles nested ROL/XOR/SBox chains)"
    CATEGORY = "Constant Folding"

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        super().__init__(*args, **kwargs)
        # Run after FoldReadonlyDataRule (MMAT_PREOPTIMIZED) has turned
        # read-only table loads into immediates.
        self.maturities = [
            ida_hexrays.MMAT_LOCOPT,
            ida_hexrays.MMAT_CALLS,
            getattr(ida_hexrays, "MMAT_GLBOPT1", ida_hexrays.MMAT_CALLS),
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
            folded, changed = _fold_bottom_up(ast, bits)
        except Exception as exc:
            if logger.debug_on:
                logger.debug(
                    "[fold-subtree] _fold_bottom_up raised at 0x%X %s: %s",
                    sanitize_ea(ins.ea),
                    opcode_to_string(ins.opcode),
                    exc,
                )
            return None

        if not changed:
            return None

        # Check whether the entire expression collapsed to a constant.
        value: int | None = _eval_subtree(folded, bits)
        if value is None:
            return None

        mask = AND_TABLE[dst_size]
        value &= mask

        if logger.debug_on:
            logger.debug(
                "[fold-subtree] 0x%X %s -> ldc 0x%X (size=%d)",
                sanitize_ea(ins.ea),
                opcode_to_string(ins.opcode),
                value,
                dst_size,
            )

        # Emit  m_ldc  #value , dst
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
