from __future__ import annotations

import logging
import typing

from d810.expr.ast import AstBase, AstLeaf, AstNode, minsn_to_ast
from d810.expr.utils import (
    get_parity_flag,
    rol1,
    rol2,
    rol4,
    rol8,
    ror1,
    ror2,
    ror4,
    ror8,
)
from d810.hexrays.hexrays_helpers import (  # already maps size→mask
    AND_TABLE,
    OPCODES_INFO,
)
from d810.optimizers.instructions.peephole.handler import PeepholeSimplificationRule

import ida_hexrays

peephole_logger = logging.getLogger("D810.optimizer")


# ────────────────────────────────────────────────────────────────────
# Utility helpers
# ────────────────────────────────────────────────────────────────────
COMMUTATIVE = {
    ida_hexrays.m_add,
    ida_hexrays.m_mul,
    ida_hexrays.m_xor,
    ida_hexrays.m_or,
    ida_hexrays.m_and,
}


def _is_const(mop):
    return mop is not None and mop.t == ida_hexrays.mop_n


#     return changed
def _fold_const_in_mop(mop: ida_hexrays.mop_t, bits: int) -> bool:
    """
    Walk a mop tree, try to constant-fold, return True if anything changed.
    """
    if mop is None or not isinstance(mop, ida_hexrays.mop_t):
        return False

    changed = False

    # Recurse only if this is an embedded instruction (mop_d)
    if mop.t == ida_hexrays.mop_d and mop.d is not None:
        ins = mop.d
        changed |= _fold_const_in_mop(ins.l, bits)
        changed |= _fold_const_in_mop(ins.r, bits)

        # After children are folded, see if *this* minsn collapses
        ast = minsn_to_ast(ins)
        val = _eval_subtree(ast, bits)
        if val is not None:
            cst = ida_hexrays.mop_t()
            cst.make_number(val, ins.d.size)
            mop.copy(cst)  # replace subtree with constant
            changed = True

    return changed


def _fold_bottom_up(ast: AstBase, bits) -> tuple[AstBase, bool]:
    """
    Constant-fold every binary/unary node whose children are constants.
    Returns (new_node, changed?).
    """
    changed = False

    # leaves
    if ast.is_leaf():
        return ast, False
    ast = typing.cast(AstNode, ast)

    # recurse first
    if ast.left is not None:
        new_left, ch_left = _fold_bottom_up(ast.left, bits)
        if ch_left:
            ast.left = new_left
            changed = True
    if ast.right is not None:
        new_right, ch_right = _fold_bottom_up(ast.right, bits)
        if ch_right:
            ast.right = new_right
            changed = True

    # now try to collapse this node
    if ast.right is None:
        val = _eval_subtree(ast, bits)
        if val is not None:
            leaf = AstLeaf(val)  # tiny helper; see below
            leaf.mop = ida_hexrays.mop_t()
            leaf.mop.make_number(val, bits // 8)
            return leaf, True
    elif ast.left is not None and ast.right is not None:
        lval = _eval_subtree(ast.left, bits)
        rval = _eval_subtree(ast.right, bits)
        if lval is not None and rval is not None:
            val = _fold(ast.opcode, lval, rval, bits)
            leaf = AstLeaf(val)
            leaf.mop = ida_hexrays.mop_t()
            leaf.mop.make_number(val, bits // 8)
            return leaf, True

    return ast, changed


def _fold(op, a, b, bits):
    mask = AND_TABLE[bits // 8]
    if op == ida_hexrays.m_add:
        return (a + b) & mask
    if op == ida_hexrays.m_sub:
        return (a - b) & mask
    if op == ida_hexrays.m_mul:
        return (a * b) & mask
    if op == ida_hexrays.m_and:
        return (a & b) & mask
    if op == ida_hexrays.m_or:
        return (a | b) & mask
    if op == ida_hexrays.m_xor:
        return (a ^ b) & mask
    if op == ida_hexrays.m_shl:
        return (a << b) & mask
    if op == ida_hexrays.m_shr:
        return (a >> b) & mask
    if op == ida_hexrays.m_sar:
        return ((a ^ (1 << bits - 1)) >> b) ^ (1 << bits - 1)
    if op == ida_hexrays.m_setp:
        # Parity flag is set when low-byte of (a - b) has even parity (PF=1 → result 1)
        nb_bytes = bits // 8 if bits else 1
        return 1 if get_parity_flag(a, b, nb_bytes) else 0

    _mcode_op: dict[str, typing.Any] = OPCODES_INFO[op]
    peephole_logger.error(
        "Unknown opcode: %s with args: %s %s and bits: %s",
        _mcode_op["name"],
        a,
        b,
        bits,
    )
    return None


def _eval_subtree(ast: AstBase | None, bits) -> int | None:
    """returns an int if subtree is constant, else None"""
    if ast is None:
        return None

    if ast.is_leaf():
        ast = typing.cast(AstLeaf, ast)
        mop = ast.mop
        if _is_const(mop):
            return mop.nnn.value & AND_TABLE[bits // 8]  # type: ignore
        return None

    # unary
    assert ast.is_node()
    ast = typing.cast(AstNode, ast)
    if ast.right is None:
        ast = typing.cast(AstNode, ast)
        val = _eval_subtree(ast.left, bits)
        if val is None:
            return None
        if ast.opcode == ida_hexrays.m_neg:
            return (-val) & AND_TABLE[bits // 8]
        if ast.opcode == ida_hexrays.m_bnot:
            return (~val) & AND_TABLE[bits // 8]
        return None

    # binary
    l = _eval_subtree(ast.left, bits)  # type: ignore
    r = _eval_subtree(ast.right, bits)  # type: ignore
    if l is None or r is None:
        return None

    # special handling for rotate calls
    if ast.opcode == ida_hexrays.m_call and ast.func_name:
        mask = (1 << bits) - 1
        shift = r % bits
        if ast.func_name.startswith("__ROL"):
            return ((l << shift) | (l >> (bits - shift))) & mask
        elif ast.func_name.startswith("__ROR"):
            return ((l >> shift) | (l << (bits - shift))) & mask
        # if needed, handle specific widths or other variants
        peephole_logger.error(
            "Unknown width for rotate call: %s with args: %s %s and bits: %s",
            ast.func_name,
            l,
            r,
            bits,
        )
        return None
    return _fold(ast.opcode, l, r, bits)  # type: ignore


class FoldPureConstantRule(PeepholeSimplificationRule):
    DESCRIPTION = (
        "Collapse any instruction whose whole expression "
        "is a compile-time constant into a single m_ldc"
    )

    maturities = [
        ida_hexrays.MMAT_GLBOPT1,
        ida_hexrays.MMAT_GLBOPT2,
    ]

    @typing.override
    def check_and_replace(
        self, blk: ida_hexrays.mblock_t, ins: ida_hexrays.minsn_t
    ) -> ida_hexrays.minsn_t | None:
        bits = ins.d.size * 8 if ins.d.size else 32
        # 1) do *local* folding everywhere inside the ins
        changed = False
        for mop in (ins.l, ins.r, ins.d):
            changed |= _fold_const_in_mop(mop, bits)

        # if we simplified any sub-expression, return the *mutated* instruction
        if changed:
            return ida_hexrays.minsn_t(ins)  # copy = treat as replacement

        # 2) second chance: whole-tree collapses → emit m_ldc
        ast = minsn_to_ast(ins)
        if ast is None:
            return None

        value = _eval_subtree(ast, bits)
        if value is None:
            return None  # not foldable

        new = ida_hexrays.minsn_t(ins)  # clone to keep ea/sizes
        new.opcode = ida_hexrays.m_ldc
        cst = ida_hexrays.mop_t()
        cst.make_number(value, ins.d.size)
        new.l = cst
        new.r.erase()
        return new


# def _fold_const_in_mop(mop: ida_hexrays.mop_t, bits: int) -> bool:
#     """
#     Recursively rewrites 'mop' in place; returns True if something changed.
#     """
#     changed = False

#     if mop is None:
#         return False

#     if mop.t == ida_hexrays.mop_d and mop.d is not None:
#         # sub-instruction:  build AST → fold → regenerate mop
#         sub_ast = minsn_to_ast(mop.d)
#         if sub_ast:
#             new_ast, ch = _fold_bottom_up(sub_ast, bits)
#             if ch and isinstance(new_ast, AstNode):
#                 # regenerate sub-insn from AST and overwrite
#                 new_sub = new_ast.create_minsn(mop.d.ea)  # this helper exists in d810
#                 mop.d = new_sub
#                 changed = True

#     # argument list of a call lives in a mop_a
#     if mop.t == ida_hexrays.mop_a:
#         for a in mop.a:  # mop.a is the list< mop_t >
#             changed |= _fold_const_in_mop(a, bits)

#     # binary mops (l/r)
#     if hasattr(mop, "l"):
#         changed |= _fold_const_in_mop(mop.l, bits)
#     if hasattr(mop, "r"):
#         changed |= _fold_const_in_mop(mop.r, bits)
# ────────────────────────────────────────────────────────────────────
# The rule
# # ────────────────────────────────────────────────────────────────────
# class FoldPureConstantRule(PatternMatchingRule):
#     """
#     Collapse any instruction whose *entire* expression tree is a numeric
#     constant into a single m_ldc.
#     Works at MMAT_LOCOPT & later (when SSA is stable).
#     """

#     # Dummy pattern just to satisfy the loader (must be an AstNode!)
#     PATTERN = AstNode(ida_hexrays.m_mov, AstLeaf("lhs"), AstLeaf("rhs"))
#     REPLACEMENT_PATTERN = PATTERN  # never used, but must exist
#     DESCRIPTION = "Generic constant-propagation / folding pass"

#     # allow every maturity after LVARS
#     def __init__(self):
#         super().__init__()
#         self.maturities = [
#             ida_hexrays.MMAT_LOCOPT,
#             ida_hexrays.MMAT_CALLS,
#             ida_hexrays.MMAT_GLBOPT1,
#             ida_hexrays.MMAT_GLBOPT2,
#             ida_hexrays.MMAT_GLBOPT3,
#             ida_hexrays.MMAT_LVARS,
#         ]

#     # We override the generic matcher completely
#     def check_and_replace(self, blk, ins):
#         ast = minsn_to_ast(ins)
#         if ast is None:
#             return None

#         bits = ins.d.size * 8 if ins.d.size else 32
#         value = _eval_subtree(ast, bits)
#         if value is None:
#             return None  # not a pure-constant expression

#         # build:  ldc  #value, dst
#         new_ins = ida_hexrays.minsn_t(ins)  # clone to keep ea, sizes…
#         new_ins.opcode = ida_hexrays.m_ldc
#         cst = ida_hexrays.mop_t()
#         cst.make_number(value, ins.d.size)
#         new_ins.l = cst  # source constant
#         new_ins.r.erase()
#         # keep the original destination (ins.d)
#         return new_ins
