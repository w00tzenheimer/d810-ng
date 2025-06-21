from d810.ast import AstLeaf, AstNode, minsn_to_ast
from d810.hexrays_helpers import AND_TABLE  # already maps size→mask
from d810.optimizers.instructions.pattern_matching.handler import PatternMatchingRule
from d810.utils import rol1, rol2, rol4, rol8, ror1, ror2, ror4, ror8

import ida_hexrays

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
    # synthetic helpers
    if op == ida_hexrays.m_call and a == "__ROL4__":
        return rol4(b, bits)
    if op == ida_hexrays.m_call and a == "__ROR4__":
        return ror4(b, bits)
    if op == ida_hexrays.m_call and a == "__ROL2__":
        return rol2(b, bits)
    if op == ida_hexrays.m_call and a == "__ROR2__":
        return ror2(b, bits)
    if op == ida_hexrays.m_call and a == "__ROL1__":
        return rol1(b, bits)
    if op == ida_hexrays.m_call and a == "__ROR1__":
        return ror1(b, bits)
    if op == ida_hexrays.m_call and a == "__ROL8__":
        return rol8(b, bits)
    if op == ida_hexrays.m_call and a == "__ROR8__":
        return ror8(b, bits)
    raise ValueError


def _eval_subtree(ast: AstNode, bits) -> int | None:
    """returns an int if subtree is constant, else None"""
    if ast.is_leaf():
        mop = ast.mop
        if _is_const(mop):
            return mop.nnn.value & AND_TABLE[bits // 8]  # type: ignore
        return None

    # unary
    if ast.right is None:
        val = _eval_subtree(ast.left, bits)
        if val is None:
            return None
        if ast.opcode == ida_hexrays.m_neg:
            return (-val) & AND_TABLE[bits // 8]
        if ast.opcode == ida_hexrays.m_bnot:
            return (~val) & AND_TABLE[bits // 8]
        return None

    # binary
    l = _eval_subtree(ast.left, bits)
    r = _eval_subtree(ast.right, bits)
    if l is None or r is None:
        return None
    return _fold(ast.opcode, l, r, bits)


# ────────────────────────────────────────────────────────────────────
# The rule
# ────────────────────────────────────────────────────────────────────
class FoldPureConstantRule(PatternMatchingRule):
    """
    Collapse any instruction whose *entire* expression tree is a numeric
    constant into a single m_ldc.
    Works at MMAT_LOCOPT & later (when SSA is stable).
    """

    DESCRIPTION = "Generic constant-propagation / folding pass"

    # allow every maturity after LVARS
    def __init__(self):
        super().__init__()
        self.maturities = [
            ida_hexrays.MMAT_LOCOPT,
            ida_hexrays.MMAT_CALLS,
            ida_hexrays.MMAT_GLBOPT1,
            ida_hexrays.MMAT_GLBOPT2,
            ida_hexrays.MMAT_GLBOPT3,
            ida_hexrays.MMAT_LVARS,
        ]

    # We override the generic matcher completely
    def check_and_replace(self, blk, ins):
        ast = minsn_to_ast(ins)
        if ast is None:
            return None

        bits = ins.d.size * 8 if ins.d.size else 32
        value = _eval_subtree(ast, bits)
        if value is None:
            return None  # not a pure-constant expression

        # build:  ldc  #value, dst
        new_ins = ida_hexrays.minsn_t(ins)  # clone to keep ea, sizes…
        new_ins.opcode = ida_hexrays.m_ldc
        cst = ida_hexrays.mop_t()
        cst.make_number(value, ins.d.size)
        new_ins.l = cst  # source constant
        new_ins.r.erase()
        # keep the original destination (ins.d)
        return new_ins
