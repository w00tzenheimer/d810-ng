from ida_hexrays import *

from d810.expr.ast import AstConstant, AstLeaf, AstNode
from d810.expr.z3_utils import z3_check_mop_equality, z3_check_mop_inequality
from d810.optimizers.microcode.instructions.z3.handler import Z3Rule


class Z3setzRuleGeneric(Z3Rule):
    DESCRIPTION = "Check with Z3 if a m_setz check is always True or False"

    @property
    def PATTERN(self) -> AstNode:
        """Return the pattern to match."""
        return AstNode(m_setz, AstLeaf("x_0"), AstLeaf("x_1"))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_mov, AstConstant("val_res"))

    def check_candidate(self, candidate):
        if z3_check_mop_equality(candidate["x_0"].mop, candidate["x_1"].mop):
            candidate.add_constant_leaf("val_res", 1, candidate.size)
            return True
        if z3_check_mop_inequality(candidate["x_0"].mop, candidate["x_1"].mop):
            candidate.add_constant_leaf("val_res", 0, candidate.size)
            return True
        return False


class Z3setnzRuleGeneric(Z3Rule):
    DESCRIPTION = "Check with Z3 if a m_setnz check is always True or False"

    @property
    def PATTERN(self) -> AstNode:
        """Return the pattern to match."""
        return AstNode(m_setnz, AstLeaf("x_0"), AstLeaf("x_1"))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_mov, AstConstant("val_res"))

    def check_candidate(self, candidate):
        if z3_check_mop_equality(candidate["x_0"].mop, candidate["x_1"].mop):
            candidate.add_constant_leaf("val_res", 0, candidate.size)
            return True
        if z3_check_mop_inequality(candidate["x_0"].mop, candidate["x_1"].mop):
            candidate.add_constant_leaf("val_res", 1, candidate.size)
            return True
        return False


class Z3lnotRuleGeneric(Z3Rule):
    DESCRIPTION = "Check with Z3 if a m_lnot check is always True or False"

    @property
    def PATTERN(self) -> AstNode:
        """Return the pattern to match."""
        return AstNode(m_lnot, AstLeaf("x_0"))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_mov, AstConstant("val_res"))

    def check_candidate(self, candidate):
        val_0_mop = mop_t()
        val_0_mop.make_number(0, candidate["x_0"].size)
        if z3_check_mop_equality(candidate["x_0"].mop, val_0_mop):
            candidate.add_constant_leaf("val_res", 1, candidate.size)
            return True
        if z3_check_mop_inequality(candidate["x_0"].mop, val_0_mop):
            candidate.add_constant_leaf("val_res", 0, candidate.size)
            return True
        return False


class Z3SmodRuleGeneric(Z3Rule):
    DESCRIPTION = "Check with Z3 if a m_setz check is always True or False"

    @property
    def PATTERN(self) -> AstNode:
        """Return the pattern to match."""
        return AstNode(m_smod, AstLeaf("x_0"), AstConstant("2", 2))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_mov, AstConstant("val_res"))

    def check_candidate(self, candidate):
        cst_0_mop = mop_t()
        cst_0_mop.make_number(0, candidate.size)
        if z3_check_mop_equality(candidate.mop, cst_0_mop):
            candidate.add_leaf("val_res", cst_0_mop)
            return True
        cst_1_mop = mop_t()
        cst_1_mop.make_number(1, candidate.size)
        if z3_check_mop_equality(candidate.mop, cst_1_mop):
            candidate.add_leaf("val_res", cst_1_mop)
            return True
        return False
