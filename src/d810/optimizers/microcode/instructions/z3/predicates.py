import ida_hexrays

from d810.expr.ast import AstConstant, AstLeaf, AstNode
from d810.expr.z3_utils import (
    z3_check_always_nonzero,
    z3_check_always_zero,
    z3_check_mop_equality,
    z3_check_mop_inequality,
)
from d810.optimizers.microcode.instructions.z3.handler import Z3Rule


class Z3setzRuleGeneric(Z3Rule):
    DESCRIPTION = "Check with Z3 if a m_setz check is always True or False"

    @property
    def PATTERN(self) -> AstNode:
        """Return the pattern to match."""
        return AstNode(ida_hexrays.m_setz, AstLeaf("x_0"), AstLeaf("x_1"))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_mov, AstConstant("val_res"))

    def check_candidate(self, candidate):
        # setz result is a boolean (0 or 1), get size from destination operand
        # The destination size (e.g., %var_365.1 is 1 byte) determines result size,
        # NOT the operand sizes (e.g., x_0 may be 4 bytes)
        res_size = candidate.dst_mop.size if candidate.dst_mop else 1
        x0_mop = candidate["x_0"].mop
        x1_mop = candidate["x_1"].mop

        if z3_check_mop_equality(x0_mop, x1_mop):
            candidate.add_constant_leaf("val_res", 1, res_size)
            return True
        if z3_check_mop_inequality(x0_mop, x1_mop):
            candidate.add_constant_leaf("val_res", 0, res_size)
            return True

        # Check if comparing expression against constant 0
        # This handles opaque predicates like setz((x * (x-1)) & 1, 0)
        if x1_mop is not None and x1_mop.t == ida_hexrays.mop_n and x1_mop.nnn.value == 0:
            # setz(expr, 0) - check if expr is always 0 or always nonzero
            # Pass block/instruction context for backward tracking of register definitions
            if z3_check_always_zero(x0_mop, self._current_blk, self._current_ins):
                # expr is always 0, so setz(0, 0) = 1
                candidate.add_constant_leaf("val_res", 1, res_size)
                return True
            if z3_check_always_nonzero(x0_mop, self._current_blk, self._current_ins):
                # expr is always nonzero, so setz(nonzero, 0) = 0
                candidate.add_constant_leaf("val_res", 0, res_size)
                return True

        return False


class Z3setnzRuleGeneric(Z3Rule):
    DESCRIPTION = "Check with Z3 if a m_setnz check is always True or False"

    @property
    def PATTERN(self) -> AstNode:
        """Return the pattern to match."""
        return AstNode(ida_hexrays.m_setnz, AstLeaf("x_0"), AstLeaf("x_1"))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_mov, AstConstant("val_res"))

    def check_candidate(self, candidate):
        # setnz result is a boolean (0 or 1), get size from destination operand
        # The destination size (e.g., %var_365.1 is 1 byte) determines result size,
        # NOT the operand sizes (e.g., x_0 may be 4 bytes)
        res_size = candidate.dst_mop.size if candidate.dst_mop else 1
        x0_mop = candidate["x_0"].mop
        x1_mop = candidate["x_1"].mop

        if z3_check_mop_equality(x0_mop, x1_mop):
            candidate.add_constant_leaf("val_res", 0, res_size)
            return True
        if z3_check_mop_inequality(x0_mop, x1_mop):
            candidate.add_constant_leaf("val_res", 1, res_size)
            return True

        # Check if comparing expression against constant 0
        # This handles opaque predicates like setnz((x * (x-1)) & 1, 0)
        if x1_mop is not None and x1_mop.t == ida_hexrays.mop_n and x1_mop.nnn.value == 0:
            # setnz(expr, 0) - check if expr is always 0 or always nonzero
            # Pass block/instruction context for backward tracking of register definitions
            if z3_check_always_zero(x0_mop, self._current_blk, self._current_ins):
                # expr is always 0, so setnz(0, 0) = 0
                candidate.add_constant_leaf("val_res", 0, res_size)
                return True
            if z3_check_always_nonzero(x0_mop, self._current_blk, self._current_ins):
                # expr is always nonzero, so setnz(nonzero, 0) = 1
                candidate.add_constant_leaf("val_res", 1, res_size)
                return True

        return False


class Z3lnotRuleGeneric(Z3Rule):
    DESCRIPTION = "Check with Z3 if a m_lnot check is always True or False"

    @property
    def PATTERN(self) -> AstNode:
        """Return the pattern to match."""
        return AstNode(ida_hexrays.m_lnot, AstLeaf("x_0"))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_mov, AstConstant("val_res"))

    def check_candidate(self, candidate):
        # lnot result is a boolean (0 or 1), get size from destination operand
        res_size = candidate.dst_mop.size if candidate.dst_mop else 1
        # For comparing x_0 against 0, use the operand's size
        operand_size = candidate["x_0"].size or 1
        val_0_mop = ida_hexrays.mop_t()
        val_0_mop.make_number(0, operand_size)
        if z3_check_mop_equality(candidate["x_0"].mop, val_0_mop):
            candidate.add_constant_leaf("val_res", 1, res_size)
            return True
        if z3_check_mop_inequality(candidate["x_0"].mop, val_0_mop):
            candidate.add_constant_leaf("val_res", 0, res_size)
            return True
        return False


class Z3SmodRuleGeneric(Z3Rule):
    DESCRIPTION = "Check with Z3 if a m_setz check is always True or False"

    @property
    def PATTERN(self) -> AstNode:
        """Return the pattern to match."""
        return AstNode(ida_hexrays.m_smod, AstLeaf("x_0"), AstConstant("2", 2))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_mov, AstConstant("val_res"))

    def check_candidate(self, candidate):
        # smod result size should match destination operand size
        res_size = candidate.dst_mop.size if candidate.dst_mop else 1
        cst_0_mop = ida_hexrays.mop_t()
        cst_0_mop.make_number(0, res_size)
        if z3_check_mop_equality(candidate.mop, cst_0_mop):
            candidate.add_leaf("val_res", cst_0_mop)
            return True
        cst_1_mop = ida_hexrays.mop_t()
        cst_1_mop.make_number(1, res_size)
        if z3_check_mop_equality(candidate.mop, cst_1_mop):
            candidate.add_leaf("val_res", cst_1_mop)
            return True
        return False
