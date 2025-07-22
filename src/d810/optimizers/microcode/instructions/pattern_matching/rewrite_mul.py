from d810.expr.ast import AstConstant, AstLeaf, AstNode
from d810.hexrays.hexrays_helpers import SUB_TABLE, equal_bnot_mop, is_check_mop
from d810.optimizers.microcode.instructions.pattern_matching.handler import (
    PatternMatchingRule,
)

from ida_hexrays import *


class Mul_MbaRule_1(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(
                m_mul,
                AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")),
                AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
            AstNode(
                m_mul,
                AstNode(m_and, AstLeaf("x_0"), AstLeaf("bnot_x_1")),
                AstNode(m_and, AstLeaf("x_1"), AstLeaf("bnot_x_0")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_mul, AstLeaf("x_0"), AstLeaf("x_1"))


# This is false.
class Mul_MbaRule_2(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not is_check_mop(candidate["x_0"].mop):
            return False
        if candidate["c_1"].value & 0x1 != 1:
            return False
        if not equal_bnot_mop(candidate["c_1"].mop, candidate["bnot_c_1"].mop):
            return False
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(
                m_mul, AstNode(m_or, AstLeaf("x_0"), AstConstant("c_1")), AstLeaf("x_0")
            ),
            AstNode(
                m_mul,
                AstNode(m_and, AstLeaf("x_0"), AstConstant("bnot_c_1")),
                AstNode(m_and, AstConstant("c_1"), AstLeaf("bnot_x_0")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_mul, AstLeaf("x_0"), AstConstant("c_1"))


# This is false.
class Mul_MbaRule_3(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not is_check_mop(candidate["x_0"].mop):
            return False
        if candidate["c_1"].value & 0x1 == 1:
            return False
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(
                m_mul,
                AstNode(m_or, AstLeaf("x_0"), AstConstant("c_1")),
                AstNode(m_and, AstLeaf("x_0"), AstConstant("c_1")),
            ),
            AstNode(
                m_mul,
                AstLeaf("x_0"),
                AstNode(m_and, AstConstant("c_1"), AstLeaf("bnot_x_0")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_mul, AstLeaf("x_0"), AstConstant("c_1"))


class Mul_MbaRule_4(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(
                m_mul,
                AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")),
                AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
            AstNode(
                m_mul,
                AstNode(m_bnot, AstNode(m_or, AstLeaf("x_0"), AstLeaf("bnot_x_1"))),
                AstNode(m_and, AstLeaf("x_0"), AstLeaf("bnot_x_1")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_mul, AstLeaf("x_0"), AstLeaf("x_1"))


class Mul_FactorRule_1(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstConstant("2", 2),
            AstNode(
                m_mul,
                AstConstant("2", 2),
                AstNode(
                    m_add,
                    AstLeaf("x_1"),
                    AstNode(m_or, AstLeaf("x_0"), AstLeaf("bnot_x_1")),
                ),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_mul, AstConstant("2", 2), AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1"))
        )


class Mul_FactorRule_2(PatternMatchingRule):

    def check_candidate(self, candidate):
        candidate.add_constant_leaf(
            "val_fe", SUB_TABLE[candidate.size] - 2, candidate.size
        )
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_neg, AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1"))),
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_mul, AstConstant("val_fe"), AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1"))
        )
