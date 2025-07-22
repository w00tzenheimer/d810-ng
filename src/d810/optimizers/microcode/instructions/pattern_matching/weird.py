from d810.expr.ast import AstConstant, AstLeaf, AstNode
from d810.hexrays.hexrays_helpers import equal_bnot_mop
from d810.optimizers.microcode.instructions.pattern_matching.handler import (
    PatternMatchingRule,
)

from ida_hexrays import *


class WeirdRule1(PatternMatchingRule):

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_1", 1, candidate.size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub, AstLeaf("x_0"), AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1"))
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(m_or, AstLeaf("x_0"), AstNode(m_bnot, AstLeaf("x_1"))),
            AstConstant("val_1"),
        )


class WeirdRule2(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_mul, AstConstant("2", 2), AstLeaf("x_0")),
            AstNode(m_and, AstLeaf("x_0"), AstNode(m_bnot, AstLeaf("x_1"))),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_add, AstLeaf("x_0"), AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1"))
        )


class WeirdRule3(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_and, AstLeaf("x_0"), AstNode(m_bnot, AstLeaf("x_1"))),
            AstNode(m_mul, AstConstant("2", 2), AstLeaf("x_0")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_neg,
            AstNode(
                m_add, AstLeaf("x_0"), AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1"))
            ),
        )


class WeirdRule4(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("bnot_x_1")),
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_sub, AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")), AstLeaf("x_1")
        )


class WeirdRule5(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(
                m_add,
                AstNode(
                    m_or,
                    AstLeaf("bnot_x_0"),
                    AstNode(m_and, AstLeaf("bnot_x_1"), AstLeaf("x_2")),
                ),
                AstNode(
                    m_add,
                    AstLeaf("x_0"),
                    AstNode(m_and, AstLeaf("x_1"), AstLeaf("x_2")),
                ),
            ),
            AstLeaf("x_2"),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_or,
            AstLeaf("x_0"),
            AstNode(m_or, AstLeaf("x_1"), AstNode(m_bnot, AstLeaf("x_2"))),
        )


class WeirdRule6(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_and, AstLeaf("x_0"), AstNode(m_bnot, AstLeaf("x_1"))),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_add, AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")), AstLeaf("x_0")
        )
