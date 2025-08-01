from ida_hexrays import *

from d810.expr.ast import AstConstant, AstLeaf, AstNode
from d810.hexrays.hexrays_helpers import AND_TABLE
from d810.optimizers.microcode.instructions.pattern_matching.handler import (
    PatternMatchingRule,
)


class Neg_HackersDelightRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(m_add, AstNode(m_bnot, AstLeaf("x_0")), AstConstant("1", 1))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_neg, AstLeaf("x_0"))


class Neg_HackersDelightRule_2(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(m_bnot, AstNode(m_sub, AstLeaf("x_0"), AstConstant("1", 1)))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_neg, AstLeaf("x_0"))


class NegSub_HackersDelightRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(
                m_mul,
                AstConstant("2", 2),
                AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_neg, AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1")))


class NegAdd_HackersDelightRule_2(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(
                m_xor, AstLeaf("x_0"), AstNode(m_or, AstLeaf("x_1"), AstLeaf("x_2"))
            ),
            AstNode(
                m_mul,
                AstConstant("2", 2),
                AstNode(
                    m_or, AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")), AstLeaf("x_2")
                ),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_neg,
            AstNode(
                m_add, AstLeaf("x_0"), AstNode(m_or, AstLeaf("x_1"), AstLeaf("x_2"))
            ),
        )


class NegAdd_HackersDelightRule_1(PatternMatchingRule):

    def check_candidate(self, candidate):
        if (candidate["val_fe"].value + 2) & AND_TABLE[candidate["val_fe"].size] != 0:
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(
                m_mul,
                AstConstant("val_fe"),
                AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
            AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_neg, AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1")))


class NegOr_HackersDelightRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_neg, AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")))


class NegXor_HackersDelightRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_neg, AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")))


class NegXor_HackersDelightRule_2(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(
                m_mul,
                AstConstant("2", 2),
                AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_neg, AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")))
