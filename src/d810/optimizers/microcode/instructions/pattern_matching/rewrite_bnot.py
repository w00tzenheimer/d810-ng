from d810.expr.ast import AstConstant, AstLeaf, AstNode
from d810.hexrays.hexrays_helpers import SUB_TABLE, equal_bnot_mop
from d810.optimizers.microcode.instructions.pattern_matching.handler import (
    PatternMatchingRule,
)

from ida_hexrays import *


class Bnot_HackersDelightRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(m_sub, AstNode(m_neg, AstLeaf("x_0")), AstConstant("1", 1))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_bnot, AstLeaf("x_0"))


class Bnot_HackersDelightRule_2(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or,
            AstNode(m_bnot, AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1"))),
            AstNode(m_bnot, AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_bnot, AstLeaf("x_1"))


class Bnot_MbaRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_sub, AstLeaf("x_0"), AstConstant("1", 1)),
            AstNode(m_mul, AstConstant("2", 2), AstLeaf("x_0")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_bnot, AstLeaf("x_0"))


class Bnot_FactorRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_xor,
            AstNode(m_bnot, AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))),
            AstLeaf("x_1"),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_bnot, AstLeaf("x_0"))


class Bnot_FactorRule_2(PatternMatchingRule):

    def check_candidate(self, candidate):
        if candidate["minus_1"].value != SUB_TABLE[candidate["minus_1"].size] - 1:
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(m_sub, AstConstant("minus_1"), AstLeaf("x_0"))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_bnot, AstLeaf("x_0"))


class Bnot_FactorRule_3(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_xor,
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_or, AstLeaf("x_0"), AstLeaf("bnot_x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_bnot, AstLeaf("x_1"))


class Bnot_FactorRule_4(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_xor, AstNode(m_bnot, AstLeaf("x_0")), AstNode(m_bnot, AstLeaf("x_1"))
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


class BnotXor_Rule_1(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or,
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_and, AstLeaf("bnot_x_0"), AstLeaf("bnot_x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_bnot, AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")))


class BnotXor_Rule_2(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_xor,
            AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_or, AstLeaf("bnot_x_0"), AstLeaf("bnot_x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_bnot, AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")))


class BnotXor_Rule_3(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_and,
            AstNode(m_or, AstLeaf("x_0"), AstLeaf("bnot_x_1")),
            AstNode(m_or, AstLeaf("bnot_x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_bnot, AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")))


class BnotXor_FactorRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstLeaf("x_0"), AstNode(m_bnot, AstLeaf("x_1")))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_bnot, AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")))


class BnotAnd_FactorRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or,
            AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_bnot, AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1"))),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_bnot, AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")))


class BnotAnd_FactorRule_2(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or,
            AstNode(m_or, AstLeaf("bnot_x_0"), AstLeaf("bnot_x_1")),
            AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_bnot, AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")))


class BnotAnd_FactorRule_3(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or, AstNode(m_bnot, AstLeaf("x_0")), AstNode(m_bnot, AstLeaf("x_1"))
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_bnot, AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")))


class BnotAnd_FactorRule_4(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or, AstLeaf("bnot_x_0"), AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_bnot, AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")))


class BnotOr_FactorRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_and, AstNode(m_bnot, AstLeaf("x_0")), AstNode(m_bnot, AstLeaf("x_1"))
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_bnot, AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")))


class BnotAdd_MbaRule_1(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_xor, AstLeaf("x_0"), AstLeaf("bnot_x_1")),
            AstNode(
                m_mul,
                AstConstant("2", 2),
                AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_bnot, AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1")))


class Bnot_Rule_1(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or,
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("bnot_x_1")),
            AstNode(m_bnot, AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1"))),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_mov, AstLeaf("bnot_x_1"))


class Bnot_XorRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or,
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_bnot, AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1"))),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_bnot, AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")))
