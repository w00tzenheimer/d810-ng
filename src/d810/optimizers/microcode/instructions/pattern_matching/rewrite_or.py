from d810.expr.ast import AstConstant, AstLeaf, AstNode
from d810.hexrays.hexrays_helpers import equal_bnot_mop
from d810.optimizers.microcode.instructions.pattern_matching.handler import (
    PatternMatchingRule,
)

from ida_hexrays import *


class Or_HackersDelightRule_1(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add, AstNode(m_and, AstLeaf("x_0"), AstLeaf("bnot_x_1")), AstLeaf("x_1")
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1"))


class Or_HackersDelightRule_2(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1"))


class Or_HackersDelightRule_2_variant_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_sub, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_and, AstLeaf("x_0"), AstNode(m_neg, AstLeaf("x_1"))),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_or, AstLeaf("x_0"), AstNode(m_neg, AstLeaf("x_1")))


class Or_MbaRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1"))


class Or_MbaRule_2(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(
                m_add,
                AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1")),
                AstConstant("1", 1),
            ),
            AstNode(m_bnot, AstNode(m_and, AstLeaf("x_1"), AstLeaf("x_0"))),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1"))


class Or_MbaRule_3(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(
                m_add, AstLeaf("x_0"), AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))
            ),
            AstNode(m_and, AstLeaf("x_0"), AstNode(m_bnot, AstLeaf("x_1"))),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1"))


class Or_FactorRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or,
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1"))


class Or_FactorRule_2(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or,
            AstNode(
                m_and, AstLeaf("x_0"), AstNode(m_xor, AstLeaf("x_1"), AstLeaf("x_2"))
            ),
            AstNode(
                m_xor, AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")), AstLeaf("x_2")
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_or, AstLeaf("x_0"), AstNode(m_xor, AstLeaf("x_1"), AstLeaf("x_2"))
        )


class Or_FactorRule_3(PatternMatchingRule):

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
            AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_xor, AstLeaf("bnot_x_0"), AstLeaf("bnot_x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1"))


class Or_OllvmRule_1(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or,
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_bnot, AstNode(m_xor, AstLeaf("bnot_x_0"), AstLeaf("x_1"))),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1"))


class Or_Rule_1(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or, AstNode(m_and, AstLeaf("bnot_x_0"), AstLeaf("x_1")), AstLeaf("x_0")
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1"))


class Or_Rule_2(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or, AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")), AstLeaf("x_1")
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1"))


class Or_Rule_3(PatternMatchingRule):

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
            AstNode(m_bnot, AstNode(m_or, AstLeaf("bnot_x_0"), AstLeaf("bnot_x_1"))),
            AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1"))


class Or_Rule_4(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_xor,
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1"))


class OrBnot_FactorRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_xor,
            AstNode(m_bnot, AstLeaf("x_0")),
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_or, AstNode(m_bnot, AstLeaf("x_0")), AstLeaf("x_1"))


class OrBnot_FactorRule_2(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_xor,
            AstLeaf("x_0"),
            AstNode(m_and, AstNode(m_bnot, AstLeaf("x_0")), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1"))


class OrBnot_FactorRule_3(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(m_sub, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_or, AstLeaf("bnot_x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_or, AstLeaf("x_0"), AstNode(m_bnot, AstLeaf("x_1")))


class OrBnot_FactorRule_4(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_xor,
            AstNode(m_or, AstLeaf("bnot_x_0"), AstLeaf("x_1")),
            AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_or, AstLeaf("x_0"), AstNode(m_bnot, AstLeaf("x_1")))
