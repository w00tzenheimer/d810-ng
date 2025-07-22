from d810.expr.ast import AstConstant, AstLeaf, AstNode
from d810.hexrays.hexrays_helpers import SUB_TABLE, equal_bnot_mop
from d810.optimizers.microcode.instructions.pattern_matching.handler import (
    PatternMatchingRule,
)

from ida_hexrays import *


class And_HackersDelightRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_or, AstNode(m_bnot, AstLeaf("x_0")), AstLeaf("x_1")),
            AstNode(m_bnot, AstLeaf("x_0")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1"))


class And_HackersDelightRule_2(PatternMatchingRule):

    def check_candidate(self, candidate):
        return equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop)

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(m_or, AstLeaf("bnot_x_0"), AstLeaf("x_1")),
            AstNode(m_add, AstLeaf("x_0"), AstConstant("1", 1)),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1"))


class And_HackersDelightRule_3(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1"))


class And_HackersDelightRule_4(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1"))


class And_OllvmRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_and,
            AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_bnot, AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1"))


class And_OllvmRule_2(PatternMatchingRule):

    def check_candidate(self, candidate):
        return equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop)

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_and,
            AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_xor, AstLeaf("x_0"), AstLeaf("bnot_x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1"))


class And_OllvmRule_3(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_and,
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_bnot, AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1"))


class And_FactorRule_1(PatternMatchingRule):

    def check_candidate(self, candidate):
        return equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop)

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_and, AstNode(m_xor, AstLeaf("x_0"), AstLeaf("bnot_x_1")), AstLeaf("x_1")
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1"))


class And_FactorRule_2(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_and,
            AstLeaf("x_0"),
            AstNode(m_bnot, AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1"))


class AndBnot_HackersDelightRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub, AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")), AstLeaf("x_1")
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_and, AstLeaf("x_0"), AstNode(m_bnot, AstLeaf("x_1")))


class AndBnot_HackersDelightRule_2(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub, AstLeaf("x_0"), AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1"))
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_and, AstLeaf("x_0"), AstNode(m_bnot, AstLeaf("x_1")))


class AndBnot_FactorRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_xor, AstLeaf("x_0"), AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1"))
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_and, AstLeaf("x_0"), AstNode(m_bnot, AstLeaf("x_1")))


class AndBnot_FactorRule_2(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_and, AstLeaf("x_0"), AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_and, AstLeaf("x_0"), AstNode(m_bnot, AstLeaf("x_1")))


class AndBnot_FactorRule_3(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_xor, AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")), AstLeaf("x_1")
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_and, AstLeaf("x_0"), AstNode(m_bnot, AstLeaf("x_1")))


class AndBnot_FactorRule_4(PatternMatchingRule):

    def check_candidate(self, candidate):
        return equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop)

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_and,
            AstNode(m_xor, AstLeaf("x_1"), AstLeaf("x_0")),
            AstNode(m_bnot, AstNode(m_and, AstLeaf("x_0"), AstLeaf("bnot_x_1"))),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_and, AstLeaf("x_1"), AstNode(m_bnot, AstLeaf("x_0")))


class AndOr_FactorRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or,
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_2")),
            AstNode(m_and, AstLeaf("x_1"), AstLeaf("x_2")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_and, AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")), AstLeaf("x_2")
        )


class AndXor_FactorRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_xor,
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_2")),
            AstNode(m_and, AstLeaf("x_1"), AstLeaf("x_2")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_and, AstNode(m_xor, AstLeaf("x_%%0"), AstLeaf("x_1")), AstLeaf("x_2")
        )


class And1_MbaRule_1(PatternMatchingRule):

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_1", 1, candidate.size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_and, AstNode(m_mul, AstLeaf("x_0"), AstLeaf("x_0")), AstConstant("3", 3)
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_and, AstLeaf("x_0"), AstConstant("val_1"))


# This is false
# The core flaw is assuming that multiplication by a power of two can be
# distributed or commuted with a bitwise AND operation in this way. It cannot.
class AndGetUpperBits_FactorRule_1(PatternMatchingRule):

    def check_candidate(self, candidate):
        # It's possible it only works for very specific values of c_3? (i.e., if c_3 is -1, an all-ones mask),
        # TODO: Add a constraint to check_candidate that c_3 is a valid constant mask.
        if (2 ** candidate["c_2"].value) != candidate["c_1"].value:
            return False
        c_res = (SUB_TABLE[candidate["c_1"].size] - candidate["c_1"].value) & candidate[
            "c_3"
        ].value
        candidate.add_constant_leaf("c_res", c_res, candidate["x_0"].size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_mul,
            AstConstant("c_1"),
            AstNode(
                m_and,
                AstNode(m_shr, AstLeaf("x_0"), AstConstant("c_2")),
                AstConstant("c_3"),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_and, AstLeaf("x_0"), AstConstant("c_res"))
