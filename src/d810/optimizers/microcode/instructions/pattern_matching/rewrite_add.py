from ida_hexrays import *

from d810.expr.ast import AstConstant, AstLeaf, AstNode
from d810.hexrays.hexrays_helpers import (
    AND_TABLE,
    equal_bnot_mop,
    equal_mops_ignore_size,
)
from d810.optimizers.microcode.instructions.pattern_matching.handler import (
    PatternMatchingRule,
)


class Add_HackersDelightRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstLeaf("x_0"),
            AstNode(m_add, AstNode(m_bnot, AstLeaf("x_1")), AstConstant("1", 1)),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1"))


class Add_HackersDelightRule_2(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(
                m_mul,
                AstConstant("2", 2),
                AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1"))


class Add_HackersDelightRule_3(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1"))


class Add_HackersDelightRule_4(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(
                m_mul,
                AstConstant("2", 2),
                AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
            AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1"))


class Add_HackersDelightRule_5(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(
                m_mul,
                AstConstant("2", 2),
                AstNode(
                    m_or, AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")), AstLeaf("x_2")
                ),
            ),
            AstNode(
                m_xor, AstLeaf("x_0"), AstNode(m_or, AstLeaf("x_1"), AstLeaf("x_2"))
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_add, AstLeaf("x_0"), AstNode(m_or, AstLeaf("x_1"), AstLeaf("x_2"))
        )


class Add_SpecialConstantRule_1(PatternMatchingRule):

    def check_candidate(self, candidate):
        return equal_mops_ignore_size(candidate["c_1"].mop, candidate["c_2"].mop)

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(m_xor, AstLeaf("x_0"), AstConstant("c_1")),
            AstNode(
                m_mul,
                AstConstant("2", 2),
                AstNode(m_and, AstLeaf("x_0"), AstConstant("c_2")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_add, AstLeaf("x_0"), AstConstant("c_1"))


# This rule is not correct!
class Add_SpecialConstantRule_2(PatternMatchingRule):

    def check_candidate(self, candidate):
        return candidate["c_1"].value & 0xFF == candidate["c_2"].value

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(
                m_xor,
                AstNode(m_and, AstLeaf("x_0"), AstConstant("val_ff", 0xFF)),
                AstConstant("c_1"),
            ),
            AstNode(
                m_mul,
                AstConstant("2", 2),
                AstNode(m_and, AstLeaf("x_0"), AstConstant("c_2")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(m_and, AstLeaf("x_0"), AstConstant("val_ff", 0xFF)),
            AstConstant("c_1"),
        )


class Add_SpecialConstantRule_3(PatternMatchingRule):

    def check_candidate(self, candidate):
        # c_1 == ~c_2
        if not equal_bnot_mop(candidate["c_1"].mop, candidate["c_2"].mop):
            return False
        # constant becomes: val_res == c_2 - 1
        candidate.add_constant_leaf(
            "val_res", candidate["c_2"].value - 1, candidate["x_0"].size
        )
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(m_xor, AstLeaf("x_0"), AstConstant("c_1")),
            AstNode(
                m_mul,
                AstConstant("2", 2),
                AstNode(m_or, AstLeaf("x_0"), AstConstant("c_2")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_add, AstLeaf("x_0"), AstConstant("val_res"))


class Add_OllvmRule_1(PatternMatchingRule):

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_1", 1, candidate.size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(m_bnot, AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))),
            AstNode(
                m_mul,
                AstConstant("2", 2),
                AstNode(m_or, AstLeaf("x_1"), AstLeaf("x_0")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_sub, AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1")), AstConstant("val_1")
        )


class Add_OllvmRule_2(PatternMatchingRule):

    def check_candidate(self, candidate):
        if (candidate["val_fe"].value + 2) & AND_TABLE[candidate["val_fe"].size] != 0:
            return False
        candidate.add_constant_leaf("val_1", 1, candidate.size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_bnot, AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))),
            AstNode(
                m_mul,
                AstConstant("val_fe"),
                AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_sub, AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1")), AstConstant("val_1")
        )


class Add_OllvmRule_3(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(
                m_mul,
                AstConstant("2", 2),
                AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1"))


class Add_OllvmRule_4(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(
                m_mul,
                AstConstant("val_fe"),
                AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1"))


class AddXor_Rule_1(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        candidate.add_constant_leaf("val_2", 2, candidate["x_0"].size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_sub, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(
                m_mul,
                AstConstant("2", 2),
                AstNode(m_or, AstLeaf("x_0"), AstLeaf("bnot_x_1")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_add, AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")), AstConstant("val_2")
        )


class AddXor_Rule_2(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        candidate.add_constant_leaf("val_2", 2, candidate["x_0"].size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_sub, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(
                m_mul,
                AstConstant("2", 2),
                AstNode(m_bnot, AstNode(m_and, AstLeaf("bnot_x_0"), AstLeaf("x_1"))),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_add, AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")), AstLeaf("val_2")
        )
