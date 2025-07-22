from d810.expr.ast import AstConstant, AstLeaf, AstNode
from d810.hexrays.hexrays_helpers import SUB_TABLE, equal_bnot_cst, equal_bnot_mop
from d810.optimizers.microcode.instructions.pattern_matching.handler import (
    PatternMatchingRule,
)

from ida_hexrays import *


class Xor_HackersDelightRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


class Xor_HackersDelightRule_2(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(
                m_mul,
                AstConstant("2", 2),
                AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
            AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


class Xor_HackersDelightRule_3(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(
                m_mul,
                AstConstant("2", 2),
                AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


class Xor_HackersDelightRule_4(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(
                m_sub,
                AstNode(m_sub, AstLeaf("x_0"), AstLeaf("x_1")),
                AstNode(
                    m_mul,
                    AstConstant("2", 2),
                    AstNode(m_or, AstLeaf("x_0"), AstNode(m_bnot, AstLeaf("x_1"))),
                ),
            ),
            AstConstant("2", 2),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


class Xor_HackersDelightRule_5(PatternMatchingRule):
    FUZZ_PATTERN = False
    PATTERNS = [
        AstNode(
            m_sub,
            AstLeaf("x_0"),
            AstNode(
                m_sub,
                AstNode(
                    m_mul,
                    AstConstant("2", 2),
                    AstNode(m_and, AstLeaf("x_1"), AstLeaf("x_0")),
                ),
                AstLeaf("x_1"),
            ),
        )
    ]

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstLeaf("x_0"),
            AstNode(
                m_sub,
                AstNode(
                    m_mul,
                    AstConstant("2", 2),
                    AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
                ),
                AstLeaf("x_1"),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


class Xor_MbaRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstLeaf("x_0"),
            AstNode(
                m_sub,
                AstNode(
                    m_mul,
                    AstConstant("2", 2),
                    AstNode(
                        m_and,
                        AstLeaf("x_1"),
                        AstNode(m_bnot, AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))),
                    ),
                ),
                AstLeaf("x_1"),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


class Xor_MbaRule_2(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstLeaf("x_0"),
            AstNode(
                m_sub,
                AstNode(
                    m_mul,
                    AstConstant("2", 2),
                    AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
                ),
                AstLeaf("x_1"),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


class Xor_MbaRule_3(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstLeaf("x_0"),
            AstNode(
                m_mul,
                AstConstant("2", 2),
                AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_sub, AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")), AstLeaf("x_1")
        )


class Xor_FactorRule_1(PatternMatchingRule):

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
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("bnot_x_1")),
            AstNode(m_and, AstLeaf("bnot_x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


class Xor_FactorRule_2(PatternMatchingRule):

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
            AstNode(m_and, AstLeaf("bnot_x_0"), AstLeaf("x_1")),
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("bnot_x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


class Xor_FactorRule_3(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_xor,
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


class Xor_SpecialConstantRule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(m_sub, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(
                m_mul,
                AstConstant("2", 2),
                AstNode(m_and, AstNode(m_bnot, AstLeaf("x_0")), AstLeaf("x_1")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


# This pattern matches the valid MBA identity: (x + y) + (-2 * (x & y))
class Xor_SpecialConstantRule_2(PatternMatchingRule):

    def check_candidate(self, candidate):
        # Get the size (in bytes) of the constant operand
        operand_size = candidate["c_minus_2"].size

        # Check if the constant's value is exactly -2 for its bit-width
        if candidate["c_minus_2"].value != SUB_TABLE[operand_size] - 2:
            return False

        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1")),  # (x_0 + x_1)
            AstNode(
                m_mul,
                AstConstant("c_minus_2"),  # Use a symbolic constant
                AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


class Xor1_MbaRule_1(PatternMatchingRule):

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_1", 1, candidate.size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(m_bnot, AstLeaf("x_0")),
            AstNode(
                m_or,
                AstNode(m_mul, AstConstant("2", 2), AstLeaf("x_0")),
                AstConstant("2", 2),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstLeaf("x_0"), AstConstant("val_1"))


class Xor_Rule_1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or,
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_bnot, AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1"))),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstLeaf("x_0"), AstNode(m_bnot, AstLeaf("x_1")))


# Found sometimes with OLLVM
class Xor_Rule_2(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or,
            AstNode(
                m_and,
                AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_2")),
                AstNode(m_xor, AstLeaf("x_1"), AstLeaf("bnot_x2")),
            ),
            AstNode(
                m_and,
                AstNode(m_xor, AstLeaf("x_0"), AstLeaf("bnot_x2")),
                AstNode(m_xor, AstLeaf("x_1"), AstLeaf("x_2")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


# Found sometimes with OLLVM
class Xor_Rule_3(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or,
            AstNode(
                m_and,
                AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_2")),
                AstNode(m_xor, AstLeaf("x_1"), AstLeaf("x_2")),
            ),
            AstNode(
                m_and,
                AstNode(m_xor, AstLeaf("x_0"), AstLeaf("bnot_x2")),
                AstNode(m_xor, AstLeaf("x_1"), AstLeaf("bnot_x2")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstNode(m_bnot, AstLeaf("x_0")), AstLeaf("x_1"))


class Xor_Rule_4(PatternMatchingRule):

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
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("bnot_x_1")),
            AstNode(m_and, AstLeaf("bnot_x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


class Xor_Rule_4_WithXdu(PatternMatchingRule):

    def check_candidate(self, candidate):
        if candidate["x_0"].mop.t != mop_d:
            return False
        if candidate["x_0"].mop.d.opcode != m_xdu:
            return False
        return equal_bnot_cst(
            candidate["c_1"].mop,
            candidate["bnot_c_1"].mop,
            mop_size=candidate["x_0"].mop.d.l.size,
        )

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or,
            AstNode(m_and, AstLeaf("x_0"), AstConstant("bnot_c_1")),
            AstNode(m_and, AstNode(m_bnot, AstLeaf("x_0")), AstConstant("c_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstLeaf("x_0"), AstLeaf("c_1"))


class XorAlmost_Rule_1(PatternMatchingRule):

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_2", 2, candidate.size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(
                m_mul,
                AstConstant("2", 2),
                AstNode(
                    m_or,
                    AstLeaf("x_0"),
                    AstNode(m_sub, AstLeaf("x_1"), AstConstant("1", 1)),
                ),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(m_xor, AstLeaf("x_0"), AstNode(m_neg, AstLeaf("x_1"))),
            AstLeaf("val_2"),
        )


class Xor_NestedStuff(PatternMatchingRule):
    FUZZ_PATTERN = False

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(
                m_add, AstNode(m_add, AstLeaf("x_9"), AstLeaf("x_10")), AstLeaf("x_11")
            ),
            AstNode(
                m_add,
                AstLeaf("x_14"),
                AstNode(
                    m_mul,
                    AstConstant("2", 2),
                    AstNode(
                        m_and,
                        AstLeaf("x_10"),
                        AstNode(
                            m_sub,
                            AstNode(m_add, AstLeaf("x_9"), AstLeaf("x_11")),
                            AstLeaf("x_14"),
                        ),
                    ),
                ),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_xor,
            AstLeaf("x_10"),
            AstNode(
                m_sub, AstNode(m_add, AstLeaf("x_9"), AstLeaf("x_11")), AstLeaf("x_14")
            ),
        )
