from d810.expr.ast import AstConstant, AstLeaf, AstNode
from d810.hexrays.hexrays_helpers import SUB_TABLE, equal_bnot_mop
from d810.optimizers.instructions.pattern_matching.handler import PatternMatchingRule

from ida_hexrays import *


class Sub_HackersDelightRule_1(PatternMatchingRule):
    PATTERN = AstNode(
        m_add,
        AstLeaf("x_0"),
        AstNode(m_add, AstNode(m_bnot, AstLeaf("x_1")), AstConstant("1", 1)),
    )
    REPLACEMENT_PATTERN = AstNode(m_sub, AstLeaf("x_0"), AstLeaf("x_1"))


class Sub_HackersDelightRule_2(PatternMatchingRule):
    PATTERN = AstNode(
        m_sub,
        AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
        AstNode(
            m_mul,
            AstConstant("2", 2),
            AstNode(m_and, AstNode(m_bnot, AstLeaf("x_0")), AstLeaf("x_1")),
        ),
    )
    REPLACEMENT_PATTERN = AstNode(m_sub, AstLeaf("x_0"), AstLeaf("x_1"))


class Sub_HackersDelightRule_3(PatternMatchingRule):
    PATTERN = AstNode(
        m_sub,
        AstNode(m_and, AstLeaf("x_0"), AstLeaf("bnot_x_1")),
        AstNode(m_and, AstLeaf("bnot_x_0"), AstLeaf("x_1")),
    )
    REPLACEMENT_PATTERN = AstNode(m_sub, AstLeaf("x_0"), AstLeaf("x_1"))

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True


class Sub_HackersDelightRule_4(PatternMatchingRule):
    PATTERN = AstNode(
        m_sub,
        AstNode(
            m_mul,
            AstConstant("2", 2),
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("bnot_x_1")),
        ),
        AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
    )
    REPLACEMENT_PATTERN = AstNode(m_sub, AstLeaf("x_0"), AstLeaf("x_1"))

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True


class Sub1_FactorRule_1(PatternMatchingRule):
    PATTERN = AstNode(
        m_sub,
        AstNode(m_sub, AstNode(m_neg, AstLeaf("x_0")), AstConstant("1", 1)),
        AstNode(m_mul, AstConstant("c_minus_2"), AstLeaf("x_0")),
    )
    REPLACEMENT_PATTERN = AstNode(m_sub, AstLeaf("x_0"), AstConstant("val_1"))

    def check_candidate(self, candidate):
        if candidate["c_minus_2"].value != SUB_TABLE[candidate["c_minus_2"].size] - 2:
            return False
        candidate.add_constant_leaf("val_1", 1, candidate["x_0"].size)
        return True


class Sub1_FactorRule_2(PatternMatchingRule):
    PATTERN = AstNode(
        m_add,
        AstNode(m_mul, AstConstant("2", 2), AstLeaf("x_0")),
        AstNode(m_bnot, AstLeaf("x_0")),
    )

    REPLACEMENT_PATTERN = AstNode(m_sub, AstLeaf("x_0"), AstConstant("1", 1))


class Sub1Add_HackersDelightRule_1(PatternMatchingRule):
    PATTERN = AstNode(
        m_add,
        AstNode(
            m_mul, AstConstant("2", 2), AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1"))
        ),
        AstNode(m_xor, AstLeaf("x_0"), AstLeaf("bnot_x_1")),
    )
    REPLACEMENT_PATTERN = AstNode(
        m_sub, AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1")), AstConstant("val_1")
    )

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        candidate.add_constant_leaf("val_1", 1, candidate["x_1"].size)
        return True


class Sub1And_HackersDelightRule_1(PatternMatchingRule):
    PATTERN = AstNode(
        m_add, AstNode(m_or, AstLeaf("x_0"), AstLeaf("bnot_x_1")), AstLeaf("x_1")
    )

    REPLACEMENT_PATTERN = AstNode(
        m_sub, AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")), AstConstant("val_1")
    )

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        candidate.add_constant_leaf("val_1", 1, candidate["x_0"].size)
        return True


class Sub1Or_MbaRule_1(PatternMatchingRule):
    PATTERN = AstNode(
        m_add,
        AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1")),
        AstNode(m_bnot, AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1"))),
    )
    REPLACEMENT_PATTERN = AstNode(
        m_sub, AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")), AstConstant("val_1")
    )

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_1", 1, candidate.size)
        return True


class Sub1And1_MbaRule_1(PatternMatchingRule):
    PATTERN = AstNode(
        m_add,
        AstNode(m_or, AstNode(m_bnot, AstLeaf("x_0")), AstConstant("1", 1)),
        AstLeaf("x_0"),
    )
    REPLACEMENT_PATTERN = AstNode(
        m_sub,
        AstNode(m_and, AstLeaf("x_0"), AstConstant("val_1_1")),
        AstConstant("val_1_2"),
    )

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_1_1", 1, candidate["x_0"].size)
        candidate.add_constant_leaf("val_1_2", 1, candidate["x_0"].size)
        return True
