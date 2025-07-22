from d810.expr.ast import AstLeaf, AstNode
from d810.hexrays.hexrays_helpers import equal_bnot_mop
from d810.optimizers.microcode.instructions.pattern_matching.handler import (
    PatternMatchingRule,
)

from ida_hexrays import *


# GetIdentRule1: ((x_0 & x_1) + (x_0 & ~x_1)) == x_0
class GetIdentRule1(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("bnot_x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_mov, AstLeaf("x_0"))


# GetIdentRule2: ((x_0 & x_1) ^ (x_0 & ~x_1)) == x_0 i
class GetIdentRule2(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_xor,
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(m_and, AstLeaf("x_0"), AstLeaf("bnot_x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_mov, AstLeaf("x_0"))


class GetIdentRule3(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_and, AstLeaf("x_0"), AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1"))
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_mov, AstLeaf("x_0"))
