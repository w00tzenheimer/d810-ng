from d810.expr.ast import AstConstant, AstLeaf, AstNode
from d810.hexrays.hexrays_helpers import equal_bnot_mop
from d810.optimizers.microcode.instructions.pattern_matching.handler import (
    PatternMatchingRule,
)

from ida_hexrays import *


# Pattern 1: ~(enc[i] ^ ((i - 0x1D) ^ 0x1C)) == enc[i] ^ (i - 0x1D) ^ 0xE3
class Xor_Hodur_1(PatternMatchingRule):
    PATTERN = AstNode(
        m_bnot,
        AstNode(m_xor, AstLeaf("x_0"), AstNode(m_xor, AstLeaf("x_1"), AstLeaf("x_2"))),
    )
    REPLACEMENT_PATTERN = AstNode(
        m_xor,
        AstLeaf("x_0"),
        AstNode(m_xor, AstLeaf("x_1"), AstNode(m_bnot, AstLeaf("x_2"))),
    )


# Pattern 2: enc[i] ^ 0x19 ^ ((0x1C - i) & 0xFA) ^ ((i - 0x1D) & 5)
#         == enc[i] ^ 0x19 ^ (-(i - 0x1D + 1) & 0xFA) ^ ((i - 0x1D) & 5)
#         == enc[i] ^ 0x19 ^ (~(i - 0x1D) & 0xFA) ^ ((i - 0x1D) & 5)
#         == enc[i] ^ 0x19 ^ ~((i - 0x1D) ^ 5)
#         == enc[i] ^ 0x19 ^ (i - 0x1D) ^ ~5
#         == enc[i] ^ (i - 0x1D) ^ 0xE3
class Bnot_Hodur_1(PatternMatchingRule):
    PATTERN = AstNode(
        m_xor,
        AstNode(
            m_and, AstNode(m_sub, AstLeaf("x_0"), AstLeaf("x_1")), AstLeaf("bnot_x_2")
        ),
        AstNode(m_and, AstNode(m_sub, AstLeaf("x_1"), AstLeaf("x_3")), AstLeaf("x_2")),
    )
    REPLACEMENT_PATTERN = AstNode(
        m_bnot,
        AstNode(m_xor, AstNode(m_sub, AstLeaf("x_1"), AstLeaf("x_3")), AstLeaf("x_2")),
    )

    def check_candidate(self, candidate):
        if (candidate["x_2"].mop is None) or (candidate["bnot_x_2"].mop is None):
            return False
        if not equal_bnot_mop(candidate["x_2"].mop, candidate["bnot_x_2"].mop):
            return False
        if (candidate["x_0"].mop is None) or (candidate["x_3"].mop is None):
            return False
        if (candidate["x_0"].mop.t != mop_n) or (candidate["x_3"].mop.t != mop_n):
            return False
        if (candidate["x_0"].mop.nnn is None) or (candidate["x_3"].mop.nnn is None):
            return False
        if candidate["x_0"].mop.nnn.value + 1 != candidate["x_3"].mop.nnn.value:
            return False
        return True


# Pattern 3: (~enc[i] & 0xE3 | enc[i] & 4 | ~enc[i] & 0x18) ^ (i - 0x1D) ^ 0x18;
#         == (~enc & 0xE3 | enc & 4 | ~enc & 0x18) ^ (i - 0x1D) ^ 0x18
#         == (~enc & (0xE3 | 0x18) | enc & 4) ^ (i - 0x1D) ^ 0x18
#         == (enc ^ 0xFB) ^ (i - 0x1D) ^ 0x18
#         == enc ^ (i - 0x1D) ^ 0xE3
class Or_Hodur_1(PatternMatchingRule):
    PATTERN = AstNode(
        m_or,
        AstNode(
            m_or,
            AstNode(m_and, AstNode(m_bnot, AstLeaf("x_0")), AstConstant("c_0")),
            AstNode(m_and, AstLeaf("x_0"), AstConstant("c_1")),
        ),
        AstNode(m_and, AstNode(m_bnot, AstLeaf("x_0")), AstConstant("c_2")),
    )
    REPLACEMENT_PATTERN = AstNode(
        m_or,
        AstNode(
            m_and,
            AstNode(m_bnot, AstLeaf("x_0")),
            AstNode(m_or, AstConstant("c_0"), AstConstant("c_2")),
        ),
        AstNode(m_and, AstLeaf("x_0"), AstConstant("c_1")),
    )


# Pattern 4: x ^ ~y == ~(x ^ y) then Xor_FactorRule_1
class Or_Hodur_2(PatternMatchingRule):
    PATTERN = AstNode(
        m_or,
        AstNode(
            m_and, AstLeaf("x_0"), AstNode(m_xor, AstLeaf("x_1"), AstConstant("c_0"))
        ),
        AstNode(
            m_and,
            AstNode(m_xor, AstLeaf("x_1"), AstConstant("bnot_c_0")),
            AstNode(m_bnot, AstLeaf("x_0")),
        ),
    )
    REPLACEMENT_PATTERN = AstNode(
        m_xor, AstLeaf("x_0"), AstNode(m_xor, AstLeaf("x_1"), AstConstant("bnot_c_0"))
    )

    def check_candidate(self, candidate):
        if (candidate["c_0"].mop is None) or (candidate["bnot_c_0"].mop is None):
            return False
        if not equal_bnot_mop(candidate["c_0"].mop, candidate["bnot_c_0"].mop):
            return False
        return True


# Pattern 5: x ^ (y - 0x1d) ^ 0xe3 == x ^ (y + 0xe3) ^ 0xe3
class Xor_Hodur_2(PatternMatchingRule):
    """
    PATTERN = AstNode(m_stx,
                      AstNode(m_xor,
                              AstNode(m_sub,
                                      AstLeaf("x_0"),
                                      AstConstant("c_0")),
                              AstNode(m_xor,
                                      AstLeaf("x_1"),
                                      AstConstant("c_1"))),
                      #AstLeaf("sel"),
                      AstLeaf("off"))
    REPLACEMENT_PATTERN = AstNode(m_stx,
                                  AstNode(m_xor,
                                          AstNode(m_add,
                                                  AstLeaf("x_0"),
                                                  AstConstant("c_1_dup")),
                                          AstNode(m_xor,
                                                  AstLeaf("x_1"),
                                                  AstConstant("c_1"))),
                                  #AstLeaf("sel"),
                                  AstLeaf("off"))
    """

    PATTERN = AstNode(
        m_xor,
        AstNode(m_sub, AstLeaf("x_0"), AstConstant("c_0")),
        AstNode(m_xor, AstLeaf("x_1"), AstConstant("c_1")),
    )
    REPLACEMENT_PATTERN = AstNode(
        m_xor,
        AstNode(m_add, AstLeaf("x_0"), AstConstant("c_1")),
        AstNode(m_xor, AstLeaf("x_1"), AstConstant("c_1")),
    )

    # def __init__(self):
    #    super().__init__()
    #    self.maturities = [MMAT_GLBOPT1] # Avoid matching in low maturity levels

    def check_candidate(self, candidate):
        # if candidate["x_1"].mop.t != mop_d:
        #    return False
        if (candidate["c_0"].value is None) or (candidate["c_1"].value is None):
            return False
        if (candidate["c_0"].value + candidate["c_1"].value) != 256:
            return False

        # c_1_dup_mop = mop_t()
        # c_1_dup_mop.make_number(candidate["c_1"].value, candidate.size)
        # candidate.add_leaf("c_1_dup", c_1_dup_mop)
        return True
