from d810.expr.ast import AstConstant, AstLeaf, AstNode
from d810.hexrays.hexrays_helpers import (
    AND_TABLE,
    SUB_TABLE,
    equal_bnot_cst,
    equal_bnot_mop,
)
from d810.optimizers.microcode.instructions.pattern_matching.handler import (
    PatternMatchingRule,
)

from ida_hexrays import *


class CstSimplificationRule1(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_and,
            AstNode(m_bnot, AstLeaf("x_0")),
            AstNode(m_xor, AstNode(m_bnot, AstLeaf("x_0")), AstConstant("c_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_xor,
            AstNode(m_and, AstLeaf("x_0"), AstNode(m_bnot, AstConstant("c_1"))),
            AstNode(m_bnot, AstConstant("c_1")),
        )


# This rule is invalid.
# Expression:     (((x_0 ^ c_1_1) & c_2_1) | ((x_0 ^ c_1_2) & c_2_2)) => (x_0 ^ c_res)
# Counterexample: [c_1_1 = 2150373929, c_1_2 = 2144593366, c_2_1 = 4292077526, c_2_2 = 2150373417, c_res = 2147484160, x_0 = 2147484160]
#  - LHS value:    2147483648 (dec: 2147483648)
# - RHS value:    0 (dec: 0)
class CstSimplificationRule2(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_cst(candidate["c_2_1"].mop, candidate["c_2_2"].mop):
            return False
        c_res = (candidate["c_1_1"].value ^ candidate["c_1_2"].value) & candidate[
            "c_2_1"
        ].value
        c_res ^= candidate["c_1_2"].value
        candidate.add_constant_leaf("c_res", c_res, candidate["c_1_1"].size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or,
            AstNode(
                m_and,
                AstNode(m_xor, AstLeaf("x_0"), AstConstant("c_1_1")),
                AstConstant("c_2_1"),
            ),
            AstNode(
                m_and,
                AstNode(m_xor, AstLeaf("x_0"), AstConstant("c_1_2")),
                AstConstant("c_2_2"),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstLeaf("x_0"), AstConstant("c_res"))


class CstSimplificationRule3(PatternMatchingRule):

    def check_candidate(self, candidate):
        c_coeff = candidate["c_1"].value + 1
        c_sub = (candidate["c_1"].value * candidate["c_2"].value) + candidate[
            "c_0"
        ].value
        candidate.add_constant_leaf("c_coeff", c_coeff, candidate["c_1"].size)
        candidate.add_constant_leaf("c_sub", c_sub, candidate["c_2"].size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(m_sub, AstLeaf("x_0"), AstConstant("c_0")),
            AstNode(
                m_mul,
                AstConstant("c_1"),
                AstNode(m_sub, AstLeaf("x_0"), AstConstant("c_2")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_mul, AstConstant("c_coeff"), AstLeaf("x_0")),
            AstConstant("c_sub"),
        )


class CstSimplificationRule4(PatternMatchingRule):

    def check_candidate(self, candidate):
        c_res = SUB_TABLE[candidate["c_1"].size] - candidate["c_1"].value
        candidate.add_constant_leaf("c_res", c_res, candidate["c_1"].size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub, AstLeaf("x_0"), AstNode(m_sub, AstConstant("c_1"), AstLeaf("x_1"))
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_add, AstLeaf("x_0"), AstNode(m_add, AstLeaf("x_1"), AstConstant("c_res"))
        )


class CstSimplificationRule5(PatternMatchingRule):

    def check_candidate(self, candidate):
        return equal_bnot_cst(candidate["c_1"].mop, candidate["c_2"].mop)

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or,
            AstNode(m_and, AstLeaf("x_0"), AstConstant("c_1")),
            AstNode(m_and, AstLeaf("x_1"), AstConstant("c_2")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_xor,
            AstNode(
                m_and,
                AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
                AstConstant("c_1"),
            ),
            AstLeaf("x_1"),
        )


class CstSimplificationRule6(PatternMatchingRule):

    def check_candidate(self, candidate):
        c_res = candidate["c_1"].value & candidate["c_2"].value
        candidate.add_constant_leaf("c_res", c_res, candidate["c_2"].size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_and,
            AstNode(m_xor, AstLeaf("x_0"), AstConstant("c_1")),
            AstConstant("c_2"),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_xor,
            AstNode(m_and, AstLeaf("x_0"), AstConstant("c_2")),
            AstConstant("c_res"),
        )


class CstSimplificationRule7(PatternMatchingRule):

    def check_candidate(self, candidate):
        c_res = candidate["c_1"].value >> candidate["c_2"].value
        candidate.add_constant_leaf("c_res", c_res, candidate["c_1"].size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_shr,
            AstNode(m_and, AstLeaf("x_0"), AstConstant("c_1")),
            AstConstant("c_2"),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_and,
            AstNode(m_shr, AstLeaf("x_0"), AstConstant("c_2")),
            AstConstant("c_res"),
        )


class CstSimplificationRule8(PatternMatchingRule):

    def check_candidate(self, candidate):
        c_res = candidate["c_1"].value & ~candidate["c_2"].value
        if c_res == candidate["c_1"].value:
            return False
        candidate.add_constant_leaf("c_res", c_res, candidate["c_1"].size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or, AstNode(m_and, AstLeaf("x_0"), AstConstant("c_1")), AstConstant("c_2")
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_or,
            AstNode(m_and, AstLeaf("x_0"), AstConstant("c_res")),
            AstConstant("c_2"),
        )


# (x_0 | c_1) & c_2 => (x_0 & (~c_1 & c_2)) ^ (c_1 & c_2)
class CstSimplificationRule9(PatternMatchingRule):

    def check_candidate(self, candidate):
        # c_and = (x_0 & (~c_1 & c_2))
        c_and = (AND_TABLE[candidate["c_1"].size] ^ candidate["c_1"].value) & candidate[
            "c_2"
        ].value
        # c_xor = (c_1 & c_2)
        c_xor = candidate["c_1"].value & candidate["c_2"].value
        candidate.add_constant_leaf("c_and", c_and, candidate["x_0"].size)
        candidate.add_constant_leaf("c_xor", c_xor, candidate["x_0"].size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_and, AstNode(m_or, AstLeaf("x_0"), AstConstant("c_1")), AstConstant("c_2")
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_xor,
            AstNode(m_and, AstLeaf("x_0"), AstConstant("c_and")),
            AstConstant("c_xor"),
        )


class CstSimplificationRule10(PatternMatchingRule):

    def check_candidate(self, candidate):
        if (candidate["c_1"].value & candidate["c_2"].value) != candidate["c_1"].value:
            return False
        c_and = (AND_TABLE[candidate["c_1"].size] ^ candidate["c_1"].value) & candidate[
            "c_2"
        ].value
        candidate.add_constant_leaf("c_and", c_and, candidate["x_0"].size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_and, AstLeaf("x_0"), AstConstant("c_1")),
            AstNode(m_and, AstLeaf("x_0"), AstConstant("c_2")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_neg, AstNode(m_and, AstLeaf("x_0"), AstConstant("c_and")))


class CstSimplificationRule11(PatternMatchingRule):

    def check_candidate(self, candidate):
        c_1_bnot = AND_TABLE[candidate["c_1"].size] ^ candidate["c_1"].value
        c_and = c_1_bnot & candidate["c_2"].value
        candidate.add_constant_leaf("c_1_bnot", c_1_bnot, candidate["c_1"].size)
        candidate.add_constant_leaf("c_and", c_and, candidate["c_1"].size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or,
            AstNode(m_xor, AstNode(m_bnot, AstLeaf("x_0")), AstConstant("c_1")),
            AstNode(m_and, AstLeaf("x_0"), AstConstant("c_2")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_xor,
            AstNode(m_xor, AstLeaf("x_0"), AstConstant("c_1_bnot")),
            AstNode(m_and, AstLeaf("x_0"), AstConstant("c_and")),
        )


class CstSimplificationRule12(PatternMatchingRule):

    def check_candidate(self, candidate):
        c_diff = candidate["c_2"].value - candidate["c_1"].value
        candidate.add_constant_leaf("c_diff", c_diff, candidate["c_1"].size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_sub, AstConstant("c_1"), AstLeaf("x_0")),
            AstNode(
                m_mul,
                AstConstant("2", 2),
                AstNode(m_and, AstNode(m_bnot, AstLeaf("x_0")), AstConstant("c_2")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_sub,
            AstNode(m_xor, AstNode(m_bnot, AstLeaf("x_0")), AstConstant("c_2")),
            AstConstant("c_diff"),
        )


class CstSimplificationRule13(PatternMatchingRule):

    def check_candidate(self, candidate):
        candidate.add_constant_leaf(
            "not_cst_1", ~candidate["cst_1"].value, candidate["cst_1"].size
        )
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_xor,
            AstNode(
                m_and,
                AstConstant("cst_1"),
                AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
            AstLeaf("x_1"),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_xor,
            AstNode(m_and, AstLeaf("x_0"), AstConstant("cst_1")),
            AstNode(m_and, AstLeaf("x_1"), AstConstant("not_cst_1")),
        )


class CstSimplificationRule14(PatternMatchingRule):

    def check_candidate(self, candidate):
        lnot_c_1_value = candidate["c_1"].value ^ AND_TABLE[candidate["c_1"].size]
        tmp = lnot_c_1_value ^ candidate["c_2"].value
        if tmp != 1:
            return False
        # the rule is only correct if ~c_1 is even
        if (lnot_c_1_value & 1) != 0:
            return False
        candidate.add_constant_leaf("val_1", 1, candidate["c_2"].size)
        candidate.add_constant_leaf("lnot_c_1", lnot_c_1_value, candidate["c_1"].size)

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(m_and, AstLeaf("x_0"), AstConstant("c_1")),
            AstConstant("c_2"),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(m_or, AstLeaf("x_0"), AstLeaf("lnot_c_1")),
            AstConstant("val_1"),
        )


class CstSimplificationRule15(PatternMatchingRule):

    def check_candidate(self, candidate):
        # Get the bit-width from one of the operands
        bit_width = candidate["x_0"].size
        c1_val = candidate["c_1"].value
        c2_val = candidate["c_2"].value

        # Condition 1: Individual shifts are sensible
        if c1_val >= bit_width or c2_val >= bit_width:
            return False

        # Condition 2: The sum does not overflow and is also sensible
        c_res_val = c1_val + c2_val
        if c_res_val >= bit_width:
            return False

        candidate.add_constant_leaf("c_res", c_res_val, candidate["c_1"].size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_shr,
            AstNode(m_shr, AstLeaf("x_0"), AstConstant("c_1")),
            AstConstant("c_2"),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_shr, AstLeaf("x_0"), AstConstant("c_res"))


class CstSimplificationRule16(PatternMatchingRule):

    def check_candidate(self, candidate):
        candidate.add_constant_leaf(
            "bnot_c_1",
            candidate["c_1"].value ^ AND_TABLE[candidate["c_1"].size],
            candidate["c_1"].size,
        )
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(m_bnot, AstNode(m_xor, AstLeaf("x_0"), AstConstant("c_1")))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstLeaf("x_0"), AstLeaf("bnot_c_1"))


class CstSimplificationRule17(PatternMatchingRule):

    def check_candidate(self, candidate):
        candidate.add_constant_leaf(
            "bnot_c_1",
            candidate["c_1"].value ^ AND_TABLE[candidate["c_1"].size],
            candidate["c_1"].size,
        )
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(m_bnot, AstNode(m_or, AstLeaf("x_0"), AstConstant("c_1")))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_and, AstNode(m_bnot, AstLeaf("x_0")), AstLeaf("bnot_c_1"))


class CstSimplificationRule18(PatternMatchingRule):

    def check_candidate(self, candidate):
        candidate.add_constant_leaf(
            "bnot_c_1",
            candidate["c_1"].value ^ AND_TABLE[candidate["c_1"].size],
            candidate["c_1"].size,
        )
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(m_bnot, AstNode(m_and, AstLeaf("x_0"), AstConstant("c_1")))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_or, AstNode(m_bnot, AstLeaf("x_0")), AstLeaf("bnot_c_1"))


class CstSimplificationRule19(PatternMatchingRule):

    def check_candidate(self, candidate):
        # Check if the MSB of c_1 is 0. This ensures that (x_0 & c_1) always has MSB=0,
        # making the arithmetic shift (sar) behave identically to a logical shift (shr),
        # which is necessary for the simplification to hold for all x_0.
        msb_mask = 1 << (candidate["c_1"].size - 1)
        if (candidate["c_1"].value & msb_mask) != 0:
            return False
        candidate.add_constant_leaf(
            "c_res",
            candidate["c_1"].value >> candidate["c_2"].value,
            candidate["c_1"].size,
        )
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_sar,
            AstNode(m_and, AstLeaf("x_0"), AstConstant("c_1")),
            AstConstant("c_2"),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_and,
            AstNode(m_shr, AstLeaf("x_0"), AstConstant("c_2")),
            AstConstant("c_res"),
        )


# Found sometimes with OLLVM
class CstSimplificationRule20(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        if candidate["c_and_1"].value & candidate["c_and_2"].value != 0:
            return False
        candidate.add_constant_leaf(
            "c_and_res",
            candidate["c_and_1"].value ^ candidate["c_and_2"].value,
            candidate["c_and_1"].size,
        )
        candidate.add_constant_leaf(
            "c_xor_res",
            candidate["c_and_1"].value ^ candidate["c_xor"].value,
            candidate["c_and_1"].size,
        )
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or,
            AstNode(m_and, AstLeaf("bnot_x_0"), AstConstant("c_and_1")),
            AstNode(
                m_xor,
                AstNode(m_and, AstLeaf("x_0"), AstConstant("c_and_2")),
                AstConstant("c_xor"),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            m_xor,
            AstNode(m_and, AstLeaf("x_0"), AstConstant("c_and_res")),
            AstConstant("c_xor_res"),
        )


# Found sometimes with OLLVM
class CstSimplificationRule21(PatternMatchingRule):

    def check_candidate(self, candidate):
        if not equal_bnot_cst(candidate["c_and"].mop, candidate["bnot_c_and"].mop):
            return False
        if candidate["c_xor_1"].mop.nnn.value & candidate["c_xor_2"].mop.nnn.value != 0:
            return False
        candidate.add_constant_leaf(
            "c_xor_res",
            candidate["c_xor_1"].value ^ candidate["c_xor_2"].value,
            candidate["c_xor_1"].size,
        )
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or,
            AstNode(
                m_xor,
                AstNode(m_and, AstLeaf("x_0"), AstConstant("c_and")),
                AstConstant("c_xor_1"),
            ),
            AstNode(
                m_xor,
                AstNode(m_and, AstLeaf("x_0"), AstConstant("bnot_c_and")),
                AstConstant("c_xor_2"),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstLeaf("x_0"), AstConstant("c_xor_res"))


# Found sometimes with OLLVM
class CstSimplificationRule22(PatternMatchingRule):

    def check_candidate(self, candidate):
        # Condition 1: Check for valid ~x_0
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        # Condition 2: Check for valid ~c_and
        if not equal_bnot_cst(candidate["c_and"].mop, candidate["bnot_c_and"].mop):
            return False

        c_and_val = candidate["c_and"].value
        bnot_c_and_val = candidate["bnot_c_and"].value  # This is ~c_and_val
        c_xor_1_val = candidate["c_xor_1"].value
        c_xor_2_val = candidate["c_xor_2"].value

        # Condition 3: c_xor_1 and c_xor_2 must be disjoint
        if (c_xor_1_val & c_xor_2_val) != 0:
            return False

        # Condition 4: c_xor_1 must "live" entirely within the c_and mask
        if (c_xor_1_val & bnot_c_and_val) != 0:  # Same as c_xor_1 & ~c_and
            return False

        # Condition 5: c_xor_2 must "live" entirely within the ~c_and mask
        if (c_xor_2_val & c_and_val) != 0:
            return False

        # If all conditions pass, define the resulting constant
        candidate.add_constant_leaf(
            "c_xor_res",
            c_xor_1_val ^ c_xor_2_val ^ bnot_c_and_val,
            candidate["c_xor_1"].size,
        )
        return True

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_or,
            AstNode(
                m_xor,
                AstNode(m_and, AstLeaf("x_0"), AstConstant("c_and")),
                AstConstant("c_xor_1"),
            ),
            AstNode(
                m_xor,
                AstNode(m_and, AstLeaf("bnot_x_0"), AstConstant("bnot_c_and")),
                AstConstant("c_xor_2"),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_xor, AstLeaf("x_0"), AstConstant("c_xor_res"))
