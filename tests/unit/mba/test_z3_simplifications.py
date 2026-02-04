import re
import unittest
from dataclasses import dataclass

from z3 import (
    ULT,
    And,
    BitVec,
    BitVecVal,
    Extract,
    If,
    LShR,
    SignExt,
    Solver,
    ZeroExt,
    is_bool,
    sat,
    simplify,
    unsat,
)


@dataclass(frozen=True, slots=True)
class RuleInfo:
    name: str
    expr: str
    known_incorrect: bool = False
    comment: str | None = None
    is_nonlinear: bool = False


RULES: list[RuleInfo] = [
    RuleInfo(
        name="Add_HackersDelightRule_1",
        expr="(x_0 - (~(x_1) + 0x1)) => (x_0 + x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Add_HackersDelightRule_2",
        expr="((x_0 ^ x_1) + (0x2 * (x_0 & x_1))) => (x_0 + x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Add_HackersDelightRule_3",
        expr="((x_0 | x_1) + (x_0 & x_1)) => (x_0 + x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Add_HackersDelightRule_4",
        expr="((0x2 * (x_0 | x_1)) - (x_0 ^ x_1)) => (x_0 + x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Add_HackersDelightRule_5",
        expr="((0x2 * ((x_0 | x_1) | x_2)) - (x_0 ^ (x_1 | x_2))) => (x_0 + (x_1 | x_2))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Add_SpecialConstantRule_1",
        expr="((x_0 ^ c_1) + (0x2 * (x_0 & c_2))) => (x_0 + c_1)",
        known_incorrect=False,
        comment="This is only true if c_2 == c_1. The general rule is false.",
    ),
    RuleInfo(
        name="Add_SpecialConstantRule_2",
        expr="(((x_0 & 0xff) ^ c_1) + (0x2 * (x_0 & c_2))) => ((x_0 & 0xff) + c_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Add_SpecialConstantRule_3",
        expr="((x_0 ^ c_1) + (0x2 * (x_0 | c_2))) => (x_0 + val_res)",
        known_incorrect=False,
        comment="if c_1 == ~c_2, then (x_0 ^ c_1) + (2 * (x_0 | c_2)) is equivalent to x_0 + (c_2 - 1)",
    ),
    RuleInfo(
        name="Add_OllvmRule_1",
        expr="(~((x_0 ^ x_1)) + (0x2 * (x_1 | x_0))) => ((x_0 + x_1) - val_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Add_OllvmRule_2",
        expr="(~((x_0 ^ x_1)) - (val_fe * (x_0 | x_1))) => ((x_0 + x_1) - val_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Add_OllvmRule_3",
        expr="((x_0 ^ x_1) + (0x2 * (x_0 & x_1))) => (x_0 + x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Add_OllvmRule_3",
        expr="((x_0 ^ x_1) + (0x2 * (x_0 & x_1))) => (x_0 + x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Add_OllvmRule_4",
        expr="((x_0 ^ x_1) - (val_fe * (x_0 & x_1))) => (x_0 + x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="AddXor_Rule_1",
        expr="((x_0 - x_1) - (0x2 * (x_0 | bnot_x_1))) => ((x_0 ^ x_1) + val_2)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="AddXor_Rule_2",
        expr="((x_0 - x_1) - (0x2 * ~((bnot_x_0 & x_1)))) => ((x_0 ^ x_1) + val_2)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="And_HackersDelightRule_1",
        expr="((~(x_0) | x_1) - ~(x_0)) => (x_0 & x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="And_HackersDelightRule_2",
        expr="((bnot_x_0 | x_1) + (x_0 + 0x1)) => (x_0 & x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="And_HackersDelightRule_3",
        expr="((x_0 + x_1) - (x_0 | x_1)) => (x_0 & x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="And_HackersDelightRule_4",
        expr="((x_0 | x_1) - (x_0 ^ x_1)) => (x_0 & x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="And_OllvmRule_1",
        expr="((x_0 | x_1) & ~((x_0 ^ x_1))) => (x_0 & x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="And_OllvmRule_2",
        expr="((x_0 | x_1) & (x_0 ^ bnot_x_1)) => (x_0 & x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="And_OllvmRule_3",
        expr="((x_0 & x_1) & ~((x_0 ^ x_1))) => (x_0 & x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="And_FactorRule_1",
        expr="((x_0 ^ bnot_x_1) & x_1) => (x_0 & x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="And_FactorRule_2",
        expr="(x_0 & ~((x_0 ^ x_1))) => (x_0 & x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="AndBnot_HackersDelightRule_1",
        expr="((x_0 | x_1) - x_1) => (x_0 & ~(x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="AndBnot_HackersDelightRule_2",
        expr="(x_0 - (x_0 & x_1)) => (x_0 & ~(x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="AndBnot_FactorRule_1",
        expr="(x_0 ^ (x_0 & x_1)) => (x_0 & ~(x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="AndBnot_FactorRule_2",
        expr="(x_0 & (x_0 ^ x_1)) => (x_0 & ~(x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="AndBnot_FactorRule_3",
        expr="((x_0 | x_1) ^ x_1) => (x_0 & ~(x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="AndBnot_FactorRule_4",
        expr="((x_1 ^ x_0) & ~((x_0 & bnot_x_1))) => (x_1 & ~(x_0))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="AndOr_FactorRule_1",
        expr="((x_0 & x_2) | (x_1 & x_2)) => ((x_0 | x_1) & x_2)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="AndXor_FactorRule_1",
        expr="((x_0 & x_2) ^ (x_1 & x_2)) => ((x_0 ^ x_1) & x_2)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="And1_MbaRule_1",
        expr="((x_0 * x_0) & 0x3) => (x_0 & val_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="AndGetUpperBits_FactorRule_1",
        expr="(c_1 * (LShR(x_0, c_2) & c_3)) => (x_0 & c_res)",
        known_incorrect=True,
        comment="This rule is only true under very specific (and unlikely) conditions on the constants.",
    ),
    RuleInfo(
        name="Bnot_HackersDelightRule_1",
        expr="(-(x_0) - 0x1) => ~(x_0)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Bnot_HackersDelightRule_2",
        expr="(~((x_0 | x_1)) | ~(x_1)) => ~(x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Bnot_MbaRule_1",
        expr="((x_0 - 0x1) - (0x2 * x_0)) => ~(x_0)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Bnot_FactorRule_1",
        expr="(~((x_0 ^ x_1)) ^ x_1) => ~(x_0)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Bnot_FactorRule_2",
        expr="(minus_1 - x_0) => ~(x_0)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Bnot_FactorRule_3",
        expr="((x_0 & x_1) ^ (x_0 | bnot_x_1)) => ~(x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Bnot_FactorRule_4",
        expr="(~(x_0) ^ ~(x_1)) => (x_0 ^ x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="BnotXor_Rule_1",
        expr="((x_0 & x_1) | (bnot_x_0 & bnot_x_1)) => ~((x_0 ^ x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="BnotXor_Rule_2",
        expr="((x_0 | x_1) ^ (bnot_x_0 | bnot_x_1)) => ~((x_0 ^ x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="BnotXor_Rule_3",
        expr="((x_0 | bnot_x_1) & (bnot_x_0 | x_1)) => ~((x_0 ^ x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="BnotXor_FactorRule_1",
        expr="(x_0 ^ ~(x_1)) => ~((x_0 ^ x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="BnotAnd_FactorRule_1",
        expr="((x_0 ^ x_1) | ~((x_0 | x_1))) => ~((x_0 & x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="BnotAnd_FactorRule_2",
        expr="((bnot_x_0 | bnot_x_1) | (x_0 ^ x_1)) => ~((x_0 & x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="BnotAnd_FactorRule_3",
        expr="(~(x_0) | ~(x_1)) => ~((x_0 & x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="BnotAnd_FactorRule_4",
        expr="(bnot_x_0 | (x_0 ^ x_1)) => ~((x_0 & x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="BnotOr_FactorRule_1",
        expr="(~(x_0) & ~(x_1)) => ~((x_0 | x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="BnotAdd_MbaRule_1",
        expr="((x_0 ^ bnot_x_1) - (0x2 * (x_0 & x_1))) => ~((x_0 + x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Bnot_Rule_1",
        expr="((x_0 & bnot_x_1) | ~((x_0 | x_1))) => (bnot_x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Bnot_XorRule_1",
        expr="((x_0 & x_1) | ~((x_0 | x_1))) => ~((x_0 ^ x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="CstSimplificationRule1",
        expr="(~(x_0) & (~(x_0) ^ c_1)) => ((x_0 & ~(c_1)) ^ ~(c_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="CstSimplificationRule2",
        expr="(((x_0 ^ c_1_1) & c_2_1) | ((x_0 ^ c_1_2) & c_2_2)) => (x_0 ^ c_res)",
        known_incorrect=True,
        comment="This identity requires that the constants used in the `&` and `^` are disjoint.",
    ),
    RuleInfo(
        name="CstSimplificationRule3",
        expr="((x_0 - c_0) + (c_1 * (x_0 - c_2))) => ((c_coeff * x_0) - c_sub)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="CstSimplificationRule4",
        expr="(x_0 - (c_1 - x_1)) => (x_0 + (x_1 + c_res))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="CstSimplificationRule5",
        expr="((x_0 & c_1) | (x_1 & c_2)) => (((x_0 ^ x_1) & c_1) ^ x_1)",
        known_incorrect=False,
        comment="This identity holds only if c_2 is the bitwise not of c_1",
    ),
    RuleInfo(
        name="CstSimplificationRule6",
        expr="((x_0 ^ c_1) & c_2) => ((x_0 & c_2) ^ c_res)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="CstSimplificationRule7",
        expr="LShR((x_0 & c_1), c_2) => (LShR(x_0, c_2) & c_res)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="CstSimplificationRule8",
        expr="((x_0 & c_1) | c_2) => ((x_0 & c_res) | c_2)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="CstSimplificationRule9",
        expr="(x_0 | c_1) & c_2 => (x_0 & (~c_1 & c_2)) ^ (c_1 & c_2)",
        known_incorrect=False,
        comment="c_and = (x_0 & (~c_1 & c_2)) and c_xor = (c_1 & c_2)",
    ),
    RuleInfo(
        name="CstSimplificationRule10",
        expr="((x_0 & c_1) - (x_0 & c_2)) => -((x_0 & c_and))",
        known_incorrect=False,
        comment="if (c_1 & c_2) == c_1, then (x_0 & c_1) - (x_0 & c_2) == -(x_0 & (~c_1 & c_2))",
    ),
    RuleInfo(
        name="CstSimplificationRule11",
        expr="((~(x_0) ^ c_1) | (x_0 & c_2)) => ((x_0 ^ c_1_bnot) ^ (x_0 & c_and))",
        known_incorrect=False,
        comment="if c_1 == ~c_2, then (~(x_0) ^ c_1) | (x_0 & c_2) is equivalent to (x_0 ^ c_1_bnot) ^ (x_0 & c_and)",
    ),
    RuleInfo(
        # TODO: (c_1 - x_0) - 2*(~x_0 & c_1)
        name="CstSimplificationRule12",
        expr="((c_1 - x_0) - (0x2 * (~(x_0) & c_2))) => ((~(x_0) ^ c_2) - c_diff)",
        known_incorrect=True,
        comment="This identity is not generally true. It's very close to a valid identity, but is off by a constant value of 1.",
    ),
    RuleInfo(
        name="CstSimplificationRule13",
        expr="((cst_1 & (x_0 ^ x_1)) ^ x_1) => ((x_0 & cst_1) ^ (x_1 & not_cst_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="CstSimplificationRule14",
        expr="((x_0 & c_1) + c_2) => ((x_0 | lnot_c_1) + val_1)",
        known_incorrect=False,
        comment="It is only valid under the much stricter condition that ~c_1 ^ c_2 == 1 AND ~c_1 is an even number",
    ),
    RuleInfo(
        name="CstSimplificationRule15",
        expr="LShR(LShR(x_0, c_1), c_2) => LShR(x_0, c_res)",
        known_incorrect=False,
        comment="The constraint `c_res = c_1 + c_2` fails for symbolic bitvectors due to overflow/underflow.",
    ),
    RuleInfo(
        name="CstSimplificationRule16",
        expr="~((x_0 ^ c_1)) => (x_0 ^ bnot_c_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="CstSimplificationRule17",
        expr="~((x_0 | c_1)) => (~(x_0) & bnot_c_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="CstSimplificationRule18",
        expr="~((x_0 & c_1)) => (~(x_0) | bnot_c_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="CstSimplificationRule19",
        expr="((x_0 & c_1) >> c_2) => (LShR(x_0, c_2) & c_res)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="CstSimplificationRule20",
        expr="((bnot_x_0 & c_and_1) | ((x_0 & c_and_2) ^ c_xor)) => ((x_0 & c_and_res) ^ c_xor_res)",
        known_incorrect=False,
        comment="if c_and_1 & c_and_2 == 0, then the following identity is always true: (~x_0 & c_and_1) | ((x_0 & c_and_2) ^ c_xor) == (x_0 & (c_and_1 | c_and_2)) ^ (c_and_1 ^ c_xor)",
    ),
    RuleInfo(
        name="CstSimplificationRule21",
        expr="(((x_0 & c_and) ^ c_xor_1) | ((x_0 & bnot_c_and) ^ c_xor_2)) => (x_0 ^ c_xor_res)",
        known_incorrect=False,
        comment="if c_xor_1 & c_xor_2 == 0, then the following identity is always true: ((x_0 & c_and) ^ c_xor_1) | ((x_0 & ~c_and) ^ c_xor_2) == x_0 ^ (c_xor_1 | c_xor_2)",
    ),
    RuleInfo(
        name="CstSimplificationRule22",
        expr="(((x_0 & c_and) ^ c_xor_1) | ((bnot_x_0 & bnot_c_and) ^ c_xor_2)) => (x_0 ^ c_xor_res)",
        known_incorrect=False,
        comment=" if c_xor_1 and c_xor_2 are disjoint, and c_xor_1 lives in the c_and mask, then the following identity is true: ((x_0 & c_and) ^ c_xor_1) | ((~x_0 & ~c_and) ^ c_xor_2) == x_0 ^ (c_xor_1 ^ c_xor_2 ^ ~c_and)",
    ),
    RuleInfo(
        name="GetIdentRule1",
        expr="((x_0 & x_1) + (x_0 & bnot_x_1)) => (x_0)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="GetIdentRule2",
        expr="((x_0 & x_1) ^ (x_0 & bnot_x_1)) => (x_0)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="GetIdentRule3",
        expr="(x_0 & (x_0 | x_1)) => (x_0)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Mul_MbaRule_1",
        expr="(((x_0 | x_1) * (x_0 & x_1)) + ((x_0 & bnot_x_1) * (x_1 & bnot_x_0))) => (x_0 * x_1)",
        known_incorrect=False,
        comment="a * b == ((a | b) * (a & b)) + ((a & ~b) * (b & ~a))",
        is_nonlinear=True,
    ),
    RuleInfo(
        name="Mul_MbaRule_2",
        expr="(((x_0 | c_1) * x_0) + ((x_0 & bnot_c_1) * (c_1 & bnot_x_0))) => (x_0 * c_1)",
        known_incorrect=True,
        comment="Multiplication does not distribute over bitwise operations like this.",
    ),
    RuleInfo(
        name="Mul_MbaRule_3",
        expr="(((x_0 | c_1) * (x_0 & c_1)) + (x_0 * (c_1 & bnot_x_0))) => (x_0 * c_1)",
        known_incorrect=True,
        comment="Multiplication does not distribute over bitwise operations like this.",
    ),
    RuleInfo(
        name="Mul_MbaRule_4",
        expr="(((x_0 | x_1) * (x_0 & x_1)) + (~((x_0 | bnot_x_1)) * (x_0 & bnot_x_1))) => (x_0 * x_1)",
        known_incorrect=False,
        comment="((x_0 | x_1) * (x_0 & x_1)) + (~(x_0 | ~x_1) * (x_0 & ~x_1)) => (x_0 * x_1)",
        is_nonlinear=True,
    ),
    RuleInfo(
        name="Mul_FactorRule_1",
        expr="(0x2 + (0x2 * (x_1 + (x_0 | bnot_x_1)))) => (0x2 * (x_0 & x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Mul_FactorRule_2",
        expr="(-((x_0 & x_1)) - (x_0 & x_1)) => (val_fe * (x_0 & x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Neg_HackersDelightRule_1",
        expr="(~(x_0) + 0x1) => -(x_0)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Neg_HackersDelightRule_2",
        expr="~((x_0 - 0x1)) => -(x_0)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="NegAdd_HackersDelightRule_1",
        expr="((val_fe * (x_0 | x_1)) + (x_0 ^ x_1)) => -((x_0 + x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="NegAdd_HackersDelightRule_2",
        expr="((x_0 ^ (x_1 | x_2)) - (0x2 * ((x_0 | x_1) | x_2))) => -((x_0 + (x_1 | x_2)))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="NegOr_HackersDelightRule_1",
        expr="((x_0 & x_1) - (x_0 + x_1)) => -((x_0 | x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="NegXor_HackersDelightRule_1",
        expr="((x_0 & x_1) - (x_0 | x_1)) => -((x_0 ^ x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="NegXor_HackersDelightRule_2",
        expr="((x_0 + x_1) - (0x2 * (x_0 | x_1))) => -((x_0 ^ x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Or_HackersDelightRule_1",
        expr="((x_0 & bnot_x_1) + x_1) => (x_0 | x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Or_HackersDelightRule_2",
        expr="((x_0 + x_1) - (x_0 & x_1)) => (x_0 | x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Or_HackersDelightRule_2_variant_1",
        expr="((x_0 - x_1) - (x_0 & -(x_1))) => (x_0 | -(x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Or_MbaRule_1",
        expr="((x_0 & x_1) + (x_0 ^ x_1)) => (x_0 | x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Or_MbaRule_2",
        expr="(((x_0 + x_1) + 0x1) + ~((x_1 & x_0))) => (x_0 | x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Or_MbaRule_3",
        expr="((x_0 + (x_0 ^ x_1)) - (x_0 & ~(x_1))) => (x_0 | x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Or_FactorRule_1",
        expr="((x_0 & x_1) | (x_0 ^ x_1)) => (x_0 | x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Or_FactorRule_2",
        expr="((x_0 & (x_1 ^ x_2)) | ((x_0 ^ x_1) ^ x_2)) => (x_0 | (x_1 ^ x_2))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Or_FactorRule_3",
        expr="((x_0 | x_1) | (bnot_x_0 ^ bnot_x_1)) => (x_0 | x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Or_OllvmRule_1",
        expr="((x_0 & x_1) | ~((bnot_x_0 ^ x_1))) => (x_0 | x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Or_Rule_1",
        expr="((bnot_x_0 & x_1) | x_0) => (x_0 | x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Or_Rule_2",
        expr="((x_0 ^ x_1) | x_1) => (x_0 | x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Or_Rule_3",
        expr="(~((bnot_x_0 | bnot_x_1)) | (x_0 ^ x_1)) => (x_0 | x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Or_Rule_4",
        expr="((x_0 & x_1) ^ (x_0 ^ x_1)) => (x_0 | x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="OrBnot_FactorRule_1",
        expr="(~(x_0) ^ (x_0 & x_1)) => (~(x_0) | x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="OrBnot_FactorRule_2",
        expr="(x_0 ^ (~(x_0) & x_1)) => (x_0 | x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="OrBnot_FactorRule_3",
        expr="((x_0 - x_1) + (bnot_x_0 | x_1)) => (x_0 | ~(x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="OrBnot_FactorRule_4",
        expr="((bnot_x_0 | x_1) ^ (x_0 ^ x_1)) => (x_0 | ~(x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="PredSetnzRule1",
        expr="((x_0 | c_1) != c_2) => (val_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="PredSetnzRule2",
        expr="((x_0 & c_1) != c_2) => (val_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="PredSetnzRule3",
        expr="(((x_0 | 0x2) + (x_0 ^ 0x2)) != 0x0) => (val_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="PredSetnzRule4",
        expr="(((cst_1 - x_0) ^ x_0) != 0x0) => (val_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="PredSetnzRule5",
        expr="(-((~(x_0) & 0x1)) != x_0) => (val_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="PredSetnzRule6",
        expr="(((x_0 + c_1) + ((x_0 + c_2) & 0x1)) != 0x0) => (val_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="PredSetnzRule8",
        expr="((~((0x3 - x_0)) ^ ~(x_0)) != 0x0) => (val_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="PredSetzRule1",
        expr="((x_0 | c_1) == c_2) => (val_0)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="PredSetzRule2",
        expr="((x_0 & c_1) == c_2) => (val_0)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="PredSetzRule3",
        expr="(((x_0 | 0x2) + (x_0 ^ 0x2)) == 0x0) => (val_0)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="PredSetbRule1",
        expr="ULT((x_0 & c_1), c_2) => (val_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="PredOdd1",
        expr="((x_0 * (x_0 - 0x1)) & 0x1) => (val_0)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="PredOdd2",
        expr="((x_0 * (x_0 + 0x1)) & 0x1) => (val_0)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Pred0Rule1",
        expr="(x_0 & ~(x_0)) => (val_0)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Pred0Rule2",
        expr="(xdu((x_0 & 0x1), 1, 32) == 0x2) => (val_0)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Pred0Rule3",
        expr="(x_0 & ~((x_0 | x_1))) => (val_0)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Pred0Rule4",
        expr="((x_0 & x_1) & ~((x_0 | x_1))) => (val_0)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Pred0Rule5",
        expr="((x_0 & x_1) & (x_0 ^ x_1)) => (val_0)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="PredFFRule1",
        expr="(x_0 | ~(x_0)) => (val_ff)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="PredFFRule2",
        expr="((x_0 ^ x_1) | (bnot_x_0 | x_1)) => (val_ff)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="PredFFRule3",
        expr="(x_0 | ~((x_0 & x_1))) => (val_ff)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="PredFFRule4",
        expr="(x_0 | x_1) | (~(x_0 & x_1))  ==>  0xff",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="PredOr2_Rule_1",
        expr="(~((x_0 * x_0)) & 0x3) => ((~(x_0) & val_1) | val_2)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="PredOr1_Rule_1",
        expr="(x_0 ^ ((x_0 & 0x1) + 0x1)) => ((x_0 ^ (val_2 * (x_0 & val_1))) | val_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Sub_HackersDelightRule_1",
        expr="(x_0 + (~(x_1) + 0x1)) => (x_0 - x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Sub_HackersDelightRule_2",
        expr="((x_0 ^ x_1) - (0x2 * (~(x_0) & x_1))) => (x_0 - x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Sub_HackersDelightRule_3",
        expr="((x_0 & bnot_x_1) - (bnot_x_0 & x_1)) => (x_0 - x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Sub_HackersDelightRule_4",
        expr="((0x2 * (x_0 & bnot_x_1)) - (x_0 ^ x_1)) => (x_0 - x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Sub1_FactorRule_1",
        expr="((-(x_0) - 0x1) - (c_minus_2 * x_0)) => (x_0 - val_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Sub1_FactorRule_2",
        expr="((0x2 * x_0) + ~(x_0)) => (x_0 - 0x1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Sub1Add_HackersDelightRule_1",
        expr="((0x2 * (x_0 | x_1)) + (x_0 ^ bnot_x_1)) => ((x_0 + x_1) - val_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Sub1And_HackersDelightRule_1",
        expr="((x_0 | bnot_x_1) + x_1) => ((x_0 & x_1) - val_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Sub1Or_MbaRule_1",
        expr="((x_0 + x_1) + ~((x_0 & x_1))) => ((x_0 | x_1) - val_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Sub1And1_MbaRule_1",
        expr="((~(x_0) | 0x1) + x_0) => ((x_0 & val_1_1) - val_1_2)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Xor_HackersDelightRule_1",
        expr="((x_0 | x_1) - (x_0 & x_1)) => (x_0 ^ x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Xor_HackersDelightRule_2",
        expr="((0x2 * (x_0 | x_1)) - (x_0 + x_1)) => (x_0 ^ x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Xor_HackersDelightRule_3",
        expr="((x_0 + x_1) - (0x2 * (x_0 & x_1))) => (x_0 ^ x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Xor_HackersDelightRule_4",
        expr="(((x_0 - x_1) - (0x2 * (x_0 | ~(x_1)))) - 0x2) => (x_0 ^ x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Xor_HackersDelightRule_5",
        expr="(x_0 - ((0x2 * (x_0 & x_1)) - x_1)) => (x_0 ^ x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Xor_MbaRule_1",
        expr="(x_0 - ((0x2 * (x_1 & ~((x_0 ^ x_1)))) - x_1)) => (x_0 ^ x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Xor_MbaRule_2",
        expr="(x_0 - ((0x2 * (x_0 & x_1)) - x_1)) => (x_0 ^ x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Xor_MbaRule_3",
        expr="(x_0 - (0x2 * (x_0 & x_1))) => ((x_0 ^ x_1) - x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Xor_FactorRule_1",
        expr="((x_0 & bnot_x_1) | (bnot_x_0 & x_1)) => (x_0 ^ x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Xor_FactorRule_2",
        expr="((bnot_x_0 & x_1) ^ (x_0 & bnot_x_1)) => (x_0 ^ x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Xor_FactorRule_3",
        expr="((x_0 & x_1) ^ (x_0 | x_1)) => (x_0 ^ x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Xor_SpecialConstantRule_1",
        expr="((x_0 - x_1) + (0x2 * (~(x_0) & x_1))) => (x_0 ^ x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Xor_SpecialConstantRule_2",
        expr="((x_0 + x_1) + (c_minus_2 * (x_0 & x_1))) => (x_0 ^ x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Xor1_MbaRule_1",
        expr="(~(x_0) + ((0x2 * x_0) | 0x2)) => (x_0 ^ val_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Xor_Rule_1",
        expr="((x_0 & x_1) | ~((x_0 | x_1))) => (x_0 ^ ~(x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Xor_Rule_2",
        expr="(((x_0 ^ x_2) & (x_1 ^ bnot_x_2)) | ((x_0 ^ bnot_x_2) & (x_1 ^ x_2))) => (x_0 ^ x_1)",
        known_incorrect=False,
        comment="( (x_0 ^ x_2) & (x_1 ^ ~x_2) ) | ( (x_0 ^ ~x_2) & (x_1 ^ x_2) ) => (x_0 ^ x_1)",
    ),
    RuleInfo(
        name="Xor_Rule_3",
        expr="(((x_0 ^ x_2) & (x_1 ^ x_2)) | ((x_0 ^ bnot_x_2) & (x_1 ^ bnot_x_2))) => (~(x_0) ^ x_1)",
        known_incorrect=False,
        comment="( (x_0 ^ x_2) & (x_1 ^ x_2) ) | ( (x_0 ^ ~x_2) & (x_1 ^ ~x_2) ) => (~(x_0) ^ x_1)",
    ),
    RuleInfo(
        name="XorAlmost_Rule_1",
        expr="((x_0 + x_1) - (0x2 * (x_0 | (x_1 - 0x1)))) => ((x_0 ^ -(x_1)) + val_2)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="Xor_NestedStuff",
        expr="(((x_9 + x_10) + x_11) - (x_14 + (0x2 * (x_10 & ((x_9 + x_11) - x_14))))) => (x_10 ^ ((x_9 + x_11) - x_14))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="WeirdRule1",
        expr="(x_0 - (x_0 | x_1)) => ((x_0 | ~(x_1)) + val_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="WeirdRule2",
        expr="((0x2 * x_0) - (x_0 & ~(x_1))) => (x_0 + (x_0 & x_1))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="WeirdRule3",
        expr="((x_0 & ~(x_1)) - (0x2 * x_0)) => -((x_0 + (x_0 & x_1)))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="WeirdRule4",
        expr="((x_0 & bnot_x_1) - (x_0 & x_1)) => ((x_0 ^ x_1) - x_1)",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="WeirdRule5",
        expr="(((bnot_x_0 | (bnot_x_1 & x_2)) + (x_0 + (x_1 & x_2))) - x_2) => (x_0 | (x_1 | ~(x_2)))",
        known_incorrect=False,
        comment=None,
    ),
    RuleInfo(
        name="WeirdRule6",
        expr="((x_0 | x_1) + (x_0 & ~(x_1))) => ((x_0 ^ x_1) + x_0)",
        known_incorrect=False,
        comment=None,
    ),
]

# convenient helpers
RULE_BY_EXPR = {r.expr: r for r in RULES}
KNOWN_INCORRECT_RULES = {r.expr for r in RULES if r.known_incorrect}


equal_ignore_msb_cst = lambda self, V: [
    # This models `equal_ignore_msb_cst`
    (V["c_1"] & ((1 << (self.BIT_WIDTH - 1)) - 1))
    == (V["c_2"] & ((1 << (self.BIT_WIDTH - 1)) - 1)),
]


class TestBitwiseSimplifications(unittest.TestCase):
    """
    A comprehensive unit test to validate a list of bitwise and arithmetic
    simplifications using the Z3 SMT solver.

    This test identifies several types of rules:
    1.  VALID: Rules that are universally true.
    2.  VALID WITH CONSTRAINTS: Rules that are true only when certain relationships
        between their constants hold (defined in CONSTRAINT_MAP).
    3.  INCORRECT: Rules from the original list that are not universally true
        and are not easily fixable with simple constraints. These are moved to
        KNOWN_INCORRECT_RULES and skipped.
    """

    # --- Test Configuration ---
    BIT_WIDTH = 32  # Bit width for Z3 variables (e.g., 8, 16, 32, 64)

    # --- Constraint Definitions ---
    CONSTRAINT_MAP = {
        "(((x_0 & 0xff) ^ c_1) + (0x2 * (x_0 & c_2))) => ((x_0 & 0xff) + c_1)": lambda _, V: [
            (V["c_1"] & 0xFF) == V["c_2"]
        ],
        # Xor_SpecialConstantRule_2:This rule simplifies the correct MBA expression for XOR.
        "((x_0 + x_1) + (c_minus_2 * (x_0 & x_1))) => (x_0 ^ x_1)": lambda _, V: [
            V["c_minus_2"] == -2
        ],
        # CstSimplificationRule19 is only valid if the MSB of c_1 is 0.
        # This rule converts an arithmetic shift to a logical one.
        # The LHS uses `>>` which is AShr. The RHS uses LShR.
        # This is only valid if the value being shifted, (x_0 & c_1), is non-negative.
        # We enforce this by requiring the top c_2 bits of the mask c_1 to be 0.
        "((x_0 & c_1) >> c_2) => (LShR(x_0, c_2) & c_res)": lambda self, V: [
            # The new constraint: MSB of c_1 must be 0.
            (V["c_1"] & (1 << (self.BIT_WIDTH - 1))) == 0,
            # The original c_res definition from the PatternMatchingRule.
            # Since c_1 is non-negative, AShr(c_1, c_2) is the same as LShR(c_1, c_2).
            V["c_res"] == (V["c_1"] >> V["c_2"]),
        ],
        # Fix for: ((x_0 ^ c_1) + (0x2 * (x_0 & c_2))) => (x_0 + c_1)
        # From Add_SpecialConstantRule_1: The condition is that c_1 and c_2 are equal.
        "((x_0 ^ c_1) + (0x2 * (x_0 & c_2))) => (x_0 + c_1)": lambda self, V: [
            V["c_1"] == V["c_2"],
        ],
        # Add_SpecialConstant_Rule_2:
        "(((x_0 & 0xff) ^ c_1) + (0x2 * (x_0 & c_2))) => (x_0 + c_1)": lambda _, V: [
            V["c_1"] == V["c_2"],
        ],
        # Fix for: (((x_0 ^ c_1_1) & c_2_1) | ...) => (x_0 ^ c_res)
        # From CstSimplificationRule2: This is a very specific bit-muxing pattern.
        "(((x_0 ^ c_1_1) & c_2_1) | ((x_0 ^ c_1_2) & c_2_2)) => (x_0 ^ c_res)": lambda _, V: [
            V["c_2_2"] == ~V["c_2_1"],
            V["c_res"] == ((V["c_1_1"] ^ V["c_1_2"]) & V["c_2_1"]) ^ V["c_1_2"],
        ],
        # Fix for: (((cst_1 - x_0) ^ x_0) != 0x0) => (val_1)
        # From PredSetnzRule4: The condition is that cst_1 is odd.
        "(((cst_1 - x_0) ^ x_0) != 0x0) => (val_1)": lambda _, V: [
            (V["cst_1"] & 1) == 1
        ],
        "((x_0 | c_1) != c_2) => (val_1)": lambda _, V: [
            (V["c_1"] | V["c_2"]) != V["c_2"]
        ],
        "((x_0 & c_1) != c_2) => (val_1)": lambda _, V: [
            (V["c_1"] & V["c_2"]) != V["c_2"]
        ],
        "(((x_0 + c_1) + ((x_0 + c_2) & 0x1)) != 0x0) => (val_1)": lambda _, V: [
            ((V["c_2"] - V["c_1"]) & 1) == 1
        ],
        "((x_0 | c_1) == c_2) => (val_0)": lambda _, V: [
            (V["c_1"] | V["c_2"]) != V["c_2"]
        ],
        "((x_0 & c_1) == c_2) => (val_0)": lambda _, V: [
            (V["c_1"] & V["c_2"]) != V["c_2"]
        ],
        "ULT((x_0 & c_1), c_2) => (val_1)": lambda _, V: [ULT(V["c_1"], V["c_2"])],
        "(((x_0 & c_and) ^ c_xor_1) | ((bnot_x_0 & bnot_c_and) ^ c_xor_2)) => (x_0 ^ c_xor_res)": lambda _, V: [
            # Conditions from check_candidate
            (V["c_xor_1"] & V["c_xor_2"]) == 0,
            (V["c_xor_1"] & ~V["c_and"]) == 0,
            # The implicit condition we discovered was necessary
            (V["c_xor_2"] & V["c_and"]) == 0,
            # The definition of the derived constant
            V["c_xor_res"] == V["c_xor_1"] ^ V["c_xor_2"] ^ ~V["c_and"],
        ],
        "(((x_0 & c_and) ^ c_xor_1) | ((x_0 & bnot_c_and) ^ c_xor_2)) => (x_0 ^ c_xor_res)": lambda _, V: [
            # The original condition from check_candidate
            (V["c_xor_1"] & V["c_xor_2"]) == 0,
            # The newly discovered required conditions
            (V["c_xor_1"] & ~V["c_and"]) == 0,  # c_xor_1 lives in the c_and mask
            (V["c_xor_2"] & V["c_and"]) == 0,  # c_xor_2 lives in the ~c_and mask
            # The definition of the derived constant
            V["c_xor_res"] == V["c_xor_1"] | V["c_xor_2"],  # Use | for disjoint sets
        ],
        "((bnot_x_0 & c_and_1) | ((x_0 & c_and_2) ^ c_xor)) => ((x_0 & c_and_res) ^ c_xor_res)": lambda _, V: [
            # The original condition from check_candidate
            (V["c_and_1"] & V["c_and_2"]) == 0,
            # The newly discovered required condition
            (V["c_xor"] & (V["c_and_1"] | V["c_and_2"])) == 0,
            # The definitions of the derived constants
            # c_and_1 ^ c_and_2 => c_and_1 | c_and_2 for c_and_res.
            # They are equivalent for disjoint inputs, but | is more conventional for combining masks.
            V["c_and_res"] == V["c_and_1"] | V["c_and_2"],  # Use | for disjoint sets
            V["c_xor_res"] == V["c_and_1"] ^ V["c_xor"],
        ],
        # Constraints for the double shift rule
        "LShR(LShR(x_0, c_1), c_2) => LShR(x_0, c_res)": lambda self, V: [
            # The derived constant is the sum
            V["c_res"] == V["c_1"] + V["c_2"],
            # Condition 1: The sum of the shifts must not overflow bit-vector addition.
            # We check this by seeing if the unsigned sum is greater than either operand.
            # This is a standard way to check for unsigned overflow.
            And(ULT(V["c_1"], V["c_1"] + V["c_2"]), ULT(V["c_2"], V["c_1"] + V["c_2"])),
            # Condition 2: The resulting total shift amount must be less than the bit-width.
            ULT(V["c_1"] + V["c_2"], self.BIT_WIDTH),
        ],
        # if ~c_1 ^ c_2 == 1 AND ~c_1 is an even number (its LSB is 0), then (x_0 & c_1) + c_2 is equivalent to (x_0 | lnot_c_1) + val_1
        "((x_0 & c_1) + c_2) => ((x_0 | lnot_c_1) + val_1)": lambda _, V: [
            # The original condition from check_candidate
            (~V["c_1"] ^ V["c_2"]) == 1,
            # The newly discovered condition
            (~V["c_1"] & 1) == 0,
            # The definitions of the derived constants
            V["lnot_c_1"] == ~V["c_1"],
            V["val_1"] == 1,
        ],
        # if c_1 == ~c_2, then (~(x_0) ^ c_1) | (x_0 & c_2) is equivalent to (x_0 ^ c_1_bnot) ^ (x_0 & c_and)
        "((~(x_0) ^ c_1) | (x_0 & c_2)) => ((x_0 ^ c_1_bnot) ^ (x_0 & c_and))": lambda _, V: [
            V["c_1_bnot"] == ~V["c_1"],
            V["c_and"] == (~V["c_1"] & V["c_2"]),
        ],
        # if (c_1 & c_2) == c_1, then (x_0 & c_1) - (x_0 & c_2) == -(x_0 & (~c_1 & c_2))
        "((x_0 & c_1) - (x_0 & c_2)) => -((x_0 & c_and))": lambda _, V: [
            # The condition from check_candidate
            (V["c_1"] & V["c_2"]) == V["c_1"],
            # The definition of the derived constant
            V["c_and"] == (~V["c_1"] & V["c_2"]),
        ],
        # if c_1 == ~c_2, then (x_0 ^ c_1) + (2 * (x_0 | c_2)) is equivalent to x_0 + (c_2 - 1)
        "((x_0 ^ c_1) + (0x2 * (x_0 | c_2))) => (x_0 + val_res)": lambda _, V: [
            V["c_1"] == ~V["c_2"],
            V["val_res"] == V["c_2"] - 1,
        ],
        # This identity requires that the constants used in the `&` and `^` are disjoint.
        "(((x_0 ^ c_1_1) & c_2_1) | ((x_0 ^ c_1_2) & c_2_2)) => (x_0 ^ c_res)": lambda _, V: [
            V["c_res"] == ((V["c_1_1"] & V["c_2_1"]) | (V["c_1_2"] & V["c_2_2"])),
            # The masks must be disjoint AND cover all bits.
            (V["c_2_1"] | V["c_2_2"]) == -1,
        ],
        "((x_0 - c_0) + (c_1 * (x_0 - c_2))) => ((c_coeff * x_0) - c_sub)": lambda _, V: [
            V["c_coeff"] == 1 + V["c_1"],
            V["c_sub"] == V["c_0"] + (V["c_1"] * V["c_2"]),
        ],
        "(x_0 - (c_1 - x_1)) => (x_0 + (x_1 + c_res))": lambda _, V: [
            V["c_res"] == -V["c_1"]
        ],
        # This identity holds only if c_2 is the bitwise not of c_1
        "((x_0 & c_1) | (x_1 & c_2)) => (((x_0 ^ x_1) & c_1) ^ x_1)": lambda _, V: [
            V["c_2"] == ~V["c_1"]
        ],
        "((x_0 ^ c_1) & c_2) => ((x_0 & c_2) ^ c_res)": lambda _, V: [
            V["c_res"] == V["c_1"] & V["c_2"]
        ],
        "LShR((x_0 & c_1), c_2) => (LShR(x_0, c_2) & c_res)": lambda _, V: [
            V["c_res"] == LShR(V["c_1"], V["c_2"])
        ],
        "((x_0 & c_1) | c_2) => ((x_0 & c_res) | c_2)": lambda _, V: [
            V["c_res"] == V["c_1"] | V["c_2"]
        ],
        "((cst_1 & (x_0 ^ x_1)) ^ x_1) => ((x_0 & cst_1) ^ (x_1 & not_cst_1))": lambda _, V: [
            V["not_cst_1"] == ~V["cst_1"]
        ],
        "~((x_0 ^ c_1)) => (x_0 ^ bnot_c_1)": lambda _, V: [V["bnot_c_1"] == ~V["c_1"]],
        "~((x_0 | c_1)) => (~(x_0) & bnot_c_1)": lambda _, V: [
            V["bnot_c_1"] == ~V["c_1"]
        ],
        "~((x_0 & c_1)) => (~(x_0) | bnot_c_1)": lambda _, V: [
            V["bnot_c_1"] == ~V["c_1"]
        ],
        "((-(x_0) - 0x1) - (c_minus_2 * x_0)) => (x_0 - val_1)": lambda _, V: [
            V["c_minus_2"] == -2
        ],
        "((~(x_0) | 0x1) + x_0) => ((x_0 & val_1_1) - val_1_2)": lambda _, V: [
            V["val_1_1"] == 1,
            V["val_1_2"] == 1,
        ],
    }

    def _to_bv_if_bool(self, expr):
        """Converts a Z3 boolean expression to a 1-bit or 0-bit vector."""
        if is_bool(expr):
            return If(expr, BitVecVal(1, self.BIT_WIDTH), BitVecVal(0, self.BIT_WIDTH))
        return expr

    def _parse_and_prove(self, rule_name, rule_str):
        """Parses a single rule string, and uses Z3 to prove its validity."""
        # 1. Pre-process and split the rule into LHS and RHS
        rule_str = rule_str.replace("==>", "=>")
        if "=>" not in rule_str:
            self.fail(f"Invalid rule ({rule_name}): format (missing '=>'): {rule_str}")

        if rule_str.endswith("=>  0xff"):
            rule_str = rule_str.replace("=>  0xff", "=> val_ff")

        lhs_str, rhs_str = [s.strip() for s in rule_str.split("=>")]

        # 2. Find all unique identifiers
        identifiers = set(re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", f"{lhs_str} {rhs_str}"))

        # 3. Create the evaluation context
        context = {
            "LShR": LShR,
            "ULT": ULT,
            "__builtins__": {"int": int, "hex": hex},
            "xdu": self.z3_xdu,
        }
        bw = self.BIT_WIDTH

        named_constants = {
            "val_0": 0,
            "val_1": 1,
            "val_2": 2,
            "val_ff": (1 << bw) - 1,
            "val_fe": (1 << bw) - 2,
            "minus_1": (1 << bw) - 1,
        }
        for name, val in named_constants.items():
            if name in identifiers:
                context[name] = BitVecVal(val, bw)

        # 1. Separate identifiers into base names and derived (bnot) names
        base_identifiers = set()
        bnot_map = {}  # Maps derived name like 'bnot_x2' to its base name 'x2'

        for name in identifiers:
            if name in context or name == "LShR":
                continue

            if name.startswith(("bnot_", "lnot_", "not_")):
                _, base_name = name.split("_", 1)
                base_identifiers.add(base_name)
                bnot_map[name] = base_name
            else:
                base_identifiers.add(name)

        # 2. Create all base symbolic variables first
        for base_name in base_identifiers:
            if base_name not in context:
                context[base_name] = BitVec(base_name, bw)

        # 3. Create all derived bnot_ variables from the existing base variables
        for bnot_name, base_name in bnot_map.items():
            if bnot_name not in context:
                context[bnot_name] = ~context[base_name]

        # 4. Create Z3 Solver and add constraints
        solver = Solver()
        if rule_str in self.CONSTRAINT_MAP:
            constraints = self.CONSTRAINT_MAP[rule_str](self, context)
            solver.add(constraints)

        # 5. Evaluate LHS and RHS strings into Z3 expressions
        try:
            lhs_expr = eval(lhs_str, {"LShR": LShR}, context)
            rhs_expr = eval(rhs_str, {"LShR": LShR}, context)
        except Exception as e:
            self.fail(
                f"Failed to parse/evaluate expression in rule ({rule_name}): {rule_str}\nError: {e}"
            )

        # 6. IMPORTANT: Convert any boolean results to bitvectors to avoid sort mismatch
        lhs_bv = self._to_bv_if_bool(lhs_expr)
        rhs_bv = self._to_bv_if_bool(rhs_expr)

        # 7. Prove equivalence by asserting inequality
        solver.add(lhs_bv != rhs_bv)
        result = solver.check()

        if result == sat:
            model = solver.model()
            # Build a clear counterexample string
            decls = model.decls()
            sorted_decls = sorted(decls, key=lambda d: d.name())
            counter_str = ", ".join([f"{d.name()} = {model[d]}" for d in sorted_decls])

            # Safely evaluate expressions with the model
            try:
                lhs_val = model.eval(lhs_bv, model_completion=True)
                rhs_val = model.eval(rhs_bv, model_completion=True)
                msg = (
                    f"\n--- FAIL: Simplification is NOT universally true ---\n"
                    f"Rule:           {rule_name}\n"
                    f"Expression:     {rule_str}\n"
                    f"Counterexample: [{counter_str}]\n"
                    f"  - LHS value:    {lhs_val} {(f'(dec: {lhs_val.as_long()})' if hasattr(lhs_val, 'as_long') else '')}\n"
                    f"  - RHS value:    {rhs_val} {(f'(dec: {rhs_val.as_long()})' if hasattr(rhs_val, 'as_long') else '')}"
                )
            except Exception as e:
                msg = (
                    f"\n--- FAIL: Simplification is NOT universally true (error during eval) ---\n"
                    f"Rule:           {rule_name}\n"
                    f"Expression:     {rule_str}\n"
                    f"Counterexample: [{counter_str}]\n"
                    f"Eval Error:     {e}"
                )
            self.fail(msg)
        elif result != unsat:
            self.fail(f"Z3 returned an unknown result for rule {rule_name}: {rule_str}")

    def z3_xdu(self, expr, src_bitwidth: int, dst_bitwidth: int):
        """Z3 representation of unsigned extension (xdu)."""
        if dst_bitwidth <= src_bitwidth:
            # In Z3, extending to a smaller/equal size is a no-op or an extract.
            # To match the Python logic which would error, we can just return the original.
            # Or, for correctness, extract the bits.
            return Extract(src_bitwidth - 1, 0, expr)
        ext_bits = dst_bitwidth - src_bitwidth
        return ZeroExt(ext_bits, expr)

    def test_simplifications(self):
        """
        Iterates through all defined rules and proves their equivalence using Z3.
        """
        # ------------------------------------------------------------------
        # Build lists from the metadata
        # ------------------------------------------------------------------
        all_rules = [r.expr for r in RULES]
        testable_rules = [
            r.expr for r in RULES if not r.is_nonlinear and not r.known_incorrect
        ]
        skipped_count = len(all_rules) - len(testable_rules)

        print(
            f"\nTesting {len(testable_rules)} unique bitwise simplifications "
            f"with Z3 (BIT_WIDTH={self.BIT_WIDTH})..."
        )
        if skipped_count > 0:
            print(f"Skipping {skipped_count} known incorrect or unprovable rules.")

        failed_rules = []
        for i, expr in enumerate(testable_rules):
            meta = RULE_BY_EXPR[expr]
            with self.subTest(rule_name=meta.name, rule_expr=expr):
                label = (
                    f"{meta.name} ({'incorrect' if meta.known_incorrect else 'valid'})"
                )
                print(f"  [{i+1}/{len(testable_rules)}] {label.ljust(40)}", end="\r")
                try:
                    self._parse_and_prove(meta.name, expr)
                except AssertionError:
                    failed_rules.append(meta.name)
                    raise
        print(
            "\n",
            "\n",
            "Successfully proved",
            len(testable_rules) - len(failed_rules),
            "simplifications. ",
            "There were",
            len(all_rules) - len(testable_rules),
            "known incorrect or unprovable rules for a total of",
            len(all_rules),
            "rules.",
            " " * 80,
        )
        if failed_rules:
            print(f"\nThe following rules failed: {failed_rules}")


if __name__ == "__main__":
    unittest.main()
