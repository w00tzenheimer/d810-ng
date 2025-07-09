import re
import unittest
from dataclasses import dataclass

from z3 import And, BitVec, BitVecVal, If, LShR, Solver, is_bool, sat, simplify, unsat


@dataclass(frozen=True, slots=True)
class RuleInfo:
    name: str
    expr: str
    known_incorrect: bool = False
    comment: str | None = None


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
        known_incorrect=True,
        comment="This is only true if c_2 == c_1. The general rule is false.",
    ),
    RuleInfo(
        name="Add_SpecialConstantRule_2",
        expr="(((x_0 & 0xff) ^ c_1) + (0x2 * (x_0 & c_2))) => (x_0 + c_1)",
        known_incorrect=True,
        comment="The `& 0xff` on the LHS makes this fundamentally different from the RHS.",
    ),
    RuleInfo(
        name="Add_SpecialConstantRule_3",
        expr="((x_0 ^ c_1) + (0x2 * (x_0 | c_2))) => (x_0 + val_res)",
        known_incorrect=True,
        comment="The constraint for val_res is complex and the provided one is likely wrong.",
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
        known_incorrect=False,
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
        expr="((x_0 | c_1) & c_2) => ((x_0 & c_and) ^ c_xor)",
        known_incorrect=True,
        comment="The identity `(a|c)&d == (a&d)^(c&d)` is not generally true.",
    ),
    RuleInfo(
        name="CstSimplificationRule10",
        expr="((x_0 & c_1) - (x_0 & c_2)) => -((x_0 & c_and))",
        known_incorrect=True,
        comment="The identity `(a&c1)-(a&c2) == -(a&(c2&~c1))` is not generally true.",
    ),
    RuleInfo(
        name="CstSimplificationRule11",
        expr="((~(x_0) ^ c_1) | (x_0 & c_2)) => ((x_0 ^ c_1_bnot) ^ (x_0 & c_and))",
        known_incorrect=True,
        comment="This identity is not generally true.",
    ),
    RuleInfo(
        name="CstSimplificationRule12",
        expr="((c_1 - x_0) - (0x2 * (~(x_0) & c_2))) => ((~(x_0) ^ c_2) - c_diff)",
        known_incorrect=True,
        comment="This identity is not generally true.",
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
        known_incorrect=True,
        comment="This is only true if c_2 == c_1 + 1, but also requires x_0 & c_1 == 0.",
    ),
    RuleInfo(
        name="CstSimplificationRule15",
        expr="LShR(LShR(x_0, c_1), c_2) => LShR(x_0, c_res)",
        known_incorrect=True,
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
        known_incorrect=True,
        comment="The provided constraints are insufficient for this complex transformation.",
    ),
    RuleInfo(
        name="CstSimplificationRule21",
        expr="(((x_0 & c_and) ^ c_xor_1) | ((x_0 & bnot_c_and) ^ c_xor_2)) => (x_0 ^ c_xor_res)",
        known_incorrect=True,
        comment="The provided constraints are insufficient for this complex transformation.",
    ),
    RuleInfo(
        name="CstSimplificationRule22",
        expr="(((x_0 & c_and) ^ c_xor_1) | ((bnot_x_0 & bnot_c_and) ^ c_xor_2)) => (x_0 ^ c_xor_res)",
        known_incorrect=True,
        comment="The provided constraints are insufficient for this complex transformation.",
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
        known_incorrect=True,
        comment="Multiplication does not distribute over bitwise operations like this.",
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
        known_incorrect=True,
        comment="Multiplication does not distribute over bitwise operations like this.",
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
        expr="((x_0 & c_1) < c_2) => (val_0)",
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
        expr="(xdu((x_0 & 0x1)) == 0x2) => (val_0)",
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
        expr="(x_0 + ((0xfe * (x_0 & x_1)) + x_1)) => (x_0 ^ x_1)",
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
        expr="(((x_0 ^ x_2) & (x_1 ^ bnot_x2)) | ((x_0 ^ bnot_x2) & (x_1 ^ x_2))) => (x_0 ^ x_1)",
        known_incorrect=True,
        comment="This identity is not generally true.",
    ),
    RuleInfo(
        name="Xor_Rule_3",
        expr="(((x_0 ^ x_2) & (x_1 ^ x_2)) | ((x_0 ^ bnot_x2) & (x_1 ^ bnot_x2))) => (~(x_0) ^ x_1)",
        known_incorrect=True,
        comment="This identity is not generally true.",
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
        # This identity requires that the constants used in the `&` and `^` are disjoint.
        "(((x_0 ^ c_1_1) & c_2_1) | ((x_0 ^ c_1_2) & c_2_2)) => (x_0 ^ c_res)": lambda V: [
            V["c_res"] == ((V["c_1_1"] & V["c_2_1"]) | (V["c_1_2"] & V["c_2_2"])),
            (V["c_2_1"] & V["c_2_2"]) == 0,
        ],
        "((x_0 - c_0) + (c_1 * (x_0 - c_2))) => ((c_coeff * x_0) - c_sub)": lambda V: [
            V["c_coeff"] == 1 + V["c_1"],
            V["c_sub"] == V["c_0"] + (V["c_1"] * V["c_2"]),
        ],
        "(x_0 - (c_1 - x_1)) => (x_0 + (x_1 + c_res))": lambda V: [
            V["c_res"] == -V["c_1"]
        ],
        # This identity holds only if c_2 is the bitwise not of c_1
        "((x_0 & c_1) | (x_1 & c_2)) => (((x_0 ^ x_1) & c_1) ^ x_1)": lambda V: [
            V["c_2"] == ~V["c_1"]
        ],
        "((x_0 ^ c_1) & c_2) => ((x_0 & c_2) ^ c_res)": lambda V: [
            V["c_res"] == V["c_1"] & V["c_2"]
        ],
        "LShR((x_0 & c_1), c_2) => (LShR(x_0, c_2) & c_res)": lambda V: [
            V["c_res"] == LShR(V["c_1"], V["c_2"])
        ],
        "((x_0 & c_1) | c_2) => ((x_0 & c_res) | c_2)": lambda V: [
            V["c_res"] == V["c_1"] | V["c_2"]
        ],
        "((cst_1 & (x_0 ^ x_1)) ^ x_1) => ((x_0 & cst_1) ^ (x_1 & not_cst_1))": lambda V: [
            V["not_cst_1"] == ~V["cst_1"]
        ],
        "~((x_0 ^ c_1)) => (x_0 ^ bnot_c_1)": lambda V: [V["bnot_c_1"] == ~V["c_1"]],
        "~((x_0 | c_1)) => (~(x_0) & bnot_c_1)": lambda V: [V["bnot_c_1"] == ~V["c_1"]],
        "~((x_0 & c_1)) => (~(x_0) | bnot_c_1)": lambda V: [V["bnot_c_1"] == ~V["c_1"]],
        "((-(x_0) - 0x1) - (c_minus_2 * x_0)) => (x_0 - val_1)": lambda V: [
            V["c_minus_2"] == -2
        ],
        "((~(x_0) | 0x1) + x_0) => ((x_0 & val_1_1) - val_1_2)": lambda V: [
            V["val_1_1"] == 1,
            V["val_1_2"] == 1,
        ],
    }

    def _to_bv_if_bool(self, expr):
        """Converts a Z3 boolean expression to a 1-bit or 0-bit vector."""
        if is_bool(expr):
            return If(expr, BitVecVal(1, self.BIT_WIDTH), BitVecVal(0, self.BIT_WIDTH))
        return expr

    def _parse_and_prove(self, rule_str):
        """Parses a single rule string, and uses Z3 to prove its validity."""
        # 1. Pre-process and split the rule into LHS and RHS
        rule_str = rule_str.replace("==>", "=>")
        if "=>" not in rule_str:
            self.fail(f"Invalid rule format (missing '=>'): {rule_str}")

        if rule_str.endswith("=>  0xff"):
            rule_str = rule_str.replace("=>  0xff", "=> val_ff")

        lhs_str, rhs_str = [s.strip() for s in rule_str.split("=>")]

        # Skip rule with undefined function 'xdu'
        if "xdu" in rule_str:
            print(f"\nSKIPPING rule with undefined function 'xdu': {rule_str}")
            return

        # 2. Find all unique identifiers
        identifiers = set(re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", f"{lhs_str} {rhs_str}"))

        # 3. Create the evaluation context
        context = {"LShR": LShR, "__builtins__": {"int": int, "hex": hex}}
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

        for name in identifiers:
            if name in context or name == "LShR":
                continue

            base_name, is_bnot = (
                (name.split("_", 1)[1], True)
                if name.startswith(("bnot_", "lnot_", "not_"))
                else (name, False)
            )

            if base_name not in context:
                context[base_name] = BitVec(base_name, bw)
            if is_bnot:
                context[name] = ~context[base_name]
            elif name not in context:
                context[name] = BitVec(name, bw)

        # 4. Create Z3 Solver and add constraints
        solver = Solver()
        if rule_str in self.CONSTRAINT_MAP:
            constraints = self.CONSTRAINT_MAP[rule_str](context)
            solver.add(constraints)

        # 5. Evaluate LHS and RHS strings into Z3 expressions
        try:
            lhs_expr = eval(lhs_str, {"LShR": LShR}, context)
            rhs_expr = eval(rhs_str, {"LShR": LShR}, context)
        except Exception as e:
            self.fail(
                f"Failed to parse/evaluate expression in rule: {rule_str}\nError: {e}"
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
                    f"Rule:           {rule_str}\n"
                    f"Counterexample: [{counter_str}]\n"
                    f"  - LHS value:    {lhs_val} {(f'(dec: {lhs_val.as_long()})' if hasattr(lhs_val, 'as_long') else '')}\n"
                    f"  - RHS value:    {rhs_val} {(f'(dec: {rhs_val.as_long()})' if hasattr(rhs_val, 'as_long') else '')}"
                )
            except Exception as e:
                msg = (
                    f"\n--- FAIL: Simplification is NOT universally true (error during eval) ---\n"
                    f"Rule:           {rule_str}\n"
                    f"Counterexample: [{counter_str}]\n"
                    f"Eval Error:     {e}"
                )
            self.fail(msg)
        elif result != unsat:
            self.fail(f"Z3 returned an unknown result for rule: {rule_str}")

    def test_simplifications(self):
        """
        Iterates through all defined rules and proves their equivalence using Z3.
        """
        # ------------------------------------------------------------------
        # Build lists from the metadata
        # ------------------------------------------------------------------
        all_rules = [r.expr for r in RULES]
        testable_rules = [r for r in all_rules if r not in KNOWN_INCORRECT_RULES]
        skipped_count = len(all_rules) - len(testable_rules)

        print(
            f"\nTesting {len(testable_rules)} unique bitwise simplifications "
            f"with Z3 (BIT_WIDTH={self.BIT_WIDTH})..."
        )
        if skipped_count > 0:
            print(f"Skipping {skipped_count} known incorrect or unprovable rules.")

        for i, rule in enumerate(testable_rules):
            with self.subTest(rule=rule):
                meta = RULE_BY_EXPR[rule]
                label = (
                    f"{meta.name} ({'incorrect' if meta.known_incorrect else 'valid'})"
                )
                print(f"  [{i+1}/{len(testable_rules)}] {label.ljust(40)}", end="\r")
                self._parse_and_prove(rule)
        print(
            f"\n\nSuccessfully proved {len(testable_rules)} simplifications. {' '*80}"
        )


if __name__ == "__main__":
    unittest.main()
