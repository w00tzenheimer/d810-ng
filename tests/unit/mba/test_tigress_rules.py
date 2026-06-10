"""Unit tests for the Tigress-indirect residual MBA rules (ticket llr-m9r4).

These tests are IDA-free. They prove each rule's pattern/replacement equivalence
via the Z3 backend (``verify_rule``) at the rule's native bit width, and they
assert that each rule's PATTERN matches the obfuscated AST shape and rewrites to
the documented clean form on the concrete Tigress constants.

The multiply rule (``TigressMultiplyBitPartitionRule``) is ``SKIP_VERIFICATION``
because a full symbolic 3-multiply Z3 proof times out; instead this module
proves it with the bit-partition algebra invariant and a large random sample.
"""

import random

import pytest

from d810.mba.dsl import SymbolicExpressionProtocol
from d810.backends.mba.z3 import verify_rule
import d810.mba.rules.tigress as T


# ---------------------------------------------------------------------------
# Z3 equivalence proofs (the linear / xor / relational rules)
# ---------------------------------------------------------------------------

_Z3_VERIFIABLE = [
    (T.TigressIncrementRule, 32),
    (T.TigressIncrementRule, 64),
    (T.TigressAddViaXorOrRule, 32),
    (T.TigressAddViaXorOrRule, 64),
    (T.TigressXorViaSubOrRule, 32),
    (T.TigressXorViaSubOrRule, 64),
    (T.TigressNotEqualSignBitRule, 32),   # 32-bit pinned 0x1F shift
    (T.TigressNotEqualSignBitRule64, 64),  # 64-bit pinned 0x3F shift
]


@pytest.mark.parametrize(
    "rule_cls,bit_width",
    _Z3_VERIFIABLE,
    ids=lambda v: getattr(v, "__name__", str(v)),
)
def test_rule_z3_equivalence(rule_cls, bit_width):
    """Each non-multiply rule must prove pattern == replacement under constraints.

    NOTE on bit width: the increment/add/xor rules carry literal-constant
    constraints (e.g. ``(c1 ^ c2) == -1``). The constraint->Z3 converter
    materializes literals at 32-bit, so 64-bit verification through
    ``verify_rule`` is only reliable for the same family of rules that the
    existing in-tree ``Add_OllvmRule_2`` (also ``c == -2``) verifies at: 32-bit.
    The mathematical 64-bit correctness is proven separately in
    ``test_increment_add_xor_64bit_direct`` with correctly-sized constants.
    """
    inst = rule_cls()
    if bit_width == 64 and rule_cls in (
        T.TigressIncrementRule,
        T.TigressAddViaXorOrRule,
        T.TigressXorViaSubOrRule,
    ):
        pytest.skip(
            "verify_rule materializes constraint literals at 32-bit; "
            "64-bit correctness proven in test_increment_add_xor_64bit_direct"
        )
    assert verify_rule(inst, bit_width=bit_width) is True


def test_increment_add_xor_64bit_direct():
    """Prove the increment/add/xor families at 64-bit with correctly-sized Z3.

    This bypasses the constraint-converter's 32-bit literal limitation by
    building the constraints with native 64-bit constants directly.
    """
    import z3

    bw = 64
    x = z3.BitVec("x", bw)
    c1 = z3.BitVec("c1", bw)
    c2 = z3.BitVec("c2", bw)
    neg1 = z3.BitVecVal(-1, bw)

    # FORM1 increment: (x ^ c1) + ((2x)|c2) + 1 == x + (c2>>1)
    s = z3.Solver()
    s.add(c2 & 1 == 0)
    s.add((c1 ^ z3.LShR(c2, 1)) == neg1)
    s.add(((x ^ c1) + ((2 * x) | c2) + 1) != x + z3.LShR(c2, 1))
    assert s.check() == z3.unsat

    # FORM4 add-via-xor-or: (x ^ c1) + 2*(x|c2) + 1 == x + c2  when c1 == ~c2
    s = z3.Solver()
    s.add((c1 ^ c2) == neg1)
    s.add(((x ^ c1) + 2 * (x | c2) + 1) != x + c2)
    assert s.check() == z3.unsat

    # FORM5 xor-via-sub-or: x - 2*(x|c1) - c2 == x ^ ~c1  when c2 == ~c1 + 2
    s = z3.Solver()
    k = ~c1
    s.add(c2 == k + 2)
    s.add((x - 2 * (x | c1) - c2) != (x ^ k))
    assert s.check() == z3.unsat


def test_signbit_rule_holds_only_at_top_bit_index():
    """The FORM3 sign-bit idiom is INVALID for an arbitrary shift amount.

    Documents WHY the rule pins the shift literal per width instead of matching
    a free shift constant: a non-(width-1) shift is not equivalent to (x != y).
    """
    import z3

    bw = 32
    x = z3.BitVec("x", bw)
    y = z3.BitVec("y", bw)
    d = x - y
    bad_shift = 10
    P = z3.LShR(((d >> bad_shift) & (2 * d)) - d, bad_shift)  # d>>n arithmetic
    neq = z3.If(x != y, z3.BitVecVal(1, bw), z3.BitVecVal(0, bw))
    s = z3.Solver()
    s.add(P != neq)
    assert s.check() == z3.sat  # NOT equivalent for shift != width-1


# ---------------------------------------------------------------------------
# Multiply rule: bit-partition algebra + large random sample
# ---------------------------------------------------------------------------


def test_multiply_bit_partition_samples():
    """FORM2a multiply identity via random samples (Z3 multiply proof times out)."""
    mask32 = (1 << 32) - 1
    mask64 = (1 << 64) - 1

    def lhs_rhs_equal(a, b, mask):
        lhs = (
            ((a & (~b & mask)) * (~a & b & mask)) + ((a | b) * (a & b))
        ) & mask
        rhs = (a * b) & mask
        return lhs == rhs

    rng = random.Random(0xD810)
    for _ in range(200_000):
        assert lhs_rhs_equal(rng.randint(0, mask32), rng.randint(0, mask32), mask32)
    for _ in range(50_000):
        assert lhs_rhs_equal(rng.randint(0, mask64), rng.randint(0, mask64), mask64)

    # Edge cases (signed extremes, all-ones, the Tigress-style operands).
    edges32 = [0, 1, mask32, 0x80000000, 0x7FFFFFFF, 0xAAAAAAAA, 0x66, 0x42, 0x173063C1]
    for a in edges32:
        for b in edges32:
            assert lhs_rhs_equal(a, b, mask32)


def test_multiply_rule_is_skip_verification():
    """The multiply rule must stay SKIP_VERIFICATION (3 multiplies -> Z3 timeout)."""
    inst = T.TigressMultiplyBitPartitionRule()
    assert getattr(inst, "SKIP_VERIFICATION", False) is True
    assert inst.description  # documented, required by the skip-rule contract


# ---------------------------------------------------------------------------
# AST shape: PATTERN matches the obfuscated form, REPLACEMENT is the clean form
# ---------------------------------------------------------------------------


def _op(expr):
    return expr.operation


def test_increment_pattern_shape():
    """PATTERN == ((x ^ c1) + ((2*x) | c2)) + 1 ; REPLACEMENT == x + k_res."""
    p = T.TigressIncrementRule._dsl_pattern
    # top: add of (...) and literal 1
    assert _op(p) == "add"
    assert p.right.is_constant() and p.right.value == 1
    inner = p.left  # (x ^ c1) + ((2*x) | c2)
    assert _op(inner) == "add"
    assert _op(inner.left) == "xor"          # x ^ c1
    assert _op(inner.right) == "or"          # (2*x) | c2
    assert _op(inner.right.left) == "mul"    # 2 * x
    r = T.TigressIncrementRule._dsl_replacement
    assert _op(r) == "add" and r.left.name == "x_0" and r.right.name == "k_res"


def test_add_via_xor_or_pattern_shape():
    """PATTERN == ((x ^ c1) + 2*(x | c2)) + 1 ; REPLACEMENT == x + c2."""
    p = T.TigressAddViaXorOrRule._dsl_pattern
    assert _op(p) == "add" and p.right.is_constant() and p.right.value == 1
    inner = p.left
    assert _op(inner.left) == "xor"               # x ^ c1
    assert _op(inner.right) == "mul"              # 2 * (x | c2)
    assert _op(inner.right.right) == "or"
    r = T.TigressAddViaXorOrRule._dsl_replacement
    assert _op(r) == "add" and r.right.name == "c_2"


def test_xor_via_sub_or_pattern_shape():
    """PATTERN == (x - 2*(x | c1)) - c2 ; REPLACEMENT == x ^ k_res."""
    p = T.TigressXorViaSubOrRule._dsl_pattern
    assert _op(p) == "sub"
    assert p.right.name == "c_2"                  # ... - c2
    inner = p.left                                # x - 2*(x | c1)
    assert _op(inner) == "sub"
    assert _op(inner.right) == "mul"              # 2 * (x | c1)
    assert _op(inner.right.right) == "or"
    r = T.TigressXorViaSubOrRule._dsl_replacement
    assert _op(r) == "xor" and r.right.name == "k_res"


def test_signbit_pattern_shape():
    """PATTERN == ((sar(x-y, N) & 2*(x-y)) - (x-y)) >> N ; REPLACEMENT == (x!=y)."""
    p = T.TigressNotEqualSignBitRule._dsl_pattern
    assert _op(p) == "shr"                        # outer logical shift
    assert p.right.is_constant() and p.right.value == 0x1F
    mid = p.left                                  # (sar & 2d) - d
    assert _op(mid) == "sub"
    assert _op(mid.left) == "and"
    assert _op(mid.left.left) == "sar"            # arithmetic inner shift
    r = T.TigressNotEqualSignBitRule._dsl_replacement
    assert _op(r) == "bool_to_int"                # comparison result, not arithmetic
    assert r.constraint.op_name == "ne"

    p64 = T.TigressNotEqualSignBitRule64._dsl_pattern
    assert p64.right.value == 0x3F


def test_multiply_pattern_shape():
    """PATTERN == (a & ~b)*(~a & b) + (a | b)*(a & b) ; REPLACEMENT == a * b."""
    p = T.TigressMultiplyBitPartitionRule._dsl_pattern
    assert _op(p) == "add"
    assert _op(p.left) == "mul"                   # (a & ~b)*(~a & b)
    assert _op(p.right) == "mul"                  # (a | b)*(a & b)
    assert _op(p.right.left) == "or" and _op(p.right.right) == "and"
    r = T.TigressMultiplyBitPartitionRule._dsl_replacement
    assert _op(r) == "mul" and r.left.name == "x_0" and r.right.name == "x_1"


# ---------------------------------------------------------------------------
# Concrete Tigress instances rewrite to the documented clean forms
# ---------------------------------------------------------------------------


def test_increment_concrete_tigress_instance():
    """c1=0xFFFFFFFE, c2=2 -> k_res=1 -> x + 1 (proved against the clean form)."""
    import z3

    bw = 32
    x = z3.BitVec("x", bw)
    lhs = (x ^ z3.BitVecVal(0xFFFFFFFE, bw)) + ((2 * x) | z3.BitVecVal(2, bw)) + 1
    s = z3.Solver()
    s.add(lhs != x + 1)
    assert s.check() == z3.unsat


def test_add_via_xor_or_concrete_tigress_instance():
    """c1=0xFFFFFFBD (== ~0x42), c2=0x42 -> x + 0x42."""
    import z3

    bw = 32
    x = z3.BitVec("x", bw)
    lhs = (x ^ z3.BitVecVal(0xFFFFFFBD, bw)) + 2 * (x | z3.BitVecVal(0x42, bw)) + 1
    s = z3.Solver()
    s.add(lhs != x + z3.BitVecVal(0x42, bw))
    assert s.check() == z3.unsat


def test_xor_via_sub_or_concrete_tigress_instance():
    """c1=0xE8CF9C3E (== ~0x173063C1), c2=0x173063C3 -> x ^ 0x173063C1."""
    import z3

    bw = 32
    x = z3.BitVec("x", bw)
    lhs = x - 2 * (x | z3.BitVecVal(0xE8CF9C3E, bw)) - z3.BitVecVal(0x173063C3, bw)
    s = z3.Solver()
    s.add(lhs != (x ^ z3.BitVecVal(0x173063C1, bw)))
    assert s.check() == z3.unsat
