"""MBA simplification rules for residual Tigress-indirect obfuscated forms.

These rules fold the five obfuscated expression families that survive the
standard OLLVM ``ins_rules`` set on the ``tigress_flatten_indirect`` recovery
output (ticket llr-m9r4). Every rule below is GENERAL: the literal constants
are parameterized as pattern leaf-constants (``Const("c_1")`` etc.) and the
clean replacement constant is derived via a declarative defining constraint,
never hardcoded to the specific Tigress values.

Verification (all proven before landing):

* ``TigressIncrementRule`` -- Z3 proved (32 & 64 bit) under its constraints.
* ``TigressXorViaOrMinusAndRule`` -- Z3 proved (32 & 64 bit), unconstrained.
* ``TigressAddViaXorOrRule`` -- Z3 proved (32 & 64 bit) under its constraint.
* ``TigressXorViaSubOrRule`` -- Z3 proved (32 & 64 bit) under its constraint.
* ``TigressNotEqualSignBitRule`` -- Z3 proved (32 & 64 bit); relational result.
* ``TigressMultiplyBitPartitionRule`` -- bit-partition ALGEBRA + 2,000,000
  random samples (32-bit) + 500,000 (64-bit), 0 mismatches. ``SKIP_VERIFICATION``
  because a full symbolic Z3 multiply proof of this 3-multiply identity times out.

Form 2b ("2*(X|y) - (y^X) == y+X") is intentionally NOT re-added here: it is
already covered exactly by ``add.Add_HackersDelightRule_4`` (``2*(x|y)-(x^y) =>
x+y``), which is already active in the config.
"""

from d810.mba.dsl import Const, Var
from d810.mba.rules._base import VerifiableRule

# Maturity constants (from ida_hexrays): fire early like the other MBA rules.
# MMAT_PREOPTIMIZED=2, MMAT_LOCOPT=3, MMAT_CALLS=4, MMAT_GLBOPT1=5
_ALL_MATURITIES = [2, 3, 4, 5]

# Shared symbolic variables / literal constants.
x, y = Var("x_0"), Var("x_1")
a, b = Var("x_0"), Var("x_1")
bnot_a, bnot_b = Var("bnot_x_0"), Var("bnot_x_1")

ONE = Const("1", 1)
TWO = Const("2", 2)
NEG_ONE = Const("-1", -1)


# ============================================================================
# FORM 1 -- INCREMENT
# ============================================================================


class TigressIncrementRule(VerifiableRule):
    """Simplify: (x ^ c1) + ((2*x) | c2) + 1 => x + (c2 >> 1)

    where ``c2`` is even and ``c1 == ~(c2 >> 1)``.

    This is the increment idiom. Because ``(2*x) | (2*k) == 2*(x | k)`` always
    (left-shift distributes over OR), this family is exactly the OLLVM
    ``(x ^ ~k) + 2*(x | k) + 1 == x + k`` identity (FORM 4) but with the OR
    operand pre-doubled into a literal constant ``c2 = 2k``. The clean result
    constant ``k_res = c2 >> 1`` is derived, never hardcoded.

    Tigress instance: c1=0xFFFFFFFE, c2=2 -> k_res=1 -> ``x + 1``.

    Z3 proved (32 & 64 bit) under the two checking constraints.
    """

    maturities = _ALL_MATURITIES

    c1 = Const("c_1")
    c2 = Const("c_2")
    k_res = Const("k_res")  # derived = c2 >> 1

    PATTERN = (x ^ c1) + ((TWO * x) | c2) + ONE
    REPLACEMENT = x + k_res

    CONSTRAINTS = [
        k_res == c2 >> ONE,        # defining: k = c2 / 2
        (c2 & ONE) == Const("0", 0),  # checking: c2 must be even
        (c1 ^ k_res) == NEG_ONE,   # checking: c1 == ~k_res  (value-based)
    ]

    DESCRIPTION = "Fold (x ^ ~k) + ((2*x) | 2k) + 1 to x + k (increment idiom)"
    REFERENCE = "Tigress indirect residual; llr-m9r4 FORM1"


# ============================================================================
# FORM 6 -- XOR-VIA-OR-MINUS-AND  (AndOr-xor identity)
# ============================================================================


class TigressXorViaOrMinusAndRule(VerifiableRule):
    """Simplify: (x | M) - (x & M) => x ^ M

    The classic AndOr-xor identity: for every bit, ``(or) - (and)`` is exactly
    the set of bits where ``x`` and ``M`` differ, i.e. ``x ^ M``. Holds for ALL
    ``x`` and ``M`` (no constraint); ``M`` is a free leaf so it covers both a
    runtime operand and a literal constant (e.g. the Tigress ``0x42``).

    Tigress instance: ``(v10 | 0x42) - (v10 & 0x42)`` -> ``v10 ^ 0x42``.

    Z3 proved (32 & 64 bit), unconstrained.
    """

    maturities = _ALL_MATURITIES

    PATTERN = (x | y) - (x & y)
    REPLACEMENT = x ^ y

    DESCRIPTION = "Fold (x | M) - (x & M) to x ^ M (AndOr-xor identity)"
    REFERENCE = "Tigress indirect residual; llr-wna1 FORM6"


# ============================================================================
# FORM 4 -- ADD-VIA-XOR-OR
# ============================================================================


class TigressAddViaXorOrRule(VerifiableRule):
    """Simplify: (x ^ c1) + 2*(x | c2) + 1 => x + c2

    where ``c1 == ~c2``.

    Tigress instance: c1=0xFFFFFFBD (== ~0x42), c2=0x42 -> ``x + 0x42``.

    Z3 proved (32 & 64 bit) under the checking constraint.
    """

    maturities = _ALL_MATURITIES

    c1 = Const("c_1")
    c2 = Const("c_2")

    PATTERN = (x ^ c1) + TWO * (x | c2) + ONE
    REPLACEMENT = x + c2

    CONSTRAINTS = [
        (c1 ^ c2) == NEG_ONE,  # c1 == ~c2  (value-based)
    ]

    DESCRIPTION = "Fold (x ^ ~M) + 2*(x | M) + 1 to x + M"
    REFERENCE = "Tigress indirect residual; llr-m9r4 FORM4"


# ============================================================================
# FORM 5 -- XOR-VIA-SUB-OR (store)
# ============================================================================


class TigressXorViaSubOrRule(VerifiableRule):
    """Simplify: x - 2*(x | c1) - c2 => x ^ k_res

    where ``k_res = ~c1`` and ``c2 == k_res + 2`` (i.e. c1 == ~K, c2 == K + 2).

    Tigress instance: c1=0xE8CF9C3E (== ~0x173063C1), c2=0x173063C3
    (== 0x173063C1 + 2) -> ``x ^ 0x173063C1``.

    Z3 proved (32 & 64 bit) under the checking constraint.
    """

    maturities = _ALL_MATURITIES

    c1 = Const("c_1")
    c2 = Const("c_2")
    k_res = Const("k_res")  # derived = ~c1

    PATTERN = x - TWO * (x | c1) - c2
    REPLACEMENT = x ^ k_res

    CONSTRAINTS = [
        k_res == ~c1,          # defining: K = ~c1   (value-based; left is fresh)
        c2 == (k_res + TWO),   # checking: c2 == K + 2
    ]

    DESCRIPTION = "Fold x - 2*(x | ~K) - (K + 2) to x ^ K"
    REFERENCE = "Tigress indirect residual; llr-m9r4 FORM5"


# ============================================================================
# FORM 3 -- SIGN-BIT RELATIONAL ("is not equal")
# ============================================================================


class TigressNotEqualSignBitRule(VerifiableRule):
    """Simplify: (((d.sar(0x1F) & (2*d)) - d) >> 0x1F) => (x != y)  [32-bit]

    where ``d = x - y``. The inner shift is an arithmetic shift (sign replicate)
    by the top-bit index; the outer shift is a logical shift extracting the
    resulting sign bit as 0/1. The whole thing is the classic "non-zero -> 1"
    idiom, so with ``d = x - y`` it equals the boolean predicate ``x != y``.
    The replacement is a comparison (lowers to ``setnz`` of ``x - y``), not
    arithmetic.

    The shift amount is the operand-width top-bit index, which is concrete in
    the microcode (0x1F for 32-bit, 0x3F for 64-bit). The identity is ONLY valid
    when the shift equals ``width - 1``; an unconstrained shift constant is NOT
    equivalent. We therefore pin the literal per width: this rule handles the
    32-bit case (BIT_WIDTH=32) and ``TigressNotEqualSignBitRule64`` the 64-bit
    case. The Tigress ``activationCode != ref_input_value`` form is 32-bit.

    Z3 proved at 32-bit with the pinned 0x1F shift.
    """

    maturities = _ALL_MATURITIES
    BIT_WIDTH = 32

    SH = Const("0x1F", 0x1F)
    d = x - y

    PATTERN = (((d.sar(SH) & (TWO * d)) - d) >> SH)
    REPLACEMENT = (x != y).to_int()

    DESCRIPTION = "Fold sign-bit non-zero idiom over (x - y) to (x != y) [32-bit]"
    REFERENCE = "Tigress indirect residual; llr-m9r4 FORM3"


class TigressNotEqualSignBitRule64(VerifiableRule):
    """Simplify: (((d.sar(0x3F) & (2*d)) - d) >> 0x3F) => (x != y)  [64-bit]

    64-bit sibling of :class:`TigressNotEqualSignBitRule`; the top-bit index is
    0x3F. See that class for the full derivation.

    Z3 proved at 64-bit with the pinned 0x3F shift.
    """

    maturities = _ALL_MATURITIES
    BIT_WIDTH = 64

    SH = Const("0x3F", 0x3F)
    d = x - y

    PATTERN = (((d.sar(SH) & (TWO * d)) - d) >> SH)
    REPLACEMENT = (x != y).to_int()

    DESCRIPTION = "Fold sign-bit non-zero idiom over (x - y) to (x != y) [64-bit]"
    REFERENCE = "Tigress indirect residual; llr-m9r4 FORM3"


# ============================================================================
# FORM 2a -- MULTIPLY (bit-partition identity)
# ============================================================================


class TigressMultiplyBitPartitionRule(VerifiableRule):
    """Simplify: (a & ~b)*(~a & b) + (a | b)*(a & b) => a * b

    Requires ``bnot_a == ~a`` and ``bnot_b == ~b``.

    Bit-partition algebra proof: let X = a & ~b, Y = a & b, Z = ~a & b (disjoint
    bit sets), so a = X + Y and b = Y + Z. Then
        LHS = X*Z + (X+Y+Z)*Y = XZ + XY + Y^2 + YZ
        RHS = a*b = (X+Y)*(Y+Z) = XY + XZ + Y^2 + YZ
    LHS - RHS = 0 in the ring Z/2^n -- holds for ALL a, b.

    Cross-checked with 2,000,000 random 32-bit samples + 500,000 random 64-bit
    samples + edge cases: 0 mismatches.

    SKIP_VERIFICATION: a full symbolic Z3 proof of this 3-multiply identity times
    out (same rationale as ``mul.Mul_MBA_1`` / ``Mul_MBA_4``). Lowers to ``m_mul``.

    Tigress instance: ``password[i] * ref_input_value``.
    """

    maturities = _ALL_MATURITIES

    SKIP_VERIFICATION = True  # 3 multiplications -> Z3 times out; proven by algebra + 2.5M samples

    PATTERN = (a & bnot_b) * (bnot_a & b) + (a | b) * (a & b)
    REPLACEMENT = a * b

    CONSTRAINTS = [
        bnot_a == ~a,
        bnot_b == ~b,
    ]

    DESCRIPTION = "Fold (a & ~b)*(~a & b) + (a | b)*(a & b) to a * b"
    REFERENCE = "Tigress indirect residual; llr-m9r4 FORM2a"
