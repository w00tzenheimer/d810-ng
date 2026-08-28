"""Eid MBA identities recovered from loader and VM expressions.

Every rule is proved by the pure Z3 backend.  The regular package import and
the deterministic rule catalogue list this module explicitly; that is the
startup path which makes the rules available outside IDA as well as after
hot-reload.

The catalogue includes rolling key-schedule XORs, S-box index arithmetic,
masked partitions, a repeated masked-operand OR, and exact complementary-mask
partitions observed in VM helper returns.
"""

from d810.mba.dsl import Const, Var
from d810.mba.maturity import MicrocodeMaturity
from d810.mba.rules._base import VerifiableRule


# These rules need the whole native optimization window.  GLBOPT2 is included
# because the key-schedule expression can become contiguous only after global
# CFG simplification; ``MicrocodeMaturity`` remains SDK-free and compares
# directly with the native integer passed to the legacy instruction matcher.
_ALL_MATURITIES = [
    MicrocodeMaturity.PREOPTIMIZED,
    MicrocodeMaturity.LOCOPT,
    MicrocodeMaturity.CALLS,
    MicrocodeMaturity.GLBOPT1,
    MicrocodeMaturity.GLBOPT2,
]

x, y = Var("x_0"), Var("x_1")
ONE = Const("1", 1)
TWO = Const("2", 2)
THREE = Const("3", 3)
FOUR = Const("4", 4)
FIVE = Const("5", 5)
SIX = Const("6", 6)
SEVEN = Const("7", 7)
EIGHT = Const("8", 8)
ELEVEN = Const("11", 11)
NEG_EIGHT = Const("-8", -8)

COMPLEMENT_1_LEFT = Const("0xF500C38D0EA2975A", 0xF500C38D0EA2975A)
COMPLEMENT_1_RIGHT = Const("0x0AFF3C72F15D68A5", 0x0AFF3C72F15D68A5)
COMPLEMENT_1_RIGHT_MINUS_ONE = Const(
    "0x0AFF3C72F15D68A4", 0x0AFF3C72F15D68A4
)
COMPLEMENT_2_LEFT = Const("0x4C8ADE951AD35D8C", 0x4C8ADE951AD35D8C)
COMPLEMENT_2_RIGHT = Const("0xB375216AE52CA273", 0xB375216AE52CA273)
COMPLEMENT_3_MASK = Const("0x3C33682BB7D99927", 0x3C33682BB7D99927)
REPEATED_OPERAND_MASK = Const("0xFFFFFBFB", 0xFFFFFBFB)

SBOX_OFFSET_13 = Const("0x13", 0x13)
SBOX_OFFSET_13_LOW_CLEAR = Const(
    "0x7FFFFFFFFFFFFFEC", 0x7FFFFFFFFFFFFFEC
)
SBOX_OFFSET_13_CLEAR = Const("0xFFFFFFFFFFFFFFEC", 0xFFFFFFFFFFFFFFEC)
SBOX_OFFSET_13_BIAS = Const("0x49", 0x49)
SBOX_OFFSET_23 = Const("0x23", 0x23)
SBOX_OFFSET_23_LOW_CLEAR = Const(
    "0x7FFFFFFFFFFFFFDC", 0x7FFFFFFFFFFFFFDC
)
SBOX_OFFSET_23_CLEAR = Const("0xFFFFFFFFFFFFFFDC", 0xFFFFFFFFFFFFFFDC)
SBOX_OFFSET_23_BIAS = Const("0x89", 0x89)
SBOX_OFFSET_27 = Const("0x27", 0x27)
SBOX_OFFSET_27_LOW_CLEAR = Const(
    "0x7FFFFFFFFFFFFFD8", 0x7FFFFFFFFFFFFFD8
)
SBOX_OFFSET_27_QUARTER_CLEAR = Const(
    "0x3FFFFFFFFFFFFFD8", 0x3FFFFFFFFFFFFFD8
)


class Add_EidSboxOffset13_1(VerifiableRule):
    """Collapse the first fixed Eid S-box index MBA to ``x + 0x13``."""

    maturities = _ALL_MATURITIES

    PATTERN = (
        TWO * (x & SBOX_OFFSET_13)
        - SIX * (x & SBOX_OFFSET_13_LOW_CLEAR)
        + ELEVEN * (x & SBOX_OFFSET_13_CLEAR)
        - SEVEN * x
        + SBOX_OFFSET_13_BIAS
        - THREE * ((~x) & SBOX_OFFSET_13)
        - THREE * (~x)
    )
    REPLACEMENT = x + SBOX_OFFSET_13

    DESCRIPTION = "Simplify the Eid S-box index MBA to x + 0x13"
    REFERENCE = "Eid packet-loop S-box index at offset 0x13"


class Add_EidSboxOffset23_1(VerifiableRule):
    """Collapse the second fixed Eid S-box index MBA to ``x + 0x23``."""

    maturities = _ALL_MATURITIES

    PATTERN = (
        TWO * (x & SBOX_OFFSET_23)
        - SIX * (x & SBOX_OFFSET_23_LOW_CLEAR)
        + ELEVEN * (x & SBOX_OFFSET_23_CLEAR)
        - SEVEN * x
        + SBOX_OFFSET_23_BIAS
        - THREE * ((~x) & SBOX_OFFSET_23)
        - THREE * (~x)
    )
    REPLACEMENT = x + SBOX_OFFSET_23

    DESCRIPTION = "Simplify the Eid S-box index MBA to x + 0x23"
    REFERENCE = "Eid packet-loop S-box index at offset 0x23"


class Bnot_EidSboxOffset27_1(VerifiableRule):
    """Collapse the staged 0x27 S-box MBA to ``~(x + 0x27)``."""

    maturities = _ALL_MATURITIES

    PATTERN = ~(
        ((~x) | SBOX_OFFSET_27)
        - THREE
        - (
            TWO * (x & SBOX_OFFSET_27_LOW_CLEAR)
            + TWO * (x & SBOX_OFFSET_27)
        )
        - FOUR * ((~x) & SBOX_OFFSET_27_QUARTER_CLEAR)
        - THREE * ((~x) & SBOX_OFFSET_27)
    )
    REPLACEMENT = ~(x + SBOX_OFFSET_27)

    DESCRIPTION = "Simplify the Eid staged S-box index MBA to ~(x + 0x27)"
    REFERENCE = "Eid packet-loop staged S-box index at offset 0x27"


class Or_EidRepeatedMaskedOperand_1(VerifiableRule):
    """Collapse an Eid MBA with one repeated masked operand.

    Encoding the observed mask in the verified pattern lets the structural AC
    matcher bind the underlying ``y`` leaf consistently even when an enclosing
    AND flattens the compound operand.
    """

    maturities = _ALL_MATURITIES

    masked_y = y & REPEATED_OPERAND_MASK

    PATTERN = (
        (x ^ masked_y)
        - ((x & masked_y) + TWO * (masked_y & ~x))
        + TWO * masked_y
    )
    REPLACEMENT = x | masked_y

    DESCRIPTION = "Simplify the Eid repeated-mask MBA to x | (y & 0xFFFFFBFB)"
    REFERENCE = "Eid VM dispatcher residual with a repeated masked operand"


class Xor_EidKeySchedule_1(VerifiableRule):
    """Simplify a constrained seven-term linear-MBA expression to ``x ^ y``.

    The identity holds at every operand width when ``c_1 == -c_2``.  It was
    observed at 0x711B67 with byte coefficients ``c_1=0xF5`` and ``c_2=0x0B``.
    """

    maturities = _ALL_MATURITIES

    c_1 = Const("c_1")
    c_2 = Const("c_2")

    PATTERN = (
        (~y)
        + c_1 * (x & y)
        + (x | y)
        + c_2 * x
        + (y & ~x)
        - c_2 * (~((~x) | y))
        + ONE
    )
    REPLACEMENT = x ^ y

    CONSTRAINTS = [c_1 == -c_2]

    DESCRIPTION = "Simplify the Eid 7-term linear-MBA XOR to x ^ y"
    REFERENCE = "Eid loader message-template key schedule (0x711B67)"


class Xor_EidKeySchedule_2(VerifiableRule):
    """Simplify an unconditional six-term linear-MBA expression to ``x ^ y``.

    This form was observed at 0x70FC53 on byte operands and is valid at every
    operand width.
    """

    maturities = _ALL_MATURITIES

    PATTERN = (
        TWO * (x & ~y)
        + (~(x | y))
        + (~(x & y))
        + TWO * ((~x) & y)
        + TWO * (x & y)
        + TWO
    )
    REPLACEMENT = x ^ y

    DESCRIPTION = "Simplify the Eid 6-term linear-MBA XOR to x ^ y"
    REFERENCE = "Eid loader message-template key schedule (0x70FC53)"


class Xor_EidKeySchedule_3(VerifiableRule):
    """Simplify a second unconditional six-term expression to ``x ^ y``.

    The coefficient-six terms cancel because the three disjoint masks
    ``~x & ~y``, ``~x & y``, and ``x & y`` sum to ``~x | y`` at every
    operand width.
    """

    maturities = _ALL_MATURITIES
    Z3_CERTIFICATE_PROVER = "eid-key-schedule-3-v1"

    PATTERN = (
        SIX * (~(x | y))
        + SIX * (y & ~x)
        + (x ^ y)
        + SIX * (x & y)
        - SIX * ((~x) | y)
    )
    REPLACEMENT = x ^ y

    DESCRIPTION = "Simplify the Eid coefficient-six linear-MBA XOR to x ^ y"
    REFERENCE = "Eid loader message-template rolling XOR"


class Xor_EidComplementConsensus_1(VerifiableRule):
    """Collapse a three-term complement consensus identity to ``x ^ y``."""

    maturities = _ALL_MATURITIES

    PATTERN = TWO * (~(x & y)) - (x ^ y) - TWO * (~(x | y))
    REPLACEMENT = x ^ y

    DESCRIPTION = "Simplify the Eid complement consensus MBA to x ^ y"
    REFERENCE = "Eid packet metadata write-back"


class Xor_EidComplementPartition_1(VerifiableRule):
    """Collapse an observed complementary-mask partition to one XOR.

    The constants satisfy ``right == ~left`` and
    ``right_minus_one == right - 1``.  They remain fixed here so ordinary Z3
    verification is fast and this rule does not need a bespoke certificate
    prover owned by the residual-rule-discovery work.
    """

    maturities = _ALL_MATURITIES

    PATTERN = (
        EIGHT * (~(x | COMPLEMENT_1_LEFT))
        + (x | COMPLEMENT_1_LEFT)
        + (x & COMPLEMENT_1_RIGHT)
        + SIX * (x & COMPLEMENT_1_LEFT)
        - COMPLEMENT_1_RIGHT_MINUS_ONE
        - FIVE * (x ^ COMPLEMENT_1_RIGHT)
    )
    REPLACEMENT = x ^ COMPLEMENT_1_RIGHT

    DESCRIPTION = "Simplify the Eid complementary partition MBA to x ^ c_2"
    REFERENCE = "Eid VM helper return using complementary 64-bit masks"


class Xor_EidComplementPartition_2(VerifiableRule):
    """Collapse the observed coefficient-six complement partition to XOR."""

    maturities = _ALL_MATURITIES

    PATTERN = (
        SIX * (~(x | COMPLEMENT_2_LEFT))
        + (x ^ COMPLEMENT_2_LEFT)
        + SIX * (x & COMPLEMENT_2_RIGHT)
        + SIX * (x & COMPLEMENT_2_LEFT)
        - SIX * (x | COMPLEMENT_2_RIGHT)
    )
    REPLACEMENT = x ^ COMPLEMENT_2_LEFT

    DESCRIPTION = "Simplify the Eid coefficient-six complement partition to XOR"
    REFERENCE = "Eid VM helper switch case 0x52"


class Xor_EidComplementPartition_3(VerifiableRule):
    """Collapse an observed masked coefficient partition to one XOR."""

    maturities = _ALL_MATURITIES

    PATTERN = NEG_EIGHT - (
        (x & COMPLEMENT_3_MASK)
        + SIX * (x | COMPLEMENT_3_MASK)
        + EIGHT * (~(x | COMPLEMENT_3_MASK))
        + (x | COMPLEMENT_3_MASK)
    )
    REPLACEMENT = x ^ COMPLEMENT_3_MASK

    DESCRIPTION = "Simplify the Eid masked coefficient partition to XOR"
    REFERENCE = "Eid VM helper switch case 0x54"
