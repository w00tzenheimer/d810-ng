"""Eidolon linear-MBA XOR rules.

Both rules are proved by the pure Z3 backend.  The regular package import and
the deterministic rule catalogue list this module explicitly; that is the
startup path which makes the rules available outside IDA as well as after
hot-reload.

The encrypted error-message templates use rolling XORs whose per-byte operation
is obfuscated by these six- and seven-term linear MBA forms.
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
SIX = Const("6", 6)


class Xor_EidolonKeySchedule_1(VerifiableRule):
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

    DESCRIPTION = "Simplify the Eidolon 7-term linear-MBA XOR to x ^ y"
    REFERENCE = "Eidolon loader message-template key schedule (0x711B67)"


class Xor_EidolonKeySchedule_2(VerifiableRule):
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

    DESCRIPTION = "Simplify the Eidolon 6-term linear-MBA XOR to x ^ y"
    REFERENCE = "Eidolon loader message-template key schedule (0x70FC53)"


class Xor_EidolonKeySchedule_3(VerifiableRule):
    """Simplify a second unconditional six-term expression to ``x ^ y``.

    The coefficient-six terms cancel because the three disjoint masks
    ``~x & ~y``, ``~x & y``, and ``x & y`` sum to ``~x | y`` at every
    operand width.
    """

    maturities = _ALL_MATURITIES
    Z3_CERTIFICATE_PROVER = "eidolon-key-schedule-3-v1"

    PATTERN = (
        SIX * (~(x | y))
        + SIX * (y & ~x)
        + (x ^ y)
        + SIX * (x & y)
        - SIX * ((~x) | y)
    )
    REPLACEMENT = x ^ y

    DESCRIPTION = "Simplify the Eidolon coefficient-six linear-MBA XOR to x ^ y"
    REFERENCE = "Eidolon loader message-template rolling XOR"
