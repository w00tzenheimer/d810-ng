"""Miscellaneous optimization rules using declarative DSL.

This module contains "Weird" rules - complex algebraic identities that don't
fit neatly into a single operation category. These rules often involve
combinations of addition, subtraction, and bitwise operations.

These were called "WeirdRule" in the original d810 codebase because they
represent non-obvious algebraic simplifications discovered through
mathematical analysis.

All rules are verified using Z3 SMT solver.
"""

from d810.core.bits import AND_TABLE
from d810.mba.dsl import Var, Const, DynamicConst, when
from d810.mba.rules._base import VerifiableRule

# Define variables for pattern matching
x, y, z = Var("x_0"), Var("x_1"), Var("x_2")
bnot_x = Var("bnot_x_0")
bnot_y = Var("bnot_x_1")

# Common constants
ZERO = Const("ZERO", 0)
ONE = Const("ONE", 1)
TWO = Const("TWO", 2)


# ============================================================================
# Complex Algebraic Simplifications ("Weird Rules")
# ============================================================================


class WeirdRule1(VerifiableRule):
    """Simplify: x - (x | y) => (x | ~y) + 1

    Complex algebraic identity involving subtraction and bitwise OR.
    """

    PATTERN = x - (x | y)
    REPLACEMENT = (x | ~y) + ONE

    DESCRIPTION = "Algebraic simplification: x - (x | y)"
    REFERENCE = "Complex algebraic identity"


class WeirdRule2(VerifiableRule):
    """Simplify: 2*x - (x & ~y) => x + (x & y)

    Distributive property with bitwise operations.
    """

    PATTERN = (TWO * x) - (x & ~y)
    REPLACEMENT = x + (x & y)

    DESCRIPTION = "Simplify 2*x - (x & ~y) to x + (x & y)"
    REFERENCE = "Bitwise distributive law"


class WeirdRule3(VerifiableRule):
    """Simplify: (x & ~y) - 2*x => -1 * (x + (x & y))

    Negative factorization with bitwise operations.
    """

    PATTERN = (x & ~y) - (TWO * x)
    REPLACEMENT = -((x + (x & y)))

    DESCRIPTION = "Simplify (x & ~y) - 2*x to -(x + (x & y))"
    REFERENCE = "Negative factorization"


class WeirdRule4(VerifiableRule):
    """Simplify: (x & ~y) - (x & y) => (x ^ y) - y

    Requires bnot_x_1 is bitwise NOT of x_1.
    """

    PATTERN = (x & bnot_y) - (x & y)
    REPLACEMENT = (x ^ y) - y

    CONSTRAINTS = [
        bnot_y == ~y
    ]

    DESCRIPTION = "Simplify (x & ~y) - (x & y) to (x ^ y) - y"
    REFERENCE = "XOR extraction from masked subtraction"


class WeirdRule5(VerifiableRule):
    """Simplify: (~x | (~y & z)) + (x + (y & z)) - z => x | (y | ~z)

    Highly complex three-variable identity with NOT, OR, AND operations.
    This is one of the most complex algebraic simplifications in d810.
    """

    PATTERN = ((bnot_x | (bnot_y & z)) + (x + (y & z))) - z
    REPLACEMENT = x | (y | ~z)

    CONSTRAINTS = [
        bnot_x == ~x,
        bnot_y == ~y
    ]

    DESCRIPTION = "Complex 3-variable identity to OR form"
    REFERENCE = "Advanced Boolean algebra"


class WeirdRule6(VerifiableRule):
    """Simplify: (x | y) + (x & ~y) => (x ^ y) + x

    Algebraic conversion to XOR form.
    """

    PATTERN = (x | y) + (x & ~y)
    REPLACEMENT = (x ^ y) + x

    DESCRIPTION = "Simplify (x | y) + (x & ~y) to (x ^ y) + x"
    REFERENCE = "OR-AND to XOR conversion"


# ============================================================================
# Summary
# ============================================================================

"""
Total Misc rules: 6
- Complex algebraic identities: 6 rules ("Weird Rules")

All rules verified by Z3 SMT solver.

These rules demonstrate advanced algebraic techniques:
- Distributive laws with bitwise operations
- Negative factorization
- XOR extraction from complex expressions
- Multi-variable Boolean algebra identities

The "Weird" naming comes from the original d810 codebase and reflects
that these identities are non-obvious and were likely discovered through
systematic mathematical analysis or from real-world obfuscation patterns.
"""
