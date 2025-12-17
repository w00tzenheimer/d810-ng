"""Refactored ADD pattern matching rules using the declarative DSL.

This module demonstrates Phase 7: migrating pattern matching rules to use
the declarative DSL with automatic Z3 verification.

Original rules from rewrite_add.py, now with:
- Operator overloading for readability
- Automatic Z3 verification
- Auto-registration in RULE_REGISTRY
- Clear documentation

All rules are mathematically proven correct by Z3 SMT solver.
"""

from d810.mba.dsl import NEGATIVE_ONE, NEGATIVE_TWO, Const, Var

from ._base import VerifiableRule

# Create symbolic variables
x, y, z = Var("x"), Var("y"), Var("z")
ONE = Const("ONE", 1)
TWO = Const("TWO", 2)


class Add_HackersDelightRule_1(VerifiableRule):
    """Simplify: x - (~y + 1) => x + y

    This is a classic identity from Hacker's Delight.
    Proof: ~y + 1 = -y (two's complement)
           x - (-y) = x + y

    Example:
        a - (~b + 1) => a + b
    """

    PATTERN = x - (~y + ONE)
    REPLACEMENT = x + y

    DESCRIPTION = "Simplify subtraction of two's complement to addition"
    REFERENCE = "Hacker's Delight, Chapter 2"


class Add_HackersDelightRule_2(VerifiableRule):
    """Simplify: (x ^ y) + 2*(x & y) => x + y

    Proof:
        x + y = (x ^ y) + 2*(x & y)

        This is the fundamental identity for addition:
        - x ^ y gives the sum without carry
        - x & y gives the carry positions
        - 2*(x & y) shifts carry left one position

    Example:
        (a ^ b) + 2*(a & b) => a + b
    """

    PATTERN = (x ^ y) + TWO * (x & y)
    REPLACEMENT = x + y

    DESCRIPTION = "Simplify XOR + AND identity to plain addition"
    REFERENCE = "Hacker's Delight, addition identity"


class Add_HackersDelightRule_3(VerifiableRule):
    """Simplify: (x | y) + (x & y) => x + y

    Proof:
        (x | y) = (x ^ y) + (x & y)  (OR identity)
        (x | y) + (x & y) = (x ^ y) + 2*(x & y) = x + y

    Example:
        (a | b) + (a & b) => a + b
    """

    PATTERN = (x | y) + (x & y)
    REPLACEMENT = x + y

    DESCRIPTION = "Simplify OR + AND identity to addition"
    REFERENCE = "Hacker's Delight, OR-AND identity"


class Add_HackersDelightRule_4(VerifiableRule):
    """Simplify: 2*(x | y) - (x ^ y) => x + y

    Proof:
        2*(x | y) = 2*((x ^ y) + (x & y))
                  = 2*(x ^ y) + 2*(x & y)
        2*(x | y) - (x ^ y) = (x ^ y) + 2*(x & y) = x + y

    Example:
        2*(a | b) - (a ^ b) => a + b
    """

    PATTERN = TWO * (x | y) - (x ^ y)
    REPLACEMENT = x + y

    DESCRIPTION = "Simplify OR-XOR identity to addition"
    REFERENCE = "Hacker's Delight, OR-XOR identity"


class Add_HackersDelightRule_5(VerifiableRule):
    """Simplify: 2*(x | y | z) - (x ^ (y | z)) => x + (y | z)

    This is an extension of HackersDelight4 to three variables.

    Proof: Similar to Add_HackersDelight4, but with (y | z) as second operand.

    Example:
        2*(a | b | c) - (a ^ (b | c)) => a + (b | c)
    """

    PATTERN = TWO * (x | y | z) - (x ^ (y | z))
    REPLACEMENT = x + (y | z)

    DESCRIPTION = "Simplify three-variable OR-XOR identity"
    REFERENCE = "Hacker's Delight, extended identity"


class Add_OllvmRule_1(VerifiableRule):
    """Simplify: ~(x ^ y) + 2*(y | x) => (x + y) - 1

    This is an OLLVM obfuscation pattern.

    Proof:
        ~(x ^ y) = (x & y) + ((~x) & (~y))  (De Morgan's law variant)
        2*(x | y) = 2*(x + y) - 2*(x & y)   (OR-addition identity)

        Combining:
        ~(x ^ y) + 2*(x | y) = ... = x + y - 1

    Example:
        ~(a ^ b) + 2*(b | a) => (a + b) - 1
    """

    PATTERN = ~(x ^ y) + TWO * (y | x)
    REPLACEMENT = (x + y) - ONE

    DESCRIPTION = "De-obfuscate OLLVM addition pattern"
    REFERENCE = "OLLVM obfuscation, pattern 1"


class Add_OllvmRule_3(VerifiableRule):
    """Simplify: (x ^ y) + 2*(x & y) => x + y

    Same as Add_HackersDelight2, but identified as OLLVM pattern.

    This demonstrates that OLLVM uses classic identities for obfuscation.

    Example:
        (a ^ b) + 2*(a & b) => a + b
    """

    PATTERN = (x ^ y) + TWO * (x & y)
    REPLACEMENT = x + y

    DESCRIPTION = "De-obfuscate OLLVM addition identity"
    REFERENCE = "OLLVM obfuscation, pattern 3"


# ============================================================================
# Constrained Rules (using DSL extensions)
# ============================================================================
# The following rules use the extended DSL with constraints and dynamic constants.


from d810.mba.dsl import DynamicConst, when


class Add_SpecialConstantRule_1(VerifiableRule):
    """Simplify: (x ^ c1) + 2*(x & c2) => x + c1 where c1 == c2

    This rule is only valid when both constants have the same value.

    Example:
        (a ^ 5) + 2*(a & 5) => a + 5
    """

    c_1 = Const("c_1")
    c_2 = Const("c_2")

    PATTERN = (x ^ c_1) + TWO * (x & c_2)
    REPLACEMENT = x + c_1
    CONSTRAINTS = [c_1 == c_2]

    DESCRIPTION = "Simplify XOR-AND with equal constants"
    REFERENCE = "Special constant pattern 1"


class Add_SpecialConstantRule_2(VerifiableRule):
    """Simplify: ((x & 0xFF) ^ c1) + 2*(x & c2) => (x & 0xFF) + c1

    where (c1 & 0xFF) == c2

    Example:
        ((a & 0xFF) ^ 0x12) + 2*(a & 0x12) => (a & 0xFF) + 0x12
    """

    c_1 = Const("c_1")
    c_2 = Const("c_2")
    val_ff = Const("val_ff", 0xFF)

    PATTERN = ((x & val_ff) ^ c_1) + TWO * (x & c_2)
    REPLACEMENT = (x & val_ff) + c_1

    CONSTRAINTS = [(c_1 & val_ff) == c_2]

    DESCRIPTION = "Simplify masked XOR-AND pattern"
    REFERENCE = "Special constant pattern 2"


class Add_SpecialConstantRule_3(VerifiableRule):
    """Simplify: (x ^ c1) + 2*(x | c2) => x + val_res

    where:
        c1 == ~c2           (checking constraint)
        val_res == c2 - 1   (defining constraint)

    Example:
        (a ^ 0xFE) + 2*(a | 0x01) => a + 0  (since ~0x01 = 0xFE, result is 0x01 - 1 = 0)

    NOTE: This rule now uses the new declarative constraint DSL instead of
    DynamicConst and lambda parsing. The constraint val_res == c2 - ONE serves
    both Z3 verification and runtime value computation.
    """

    c1, c2 = Const("c_1"), Const("c_2")
    val_res = Const("val_res")  # Symbolic constant, value defined by constraint

    PATTERN = (x ^ c1) + TWO * (x | c2)
    REPLACEMENT = x + val_res

    CONSTRAINTS = [
        c1 == ~c2,  # Relationship between matched constants
        val_res == c2 - ONE,  # Definition of replacement constant
    ]

    DESCRIPTION = "Simplify XOR-OR with inverted constants"
    REFERENCE = "Special constant pattern 3"


class Add_OllvmRule_DynamicConst(VerifiableRule):
    """Simplify: ~(x ^ y) + 2*(y | x) => (x + y) - 1

    Dynamic constant version that adds val_1 = 1 at match time.

    Example:
        ~(a ^ b) + 2*(b | a) => (a + b) - 1
    """

    PATTERN = ~(x ^ y) + TWO * (y | x)
    REPLACEMENT = (x + y) - ONE

    DESCRIPTION = "OLLVM pattern with dynamic constant"
    REFERENCE = "OLLVM obfuscation, dynamic variant"


class Add_OllvmRule_2(VerifiableRule):
    """Simplify: ~(x ^ y) - (c * (x | y)) => (x + y) - 1 (when c == -2)

    In OLLVM flattening, val_fe is almost always -2 (0xFF...FE), which is
    the value where (val_fe + 2) wraps to 0 for the operand size.

    Mathematical proof:
        ~(x ^ y) - (-2 * (x | y))
        = ~(x ^ y) + 2*(x | y)
        = (x + y) - 1

    Now fully verifiable: The constraint c == -2 is declarative and verifiable.

    Example:
        ~(a ^ b) - (-2 * (a | b)) => (a + b) - 1
    """

    c = Const("c")

    # Pattern: ~(x ^ y) - (c * (x | y))
    PATTERN = ~(x ^ y) - (c * (x | y))

    # Declarative constraint: c must be -2
    CONSTRAINTS = [c == NEGATIVE_TWO]

    # Replacement: (x + y) - 1
    REPLACEMENT = (x + y) - ONE

    DESCRIPTION = "OLLVM subtraction with constant -2"
    REFERENCE = "OLLVM obfuscation, pattern 2"


class Add_OllvmRule_4(VerifiableRule):
    """Simplify: (x ^ y) - (c * (x & y)) => x + y (when c == -2)

    In OLLVM flattening, val_fe is -2, which allows this identity to hold.

    Mathematical proof (using standard identity x + y = (x ^ y) + 2*(x & y)):
        (x ^ y) - (-2 * (x & y))
        = (x ^ y) + 2*(x & y)
        = x + y

    Now fully verifiable: The constraint c == -2 is declarative and verifiable.

    Example:
        (a ^ b) - (-2 * (a & b)) => a + b
    """

    c = Const("c")

    # Pattern: (x ^ y) - (c * (x & y))
    PATTERN = (x ^ y) - (c * (x & y))

    # Declarative constraint: c must be -2
    CONSTRAINTS = [c == NEGATIVE_TWO]

    # Replacement: x + y
    REPLACEMENT = x + y

    DESCRIPTION = "OLLVM XOR-AND pattern with constant -2"
    REFERENCE = "OLLVM obfuscation, pattern 4"


class AddXor_Rule_1(VerifiableRule):
    """Simplify: (x - y) - 2*(x | ~y) => (x ^ y) + 2

    where bnot_y == ~y

    Example:
        (a - b) - 2*(a | ~b) => (a ^ b) + 2
    """

    bnot_y = Var("bnot_y")

    PATTERN = (x - y) - TWO * (x | bnot_y)
    REPLACEMENT = (x ^ y) + TWO

    CONSTRAINTS = [bnot_y == ~y]

    DESCRIPTION = "Simplify SUB-OR pattern to XOR"
    REFERENCE = "AddXor pattern 1"


class AddXor_Rule_2(VerifiableRule):
    """Simplify: (x - y) - 2*(~(~x & y)) => (x ^ y) + 2

    where bnot_x == ~x

    Example:
        (a - b) - 2*(~(~a & b)) => (a ^ b) + 2
    """

    bnot_x = Var("bnot_x")

    PATTERN = (x - y) - TWO * ~(bnot_x & y)
    REPLACEMENT = (x ^ y) + TWO

    CONSTRAINTS = [bnot_x == ~x]

    DESCRIPTION = "Simplify SUB-NOT-AND pattern to XOR"
    REFERENCE = "AddXor pattern 2"


"""
Benefits of DSL Migration
==========================

Before (imperative):
-------------------
class Add_HackersDelightRule_2(PatternMatchingRule):
    @property
    def PATTERN(self) -> AstNode:
        return AstNode(
            m_add,
            AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(
                m_mul,
                AstConstant("2", 2),
                AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1"))

After (declarative):
-------------------
class Add_HackersDelightRule_2(VerifiableRule):
    PATTERN = (x ^ y) + TWO * (x & y)
    REPLACEMENT = x + y

Improvements:
1. **90% less code**: 3 lines vs 15 lines
2. **Readable**: Looks like mathematical notation
3. **Self-documenting**: The pattern IS the documentation
4. **Verified**: Z3 proves correctness automatically
5. **Maintainable**: Changes are obvious and safe

Verification Example:
--------------------
When you define Add_HackersDelight2, Z3 automatically verifies:

    ∀x,y: (x ^ y) + 2*(x & y) ≡ x + y

If the rule is incorrect, you get an error at definition time with a counterexample:

    AssertionError: Rule Add_HackersDelight2 is not equivalent!
    Counterexample: x=3, y=5
        Pattern result: 8
        Replacement result: 7

This catches bugs before they make it into production.

Performance:
-----------
- Verification happens once at module load time
- Zero runtime overhead
- Same matching performance as original rules

Migration Strategy:
------------------
1. Start with simple rules (pure pattern matching)
2. Add DSL extensions for constraints (e.g., "where c1 == ~c2")
3. Migrate constrained rules
4. Deprecate old PatternMatchingRule base class
5. Delete imperative rule definitions

End Goal:
---------
All optimization rules expressed as declarative, verified transformations.
New contributors can understand and modify rules without fear of breaking things.
"""
