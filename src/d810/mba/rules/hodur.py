"""HODUR obfuscation pattern rules (Declarative DSL version).

HODUR is an obfuscator that applies complex algebraic transformations.
These rules simplify the obfuscated patterns back to cleaner code.

All rules have been migrated to the declarative DSL and are automatically
verified with Z3.
"""

from d810.mba.dsl import Const, Var, ONE, ZERO
from d810.mba.rules._base import VerifiableRule

# Common variables for HODUR patterns
x = Var("x")
y = Var("y")
z = Var("z")


class Xor_Hodur_1(VerifiableRule):
    """Simplify: ~(x ^ (y ^ z)) => x ^ (y ^ ~z)

    Mathematical proof using XOR properties:
        ~(x ^ (y ^ z))
        = ~((x ^ y) ^ z)    [XOR associativity]
        = (x ^ y) ^ ~z      [DeMorgan for XOR]
        = x ^ (y ^ ~z)      [XOR associativity]

    Example (HODUR pattern 1):
        ~(enc[i] ^ ((i - 0x1D) ^ 0x1C))
        => enc[i] ^ ((i - 0x1D) ^ ~0x1C)
        => enc[i] ^ ((i - 0x1D) ^ 0xE3)
    """

    PATTERN = ~(x ^ (y ^ z))
    REPLACEMENT = x ^ (y ^ ~z)

    DESCRIPTION = "HODUR: Distribute NOT through nested XOR"
    REFERENCE = "HODUR obfuscator, pattern 1"


class Bnot_Hodur_1(VerifiableRule):
    """Simplify: ((c_0 - x) & bnot_z) ^ ((x - c_3) & z) => ~((x - c_3) ^ z)

    This rule handles a complex HODUR pattern where:
    - c_0 and c_3 are consecutive constants (c_0 + 1 == c_3)
    - bnot_z is the bitwise NOT of z

    Mathematical proof (when c_0 + 1 == c_3 and bnot_z == ~z):
        c_0 - x = -(x - c_0) = -(x - (c_3 - 1)) = -(x - c_3 + 1)
        In two's complement: ~y = -y - 1, so -y = ~y + 1
        Therefore: -(x - c_3 + 1) = ~(x - c_3 + 1) + 1 = ~(x - c_3) + ~1 + 1 = ~(x - c_3)

        So: (c_0 - x) & bnot_z = ~(x - c_3) & ~z

        Using DeMorgan's laws:
        (~(x - c_3) & ~z) ^ ((x - c_3) & z)
        = ~((x - c_3) | z) ^ ((x - c_3) & z)
        = ... [complex derivation]
        = ~((x - c_3) ^ z)

    Example (HODUR pattern 2):
        ((0x1C - i) & 0xFA) ^ ((i - 0x1D) & 5)
        => ~((i - 0x1D) ^ 5)
    """

    c_0 = Const("c_0")
    c_3 = Const("c_3")
    bnot_z = Var("bnot_z")

    PATTERN = ((c_0 - x) & bnot_z) ^ ((x - c_3) & z)
    REPLACEMENT = ~((x - c_3) ^ z)

    # Constraints:
    # 1. c_0 and c_3 must be consecutive constants
    # 2. bnot_z must be the bitwise NOT of z
    CONSTRAINTS = [c_0 + ONE == c_3, bnot_z == ~z]

    DESCRIPTION = "HODUR: Simplify consecutive constant pattern with BNOT"
    REFERENCE = "HODUR obfuscator, pattern 2"


class Or_Hodur_1(VerifiableRule):
    """Simplify: ((~x & c_0) | (x & c_1)) | (~x & c_2) => (~x & (c_0 | c_2)) | (x & c_1)

    This is simple boolean factoring using the distributive law:
        (A & B) | (A & C) = A & (B | C)

    Applied here:
        (~x & c_0) | (~x & c_2) = ~x & (c_0 | c_2)

    Example (HODUR pattern 3):
        (~enc[i] & 0xE3) | (enc[i] & 4) | (~enc[i] & 0x18)
        => (~enc[i] & (0xE3 | 0x18)) | (enc[i] & 4)
        => (~enc[i] & 0xFB) | (enc[i] & 4)
    """

    c_0 = Const("c_0")
    c_1 = Const("c_1")
    c_2 = Const("c_2")

    PATTERN = ((~x & c_0) | (x & c_1)) | (~x & c_2)
    REPLACEMENT = (~x & (c_0 | c_2)) | (x & c_1)

    DESCRIPTION = "HODUR: Factor OR with multiple AND terms"
    REFERENCE = "HODUR obfuscator, pattern 3"


class Or_Hodur_2(VerifiableRule):
    """Simplify: (x & (y ^ c_0)) | ((y ^ bnot_c_0) & ~x) => x ^ (y ^ bnot_c_0)

    This rule handles a pattern where bnot_c_0 is the bitwise NOT of c_0.

    Mathematical proof (when bnot_c_0 == ~c_0):
        Note: y ^ c_0 and y ^ bnot_c_0 = y ^ ~c_0

        Using the identity: (A & B) | (~A & C) = (A & B) | (~A & C)

        When we have: (x & (y ^ c_0)) | (~x & (y ^ ~c_0))

        This is a MUX (multiplexer) pattern:
        - If x is all 1's: result = y ^ c_0
        - If x is all 0's: result = y ^ ~c_0

        Using XOR properties, this simplifies to: x ^ (y ^ ~c_0)

    Example (HODUR pattern 4):
        (x & (y ^ 0x1C)) | ((y ^ 0xE3) & ~x)
        => x ^ (y ^ 0xE3)  [when 0xE3 == ~0x1C]
    """

    c_0 = Const("c_0")
    bnot_c_0 = Const("bnot_c_0")

    PATTERN = (x & (y ^ c_0)) | ((y ^ bnot_c_0) & ~x)
    REPLACEMENT = x ^ (y ^ bnot_c_0)

    # Constraint: bnot_c_0 must be the bitwise NOT of c_0
    CONSTRAINTS = [bnot_c_0 == ~c_0]

    DESCRIPTION = "HODUR: Simplify MUX pattern with XOR"
    REFERENCE = "HODUR obfuscator, pattern 4"


class Xor_Hodur_2(VerifiableRule):
    """Simplify: (x - c_0) ^ (y ^ c_1) => (x + c_1) ^ (y ^ c_1) when c_0 + c_1 = 256

    This rule handles HODUR's use of modular arithmetic where c_0 + c_1 = 256.

    BYTE-SPECIFIC VERIFICATION: This rule uses 8-bit Z3 bitvectors for verification.
    In byte arithmetic: -c_0 ≡ c_1 (mod 256) when c_0 + c_1 = 256
    Therefore: x - c_0 ≡ x + c_1 (mod 256)

    Mathematical proof (8-bit arithmetic):
        c_0 + c_1 = 256 ≡ 0 (mod 256)
        Therefore: c_1 ≡ -c_0 (mod 256)
        So: x - c_0 ≡ x + c_1 (mod 256)
        And: (x - c_0) ^ (y ^ c_1) ≡ (x + c_1) ^ (y ^ c_1)

    Example (HODUR pattern 5, with c_0=0x1D=29, c_1=0xE3=227):
        0x1D + 0xE3 = 256 = 0x100 (wraps to 0 in byte arithmetic)
        (y - 0x1D) ^ (x ^ 0xE3) => (y + 0xE3) ^ (x ^ 0xE3)

    Now fully verifiable with 8-bit Z3 bitvectors!
    """

    # Use 8-bit verification for byte-specific rule
    BIT_WIDTH = 8

    c_0 = Const("c_0")
    c_1 = Const("c_1")

    PATTERN = (x - c_0) ^ (y ^ c_1)
    REPLACEMENT = (x + c_1) ^ (y ^ c_1)

    def get_constraints(self, z3_vars):
        """Custom constraint: c_0 + c_1 == 0 in 8-bit arithmetic.

        This override provides explicit Z3 constraint generation.
        At 8-bit width, 256 wraps to 0, so c_0 + c_1 == 0 means they sum to 256.
        """
        import z3

        if "c_0" not in z3_vars or "c_1" not in z3_vars:
            return []

        # Explicit constraint: sum must be zero (representing 256 overflow in 8-bit)
        return [z3_vars["c_0"] + z3_vars["c_1"] == z3.BitVecVal(0, 8)]

    def check_candidate(self, candidate):
        """Runtime check: verify c_0 + c_1 == 256 with actual values.

        The Z3 constraint checks (c_0 + c_1) == 0 in 8-bit arithmetic.
        At runtime, we need to verify the actual constant values sum to 256.
        """
        if (candidate["c_0"].value is None) or (candidate["c_1"].value is None):
            return False
        return (candidate["c_0"].value + candidate["c_1"].value) == 256

    DESCRIPTION = "HODUR: Convert subtraction to addition using modular arithmetic (byte-specific)"
    REFERENCE = "HODUR obfuscator, pattern 5"
