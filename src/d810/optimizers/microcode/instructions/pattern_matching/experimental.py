"""Context-aware move instruction rules using the declarative DSL.

These rules demonstrate the context-aware DSL for pattern matching rules that need
to inspect or modify the instruction context beyond the source operands.
"""

from d810.mba.dsl import Const, Var
from d810.optimizers.extensions import context, when
from d810.mba.rules import VerifiableRule

# Common variables
c_0 = Const("c_0")
full_reg = Var("full_reg")


class ReplaceMovHighContext(VerifiableRule):
    """Fix IDA's constant propagation limitation for high-half register writes.

    IDA does not perform constant propagation for patterns like:
        mov #0x65A4.2, r6.2      ; Low half
        mov #0x210F.2, r6^2.2    ; High half (THIS IS THE PROBLEM)
        jz  r0.4, r6.4           ; IDA doesn't know r6 = 0x210F65A4

    This rule transforms:
        mov #c, rX^2  →  mov ((rX & 0xFFFF) | (#c << 16)), rX

    By writing to the full register with the computed value, IDA's constant
    propagation can now track the full 32-bit value.

    Context-aware features used:
    - when.dst.is_high_half: Checks if destination is high-half register (e.g., r6^2)
    - context.dst.parent_register: Binds the full register (e.g., r6 from r6^2)
    - UPDATE_DESTINATION: Changes destination from r6^2 to r6

    Example:
        Before: mov #0x210F.2, r6^2.2
        After:  mov #0x210F0000 | (r6 & 0xFFFF), r6.4
    """

    # Pattern: mov #constant, dst (where dst is checked by constraint)
    PATTERN = c_0

    # Replacement: (#c << 16) | (full_reg & 0xFFFF)
    # Combines the new high bits with the existing low bits
    REPLACEMENT = (c_0 << 16) | (full_reg & 0xFFFF)

    # Constraint: Destination must be a high-half register (e.g., r6^2)
    CONSTRAINTS = [
        when.dst.is_high_half
    ]

    # Context: Bind 'full_reg' to the parent register (e.g., r6 from r6^2)
    CONTEXT_VARS = {
        "full_reg": context.dst.parent_register
    }

    # Side effect: Change destination from r6^2 to r6
    UPDATE_DESTINATION = "full_reg"

    # Skip verification: This rule changes the destination size and semantics
    # The verification would need special handling for size mismatches
    SKIP_VERIFICATION = True

    DESCRIPTION = "Fix IDA constant propagation for high-half register writes"
    REFERENCE = "IDA limitation workaround"
