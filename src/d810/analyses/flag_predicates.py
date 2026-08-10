"""Architectural facts about the x86 flags register, used to decide branches.

Obfuscators use the flags register as an opaque predicate source::

    pushfq
    pop  rax
    test rax, rax
    jz   somewhere        ; never taken

Hex-Rays will not prove this, so the branch survives and the structurer renders
a loop around straight-line code. The fact that decides it is architectural, not
data-flow, which is why it lives here rather than in a backend.

Backend-neutral by construction: no IDA or Hex-Rays types appear here.
"""

from __future__ import annotations

#: Bit 1 of EFLAGS/RFLAGS is reserved and always reads as 1 on x86 and x86-64.
#: Intel SDM Vol. 1 §3.4.3 (EFLAGS): "bit 1 ... is always set to 1".
RFLAGS_RESERVED_SET_BIT = 1


def flags_register_can_be_zero() -> bool:
    """Can a full read of EFLAGS/RFLAGS ever yield zero? No.

    Because :data:`RFLAGS_RESERVED_SET_BIT` is always 1, the register always has
    at least that bit set, so ``test reg, reg`` never sets ZF.
    """
    return False


def flags_compare_zero_is_taken(*, equal_test: bool) -> bool:
    """Is a branch comparing a full flags read against zero taken?

    ``equal_test`` distinguishes the two forms:

    ``True`` (``jz``/``je``)
        Never taken -- the value is never zero. Fall through.
    ``False`` (``jnz``/``jne``)
        Always taken -- the value is always non-zero. Jump unconditionally.

    Both directions are decided; there is no unknown case. A rule that handles
    only ``jz`` silently misses the ``jnz`` sites (2 of the 7 in the motivating
    binary).
    """
    if flags_register_can_be_zero():  # pragma: no cover - documents the premise
        raise AssertionError("flags register cannot be zero on x86")
    return not equal_test


__all__ = [
    "RFLAGS_RESERVED_SET_BIT",
    "flags_compare_zero_is_taken",
    "flags_register_can_be_zero",
]
