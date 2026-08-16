"""SDK-free native microcode maturity identifiers for MBA rules.

The instruction matcher receives Hex-Rays ``MMAT_*`` integers.  Keeping these
as an :class:`IntEnum` gives portable rule modules named stages while preserving
direct equality with the native integers, without importing ``ida_hexrays``.
"""

from enum import IntEnum


class MicrocodeMaturity(IntEnum):
    """Stable numeric identities of the native microcode stages used by MBA."""

    PREOPTIMIZED = 2
    LOCOPT = 3
    CALLS = 4
    GLBOPT1 = 5
    GLBOPT2 = 6


__all__ = ["MicrocodeMaturity"]
