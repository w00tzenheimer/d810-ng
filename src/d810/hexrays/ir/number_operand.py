"""Size-safe construction of ``mop_n`` constants.

``mop_t::make_number`` keeps the constant in a 64-bit ``mnumber_t`` and accepts
only sizes 1/2/4/8 (``hexrays.hpp:2755``). For a larger size Hex-Rays clamps the
number to 8 and widens it through a synthesized ``m_xds`` sub-instruction, which
needs a real instruction address; with the default ``BADADDR`` it raises
INTERR 51617 (verified in hexx64 9.3 and 9.4). 16 is a legal *mop* size but not
a legal ``make_number`` size, so every construction site has to go through here.

This is deliberately a leaf module - it imports nothing from ``d810`` beyond
logging - so the lowest-level Hex-Rays helpers can use it without an import
cycle back through ``mop_utils``.
"""

from __future__ import annotations

from d810.core import getLogger

logger = getLogger(__name__)

VALID_MOP_SIZES = frozenset({1, 2, 4, 8, 16})
MAX_MAKE_NUMBER_SIZE = 8
BADADDR = 0xFFFFFFFFFFFFFFFF


def _anchor(ea) -> int | None:
    """Return a usable instruction address, or None when there is none."""
    if ea is None:
        return None
    anchor = int(ea)
    if anchor == BADADDR or anchor < 0:
        return None
    return anchor


def safe_make_number(mop, value, size, ea=None) -> bool:
    """Create a number operand with a size ``make_number`` can actually store.

    Returns whether the operand carries the *requested* width. A caller that
    needs the exact width - anything emitting ``m_ldc``, whose ``l`` operand
    must be a real ``mop_n`` - must check this and abstain when it is False,
    rather than emit an instruction whose operand sizes disagree.

    If *size* is not one of the valid IDA operand sizes (1, 2, 4, 8, 16), it is
    replaced with 4 (32-bit) to prevent a zero-size ``mop_n`` from crashing
    Hex-Rays' C++ verify / optimize_local passes.

    A size above 8 is only expressible when *ea* names a real instruction, which
    lets Hex-Rays anchor the widening ``m_xds``. Without one the size is clamped
    to 8 rather than raising INTERR 51617 - but note that the widened form is a
    ``mop_d`` holding a nested instruction, not a number, so it is not a
    substitute for a wide constant everywhere a number is required.

    >>> class _Mop:
    ...     def make_number(self, value, size, *rest):
    ...         print(value, size, rest)
    >>> safe_make_number(_Mop(), 0xFFFF, 16)
    65535 8 ()
    False
    >>> safe_make_number(_Mop(), 0xFFFF, 16, ea=0x401000)
    65535 16 (4198400,)
    True
    >>> safe_make_number(_Mop(), 0xFF, 4)
    255 4 ()
    True
    """
    requested = size
    if size not in VALID_MOP_SIZES:
        logger.warning("Invalid mop size %s, defaulting to 4", size)
        size = 4
    anchor = _anchor(ea)
    if size > MAX_MAKE_NUMBER_SIZE and anchor is None:
        logger.debug(
            "mop size %d exceeds make_number's %d-byte limit and no anchor ea "
            "was supplied; clamping (INTERR 51617 avoidance)",
            size,
            MAX_MAKE_NUMBER_SIZE,
        )
        size = MAX_MAKE_NUMBER_SIZE
    masked = value & ((1 << (size * 8)) - 1)
    if anchor is None:
        mop.make_number(masked, size)
    else:
        mop.make_number(masked, size, anchor)
    return size == requested


__all__ = [
    "BADADDR",
    "MAX_MAKE_NUMBER_SIZE",
    "VALID_MOP_SIZES",
    "safe_make_number",
]
