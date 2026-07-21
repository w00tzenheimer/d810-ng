"""Portable normalization for native register comparisons."""

from __future__ import annotations

_MASK32 = 0xFFFFFFFF

_SWAPPED_X86_CONDITION_CODES = {
    2: 7,
    3: 6,
    4: 4,
    5: 5,
    6: 3,
    7: 2,
    12: 15,
    13: 14,
    14: 13,
    15: 12,
}


def swapped_x86_condition_code(condition_code: int | None) -> int | None:
    """Return the equivalent condition after exchanging compare operands."""
    if condition_code is None:
        return None
    return _SWAPPED_X86_CONDITION_CODES.get(int(condition_code))


def normalize_register_compare_predicate(
    *,
    left_mreg: int | None,
    left_values: frozenset[int] | None,
    right_mreg: int | None,
    right_values: frozenset[int] | None,
) -> tuple[int, int, bool] | None:
    """Normalize a register compare with exactly one constant-valued side.

    The returned flag records whether the native operands were swapped to put
    the dynamic predicate register on the left.
    """
    left_singleton = (
        None
        if left_values is None or len(left_values) != 1
        else int(next(iter(left_values))) & _MASK32
    )
    right_singleton = (
        None
        if right_values is None or len(right_values) != 1
        else int(next(iter(right_values))) & _MASK32
    )
    if left_mreg is not None and left_singleton is None and right_singleton is not None:
        return int(left_mreg), right_singleton, False
    if (
        right_mreg is not None
        and right_singleton is None
        and left_singleton is not None
    ):
        return int(right_mreg), left_singleton, True
    return None


__all__ = [
    "normalize_register_compare_predicate",
    "swapped_x86_condition_code",
]
