"""Backend-neutral state-variable cleanup helpers.

State cleanup strategies still own backend-specific mutation mechanics, but the
state-constant evidence they consume is common to BST, switch, and compare-chain
flatteners: a snapshot contributes known state constants, and dispatcher models
may contribute exact handler states or interval bounds.
"""
from __future__ import annotations

from d810.core.typing import Iterable

__all__ = [
    "collect_state_constants",
    "is_known_state_constant",
]


def collect_state_constants(
    state_constants: Iterable[int] | None = None,
    bst_result: object | None = None,
) -> frozenset[int]:
    """Collect known dispatcher state constants from generic evidence.

    Args:
        state_constants: Constants already discovered by the active family.
        bst_result: Optional dispatcher/BST analysis result exposing
            ``handler_state_map`` and/or ``handler_range_map`` attributes.

    Returns:
        A frozen set of integer state constants.  Range maps contribute both
        bounds because existing cleanup heuristics use those as conservative
        known-state sentinels.
    """
    constants: set[int] = {
        int(value)
        for value in (state_constants or ())
    }

    if bst_result is not None:
        handler_state_map = getattr(bst_result, "handler_state_map", {}) or {}
        handler_range_map = getattr(bst_result, "handler_range_map", {}) or {}
        for state_value in handler_state_map.values():
            constants.add(int(state_value))
        for low, high in handler_range_map.values():
            if low is not None:
                constants.add(int(low))
            if high is not None:
                constants.add(int(high))

    return frozenset(constants)


def is_known_state_constant(
    value: int | None,
    state_constants: Iterable[int],
    *,
    mask32: bool = False,
) -> bool:
    """Return whether ``value`` belongs to the known state-constant set."""
    if value is None:
        return False
    candidate = int(value)
    if mask32:
        candidate &= 0xFFFFFFFF
        return candidate in {int(state) & 0xFFFFFFFF for state in state_constants}
    return candidate in {int(state) for state in state_constants}
