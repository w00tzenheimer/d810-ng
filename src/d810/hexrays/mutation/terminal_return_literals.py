"""In-memory terminal return literals observed during Hex-Rays materialization."""
from __future__ import annotations

from d810.core.typing import Any


_TERMINAL_ZERO_GUARD_LITERAL_RETURNS: dict[int, set[int]] = {}


def remember_terminal_zero_guard_literal_return_value(mba: Any, value: int) -> None:
    """Remember an in-memory literal proven for a terminal zero-guard return."""
    func_ea = int(getattr(mba, "entry_ea", 0) or 0)
    normalized = int(value) & 0xFFFFFFFFFFFFFFFF
    _TERMINAL_ZERO_GUARD_LITERAL_RETURNS.setdefault(func_ea, set()).add(normalized)


def terminal_zero_guard_literal_return_values(mba: Any) -> tuple[int, ...]:
    """Return remembered terminal zero-guard return literals for an MBA."""
    func_ea = int(getattr(mba, "entry_ea", 0) or 0)
    return tuple(sorted(_TERMINAL_ZERO_GUARD_LITERAL_RETURNS.get(func_ea, ())))
