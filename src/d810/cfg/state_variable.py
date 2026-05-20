"""Backend-neutral dispatcher state-variable identity."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class StateVariableRef:
    """Stable identity for a state variable without backend operand objects."""

    stkoff: int
    width: int = 4


__all__ = ["StateVariableRef"]
