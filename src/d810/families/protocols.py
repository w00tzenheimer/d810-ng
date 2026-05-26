"""Generic family protocols."""
from __future__ import annotations

from d810.core.typing import Protocol, runtime_checkable

__all__ = ["DetectionResult"]


@runtime_checkable
class DetectionResult(Protocol):
    """Result of a strategy family's detection phase."""

    @property
    def detected(self) -> bool:
        """Whether the family's target pattern was found."""
        ...

    @property
    def description(self) -> str:
        """Human-readable description of what was detected."""
        ...
