"""Scoped exclusion for nested Hex-Rays microcode generation."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar

from d810.core.typing import Iterator


_SUPPRESSION_DEPTH: ContextVar[int] = ContextVar(
    "d810_optimization_suppression_depth",
    default=0,
)


def d810_optimization_is_suppressed() -> bool:
    """Return whether d810 instruction/block hooks must abstain."""
    return _SUPPRESSION_DEPTH.get() > 0


@contextmanager
def suppress_d810_optimization() -> Iterator[None]:
    """Exclude d810 rewrites while Hex-Rays builds an evidence-only MBA."""
    token = _SUPPRESSION_DEPTH.set(_SUPPRESSION_DEPTH.get() + 1)
    try:
        yield
    finally:
        _SUPPRESSION_DEPTH.reset(token)


__all__ = [
    "d810_optimization_is_suppressed",
    "suppress_d810_optimization",
]
