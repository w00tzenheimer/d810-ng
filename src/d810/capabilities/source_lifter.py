"""Source-lifter capability Protocol + registry.

A :class:`SourceLifter` turns a backend-native *source* (a live Hex-Rays ``mba``,
a future angr function, ...) into a portable flow graph that portable analyses
iterate.  The Hex-Rays implementation lives at ``d810.backends.facts.ida`` and
registers itself at import time (the only lawful call site); portable code picks
a lifter via :func:`select_lifter` and falls back to its existing
snapshot/instruction iteration when none is registered (Landing Sequence LS10).

Layering: ``d810.capabilities`` sits BELOW ``backends`` (which register lifters
DOWN) and BELOW ``recon`` (which selects DOWN), so hosting the registry here
inverts the dependency honestly.  ``FlowGraph`` lives in ``d810.cfg`` (ABOVE
capabilities), so ``lift``'s return and ``matches``'s argument are typed ``Any``
-- a real import would be an upward-fatal edge.  Protocol parameters are
contravariant, so ``Any`` is what lets a concrete ``lift(self, mba: mba_t)``
structurally satisfy the contract (mirrors ``capabilities/constant_fixpoint.py``).
"""
from __future__ import annotations

import threading

from d810.core.typing import Any, Optional, Protocol, runtime_checkable

__all__ = [
    "LiveLifter",
    "SourceLifter",
    "register_live_lifter",
    "registered_lifters",
    "reset_live_lifters_for_tests",
    "select_lifter",
]


@runtime_checkable
class SourceLifter(Protocol):
    """Backend boundary: lift a native source into a portable flow graph."""

    def matches(self, source: Any) -> bool:
        """True iff this lifter can lift ``source`` (a backend-native object)."""
        ...

    def lift(self, source: Any) -> Any:
        """Lift ``source`` into a portable flow graph (a ``d810.cfg`` FlowGraph)."""
        ...


LiveLifter = SourceLifter
"""Readability alias for :class:`SourceLifter` (the live-source lifter role)."""


_lock = threading.Lock()
_LIVE_LIFTERS: list[SourceLifter] = []


def register_live_lifter(lifter: SourceLifter) -> None:
    """Register a backend :class:`SourceLifter`.

    Called only by the backend evidence adapter (``d810.backends.facts.ida``) at
    import time -- the single lawful call site (enforced by the
    ``register-live-lifter-only-in-backends`` ast-grep rule).  Idempotent.
    """
    with _lock:
        if lifter not in _LIVE_LIFTERS:
            _LIVE_LIFTERS.append(lifter)


def select_lifter(source: Any) -> Optional[SourceLifter]:
    """Return the first registered lifter whose ``matches(source)`` is True.

    Returns ``None`` when no lifter is registered or none matches -- callers then
    use their own default portable iteration (the recon snapshot/instruction
    fallback).
    """
    with _lock:
        lifters = tuple(_LIVE_LIFTERS)
    for lifter in lifters:
        if lifter.matches(source):
            return lifter
    return None


def registered_lifters() -> tuple[SourceLifter, ...]:
    """Snapshot of the registered lifters (diagnostic / test helper)."""
    with _lock:
        return tuple(_LIVE_LIFTERS)


def reset_live_lifters_for_tests() -> None:
    """Clear the lifter registry (test isolation)."""
    with _lock:
        _LIVE_LIFTERS.clear()
