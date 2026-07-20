"Source-lifter capability Protocol + registry.\n\nA :class:`SourceLifter` turns a backend-native *source* (a live Hex-Rays ``mba``,\na future angr function, ...) into a portable flow graph that portable analyses\niterate.  The Hex-Rays implementation lives at ``d810.backends.facts.ida`` and\nregisters itself at import time (the only lawful call site); portable code picks\na lifter via :func:`select_lifter` and falls back to its existing\nsnapshot/instruction iteration when none is registered (Landing Sequence LS10).\n\nLayering: ``d810.capabilities`` sits BELOW ``backends`` (which register lifters\nDOWN) and BELOW ``preanalysis`` (which selects DOWN), so hosting the registry here\ninverts the dependency honestly.  ``FlowGraph`` lives in ``d810.ir`` (BELOW\ncapabilities); ``lift``'s return and ``matches``'s argument are still typed ``Any``\nto keep this contract decoupled from any concrete graph type.  Protocol parameters are\ncontravariant, so ``Any`` is what lets a concrete ``lift(self, mba: mba_t)``\nstructurally satisfy the contract (mirrors ``capabilities/constant_fixpoint.py``).\n"
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
        """Lift ``source`` into a portable flow graph (a ``d810.ir`` FlowGraph)."""
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
    "Return the first registered lifter whose ``matches(source)`` is True.\n\n    Returns ``None`` when no lifter is registered or none matches -- callers then\n    use their own default portable iteration (the preanalysis snapshot/instruction\n    fallback).\n    "
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
