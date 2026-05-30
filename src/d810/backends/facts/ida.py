"""Hex-Rays live-source lifter (Landing Sequence LS10 C3).

Registers a :class:`~d810.capabilities.source_lifter.SourceLifter` that lifts a
live Hex-Rays ``mba_t`` into the portable fact target the recon induction
collector iterates.  Both importing this module AND calling
``ensure_hexrays_lifter_registered()`` register the lifter -- the single lawful
``register_live_lifter()`` call site (the
``register-live-lifter-only-in-backends`` ast-grep rule ignores ``backends/**``).

IDA-bound: ``d810.hexrays.fact_target`` imports ``ida_hexrays``, so this module
is not importable without IDA.  The composition root calls
``ensure_hexrays_lifter_registered()`` (imported lazily inside ``Manager.start``,
C4) to keep ``d810.manager`` collectable in unit tests AND to re-register after a
``reset_live_lifters_for_tests()`` -- a ``sys.modules``-cached module would make
a bare re-import a no-op, silently leaving the registry empty.

Currently dormant in the live pipeline: both capture paths already hand the
collectors a portable target (a ``FlowGraph`` snapshot pre-D810, the
``mba_to_fact_target`` result post-D810), so ``matches`` returns False and the
recon default iteration runs unchanged.  The lifter activates only when a raw
``mba`` reaches a fact collector directly.
"""
from __future__ import annotations

from d810.capabilities.source_lifter import register_live_lifter
from d810.core.typing import Any
from d810.hexrays.fact_target import mba_to_fact_target

__all__ = ["HexRaysMicrocodeLifter", "ensure_hexrays_lifter_registered"]


class HexRaysMicrocodeLifter:
    """Lift a live Hex-Rays ``mba_t`` into a portable fact target."""

    def matches(self, source: Any) -> bool:
        """True iff ``source`` is a live ``mba_t`` (duck-typed via ``get_mblock``
        + ``qty``); portable ``FlowGraph`` snapshots / fact targets do not match,
        so the recon default iteration handles them."""
        return hasattr(source, "get_mblock") and hasattr(source, "qty")

    def lift(self, source: Any) -> Any:
        """Lift the live ``mba`` into a portable fact target (reuses the existing
        ``d810.hexrays.fact_target.mba_to_fact_target`` adapter)."""
        return mba_to_fact_target(source)


# Module-level singleton so repeated registration (e.g. after a registry reset
# in a test/reload path) re-registers the SAME instance -- register_live_lifter's
# membership guard then dedupes by identity, never appending a duplicate.
_LIFTER = HexRaysMicrocodeLifter()


def ensure_hexrays_lifter_registered() -> None:
    """Register the Hex-Rays live lifter; idempotent and reset-safe.

    ``Manager.start`` calls this instead of relying on this module's import
    side effect: a ``sys.modules``-cached module makes the manager's ``import``
    a no-op, so a prior ``reset_live_lifters_for_tests()`` would otherwise leave
    the registry empty.  Re-registering the singleton restores it; the identity
    dedupe in ``register_live_lifter`` makes repeated calls a no-op.
    """
    register_live_lifter(_LIFTER)


# Import-time registration (the single lawful register_live_lifter() call site)
# funnels through the idempotent ensure() so both paths share one instance.
ensure_hexrays_lifter_registered()
