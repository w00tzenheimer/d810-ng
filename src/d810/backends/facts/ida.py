"""Hex-Rays live-source lifter (Landing Sequence LS10 C3).

Registers a :class:`~d810.capabilities.source_lifter.SourceLifter` that lifts a
live Hex-Rays ``mba_t`` into the portable fact target the recon induction
collector iterates.  Importing this module registers the lifter -- the single
lawful ``register_live_lifter()`` call site (the
``register-live-lifter-only-in-backends`` ast-grep rule ignores ``backends/**``).

IDA-bound: ``d810.hexrays.fact_target`` imports ``ida_hexrays``, so this module
is not importable without IDA.  The composition root imports it lazily inside
``Manager.start`` (C4) to keep ``d810.manager`` collectable in unit tests.

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

__all__ = ["HexRaysMicrocodeLifter"]


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


# Import-time registration: the single lawful register_live_lifter() call site.
register_live_lifter(HexRaysMicrocodeLifter())
