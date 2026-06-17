"""Injected mop-comparison oracle for matching-time constraint checks.

The portable expression DSL (:mod:`d810.ir.expr.dsl` / :mod:`d810.ir.expr.constraints`)
describes constraints *structurally*. A few of them — ``equal_mops`` / ``is_bnot`` —
can only be decided by comparing two LIVE Hex-Rays microcode operands during rule
matching. That comparison lives in the Hex-Rays backend (``hexrays_helpers``), which
the portable ``ir`` layer must not import (``portable-core-no-ida``).

So the check delegates to a provider injected by the backend at the composition root
(:func:`register_mop_ops`, mirroring ``register_condition_chain_walkers``). With no provider
registered — headless / portable use, where these matching-time checks are never
invoked — it returns a conservative default. This replaces the
``importlib.import_module("d810.hexrays...")`` dodge that silently bypassed the
``mba-core-no-hexrays`` / ``portable-core-no-ida`` *static* contracts.
"""
from __future__ import annotations

from d810.core.typing import Protocol, runtime_checkable


@runtime_checkable
class MopOpsProvider(Protocol):
    """Live-mop structural comparisons; provided by the Hex-Rays backend.

    Operands are opaque to this layer (live ``mop_t`` from the matching context);
    the provider implementation interprets them.
    """

    def equal_mops_ignore_size(self, lo: object, ro: object) -> bool: ...

    def equal_bnot_mop(self, lo: object, ro: object) -> bool: ...


_PROVIDER: "MopOpsProvider | None" = None


def register_mop_ops(provider: "MopOpsProvider | None") -> None:
    """Register the backend mop-comparison provider (call from the composition root)."""
    global _PROVIDER
    _PROVIDER = provider


def get_mop_ops() -> "MopOpsProvider | None":
    """Return the registered provider, or None when no backend is available."""
    return _PROVIDER
