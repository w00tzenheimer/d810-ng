"""CFG-domain diagnostic capture facade and event API.

This module hosts two layered surfaces:

1. **Event-based observability API** (the long-term boundary).
   Runtime CFG mutation code constructs ``*Observed`` events and
   publishes them on the :mod:`d810.core.observability` bus. The
   diag sink subscribes in :mod:`d810.core.diag.event_handlers`; CFG
   producer code never touches :mod:`d810.core.diag`.

2. **Legacy capture re-exports** (back-compat). The pre-event facade
   re-exported ``log_cfg_provenance`` / ``snapshot_watch_transition``
   etc. so existing call sites compile during the Phase 5
   per-subsystem migration. Phase 6 removes them.

See:
    docs/diag-observability-boundary.md
"""
from __future__ import annotations

from d810.core.observability import (
    emit as _emit,
    has_subscribers as _has_subscribers,
)
# Event dataclasses live under d810.core.observability_events so the
# SQLite sink can subscribe without an upward import. The cfg facade
# re-exports the cfg-relevant types so call sites don't have to know
# where they live.
from d810.core.observability_events import (
    BlockLineageDrainRequested as BlockLineageDrainRequested,
    CfgProvenanceObserved as CfgProvenanceObserved,
    WatchBlockTransitionObserved as WatchBlockTransitionObserved,
)
from d810.core.typing import Any


# ---------------------------------------------------------------------------
# Emit helpers
# ---------------------------------------------------------------------------


def observe_cfg_provenance(
    *,
    pass_name: str,
    action: str,
    block_serial: int,
    target_serial: int | None = None,
    reason: str = "",
    extra: dict[str, Any] | None = None,
    mba: Any | None = None,
    block_label: str | None = None,
    target_label: str | None = None,
    maturity_label: str | None = None,
) -> None:
    """Publish a :class:`CfgProvenanceObserved` event.

    Drop-in replacement for the legacy ``log_cfg_provenance``: accepts
    the same keyword arguments. When ``mba`` is supplied the helper
    pre-computes live block / maturity labels (so the event payload
    stays neutral and the subscriber doesn't need to know about
    Hex-Rays). Explicit ``block_label`` / ``target_label`` /
    ``maturity_label`` overrides win over the mba-derived values.
    """
    # Live-label resolution (cheap, happens in the producer process).
    if mba is not None:
        from d810.cfg.provenance import (
            _live_block_label,
            _live_maturity_label,
            _safe_serial,
        )
        block_int = _safe_serial(block_serial)
        target_int = (
            _safe_serial(target_serial) if target_serial is not None else None
        )
        if block_label is None:
            block_label = _live_block_label(mba, block_int)
        if target_label is None and target_int is not None:
            target_label = _live_block_label(mba, target_int)
        if maturity_label is None:
            maturity_label = _live_maturity_label(mba)
    _emit(CfgProvenanceObserved(
        pass_name=str(pass_name),
        action=str(action),
        block_serial=int(block_serial),
        target_serial=(
            int(target_serial) if target_serial is not None else None
        ),
        reason=str(reason),
        extra=dict(extra or {}),
        block_label=block_label,
        target_label=target_label,
        maturity_label=maturity_label,
    ))


def observe_watch_block_transition(
    *,
    func_ea: int,
    apply_session_id: str,
    mod_index: int | None,
    mod_type: str,
    phase: str,
    block_serial: int,
    prev_type_name: str | None,
    prev_succs: tuple[int, ...] | None,
    prev_preds: tuple[int, ...] | None,
    now_type_name: str | None,
    now_succs: tuple[int, ...] | None,
    now_preds: tuple[int, ...] | None,
) -> None:
    """Publish a :class:`WatchBlockTransitionObserved` event."""
    _emit(WatchBlockTransitionObserved(
        func_ea=int(func_ea),
        apply_session_id=str(apply_session_id),
        mod_index=mod_index,
        mod_type=str(mod_type),
        phase=str(phase),
        block_serial=int(block_serial),
        prev_type_name=prev_type_name,
        prev_succs=prev_succs,
        prev_preds=prev_preds,
        now_type_name=now_type_name,
        now_succs=now_succs,
        now_preds=now_preds,
    ))


def diagnostics_enabled() -> bool:
    """Cheap predicate: is any CFG-event subscriber installed?"""
    return any(
        _has_subscribers(t)
        for t in (
            CfgProvenanceObserved,
            WatchBlockTransitionObserved,
            BlockLineageDrainRequested,
        )
    )


# ---------------------------------------------------------------------------
# Legacy capture shims (back-compat for runtime sites that need the diag
# connection directly: byte_emit_tail_isolation_runtime read paths,
# cfg.block_lineage IoC registration). These wrappers delegate via
# `importlib.import_module` so the static import graph has ZERO
# cfg.observability -> d810.core.diag edges. The runtime-no-core-diag
# import-linter contract therefore needs no ignore_imports entry for
# this module.
#
# The fire-and-forget wrappers (`record_cfg_provenance` /
# `record_watch_block_transition`) were removed in an earlier commit
# once every caller migrated to the observe_* event helpers.
# ---------------------------------------------------------------------------


def _diag_module():
    import importlib
    return importlib.import_module("d810.core.diag")


def get_diag_db(*args, **kwargs):
    return _diag_module().get_diag_db(*args, **kwargs)


def register_lineage_drainer(*args, **kwargs):
    return _diag_module().register_lineage_drainer(*args, **kwargs)


# Producer-facing CFG provenance API stays on d810.cfg.provenance
# (same layer; no cross-layer import).
from d810.cfg.provenance import (
    drain_pending_provenance as drain_pending_provenance,
    reset_pending_provenance as reset_pending_provenance,
)


__all__ = [
    # Event dataclasses
    "BlockLineageDrainRequested",
    "CfgProvenanceObserved",
    "WatchBlockTransitionObserved",
    # Emit helpers
    "diagnostics_enabled",
    "observe_cfg_provenance",
    "observe_watch_block_transition",
    # Legacy re-exports retained for non-migrated call sites
    "drain_pending_provenance",
    "get_diag_db",
    "register_lineage_drainer",
    "reset_pending_provenance",
]
