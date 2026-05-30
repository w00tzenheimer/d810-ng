"""CFG-domain diagnostic capture facade and event API.

Runtime CFG mutation code constructs ``*Observed`` events and publishes
them on the :mod:`d810.core.observability` bus. The diag SQLite backend
subscribes via the abstract observability interface; CFG producer code
never touches the diag backend.

This module is portable (``core`` layer): live block / maturity label
resolution is delegated to :mod:`d810.core.observability_labels` (neutral,
duck-typed formatting), so the facade carries no Hex-Rays / ``ir`` / ``cfg``
import. When an ``mba``-like source is supplied the helper pre-computes
labels; explicit ``*_label`` overrides win.

See:
    docs/diag-observability-boundary.md
"""
from __future__ import annotations

from d810.core.observability import (
    emit as _emit,
    has_subscribers as _has_subscribers,
)
# Event dataclasses live under d810.core.observability_events so the
# SQLite sink can subscribe without an upward import. This facade
# re-exports the cfg-relevant types so call sites don't have to know
# where they live.
from d810.core.observability_events import (
    BlockLineageDrainRequested as BlockLineageDrainRequested,
    CfgProvenanceForLatestSnapshot as CfgProvenanceForLatestSnapshot,
    CfgProvenanceObserved as CfgProvenanceObserved,
    WatchBlockTransitionObserved as WatchBlockTransitionObserved,
)
from d810.core.observability_labels import (
    live_block_label,
    live_maturity_label,
    safe_serial,
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
    pre-computes live block / maturity labels via
    :mod:`d810.core.observability_labels` (neutral formatting; the
    subscriber doesn't need to know about Hex-Rays). Explicit
    ``block_label`` / ``target_label`` / ``maturity_label`` overrides win
    over the mba-derived values.
    """
    # Live-label resolution (cheap, happens in the producer process).
    if mba is not None:
        block_int = safe_serial(block_serial)
        target_int = (
            safe_serial(target_serial) if target_serial is not None else None
        )
        if block_label is None:
            block_label = live_block_label(mba, block_int)
        if target_label is None and target_int is not None:
            target_label = live_block_label(mba, target_int)
        if maturity_label is None:
            maturity_label = live_maturity_label(mba)
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


def observe_cfg_provenance_latest(
    *,
    func_ea: int,
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
    """Publish CFG provenance against the latest snapshot for ``func_ea``.

    Late-binding companion to :func:`observe_cfg_provenance`, for
    planning/recon observations (abstentions, vetoes) where there may be
    no later MBA snapshot to flush a buffered row. Label resolution mirrors
    :func:`observe_cfg_provenance` (delegated to
    :mod:`d810.core.observability_labels`).
    """
    if mba is not None:
        block_int = safe_serial(block_serial)
        target_int = (
            safe_serial(target_serial) if target_serial is not None else None
        )
        if block_label is None:
            block_label = live_block_label(mba, block_int)
        if target_label is None and target_int is not None:
            target_label = live_block_label(mba, target_int)
        if maturity_label is None:
            maturity_label = live_maturity_label(mba)
    event = CfgProvenanceObserved(
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
    )
    # Prefer the explicit late-binding event. Some embedded IDA harnesses
    # install an older handler set before this event is subscribed; when that
    # happens, fall back to the already-established next-snapshot event so the
    # diagnostic is not silently lost.
    if not _has_subscribers(CfgProvenanceForLatestSnapshot):
        _emit(event)
        return
    _emit(CfgProvenanceForLatestSnapshot(
        func_ea=int(func_ea),
        events=(event,),
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
            CfgProvenanceForLatestSnapshot,
            WatchBlockTransitionObserved,
            BlockLineageDrainRequested,
        )
    )


__all__ = [
    # Event dataclasses
    "BlockLineageDrainRequested",
    "CfgProvenanceForLatestSnapshot",
    "CfgProvenanceObserved",
    "WatchBlockTransitionObserved",
    # Emit helpers
    "diagnostics_enabled",
    "observe_cfg_provenance",
    "observe_cfg_provenance_latest",
    "observe_watch_block_transition",
]
