"""Hex-Rays diagnostic capture facade and event API.

The single command-style API is :func:`request_capture_mba_snapshot`
which builds a :class:`SnapshotRef`, publishes a
:class:`CaptureMbaSnapshotRequested` event on the
:mod:`d810.core.observability` bus, and returns the ref so subsequent
``observe_*`` calls can correlate. A diag subscriber resolves the
ref to a backend snapshot id; this module never imports a backend.

:func:`mba_to_block_snapshots` is re-exported from
:mod:`d810.hexrays.mba_serializer` (same layer) for callers that
already import from the facade.

See:
    docs/diag-observability-boundary.md
"""

from __future__ import annotations

from d810.core.observability import (
    SnapshotRef,
    emit as _emit,
    has_subscribers as _has_subscribers,
    new_snapshot_key,
)

# Event dataclass lives under d810.core.observability_events so the
# SQLite sink can subscribe without an upward import. The hexrays
# facade re-exports it so call sites don't have to know where it lives.
from d810.core.observability_events import (
    CaptureMbaSnapshotRequested as CaptureMbaSnapshotRequested,
    OptblockCallbackExceptionObserved as OptblockCallbackExceptionObserved,
)
from d810.core.observability_models import (
    BlockSnapshot as BlockSnapshot,
    InstructionSnapshot as InstructionSnapshot,
)


# ---------------------------------------------------------------------------
# Request/response command API (the one synchronous emit)
# ---------------------------------------------------------------------------


def request_capture_mba_snapshot(
    *,
    blocks,
    label: str,
    func_ea: int,
    maturity: str = "UNKNOWN",
    maturity_id: int | None = None,
    maturity_json: str | None = None,
    phase: str = "unknown",
) -> SnapshotRef | None:
    """Request a full MBA capture; return a :class:`SnapshotRef` or ``None``.

    Caller flow::

        snap = request_capture_mba_snapshot(
            blocks=mba_to_block_snapshots(mba),
            label="...",
            func_ea=...,
            maturity="MMAT_GLBOPT1",
            phase="post_d810",
        )
        if snap is not None:
            observe_dag(snap, nodes, edges)
            observe_modifications(snap, modifications)

    Returns ``None`` when no subscriber is installed for
    :class:`CaptureMbaSnapshotRequested` -- the caller should treat
    that as "diagnostics disabled" and skip subsequent ``observe_*``
    calls. This avoids constructing per-snapshot payloads that nobody
    will read.
    """
    if not _has_subscribers(CaptureMbaSnapshotRequested):
        return None
    if maturity_json is None:
        try:
            from d810.hexrays.ir_maturity import hexrays_maturity_envelope_json

            maturity_json = hexrays_maturity_envelope_json(
                int(maturity_id) if maturity_id is not None else str(maturity)
            )
        except Exception:
            maturity_json = None
    snap = SnapshotRef(
        key=new_snapshot_key(),
        func_ea=int(func_ea),
        label=str(label),
        maturity=str(maturity),
        phase=str(phase),
        maturity_json=maturity_json,
    )
    _emit(CaptureMbaSnapshotRequested(snapshot=snap, blocks=tuple(blocks)))
    return snap


def diagnostics_enabled() -> bool:
    """Cheap predicate: is the MBA-capture subscriber installed?"""
    return _has_subscribers(CaptureMbaSnapshotRequested)


def observe_optblock_callback_exception(
    *,
    func_ea: int,
    maturity: str,
    block_serial: int | None,
    block_ea: int | None,
    error_type: str,
    error_message: str,
    traceback_text: str,
) -> None:
    """Publish one top-level optblock callback failure for diagnostics."""
    _emit(
        OptblockCallbackExceptionObserved(
            func_ea=int(func_ea),
            maturity=str(maturity),
            block_serial=(int(block_serial) if block_serial is not None else None),
            block_ea=(int(block_ea) if block_ea is not None else None),
            error_type=str(error_type),
            error_message=str(error_message),
            traceback_text=str(traceback_text),
        )
    )


# `mba_to_block_snapshots` lives in `d810.hexrays.mba_serializer`
# (same layer); the facade re-export is for callers that already
# import from hexrays.observability and don't want to pull from
# two modules.
from d810.hexrays.mba_serializer import (
    mba_to_block_snapshots as mba_to_block_snapshots,
)


__all__ = [
    # Event dataclasses
    "CaptureMbaSnapshotRequested",
    "OptblockCallbackExceptionObserved",
    # Request/response command API
    "diagnostics_enabled",
    "observe_optblock_callback_exception",
    "request_capture_mba_snapshot",
    # Neutral models (kept here for callers that construct them)
    "BlockSnapshot",
    "InstructionSnapshot",
    # Live-MBA serializer (re-export from d810.hexrays.mba_serializer)
    "mba_to_block_snapshots",
]
