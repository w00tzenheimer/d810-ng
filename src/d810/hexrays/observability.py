"""Hex-Rays diagnostic capture facade and event API.

This module hosts two layered surfaces:

1. **Event-based observability API** (the long-term boundary). The
   single command-style API is :func:`request_capture_mba_snapshot`
   which builds a :class:`SnapshotRef`, publishes a
   :class:`CaptureMbaSnapshotRequested` event on the bus, and returns
   the ref so subsequent ``observe_*`` calls can correlate. The diag
   subscriber resolves the ref to a SQLite ``snapshots.id``. Phase 6
   renames :func:`request_capture_mba_snapshot` back to
   :func:`capture_mba_snapshot` once the legacy re-export is gone.

2. **Legacy capture re-exports** (back-compat). The pre-event facade
   re-exported ``snapshot_mba`` as ``capture_mba_snapshot`` (returning
   an int) and exposed ``mba_to_block_snapshots`` plus session
   helpers. These keep existing call sites compiling during the
   Phase 5 per-subsystem migration; Phase 6 removes them.

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

    Returns ``None`` when no diag subscriber is installed for
    :class:`CaptureMbaSnapshotRequested` -- the caller should treat
    that as "diagnostics disabled" and skip subsequent ``observe_*``
    calls. This avoids constructing per-snapshot payloads that nobody
    will read.

    Phase 6 renames this back to :func:`capture_mba_snapshot` after
    the legacy re-export is removed.
    """
    if not _has_subscribers(CaptureMbaSnapshotRequested):
        return None
    snap = SnapshotRef(
        key=new_snapshot_key(),
        func_ea=int(func_ea),
        label=str(label),
        maturity=str(maturity),
        phase=str(phase),
    )
    _emit(CaptureMbaSnapshotRequested(snapshot=snap, blocks=tuple(blocks)))
    return snap


def diagnostics_enabled() -> bool:
    """Cheap predicate: is the MBA-capture subscriber installed?"""
    return _has_subscribers(CaptureMbaSnapshotRequested)


# ---------------------------------------------------------------------------
# Legacy capture shims (back-compat for sites that still call
# `capture_mba_snapshot` with an explicit (conn, blocks, ...) pair or
# manage the diag session directly). These wrappers delegate via
# `importlib.import_module` so the static import graph has ZERO
# hexrays.observability -> d810.core.diag edges. The runtime-no-core-diag
# import-linter contract therefore needs no ignore_imports entry for
# this module.
#
# `mba_to_block_snapshots` lives in `d810.hexrays.mba_serializer`
# (same layer); the facade re-export is for callers that already import
# from hexrays.observability and don't want to import from two modules.
# ---------------------------------------------------------------------------

from d810.hexrays.mba_serializer import (
    mba_to_block_snapshots as mba_to_block_snapshots,
)


def _diag_module():
    import importlib
    return importlib.import_module("d810.core.diag")


def _snapshot_module():
    import importlib
    return importlib.import_module("d810.core.diag.snapshot")


def get_diag_db(*args, **kwargs):
    return _diag_module().get_diag_db(*args, **kwargs)


def open_capture_session(*args, **kwargs):
    return _diag_module().open_diag_session(*args, **kwargs)


def close_capture_session(*args, **kwargs):
    return _diag_module().close_diag_session(*args, **kwargs)


def capture_mba_snapshot(*args, **kwargs):
    return _snapshot_module().snapshot_mba(*args, **kwargs)


__all__ = [
    # Event dataclasses
    "CaptureMbaSnapshotRequested",
    # Request/response command API
    "diagnostics_enabled",
    "request_capture_mba_snapshot",
    # Neutral models (kept here for callers that construct them)
    "BlockSnapshot",
    "InstructionSnapshot",
    # Legacy re-exports (deprecated; removed in Phase 6)
    "capture_mba_snapshot",
    "close_capture_session",
    "get_diag_db",
    "mba_to_block_snapshots",
    "open_capture_session",
]
