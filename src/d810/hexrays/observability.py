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

from dataclasses import dataclass

from d810.core.observability import (
    SnapshotRef,
    emit as _emit,
    has_subscribers as _has_subscribers,
    new_snapshot_key,
)
from d810.core.observability_models import (
    BlockSnapshot as BlockSnapshot,
    InstructionSnapshot as InstructionSnapshot,
)


# ---------------------------------------------------------------------------
# Event dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CaptureMbaSnapshotRequested:
    """Hexrays requested a full MBA capture under ``snapshot``.

    The diag subscriber inserts a row in ``snapshots`` and binds
    ``snapshot.key`` to the assigned SQLite id; subsequent
    ``*Observed`` events that carry the same ``snapshot`` then resolve
    to that id and write child rows.
    """

    snapshot: SnapshotRef
    blocks: tuple[BlockSnapshot, ...]


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
# Legacy capture re-exports (back-compat for Phase 5 migration)
#
# These keep existing call sites compiling while each subsystem is
# migrated to the event API. Phase 6 removes them.
# ---------------------------------------------------------------------------

from d810.core.diag import (
    close_diag_session as close_capture_session,
    get_diag_db as get_diag_db,
    open_diag_session as open_capture_session,
)
from d810.core.diag.snapshot import (
    snapshot_mba as capture_mba_snapshot,
)
from d810.hexrays.mba_serializer import (
    mba_to_block_snapshots as mba_to_block_snapshots,
)


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
