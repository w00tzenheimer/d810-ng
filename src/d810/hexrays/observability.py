"""Hex-Rays diagnostic capture facade.

Runtime Hex-Rays code (``d810.hexrays.hooks.hexrays_hooks``,
``d810.hexrays.mutation.deferred_modifier``, the flattening executor,
hodur unflattener, etc.) calls into this module instead of importing
``d810.core.diag.*`` directly.

This is the *capture-side* boundary for live Hex-Rays microcode
serialization:

- ``capture_mba_snapshot`` writes a full MBA into the diag DB.
- ``mba_to_block_snapshots`` converts a live ``ida_hexrays.mbl_array_t``
  into neutral :class:`BlockSnapshot` rows for capture.
- ``get_diag_db`` / ``open_capture_session`` / ``close_capture_session``
  expose the session-scoped connection lifecycle that runtime call sites
  use to fence diagnostic writes behind a "session present" check.

Phase 1 (this module): thin re-exports of the underlying
``d810.core.diag`` functions. Phase 5 moves the live-MBA serializer
into ``d810.hexrays.mba_serializer``; the facade names remain stable on
the hexrays side.

See:
    docs/plans/2026-05-11-diag-observability-boundary.md
    docs/diag-observability-boundary.md
"""
from __future__ import annotations

from d810.core.diag import (
    close_diag_session as close_capture_session,
    get_diag_db as get_diag_db,
    open_diag_session as open_capture_session,
)
from d810.core.diag.mba_serializer import (
    mba_to_block_snapshots as mba_to_block_snapshots,
)
from d810.core.diag.snapshot import (
    BlockSnapshot as BlockSnapshot,
    InstructionSnapshot as InstructionSnapshot,
    snapshot_mba as capture_mba_snapshot,
)

__all__ = [
    "BlockSnapshot",
    "InstructionSnapshot",
    "capture_mba_snapshot",
    "close_capture_session",
    "get_diag_db",
    "mba_to_block_snapshots",
    "open_capture_session",
]
