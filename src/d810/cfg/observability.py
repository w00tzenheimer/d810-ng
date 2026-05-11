"""CFG-domain diagnostic capture facade.

Runtime CFG mutation code (``d810.hexrays.mutation.cfg_mutations``,
``d810.hexrays.mutation.deferred_modifier``, the flattening executor,
hodur unflattener, byte-emit tail isolation runtime, etc.) calls into
this module instead of importing ``d810.cfg.provenance`` or
``d810.core.diag.snapshot.snapshot_watch_transition`` directly.

This is the *capture-side* boundary for CFG-domain observations:

- ``record_cfg_provenance`` buffers a pass / action / block triple that
  is later drained into the snapshot's ``cfg_provenance`` table by
  ``record_mba_snapshot``.
- ``drain_pending_provenance`` returns the buffered entries (consumed
  by ``core.diag.snapshot`` during flush).
- ``record_watch_block_transition`` persists a single before/after
  block-shape transition for diagnostics.
- ``register_lineage_drainer`` registers a callback that drains pending
  ``block_lineage`` rows into the active snapshot. Used by
  :mod:`d810.cfg.block_lineage` as an inversion-of-control hook.

Phase 1 (this module): thin re-exports of the underlying
``d810.core.diag`` functions. Phase 6 splits the CFG provenance API
into ``d810.cfg.provenance`` (producer) and a DB-sink adapter; the
facade names remain stable on the CFG side.

See:
    docs/plans/2026-05-11-diag-observability-boundary.md
    docs/diag-observability-boundary.md
"""
from __future__ import annotations

from d810.core.diag import (
    get_diag_db as get_diag_db,
    register_lineage_drainer as register_lineage_drainer,
)
from d810.core.diag.snapshot import (
    snapshot_watch_transition as record_watch_block_transition,
)

# Producer-facing CFG provenance API (Phase 6 split). The producer
# lives in d810.cfg.provenance; the SQLite sink stays in
# d810.core.diag.snapshot and consumes the buffered entries through the
# core.diag IoC drainer hook that d810.cfg.provenance registers at
# import time.
from d810.cfg.provenance import (
    drain_pending_provenance as drain_pending_provenance,
    log_cfg_provenance as record_cfg_provenance,
    reset_pending_provenance as reset_pending_provenance,
)

__all__ = [
    "drain_pending_provenance",
    "get_diag_db",
    "record_cfg_provenance",
    "record_watch_block_transition",
    "register_lineage_drainer",
    "reset_pending_provenance",
]
