"""Structured provenance logging for CFG mutations.

Every CFG-mutating site emits a single ``CFG_PROVENANCE`` log line with
attribution.  Used to answer "who killed/created/redirected this block/edge?"
in any future debugging session.

Format:
    CFG_PROVENANCE pass=<pass_name> action=<action> block=blk[N] target=blk[M]|-
                   reason=<reason> extra=<json|->

Actions (canonical):
    CREATE        -- new block added (typically an InsertBlock or duplicated block)
    DELETE        -- block removed from mba (qty decremented)
    SOFT_KILL     -- block converted to BLT_1WAY goto-shell (GutAndWire)
    SEVER_EDGE    -- succ/pred edge removed (block stays alive)
    REDIRECT_EDGE -- succ replaced (e.g., succ X -> succ Y)
    RENUMBER      -- block kept but serial changed (recovery / cleanup)
    MERGE         -- block merged into another (qty decremented)
    NOP_INSNS     -- payload instructions NOP'd (block kept, body emptied)
    BULK_DEEP_CLEAN -- mba.merge_blocks() / remove_empty_and_unreachable_blocks()
                       called; specific killed serials are not reported by IDA
                       so this records the call site

The helper also accumulates entries into a per-process buffer so the diag DB
snapshot writer can flush them under a snapshot_id when a new snapshot is
captured.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from d810.core.typing import Any

from d810.core import logging as _d810_logging

_logger = _d810_logging.getLogger("D810.cfg.provenance")


@dataclass
class _ProvenanceEntry:
    """In-memory record of a single provenance event."""

    pass_name: str
    action: str
    block_serial: int
    target_serial: int | None
    reason: str
    extra_json: str | None


# Process-level buffer of provenance entries pending flush. ``snapshot_mba``
# moves them into ``cfg_provenance`` rows under the new snapshot_id.
_pending_lock = threading.Lock()
_pending: list[_ProvenanceEntry] = []


def log_cfg_provenance(
    *,
    pass_name: str,
    action: str,
    block_serial: int,
    target_serial: int | None = None,
    reason: str = "",
    extra: dict[str, Any] | None = None,
) -> None:
    """Emit a single canonical provenance line and buffer for DB flush."""
    target_str = (
        f"blk[{int(target_serial)}]" if target_serial is not None else "-"
    )
    extra_str = "-"
    extra_json: str | None = None
    if extra:
        try:
            extra_json = json.dumps(extra, default=str, sort_keys=True)
            extra_str = extra_json
        except Exception:
            extra_json = None
            extra_str = str(extra)
    try:
        block_int = int(block_serial)
    except Exception:
        block_int = -1
    target_int: int | None
    try:
        target_int = int(target_serial) if target_serial is not None else None
    except Exception:
        target_int = None
    _logger.info(
        "CFG_PROVENANCE pass=%s action=%s block=blk[%d] target=%s reason=%s extra=%s",
        pass_name,
        action,
        block_int,
        target_str,
        reason,
        extra_str,
    )
    entry = _ProvenanceEntry(
        pass_name=str(pass_name),
        action=str(action),
        block_serial=block_int,
        target_serial=target_int,
        reason=str(reason),
        extra_json=extra_json,
    )
    with _pending_lock:
        _pending.append(entry)


def drain_pending_provenance() -> list[_ProvenanceEntry]:
    """Atomically drain and return the pending provenance buffer.

    Called by ``snapshot_mba`` to flush entries under the new snapshot_id.
    """
    with _pending_lock:
        out = list(_pending)
        _pending.clear()
    return out


def reset_pending_provenance() -> None:
    """Clear the pending buffer without flushing.  Test harness use."""
    with _pending_lock:
        _pending.clear()


__all__ = [
    "log_cfg_provenance",
    "drain_pending_provenance",
    "reset_pending_provenance",
]
