"""Producer-facing CFG mutation provenance API.

Every CFG-mutating site emits a single ``CFG_PROVENANCE`` log line with
attribution via :func:`log_cfg_provenance`, then buffers the same record
for later flush into the ``cfg_provenance`` SQLite table under a
snapshot id.

Format:
    CFG_PROVENANCE pass=<pass_name> action=<action> block=blk[N] target=blk[M]|-
                   reason=<reason> extra=<json|->

Actions (canonical):
    CREATE          new block added (typically InsertBlock or duplicated block)
    DELETE          block removed from mba (qty decremented)
    SOFT_KILL       block converted to BLT_1WAY goto-shell (GutAndWire)
    SEVER_EDGE      succ/pred edge removed (block stays alive)
    REDIRECT_EDGE   succ replaced (e.g. succ X -> succ Y)
    RENUMBER        block kept but serial changed (recovery / cleanup)
    MERGE           block merged into another (qty decremented)
    NOP_INSNS       payload instructions NOP'd (block kept, body emptied)
    BULK_DEEP_CLEAN mba.merge_blocks() / remove_empty_and_unreachable_blocks()
                    called; specific killed serials are not reported by IDA
                    so this records the call site

Architecture
------------

The producer side (this module) lives in ``d810.cfg``. Runtime
callers reach the API through ``d810.cfg.observability``
(``observe_cfg_provenance``), which constructs a
``CfgProvenanceObserved`` event and publishes it on the
:mod:`d810.core.observability` event bus. A diag backend subscribes
to that event via the abstract observability interface and persists
rows under the next captured snapshot; this module never imports the
diag backend.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass

from d810.core import logging as _d810_logging
from d810.core.typing import Any

_logger = _d810_logging.getLogger("D810.cfg.provenance")


@dataclass
class ProvenanceEntry:
    """In-memory record of a single provenance event.

    The diag sink reads ``pass_name``, ``action``, ``block_serial``,
    ``target_serial``, ``reason``, and ``extra_json`` by duck typing;
    keep these attribute names stable.
    """

    pass_name: str
    action: str
    block_serial: int
    target_serial: int | None
    reason: str
    extra_json: str | None


# Process-level buffer of provenance entries pending flush. Retained
# for direct producer use; production flows route entries through the
# event bus (``CfgProvenanceObserved``) instead.
_pending_lock = threading.Lock()
_pending: list[ProvenanceEntry] = []


def log_cfg_provenance(
    *,
    pass_name: str,
    action: str,
    block_serial: int,
    target_serial: int | None = None,
    reason: str = "",
    extra: dict[str, Any] | None = None,
    mba: Any | None = None,
) -> None:
    """Emit a canonical provenance line and buffer it for DB flush."""
    block_int = _safe_serial(block_serial)
    target_int = _safe_serial(target_serial) if target_serial is not None else None
    block_str = _live_block_label(mba, block_int)
    target_str = _live_block_label(mba, target_int) if target_int is not None else "-"

    merged_extra: dict[str, Any] = dict(extra or {})
    if mba is not None:
        merged_extra.setdefault("block_label", block_str)
        if target_int is not None:
            merged_extra.setdefault("target_label", target_str)
        merged_extra.setdefault("maturity", _live_maturity_label(mba))

    extra_str = "-"
    extra_json: str | None = None
    if merged_extra:
        try:
            extra_json = json.dumps(merged_extra, default=str, sort_keys=True)
            extra_str = extra_json
        except Exception:
            extra_json = None
            extra_str = str(merged_extra)
    _logger.info(
        "CFG_PROVENANCE pass=%s action=%s block=%s target=%s reason=%s extra=%s",
        pass_name,
        action,
        block_str,
        target_str,
        reason,
        extra_str,
    )
    entry = ProvenanceEntry(
        pass_name=str(pass_name),
        action=str(action),
        block_serial=block_int,
        target_serial=target_int,
        reason=str(reason),
        extra_json=extra_json,
    )
    with _pending_lock:
        _pending.append(entry)


def _safe_serial(value: object) -> int:
    try:
        return int(value)
    except Exception:
        return -1


def _live_maturity_label(mba: Any | None) -> str:
    if mba is None:
        return "maturity=?"
    try:
        value = int(getattr(mba, "maturity"))
    except Exception:
        return "maturity=?"
    names = {
        0: "MMAT_ZERO",
        1: "MMAT_GENERATED",
        2: "MMAT_PREOPTIMIZED",
        3: "MMAT_LOCOPT",
        4: "MMAT_CALLS",
        5: "MMAT_GLBOPT1",
        6: "MMAT_GLBOPT2",
        7: "MMAT_GLBOPT3",
        8: "MMAT_LVARS",
    }
    return names.get(value, f"MMAT_{value}")


def _live_block_label(mba: Any | None, serial: int | None) -> str:
    if serial is None:
        return "blk[?]@?"
    serial_int = int(serial)
    if mba is None:
        return f"blk[{serial_int}]@?"
    try:
        blk = mba.get_mblock(serial_int)
        return f"blk[{serial_int}]@0x{int(blk.start):x}"
    except Exception:
        return f"blk[{serial_int}]@?"


def drain_pending_provenance() -> list[ProvenanceEntry]:
    """Atomically drain and return the pending provenance buffer.

    Retained for tests that drive the producer directly; production
    flows publish ``CfgProvenanceObserved`` events through the bus
    instead, and the diag subscriber owns the flush.
    """
    with _pending_lock:
        out = list(_pending)
        _pending.clear()
    return out


def reset_pending_provenance() -> None:
    """Clear the pending buffer without flushing. Test harness use."""
    with _pending_lock:
        _pending.clear()


# All call sites use ``observe_cfg_provenance`` from
# ``d810.cfg.observability``; the diag subscriber buffers
# ``CfgProvenanceObserved`` events and flushes them under the next
# captured snapshot. ``log_cfg_provenance`` is the concrete producer;
# ``observe_cfg_provenance`` constructs the event payload and emits.

__all__ = [
    "ProvenanceEntry",
    "drain_pending_provenance",
    "log_cfg_provenance",
    "reset_pending_provenance",
]
