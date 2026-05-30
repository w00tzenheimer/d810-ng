"""Neutral diagnostic label formatting (``core`` layer, dependency-free).

Duck-typed, diagnostic-only helpers shared by the producer-side
provenance log API (:mod:`d810.ir.provenance`) and the CFG observability
event facade (:mod:`d810.core.observability_cfg`). They format
human-readable block / maturity labels from a live ``mba``-like source
without importing Hex-Rays, IDA, ``ir`` or ``cfg`` -- the source is
duck-typed (``get_mblock`` / ``start`` / ``maturity`` attributes), so
this stays portable at the ``core`` layer and both the log line and the
event payload use the exact same label strings (no drift).
"""
from __future__ import annotations

from d810.core.typing import Any


def safe_serial(value: object) -> int:
    """Coerce a block serial to ``int``; ``-1`` when not coercible."""
    try:
        return int(value)
    except Exception:
        return -1


def live_maturity_label(source: Any | None) -> str:
    """Format the ``MMAT_*`` maturity name from a duck-typed ``mba`` source."""
    if source is None:
        return "maturity=?"
    try:
        value = int(getattr(source, "maturity"))
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


def live_block_label(source: Any | None, serial: int | None) -> str:
    """Format ``blk[serial]@0x...`` from a duck-typed ``mba`` source."""
    if serial is None:
        return "blk[?]@?"
    serial_int = int(serial)
    if source is None:
        return f"blk[{serial_int}]@?"
    try:
        blk = source.get_mblock(serial_int)
        return f"blk[{serial_int}]@0x{int(blk.start):x}"
    except Exception:
        return f"blk[{serial_int}]@?"
