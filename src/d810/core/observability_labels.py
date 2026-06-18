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

from d810.core.formatting import format_block_id
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
    """Format ``blk[serial]@0x...`` from a live or portable CFG source.

    Reads ``source.blocks[serial].start_ea`` (portable ``FlowGraph``) or
    ``source.get_mblock(serial).start`` (live Hex-Rays MBA) by duck typing
    only -- ``core`` may not import ``ir``, Hex-Rays, or IDA. Degrades to
    ``blk[serial]@unknown`` only when no effective address is available.
    """
    if serial is None:
        return format_block_id(None)
    serial_int = int(serial)
    ea = live_block_start_ea(source, serial_int)
    return format_block_id(serial_int, start_ea=ea)


def live_block_start_ea(source: Any | None, serial: int | None) -> int | None:
    """Return a block start EA from a portable graph or live MBA source."""
    if source is None or serial is None:
        return None
    serial_int = int(serial)
    try:
        blocks = getattr(source, "blocks", None)
        getter = getattr(blocks, "get", None)
        blk = getter(serial_int) if callable(getter) else None
        ea = getattr(blk, "start_ea", None) if blk is not None else None
        if ea is not None:
            return int(ea)
    except Exception:
        pass
    try:
        getter = getattr(source, "get_mblock", None)
        blk = getter(serial_int) if callable(getter) else None
        ea = getattr(blk, "start", None) if blk is not None else None
        if ea is not None:
            return int(ea)
    except Exception:
        pass
    return None
