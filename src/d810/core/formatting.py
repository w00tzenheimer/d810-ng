"""Shared diagnostic formatting helpers.

Lives under :mod:`d810.core` (not :mod:`d810.core.diag`) so that the
neutral observation-model module
(:mod:`d810.core.observability_models`) can format block ids in its
``__str__`` methods without dragging the diag SQLite sink into the
import graph.

``d810.core.diag.formatting`` is a thin re-export of this module for
back-compat with existing callers.
"""
from __future__ import annotations


def _normalize_ea(value: int | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            value = int(stripped, 0)
        except ValueError:
            return stripped
    return f"0x{int(value):X}"


def format_block_id(
    serial: int | str | None,
    start_ea: int | str | None = None,
    lineage_ea: int | str | None = None,
    synthetic: bool = False,
) -> str:
    """Format a block serial with diagnostic identity.

    Serial-only block identifiers are ambiguous across snapshots.
    Prefer a concrete start EA, then copy-lineage EA, then an explicit
    synthetic marker.
    """
    if serial is None:
        return "blk[?]@unknown"
    base = f"blk[{serial}]"
    ea_text = _normalize_ea(start_ea)
    if ea_text is not None:
        return f"{base}@{ea_text}"
    lineage_text = _normalize_ea(lineage_ea)
    if lineage_text is not None:
        return f"{base}@copy-of:{lineage_text}"
    if synthetic:
        return f"{base}@synthetic"
    return f"{base}@unknown"


__all__ = ["format_block_id"]
