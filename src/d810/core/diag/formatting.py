"""Shared diagnostic formatting helpers (back-compat re-export).

The implementation now lives in :mod:`d810.core.formatting` so neutral
observation models can format block ids without importing core.diag.
This module is kept for back-compat with existing callers (mainly
:mod:`d810.diagnostics.__main__`).
"""
from __future__ import annotations

from d810.core.formatting import format_block_id as format_block_id

__all__ = ["format_block_id"]
