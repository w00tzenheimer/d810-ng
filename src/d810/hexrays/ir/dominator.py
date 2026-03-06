"""Hex-Rays compatibility shims for dominator analysis over live ``mba_t``.

The actual implementation now lives in :mod:`d810.cfg.dominator`.
This module re-exports the public API for backward compatibility.
"""
from __future__ import annotations

from d810.cfg.dominator import compute_dominators, dominates  # noqa: F401

__all__ = ["compute_dominators", "dominates"]
