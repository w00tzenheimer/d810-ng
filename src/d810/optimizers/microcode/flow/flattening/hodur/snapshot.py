"""Backward-compatible Hodur snapshot re-exports.

The canonical snapshot surface now lives in
``d810.optimizers.microcode.flow.flattening.engine.snapshot``.
"""
from __future__ import annotations

from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
    ReachabilityInfo,
    StateModelSummary,
)

__all__ = ["AnalysisSnapshot", "ReachabilityInfo", "StateModelSummary"]
