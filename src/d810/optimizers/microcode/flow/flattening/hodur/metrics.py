"""Backward-compatible Hodur metrics re-exports."""
from __future__ import annotations

from d810.optimizers.microcode.flow.flattening.engine.metrics import (
    handler_coverage,
    structure_quality_score,
)

__all__ = ["handler_coverage", "structure_quality_score"]
