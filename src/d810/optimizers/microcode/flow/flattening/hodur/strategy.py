"""Backward-compatible Hodur strategy re-exports.

The canonical protocol surface now lives in
``d810.optimizers.microcode.flow.flattening.engine.strategy``.
"""
from __future__ import annotations

from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_CLEANUP,
    FAMILY_DIRECT,
    FAMILY_FALLBACK,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
    StageResult,
    UnflatteningStrategy,
    VerificationGate,
)

__all__ = [
    "FAMILY_CLEANUP",
    "FAMILY_DIRECT",
    "FAMILY_FALLBACK",
    "BenefitMetrics",
    "OwnershipScope",
    "PlanFragment",
    "StageResult",
    "UnflatteningStrategy",
    "VerificationGate",
]


def __getattr__(name: str):
    if name == "SemanticGate":
        from d810.optimizers.microcode.flow.flattening.engine import (
            strategy as engine_strategy,
        )

        return engine_strategy.SemanticGate
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
