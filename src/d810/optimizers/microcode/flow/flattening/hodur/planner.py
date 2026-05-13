"""Backward-compatible Hodur planner re-exports.

The canonical planner surface now lives in
``d810.optimizers.microcode.flow.flattening.engine.planner``.
"""
from __future__ import annotations

from d810.optimizers.microcode.flow.flattening.engine.planner import (
    HintAdjustment,
    PipelinePolicy,
    PlannerCandidate,
    PlannerDecision,
    PlannerDecisionReason,
    PlannerHintSignals,
    UnflatteningPlanner,
    _REASON_TO_CODE,
    _REASON_TO_PHASE,
    compute_hint_adjustment,
    derive_hint_signals,
)

__all__ = [
    "HintAdjustment",
    "PipelinePolicy",
    "PlannerCandidate",
    "PlannerDecision",
    "PlannerDecisionReason",
    "PlannerHintSignals",
    "UnflatteningPlanner",
    "compute_hint_adjustment",
    "derive_hint_signals",
]
