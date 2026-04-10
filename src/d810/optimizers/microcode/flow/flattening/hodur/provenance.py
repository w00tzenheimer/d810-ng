"""Backward-compatible Hodur provenance re-exports.

The canonical provenance surface now lives in
``d810.optimizers.microcode.flow.flattening.engine.provenance``.
"""
from __future__ import annotations

from d810.optimizers.microcode.flow.flattening.engine.provenance import (
    DecisionInputSummary,
    DecisionPhase,
    DecisionReasonCode,
    DecisionRecord,
    GateAccounting,
    GateDecision,
    GateVerdict,
    PipelineProvenance,
    PlannerInputs,
)

__all__ = [
    "DecisionInputSummary",
    "DecisionPhase",
    "DecisionReasonCode",
    "DecisionRecord",
    "GateAccounting",
    "GateDecision",
    "GateVerdict",
    "PipelineProvenance",
    "PlannerInputs",
]
