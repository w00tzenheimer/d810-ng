"""Shared unflattening engine primitives.

This package hosts the reusable execution surface for strategy-based
unflattening flows. The canonical lifecycle remains detect -> snapshot ->
plan -> execute, with Hodur as the first production consumer.
"""

from .family import CFFStrategyFamily, DetectionResult
from .metrics import handler_coverage, structure_quality_score
from .planner import PipelinePolicy, PlannerHintSignals, UnflatteningPlanner
from .provenance import (
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
from .snapshot import AnalysisSnapshot, ReachabilityInfo, StateModelSummary
from .strategy import (
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
    "AnalysisSnapshot",
    "CFFStrategyFamily",
    "DecisionInputSummary",
    "DecisionPhase",
    "DecisionReasonCode",
    "DecisionRecord",
    "DetectionResult",
    "FAMILY_CLEANUP",
    "FAMILY_DIRECT",
    "FAMILY_FALLBACK",
    "GateAccounting",
    "GateDecision",
    "GateVerdict",
    "BenefitMetrics",
    "OwnershipScope",
    "PipelinePolicy",
    "PlanFragment",
    "PipelineProvenance",
    "PlannerHintSignals",
    "PlannerInputs",
    "ReachabilityInfo",
    "StateModelSummary",
    "StageResult",
    "UnflatteningPlanner",
    "UnflatteningStrategy",
    "VerificationGate",
    "handler_coverage",
    "structure_quality_score",
]


def __getattr__(name: str):
    if name == "SemanticGate":
        from . import strategy as strategy_module

        return strategy_module.SemanticGate
    if name == "TransactionalExecutor":
        try:
            from .executor import TransactionalExecutor
        except ModuleNotFoundError as exc:
            if exc.name and exc.name.startswith("ida"):
                raise AttributeError(
                    "TransactionalExecutor is unavailable without IDA dependencies"
                ) from exc
            raise

        return TransactionalExecutor
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
