"""Shared unflattening engine primitives.

This package hosts the reusable execution surface for strategy-based
unflattening flows. The canonical lifecycle remains detect -> snapshot ->
plan -> execute, with Hodur as the first production consumer.
"""

from .family import CFFStrategyFamily, DetectionResult
from .metrics import handler_coverage, structure_quality_score
from .planner import PipelinePolicy, PlannerHintSignals, UnflatteningPlanner
from .provenance import (
    DagDisagreementRecord,
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
from .runtime import (
    ExecutedPipeline,
    ExecutorPolicy,
    FamilyAnalysis,
    FamilyContext,
    FamilyPassResult,
    FamilyPostPipelineContext,
    FamilyRunState,
    FamilyRuntimePolicy,
    PlannedPipeline,
    apply_execution_results_to_provenance,
    execute_family_pipeline,
    make_transactional_executor_factory,
    plan_family_pipeline,
    run_configured_family_pass,
    run_family_pass,
    run_ordered_family_hooks,
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
    "apply_execution_results_to_provenance",
    "CFFStrategyFamily",
    "DagDisagreementRecord",
    "DecisionInputSummary",
    "DecisionPhase",
    "DecisionReasonCode",
    "DecisionRecord",
    "DetectionResult",
    "ExecutedPipeline",
    "ExecutorPolicy",
    "FamilyAnalysis",
    "FamilyContext",
    "FamilyPassResult",
    "FamilyPostPipelineContext",
    "FamilyRunState",
    "FamilyRuntimePolicy",
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
    "PlannedPipeline",
    "PipelineProvenance",
    "PlannerHintSignals",
    "PlannerInputs",
    "ReachabilityInfo",
    "StateModelSummary",
    "StageResult",
    "UnflatteningPlanner",
    "UnflatteningStrategy",
    "VerificationGate",
    "execute_family_pipeline",
    "handler_coverage",
    "make_transactional_executor_factory",
    "plan_family_pipeline",
    "run_configured_family_pass",
    "run_family_pass",
    "run_ordered_family_hooks",
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
