"""Generic runtime helpers for family-driven unflattening pipelines."""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import TYPE_CHECKING, Any, Callable, Protocol

from .provenance import (
    DecisionPhase,
    DecisionReasonCode,
    PipelineProvenance,
    PlannerInputs,
)
from .strategy import PlanFragment, StageResult

if TYPE_CHECKING:
    from .planner import UnflatteningPlanner
    from .snapshot import AnalysisSnapshot
    from .strategy import UnflatteningStrategy

__all__ = [
    "PlannedPipeline",
    "ExecutedPipeline",
    "plan_family_pipeline",
    "apply_execution_results_to_provenance",
    "execute_family_pipeline",
]


class _PipelineExecutor(Protocol):
    @property
    def total_changes(self) -> int: ...

    def execute_pipeline(
        self, pipeline: list[PlanFragment], total_handlers: int
    ) -> list[StageResult]: ...


@dataclass(frozen=True)
class PlannedPipeline:
    """Planner output for one family pass."""

    pipeline: list[PlanFragment]
    provenance: PipelineProvenance


@dataclass(frozen=True)
class ExecutedPipeline:
    """Executor output for one family pass."""

    pipeline: list[PlanFragment]
    results: list[StageResult]
    provenance: PipelineProvenance
    total_changes: int
    executor: object | None = None


def plan_family_pipeline(
    snapshot: AnalysisSnapshot,
    strategies: list[UnflatteningStrategy],
    *,
    planner: UnflatteningPlanner,
    inputs: PlannerInputs | None = None,
) -> PlannedPipeline:
    """Run the shared planner against one family snapshot."""
    pipeline, provenance = planner.plan(snapshot, strategies, inputs=inputs)
    return PlannedPipeline(pipeline=pipeline, provenance=provenance)


def apply_execution_results_to_provenance(
    provenance: PipelineProvenance,
    pipeline: list[PlanFragment],
    results: list[StageResult],
) -> PipelineProvenance:
    """Project executor outcomes back onto planner provenance rows."""
    updated = provenance
    for fragment, result in zip(pipeline, results):
        gate_accounting = result.metadata.get("gate_accounting")
        if result.success:
            updated = updated.update_phase(
                fragment.strategy_name,
                DecisionPhase.APPLIED,
                reason_code=DecisionReasonCode.ACCEPTED,
                gate_accounting=gate_accounting,
            )
        elif result.failure_phase == "preflight":
            updated = updated.update_phase(
                fragment.strategy_name,
                DecisionPhase.PREFLIGHT_REJECTED,
                reason_code=DecisionReasonCode.REJECTED_PREFLIGHT,
                reason_detail=result.error,
                gate_accounting=gate_accounting,
            )
        elif result.failure_phase == "safeguard":
            updated = updated.update_phase(
                fragment.strategy_name,
                DecisionPhase.GATE_FAILED,
                reason_code=DecisionReasonCode.REJECTED_GATE_SAFEGUARD,
                reason_detail=result.error,
                gate_accounting=gate_accounting,
            )
        elif result.failure_phase == "semantic_gate":
            updated = updated.update_phase(
                fragment.strategy_name,
                DecisionPhase.GATE_FAILED,
                reason_code=DecisionReasonCode.REJECTED_GATE_SEMANTIC,
                reason_detail=result.error,
                gate_accounting=gate_accounting,
            )
        elif result.failure_phase == "post_apply_contract":
            updated = updated.update_phase(
                fragment.strategy_name,
                DecisionPhase.GATE_FAILED,
                reason_code=DecisionReasonCode.REJECTED_GATE,
                reason_detail=result.error,
                gate_accounting=gate_accounting,
            )
        else:
            updated = updated.update_phase(
                fragment.strategy_name,
                DecisionPhase.GATE_FAILED,
                reason_code=DecisionReasonCode.REJECTED_TRANSACTION,
                reason_detail=result.error or "execution failed",
                gate_accounting=gate_accounting,
            )

    for fragment in pipeline[len(results):]:
        updated = updated.update_phase(
            fragment.strategy_name,
            DecisionPhase.BYPASSED,
            reason_code=DecisionReasonCode.BYPASSED_PIPELINE_ABORT,
            reason_detail="pipeline aborted before this fragment was executed",
        )

    return updated


def execute_family_pipeline(
    snapshot: AnalysisSnapshot,
    planned: PlannedPipeline,
    *,
    executor_factory: Callable[[object], _PipelineExecutor],
    flow_context: Any | None = None,
) -> ExecutedPipeline:
    """Execute a planned pipeline and update generic provenance state."""
    if not planned.pipeline:
        return ExecutedPipeline(
            pipeline=[],
            results=[],
            provenance=planned.provenance,
            total_changes=0,
            executor=None,
        )

    executor = executor_factory(snapshot.mba)
    attach_snapshot = getattr(executor, "set_analysis_snapshot", None)
    if callable(attach_snapshot):
        attach_snapshot(snapshot)
    results = executor.execute_pipeline(
        planned.pipeline, total_handlers=snapshot.handler_count
    )
    provenance = apply_execution_results_to_provenance(
        planned.provenance,
        planned.pipeline,
        results,
    )

    if flow_context is not None and hasattr(flow_context, "report_outcome"):
        flow_context.report_outcome(provenance, "planner")

    return ExecutedPipeline(
        pipeline=planned.pipeline,
        results=results,
        provenance=provenance,
        total_changes=executor.total_changes,
        executor=executor,
    )
