"""Generic runtime helpers for family-driven unflattening pipelines."""
from __future__ import annotations

from dataclasses import dataclass, replace

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
    "ExecutorPolicy",
    "FamilyRunState",
    "PlannedPipeline",
    "ExecutedPipeline",
    "make_transactional_executor_factory",
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
class ExecutorPolicy:
    """Runtime-owned configuration for transactional executor construction."""

    gate: object | None = None
    allow_legacy_block_creation: bool = True
    safeguard_profile: str = "engine"


@dataclass(frozen=True)
class FamilyRunState:
    """Runtime-owned pass bookkeeping shared by family adapters."""

    pass_number: int = 0
    resolved_transitions: frozenset[tuple[int | None, int]] = frozenset()
    initial_transitions: tuple[object, ...] = ()

    def begin_pass(self, pass_number: int) -> "FamilyRunState":
        """Return run state for the next family pass."""
        return replace(self, pass_number=int(pass_number))

    def remember_initial_transitions(
        self, transitions: object
    ) -> "FamilyRunState":
        """Capture pass-0 transitions once for later supplementation."""
        if self.pass_number != 0 or self.initial_transitions:
            return self
        return replace(self, initial_transitions=tuple(transitions or ()))

    def record_resolved_transitions(
        self, transitions: object
    ) -> "FamilyRunState":
        """Record transition keys covered by a successful execution pass."""
        resolved = set(self.resolved_transitions)
        for transition in transitions or ():
            to_state = getattr(transition, "to_state", None)
            if not isinstance(to_state, int):
                continue
            from_state = getattr(transition, "from_state", None)
            if from_state is not None and not isinstance(from_state, int):
                continue
            resolved.add((from_state, to_state))
        return replace(self, resolved_transitions=frozenset(resolved))


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


def make_transactional_executor_factory(
    policy: ExecutorPolicy,
) -> Callable[[object], _PipelineExecutor]:
    """Build a transactional executor factory from shared runtime policy."""

    def _factory(mba: object) -> _PipelineExecutor:
        from .executor import TransactionalExecutor

        return TransactionalExecutor(
            mba,
            gate=policy.gate,
            allow_legacy_block_creation=policy.allow_legacy_block_creation,
            safeguard_profile=policy.safeguard_profile,
        )

    return _factory


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
