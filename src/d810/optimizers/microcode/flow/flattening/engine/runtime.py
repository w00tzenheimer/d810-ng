"""Generic runtime helpers for family-driven unflattening pipelines."""
from __future__ import annotations

from dataclasses import dataclass, field, replace

from d810.core.typing import TYPE_CHECKING, Any, Callable, Mapping, Protocol

from d810.analyses.control_flow.provenance import (
    DecisionPhase,
    DecisionReasonCode,
    PipelineProvenance,
    PlannerInputs,
)
from d810.passes.strategy import PlanFragment, StageResult

if TYPE_CHECKING:
    from .planner import UnflatteningPlanner
    from d810.transforms.snapshot import AnalysisSnapshot
    from d810.passes.strategy import UnflatteningStrategy

__all__ = [
    "ExecutorPolicy",
    "FamilyAnalysis",
    "FamilyContext",
    "FamilyPassResult",
    "FamilyPostPipelineContext",
    "FamilyRunState",
    "FamilyRuntimePolicy",
    "PlannedPipeline",
    "ExecutedPipeline",
    "make_transactional_executor_factory",
    "plan_family_pipeline",
    "run_configured_family_pass",
    "run_family_pass",
    "run_ordered_family_hooks",
    "apply_execution_results_to_provenance",
    "execute_family_pipeline",
]


class _PipelineExecutor(Protocol):
    @property
    def total_changes(self) -> int: ...

    def execute_pipeline(
        self, pipeline: list[PlanFragment], total_handlers: int
    ) -> list[StageResult]: ...


class FamilyHook(Protocol):
    def __call__(self, context: "FamilyPostPipelineContext") -> None: ...


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
class FamilyContext:
    """Runtime context for one family pass."""

    mba: object
    maturity: int
    pass_number: int
    flow_context: Any | None = None
    log_dir: object | None = None

    @classmethod
    def from_rule(cls, rule: object, blk: object) -> "FamilyContext":
        """Build a family context from an optimizer rule callback."""
        mba = getattr(blk, "mba")
        return cls(
            mba=mba,
            maturity=int(getattr(rule, "cur_maturity")),
            pass_number=int(getattr(rule, "_actual_pass_count", 0)),
            flow_context=getattr(rule, "flow_context", None),
            log_dir=getattr(rule, "log_dir", None),
        )


@dataclass(frozen=True)
class FamilyAnalysis:
    """Detection plus immutable snapshot for one family pass."""

    detection: object
    snapshot: AnalysisSnapshot

    @property
    def detected(self) -> bool:
        return bool(getattr(self.detection, "detected", False))


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


@dataclass(frozen=True)
class FamilyPassResult:
    """Complete generic runtime result for one family pass."""

    analysis: FamilyAnalysis
    planned: PlannedPipeline
    executed: ExecutedPipeline

    @property
    def pipeline(self) -> list[PlanFragment]:
        return self.executed.pipeline

    @property
    def results(self) -> list[StageResult]:
        return self.executed.results

    @property
    def provenance(self) -> PipelineProvenance:
        return self.executed.provenance

    @property
    def total_changes(self) -> int:
        return self.executed.total_changes


@dataclass
class FamilyPostPipelineContext:
    """Mutable state shared by ordered family post-pipeline hooks."""

    analysis: FamilyAnalysis
    planned: PlannedPipeline
    executed: ExecutedPipeline
    total_changes: int
    state: dict[str, Any] = field(default_factory=dict)

    @property
    def snapshot(self) -> AnalysisSnapshot:
        return self.analysis.snapshot

    @property
    def pipeline(self) -> list[PlanFragment]:
        return self.executed.pipeline

    @property
    def results(self) -> list[StageResult]:
        return self.executed.results

    @property
    def provenance(self) -> PipelineProvenance:
        return self.executed.provenance


def run_ordered_family_hooks(
    hook_names: tuple[str, ...],
    hook_handlers: Mapping[str, FamilyHook],
    context: FamilyPostPipelineContext,
    *,
    strict: bool = True,
) -> FamilyPostPipelineContext:
    """Run profile-declared hooks in order against one family pass context."""
    for hook_name in hook_names:
        handler = hook_handlers.get(hook_name)
        if handler is None:
            if strict:
                raise KeyError(f"family hook is not registered: {hook_name}")
            continue
        handler(context)
    return context


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


@dataclass(frozen=True)
class FamilyRuntimePolicy:
    """Callable policy for one configured family runtime pass."""

    planner: UnflatteningPlanner
    executor_policy: ExecutorPolicy
    build_planner_inputs: Callable[[FamilyContext, FamilyAnalysis], PlannerInputs | None]
    select_strategies: Callable[[FamilyContext, FamilyAnalysis], list[UnflatteningStrategy]]
    plan_pipeline: Callable[..., PlannedPipeline] = plan_family_pipeline
    execute_pipeline: Callable[..., ExecutedPipeline] = execute_family_pipeline
    executor_factory_builder: Callable[
        [ExecutorPolicy], Callable[[object], _PipelineExecutor]
    ] = make_transactional_executor_factory
    on_analysis: Callable[[FamilyContext, FamilyAnalysis], None] | None = None
    on_planned: Callable[[FamilyContext, FamilyAnalysis, PlannedPipeline], None] | None = None
    on_executed: Callable[
        [FamilyContext, FamilyAnalysis, PlannedPipeline, ExecutedPipeline], None
    ] | None = None


def run_family_pass(
    family: object,
    context: FamilyContext,
    *,
    planner: UnflatteningPlanner,
    executor_policy: ExecutorPolicy,
    build_planner_inputs: Callable[[FamilyContext, FamilyAnalysis], PlannerInputs | None],
    select_strategies: Callable[[FamilyContext, FamilyAnalysis], list[UnflatteningStrategy]],
    plan_pipeline: Callable[..., PlannedPipeline] = plan_family_pipeline,
    execute_pipeline: Callable[..., ExecutedPipeline] = execute_family_pipeline,
    executor_factory_builder: Callable[
        [ExecutorPolicy], Callable[[object], _PipelineExecutor]
    ] = make_transactional_executor_factory,
    on_analysis: Callable[[FamilyContext, FamilyAnalysis], None] | None = None,
    on_planned: Callable[[FamilyContext, FamilyAnalysis, PlannedPipeline], None]
    | None = None,
    on_executed: Callable[
        [FamilyContext, FamilyAnalysis, PlannedPipeline, ExecutedPipeline], None
    ]
    | None = None,
) -> FamilyPassResult:
    """Run the generic detect -> snapshot -> plan -> execute family pipeline."""
    begin_pass = getattr(family, "begin_pass", None)
    if callable(begin_pass):
        begin_pass(context.pass_number)

    detection = family.detect(context.mba)
    snapshot = family.build_snapshot(context.mba, detection)
    analysis = FamilyAnalysis(detection=detection, snapshot=snapshot)
    if on_analysis is not None:
        on_analysis(context, analysis)

    planner_inputs = build_planner_inputs(context, analysis)
    strategies = select_strategies(context, analysis)
    planned = plan_pipeline(
        snapshot,
        strategies,
        planner=planner,
        inputs=planner_inputs,
    )
    if on_planned is not None:
        on_planned(context, analysis, planned)

    if planned.pipeline:
        executed = execute_pipeline(
            snapshot,
            planned,
            executor_factory=executor_factory_builder(executor_policy),
            flow_context=context.flow_context,
        )
    else:
        executed = ExecutedPipeline(
            pipeline=[],
            results=[],
            provenance=planned.provenance,
            total_changes=0,
            executor=None,
        )

    if on_executed is not None:
        on_executed(context, analysis, planned, executed)

    return FamilyPassResult(
        analysis=analysis,
        planned=planned,
        executed=executed,
    )


def run_configured_family_pass(
    family: object,
    context: FamilyContext,
    policy: FamilyRuntimePolicy,
) -> FamilyPassResult:
    """Run a family pass using a pre-bound runtime policy."""
    return run_family_pass(
        family,
        context,
        planner=policy.planner,
        executor_policy=policy.executor_policy,
        build_planner_inputs=policy.build_planner_inputs,
        select_strategies=policy.select_strategies,
        plan_pipeline=policy.plan_pipeline,
        execute_pipeline=policy.execute_pipeline,
        executor_factory_builder=policy.executor_factory_builder,
        on_analysis=policy.on_analysis,
        on_planned=policy.on_planned,
        on_executed=policy.on_executed,
    )
