"""Runtime tests for shared family pipeline helpers."""
from __future__ import annotations

from types import SimpleNamespace

from d810.optimizers.microcode.flow.flattening import engine
from d810.optimizers.microcode.flow.flattening.engine.provenance import (
    DecisionPhase,
    DecisionReasonCode,
    DecisionRecord,
    GateAccounting,
    GateDecision,
    GateVerdict,
    PipelineProvenance,
)
from d810.optimizers.microcode.flow.flattening.engine.runtime import (
    ExecutedPipeline,
    PlannedPipeline,
    apply_execution_results_to_provenance,
    execute_family_pipeline,
    plan_family_pipeline,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
    StageResult,
)


def _fragment(name: str) -> PlanFragment:
    return PlanFragment(
        strategy_name=name,
        family="cleanup",
        ownership=OwnershipScope(
            blocks=frozenset(),
            edges=frozenset(),
            transitions=frozenset(),
        ),
        prerequisites=[],
        expected_benefit=BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=0,
            blocks_freed=0,
            conflict_density=0.0,
        ),
        risk_score=0.0,
        modifications=[object()],
    )


def _provenance(*names: str) -> PipelineProvenance:
    return PipelineProvenance(
        rows=tuple(
            DecisionRecord(
                strategy_name=name,
                family="cleanup",
                phase=DecisionPhase.SELECTED,
                reason_code=DecisionReasonCode.ACCEPTED,
                reason="selected",
            )
            for name in names
        ),
    )


def test_engine_package_re_exports_runtime_types() -> None:
    assert engine.PlannedPipeline is PlannedPipeline
    assert engine.ExecutedPipeline is ExecutedPipeline
    assert engine.plan_family_pipeline is plan_family_pipeline
    assert engine.execute_family_pipeline is execute_family_pipeline
    assert (
        engine.apply_execution_results_to_provenance
        is apply_execution_results_to_provenance
    )


def test_plan_family_pipeline_delegates_to_planner() -> None:
    fragment = _fragment("planned")
    provenance = _provenance("planned")
    calls: list[object] = []

    class _Planner:
        def plan(self, snapshot, strategies, *, inputs=None):
            calls.append((snapshot, strategies, inputs))
            return [fragment], provenance

    snapshot = SimpleNamespace()
    strategies = [object()]

    planned = plan_family_pipeline(
        snapshot,
        strategies,
        planner=_Planner(),
        inputs="planner_inputs",
    )

    assert planned == PlannedPipeline(pipeline=[fragment], provenance=provenance)
    assert calls == [(snapshot, strategies, "planner_inputs")]


def test_execute_family_pipeline_skips_executor_for_empty_pipeline() -> None:
    planned = PlannedPipeline(pipeline=[], provenance=_provenance())
    snapshot = SimpleNamespace(mba=object(), handler_count=3)
    executor_factories: list[object] = []
    outcomes: list[object] = []
    flow_context = SimpleNamespace(
        report_outcome=lambda provenance, source: outcomes.append((provenance, source))
    )

    executed = execute_family_pipeline(
        snapshot,
        planned,
        executor_factory=lambda mba: executor_factories.append(mba),
        flow_context=flow_context,
    )

    assert executed == ExecutedPipeline(
        pipeline=[],
        results=[],
        provenance=planned.provenance,
        total_changes=0,
        executor=None,
    )
    assert executor_factories == []
    assert outcomes == []


def test_apply_execution_results_to_provenance_maps_failure_phases() -> None:
    accounting = GateAccounting().add(
        GateDecision("semantic_gate", GateVerdict.FAILED, "semantic mismatch")
    )
    pipeline = [
        _fragment("applied"),
        _fragment("preflight"),
        _fragment("safeguard"),
        _fragment("semantic"),
        _fragment("contract"),
        _fragment("transaction"),
    ]
    provenance = _provenance(*(fragment.strategy_name for fragment in pipeline))

    updated = apply_execution_results_to_provenance(
        provenance,
        pipeline,
        [
            StageResult(strategy_name="applied", success=True),
            StageResult(
                strategy_name="preflight",
                success=False,
                error="preflight rejected",
                failure_phase="preflight",
            ),
            StageResult(
                strategy_name="safeguard",
                success=False,
                error="too many edges",
                failure_phase="safeguard",
            ),
            StageResult(
                strategy_name="semantic",
                success=False,
                error="semantic mismatch",
                failure_phase="semantic_gate",
                metadata={"gate_accounting": accounting},
            ),
            StageResult(
                strategy_name="contract",
                success=False,
                error="contract violated",
                failure_phase="post_apply_contract",
            ),
            StageResult(
                strategy_name="transaction",
                success=False,
                error=None,
                failure_phase="rollback",
            ),
        ],
    )

    rows = {row.strategy_name: row for row in updated.rows}
    assert rows["applied"].phase == DecisionPhase.APPLIED
    assert rows["applied"].reason_code == DecisionReasonCode.ACCEPTED
    assert rows["preflight"].phase == DecisionPhase.PREFLIGHT_REJECTED
    assert rows["preflight"].reason_code == DecisionReasonCode.REJECTED_PREFLIGHT
    assert rows["safeguard"].reason_code == DecisionReasonCode.REJECTED_GATE_SAFEGUARD
    assert rows["semantic"].reason_code == DecisionReasonCode.REJECTED_GATE_SEMANTIC
    assert rows["semantic"].gate_accounting == accounting
    assert rows["contract"].reason_code == DecisionReasonCode.REJECTED_GATE
    assert rows["transaction"].reason_code == DecisionReasonCode.REJECTED_TRANSACTION
    assert rows["transaction"].reason == "execution failed"


def test_apply_execution_results_to_provenance_marks_pipeline_tail_bypassed() -> None:
    pipeline = [_fragment("first"), _fragment("second")]
    provenance = _provenance("first", "second")

    updated = apply_execution_results_to_provenance(
        provenance,
        pipeline,
        [StageResult(strategy_name="first", success=True)],
    )

    rows = {row.strategy_name: row for row in updated.rows}
    assert rows["first"].phase == DecisionPhase.APPLIED
    assert rows["second"].phase == DecisionPhase.BYPASSED
    assert rows["second"].reason_code == DecisionReasonCode.BYPASSED_PIPELINE_ABORT


def test_execute_family_pipeline_runs_executor_and_reports_outcome() -> None:
    fragment = _fragment("executed")
    planned = PlannedPipeline(
        pipeline=[fragment],
        provenance=_provenance("executed"),
    )
    snapshot = SimpleNamespace(mba="mba", handler_count=7)
    outcomes: list[object] = []

    class _Executor:
        def __init__(self):
            self.total_changes = 2

        def execute_pipeline(self, pipeline, total_handlers):
            assert pipeline == [fragment]
            assert total_handlers == 7
            return [
                StageResult(
                    strategy_name="executed",
                    edits_applied=2,
                    success=True,
                )
            ]

    executed = execute_family_pipeline(
        snapshot,
        planned,
        executor_factory=lambda mba: _Executor() if mba == "mba" else None,
        flow_context=SimpleNamespace(
            report_outcome=lambda provenance, source: outcomes.append(
                (provenance, source)
            )
        ),
    )

    assert executed.total_changes == 2
    assert executed.results[0].strategy_name == "executed"
    assert executed.provenance.rows[0].phase == DecisionPhase.APPLIED
    assert outcomes == [(executed.provenance, "planner")]
