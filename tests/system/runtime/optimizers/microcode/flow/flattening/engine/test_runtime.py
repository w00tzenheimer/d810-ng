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
    FamilyAnalysis,
    FamilyContext,
    FamilyPassResult,
    ExecutorPolicy,
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
    assert engine.ExecutorPolicy is ExecutorPolicy
    assert engine.FamilyAnalysis is FamilyAnalysis
    assert engine.FamilyContext is FamilyContext
    assert engine.FamilyPassResult is FamilyPassResult
    assert engine.FamilyPostPipelineContext is FamilyPostPipelineContext
    assert engine.FamilyRunState is FamilyRunState
    assert engine.FamilyRuntimePolicy is FamilyRuntimePolicy
    assert engine.PlannedPipeline is PlannedPipeline
    assert engine.ExecutedPipeline is ExecutedPipeline
    assert (
        engine.make_transactional_executor_factory
        is make_transactional_executor_factory
    )
    assert engine.plan_family_pipeline is plan_family_pipeline
    assert engine.run_configured_family_pass is run_configured_family_pass
    assert engine.run_family_pass is run_family_pass
    assert engine.run_ordered_family_hooks is run_ordered_family_hooks
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


def test_make_transactional_executor_factory_applies_policy(monkeypatch) -> None:
    seen: list[object] = []

    class _Executor:
        total_changes = 0

        def __init__(self, mba, *, gate, allow_legacy_block_creation, safeguard_profile):
            seen.append((mba, gate, allow_legacy_block_creation, safeguard_profile))

        def execute_pipeline(self, pipeline, total_handlers):
            return []

    from d810.optimizers.microcode.flow.flattening.engine import executor as executor_mod

    monkeypatch.setattr(executor_mod, "TransactionalExecutor", _Executor)
    gate = object()
    factory = make_transactional_executor_factory(
        ExecutorPolicy(
            gate=gate,
            allow_legacy_block_creation=False,
            safeguard_profile="hodur",
        )
    )

    executor = factory("mba")

    assert isinstance(executor, _Executor)
    assert seen == [("mba", gate, False, "hodur")]


def test_family_run_state_tracks_pass_and_transitions() -> None:
    pass0 = FamilyRunState().begin_pass(0)
    transitions = [
        SimpleNamespace(from_state=None, to_state=1),
        SimpleNamespace(from_state=1, to_state=2),
    ]

    pass0 = pass0.remember_initial_transitions(transitions)
    assert pass0.pass_number == 0
    assert pass0.initial_transitions == tuple(transitions)

    pass1 = pass0.begin_pass(1)
    assert pass1.initial_transitions == tuple(transitions)

    resolved = pass1.record_resolved_transitions(transitions)
    assert resolved.resolved_transitions == frozenset({(None, 1), (1, 2)})


def test_run_family_pass_orchestrates_detection_planning_and_execution() -> None:
    fragment = _fragment("runtime")
    planned_provenance = _provenance("runtime")
    executed_provenance = planned_provenance.update_phase(
        "runtime",
        DecisionPhase.APPLIED,
        reason_code=DecisionReasonCode.ACCEPTED,
    )
    calls: list[object] = []
    detection = SimpleNamespace(detected=True)
    snapshot = SimpleNamespace(mba="mba", handler_count=1)
    context = FamilyContext(mba="mba", maturity=8, pass_number=3)

    class _Family:
        def begin_pass(self, pass_number):
            calls.append(("begin_pass", pass_number))

        def detect(self, mba):
            calls.append(("detect", mba))
            return detection

        def build_snapshot(self, mba, detection_arg):
            calls.append(("build_snapshot", mba, detection_arg))
            return snapshot

    result = run_family_pass(
        _Family(),
        context,
        planner="planner",
        executor_policy=ExecutorPolicy(safeguard_profile="hodur"),
        build_planner_inputs=lambda ctx, analysis: (
            calls.append(("build_inputs", ctx, analysis))
            or "planner_inputs"
        ),
        select_strategies=lambda ctx, analysis: (
            calls.append(("select_strategies", ctx, analysis))
            or ["strategy"]
        ),
        plan_pipeline=lambda snap, strategies, *, planner, inputs=None: (
            calls.append(("plan", snap, strategies, planner, inputs))
            or PlannedPipeline([fragment], planned_provenance)
        ),
        execute_pipeline=lambda snap, planned, *, executor_factory, flow_context=None: (
            calls.append(("execute", snap, planned, executor_factory, flow_context))
            or ExecutedPipeline(
                planned.pipeline,
                [StageResult(strategy_name="runtime", success=True)],
                executed_provenance,
                1,
            )
        ),
        executor_factory_builder=lambda policy: (
            calls.append(("executor_policy", policy)) or "factory"
        ),
        on_analysis=lambda ctx, analysis: calls.append(("on_analysis", ctx, analysis)),
        on_planned=lambda ctx, analysis, planned: calls.append(
            ("on_planned", ctx, analysis, planned)
        ),
        on_executed=lambda ctx, analysis, planned, executed: calls.append(
            ("on_executed", ctx, analysis, planned, executed)
        ),
    )

    assert result.analysis.detection is detection
    assert result.analysis.snapshot is snapshot
    assert result.pipeline == [fragment]
    assert result.total_changes == 1
    assert calls[0:3] == [
        ("begin_pass", 3),
        ("detect", "mba"),
        ("build_snapshot", "mba", detection),
    ]
    assert any(call[0] == "executor_policy" for call in calls)
    assert any(call[0] == "on_executed" for call in calls)


def test_run_ordered_family_hooks_uses_profile_order_and_mutable_context() -> None:
    analysis = FamilyAnalysis(
        detection=SimpleNamespace(detected=True),
        snapshot=SimpleNamespace(),
    )
    planned = PlannedPipeline(pipeline=[], provenance=_provenance())
    executed = ExecutedPipeline(
        pipeline=[],
        results=[],
        provenance=planned.provenance,
        total_changes=0,
    )
    context = FamilyPostPipelineContext(
        analysis=analysis,
        planned=planned,
        executed=executed,
        total_changes=1,
    )
    calls: list[str] = []

    def first(ctx: FamilyPostPipelineContext) -> None:
        calls.append("first")
        ctx.total_changes += 2
        ctx.state["seen"] = "first"

    def second(ctx: FamilyPostPipelineContext) -> None:
        calls.append(f"second:{ctx.state['seen']}")
        ctx.total_changes *= 3

    result = run_ordered_family_hooks(
        ("first", "second"),
        {"first": first, "second": second},
        context,
    )

    assert result is context
    assert calls == ["first", "second:first"]
    assert context.total_changes == 9


def test_run_configured_family_pass_uses_bound_runtime_policy() -> None:
    fragment = _fragment("configured")
    provenance = _provenance("configured")
    calls: list[object] = []
    detection = SimpleNamespace(detected=True)
    snapshot = SimpleNamespace(mba="mba", handler_count=1)
    context = FamilyContext(mba="mba", maturity=8, pass_number=1)

    class _Family:
        def begin_pass(self, pass_number):
            calls.append(("begin_pass", pass_number))

        def detect(self, mba):
            calls.append(("detect", mba))
            return detection

        def build_snapshot(self, mba, detection_arg):
            calls.append(("build_snapshot", mba, detection_arg))
            return snapshot

    policy = FamilyRuntimePolicy(
        planner="planner",
        executor_policy=ExecutorPolicy(safeguard_profile="configured"),
        build_planner_inputs=lambda ctx, analysis: (
            calls.append(("inputs", ctx, analysis)) or None
        ),
        select_strategies=lambda ctx, analysis: (
            calls.append(("strategies", ctx, analysis)) or ["strategy"]
        ),
        plan_pipeline=lambda snap, strategies, *, planner, inputs=None: (
            calls.append(("plan", snap, strategies, planner, inputs))
            or PlannedPipeline([fragment], provenance)
        ),
        execute_pipeline=lambda snap, planned, *, executor_factory, flow_context=None: (
            calls.append(("execute", snap, planned, executor_factory, flow_context))
            or ExecutedPipeline(planned.pipeline, [], provenance, 2)
        ),
        executor_factory_builder=lambda executor_policy: (
            calls.append(("factory", executor_policy)) or "factory"
        ),
    )

    result = run_configured_family_pass(_Family(), context, policy)

    assert result.pipeline == [fragment]
    assert result.total_changes == 2
    assert ("factory", policy.executor_policy) in calls
    assert any(call[0] == "execute" for call in calls)


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
