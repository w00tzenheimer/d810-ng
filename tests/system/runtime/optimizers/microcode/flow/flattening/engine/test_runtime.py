"""Runtime tests for shared family pipeline helpers."""

from __future__ import annotations

from types import SimpleNamespace

from d810.optimizers.microcode.flow.flattening import engine
from d810.optimizers.microcode.flow.flattening.engine import (
    executor as executor_module,
)
from d810.analyses.control_flow.native_preanalysis_session import (
    CommittedSemanticFragmentOwnership,
    SemanticFragmentBlockOwner,
)
from d810.analyses.control_flow.provenance import (
    DecisionPhase,
    DecisionReasonCode,
    DecisionRecord,
    GateAccounting,
    GateDecision,
    GateVerdict,
    PipelineProvenance,
)
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.ir.block_identity import StableBlockIdentity
from d810.ir.flowgraph import (
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
)
from d810.ir.maturity import MaturityEnvelope
from d810.optimizers.microcode.flow.flattening.engine.executor import (
    TransactionalExecutor,
    _committed_semantic_ownership_gate,
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
from d810.transforms.cfg_transaction import (
    CfgGenerationPoisoned,
    CfgTransactionFailure,
    CfgTransactionPhase,
    NativeBlockRef,
    PlanBlockRef,
    TransactionAttemptId,
)
from d810.transforms.plan import PatchBlockSpec, PatchConvertToGoto, PatchPlan
from d810.transforms.graph_modification import RedirectGoto
from d810.transforms.plan_fragment import (
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
    StageResult,
)
from tests.native_preanalysis import make_native_key


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


def _semantic_ownership_gate_plan(
    *identity_eas: int,
    plan_id: str,
) -> PatchPlan:
    native_key = make_native_key()
    refs = tuple(
        NativeBlockRef(
            StableBlockIdentity.from_instruction_eas(
                (ea,),
                native_key=native_key,
            )
        )
        for ea in identity_eas
    )
    return PatchPlan(
        plan_id=plan_id,
        source_maturity=MaturityEnvelope(
            ir=None,
            provider="hexrays",
            provider_id=0,
        ),
        source_generation=1,
        steps=(
            PatchConvertToGoto(
                block_serial=refs[0],
                goto_target=refs[1],
            ),
        ),
        source_coordinates=tuple(
            (ref, coordinate) for coordinate, ref in enumerate(refs)
        ),
    )


def _origin_graph() -> FlowGraph:
    return FlowGraph(
        blocks={
            4: BlockSnapshot(
                serial=4,
                block_type=2,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x401000,
                insn_snapshots=(),
                tail_opcode=0,
                kind=BlockKind.ZERO_WAY,
                tail_kind=InsnKind.NOP,
            ),
            7: BlockSnapshot(
                serial=7,
                block_type=2,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x402000,
                insn_snapshots=(),
                tail_opcode=0,
                kind=BlockKind.ZERO_WAY,
                tail_kind=InsnKind.NOP,
            ),
        },
        entry_serial=4,
        func_ea=0x401000,
    )


def _effectful_fake_jump_graph(*, effectful: bool = True) -> FlowGraph:
    """Small graph whose block 2 models the observed local CALL site."""
    effect_kind = InsnKind.CALL if effectful else InsnKind.MOV
    effect_insn = InsnSnapshot(
        opcode=0,
        ea=0x7FF85662A96E,
        operands=(),
        kind=effect_kind,
    )
    return FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=1,
                succs=(1,),
                preds=(),
                flags=0,
                start_ea=0x7FF856629E30,
                insn_snapshots=(),
                kind=BlockKind.ONE_WAY,
                tail_kind=InsnKind.GOTO,
            ),
            1: BlockSnapshot(
                serial=1,
                block_type=1,
                succs=(2,),
                preds=(0,),
                flags=0,
                start_ea=0x7FF85662A950,
                insn_snapshots=(),
                kind=BlockKind.ONE_WAY,
                tail_kind=InsnKind.GOTO,
            ),
            2: BlockSnapshot(
                serial=2,
                block_type=1,
                succs=(3,),
                preds=(1,),
                flags=0,
                start_ea=0x7FF85662A96E,
                insn_snapshots=(effect_insn,),
                kind=BlockKind.ONE_WAY,
                tail_kind=effect_kind,
            ),
            3: BlockSnapshot(
                serial=3,
                block_type=0,
                succs=(),
                preds=(2,),
                flags=0,
                start_ea=0x7FF85662AA10,
                insn_snapshots=(),
                kind=BlockKind.STOP,
                tail_kind=InsnKind.RET,
            ),
        },
        entry_serial=0,
        func_ea=0x7FF856629E30,
    )


def _fake_jump_fragment(modification: RedirectGoto) -> PlanFragment:
    return PlanFragment(
        strategy_name="fake_jump",
        family="cleanup",
        ownership=OwnershipScope(
            blocks=frozenset({modification.from_serial}),
            edges=frozenset(
                {(modification.from_serial, modification.old_target)}
            ),
            transitions=frozenset(),
        ),
        prerequisites=[],
        expected_benefit=BenefitMetrics(
            handlers_resolved=1,
            transitions_resolved=1,
            blocks_freed=1,
            conflict_density=0.0,
        ),
        risk_score=0.0,
        metadata={"safeguard_min_required": 1},
        modifications=[modification],
    )


def _run_fake_jump_preflight(
    monkeypatch,
    cfg: FlowGraph,
    modification: RedirectGoto,
):
    executor = object.__new__(TransactionalExecutor)
    compile_calls: list[object] = []
    monkeypatch.setattr(
        executor_module,
        "compile_patch_plan",
        lambda *args, **kwargs: (
            compile_calls.append((args, kwargs))
            or PatchPlan(plan_id="control-plan")
        ),
    )
    result = executor._run_preflight(
        _fake_jump_fragment(modification),
        cfg,
        [modification],
        executor_module.ExecutionPolicy.STRICT,
        snapshot_id="snapshot",
        source_maturity=MaturityEnvelope(ir=None, provider="hexrays", provider_id=0),
        source_generation=1,
        block_refs_by_serial={},
    )
    return result, compile_calls


def test_fake_jump_preflight_rejects_lost_effectful_call_before_backend(
    monkeypatch,
) -> None:
    """Keep the observed local CALL reachable before any live mutation."""
    pre_cfg = _effectful_fake_jump_graph()
    fragment = _fake_jump_fragment(
        RedirectGoto(from_serial=0, old_target=1, new_target=3)
    )
    compile_calls: list[object] = []
    backend_counts = {"construct": 0, "apply": 0}

    class _Translator:
        contract = None
        last_lowering_phase = None
        last_lowering_subphase = None

        def lift(self, _mba):
            return pre_cfg

    class _MBA:
        qty = 0
        entry_ea = pre_cfg.func_ea

    gateway = SimpleNamespace(
        identity_index=SimpleNamespace(
            maturity=0,
            snapshot_id="snapshot",
            generation=1,
            plan_refs_by_serial=lambda: {},
        ),
        lifecycle_authority=None,
        begin_count=0,
        poison_requests=[],
    )

    class _Backend:
        def __init__(self, **_kwargs):
            backend_counts["construct"] += 1
            self.last_patch_execution = SimpleNamespace(
                applied_count=1,
                creation_receipts=(),
            )
            self.last_patch_failure = None

        def apply(self, _plan, _mba):
            backend_counts["apply"] += 1
            return pre_cfg

    monkeypatch.setattr(
        executor_module,
        "compile_patch_plan",
        lambda *args, **kwargs: (
            compile_calls.append((args, kwargs))
            or PatchPlan(plan_id="must-not-reach-backend")
        ),
    )
    monkeypatch.setattr(executor_module, "HexRaysMutationBackend", _Backend)
    monkeypatch.setattr(
        executor_module,
        "filter_return_carrier_fact_redirects",
        lambda modifications, **_kwargs: (modifications, ()),
    )
    monkeypatch.setattr(
        executor_module,
        "filter_terminal_byte_emit_fact_redirects",
        lambda modifications, **_kwargs: (modifications, ()),
    )

    executor = TransactionalExecutor(_MBA(), translator=_Translator())
    executor.set_mutation_gateway_factory(lambda: gateway)
    monkeypatch.setattr(
        executor,
        "_filter_backend_unsupported_modifications",
        lambda modifications: (modifications, 0),
    )

    result = executor.execute_stage(fragment, total_handlers=1)

    assert result.success is False
    assert result.failure_phase == "preflight"
    assert result.metadata["effectful_reachability"].lost_block_serials == frozenset(
        {2}
    )
    assert result.metadata["lost_effectful_ea_anchors"] == (0x7FF85662A96E,)
    assert compile_calls == []
    assert backend_counts == {"construct": 0, "apply": 0}
    assert gateway.begin_count == 0
    assert gateway.poison_requests == []


def test_fake_jump_effectful_preflight_allows_call_preserving_redirect(
    monkeypatch,
) -> None:
    cfg = _effectful_fake_jump_graph()
    result_tuple, compile_calls = _run_fake_jump_preflight(
        monkeypatch,
        cfg,
        RedirectGoto(from_serial=0, old_target=1, new_target=2),
    )

    _modifications, patch_plan, result, _cycle_removed = result_tuple
    assert result is None
    assert patch_plan is not None
    assert compile_calls


def test_fake_jump_effectful_preflight_allows_dead_control_only_block(
    monkeypatch,
) -> None:
    cfg = _effectful_fake_jump_graph(effectful=False)
    result_tuple, compile_calls = _run_fake_jump_preflight(
        monkeypatch,
        cfg,
        RedirectGoto(from_serial=0, old_target=1, new_target=3),
    )

    _modifications, patch_plan, result, _cycle_removed = result_tuple
    assert result is None
    assert patch_plan is not None
    assert compile_calls


def test_new_block_origin_logging_resolves_native_template_reference() -> None:
    native_key = make_native_key()
    template_ref = NativeBlockRef(
        StableBlockIdentity.from_instruction_eas(
            (0x401000,),
            native_key=native_key,
        )
    )
    created_ref = PlanBlockRef("origin-log-plan", "created:0")
    plan = PatchPlan(
        plan_id="origin-log-plan",
        new_blocks=(
            PatchBlockSpec(
                block_id=created_ref,
                kind="duplicate_block",
                template_block=template_ref,
            ),
        ),
        source_coordinates=((template_ref, 4),),
    )

    executor = object.__new__(TransactionalExecutor)
    executor._log_new_block_origins(
        plan,
        _origin_graph(),
        _origin_graph(),
        realized_serials={created_ref: 7},
    )


def test_generation_poison_quarantines_stage_and_aborts_pipeline(monkeypatch) -> None:
    """A poisoned live MBA must not receive the next planned fragment."""
    fragment = _fragment("fake_jump")
    follow_up = _fragment("follow_up")
    fragment.metadata["safeguard_min_required"] = 1
    follow_up.metadata["safeguard_min_required"] = 1
    pre_cfg = FlowGraph(blocks={}, entry_serial=0, func_ea=0x401000)
    poison = CfgGenerationPoisoned(
        CfgTransactionFailure(
            attempt_id=TransactionAttemptId(
                plan_id="poisoned-plan",
                session_id="test-session",
                generation=1,
                attempt_id="test-attempt",
            ),
            phase=CfgTransactionPhase.POISONED_RESTART_REQUIRED,
            reason="observed reachability rejected",
            live_mutation_started=True,
            failure_phase="post_observation_contract",
        )
    )

    class _Translator:
        last_lowering_phase = None
        last_lowering_subphase = None
        contract = None

        @staticmethod
        def lift(_mba):
            return pre_cfg

    class _PoisonedBackend:
        def __init__(self, **_kwargs):
            self.last_patch_execution = None
            self.last_patch_failure = poison

        def apply(self, _plan, _mba):
            raise poison

    executor = TransactionalExecutor(
        SimpleNamespace(qty=0),
        translator=_Translator(),
    )
    executor.set_mutation_gateway_factory(
        lambda: SimpleNamespace(
            identity_index=SimpleNamespace(
                maturity=0,
                snapshot_id="snapshot",
                generation=1,
                plan_refs_by_serial=lambda: {},
            ),
            lifecycle_authority=None,
        )
    )
    monkeypatch.setattr(
        executor_module,
        "filter_return_carrier_fact_redirects",
        lambda modifications, **_kwargs: (modifications, ()),
    )
    monkeypatch.setattr(
        executor_module,
        "filter_terminal_byte_emit_fact_redirects",
        lambda modifications, **_kwargs: (modifications, ()),
    )
    monkeypatch.setattr(
        executor,
        "_filter_backend_unsupported_modifications",
        lambda modifications: (modifications, 0),
    )
    monkeypatch.setattr(
        executor,
        "_run_preflight",
        lambda _fragment, _cfg, modifications, _policy, **_kwargs: (
            modifications,
            PatchPlan(plan_id="poisoned-plan"),
            None,
            0,
        ),
    )
    monkeypatch.setattr(executor_module, "HexRaysMutationBackend", _PoisonedBackend)

    stage_result = executor.execute_stage(fragment, total_handlers=1)

    assert stage_result.success is False
    assert stage_result.quarantine is True

    executed: list[str] = []
    monkeypatch.setattr(
        executor,
        "execute_stage",
        lambda candidate, _total_handlers: (
            executed.append(candidate.strategy_name) or stage_result
        ),
    )
    results = executor.execute_pipeline([fragment, follow_up], total_handlers=1)

    assert executed == ["fake_jump"]
    assert results == [stage_result]


def test_committed_semantic_ownership_gate_rejects_before_transaction() -> None:
    patch_plan = _semantic_ownership_gate_plan(
        0x401000,
        0x402000,
        plan_id="ordinary-cleanup",
    )
    source_identity = patch_plan.source_coordinates[0][0].identity
    native_key = source_identity.native_key
    publication = CommittedSemanticFragmentOwnership(
        plan_id="canonical-semantic-plan",
        atomic_group_id="canonical-route",
        evidence_generation=1,
        owners=(
            SemanticFragmentBlockOwner(
                operation_id="semantic-route",
                source_block_id="native-body-edge@0x401000",
                stable_identity=source_identity,
            ),
        ),
    )
    identity_index = MbaBlockIdentityIndex.from_bindings(
        generation=1,
        native_key=native_key,
        bindings=((source_identity, 7),),
    )
    gateway = SimpleNamespace(
        identity_index=identity_index,
        lifecycle_authority=SimpleNamespace(
            committed_semantic_ownership=lambda: (publication,)
        ),
    )

    result, accounting = _committed_semantic_ownership_gate(
        strategy_name="ordinary-cleanup",
        patch_plan=patch_plan,
        mutation_gateway=gateway,
        gate_accounting=GateAccounting(),
    )

    assert result is not None
    assert result.success is False
    assert result.failure_phase == "semantic_preflight"
    assert result.metadata["gate_accounting"] is accounting
    assert accounting.decisions[-1].verdict is GateVerdict.FAILED
    assert result.metadata["committed_semantic_ownership_overlap"] == {
        "plan_id": "canonical-semantic-plan",
        "atomic_group_id": "canonical-route",
        "operation_id": "semantic-route",
        "source_block_id": "native-body-edge@0x401000",
        "anchor_ea": 0x401000,
    }
    assert "serial" not in str(result.metadata)
    assert patch_plan.plan_id not in (result.error or "")

    disjoint = _semantic_ownership_gate_plan(
        0x403000,
        0x404000,
        plan_id="disjoint-cleanup",
    )
    accepted, accepted_accounting = _committed_semantic_ownership_gate(
        strategy_name="disjoint-cleanup",
        patch_plan=disjoint,
        mutation_gateway=gateway,
        gate_accounting=GateAccounting(),
    )

    assert accepted is None
    assert accepted_accounting.decisions[-1].verdict is GateVerdict.PASSED


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

        def __init__(self, mba, *, gate, safeguard_profile):
            seen.append((mba, gate, safeguard_profile))

        def execute_pipeline(self, pipeline, total_handlers):
            return []

    from d810.optimizers.microcode.flow.flattening.engine import (
        executor as executor_mod,
    )

    monkeypatch.setattr(executor_mod, "TransactionalExecutor", _Executor)
    gate = object()
    factory = make_transactional_executor_factory(
        ExecutorPolicy(
            gate=gate,
            safeguard_profile="hodur",
        )
    )

    executor = factory("mba")

    assert isinstance(executor, _Executor)
    assert seen == [("mba", gate, "hodur")]


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
            calls.append(("build_inputs", ctx, analysis)) or "planner_inputs"
        ),
        select_strategies=lambda ctx, analysis: (
            calls.append(("select_strategies", ctx, analysis)) or ["strategy"]
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
    mutation_gateway = object()
    attached_gateway_factories: list[object] = []

    class _Executor:
        def __init__(self):
            self.total_changes = 2

        def set_mutation_gateway_factory(self, factory):
            attached_gateway_factories.append(factory)

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
            ),
            new_mba_mutation_gateway=lambda: mutation_gateway,
        ),
    )

    assert executed.total_changes == 2
    assert executed.results[0].strategy_name == "executed"
    assert executed.provenance.rows[0].phase == DecisionPhase.APPLIED
    assert outcomes == [(executed.provenance, "planner")]
    assert len(attached_gateway_factories) == 1
    assert attached_gateway_factories[0]() is mutation_gateway
