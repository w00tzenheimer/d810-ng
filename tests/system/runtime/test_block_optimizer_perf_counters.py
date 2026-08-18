"""Runtime tests for BlockOptimizerManager rule-iteration perf counters."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.core.stats import OptimizationStatistics
from d810.core.execution_scope import ExecutionStageIdentity
from d810.core.execution_journal import (
    DecompilationSessionId,
    ExecutionAttemptStatus,
    ExecutionDomain,
)
from d810.core.execution_journal_store import ExecutionJournalStore
from d810.hexrays.hooks.optblock_adapter import BlockOptimizerManager
from d810.ir.maturity import IRMaturity
from d810.optimizers.microcode.flow.context import FlowMaturityContext
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule
from d810.passes.scheduler import PassScheduler, RunLater


class _DummyRule:
    def __init__(
        self,
        name: str,
        *,
        patches: int = 0,
        priority: int = 100,
        whitelist: list[int] | None = None,
        blacklist: list[int] | None = None,
    ):
        self.name = name
        self.patches = patches
        self.priority = priority
        self.current_maturity = None
        self.use_whitelist = whitelist is not None
        self.whitelisted_function_ea_list = list(whitelist or [])
        self.use_blacklist = blacklist is not None
        self.blacklisted_function_ea_list = list(blacklist or [])
        self.calls = 0
        self.flow_context = None

    def set_flow_context(self, flow_context) -> None:
        self.flow_context = flow_context

    def optimize(self, blk) -> int:
        self.calls += 1
        return self.patches


class _RunLaterRule(_DummyRule):
    def optimize(self, blk) -> int:
        self.calls += 1
        if self.calls == 1 and self.flow_context is not None:
            self.flow_context.run_later(
                IRMaturity.GLOBAL_OPTIMIZED,
                reason="needs GLBOPT2 facts",
            )
        return self.patches


class _CrossPassRunLaterRule(_DummyRule):
    def __init__(self, name: str, target_rule_name: str):
        super().__init__(name)
        self.target_rule_name = target_rule_name

    def optimize(self, blk) -> int:
        self.calls += 1
        if self.calls == 1 and self.flow_context is not None:
            self.flow_context.run_later(
                IRMaturity.GLOBAL_OPTIMIZED,
                reason="needs target rule at GLBOPT2",
                target_id=self.target_rule_name,
            )
        return self.patches


class _FailingRule(_DummyRule):
    def optimize(self, blk) -> int:
        del blk
        self.calls += 1
        raise RuntimeError("flow rule failure")


class _GatewayRule(FlowOptimizationRule):
    def optimize(self, _blk) -> int:
        return 0


class _FakeExecutionScopeService:
    def __init__(
        self,
        rules: tuple[_DummyRule, ...],
        *,
        known_rules: tuple[_DummyRule, ...] | None = None,
    ):
        self.rules = rules
        self.known_rules = known_rules or rules
        self.calls: list[tuple[int, int, str, str]] = []

    def active_stages(
        self,
        *,
        project_name: str,
        idb_key: str,
        func_ea: int,
        pipeline: str,
        maturity: int,
        function_tags=None,
    ) -> tuple[SimpleNamespace, ...]:
        self.calls.append((func_ea, maturity, project_name, idb_key))
        return tuple(SimpleNamespace(implementation=rule) for rule in self.rules)

    def identity_for_implementation(self, implementation, *, pipeline):
        del pipeline
        if all(rule is not implementation for rule in self.known_rules):
            return None
        return ExecutionStageIdentity(implementation.name, implementation.name)

    def identity_for_target(self, target_id, *, pipeline):
        del pipeline
        if all(rule.name != target_id for rule in self.known_rules):
            return None
        return ExecutionStageIdentity(target_id, target_id)

    def scheduled_stages(self, *, identities, func_ea, pipeline):
        del func_ea, pipeline
        requested = frozenset(identities)
        return tuple(
            SimpleNamespace(implementation=rule)
            for rule in self.known_rules
            if ExecutionStageIdentity(rule.name, rule.name) in requested
        )


class _MutationGatewayLifecycle:
    def __init__(self, gateway: object, materializer: object) -> None:
        self.gateway = gateway
        self.materializer = materializer
        self.build_calls: list[tuple[int, object]] = []
        self.gateway_calls: list[tuple[int, int]] = []
        self.materializer_calls: list[tuple[int, object]] = []

    def build_current_mba_identity_index(
        self, *, function_ea: int, mba: object
    ) -> object:
        self.build_calls.append((function_ea, mba))
        return object()

    def new_current_mba_mutation_gateway(
        self,
        *,
        function_ea: int,
        maturity: int,
    ) -> object:
        self.gateway_calls.append((function_ea, maturity))
        return self.gateway

    def new_semantic_native_body_materializer(
        self,
        *,
        function_ea: int,
        mba: object,
    ) -> object:
        self.materializer_calls.append((function_ea, mba))
        return self.materializer


class _RecordingPassPipeline:
    passes: tuple[object, ...] = ()

    def __init__(self) -> None:
        self.calls: list[tuple[object, dict[str, object]]] = []

    def run(self, backend_state: object, **kwargs: object) -> int:
        self.calls.append((backend_state, kwargs))
        return 0


def _make_block(func_ea: int = 0x401000, maturity=None):
    mba = SimpleNamespace(entry_ea=func_ea, qty=1)
    if maturity is not None:
        mba.maturity = maturity
    return SimpleNamespace(mba=mba, serial=0)


def test_flow_context_records_and_drains_run_later_request():
    context = FlowMaturityContext(
        mba=SimpleNamespace(),
        func_ea=0x401000,
        maturity=ida_hexrays.MMAT_GLBOPT1,
    )
    context.set_current_rule_name("late_rule")
    context.run_later(IRMaturity.GLOBAL_OPTIMIZED, reason="needs GLBOPT2 facts")

    assert context.drain_run_later_requests() == (
        (
            "late_rule",
            RunLater(
                IRMaturity.GLOBAL_OPTIMIZED,
                reason="needs GLBOPT2 facts",
            ),
        ),
    )
    assert context.drain_run_later_requests() == ()


def test_block_optimizer_refreshes_live_identity_before_each_gateway() -> None:
    manager = BlockOptimizerManager(
        OptimizationStatistics(), Path("."), ctx_cls=FlowMaturityContext
    )
    manager.current_maturity = ida_hexrays.MMAT_GLBOPT1
    rule = _DummyRule("mutation_port")
    scope_service = _FakeExecutionScopeService((rule,))
    gateway = object()
    materializer = object()
    lifecycle = _MutationGatewayLifecycle(gateway, materializer)
    manager.configure(
        execution_scope_service=scope_service,
        execution_scope_project_name="proj",
        execution_scope_idb_key="idb",
        decompilation_lifecycle=lifecycle,
    )

    block = _make_block(maturity=ida_hexrays.MMAT_GLBOPT1)
    assert manager.optimize(block) == 0

    assert lifecycle.build_calls == [(0x401000, block.mba)]
    assert rule.flow_context.new_mba_mutation_gateway() is gateway
    assert lifecycle.build_calls == [
        (0x401000, block.mba),
        (0x401000, block.mba),
    ]
    assert rule.flow_context.new_mba_mutation_gateway() is gateway
    assert lifecycle.build_calls == [
        (0x401000, block.mba),
        (0x401000, block.mba),
        (0x401000, block.mba),
    ]
    assert lifecycle.gateway_calls == [
        (0x401000, ida_hexrays.MMAT_GLBOPT1),
        (0x401000, ida_hexrays.MMAT_GLBOPT1),
    ]
    assert rule.flow_context.semantic_native_body_materializer() is materializer
    assert lifecycle.materializer_calls == [(0x401000, block.mba)]


def test_block_optimizer_binds_the_lifecycle_execution_attempt_context(
    tmp_path,
) -> None:
    journal = ExecutionJournalStore(tmp_path / "execution.sqlite")
    session_id = DecompilationSessionId.new()
    parent = journal.begin_attempt(
        session_id,
        stage_id="hexrays_preanalysis",
        domain=ExecutionDomain.HOOK,
    )
    manager = BlockOptimizerManager(
        OptimizationStatistics(), Path("."), ctx_cls=FlowMaturityContext
    )
    manager.current_maturity = ida_hexrays.MMAT_GLBOPT1
    rule = _DummyRule("execution_context")
    lifecycle = _MutationGatewayLifecycle(object(), object())
    lifecycle.execution_journal = journal
    lifecycle.current_session = lambda _function_ea: SimpleNamespace(
        session_id=session_id,
        preanalysis_attempt_id=parent.attempt_id,
    )
    manager.configure(
        execution_scope_service=_FakeExecutionScopeService((rule,)),
        execution_scope_project_name="proj",
        execution_scope_idb_key="idb",
        decompilation_lifecycle=lifecycle,
    )

    try:
        assert manager.optimize(_make_block(maturity=ida_hexrays.MMAT_GLBOPT1)) == 0
        assert rule.flow_context.execution_attempt_context() == (
            journal,
            session_id,
            parent.attempt_id,
        )
    finally:
        journal.close()


def test_block_optimizer_threads_its_lifecycle_attempt_into_pass_pipeline(
    tmp_path,
) -> None:
    journal = ExecutionJournalStore(tmp_path / "execution.sqlite")
    session_id = DecompilationSessionId.new()
    parent = journal.begin_attempt(
        session_id,
        stage_id="hexrays_preanalysis",
        domain=ExecutionDomain.HOOK,
    )
    manager = BlockOptimizerManager(
        OptimizationStatistics(), Path("."), ctx_cls=FlowMaturityContext
    )
    manager.current_maturity = ida_hexrays.MMAT_GLBOPT1
    rule = _DummyRule("pipeline_context")
    lifecycle = _MutationGatewayLifecycle(object(), object())
    lifecycle.execution_journal = journal
    lifecycle.current_session = lambda _function_ea: SimpleNamespace(
        session_id=session_id,
        preanalysis_attempt_id=parent.attempt_id,
    )
    pipeline = _RecordingPassPipeline()
    manager.configure(
        execution_scope_service=_FakeExecutionScopeService((rule,)),
        execution_scope_project_name="proj",
        execution_scope_idb_key="idb",
        decompilation_lifecycle=lifecycle,
        pass_pipeline=pipeline,
    )
    block = _make_block(maturity=ida_hexrays.MMAT_GLBOPT1)

    try:
        assert manager.optimize(block) == 0
        manager._run_pass_pipeline_once(block.mba, phase_label="test")
        assert len(pipeline.calls) == 1
        _, captured = pipeline.calls[0]
        assert captured["journal"] is journal
        assert captured["session_id"] == session_id
        assert captured["parent_attempt_id"] == parent.attempt_id
        assert captured["maturity"] == "MMAT_GLBOPT1"
    finally:
        journal.close()


def test_pass_pipeline_uses_coordinator_gateway_after_maturity_transition(
    tmp_path,
) -> None:
    """The GLBOPT2 pipeline must not depend on the prior maturity context.

    ``log_info_on_input`` deliberately invalidates ``_flow_context`` when IDA
    advances the MBA to a new maturity.  The pipeline runs at that boundary,
    before any GLBOPT2 flow rule has had a chance to recreate the context, so
    its mutation gateway must come from the lifecycle coordinator directly.
    """
    manager = BlockOptimizerManager(
        OptimizationStatistics(), Path("."), ctx_cls=FlowMaturityContext
    )
    manager.current_maturity = ida_hexrays.MMAT_GLBOPT1
    rule = _DummyRule("pipeline_boundary_context")
    lifecycle = _MutationGatewayLifecycle(object(), object())
    lifecycle.analyze_current_function = lambda **_kwargs: None
    journal = ExecutionJournalStore(tmp_path / "execution.sqlite")
    session_id = DecompilationSessionId.new()
    parent = journal.begin_attempt(
        session_id,
        stage_id="hexrays_preanalysis",
        domain=ExecutionDomain.HOOK,
    )
    lifecycle.execution_journal = journal
    lifecycle.current_session = lambda _function_ea: SimpleNamespace(
        session_id=session_id,
        preanalysis_attempt_id=parent.attempt_id,
    )
    pipeline = _RecordingPassPipeline()
    manager.configure(
        execution_scope_service=_FakeExecutionScopeService((rule,)),
        execution_scope_project_name="proj",
        execution_scope_idb_key="idb",
        decompilation_lifecycle=lifecycle,
        pass_pipeline=pipeline,
    )

    try:
        # Create the GLBOPT1 context, then cross the maturity boundary.  The
        # boundary callback invalidates that context before the GLBOPT2
        # pipeline fires.
        first_block = _make_block(maturity=ida_hexrays.MMAT_GLBOPT1)
        assert manager.optimize(first_block) == 0
        assert manager._flow_context is not None

        manager.log_info_on_input(_make_block(maturity=ida_hexrays.MMAT_GLBOPT2))

        assert manager._flow_context is None
        assert len(pipeline.calls) == 1
        _, pipeline_kwargs = pipeline.calls[0]
        assert pipeline_kwargs["mutation_gateway"] is lifecycle.gateway
        assert pipeline_kwargs["journal"] is journal
        assert pipeline_kwargs["session_id"] == session_id
        assert pipeline_kwargs["parent_attempt_id"] == parent.attempt_id
        assert lifecycle.gateway_calls[-1] == (
            0x401000,
            ida_hexrays.MMAT_GLBOPT2,
        )
    finally:
        journal.close()


def test_pass_pipeline_abstains_when_coordinator_gateway_is_unavailable() -> None:
    """A missing coordinator context must fail closed without running passes."""

    class _UnavailableLifecycle(_MutationGatewayLifecycle):
        def build_current_mba_identity_index(self, *, function_ea: int, mba):
            self.build_calls.append((function_ea, mba))
            return None

    class _UnexpectedFlowContext:
        def __init__(self) -> None:
            self.calls = 0

        def new_mba_mutation_gateway(self):
            self.calls += 1
            raise AssertionError("pipeline must not use a stale flow context")

    manager = BlockOptimizerManager(
        OptimizationStatistics(), Path("."), ctx_cls=FlowMaturityContext
    )
    manager.current_maturity = ida_hexrays.MMAT_GLBOPT2
    lifecycle = _UnavailableLifecycle(object(), object())
    pipeline = _RecordingPassPipeline()
    stale_context = _UnexpectedFlowContext()
    manager._flow_context = stale_context
    manager.configure(
        decompilation_lifecycle=lifecycle,
        pass_pipeline=pipeline,
    )

    manager._run_pass_pipeline_once(
        _make_block(maturity=ida_hexrays.MMAT_GLBOPT2).mba,
        phase_label="MMAT_GLBOPT2",
    )

    assert pipeline.calls == []
    assert stale_context.calls == 0
    assert lifecycle.gateway_calls == []


def test_block_optimizer_records_rule_and_mba_mutation_attempts(tmp_path) -> None:
    journal = ExecutionJournalStore(
        tmp_path / "execution.sqlite", callback_detail="full"
    )
    session_id = DecompilationSessionId.new()
    parent = journal.begin_attempt(
        session_id,
        stage_id="hexrays_preanalysis",
        domain=ExecutionDomain.HOOK,
    )
    manager = BlockOptimizerManager(
        OptimizationStatistics(), Path("."), ctx_cls=FlowMaturityContext
    )
    manager.current_maturity = ida_hexrays.MMAT_GLBOPT1
    rule = _DummyRule("solver_backed_rule", patches=2)
    lifecycle = _MutationGatewayLifecycle(object(), object())
    lifecycle.execution_journal = journal
    lifecycle.current_session = lambda _function_ea: SimpleNamespace(
        session_id=session_id,
        preanalysis_attempt_id=parent.attempt_id,
    )
    manager.configure(
        execution_scope_service=_FakeExecutionScopeService((rule,)),
        execution_scope_project_name="proj",
        execution_scope_idb_key="idb",
        decompilation_lifecycle=lifecycle,
    )

    try:
        assert manager.optimize(_make_block(maturity=ida_hexrays.MMAT_GLBOPT1)) == 2
        rule_attempt = journal.only_attempt(
            session_id,
            stage_id="flow_rule:solver_backed_rule:maturity=MMAT_GLBOPT1:unknown",
        )
        mutation_attempt = journal.only_attempt(
            session_id,
            stage_id=(
                "mba_rule_mutation:solver_backed_rule:maturity=MMAT_GLBOPT1:unknown"
            ),
        )
        assert rule_attempt.status is ExecutionAttemptStatus.COMPLETED
        assert rule_attempt.parent_attempt_id == parent.attempt_id
        assert rule_attempt.details == {"patch_count": 2, "maturity": "MMAT_GLBOPT1"}
        assert mutation_attempt.status is ExecutionAttemptStatus.COMPLETED
        assert mutation_attempt.parent_attempt_id == rule_attempt.attempt_id
        assert mutation_attempt.effect_refs[0].kind == "mba_rule_edit"
    finally:
        journal.close()


def test_block_optimizer_records_noop_and_failure_attempts(tmp_path) -> None:
    journal = ExecutionJournalStore(
        tmp_path / "execution.sqlite", callback_detail="full"
    )
    session_id = DecompilationSessionId.new()
    parent = journal.begin_attempt(
        session_id,
        stage_id="hexrays_preanalysis",
        domain=ExecutionDomain.HOOK,
    )
    manager = BlockOptimizerManager(
        OptimizationStatistics(), Path("."), ctx_cls=FlowMaturityContext
    )
    manager.current_maturity = ida_hexrays.MMAT_GLBOPT1
    noop = _DummyRule("solver_backed_noop")
    failing = _FailingRule("solver_backed_failure")
    lifecycle = _MutationGatewayLifecycle(object(), object())
    lifecycle.execution_journal = journal
    lifecycle.current_session = lambda _function_ea: SimpleNamespace(
        session_id=session_id,
        preanalysis_attempt_id=parent.attempt_id,
    )
    manager.configure(
        execution_scope_service=_FakeExecutionScopeService((noop, failing)),
        execution_scope_project_name="proj",
        execution_scope_idb_key="idb",
        decompilation_lifecycle=lifecycle,
    )

    try:
        with pytest.raises(RuntimeError, match="flow rule failure"):
            manager.optimize(_make_block(maturity=ida_hexrays.MMAT_GLBOPT1))
        noop_attempt = journal.only_attempt(
            session_id,
            stage_id="flow_rule:solver_backed_noop:maturity=MMAT_GLBOPT1:unknown",
        )
        assert noop_attempt.status is ExecutionAttemptStatus.ABSTAINED
        assert noop_attempt.reason_code == "no_modifications"
        failed_attempt = journal.only_attempt(
            session_id,
            stage_id="flow_rule:solver_backed_failure:maturity=MMAT_GLBOPT1:unknown",
        )
        failed_mutation = journal.only_attempt(
            session_id,
            stage_id=(
                "mba_rule_mutation:solver_backed_failure:maturity=MMAT_GLBOPT1:unknown"
            ),
        )
        assert failed_attempt.status is ExecutionAttemptStatus.FAILED
        assert failed_mutation.status is ExecutionAttemptStatus.FAILED
        assert failed_attempt.reason_code == "RuntimeError: flow rule failure"
    finally:
        journal.close()


def test_block_optimizer_summarizes_noop_rule_by_default(tmp_path) -> None:
    journal = ExecutionJournalStore(tmp_path / "execution.sqlite")
    session_id = DecompilationSessionId.new()
    parent = journal.begin_attempt(
        session_id,
        stage_id="hexrays_preanalysis",
        domain=ExecutionDomain.HOOK,
    )
    manager = BlockOptimizerManager(
        OptimizationStatistics(), Path("."), ctx_cls=FlowMaturityContext
    )
    manager.current_maturity = ida_hexrays.MMAT_GLBOPT1
    noop = _DummyRule("summarized_noop")
    failing = _FailingRule("summarized_failure")
    lifecycle = _MutationGatewayLifecycle(object(), object())
    lifecycle.execution_journal = journal
    lifecycle.current_session = lambda _function_ea: SimpleNamespace(
        session_id=session_id,
        preanalysis_attempt_id=parent.attempt_id,
    )
    manager.configure(
        execution_scope_service=_FakeExecutionScopeService((noop, failing)),
        execution_scope_project_name="proj",
        execution_scope_idb_key="idb",
        decompilation_lifecycle=lifecycle,
    )

    try:
        with pytest.raises(RuntimeError, match="flow rule failure"):
            manager.optimize(_make_block(maturity=ida_hexrays.MMAT_GLBOPT1))
        attempts = journal.attempts_for_session(session_id)
        assert [attempt.stage_id for attempt in attempts] == [
            "hexrays_preanalysis",
            "flow_rule:summarized_failure:maturity=MMAT_GLBOPT1:unknown",
            "mba_rule_mutation:summarized_failure:maturity=MMAT_GLBOPT1:unknown",
        ]
        assert attempts[1].status is ExecutionAttemptStatus.FAILED
        assert attempts[2].status is ExecutionAttemptStatus.FAILED
        summary = journal.flush_callback_summaries(
            session_id, parent_attempt_id=parent.attempt_id
        )
        assert summary is not None
        assert summary.details["total_abstentions"] == 1
        assert summary.details["groups"][0]["callback_kind"] == "optblock"
    finally:
        journal.close()


def test_disabled_impossible_return_cleanup_does_not_build_gateway(
    monkeypatch,
) -> None:
    monkeypatch.delenv("D810_REWRITE_IMPOSSIBLE_RETURN_ARTIFACTS", raising=False)
    manager = BlockOptimizerManager(
        OptimizationStatistics(), Path("."), ctx_cls=FlowMaturityContext
    )
    manager.current_maturity = ida_hexrays.MMAT_GLBOPT2
    gateway_calls = []
    manager._flow_context = SimpleNamespace(
        new_mba_mutation_gateway=lambda: gateway_calls.append(True)
    )

    assert (
        manager._maybe_rewrite_impossible_return_artifact_edges(
            _make_block(maturity=ida_hexrays.MMAT_GLBOPT2)
        )
        == 0
    )
    assert gateway_calls == []


def test_terminal_zero_cleanup_without_evidence_does_not_build_gateway(
    monkeypatch,
) -> None:
    monkeypatch.delenv(
        "D810_REWRITE_TERMINAL_ZERO_GUARD_LITERAL_RETURNS",
        raising=False,
    )
    monkeypatch.setattr(
        "d810.hexrays.mutation.byte_emit_tail_isolation_runtime."
        "terminal_zero_guard_literal_return_values",
        lambda _mba: (),
    )
    manager = BlockOptimizerManager(
        OptimizationStatistics(), Path("."), ctx_cls=FlowMaturityContext
    )
    manager.current_maturity = ida_hexrays.MMAT_GLBOPT2
    gateway_calls = []
    manager._flow_context = SimpleNamespace(
        new_mba_mutation_gateway=lambda: gateway_calls.append(True)
    )

    assert (
        manager._maybe_rewrite_terminal_zero_guard_literal_edges(
            _make_block(maturity=ida_hexrays.MMAT_GLBOPT2)
        )
        == 0
    )
    assert gateway_calls == []


def test_flow_rule_constructs_a_modifier_from_its_injected_gateway_port() -> None:
    gateway = object()
    context = FlowMaturityContext(
        mba=SimpleNamespace(entry_ea=0x401000, qty=1),
        func_ea=0x401000,
        maturity=ida_hexrays.MMAT_GLBOPT1,
    )
    context.set_mutation_gateway_factory(lambda: gateway)
    rule = _GatewayRule()
    rule.set_flow_context(context)

    modifier = rule.new_deferred_modifier(context.mba)

    assert modifier.mutation_gateway is gateway


def test_flow_context_materializer_factory_uses_the_refreshed_mba() -> None:
    first_mba = SimpleNamespace(entry_ea=0x401000)
    second_mba = SimpleNamespace(entry_ea=0x401000)
    context = FlowMaturityContext(
        mba=first_mba,
        func_ea=0x401000,
        maturity=ida_hexrays.MMAT_GLBOPT1,
    )
    context.set_semantic_native_body_materializer_factory(
        lambda: context.mba,
    )

    assert context.semantic_native_body_materializer() is first_mba
    context.refresh_mba(second_mba)
    assert context.semantic_native_body_materializer() is second_mba


def test_flow_rule_fails_closed_without_an_injected_gateway_port() -> None:
    rule = _GatewayRule()
    mba = SimpleNamespace(entry_ea=0x401000, qty=1)

    with pytest.raises(
        RuntimeError,
        match="flow rule requires a coordinator-owned mutation gateway",
    ):
        rule.new_deferred_modifier(mba)


def test_block_optimizer_runs_scheduled_rule_at_later_maturity():
    manager = BlockOptimizerManager(
        OptimizationStatistics(), Path("."), ctx_cls=FlowMaturityContext
    )
    scheduler = PassScheduler()
    rule = _RunLaterRule("late_rule")
    scope_service = _FakeExecutionScopeService((rule,))
    manager.add_rule(rule)
    manager.configure(
        execution_scope_service=scope_service,
        execution_scope_project_name="proj",
        execution_scope_idb_key="idb",
        pass_scheduler=scheduler,
    )

    manager.current_maturity = ida_hexrays.MMAT_GLBOPT1
    assert manager.optimize(_make_block()) == 0
    assert rule.calls == 1

    scope_service.rules = ()
    manager.log_info_on_input(
        _make_block(maturity=ida_hexrays.MMAT_GLBOPT2),
    )
    assert manager.optimize(_make_block()) == 0
    assert rule.calls == 2


def test_block_optimizer_abstains_during_scoped_suppression():
    from d810.hexrays.hooks.optimization_suppression import (
        suppress_d810_optimization,
    )

    manager = BlockOptimizerManager(
        OptimizationStatistics(), Path("."), ctx_cls=FlowMaturityContext
    )
    rule = _DummyRule("suppressed_rule")
    scope_service = _FakeExecutionScopeService((rule,))
    manager.add_rule(rule)
    manager.configure(
        execution_scope_service=scope_service,
        execution_scope_project_name="proj",
        execution_scope_idb_key="idb",
    )
    manager.current_maturity = ida_hexrays.MMAT_GLBOPT1

    with suppress_d810_optimization():
        assert manager.optimize(_make_block()) == 0
    assert rule.calls == 0
    assert manager.optimize(_make_block()) == 0
    assert rule.calls == 1


def test_block_optimizer_runs_cross_pass_scheduled_rule_at_later_maturity():
    manager = BlockOptimizerManager(
        OptimizationStatistics(), Path("."), ctx_cls=FlowMaturityContext
    )
    scheduler = PassScheduler()
    source_rule = _CrossPassRunLaterRule("source_rule", "target_rule")
    target_rule = _DummyRule("target_rule")
    scope_service = _FakeExecutionScopeService(
        (source_rule,),
        known_rules=(source_rule, target_rule),
    )
    manager.add_rule(source_rule)
    manager.add_rule(target_rule)
    manager.configure(
        execution_scope_service=scope_service,
        execution_scope_project_name="proj",
        execution_scope_idb_key="idb",
        pass_scheduler=scheduler,
    )

    manager.current_maturity = ida_hexrays.MMAT_GLBOPT1
    assert manager.optimize(_make_block()) == 0
    assert source_rule.calls == 1
    assert target_rule.calls == 0

    scope_service.rules = ()
    manager.log_info_on_input(
        _make_block(maturity=ida_hexrays.MMAT_GLBOPT2),
    )
    assert manager.optimize(_make_block()) == 0
    assert source_rule.calls == 1
    assert target_rule.calls == 1


def test_scoped_perf_counters_track_calls_candidates_and_lookup_time():
    manager = BlockOptimizerManager(
        OptimizationStatistics(), Path("."), ctx_cls=FlowMaturityContext
    )
    manager.current_maturity = 1
    scoped_rule = _DummyRule("scoped")
    scope_service = _FakeExecutionScopeService((scoped_rule,))
    manager.configure(
        execution_scope_service=scope_service,
        execution_scope_project_name="proj",
        execution_scope_idb_key="idb",
    )

    assert manager.optimize(_make_block()) == 0

    assert len(scope_service.calls) == 1
    assert manager._perf_counters["scoped_calls"] == 1
    assert manager._perf_counters["scoped_candidates_total"] == 1
    assert manager._perf_counters["legacy_calls"] == 0
    assert manager._perf_counters["legacy_candidates_total"] == 0
    assert manager._perf_counters["scoped_lookup_ns"] >= 0


def test_no_scope_service_fail_closed_ignores_legacy_candidates():
    manager = BlockOptimizerManager(
        OptimizationStatistics(), Path("."), ctx_cls=FlowMaturityContext
    )
    manager.current_maturity = 1
    allowed = _DummyRule("allowed", whitelist=[0x401000])
    denied = _DummyRule("denied", blacklist=[0x401000])
    manager.add_rule(allowed)
    manager.add_rule(denied)

    assert manager.optimize(_make_block()) == 0

    assert manager._perf_counters["legacy_calls"] == 0
    assert manager._perf_counters["legacy_candidates_total"] == 0
    assert manager._perf_counters["scoped_calls"] == 1
    assert manager._perf_counters["scoped_candidates_total"] == 0
    assert allowed.calls == 0
    assert denied.calls == 0


def test_scoped_compare_mode_records_legacy_baseline_and_can_reset():
    manager = BlockOptimizerManager(
        OptimizationStatistics(), Path("."), ctx_cls=FlowMaturityContext
    )
    manager.current_maturity = 1
    legacy_allowed = _DummyRule("legacy_allowed", whitelist=[0x401000])
    legacy_denied = _DummyRule("legacy_denied", blacklist=[0x401000])
    manager.add_rule(legacy_allowed)
    manager.add_rule(legacy_denied)
    scope_service = _FakeExecutionScopeService(
        (_DummyRule("scoped_a"), _DummyRule("scoped_b"))
    )
    manager.configure(
        execution_scope_service=scope_service,
        execution_scope_project_name="proj",
        execution_scope_idb_key="idb",
        execution_scope_perf_compare=True,
    )

    assert manager.optimize(_make_block()) == 0

    assert manager._perf_counters["scoped_calls"] == 1
    assert manager._perf_counters["scoped_candidates_total"] == 2
    assert manager._perf_counters["legacy_calls"] == 0
    assert manager._perf_counters["legacy_candidates_total"] == 1
    manager.report_perf_counters()

    manager.reset_perf_counters()
    assert manager._perf_counters == {
        "scoped_calls": 0,
        "legacy_calls": 0,
        "scoped_candidates_total": 0,
        "legacy_candidates_total": 0,
        "scoped_lookup_ns": 0,
    }


def test_scoped_rules_are_executed_in_priority_order():
    manager = BlockOptimizerManager(
        OptimizationStatistics(), Path("."), ctx_cls=FlowMaturityContext
    )
    manager.current_maturity = 1
    low = _DummyRule("low", patches=1, priority=10)
    high = _DummyRule("high", patches=1, priority=90)
    scope_service = _FakeExecutionScopeService((low, high))
    manager.configure(
        execution_scope_service=scope_service,
        execution_scope_project_name="proj",
        execution_scope_idb_key="idb",
    )

    assert manager.optimize(_make_block()) == 1
    assert high.calls == 1
    assert low.calls == 0


def test_equal_priority_scoped_rules_preserve_public_pipeline_order():
    manager = BlockOptimizerManager(
        OptimizationStatistics(), Path("."), ctx_cls=FlowMaturityContext
    )
    manager.current_maturity = 1
    first = _DummyRule("z_first", patches=1)
    second = _DummyRule("a_second", patches=1)
    scope_service = _FakeExecutionScopeService((first, second))
    manager.configure(
        execution_scope_service=scope_service,
        execution_scope_project_name="proj",
        execution_scope_idb_key="idb",
    )

    assert manager.optimize(_make_block()) == 1
    assert first.calls == 1
    assert second.calls == 0


def test_pending_preopt_reimport_marks_current_flow_generation_stale():
    def resolver_state(*, evidence, normalized, pending=False):
        return SimpleNamespace(
            is_materialized=True,
            pending_preopt_reimport=pending,
            evidence_generation=evidence,
            native_preanalysis=SimpleNamespace(
                normalization_published_postvalidated_generation=normalized
            ),
        )

    stale = SimpleNamespace(
        resolver_session_state=lambda: resolver_state(
            evidence=2,
            normalized=1,
        )
    )
    current = SimpleNamespace(
        resolver_session_state=lambda: resolver_state(
            evidence=2,
            normalized=2,
        )
    )
    pending = SimpleNamespace(
        resolver_session_state=lambda: resolver_state(
            evidence=2,
            normalized=2,
            pending=True,
        )
    )

    assert BlockOptimizerManager._frontend_generation_is_stale(stale)
    assert BlockOptimizerManager._frontend_generation_is_stale(pending)
    assert not BlockOptimizerManager._frontend_generation_is_stale(current)
    assert not BlockOptimizerManager._frontend_generation_is_stale(None)


def test_no_scope_service_does_not_execute_legacy_rules():
    manager = BlockOptimizerManager(
        OptimizationStatistics(), Path("."), ctx_cls=FlowMaturityContext
    )
    manager.current_maturity = 1
    low = _DummyRule("legacy_low", patches=1, priority=20)
    high = _DummyRule("legacy_high", patches=1, priority=80)
    manager.add_rule(low)
    manager.add_rule(high)

    assert manager.optimize(_make_block()) == 0
    assert high.calls == 0
    assert low.calls == 0
