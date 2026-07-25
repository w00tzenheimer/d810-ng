"""Runtime tests for BlockOptimizerManager rule-iteration perf counters."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.core.stats import OptimizationStatistics
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
                pass_id=self.target_rule_name,
            )
        return self.patches


class _GatewayRule(FlowOptimizationRule):
    def optimize(self, _blk) -> int:
        return 0


class _FakeRuleScopeService:
    def __init__(self, rules: tuple[_DummyRule, ...]):
        self.rules = rules
        self.calls: list[tuple[int, int, str, str]] = []

    def get_active_rules(
        self,
        *,
        project_name: str,
        idb_key: str,
        func_ea: int,
        pipeline: str,
        maturity: int,
        function_tags=None,
    ) -> tuple[_DummyRule, ...]:
        self.calls.append((func_ea, maturity, project_name, idb_key))
        return self.rules


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


def test_block_optimizer_injects_the_session_mutation_gateway_port() -> None:
    manager = BlockOptimizerManager(
        OptimizationStatistics(), Path("."), ctx_cls=FlowMaturityContext
    )
    manager.current_maturity = ida_hexrays.MMAT_GLBOPT1
    rule = _DummyRule("mutation_port")
    scope_service = _FakeRuleScopeService((rule,))
    gateway = object()
    materializer = object()
    lifecycle = _MutationGatewayLifecycle(gateway, materializer)
    manager.configure(
        rule_scope_service=scope_service,
        rule_scope_project_name="proj",
        rule_scope_idb_key="idb",
        decompilation_lifecycle=lifecycle,
    )

    block = _make_block(maturity=ida_hexrays.MMAT_GLBOPT1)
    assert manager.optimize(block) == 0

    assert lifecycle.build_calls == [(0x401000, block.mba)]
    assert rule.flow_context.new_mba_mutation_gateway() is gateway
    assert lifecycle.gateway_calls == [(0x401000, ida_hexrays.MMAT_GLBOPT1)]
    assert rule.flow_context.semantic_native_body_materializer() is materializer
    assert lifecycle.materializer_calls == [(0x401000, block.mba)]


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
    scope_service = _FakeRuleScopeService((rule,))
    manager.add_rule(rule)
    manager.configure(
        rule_scope_service=scope_service,
        rule_scope_project_name="proj",
        rule_scope_idb_key="idb",
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
    scope_service = _FakeRuleScopeService((rule,))
    manager.add_rule(rule)
    manager.configure(
        rule_scope_service=scope_service,
        rule_scope_project_name="proj",
        rule_scope_idb_key="idb",
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
    scope_service = _FakeRuleScopeService((source_rule,))
    manager.add_rule(source_rule)
    manager.add_rule(target_rule)
    manager.configure(
        rule_scope_service=scope_service,
        rule_scope_project_name="proj",
        rule_scope_idb_key="idb",
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
    scope_service = _FakeRuleScopeService((scoped_rule,))
    manager.configure(
        rule_scope_service=scope_service,
        rule_scope_project_name="proj",
        rule_scope_idb_key="idb",
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
    scope_service = _FakeRuleScopeService(
        (_DummyRule("scoped_a"), _DummyRule("scoped_b"))
    )
    manager.configure(
        rule_scope_service=scope_service,
        rule_scope_project_name="proj",
        rule_scope_idb_key="idb",
        rule_scope_perf_compare=True,
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
    scope_service = _FakeRuleScopeService((low, high))
    manager.configure(
        rule_scope_service=scope_service,
        rule_scope_project_name="proj",
        rule_scope_idb_key="idb",
    )

    assert manager.optimize(_make_block()) == 1
    assert high.calls == 1
    assert low.calls == 0


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
