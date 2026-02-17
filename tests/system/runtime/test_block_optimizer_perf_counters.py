"""Runtime tests for BlockOptimizerManager rule-iteration perf counters."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from d810.core.stats import OptimizationStatistics
from d810.hexrays.hexrays_hooks import BlockOptimizerManager


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

    def set_flow_context(self, flow_context) -> None:
        pass

    def optimize(self, blk) -> int:
        self.calls += 1
        return self.patches


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


def _make_block(func_ea: int = 0x401000):
    mba = SimpleNamespace(entry_ea=func_ea)
    return SimpleNamespace(mba=mba, serial=0)


def test_scoped_perf_counters_track_calls_candidates_and_lookup_time():
    manager = BlockOptimizerManager(OptimizationStatistics(), Path("."))
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
    manager = BlockOptimizerManager(OptimizationStatistics(), Path("."))
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
    manager = BlockOptimizerManager(OptimizationStatistics(), Path("."))
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
    manager = BlockOptimizerManager(OptimizationStatistics(), Path("."))
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
    manager = BlockOptimizerManager(OptimizationStatistics(), Path("."))
    manager.current_maturity = 1
    low = _DummyRule("legacy_low", patches=1, priority=20)
    high = _DummyRule("legacy_high", patches=1, priority=80)
    manager.add_rule(low)
    manager.add_rule(high)

    assert manager.optimize(_make_block()) == 0
    assert high.calls == 0
    assert low.calls == 0
