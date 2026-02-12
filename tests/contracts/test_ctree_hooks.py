"""System tests for ctree optimizer manager and rule registration.

These tests import d810.hexrays and d810.optimizers, which are forbidden
in tests/unit by the import-linter contract.  They live here in tests/system.
"""
from __future__ import annotations

import pytest

from d810.core.stats import OptimizationStatistics
from d810.hexrays.ctree_hooks import (
    CtreeOptimizerManager,
    CtreeOptimizationRule,
)


# -------------------------------------------------------------------------
# CtreeOptimizerManager tests (without IDA)
# -------------------------------------------------------------------------
class TestCtreeOptimizerManager:
    def test_manager_creation(self):
        stats = OptimizationStatistics()
        mgr = CtreeOptimizerManager(stats)
        assert mgr.ctree_rules == []
        assert mgr.stats is stats

    def test_on_maturity_skips_non_final(self):
        stats = OptimizationStatistics()
        mgr = CtreeOptimizerManager(stats)
        # When ida_hexrays is None, CMAT_FINAL comparison is skipped
        # and all rules are evaluated. With no rules, result is 0.
        assert mgr.on_maturity(None, 3) == 0


# -------------------------------------------------------------------------
# CtreeOptimizationRule registration tests
# -------------------------------------------------------------------------
class TestCtreeOptimizationRuleRegistration:
    def test_noop_counter_is_registered(self):
        """NoopCtreeCounter should auto-register when imported."""
        # Force import to trigger registration
        from d810.optimizers.ctree.noop_counter import NoopCtreeCounter  # noqa: F401

        # Registry uses normalize_key(keyof(cls)) which is cls.__name__.lower()
        key = CtreeOptimizationRule.normalize_key(
            CtreeOptimizationRule.keyof(NoopCtreeCounter)
        )
        assert key in CtreeOptimizationRule.registry
        assert CtreeOptimizationRule.registry[key] is NoopCtreeCounter

    def test_noop_counter_returns_zero(self):
        from d810.optimizers.ctree.noop_counter import NoopCtreeCounter

        rule = NoopCtreeCounter()
        assert rule.name == "noop_ctree_counter"
        # With None cfunc, should still return 0
        assert rule.optimize_ctree(None) == 0


# -------------------------------------------------------------------------
# CtreeOptimizerManager rule execution tests (MEDIUM issue)
# -------------------------------------------------------------------------
class TestCtreeOptimizerManagerRuleExecution:
    def test_rules_fire_and_stats_recorded(self):
        """Rules should fire and statistics should be recorded."""
        class FakeRule(CtreeOptimizationRule):
            NAME = "fake_rule"
            def optimize_ctree(self, cfunc):
                return 3  # 3 patches

        stats = OptimizationStatistics()
        mgr = CtreeOptimizerManager(stats)
        rule = FakeRule()
        mgr.add_rule(rule)

        # Without IDA, on_maturity skips CMAT_FINAL check, evaluates all rules
        total = mgr.on_maturity(None, 8)
        assert total == 3
        # Stats should have recorded the patches
        assert stats.get_cfg_rule_patch_counts("fake_rule") == [3]

    def test_exception_handling_in_rules(self):
        """Exceptions in rules should be caught and not propagate."""
        class FailingRule(CtreeOptimizationRule):
            NAME = "failing_rule"
            def optimize_ctree(self, cfunc):
                raise RuntimeError("boom")

        stats = OptimizationStatistics()
        mgr = CtreeOptimizerManager(stats)
        mgr.add_rule(FailingRule())

        # Should not raise
        total = mgr.on_maturity(None, 8)
        assert total == 0

    def test_multiple_rules_accumulate(self):
        """Multiple rules should accumulate their patch counts."""
        class Rule1(CtreeOptimizationRule):
            NAME = "rule_one"
            def optimize_ctree(self, cfunc):
                return 2

        class Rule2(CtreeOptimizationRule):
            NAME = "rule_two"
            def optimize_ctree(self, cfunc):
                return 5

        stats = OptimizationStatistics()
        mgr = CtreeOptimizerManager(stats)
        mgr.add_rule(Rule1())
        mgr.add_rule(Rule2())

        total = mgr.on_maturity(None, 8)
        assert total == 7
