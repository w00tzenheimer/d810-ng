"""Tests for OptimizationStatistics with rule object tracking."""

import pytest
from d810.core.stats import (
    OptimizationStatistics,
    OptimizationEvent,
    RuleExecution,
)


class MockRule:
    """Mock rule for testing."""

    def __init__(self, name: str):
        self._name = name

    @property
    def name(self) -> str:
        return self._name


class TestRuleExecution:
    """Tests for RuleExecution dataclass."""

    def test_from_rule_with_instance(self):
        """Test creating RuleExecution from rule instance."""
        rule = MockRule("TestRule")
        execution = RuleExecution.from_rule(rule)

        assert execution.rule is rule
        assert execution.rule_name == "TestRule"
        assert execution.match_count == 1

    def test_from_rule_with_class(self):
        """Test creating RuleExecution from rule class."""
        execution = RuleExecution.from_rule(MockRule)

        assert execution.rule is MockRule
        assert execution.rule_name == "MockRule"
        assert execution.match_count == 1

    def test_from_rule_with_metadata(self):
        """Test creating RuleExecution with metadata."""
        rule = MockRule("TestRule")
        execution = RuleExecution.from_rule(
            rule, optimizer="PatternOptimizer", maturity=5
        )

        assert execution.metadata["optimizer"] == "PatternOptimizer"
        assert execution.metadata["maturity"] == 5


class TestOptimizationStatistics:
    """Tests for OptimizationStatistics class."""

    def test_record_rule_fired(self):
        """Test recording a rule firing with actual rule object."""
        stats = OptimizationStatistics()
        rule = MockRule("Xor_HackersDelight1")

        stats.record_rule_fired(rule, optimizer="PatternOptimizer")

        # Check it was recorded
        assert stats.did_rule_fire(rule)
        assert stats.did_rule_fire("Xor_HackersDelight1")
        assert stats.get_rule_match_count(rule) == 1

    def test_multiple_firings(self):
        """Test that multiple firings are counted correctly."""
        stats = OptimizationStatistics()
        rule = MockRule("TestRule")

        stats.record_rule_fired(rule)
        stats.record_rule_fired(rule)
        stats.record_rule_fired(rule)

        assert stats.get_rule_match_count(rule) == 3
        assert stats.get_rule_match_count("TestRule") == 3

    def test_get_fired_rules(self):
        """Test getting list of fired rules."""
        stats = OptimizationStatistics()
        rule1 = MockRule("Rule1")
        rule2 = MockRule("Rule2")

        stats.record_rule_fired(rule1)
        stats.record_rule_fired(rule2)

        fired = stats.get_fired_rules()
        assert len(fired) == 2
        assert rule1 in fired
        assert rule2 in fired

    def test_get_fired_rule_names(self):
        """Test getting list of fired rule names."""
        stats = OptimizationStatistics()
        stats.record_rule_fired(MockRule("Rule1"))
        stats.record_rule_fired(MockRule("Rule2"))

        names = stats.get_fired_rule_names()
        assert "Rule1" in names
        assert "Rule2" in names

    def test_execution_log_order(self):
        """Test that execution log maintains order."""
        stats = OptimizationStatistics()
        rule1 = MockRule("First")
        rule2 = MockRule("Second")
        rule3 = MockRule("Third")

        stats.record_rule_fired(rule1)
        stats.record_rule_fired(rule2)
        stats.record_rule_fired(rule3)

        log = stats.get_execution_log()
        assert len(log) == 3
        assert log[0].rule_name == "First"
        assert log[1].rule_name == "Second"
        assert log[2].rule_name == "Third"

    def test_assert_rule_fired_success(self):
        """Test assert_rule_fired succeeds when rule fired."""
        stats = OptimizationStatistics()
        rule = MockRule("TestRule")
        stats.record_rule_fired(rule)
        stats.record_rule_fired(rule)

        # Should not raise
        stats.assert_rule_fired(rule)
        stats.assert_rule_fired("TestRule")
        stats.assert_rule_fired(rule, min_count=2)
        stats.assert_rule_fired(rule, min_count=1, max_count=5)

    def test_assert_rule_fired_fails_not_fired(self):
        """Test assert_rule_fired raises when rule didn't fire."""
        stats = OptimizationStatistics()

        with pytest.raises(AssertionError) as exc_info:
            stats.assert_rule_fired("NonExistentRule")

        assert "NonExistentRule" in str(exc_info.value)
        assert "0 time(s)" in str(exc_info.value)

    def test_assert_rule_fired_fails_count_too_low(self):
        """Test assert_rule_fired raises when count is below minimum."""
        stats = OptimizationStatistics()
        rule = MockRule("TestRule")
        stats.record_rule_fired(rule)

        with pytest.raises(AssertionError):
            stats.assert_rule_fired(rule, min_count=5)

    def test_assert_rule_fired_fails_count_too_high(self):
        """Test assert_rule_fired raises when count exceeds maximum."""
        stats = OptimizationStatistics()
        rule = MockRule("TestRule")
        for _ in range(10):
            stats.record_rule_fired(rule)

        with pytest.raises(AssertionError):
            stats.assert_rule_fired(rule, max_count=5)

    def test_assert_no_rule_fired_success(self):
        """Test assert_no_rule_fired succeeds when nothing fired."""
        stats = OptimizationStatistics()
        stats.assert_no_rule_fired()  # Should not raise

    def test_assert_no_rule_fired_fails(self):
        """Test assert_no_rule_fired raises when something fired."""
        stats = OptimizationStatistics()
        stats.record_rule_fired(MockRule("TestRule"))

        with pytest.raises(AssertionError) as exc_info:
            stats.assert_no_rule_fired()

        assert "TestRule" in str(exc_info.value)

    def test_reset(self):
        """Test that reset clears all data."""
        stats = OptimizationStatistics()
        stats.record_rule_fired(MockRule("TestRule"))
        stats.record_optimizer_match("PatternOptimizer")
        stats.record_cfg_rule_patches("CfgRule", 5)

        stats.reset()

        assert not stats.did_rule_fire("TestRule")
        assert stats.get_optimizer_match_count("PatternOptimizer") == 0
        assert stats.get_cfg_rule_patch_counts("CfgRule") == []
        assert len(stats.get_execution_log()) == 0

    def test_summary(self):
        """Test summary dict generation."""
        stats = OptimizationStatistics()
        stats.record_rule_fired(MockRule("Rule1"))
        stats.record_rule_fired(MockRule("Rule2"))
        stats.record_cfg_rule_patches("CfgRule", 10)

        summary = stats.summary()

        assert summary["total_rule_firings"] == 2
        assert "Rule1" in summary["rule_matches"]
        assert "Rule2" in summary["rule_matches"]
        assert "CfgRule" in summary["cfg_patches"]

    def test_case_insensitive_lookup(self):
        """Test that rule lookups are case-insensitive."""
        stats = OptimizationStatistics()
        stats.record_rule_fired(MockRule("TestRule"))

        assert stats.did_rule_fire("testrule")
        assert stats.did_rule_fire("TESTRULE")
        assert stats.did_rule_fire("TestRule")
        assert stats.get_rule_match_count("TESTRULE") == 1


class TestOptimizationEvent:
    """Tests for OptimizationEvent enum."""

    def test_event_values_unique(self):
        """Test that all event values are unique."""
        values = [e.value for e in OptimizationEvent]
        assert len(values) == len(set(values))

    def test_expected_events_exist(self):
        """Test that expected events exist."""
        assert hasattr(OptimizationEvent, "RULE_MATCH")
        assert hasattr(OptimizationEvent, "RULE_APPLIED")
        assert hasattr(OptimizationEvent, "OPTIMIZER_MATCH")
        assert hasattr(OptimizationEvent, "CFG_RULE_PATCHES")


class TestEventEmitterIntegration:
    """Tests for EventEmitter integration with statistics."""

    def test_events_emitted_on_record(self):
        """Test that events are emitted when recording."""
        stats = OptimizationStatistics()
        received_events = []

        @stats.events.on(OptimizationEvent.RULE_APPLIED)
        def on_rule_applied(rule, metadata):
            received_events.append((rule, metadata))

        rule = MockRule("TestRule")
        stats.record_rule_fired(rule, key="value")

        assert len(received_events) == 1
        assert received_events[0][0] is rule
        assert received_events[0][1]["key"] == "value"

    def test_multiple_handlers(self):
        """Test that multiple handlers can listen."""
        stats = OptimizationStatistics()
        handler1_calls = []
        handler2_calls = []

        stats.events.on(OptimizationEvent.RULE_MATCH, lambda name: handler1_calls.append(name))
        stats.events.on(OptimizationEvent.RULE_MATCH, lambda name: handler2_calls.append(name))

        stats.record_instruction_rule_match("TestRule")

        assert len(handler1_calls) == 1
        assert len(handler2_calls) == 1

    def test_reset_preserves_handlers(self):
        """Test that reset doesn't clear event handlers."""
        stats = OptimizationStatistics()
        calls = []

        stats.events.on(OptimizationEvent.RULE_APPLIED, lambda r, m: calls.append(r))
        stats.record_rule_fired(MockRule("Before"))

        stats.reset()

        stats.record_rule_fired(MockRule("After"))

        # Handler should still work after reset
        assert len(calls) == 2


class TestBackwardCompatibility:
    """Tests for backward compatibility with legacy API."""

    def test_legacy_record_instruction_rule_match(self):
        """Test legacy record_instruction_rule_match still works."""
        stats = OptimizationStatistics()

        stats.record_instruction_rule_match("TestRule")

        assert stats.get_instruction_rule_match_count("TestRule") == 1

    def test_legacy_record_optimizer_match(self):
        """Test legacy record_optimizer_match still works."""
        stats = OptimizationStatistics()

        stats.record_optimizer_match("PatternOptimizer")

        assert stats.get_optimizer_match_count("PatternOptimizer") == 1

    def test_legacy_record_cfg_rule_patches(self):
        """Test legacy record_cfg_rule_patches still works."""
        stats = OptimizationStatistics()

        stats.record_cfg_rule_patches("CfgRule", 10)
        stats.record_cfg_rule_patches("CfgRule", 5)

        patches = stats.get_cfg_rule_patch_counts("CfgRule")
        assert patches == [10, 5]

    def test_record_rule_fired_updates_legacy_counters(self):
        """Test that new API updates legacy counters for compatibility."""
        stats = OptimizationStatistics()
        rule = MockRule("TestRule")

        stats.record_rule_fired(rule)

        # Legacy counter should also be updated
        assert stats.get_instruction_rule_match_count("TestRule") == 1
