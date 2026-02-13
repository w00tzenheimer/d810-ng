"""Unit tests for rule registry compilation and invalidation (PR3).

This module tests the compiled registry view mechanism that caches
expensive pattern storage structures and invalidates them only when
rules change.

IMPORTANT: Unit tests MUST be pure Python — no IDA imports, no mock IDA objects.
"""

import dataclasses
import time
import unittest


# Mock classes to simulate the pattern optimizer without IDA dependencies
@dataclasses.dataclass
class MockRule:
    """Minimal rule mock for testing."""
    name: str
    generation: int = 0


@dataclasses.dataclass
class CompiledRuleView:
    """Cached compiled state for an optimizer's rule set.

    This dataclass represents the compiled view of all active rules.
    It includes a generation counter to detect when invalidation is needed.
    """
    generation: int
    rule_count: int
    compiled_at: float  # time.monotonic()
    metadata: dict = dataclasses.field(default_factory=dict)


class MockOptimizer:
    """Mock optimizer with generation-based compilation."""

    def __init__(self):
        self.rules: list[MockRule] = []
        self._generation: int = 0
        self._compiled_view: CompiledRuleView | None = None

    def add_rule(self, rule: MockRule) -> None:
        """Add a rule and increment generation."""
        self.rules.append(rule)
        self._generation += 1
        # Compiled view is now stale

    def remove_rule(self, rule_name: str) -> None:
        """Remove a rule and increment generation."""
        self.rules = [r for r in self.rules if r.name != rule_name]
        self._generation += 1

    def get_compiled_view(self) -> CompiledRuleView:
        """Get or rebuild the compiled rule view."""
        if self._compiled_view is None or self._compiled_view.generation != self._generation:
            self._compiled_view = self._compile_rules()
        return self._compiled_view

    def _compile_rules(self) -> CompiledRuleView:
        """Build compiled view from current rule set."""
        return CompiledRuleView(
            generation=self._generation,
            rule_count=len(self.rules),
            compiled_at=time.monotonic(),
        )

    def invalidate(self) -> None:
        """Explicitly invalidate the compiled view."""
        self._generation += 1


class TestCompiledRuleView(unittest.TestCase):
    """Test the CompiledRuleView dataclass."""

    def test_compiled_view_creation(self):
        """Test that CompiledRuleView can be created with basic fields."""
        view = CompiledRuleView(
            generation=1,
            rule_count=5,
            compiled_at=time.monotonic(),
        )
        self.assertEqual(view.generation, 1)
        self.assertEqual(view.rule_count, 5)
        self.assertIsInstance(view.compiled_at, float)
        self.assertIsInstance(view.metadata, dict)

    def test_compiled_view_with_metadata(self):
        """Test that metadata field works correctly."""
        view = CompiledRuleView(
            generation=2,
            rule_count=10,
            compiled_at=time.monotonic(),
            metadata={"opcodes": {1, 2, 3}},
        )
        self.assertEqual(view.metadata["opcodes"], {1, 2, 3})


class TestRegistryCompilation(unittest.TestCase):
    """Test registry compilation and invalidation logic."""

    def test_initial_compilation(self):
        """Test that first access creates compiled view."""
        opt = MockOptimizer()
        opt.add_rule(MockRule(name="rule1"))

        view = opt.get_compiled_view()
        self.assertEqual(view.generation, 1)
        self.assertEqual(view.rule_count, 1)

    def test_cache_reuse_when_no_changes(self):
        """Test that compiled view is reused when no changes occur."""
        opt = MockOptimizer()
        opt.add_rule(MockRule(name="rule1"))

        view1 = opt.get_compiled_view()
        view2 = opt.get_compiled_view()

        # Should be the same object (cached)
        self.assertIs(view1, view2)
        self.assertEqual(view1.compiled_at, view2.compiled_at)

    def test_invalidation_on_add_rule(self):
        """Test that adding a rule increments generation and invalidates cache."""
        opt = MockOptimizer()
        opt.add_rule(MockRule(name="rule1"))
        view1 = opt.get_compiled_view()

        # Add another rule
        opt.add_rule(MockRule(name="rule2"))
        view2 = opt.get_compiled_view()

        # Should be different views
        self.assertIsNot(view1, view2)
        self.assertEqual(view1.generation, 1)
        self.assertEqual(view2.generation, 2)
        self.assertEqual(view2.rule_count, 2)

    def test_invalidation_on_remove_rule(self):
        """Test that removing a rule increments generation and invalidates cache."""
        opt = MockOptimizer()
        opt.add_rule(MockRule(name="rule1"))
        opt.add_rule(MockRule(name="rule2"))
        view1 = opt.get_compiled_view()

        # Remove a rule
        opt.remove_rule("rule1")
        view2 = opt.get_compiled_view()

        # Should be different views
        self.assertIsNot(view1, view2)
        self.assertEqual(view1.generation, 2)
        self.assertEqual(view2.generation, 3)
        self.assertEqual(view2.rule_count, 1)

    def test_explicit_invalidation(self):
        """Test explicit invalidation via invalidate() method."""
        opt = MockOptimizer()
        opt.add_rule(MockRule(name="rule1"))
        view1 = opt.get_compiled_view()

        # Explicit invalidation
        opt.invalidate()
        view2 = opt.get_compiled_view()

        # Should be different views
        self.assertIsNot(view1, view2)
        self.assertEqual(view1.generation, 1)
        self.assertEqual(view2.generation, 2)

    def test_multiple_operations_increment_generation(self):
        """Test that multiple operations correctly increment generation."""
        opt = MockOptimizer()

        self.assertEqual(opt._generation, 0)

        opt.add_rule(MockRule(name="rule1"))
        self.assertEqual(opt._generation, 1)

        opt.add_rule(MockRule(name="rule2"))
        self.assertEqual(opt._generation, 2)

        opt.remove_rule("rule1")
        self.assertEqual(opt._generation, 3)

        opt.invalidate()
        self.assertEqual(opt._generation, 4)


class TestLifecycleInvalidation(unittest.TestCase):
    """Test invalidation during lifecycle transitions."""

    def test_reload_triggers_rebuild(self):
        """Test that reload (simulated by invalidate) triggers recompilation."""
        opt = MockOptimizer()
        opt.add_rule(MockRule(name="rule1"))
        opt.add_rule(MockRule(name="rule2"))

        view1 = opt.get_compiled_view()
        self.assertEqual(view1.rule_count, 2)

        # Simulate reload (manager.reload() should call invalidate)
        opt.invalidate()

        # Next access should rebuild
        view2 = opt.get_compiled_view()
        self.assertIsNot(view1, view2)
        self.assertEqual(view2.generation, view1.generation + 1)

    def test_config_change_triggers_rebuild(self):
        """Test that configuration changes (via invalidate) trigger recompilation."""
        opt = MockOptimizer()
        opt.add_rule(MockRule(name="rule1"))

        view1 = opt.get_compiled_view()

        # Simulate config change
        opt.invalidate()

        view2 = opt.get_compiled_view()
        self.assertIsNot(view1, view2)
        self.assertGreater(view2.generation, view1.generation)


if __name__ == "__main__":
    unittest.main()
