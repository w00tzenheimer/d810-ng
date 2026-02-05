"""Unit tests for VerifiableRule Registrant-based registration.

Tests the automatic registration system that enables:
- Unit testing without IDA (store classes, not instances)
- Automatic discovery via Registrant metaclass
- Lazy instantiation when IDA is available
"""

import pytest

from d810.mba.dsl import Var
from d810.mba.rules import VerifiableRule
from d810.core.registry import Registrant


# Test variables
x, y = Var("x"), Var("y")


class TestVerifiableRuleRegistrant:
    """Tests for VerifiableRule Registrant-based registration."""

    def test_verifiable_rule_has_registry(self):
        """Test that VerifiableRule has its own registry."""
        assert hasattr(VerifiableRule, 'registry')
        assert isinstance(VerifiableRule.registry, dict)

    def test_automatic_registration(self):
        """Test that subclasses automatically register."""
        # Create a unique test hierarchy to avoid pollution
        class TestBase(VerifiableRule, Registrant):
            pass

        initial_count = len(TestBase.registry)

        class TestRule(TestBase):
            PATTERN = x + y
            REPLACEMENT = y + x
            DESCRIPTION = "Test"

        # Class should be automatically registered in TestBase
        assert len(TestBase.registry) == initial_count + 1
        assert TestRule in TestBase.registry.values()

    def test_iteration_over_registry(self):
        """Test iterating over registry yields classes."""
        # Create isolated hierarchy
        class IterTestBase(VerifiableRule, Registrant):
            pass

        class IterRule1(IterTestBase):
            PATTERN = x | y
            REPLACEMENT = y | x
            DESCRIPTION = "Iter 1"

        class IterRule2(IterTestBase):
            PATTERN = x & y
            REPLACEMENT = y & x
            DESCRIPTION = "Iter 2"

        classes = list(IterTestBase.registry.values())
        assert IterRule1 in classes
        assert IterRule2 in classes

    def test_contains_check(self):
        """Test 'in' operator for registry values."""
        class ContainsTestBase(VerifiableRule, Registrant):
            pass

        class ContainsRule(ContainsTestBase):
            PATTERN = x ^ y
            REPLACEMENT = y ^ x
            DESCRIPTION = "Contains test"

        assert ContainsRule in ContainsTestBase.registry.values()

    def test_registry_len(self):
        """Test len() on registry."""
        class LenTestBase(VerifiableRule, Registrant):
            pass

        initial_count = len(LenTestBase.registry)
        
        class LenRule(LenTestBase):
            PATTERN = x + y
            REPLACEMENT = y + x
            DESCRIPTION = "Len test"

        assert len(LenTestBase.registry) == initial_count + 1

    def test_hierarchical_scoping(self):
        """Test that intermediate base classes that inherit from Registrant get their own registries."""
        # These must ALSO inherit from Registrant to get separate registries
        class ArmRule(VerifiableRule, Registrant):
            """Base for ARM-specific rules."""
            pass

        class X86Rule(VerifiableRule, Registrant):
            """Base for X86-specific rules."""
            pass

        class ArmAdd(ArmRule):
            PATTERN = x + y
            REPLACEMENT = y + x
            DESCRIPTION = "ARM add"

        class X86Add(X86Rule):
            PATTERN = x - y  
            REPLACEMENT = x + (-y)
            DESCRIPTION = "X86 add"

        # Each hierarchy should have its own registry
        arm_rules = list(ArmRule.registry.values())
        x86_rules = list(X86Rule.registry.values())

        assert ArmAdd in arm_rules
        assert X86Add in x86_rules
        assert ArmAdd not in x86_rules
        assert X86Add not in arm_rules


class TestInstantiateAll:
    """Tests for lazy instantiation."""

    def test_instantiate_returns_list(self):
        """Test instantiate_all returns list."""
        # Note: Without IDA, instantiation will fail but should return empty list
        # The API test is still valid - we're testing that it returns a list
        instances = VerifiableRule.instantiate_all()
        assert isinstance(instances, list)

    def test_instantiate_on_custom_hierarchy(self):
        """Test instantiate_all works on custom hierarchies."""
        class CustomBase(VerifiableRule, Registrant):
            pass

        instances = CustomBase.instantiate_all()
        assert isinstance(instances, list)
