"""Tests for context-aware DSL extensions.

These tests verify that the context-aware DSL correctly handles:
1. Context providers (binding variables from instruction context)
2. Context constraints (checking destination properties)
3. Destination updates (modifying the instruction destination)

WHY THIS IS IN system/ TESTS:
    The extensions module (d810.optimizers.extensions) directly imports from
    ida_hexrays at module level, so it requires IDA Pro to be available.
    These are IDA-specific helpers for pattern matching optimization rules.
"""

import pytest

from d810.optimizers import extensions
from d810.optimizers.extensions import context, when

# --- DestinationHelpers tests ---


@pytest.mark.parametrize(
    "helper, ctx, expected",
    [
        (when.dst.is_high_half, {"_candidate": None}, False),
        (when.dst.is_register, {"_candidate": None}, False),
        (when.dst.is_memory, {"_candidate": None}, False),
    ],
)
def test_destination_helpers_no_candidate(helper, ctx, expected):
    """Test destination helpers when candidate is None."""
    assert helper(ctx) is expected


# --- ContextProviders tests ---


@pytest.mark.parametrize(
    "provider, ctx, expected",
    [
        (context.dst.parent_register, {"_candidate": None}, None),
        (context.dst.operand_size, {}, None),
    ],
)
def test_context_providers_no_candidate(provider, ctx, expected):
    """Test context providers when candidate is None or missing."""
    assert provider(ctx) is expected


# --- Context-aware Rule Integration tests ---


def import_replace_mov_high_context():
    """Utility to try importing ReplaceMovHighContext, skip test if not found."""
    try:
        from d810.optimizers.microcode.instructions.pattern_matching.experimental import (
            ReplaceMovHighContext,
        )

        return ReplaceMovHighContext
    except ImportError as e:
        pytest.skip(f"Could not import context-aware rule: {e}")


def test_rule_imports_correctly():
    """Test that the context-aware rule can be imported and has expected attributes."""
    ReplaceMovHighContext = import_replace_mov_high_context()
    # Verify the rule has the expected attributes
    assert hasattr(ReplaceMovHighContext, "PATTERN")
    assert hasattr(ReplaceMovHighContext, "REPLACEMENT")
    assert hasattr(ReplaceMovHighContext, "CONSTRAINTS")
    assert hasattr(ReplaceMovHighContext, "CONTEXT_VARS")
    assert hasattr(ReplaceMovHighContext, "UPDATE_DESTINATION")
    # Verify class-level values
    assert ReplaceMovHighContext.UPDATE_DESTINATION == "full_reg"
    assert "full_reg" in ReplaceMovHighContext.CONTEXT_VARS
    assert len(ReplaceMovHighContext.CONSTRAINTS) > 0


def test_rule_instance_creation():
    """Test that we can create an instance of the context-aware rule."""
    ReplaceMovHighContext = import_replace_mov_high_context()
    rule = ReplaceMovHighContext()
    # Check that the rule has the required properties
    assert rule.name == "ReplaceMovHighContext"
    assert rule.SKIP_VERIFICATION is True  # Size-changing rule
    assert hasattr(rule, "check_candidate")


def test_context_vars_processing():
    """Test that CONTEXT_VARS are processed correctly."""
    ReplaceMovHighContext = import_replace_mov_high_context()
    rule = ReplaceMovHighContext()
    # CONTEXT_VARS should be a dict and its items callable
    assert isinstance(rule.CONTEXT_VARS, dict)
    assert "full_reg" in rule.CONTEXT_VARS
    provider = rule.CONTEXT_VARS["full_reg"]
    assert callable(provider)


# --- DSL Documentation tests ---


def test_extensions_module_has_docstring():
    """Verify the extensions module has documentation."""
    assert extensions.__doc__ is not None
    assert "context-aware" in extensions.__doc__.lower()


def test_helpers_have_docstrings():
    """Verify all helpers have documentation."""
    from d810.optimizers.extensions import ContextProviders, DestinationHelpers

    # Check DestinationHelpers
    assert DestinationHelpers.is_high_half.__doc__ is not None
    assert DestinationHelpers.is_register.__doc__ is not None
    assert DestinationHelpers.is_memory.__doc__ is not None

    # Check ContextProviders
    assert ContextProviders.parent_register.__doc__ is not None
    assert ContextProviders.operand_size.__doc__ is not None


def test_example_rule_has_comprehensive_docstring():
    """Verify the example rule has comprehensive documentation."""
    ReplaceMovHighContext = import_replace_mov_high_context()
    docstring = ReplaceMovHighContext.__doc__
    assert docstring is not None
    assert "when.dst.is_high_half" in docstring
    assert "context.dst.parent_register" in docstring
    assert "UPDATE_DESTINATION" in docstring
    assert "Example:" in docstring
