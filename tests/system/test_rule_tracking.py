"""Test to verify that d810 rules are firing during deobfuscation.

This test tracks which optimization rules are applied during the
deobfuscation process.
"""

import logging
import os
import platform
from collections import defaultdict

import pytest

import idaapi
import idc


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"

# Configure detailed logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class RuleTracker:
    """Tracks which optimization rules are applied during deobfuscation."""

    def __init__(self):
        self.rules_fired = defaultdict(int)
        self.flow_optimizations = []
        self.instruction_optimizations = []

    def reset(self):
        """Reset tracking data."""
        self.rules_fired.clear()
        self.flow_optimizations.clear()
        self.instruction_optimizations.clear()

    def track_rule(self, rule_name, rule_type="instruction"):
        """Track that a rule was applied."""
        self.rules_fired[rule_name] += 1
        if rule_type == "flow":
            self.flow_optimizations.append(rule_name)
        else:
            self.instruction_optimizations.append(rule_name)

    def get_summary(self):
        """Get a summary of rules fired."""
        total = sum(self.rules_fired.values())
        return {
            "total_applications": total,
            "unique_rules": len(self.rules_fired),
            "rules_fired": dict(self.rules_fired),
            "flow_count": len(self.flow_optimizations),
            "instruction_count": len(self.instruction_optimizations),
        }

    def print_summary(self):
        """Print a human-readable summary."""
        summary = self.get_summary()
        logger.info("=" * 80)
        logger.info("D810 OPTIMIZATION SUMMARY")
        logger.info("=" * 80)
        logger.info(f"Total rule applications: {summary['total_applications']}")
        logger.info(f"Unique rules fired: {summary['unique_rules']}")
        logger.info(f"Flow optimizations: {summary['flow_count']}")
        logger.info(f"Instruction optimizations: {summary['instruction_count']}")
        logger.info("")
        logger.info("Rules fired (sorted by frequency):")
        for rule, count in sorted(
            summary["rules_fired"].items(), key=lambda x: x[1], reverse=True
        ):
            logger.info(f"  {rule}: {count}x")
        logger.info("=" * 80)


# Global tracker instance
tracker = RuleTracker()


@pytest.fixture(scope="class")
def rule_tracking_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    """Setup fixture for rule tracking tests - runs once per class."""
    # Initialize Hex-Rays
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")

    # configure_hexrays and setup_libobfuscated_funcs are auto-executed by pytest

    # Enable debug logging for d810
    logging.getLogger("d810").setLevel(logging.DEBUG)
    logging.getLogger("D810").setLevel(logging.DEBUG)

    return ida_database


@pytest.fixture(autouse=True)
def reset_tracker():
    """Reset tracker before each test."""
    tracker.reset()
    yield
    # Optionally print summary after test
    tracker.print_summary()


def _get_func_ea(func_name):
    """Get function EA, trying different name prefixes."""
    for prefix in ["", "_", "__"]:
        ea = idc.get_name_ea_simple(prefix + func_name)
        if ea != idaapi.BADADDR:
            return ea
    return idaapi.BADADDR


def _decompile_and_track(func_name, d810_state_all_rules, pseudocode_to_string):
    """Decompile a function and track which rules fire.

    Args:
        func_name: Name of the function to decompile
        d810_state_all_rules: Fixture providing d810 state with all rules
        pseudocode_to_string: Fixture providing pseudocode conversion function

    Returns:
        Tuple of (pseudocode_before, pseudocode_after, tracker)
    """
    func_ea = _get_func_ea(func_name)
    assert func_ea != idaapi.BADADDR, f"Function '{func_name}' not found (tried prefixes: '', '_', '__')"

    # Use all_rules=True to test all DSL rules
    with d810_state_all_rules() as state:
        # BEFORE: Decompile without d810
        state.stop_d810()
        decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
        assert decompiled_before is not None, f"Decompilation failed for {func_name}"
        pseudocode_before = pseudocode_to_string(decompiled_before.get_pseudocode())

        # AFTER: Decompile with d810 and track optimizations
        state.start_d810()
        decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
        assert (
            decompiled_after is not None
        ), f"Decompilation with d810 failed for {func_name}"
        pseudocode_after = pseudocode_to_string(decompiled_after.get_pseudocode())

    return pseudocode_before, pseudocode_after, tracker


@pytest.mark.usefixtures("rule_tracking_setup")
class TestRuleTracking:
    """Test class for rule tracking - requires binary_name for ida_database fixture."""

    binary_name = _get_default_binary()

    def test_xor_pattern_optimization(self, d810_state_all_rules, pseudocode_to_string):
        """Test that XOR pattern is optimized by DSL rules."""
        logger.info("\n" + "=" * 80)
        logger.info("TEST: XOR Pattern Optimization")
        logger.info("=" * 80)

        before, after, _ = _decompile_and_track(
            "test_xor", d810_state_all_rules, pseudocode_to_string
        )

        logger.info("\nCode BEFORE d810:")
        logger.info(before)
        logger.info("\nCode AFTER d810:")
        logger.info(after)

        # Verify optimization happened
        assert before != after, "d810 should modify the code"

        # Check that XOR patterns are present in after
        assert "^" in after, "Should contain XOR operator after optimization"

        # Check for obfuscated patterns in before
        assert " & " in before, "Before should contain AND from obfuscated XOR pattern"

    def test_constant_folding_optimization(self, d810_state_all_rules, pseudocode_to_string):
        """Test that constant folding uses DSL rules."""
        logger.info("\n" + "=" * 80)
        logger.info("TEST: Constant Folding")
        logger.info("=" * 80)

        before, after, _ = _decompile_and_track(
            "test_cst_simplification", d810_state_all_rules, pseudocode_to_string
        )

        logger.info("\nCode BEFORE d810:")
        logger.info(before)
        logger.info("\nCode AFTER d810:")
        logger.info(after)

        # Verify optimization happened
        assert before != after, "d810 should simplify constants"

        # Check for hex constants (we configured DEFAULT_RADIX=16)
        assert "0x" in after, "Should have hexadecimal constants after d810"

    def test_mba_pattern_optimization(self, d810_state_all_rules, pseudocode_to_string):
        """Test that MBA patterns are optimized by DSL rules."""
        logger.info("\n" + "=" * 80)
        logger.info("TEST: MBA Pattern Optimization")
        logger.info("=" * 80)

        before, after, _ = _decompile_and_track(
            "test_mba_guessing", d810_state_all_rules, pseudocode_to_string
        )

        logger.info("\nCode BEFORE d810:")
        logger.info(before)
        logger.info("\nCode AFTER d810:")
        logger.info(after)

        # Verify optimization happened
        assert before != after, "d810 should simplify MBA patterns"

        # Count operators before and after
        ops_before = before.count("+") + before.count("-") + before.count("*")
        ops_after = after.count("+") + after.count("-") + after.count("*")

        assert (
            ops_after < ops_before
        ), f"MBA simplification should reduce operators ({ops_before} -> {ops_after})"

    def test_opaque_predicate_removal(self, d810_state_all_rules, pseudocode_to_string):
        """Test that opaque predicates are removed."""
        logger.info("\n" + "=" * 80)
        logger.info("TEST: Opaque Predicate Removal")
        logger.info("=" * 80)

        before, after, _ = _decompile_and_track(
            "test_opaque_predicate", d810_state_all_rules, pseudocode_to_string
        )

        logger.info("\nCode BEFORE d810:")
        logger.info(before)
        logger.info("\nCode AFTER d810:")
        logger.info(after)

        # Verify optimization happened
        assert before != after, "d810 should remove opaque predicates"

        # Check for constant assignments
        assert "= 1;" in after, "Should have constant 1"
        assert "= 0;" in after, "Should have constant 0"
