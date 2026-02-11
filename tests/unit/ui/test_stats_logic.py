"""Tests for stats_logic module (pure Python, no IDA dependencies)."""
from __future__ import annotations

import pytest

from d810.core.persistence import FunctionRuleConfig
from d810.ui.stats_logic import (
    get_fired_rule_names,
    save_fired_rules_for_function,
)


class TestGetFiredRuleNames:
    """Test get_fired_rule_names function."""

    def test_empty_stats(self):
        """Test with empty stats dict."""
        result = get_fired_rule_names({})
        assert result == []

    def test_none_stats(self):
        """Test with None stats (should handle gracefully)."""
        # Function handles None via truthiness check
        result = get_fired_rule_names(None)  # type: ignore[arg-type]
        assert result == []

    def test_optimizer_matches_only(self):
        """Test stats with only optimizer_matches."""
        stats = {
            "optimizer_matches": {"PatternOptimizer": 10, "ZeroRule": 5},
            "rule_matches": {},
            "cfg_patches": {},
        }
        result = get_fired_rule_names(stats)
        assert result == ["PatternOptimizer", "ZeroRule"]

    def test_rule_matches_only(self):
        """Test stats with only rule_matches."""
        stats = {
            "optimizer_matches": {},
            "rule_matches": {"AddRule": 3, "XorRule": 7},
            "cfg_patches": {},
        }
        result = get_fired_rule_names(stats)
        assert result == ["AddRule", "XorRule"]

    def test_cfg_patches_only(self):
        """Test stats with only cfg_patches."""
        stats = {
            "optimizer_matches": {},
            "rule_matches": {},
            "cfg_patches": {
                "Unflattener": {"uses": 2, "total_patches": 10}
            },
        }
        result = get_fired_rule_names(stats)
        assert result == ["Unflattener"]

    def test_combined_stats(self):
        """Test stats with rules from all three categories."""
        stats = {
            "optimizer_matches": {"PatternOpt": 1},
            "rule_matches": {"AddRule": 2},
            "cfg_patches": {
                "Unflattener": {"uses": 3, "total_patches": 10}
            },
        }
        result = get_fired_rule_names(stats)
        # Should be sorted and unique
        assert result == ["AddRule", "PatternOpt", "Unflattener"]

    def test_zero_count_excluded(self):
        """Test that rules with zero counts are excluded."""
        stats = {
            "optimizer_matches": {"RuleA": 5, "RuleB": 0},
            "rule_matches": {"RuleC": 0},
            "cfg_patches": {
                "RuleD": {"uses": 0, "total_patches": 100}
            },
        }
        result = get_fired_rule_names(stats)
        # Only RuleA should be included (count > 0)
        assert result == ["RuleA"]

    def test_duplicate_rules_deduped(self):
        """Test that duplicate rule names are deduped."""
        stats = {
            "optimizer_matches": {"SameRule": 5},
            "rule_matches": {"SameRule": 10},
            "cfg_patches": {},
        }
        result = get_fired_rule_names(stats)
        # Should only appear once, even though it's in two categories
        assert result == ["SameRule"]

    def test_sorted_output(self):
        """Test that output is sorted alphabetically."""
        stats = {
            "optimizer_matches": {},
            "rule_matches": {"ZRule": 1, "ARule": 2, "MRule": 3},
            "cfg_patches": {},
        }
        result = get_fired_rule_names(stats)
        assert result == ["ARule", "MRule", "ZRule"]

    def test_missing_keys_handled(self):
        """Test that missing dict keys are handled gracefully."""
        stats = {
            "optimizer_matches": {"Rule1": 1},
            # rule_matches and cfg_patches missing
        }
        result = get_fired_rule_names(stats)
        assert result == ["Rule1"]


class TestSaveFiredRulesForFunction:
    """Test save_fired_rules_for_function function."""

    def test_basic_creation(self):
        """Test creating a FunctionRuleConfig with fired rules."""
        config = save_fired_rules_for_function(
            func_ea=0x401000,
            fired_rule_names=["AddRule", "XorRule"],
        )

        assert config is not None
        assert config.function_addr == 0x401000
        assert config.enabled_rules == {"AddRule", "XorRule"}
        assert config.disabled_rules == set()

    def test_empty_fired_rules(self):
        """Test with empty fired rules list."""
        config = save_fired_rules_for_function(
            func_ea=0x402000,
            fired_rule_names=[],
        )

        assert config.function_addr == 0x402000
        assert config.enabled_rules == set()
        assert config.disabled_rules == set()

    def test_with_func_name(self):
        """Test that func_name is used in auto-generated notes."""
        config = save_fired_rules_for_function(
            func_ea=0x403000,
            fired_rule_names=["RuleA"],
            func_name="my_function",
        )

        assert config.notes == "Rules that fired during deobfuscation of my_function"

    def test_with_custom_notes(self):
        """Test that custom notes override auto-generated notes."""
        config = save_fired_rules_for_function(
            func_ea=0x404000,
            fired_rule_names=["RuleB"],
            func_name="my_function",
            notes="Custom notes here",
        )

        assert config.notes == "Custom notes here"

    def test_no_func_name_no_notes(self):
        """Test that notes are empty if neither provided."""
        config = save_fired_rules_for_function(
            func_ea=0x405000,
            fired_rule_names=["RuleC"],
        )

        assert config.notes == ""

    def test_preserves_rule_order_as_set(self):
        """Test that fired_rule_names are stored as a set (unordered)."""
        config = save_fired_rules_for_function(
            func_ea=0x406000,
            fired_rule_names=["ZRule", "ARule", "MRule"],
        )

        # Should be a set with all three rules
        assert len(config.enabled_rules) == 3
        assert "ZRule" in config.enabled_rules
        assert "ARule" in config.enabled_rules
        assert "MRule" in config.enabled_rules
