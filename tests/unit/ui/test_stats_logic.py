"""Tests for stats_logic module (pure Python, no IDA dependencies)."""

from __future__ import annotations

from pathlib import Path

from d810.ui.stats_logic import get_fired_rule_names


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
                "EmulatedDispatcherUnflattener": {"uses": 2, "total_patches": 10}
            },
        }
        result = get_fired_rule_names(stats)
        assert result == ["EmulatedDispatcherUnflattener"]

    def test_combined_stats(self):
        """Test stats with rules from all three categories."""
        stats = {
            "optimizer_matches": {"PatternOpt": 1},
            "rule_matches": {"AddRule": 2},
            "cfg_patches": {
                "EmulatedDispatcherUnflattener": {"uses": 3, "total_patches": 10}
            },
        }
        result = get_fired_rule_names(stats)
        # Should be sorted and unique
        assert result == ["AddRule", "EmulatedDispatcherUnflattener", "PatternOpt"]

    def test_zero_count_excluded(self):
        """Test that rules with zero counts are excluded."""
        stats = {
            "optimizer_matches": {"RuleA": 5, "RuleB": 0},
            "rule_matches": {"RuleC": 0},
            "cfg_patches": {"RuleD": {"uses": 0, "total_patches": 100}},
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


def test_stats_panel_has_no_private_rule_override_controls() -> None:
    source = (
        Path(__file__).resolve().parents[3]
        / "src"
        / "d810"
        / "ui"
        / "stats_dialog.py"
    ).read_text(encoding="utf-8")

    for removed in (
        "add_btn",
        "Save for function",
        "Apply fired rules as active inference",
        "_on_save_for_function",
        "_on_apply_inference_for_function",
        "_on_clear_active_inference",
    ):
        assert removed not in source
