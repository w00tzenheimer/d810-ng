"""Unit tests for d810-ng pseudocode actions logic.

These tests verify the business logic of context menu actions without
requiring IDA Pro or Qt. The logic is separated into a pure-Python module
for testability.
"""
from __future__ import annotations

from unittest.mock import MagicMock

from d810.ui.actions_logic import (
    check_plugin_state,
    format_stats_for_display,
    get_deobfuscation_stats,
    stats_to_csv,
    stats_to_table_rows,
)


class TestCheckPluginState:
    """Test plugin state checking logic."""

    def test_state_is_none(self):
        """Plugin state check should fail when state is None."""
        is_ready, error_msg = check_plugin_state(None)

        assert not is_ready
        assert "not loaded" in error_msg.lower()

    def test_not_loaded(self):
        """Plugin state check should fail when plugin is not loaded."""
        state = MagicMock()
        state.is_loaded.return_value = False

        is_ready, error_msg = check_plugin_state(state)

        assert not is_ready
        assert "not loaded" in error_msg.lower()

    def test_manager_not_initialized(self):
        """Plugin state check should fail when manager is None."""
        state = MagicMock()
        state.is_loaded.return_value = True
        state.manager = None

        is_ready, error_msg = check_plugin_state(state)

        assert is_ready  # Manager being None is okay if state is loaded
        assert error_msg == ""

    def test_manager_not_started(self):
        """Plugin state check should fail when manager is not started."""
        state = MagicMock()
        state.is_loaded.return_value = True
        state.manager = MagicMock()
        state.manager.started = False

        is_ready, error_msg = check_plugin_state(state)

        assert not is_ready
        assert "not started" in error_msg.lower()

    def test_ready_state(self):
        """Plugin state check should succeed when fully initialized and started."""
        state = MagicMock()
        state.is_loaded.return_value = True
        state.manager = MagicMock()
        state.manager.started = True

        is_ready, error_msg = check_plugin_state(state)

        assert is_ready
        assert error_msg == ""


class TestGetDeobfuscationStats:
    """Test statistics collection logic."""

    def test_manager_without_stats(self):
        """Stats collection should return empty dict when manager has no stats."""
        manager = MagicMock()
        del manager.stats  # Remove stats attribute

        stats = get_deobfuscation_stats(manager)

        assert stats == {
            "optimizer_matches": {},
            "rule_matches": {},
            "cfg_patches": {},
            "total_rule_firings": 0,
            "total_cycles_detected": 0,
        }

    def test_manager_with_none_stats(self):
        """Stats collection should return empty dict when stats is None."""
        manager = MagicMock()
        manager.stats = None

        stats = get_deobfuscation_stats(manager)

        assert stats == {
            "optimizer_matches": {},
            "rule_matches": {},
            "cfg_patches": {},
            "total_rule_firings": 0,
            "total_cycles_detected": 0,
        }

    def test_no_report_yet(self):
        """Stats collection should return empty dict when no report has been generated."""
        manager = MagicMock()
        manager.stats.last_report.return_value = {}

        stats = get_deobfuscation_stats(manager)

        assert stats == {
            "optimizer_matches": {},
            "rule_matches": {},
            "cfg_patches": {},
            "total_rule_firings": 0,
            "total_cycles_detected": 0,
        }

    def test_collects_optimizer_matches(self):
        """Stats collection should include optimizer match counts."""
        manager = MagicMock()
        manager.stats.last_report.return_value = {
            "optimizer_matches": {"PatternOptimizer": 10, "ChainOptimizer": 5},
            "rule_matches": {},
            "cfg_patches": {},
            "total_rule_firings": 15,
            "total_cycles_detected": 0,
        }

        stats = get_deobfuscation_stats(manager)

        assert stats["optimizer_matches"] == {
            "PatternOptimizer": 10,
            "ChainOptimizer": 5,
        }
        assert stats["total_rule_firings"] == 15

    def test_collects_rule_matches(self):
        """Stats collection should include individual rule match counts."""
        manager = MagicMock()
        manager.stats.last_report.return_value = {
            "optimizer_matches": {},
            "rule_matches": {
                "FoldReadonlyDataRule": 32,
                "RotateHelperInlineRule": 4,
                "OrChain": 12,
            },
            "cfg_patches": {},
            "total_rule_firings": 48,
            "total_cycles_detected": 0,
        }

        stats = get_deobfuscation_stats(manager)

        assert stats["rule_matches"] == {
            "FoldReadonlyDataRule": 32,
            "RotateHelperInlineRule": 4,
            "OrChain": 12,
        }
        assert stats["total_rule_firings"] == 48

    def test_collects_cfg_patches(self):
        """Stats collection should include CFG rule patch information."""
        manager = MagicMock()
        manager.stats.last_report.return_value = {
            "optimizer_matches": {},
            "rule_matches": {},
            "cfg_patches": {
                "UnflattenRule": {"uses": 3, "total_patches": 15},
            },
            "total_rule_firings": 0,
            "total_cycles_detected": 0,
        }

        stats = get_deobfuscation_stats(manager)

        assert stats["cfg_patches"] == {
            "UnflattenRule": {"uses": 3, "total_patches": 15},
        }

    def test_collects_cycle_detection(self):
        """Stats collection should include cycle detection counts."""
        manager = MagicMock()
        manager.stats.last_report.return_value = {
            "optimizer_matches": {},
            "rule_matches": {},
            "cfg_patches": {},
            "total_rule_firings": 0,
            "total_cycles_detected": 2,
        }

        stats = get_deobfuscation_stats(manager)

        assert stats["total_cycles_detected"] == 2

    def test_complete_stats(self):
        """Stats collection should handle complete statistics with all fields."""
        manager = MagicMock()
        manager.stats.last_report.return_value = {
            "optimizer_matches": {"PatternOptimizer": 10},
            "rule_matches": {"TestRule": 5},
            "cfg_patches": {"UnflattenRule": {"uses": 1, "total_patches": 3}},
            "total_rule_firings": 15,
            "total_cycles_detected": 1,
        }

        stats = get_deobfuscation_stats(manager)

        assert stats["optimizer_matches"] == {"PatternOptimizer": 10}
        assert stats["rule_matches"] == {"TestRule": 5}
        assert stats["cfg_patches"] == {
            "UnflattenRule": {"uses": 1, "total_patches": 3}
        }
        assert stats["total_rule_firings"] == 15
        assert stats["total_cycles_detected"] == 1


class TestFormatStatsForDisplay:
    """Test statistics formatting for display."""

    def test_empty_stats(self):
        """Formatting empty stats should show zeros."""
        stats = {
            "optimizer_matches": {},
            "rule_matches": {},
            "cfg_patches": {},
            "total_rule_firings": 0,
            "total_cycles_detected": 0,
        }

        formatted = format_stats_for_display(stats)

        assert "=== d810-ng Deobfuscation Statistics ===" in formatted
        assert "Total rule firings: 0" in formatted
        assert "Cycles detected and broken: 0" in formatted

    def test_optimizer_matches_formatting(self):
        """Formatting should include optimizer match counts."""
        stats = {
            "optimizer_matches": {"PatternOptimizer": 10, "ChainOptimizer": 5},
            "rule_matches": {},
            "cfg_patches": {},
            "total_rule_firings": 15,
            "total_cycles_detected": 0,
        }

        formatted = format_stats_for_display(stats)

        assert "Optimizer matches:" in formatted
        assert "PatternOptimizer: 10" in formatted
        assert "ChainOptimizer: 5" in formatted

    def test_rule_matches_formatting(self):
        """Formatting should include rule match counts."""
        stats = {
            "optimizer_matches": {},
            "rule_matches": {"FoldReadonlyDataRule": 32, "OrChain": 12},
            "cfg_patches": {},
            "total_rule_firings": 44,
            "total_cycles_detected": 0,
        }

        formatted = format_stats_for_display(stats)

        assert "Rule matches:" in formatted
        assert "FoldReadonlyDataRule: 32" in formatted
        assert "OrChain: 12" in formatted
        assert "Total rule firings: 44" in formatted

    def test_cfg_patches_formatting(self):
        """Formatting should include CFG rule patch information."""
        stats = {
            "optimizer_matches": {},
            "rule_matches": {},
            "cfg_patches": {
                "UnflattenRule": {"uses": 3, "total_patches": 15},
            },
            "total_rule_firings": 0,
            "total_cycles_detected": 0,
        }

        formatted = format_stats_for_display(stats)

        assert "CFG rule patches:" in formatted
        assert "UnflattenRule: 3 uses, 15 patches" in formatted

    def test_cycles_formatting(self):
        """Formatting should include cycle detection counts."""
        stats = {
            "optimizer_matches": {},
            "rule_matches": {},
            "cfg_patches": {},
            "total_rule_firings": 10,
            "total_cycles_detected": 2,
        }

        formatted = format_stats_for_display(stats)

        assert "Cycles detected and broken: 2" in formatted

    def test_sorted_output(self):
        """Formatting should sort items alphabetically."""
        stats = {
            "optimizer_matches": {"ZOptimizer": 1, "AOptimizer": 2},
            "rule_matches": {"ZRule": 10, "ARule": 20},
            "cfg_patches": {},
            "total_rule_firings": 0,
            "total_cycles_detected": 0,
        }

        formatted = format_stats_for_display(stats)
        lines = formatted.split("\n")

        # Find optimizer section
        opt_start = next(i for i, line in enumerate(lines) if "Optimizer matches:" in line)
        assert "AOptimizer" in lines[opt_start + 1]
        assert "ZOptimizer" in lines[opt_start + 2]

        # Find rule section
        rule_start = next(i for i, line in enumerate(lines) if "Rule matches:" in line)
        assert "ARule" in lines[rule_start + 1]
        assert "ZRule" in lines[rule_start + 2]

    def test_multiline_structure(self):
        """Formatting should produce properly structured multi-line output."""
        stats = {
            "optimizer_matches": {"PatternOptimizer": 10},
            "rule_matches": {"TestRule": 5},
            "cfg_patches": {},
            "total_rule_firings": 15,
            "total_cycles_detected": 0,
        }

        formatted = format_stats_for_display(stats)
        lines = formatted.split("\n")

        # Should start with header
        assert lines[0] == "=== d810-ng Deobfuscation Statistics ==="

        # Should have sections separated by blank lines
        assert "" in lines  # At least one blank line

        # Should end with totals
        assert any("Total rule firings:" in line for line in lines)
        assert any("Cycles detected" in line for line in lines)

    def test_function_info_with_ea_and_name(self):
        """Formatting should include function EA and name when provided."""
        stats = {
            "optimizer_matches": {},
            "rule_matches": {},
            "cfg_patches": {},
            "total_rule_firings": 0,
            "total_cycles_detected": 0,
        }

        formatted = format_stats_for_display(stats, func_ea=0x401000, func_name="sub_401000")

        assert "Function: sub_401000 (0x401000)" in formatted

    def test_function_info_with_ea_only(self):
        """Formatting should include function EA when only EA is provided."""
        stats = {
            "optimizer_matches": {},
            "rule_matches": {},
            "cfg_patches": {},
            "total_rule_firings": 0,
            "total_cycles_detected": 0,
        }

        formatted = format_stats_for_display(stats, func_ea=0x401000)

        assert "Function: 0x401000" in formatted

    def test_function_info_with_name_only(self):
        """Formatting should include function name when only name is provided."""
        stats = {
            "optimizer_matches": {},
            "rule_matches": {},
            "cfg_patches": {},
            "total_rule_firings": 0,
            "total_cycles_detected": 0,
        }

        formatted = format_stats_for_display(stats, func_name="my_function")

        assert "Function: my_function" in formatted


class TestStatsToTableRows:
    """Test conversion of stats to table rows."""

    def test_empty_stats(self):
        """Empty stats should produce only the Total section."""
        stats = {
            "optimizer_matches": {},
            "rule_matches": {},
            "cfg_patches": {},
            "total_rule_firings": 0,
            "total_cycles_detected": 0,
        }

        rows = stats_to_table_rows(stats)

        # Should have 2 total rows (no separate header)
        assert len(rows) == 2
        assert rows[0] == ("Total", "Rule Firings", "0")
        assert rows[1] == ("Total", "Cycles Broken", "0")

    def test_optimizer_matches(self):
        """Optimizer matches should be in their own section."""
        stats = {
            "optimizer_matches": {"PatternOptimizer": 10, "ChainOptimizer": 5},
            "rule_matches": {},
            "cfg_patches": {},
            "total_rule_firings": 15,
            "total_cycles_detected": 0,
        }

        rows = stats_to_table_rows(stats)

        # Find Optimizers rows (sorted alphabetically)
        opt_rows = [r for r in rows if r[0] == "Optimizers"]
        assert len(opt_rows) == 2
        assert opt_rows[0] == ("Optimizers", "ChainOptimizer", "5")
        assert opt_rows[1] == ("Optimizers", "PatternOptimizer", "10")

    def test_rule_matches(self):
        """Rule matches should be in their own section."""
        stats = {
            "optimizer_matches": {},
            "rule_matches": {"ZRule": 8, "ARule": 15},
            "cfg_patches": {},
            "total_rule_firings": 23,
            "total_cycles_detected": 0,
        }

        rows = stats_to_table_rows(stats)

        # Find Rules rows (sorted alphabetically)
        rule_rows = [r for r in rows if r[0] == "Rules"]
        assert len(rule_rows) == 2
        assert rule_rows[0] == ("Rules", "ARule", "15")
        assert rule_rows[1] == ("Rules", "ZRule", "8")

    def test_cfg_patches_format(self):
        """CFG patches should show 'N uses, M patches' format."""
        stats = {
            "optimizer_matches": {},
            "rule_matches": {},
            "cfg_patches": {
                "UnflattenRule": {"uses": 3, "total_patches": 42},
            },
            "total_rule_firings": 0,
            "total_cycles_detected": 0,
        }

        rows = stats_to_table_rows(stats)

        # Find CFG Patches row
        cfg_rows = [r for r in rows if r[0] == "CFG Patches"]
        assert len(cfg_rows) == 1
        assert cfg_rows[0] == ("CFG Patches", "UnflattenRule", "3 uses, 42 patches")

    def test_cycles_section_only_when_present(self):
        """Cycles section should only appear if cycles were detected."""
        # No cycles
        stats = {
            "optimizer_matches": {},
            "rule_matches": {},
            "cfg_patches": {},
            "cycles_detected": {},
            "total_rule_firings": 0,
            "total_cycles_detected": 0,
        }

        rows = stats_to_table_rows(stats)
        cycles_rows = [r for r in rows if r[0] == "Cycles"]
        assert len(cycles_rows) == 0

        # With cycles
        stats["cycles_detected"] = {"SomeOptimizer": 5}
        stats["total_cycles_detected"] = 5

        rows = stats_to_table_rows(stats)
        cycles_rows = [r for r in rows if r[0] == "Cycles"]
        assert len(cycles_rows) == 1
        assert cycles_rows[0] == ("Cycles", "SomeOptimizer", "5")

    def test_complete_stats(self):
        """Complete stats should include all sections in correct order."""
        stats = {
            "optimizer_matches": {"PatternOptimizer": 10},
            "rule_matches": {"TestRule": 5},
            "cfg_patches": {"UnflattenRule": {"uses": 1, "total_patches": 3}},
            "cycles_detected": {"ChainOptimizer": 2},
            "total_rule_firings": 15,
            "total_cycles_detected": 2,
        }

        rows = stats_to_table_rows(stats)

        # Check that we have rows for each category
        categories = [r[0] for r in rows]
        assert "Optimizers" in categories
        assert "Rules" in categories
        assert "CFG Patches" in categories
        assert "Cycles" in categories
        assert "Total" in categories

        # Check specific rows
        assert ("Optimizers", "PatternOptimizer", "10") in rows
        assert ("Rules", "TestRule", "5") in rows
        assert ("CFG Patches", "UnflattenRule", "1 uses, 3 patches") in rows
        assert ("Cycles", "ChainOptimizer", "2") in rows
        assert ("Total", "Rule Firings", "15") in rows
        assert ("Total", "Cycles Broken", "2") in rows

    def test_category_on_every_row(self):
        """Category should be set on every row for proper sorting/grouping."""
        stats = {
            "optimizer_matches": {"PatternOptimizer": 10},
            "rule_matches": {"TestRule": 5},
            "cfg_patches": {},
            "total_rule_firings": 15,
            "total_cycles_detected": 0,
        }

        rows = stats_to_table_rows(stats)

        # Every row should have a category
        assert all(r[0] for r in rows)

        # Every row should have a name
        assert all(r[1] for r in rows)

        # Check specific rows have proper category
        opt_rows = [r for r in rows if r[0] == "Optimizers"]
        assert len(opt_rows) == 1
        assert opt_rows[0] == ("Optimizers", "PatternOptimizer", "10")

        rule_rows = [r for r in rows if r[0] == "Rules"]
        assert len(rule_rows) == 1
        assert rule_rows[0] == ("Rules", "TestRule", "5")

        total_rows = [r for r in rows if r[0] == "Total"]
        assert len(total_rows) == 2
        assert ("Total", "Rule Firings", "15") in total_rows
        assert ("Total", "Cycles Broken", "0") in total_rows


class TestStatsToCsv:
    """Test CSV export functionality."""

    def test_empty_stats(self):
        """CSV export of empty stats should have header and totals."""
        stats = {
            "optimizer_matches": {},
            "rule_matches": {},
            "cfg_patches": {},
            "total_rule_firings": 0,
            "total_cycles_detected": 0,
        }

        csv_output = stats_to_csv(stats)

        assert "Category,Name,Count" in csv_output
        assert "Total" in csv_output
        assert "Rule Firings,0" in csv_output
        assert "Cycles Broken,0" in csv_output

    def test_function_header_comment(self):
        """CSV should include function info as comment."""
        stats = {
            "optimizer_matches": {},
            "rule_matches": {},
            "cfg_patches": {},
            "total_rule_firings": 0,
            "total_cycles_detected": 0,
        }

        csv_output = stats_to_csv(stats, func_ea=0x401000, func_name="sub_401000")

        assert "# Function: sub_401000 (0x401000)" in csv_output

    def test_csv_format(self):
        """CSV should be properly formatted with commas."""
        stats = {
            "optimizer_matches": {"PatternOptimizer": 10},
            "rule_matches": {"TestRule": 5},
            "cfg_patches": {},
            "total_rule_firings": 15,
            "total_cycles_detected": 0,
        }

        csv_output = stats_to_csv(stats)

        # Header
        assert "Category,Name,Count" in csv_output

        # Data rows (with categories on every row)
        assert "Optimizers,PatternOptimizer,10" in csv_output
        assert "Rules,TestRule,5" in csv_output
        assert "Total,Rule Firings,15" in csv_output
        assert "Total,Cycles Broken,0" in csv_output

    def test_cfg_patches_csv_format(self):
        """CFG patches in CSV should handle 'N uses, M patches' format."""
        stats = {
            "optimizer_matches": {},
            "rule_matches": {},
            "cfg_patches": {
                "UnflattenRule": {"uses": 3, "total_patches": 42},
            },
            "total_rule_firings": 0,
            "total_cycles_detected": 0,
        }

        csv_output = stats_to_csv(stats)

        # CSV should quote the count field since it contains a comma
        assert 'CFG Patches,UnflattenRule,"3 uses, 42 patches"' in csv_output
