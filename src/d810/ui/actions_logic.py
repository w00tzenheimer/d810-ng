"""Pure logic for pseudocode context menu actions.

This module contains the business logic for d810-ng pseudocode actions,
separated from IDA/Qt dependencies to enable unit testing.

All functions in this module can be imported and tested without IDA Pro.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from d810.manager import D810Manager, D810State


def check_plugin_state(state: "D810State | None") -> tuple[bool, str]:
    """Check if d810-ng plugin is ready to process deobfuscation.

    Args:
        state: The D810State instance, or None if not loaded

    Returns:
        Tuple of (is_ready, error_message). If is_ready is True, error_message
        will be empty. If False, error_message explains why.
    """
    if state is None:
        return False, "d810-ng is not loaded. Please load the plugin first."

    if not state.is_loaded():
        return False, "d810-ng is not loaded. Please load the plugin first."

    if hasattr(state, 'manager') and state.manager is not None:
        if not state.manager.started:
            return False, "d810-ng is not started. Use Edit > d810-ng to start."

    return True, ""


def get_deobfuscation_stats(manager: "D810Manager") -> dict[str, Any]:
    """Collect deobfuscation statistics from the manager.

    This function aggregates stats from:
    - Instruction optimizer usage counts
    - Individual instruction rule match counts
    - Block/CFG rule patch counts
    - Total rule firings
    - Cycle detection counts

    Args:
        manager: The D810Manager instance with accumulated stats

    Returns:
        Dictionary with formatted statistics suitable for display
    """
    if not hasattr(manager, 'stats') or manager.stats is None:
        return {
            "optimizer_matches": {},
            "rule_matches": {},
            "cfg_patches": {},
            "total_rule_firings": 0,
            "total_cycles_detected": 0,
        }

    # Get the last reported stats (preserved across reset())
    # This ensures we show stats from the last completed deobfuscation
    summary = manager.stats.last_report()

    # If no report has been generated yet, fall back to empty stats
    if not summary:
        return {
            "optimizer_matches": {},
            "rule_matches": {},
            "cfg_patches": {},
            "total_rule_firings": 0,
            "total_cycles_detected": 0,
        }

    # The last_report() method already returns a properly formatted dict,
    # but let's verify all expected keys are present
    return {
        "optimizer_matches": summary.get("optimizer_matches", {}),
        "rule_matches": summary.get("rule_matches", {}),
        "cfg_patches": summary.get("cfg_patches", {}),
        "total_rule_firings": summary.get("total_rule_firings", 0),
        "total_cycles_detected": summary.get("total_cycles_detected", 0),
    }


def stats_to_table_rows(stats: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Convert statistics dict to table rows for QTableWidget display.

    This is a pure Python function that converts the stats dictionary into
    a list of (category, name, count_str) tuples suitable for display in
    a table widget. Every row includes the category for proper sorting/grouping.

    Args:
        stats: Statistics dict from get_deobfuscation_stats()

    Returns:
        List of (category, name, count_str) tuples for table rows
    """
    rows: list[tuple[str, str, str]] = []

    # Optimizers section
    opt_matches = stats.get("optimizer_matches", {})
    for name in sorted(opt_matches.keys()):
        count = opt_matches[name]
        rows.append(("Optimizers", name, str(count)))

    # Rules section
    rule_matches = stats.get("rule_matches", {})
    for name in sorted(rule_matches.keys()):
        count = rule_matches[name]
        rows.append(("Rules", name, str(count)))

    # CFG Patches section
    cfg_patches = stats.get("cfg_patches", {})
    for name in sorted(cfg_patches.keys()):
        info = cfg_patches[name]
        uses = info.get("uses", 0)
        total = info.get("total_patches", 0)
        rows.append(("CFG Patches", name, f"{uses} uses, {total} patches"))

    # Cycles section (only if any detected)
    cycles_detected = stats.get("cycles_detected", {})
    for name in sorted(cycles_detected.keys()):
        count = cycles_detected[name]
        rows.append(("Cycles", name, str(count)))

    # Total section
    total_firings = stats.get("total_rule_firings", 0)
    rows.append(("Total", "Rule Firings", str(total_firings)))
    total_cycles = stats.get("total_cycles_detected", 0)
    rows.append(("Total", "Cycles Broken", str(total_cycles)))

    return rows


def stats_to_csv(
    stats: dict[str, Any],
    func_ea: int | None = None,
    func_name: str | None = None,
) -> str:
    """Convert statistics dict to CSV format.

    Args:
        stats: Statistics dict from get_deobfuscation_stats()
        func_ea: Optional function EA to include in the header
        func_name: Optional function name to include in the header

    Returns:
        CSV-formatted string with statistics
    """
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)

    # Header comment with function info
    if func_ea is not None or func_name is not None:
        if func_name and func_ea is not None:
            output.write(f"# Function: {func_name} ({func_ea:#x})\n")
        elif func_name:
            output.write(f"# Function: {func_name}\n")
        elif func_ea is not None:
            output.write(f"# Function: {func_ea:#x}\n")

    # CSV header
    writer.writerow(["Category", "Name", "Count"])

    # Data rows
    rows = stats_to_table_rows(stats)
    for category, name, count_str in rows:
        writer.writerow([category, name, count_str])

    return output.getvalue()


def format_stats_for_display(
    stats: dict[str, Any],
    func_ea: int | None = None,
    func_name: str | None = None,
) -> str:
    """Format statistics dictionary into a human-readable string.

    This function is kept for logging purposes. For UI display, use
    stats_to_table_rows() or the DeobfuscationStatsDialog.

    Args:
        stats: Statistics dict from get_deobfuscation_stats()
        func_ea: Optional function EA to include in the header
        func_name: Optional function name to include in the header

    Returns:
        Multi-line formatted string suitable for display in a dialog
    """
    lines: list[str] = ["=== d810-ng Deobfuscation Statistics ===\n"]

    # Add function info if provided
    if func_ea is not None or func_name is not None:
        if func_name and func_ea is not None:
            lines.append(f"Function: {func_name} ({func_ea:#x})\n")
        elif func_name:
            lines.append(f"Function: {func_name}\n")
        elif func_ea is not None:
            lines.append(f"Function: {func_ea:#x}\n")

    opt_matches = stats.get("optimizer_matches", {})
    if opt_matches:
        lines.append("Optimizer matches:")
        for name, count in sorted(opt_matches.items()):
            lines.append(f"  {name}: {count}")
        lines.append("")

    rule_matches = stats.get("rule_matches", {})
    if rule_matches:
        lines.append("Rule matches:")
        for name, count in sorted(rule_matches.items()):
            lines.append(f"  {name}: {count}")
        lines.append("")

    cfg_patches = stats.get("cfg_patches", {})
    if cfg_patches:
        lines.append("CFG rule patches:")
        for name, info in sorted(cfg_patches.items()):
            lines.append(f"  {name}: {info['uses']} uses, {info['total_patches']} patches")
        lines.append("")

    total = stats.get("total_rule_firings", 0)
    cycles = stats.get("total_cycles_detected", 0)
    lines.append(f"Total rule firings: {total}")
    lines.append(f"Cycles detected and broken: {cycles}")

    return "\n".join(lines)
