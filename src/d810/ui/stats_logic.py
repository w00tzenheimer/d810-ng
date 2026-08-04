"""Pure logic for deobfuscation statistics panel and rule management.

This module provides the business logic for the stats panel, separated from
IDA/Qt dependencies to enable unit testing.

All functions in this module can be imported and tested without IDA Pro.
"""

from __future__ import annotations

def get_fired_rule_names(stats: dict | None) -> list[str]:
    """Extract the names of all rules that fired from the stats dict.

    Collects from optimizer_matches, rule_matches, and cfg_patches keys.
    Returns sorted list of unique rule names.

    Args:
        stats: Statistics dict from get_deobfuscation_stats(), or None

    Returns:
        Sorted list of unique rule names that have non-zero counts
    """
    fired_rules: set[str] = set()

    if not stats:
        return []

    # Collect from optimizer_matches
    optimizer_matches = stats.get("optimizer_matches", {})
    for rule_name, count in optimizer_matches.items():
        if count > 0:
            fired_rules.add(rule_name)

    # Collect from rule_matches
    rule_matches = stats.get("rule_matches", {})
    for rule_name, count in rule_matches.items():
        if count > 0:
            fired_rules.add(rule_name)

    # Collect from cfg_patches (different structure: {name: {"uses": N, "total_patches": M}})
    cfg_patches = stats.get("cfg_patches", {})
    for rule_name, patch_info in cfg_patches.items():
        if isinstance(patch_info, dict) and patch_info.get("uses", 0) > 0:
            fired_rules.add(rule_name)

    return sorted(fired_rules)
