"""Persist inference deltas to project JSON config.

This module implements the "persist" user action: promoting ephemeral
inference deltas into durable project JSON configuration.  After
persistence, the deltas are user-owned (highest precedence) and can
be edited directly in the JSON file.

The persist action writes to two existing config mechanisms:

- ``suppress`` deltas -> ``blacklisted_functions`` on the target rule
- ``activate`` deltas -> ``whitelisted_functions`` on the target rule
- ``override`` deltas -> ``per_function_overrides`` on the target rule

See ``docs/plans/2026-03-09-rule-inference-layer-design.md`` for
design rationale (section D4).
"""
from __future__ import annotations

import json
from pathlib import Path

from d810.core.logging import getLogger
from d810.core.rule_scope import RuleDelta

logger = getLogger("D810.recon.persist_inference")


def persist_inference(
    *,
    func_ea: int,
    deltas: list[RuleDelta],
    config_path: Path,
) -> int:
    """Persist inference deltas into project JSON config.

    Reads the config file, applies each delta idempotently, and writes
    the result back with ``indent=2``.

    Args:
        func_ea: Function address to scope the deltas to.
        deltas: List of ``RuleDelta`` to persist.
        config_path: Path to the project JSON config file.

    Returns:
        Number of deltas actually persisted (excludes duplicates and
        unknown rules).
    """
    config = json.loads(config_path.read_text())
    ea_str = "0x%x" % func_ea
    persisted = 0

    # Build rule name -> config entry map across all rule categories
    rule_map: dict[str, dict] = {}
    for key in ("ins_rules", "blk_rules"):
        for rule_entry in config.get(key, []):
            rule_map[rule_entry["name"]] = rule_entry

    for delta in deltas:
        entry = rule_map.get(delta.rule_name)
        if entry is None:
            logger.warning(
                "persist_inference: rule %r not found in config, skipping delta",
                delta.rule_name,
            )
            continue

        cfg = entry.setdefault("config", {})

        if delta.action == "suppress":
            bl = cfg.setdefault("blacklisted_functions", [])
            if ea_str not in bl:
                bl.append(ea_str)
                persisted += 1

        elif delta.action == "activate":
            wl = cfg.setdefault("whitelisted_functions", [])
            if ea_str not in wl:
                wl.append(ea_str)
                persisted += 1

        elif delta.action == "override":
            pfo = cfg.setdefault("per_function_overrides", {})
            func_overrides = pfo.setdefault(ea_str, {})
            func_overrides.update(delta.overrides)
            persisted += 1

    config_path.write_text(json.dumps(config, indent=2) + "\n")
    logger.info(
        "persist_inference: persisted %d delta(s) for func=0x%x to %s",
        persisted, func_ea, config_path,
    )
    return persisted
