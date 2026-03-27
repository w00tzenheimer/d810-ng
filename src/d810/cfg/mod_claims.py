"""Helpers for tracking which virtual edits already claim CFG blocks/targets."""

from __future__ import annotations


def collect_mod_claims(
    modifications: list,
) -> tuple[set[int], set[int]]:
    """Return ``(claimed_sources, claimed_targets)`` for planned modifications."""
    claimed_sources: set[int] = set()
    claimed_targets: set[int] = set()
    for mod in modifications:
        if hasattr(mod, "new_target"):
            claimed_targets.add(int(mod.new_target))
        if hasattr(mod, "goto_target"):
            claimed_targets.add(int(mod.goto_target))
        if hasattr(mod, "conditional_target"):
            claimed_targets.add(int(mod.conditional_target))
        if hasattr(mod, "fallthrough_target"):
            claimed_targets.add(int(mod.fallthrough_target))
        if hasattr(mod, "per_pred_targets"):
            for pred_serial, target_serial in mod.per_pred_targets:
                claimed_sources.add(int(pred_serial))
                claimed_targets.add(int(target_serial))
        if hasattr(mod, "from_serial"):
            claimed_sources.add(int(mod.from_serial))
        if hasattr(mod, "source_serial"):
            claimed_sources.add(int(mod.source_serial))
        if hasattr(mod, "source_block"):
            claimed_sources.add(int(mod.source_block))
        if hasattr(mod, "src_block"):
            claimed_sources.add(int(mod.src_block))
        if hasattr(mod, "block_serial"):
            claimed_sources.add(int(mod.block_serial))
    return claimed_sources, claimed_targets


__all__ = ["collect_mod_claims"]
