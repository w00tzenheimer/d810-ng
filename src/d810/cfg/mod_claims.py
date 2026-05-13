"""Helpers for tracking which virtual edits already claim CFG blocks/targets."""

from __future__ import annotations


def collect_mod_claims(
    modifications: list,
) -> tuple[set[int], set[int]]:
    """Return ``(claimed_sources, claimed_targets)`` for planned modifications."""
    claimed_sources: set[int] = set()
    claimed_targets: set[int] = set()
    for mod in modifications:
        new_target = getattr(mod, "new_target", None)
        if new_target is not None:
            claimed_targets.add(int(new_target))
        goto_target = getattr(mod, "goto_target", None)
        if goto_target is not None:
            claimed_targets.add(int(goto_target))
        conditional_target = getattr(mod, "conditional_target", None)
        if conditional_target is not None:
            claimed_targets.add(int(conditional_target))
        fallthrough_target = getattr(mod, "fallthrough_target", None)
        if fallthrough_target is not None:
            claimed_targets.add(int(fallthrough_target))
        if hasattr(mod, "per_pred_targets"):
            for pred_serial, target_serial in mod.per_pred_targets:
                claimed_sources.add(int(pred_serial))
                claimed_targets.add(int(target_serial))
        if hasattr(mod, "from_serial"):
            claimed_sources.add(int(mod.from_serial))
        pred_serial = getattr(mod, "pred_serial", None)
        if pred_serial is not None:
            claimed_sources.add(int(pred_serial))
        via_pred = getattr(mod, "via_pred", None)
        if via_pred is not None:
            claimed_sources.add(int(via_pred))
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
