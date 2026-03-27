"""Generic lowering-shape selection for shared feeder transitions.

This module lives in :mod:`d810.cfg` because it chooses between *virtual*
graph-edit shapes before any Hex-Rays lowering occurs.

The current first slice handles the shared 1-way feeder case:

- block-scope goto redirect
- predecessor-scoped clone

The selector is intentionally generic and consumes only projected CFG facts
plus corridor ownership hints.  Callers in Hodur provide those facts from
``d810.recon`` outputs.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.lowering_scope import derive_edge_predecessor, requires_pred_scoped_lowering


class SharedFeederLoweringKind:
    """Labels for shared-feeder lowering decisions."""

    BLOCK_GOTO = "block_goto"
    PRED_EDGE_PEEL = "pred_edge_peel"
    PRED_SCOPED_CLONE = "pred_scoped_clone"


@dataclass(frozen=True, slots=True)
class SharedFeederLoweringDecision:
    """Decision returned by :func:`select_shared_feeder_lowering`."""

    kind: str
    via_pred: int | None = None
    reason: str = ""


def target_reaches_source_ignoring_blocks(
    flow_graph: object,
    *,
    target_entry: int,
    source_block: int,
    ignored_blocks: set[int],
    limit: int = 256,
) -> bool:
    """Return True if ``target_entry`` can reach ``source_block``.

    Used to reject lowering shapes that would immediately introduce a cycle
    when redirecting to ``target_entry``.
    """
    if target_entry == source_block:
        return True
    worklist: list[int] = [target_entry]
    seen: set[int] = set()
    while worklist and len(seen) < limit:
        current = worklist.pop()
        if current in seen:
            continue
        seen.add(current)
        if current == source_block:
            return True
        try:
            succs = tuple(flow_graph.successors(current))
        except Exception:
            block = flow_graph.get_block(current)
            succs = tuple(getattr(block, "succs", ())) if block is not None else ()
        for succ in succs:
            succ = int(succ)
            if succ in ignored_blocks or succ in seen:
                continue
            worklist.append(succ)
    return False


def can_peel_predecessor_edge(
    *,
    via_pred: int | None,
    via_pred_succs: tuple[int, ...],
    source_block: int,
    target_entry: int,
    dispatcher_serial: int,
    bst_node_blocks: set[int],
    target_reaches_pred: bool,
) -> bool:
    """Return True when a predecessor edge can be peeled instead of cloning."""
    if via_pred is None:
        return False
    if len(via_pred_succs) != 2:
        return False
    if source_block not in via_pred_succs:
        return False
    if target_entry in {dispatcher_serial, source_block, via_pred}:
        return False
    if target_entry in bst_node_blocks:
        return False
    other_succs = {int(succ) for succ in via_pred_succs if int(succ) != source_block}
    if target_entry in other_succs:
        return False
    if target_reaches_pred:
        return False
    return True


def select_shared_feeder_lowering(
    *,
    source_serial: int,
    source_pred_count: int,
    ordered_path: tuple[int, ...] | list[int] | None,
    via_pred_succs: tuple[int, ...],
    target_entry: int,
    dispatcher_serial: int,
    bst_node_blocks: set[int],
    target_reaches_pred: bool,
) -> SharedFeederLoweringDecision:
    """Choose a lowering shape for a shared 1-way feeder redirect.

    Current behavior-preserving order:

    1. block-scope goto redirect when pred-scoping is unnecessary
    2. predecessor-scoped clone as the conservative fallback

    A predecessor-edge peel helper is extracted in this module, but the
    selector does not choose it by default on the refactor branch. That keeps
    shared-feeder lowering observationally aligned with the pre-extraction
    Hodur behavior for ``sub_7FFD`` while preserving the extracted seam for a
    future, separately-validated peel policy.
    """
    if not requires_pred_scoped_lowering(source_serial, source_pred_count, ordered_path):
        return SharedFeederLoweringDecision(
            kind=SharedFeederLoweringKind.BLOCK_GOTO,
            reason="source_not_shared",
        )

    via_pred = derive_edge_predecessor(ordered_path or ())
    return SharedFeederLoweringDecision(
        kind=SharedFeederLoweringKind.PRED_SCOPED_CLONE,
        via_pred=via_pred,
        reason="shared_source_requires_clone",
    )


__all__ = [
    "SharedFeederLoweringDecision",
    "SharedFeederLoweringKind",
    "can_peel_predecessor_edge",
    "select_shared_feeder_lowering",
    "target_reaches_source_ignoring_blocks",
]
