"""Lowering-scope decision for family-owned transitions.

Pure-logic predicates that determine whether a 1-way feeder redirect
must use pred-scoped lowering (duplicate-and-redirect) vs whole-block
lowering (RedirectGoto).

These live in ``d810.cfg`` (not ``d810.optimizers``) so unit tests can
import them without violating the layered architecture contract.
"""
from __future__ import annotations


class LoweringScope:
    """Labels for the two lowering modes."""

    BLOCK = "block"
    PRED_SCOPED = "pred_scoped"


def requires_pred_scoped_lowering(
    source_serial: int,
    pred_count: int,
    ordered_path: tuple[int, ...] | list[int] | None,
) -> bool:
    """Decide whether a 1-way feeder redirect must use pred-scoped lowering.

    A whole-block ``RedirectGoto`` on a shared source block (npred > 1)
    merges all predecessor families into one target, silently collapsing
    distinct semantic paths. Pred-scoped lowering (duplicate-and-redirect)
    preserves family ownership by cloning the source block and redirecting
    only the owning predecessor.

    Args:
        source_serial: Serial of the 1-way source block being redirected.
        pred_count: Number of predecessors of the source block in the
            projected (post-prior-edits) flow graph.
        ordered_path: The DAG edge's ordered corridor path. Must be
            non-empty to identify which predecessor owns the transition.

    Returns:
        True if pred-scoped lowering is required, False if block-scope
        redirect is safe.
    """
    if pred_count <= 1:
        return False
    if not ordered_path:
        return False
    return True


def derive_edge_predecessor(
    ordered_path: tuple[int, ...] | list[int],
) -> int:
    """Extract the owning predecessor from an ordered DAG corridor path.

    The predecessor is the second-to-last block in the path (the block
    immediately before the source). If the path has only one entry, use
    that entry as both source and predecessor.

    Raises:
        ValueError: If ordered_path is empty.
    """
    if not ordered_path:
        raise ValueError("ordered_path must be non-empty")
    if len(ordered_path) >= 2:
        return int(ordered_path[-2])
    return int(ordered_path[-1])
