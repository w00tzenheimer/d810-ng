"""Utility metrics functions for the Hodur unflattening pipeline."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.executor import StageResult


def handler_coverage(resolved_count: int, total_handlers: int) -> float:
    """Fraction of handlers resolved by strategies.

    Args:
        resolved_count: Number of handlers resolved.
        total_handlers: Total number of handlers in the state machine.

    Returns:
        Fraction in [0.0, 1.0] representing resolved coverage.

    >>> handler_coverage(3, 10)
    0.3
    >>> handler_coverage(0, 0)
    0.0
    """
    if total_handlers == 0:
        return 0.0
    return resolved_count / total_handlers


def structure_quality_score(results: list) -> dict:
    """Summarize pipeline results.

    Args:
        results: List of :class:`~d810.optimizers.microcode.flow.flattening.hodur.executor.StageResult`
            objects from the executor pipeline.

    Returns:
        Dictionary with keys ``total_edits``, ``stages_succeeded``,
        ``stages_failed``, and ``final_reachability``.

    >>> structure_quality_score([])
    {'total_edits': 0, 'stages_succeeded': 0, 'stages_failed': 0, 'final_reachability': 0.0}
    """
    return {
        "total_edits": sum(r.edits_applied for r in results),
        "stages_succeeded": sum(1 for r in results if r.success),
        "stages_failed": sum(1 for r in results if not r.success),
        "final_reachability": results[-1].reachability_after if results else 0.0,
    }
