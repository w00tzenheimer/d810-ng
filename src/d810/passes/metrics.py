"""Utility metrics functions for the shared unflattening engine."""
from __future__ import annotations

from d810.core.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from d810.transforms.plan_fragment import StageResult

__all__ = ["handler_coverage", "structure_quality_score"]


def handler_coverage(resolved_count: int, total_handlers: int) -> float:
    """Fraction of handlers resolved by strategies."""
    if total_handlers == 0:
        return 0.0
    return resolved_count / total_handlers


def structure_quality_score(results: list[StageResult]) -> dict[str, int | float]:
    """Summarize pipeline results."""
    return {
        "total_edits": sum(r.edits_applied for r in results),
        "stages_succeeded": sum(1 for r in results if r.success),
        "stages_failed": sum(1 for r in results if not r.success),
        "final_reachability": results[-1].reachability_after if results else 0.0,
    }
