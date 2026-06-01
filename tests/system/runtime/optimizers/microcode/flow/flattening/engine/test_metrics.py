from __future__ import annotations

import pytest

from d810.passes.metrics import (
    handler_coverage,
    structure_quality_score,
)
from d810.transforms.plan_fragment import StageResult


def test_handler_coverage_handles_zero_total() -> None:
    assert handler_coverage(0, 0) == pytest.approx(0.0)


def test_handler_coverage_computes_fraction() -> None:
    assert handler_coverage(3, 10) == pytest.approx(0.3)


def test_structure_quality_score_summarizes_stage_results() -> None:
    results = [
        StageResult(
            strategy_name="s1",
            edits_applied=2,
            success=True,
            reachability_after=0.9,
        ),
        StageResult(
            strategy_name="s2",
            edits_applied=1,
            success=False,
            reachability_after=0.8,
        ),
    ]

    assert structure_quality_score(results) == {
        "total_edits": 3,
        "stages_succeeded": 1,
        "stages_failed": 1,
        "final_reachability": 0.8,
    }
