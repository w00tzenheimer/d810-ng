"""Unit tests for TransactionalExecutor pure-Python components.

TransactionalExecutor itself requires IDA types; only StageResult and
VerificationGate are tested here.
"""
from __future__ import annotations

import pytest

from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    StageResult,
    VerificationGate,
)


# ---------------------------------------------------------------------------
# StageResult
# ---------------------------------------------------------------------------


class TestStageResult:
    def test_default_values(self) -> None:
        result = StageResult(strategy_name="my_strategy")
        assert result.strategy_name == "my_strategy"
        assert result.edits_applied == 0
        assert result.reachability_after == pytest.approx(1.0)
        assert result.conflict_count_after == 0
        assert result.success is True
        assert result.rollback_needed is False
        assert result.error is None

    def test_custom_values(self) -> None:
        result = StageResult(
            strategy_name="test_stage",
            edits_applied=5,
            reachability_after=0.85,
            conflict_count_after=3,
            success=False,
            rollback_needed=True,
            error="something went wrong",
        )
        assert result.edits_applied == 5
        assert result.reachability_after == pytest.approx(0.85)
        assert result.conflict_count_after == 3
        assert result.success is False
        assert result.rollback_needed is True
        assert result.error == "something went wrong"

    def test_strategy_name_preserved(self) -> None:
        result = StageResult(strategy_name="direct_linearize")
        assert result.strategy_name == "direct_linearize"

    def test_mutable_fields(self) -> None:
        result = StageResult(strategy_name="s")
        result.edits_applied = 42
        result.success = False
        assert result.edits_applied == 42
        assert result.success is False


# ---------------------------------------------------------------------------
# VerificationGate
# ---------------------------------------------------------------------------


class TestVerificationGate:
    def test_default_thresholds(self) -> None:
        gate = VerificationGate()
        assert gate.min_reachability == pytest.approx(0.7)
        assert gate.max_conflict_count == 10

    def test_passes_when_above_thresholds(self) -> None:
        gate = VerificationGate(min_reachability=0.7, max_conflict_count=10)
        result = StageResult(
            strategy_name="ok",
            reachability_after=0.9,
            conflict_count_after=5,
        )
        assert gate.check(result) is True

    def test_passes_at_exact_thresholds(self) -> None:
        gate = VerificationGate(min_reachability=0.7, max_conflict_count=10)
        result = StageResult(
            strategy_name="boundary",
            reachability_after=0.7,
            conflict_count_after=10,
        )
        assert gate.check(result) is True

    def test_fails_when_reachability_below_minimum(self) -> None:
        gate = VerificationGate(min_reachability=0.7, max_conflict_count=10)
        result = StageResult(
            strategy_name="bad_reach",
            reachability_after=0.5,
            conflict_count_after=0,
        )
        assert gate.check(result) is False

    def test_fails_when_conflict_count_exceeds_maximum(self) -> None:
        gate = VerificationGate(min_reachability=0.7, max_conflict_count=10)
        result = StageResult(
            strategy_name="conflict_heavy",
            reachability_after=0.95,
            conflict_count_after=11,
        )
        assert gate.check(result) is False

    def test_fails_both_conditions(self) -> None:
        gate = VerificationGate(min_reachability=0.7, max_conflict_count=10)
        result = StageResult(
            strategy_name="both_bad",
            reachability_after=0.3,
            conflict_count_after=20,
        )
        assert gate.check(result) is False

    def test_custom_thresholds(self) -> None:
        gate = VerificationGate(min_reachability=0.5, max_conflict_count=5)
        good = StageResult(
            strategy_name="good",
            reachability_after=0.6,
            conflict_count_after=3,
        )
        bad = StageResult(
            strategy_name="bad",
            reachability_after=0.4,
            conflict_count_after=3,
        )
        assert gate.check(good) is True
        assert gate.check(bad) is False

    def test_zero_reachability_fails(self) -> None:
        gate = VerificationGate()
        result = StageResult(strategy_name="dead", reachability_after=0.0)
        assert gate.check(result) is False

    def test_full_reachability_passes(self) -> None:
        gate = VerificationGate()
        result = StageResult(strategy_name="perfect", reachability_after=1.0)
        assert gate.check(result) is True
