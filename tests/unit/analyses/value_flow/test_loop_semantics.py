"""Tests for the unwired loop-semantics classifier (LS8 S7). Pure-Python, no IDA."""
from __future__ import annotations

from d810.analyses.value_flow.loop_semantics import (
    LoopSemanticsClassification,
    LoopSemanticsClassifier,
    LoopSemanticsKind,
)


def test_no_evidence_is_unknown() -> None:
    result = LoopSemanticsClassifier().classify()
    assert result.kind is LoopSemanticsKind.UNKNOWN


def test_induction_only_is_counted() -> None:
    result = LoopSemanticsClassifier().classify(has_induction=True)
    assert result.kind is LoopSemanticsKind.COUNTED
    assert "induction" in result.evidence


def test_induction_plus_strided_is_memory_copy() -> None:
    result = LoopSemanticsClassifier().classify(
        has_induction=True, has_strided_access=True
    )
    assert result.kind is LoopSemanticsKind.MEMORY_COPY


def test_strided_only_is_memory_fill() -> None:
    result = LoopSemanticsClassifier().classify(has_strided_access=True)
    assert result.kind is LoopSemanticsKind.MEMORY_FILL


def test_reduction_takes_priority() -> None:
    result = LoopSemanticsClassifier().classify(
        has_induction=True, has_strided_access=True, has_reduction=True
    )
    assert result.kind is LoopSemanticsKind.REDUCTION


def test_classification_default_confidence() -> None:
    assert LoopSemanticsClassification(LoopSemanticsKind.UNKNOWN).confidence == 1.0
