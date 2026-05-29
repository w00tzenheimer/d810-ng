"""Structural tests for the recurrence capability Protocols (LS8 S4).

Pure-Python, no IDA. The layer constraint (no capabilities->analyses upward
edge) is proven by lint-imports; here we check structural conformance.
"""
from __future__ import annotations

from d810.capabilities import ExternalRecurrenceCapability as ExternalReexport
from d810.capabilities import RecurrenceAnalysis as ReanalysisReexport
from d810.capabilities.recurrence import (
    ExternalRecurrenceCapability,
    RecurrenceAnalysis,
)


class _GoodAnalysis:
    def recurrence_for(self, value, loop):
        return None

    def step_expression(self, recurrence):
        return None


class _MissingMethod:
    def recurrence_for(self, value, loop):
        return None


class _GoodExternal:
    def lift_recurrence(self, value, region):
        return None


def test_runtime_checkable_conformance() -> None:
    assert isinstance(_GoodAnalysis(), RecurrenceAnalysis)
    assert isinstance(_GoodExternal(), ExternalRecurrenceCapability)


def test_missing_method_fails_conformance() -> None:
    assert not isinstance(_MissingMethod(), RecurrenceAnalysis)


def test_protocols_are_reexported_from_package() -> None:
    assert ReanalysisReexport is RecurrenceAnalysis
    assert ExternalReexport is ExternalRecurrenceCapability
