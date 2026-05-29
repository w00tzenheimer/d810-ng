"""Tests for portable recurrence facts (LS8 S4). Pure-Python, no IDA."""
from __future__ import annotations

import dataclasses

import pytest

from d810.analyses.control_flow.loops import LoopRef
from d810.analyses.value_flow.recurrence import (
    AddRecurrence,
    RecurrenceCandidate,
    RecurrenceExpr,
)
from d810.ir.confidence import FactConfidence
from d810.ir.expressions import Const, Move
from d810.ir.handles import InsnHandle
from d810.ir.value_refs import SSAValueRef


def _add_rec() -> AddRecurrence:
    iv = SSAValueRef(value_id=1)
    return AddRecurrence(
        loop=LoopRef(header=2),
        base=Move(source=iv),
        step=Const(value=1),
        update=InsnHandle(0x1800134A5),
        evidence=(InsnHandle(0x1800134A5),),
    )


def test_add_recurrence_constructs() -> None:
    rec = _add_rec()
    assert rec.loop.header == 2
    assert isinstance(rec.step, Const) and rec.step.value == 1
    assert rec.update == 0x1800134A5
    assert rec.evidence == (0x1800134A5,)


def test_recurrence_expr_umbrella_aliases_add_recurrence() -> None:
    assert RecurrenceExpr is AddRecurrence


def test_recurrence_candidate_carries_confidence() -> None:
    cand = RecurrenceCandidate(
        value=SSAValueRef(1), recurrence=_add_rec(), confidence=FactConfidence(0.9)
    )
    assert cand.confidence == 0.9
    assert isinstance(cand.recurrence, AddRecurrence)


def test_recurrence_default_evidence_empty() -> None:
    rec = AddRecurrence(
        loop=LoopRef(0), base=Const(0), step=Const(1), update=InsnHandle(0)
    )
    assert rec.evidence == ()


def test_frozen() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        _add_rec().step = Const(2)  # type: ignore[misc]
