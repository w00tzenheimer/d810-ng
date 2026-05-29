"""Tests for LS8 S6 value-flow facts: strength_reduction / memory_access /
range_proof. Pure-Python, no IDA."""
from __future__ import annotations

import dataclasses

import pytest

from d810.analyses.value_flow.memory_access import AccessKind, MemoryAccessPattern
from d810.analyses.value_flow.range_proof import RangeCheck, RangeProof
from d810.analyses.value_flow.strength_reduction import StrengthReductionCandidate
from d810.ir.confidence import FactConfidence
from d810.ir.locations import StackSlot
from d810.ir.value_refs import SSAValueRef


def test_strength_reduction_candidate_constructs() -> None:
    cand = StrengthReductionCandidate(
        value=SSAValueRef(2), basis=SSAValueRef(1), multiplier=4
    )
    assert cand.multiplier == 4
    assert cand.confidence == 1.0


def test_strength_reduction_is_frozen() -> None:
    cand = StrengthReductionCandidate(SSAValueRef(2), SSAValueRef(1), 4)
    with pytest.raises(dataclasses.FrozenInstanceError):
        cand.multiplier = 8  # type: ignore[misc]


def test_memory_access_pattern_defaults_to_strided() -> None:
    pat = MemoryAccessPattern(base=StackSlot(0x20, 8), stride=8)
    assert pat.kind is AccessKind.STRIDED
    assert isinstance(pat.base, StackSlot) and pat.stride == 8


def test_access_kind_members() -> None:
    assert {k.name for k in AccessKind} == {
        "SCALAR",
        "SEQUENTIAL",
        "STRIDED",
        "INDIRECT",
    }


def test_range_check_open_sides_default_none() -> None:
    rc = RangeCheck(value=SSAValueRef(1))
    assert rc.lo is None and rc.hi is None


def test_range_proof_carries_bounds_and_confidence() -> None:
    proof = RangeProof(
        value=SSAValueRef(1), lo=0, hi=255, confidence=FactConfidence(0.8)
    )
    assert (proof.lo, proof.hi) == (0, 255)
    assert proof.confidence == 0.8


def test_range_proof_is_frozen() -> None:
    proof = RangeProof(value=SSAValueRef(1), lo=0, hi=10)
    with pytest.raises(dataclasses.FrozenInstanceError):
        proof.hi = 20  # type: ignore[misc]
