"""Tests for portable def-use facts (LS8 S3). Pure-Python, no IDA."""
from __future__ import annotations

import dataclasses

import pytest

from d810.analyses.value_flow.def_use import DefUseFacts
from d810.ir.value_refs import SSAValueRef


def test_empty_def_use_has_no_uses() -> None:
    du = DefUseFacts()
    assert du.uses_of(SSAValueRef(1)) == ()
    assert du.has_uses(SSAValueRef(1)) is False


def test_uses_of_returns_recorded_uses() -> None:
    d, u1, u2 = SSAValueRef(1), SSAValueRef(2), SSAValueRef(3)
    du = DefUseFacts(uses_by_def={d: (u1, u2)})
    assert du.uses_of(d) == (u1, u2)
    assert du.has_uses(d) is True


def test_uses_of_unknown_def_is_empty() -> None:
    du = DefUseFacts(uses_by_def={SSAValueRef(1): (SSAValueRef(2),)})
    assert du.uses_of(SSAValueRef(99)) == ()


def test_facts_are_frozen() -> None:
    du = DefUseFacts()
    with pytest.raises(dataclasses.FrozenInstanceError):
        du.uses_by_def = {}  # type: ignore[misc]


def test_default_mapping_is_independent_per_instance() -> None:
    a, b = DefUseFacts(), DefUseFacts()
    assert a.uses_by_def is not b.uses_by_def
