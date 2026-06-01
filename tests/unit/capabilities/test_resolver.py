"""Portable tests for the CapabilitySet resolver + context field (no IDA)."""
from __future__ import annotations

import dataclasses

import pytest

from d810.capabilities import (
    CapabilityNotProvided,
    CapabilitySet,
    ValRangeCapability,
)


def test_optional_returns_none_when_absent():
    assert CapabilitySet().optional(ValRangeCapability) is None


def test_require_raises_when_absent():
    with pytest.raises(CapabilityNotProvided):
        CapabilitySet().require(ValRangeCapability)


def test_register_and_resolve():
    sentinel = object()
    caps = CapabilitySet({ValRangeCapability: sentinel})
    assert caps.optional(ValRangeCapability) is sentinel
    assert caps.require(ValRangeCapability) is sentinel
    assert ValRangeCapability in caps


def test_with_capability_is_immutable():
    base = CapabilitySet()
    extended = base.with_capability(ValRangeCapability, object())
    assert ValRangeCapability not in base
    assert ValRangeCapability in extended


def test_context_carries_capabilities_field():
    from d810.passes.pass_pipeline import FunctionPipelineContext

    names = {f.name for f in dataclasses.fields(FunctionPipelineContext)}
    assert "capabilities" in names
