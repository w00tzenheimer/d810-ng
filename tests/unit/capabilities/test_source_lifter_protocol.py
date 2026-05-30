"""Tests for the SourceLifter capability Protocol + registry (LS10 COMMIT 1).

Pure-Python, no IDA. The no-capabilities->cfg upward edge is proven by
lint-imports; here we check Protocol conformance + registry behavior.
"""
from __future__ import annotations

import pytest

from d810.capabilities import (
    LiveLifter,
    SourceLifter,
    register_live_lifter,
    select_lifter,
)
from d810.capabilities.source_lifter import (
    registered_lifters,
    reset_live_lifters_for_tests,
)


class _Lifter:
    def __init__(self, *, handles: object) -> None:
        self._handles = handles
        self.lift_calls = 0

    def matches(self, source: object) -> bool:
        return source is self._handles

    def lift(self, source: object) -> object:
        self.lift_calls += 1
        return ("flow_graph_for", source)


@pytest.fixture(autouse=True)
def _isolate_registry():
    reset_live_lifters_for_tests()
    yield
    reset_live_lifters_for_tests()


def test_runtime_checkable_conformance() -> None:
    assert isinstance(_Lifter(handles=object()), SourceLifter)
    assert LiveLifter is SourceLifter


def test_missing_method_fails_conformance() -> None:
    class _NoLift:
        def matches(self, source: object) -> bool:
            return True

    assert not isinstance(_NoLift(), SourceLifter)


def test_select_returns_none_when_empty() -> None:
    assert select_lifter(object()) is None


def test_register_then_select_matches_source() -> None:
    src = object()
    lifter = _Lifter(handles=src)
    register_live_lifter(lifter)
    assert select_lifter(src) is lifter
    assert select_lifter(object()) is None  # different source, no match


def test_first_matching_lifter_wins() -> None:
    shared = object()
    first, second = _Lifter(handles=shared), _Lifter(handles=shared)
    register_live_lifter(first)
    register_live_lifter(second)
    assert select_lifter(shared) is first


def test_register_is_idempotent() -> None:
    lifter = _Lifter(handles=object())
    register_live_lifter(lifter)
    register_live_lifter(lifter)
    assert registered_lifters() == (lifter,)


def test_reset_clears_registry() -> None:
    register_live_lifter(_Lifter(handles=object()))
    reset_live_lifters_for_tests()
    assert registered_lifters() == ()
