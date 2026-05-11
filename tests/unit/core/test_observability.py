"""Unit tests for ``d810.core.observability`` (event bus + SnapshotRef)."""
from __future__ import annotations

import dataclasses

import pytest

from d810.core.observability import (
    SnapshotRef,
    emit,
    has_subscribers,
    new_snapshot_key,
    reset_diagnostic_bus,
    subscribe,
    unsubscribe,
)


@dataclasses.dataclass(frozen=True)
class _SampleEvent:
    value: int


@dataclasses.dataclass(frozen=True)
class _OtherEvent:
    text: str


@pytest.fixture(autouse=True)
def _reset_bus() -> None:
    reset_diagnostic_bus()
    yield
    reset_diagnostic_bus()


def test_emit_with_no_subscribers_is_a_noop():
    emit(_SampleEvent(value=42))


def test_subscriber_receives_event_of_its_type():
    seen: list[_SampleEvent] = []
    subscribe(_SampleEvent, seen.append)
    emit(_SampleEvent(value=7))
    assert seen == [_SampleEvent(value=7)]


def test_subscriber_does_not_receive_other_event_types():
    seen: list[_SampleEvent] = []
    subscribe(_SampleEvent, seen.append)
    emit(_OtherEvent(text="ignored"))
    assert seen == []


def test_multiple_subscribers_all_fire_in_insertion_order():
    order: list[str] = []
    subscribe(_SampleEvent, lambda _: order.append("A"))
    subscribe(_SampleEvent, lambda _: order.append("B"))
    subscribe(_SampleEvent, lambda _: order.append("C"))
    emit(_SampleEvent(value=1))
    assert order == ["A", "B", "C"]


def test_subscriber_raising_is_swallowed_and_does_not_block_others(caplog):
    bad_calls: list[int] = []
    good_calls: list[int] = []

    def bad(_ev: _SampleEvent) -> None:
        bad_calls.append(1)
        raise RuntimeError("boom")

    def good(ev: _SampleEvent) -> None:
        good_calls.append(ev.value)

    subscribe(_SampleEvent, bad)
    subscribe(_SampleEvent, good)

    # Must not raise.
    emit(_SampleEvent(value=99))

    assert bad_calls == [1]
    assert good_calls == [99]


def test_unsubscribe_removes_one_handler():
    seen: list[_SampleEvent] = []
    subscribe(_SampleEvent, seen.append)
    subscribe(_SampleEvent, seen.append)  # registered twice

    unsubscribe(_SampleEvent, seen.append)
    emit(_SampleEvent(value=1))
    # One remaining subscriber → one append.
    assert len(seen) == 1


def test_unsubscribe_unknown_handler_is_noop():
    def handler(_ev: _SampleEvent) -> None:
        pass

    # Never subscribed → no exception.
    unsubscribe(_SampleEvent, handler)


def test_reset_clears_all_subscribers_across_types():
    subscribe(_SampleEvent, lambda _: None)
    subscribe(_OtherEvent, lambda _: None)
    assert has_subscribers(_SampleEvent)
    assert has_subscribers(_OtherEvent)
    reset_diagnostic_bus()
    assert not has_subscribers(_SampleEvent)
    assert not has_subscribers(_OtherEvent)


def test_has_subscribers_reports_accurately():
    assert not has_subscribers(_SampleEvent)
    subscribe(_SampleEvent, lambda _: None)
    assert has_subscribers(_SampleEvent)
    assert not has_subscribers(_OtherEvent)


def test_new_snapshot_key_is_unique():
    keys = {new_snapshot_key() for _ in range(100)}
    assert len(keys) == 100


def test_new_snapshot_key_returns_hex_string():
    key = new_snapshot_key()
    assert isinstance(key, str)
    assert len(key) >= 16
    # uuid4 hex contains only [0-9a-f]
    assert all(c in "0123456789abcdef" for c in key)


def test_snapshot_ref_is_hashable_and_immutable():
    ref = SnapshotRef(
        key="abc",
        func_ea=0x401000,
        label="MMAT_GLBOPT1_pre_d810",
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
    )
    assert hash(ref) == hash(ref)
    with pytest.raises(dataclasses.FrozenInstanceError):
        ref.key = "different"  # type: ignore[misc]


def test_snapshot_ref_equality_by_value():
    a = SnapshotRef(key="k", func_ea=1, label="L", maturity="M", phase="p")
    b = SnapshotRef(key="k", func_ea=1, label="L", maturity="M", phase="p")
    c = SnapshotRef(key="different", func_ea=1, label="L", maturity="M", phase="p")
    assert a == b
    assert a != c
