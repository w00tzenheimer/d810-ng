"""Allocation evidence must not collect the entire heap on every callback."""

import pytest

from tests.system.helpers import callback_allocation_probe as probe_module


def test_only_two_windows_are_measured_while_all_callbacks_execute(monkeypatch):
    calls = []
    monkeypatch.setattr(probe_module.gc, "collect", lambda: calls.append("collect"))
    monkeypatch.setattr(probe_module.tracemalloc, "start", lambda: calls.append("start"))
    monkeypatch.setattr(probe_module.tracemalloc, "stop", lambda: calls.append("stop"))
    values = iter(((10, 10), (20, 30), (40, 40), (55, 75)))
    monkeypatch.setattr(probe_module.tracemalloc, "get_traced_memory", lambda: next(values))
    probe = probe_module.BoundedAllocationProbe(limit=2)
    executed = []

    def callback(value):
        executed.append(value)
        return value + 1

    assert [probe.measure(callback, i) for i in range(633)] == list(range(1, 634))
    assert executed == list(range(633))
    assert calls == ["collect", "start", "collect", "stop"] * 2
    assert [sample.retained for sample in probe.samples] == [10, 15]
    assert [sample.peak for sample in probe.samples] == [30, 75]


def test_callback_exception_still_stops_tracing(monkeypatch):
    calls = []
    monkeypatch.setattr(probe_module.gc, "collect", lambda: None)
    monkeypatch.setattr(probe_module.tracemalloc, "start", lambda: calls.append("start"))
    monkeypatch.setattr(probe_module.tracemalloc, "stop", lambda: calls.append("stop"))
    monkeypatch.setattr(probe_module.tracemalloc, "get_traced_memory", lambda: (0, 0))
    probe = probe_module.BoundedAllocationProbe(limit=1)
    with pytest.raises(ValueError, match="callback"):
        probe.measure(lambda: (_ for _ in ()).throw(ValueError("callback")))
    assert calls == ["start", "stop"]
    assert len(probe.samples) == 1
