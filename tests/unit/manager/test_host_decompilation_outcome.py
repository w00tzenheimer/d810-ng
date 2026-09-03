"""Lifecycle ownership tests for host decompilation outcomes."""

from __future__ import annotations

import pytest

from d810.core.decompilation_session import DecompilationEvent
from d810.core.observability_events import (
    HostDecompilationOutcome,
    HostDecompilationOutcomeKind,
    HostDecompilationOutcomeObserved,
)
from d810.core.observability_unflat import (
    note_committed_batch,
    note_unflat_counters,
    reset_unflat_counters,
    unflat_counters,
)
from d810.manager.decompilation_lifecycle import DecompilationLifecycleCoordinator
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key()


@pytest.fixture(autouse=True)
def _clean_unflat_counters():
    """Isolate the unflatten counters process-global across every test here.

    ``d810.core.observability_unflat._COUNTERS`` is process-global; without
    this, a counters test could leak into an unrelated session test (or vice
    versa) sharing the same ``0x401000`` func_ea.
    """
    reset_unflat_counters()
    yield
    reset_unflat_counters()


class _Emitter:
    def __init__(self) -> None:
        self.events: list[object] = []

    def emit(self, event, payload) -> None:
        self.events.append((event, payload))


def _coordinator(emitter: _Emitter) -> DecompilationLifecycleCoordinator:
    return DecompilationLifecycleCoordinator(
        preanalysis_runtime=None,
        analysis_runtime=None,
        execution_scope_service=None,
        native_preanalysis_key_provider=lambda _function_ea: NATIVE_KEY,
        event_emitter=emitter,
    )


def _host_events(observed: list[object]) -> list[HostDecompilationOutcomeObserved]:
    return [event for event in observed if isinstance(event, HostDecompilationOutcomeObserved)]


def test_structural_completion_keeps_session_active_without_finish(monkeypatch) -> None:
    observed: list[object] = []
    monkeypatch.setattr(
        "d810.manager.decompilation_lifecycle.emit_diagnostic", observed.append
    )
    emitter = _Emitter()
    coordinator = _coordinator(emitter)
    session, _ = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )

    coordinator.mark_structural_complete()

    assert session.structural_complete is True
    assert coordinator.current_session(0x401000) is session
    assert not [event for event, _payload in emitter.events if event is DecompilationEvent.SESSION_FINISHED]
    assert not _host_events(observed)


def test_rendered_host_output_finishes_matching_owner_once(monkeypatch) -> None:
    observed: list[object] = []
    monkeypatch.setattr(
        "d810.manager.decompilation_lifecycle.emit_diagnostic", observed.append
    )
    emitter = _Emitter()
    coordinator = _coordinator(emitter)
    coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    outcome = _rendered("headless")

    assert coordinator.observe_host_outcome(0x401000, outcome) is True
    assert coordinator.observe_host_outcome(0x401000, outcome) is True
    assert coordinator.current_session(0x401000) is not None
    coordinator.mark_structural_complete()
    assert coordinator.current_session(0x401000) is None
    assert len(_host_events(observed)) == 1
    assert [event for event, _payload in emitter.events if event is DecompilationEvent.SESSION_FINISHED] == [
        DecompilationEvent.SESSION_FINISHED
    ]


def test_wrapper_and_func_printed_rendered_outcomes_are_idempotent(monkeypatch) -> None:
    observed: list[object] = []
    monkeypatch.setattr(
        "d810.manager.decompilation_lifecycle.emit_diagnostic", observed.append
    )
    coordinator = _coordinator(_Emitter())
    coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    wrapper_outcome = _rendered("hxe_func_printed")

    assert coordinator.observe_host_outcome(0x401000, wrapper_outcome) is True
    assert coordinator.observe_host_outcome(
        0x401000,
        _rendered("hxe_func_printed"),
    ) is True
    assert len(_host_events(observed)) == 1
    coordinator.mark_structural_complete()
    assert coordinator.current_session(0x401000) is None


def test_failed_host_output_finishes_owner_without_synthesizing_code(monkeypatch) -> None:
    observed: list[object] = []
    monkeypatch.setattr(
        "d810.manager.decompilation_lifecycle.emit_diagnostic", observed.append
    )
    emitter = _Emitter()
    coordinator = _coordinator(emitter)
    coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    coordinator.mark_structural_complete()

    outcome = _failed("headless", code=None)
    assert coordinator.observe_host_outcome(0x401000, outcome) is True
    assert coordinator.current_session(0x401000) is None
    event = _host_events(observed)[0]
    assert event.outcome.kind is HostDecompilationOutcomeKind.FAILED
    assert event.outcome.failure_code is None


def test_final_host_outcome_closes_observability_after_lifecycle_events(monkeypatch) -> None:
    observed: list[object] = []
    order: list[str] = []

    class _OrderedEmitter(_Emitter):
        def emit(self, event, payload) -> None:
            super().emit(event, payload)
            if event is DecompilationEvent.SESSION_FINISHED:
                order.append("finished")

    monkeypatch.setattr(
        "d810.manager.decompilation_lifecycle.emit_diagnostic", observed.append
    )
    monkeypatch.setattr(
        "d810.manager.decompilation_lifecycle.close_observability_session",
        lambda: order.append("closed"),
    )
    emitter = _OrderedEmitter()
    coordinator = _coordinator(emitter)
    coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    coordinator.mark_structural_complete()

    assert coordinator.observe_host_outcome(0x401000, _failed("headless", code=None))
    assert coordinator.has_active_sessions is False
    assert [event for event, _payload in emitter.events] == [
        DecompilationEvent.SESSION_STARTED,
        DecompilationEvent.SESSION_FINISHED,
    ]
    assert order == ["finished", "closed"]


def test_new_session_resets_unflatten_counters_for_the_same_func_ea(monkeypatch) -> None:
    """Ticket d81-pqrc: a fresh session must never inherit a stale run's counters.

    Reproduces the reviewer's report verbatim: a prior session left
    ``handlers_recovered=85``, a ``plan_id``, and one committed batch behind
    for this func_ea; a brand new top-level session at the SAME func_ea must
    start from zero, not silently read the old run's numbers.
    """
    monkeypatch.setattr(
        "d810.manager.decompilation_lifecycle.emit_diagnostic", lambda *a, **k: None
    )
    coordinator = _coordinator(_Emitter())

    note_unflat_counters(0x401000, handlers_recovered=85, handlers_total=85, plan_id="plan-old")
    note_committed_batch(0x401000)
    assert unflat_counters(0x401000).handlers_recovered == 85

    coordinator.ensure_hexrays_session(function_ea=0x401000, database_identity="sample.i64")

    stale = unflat_counters(0x401000)
    assert stale.handlers_recovered is None
    assert stale.plan_id is None
    assert stale.committed_batches == 0


def test_finished_session_drops_unflatten_counters_for_its_func_ea(monkeypatch) -> None:
    """Ticket d81-pqrc: counters must not outlive the session that owned them."""
    monkeypatch.setattr(
        "d810.manager.decompilation_lifecycle.emit_diagnostic", lambda *a, **k: None
    )
    monkeypatch.setattr(
        "d810.manager.decompilation_lifecycle.close_observability_session", lambda: None
    )
    coordinator = _coordinator(_Emitter())
    coordinator.ensure_hexrays_session(function_ea=0x401000, database_identity="sample.i64")
    note_unflat_counters(0x401000, dag_nodes=59)
    coordinator.mark_structural_complete()

    assert coordinator.observe_host_outcome(0x401000, _rendered("headless")) is True

    assert unflat_counters(0x401000).dag_nodes is None


def test_reentrant_activation_for_the_same_func_ea_keeps_its_counters(monkeypatch) -> None:
    """A borrowed/reentrant activation must not reset counters mid-session."""
    monkeypatch.setattr(
        "d810.manager.decompilation_lifecycle.emit_diagnostic", lambda *a, **k: None
    )
    coordinator = _coordinator(_Emitter())
    coordinator.ensure_hexrays_session(function_ea=0x401000, database_identity="sample.i64")
    note_unflat_counters(0x401000, dag_nodes=59)

    # Same func_ea, same database identity, no active-session change: this is
    # the reentrant "current, False" branch and must not touch counters.
    coordinator.ensure_hexrays_session(function_ea=0x401000, database_identity="sample.i64")

    assert unflat_counters(0x401000).dag_nodes == 59


def test_next_prolog_abandonment_closes_before_new_owner_opens(monkeypatch) -> None:
    observed: list[object] = []
    close_order: list[str] = []
    monkeypatch.setattr(
        "d810.manager.decompilation_lifecycle.emit_diagnostic", observed.append
    )
    monkeypatch.setattr(
        "d810.manager.decompilation_lifecycle.close_observability_session",
        lambda: close_order.append("closed"),
    )
    coordinator = _coordinator(_Emitter())
    coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    coordinator.mark_structural_complete()

    coordinator.ensure_hexrays_session(
        function_ea=0x402000,
        database_identity="sample.i64",
    )

    assert close_order == ["closed"]
    assert coordinator.current_session(0x402000) is not None


def test_next_top_level_prolog_abandons_previous_structural_owner(monkeypatch) -> None:
    observed: list[object] = []
    monkeypatch.setattr(
        "d810.manager.decompilation_lifecycle.emit_diagnostic", observed.append
    )
    emitter = _Emitter()
    coordinator = _coordinator(emitter)
    coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    coordinator.mark_structural_complete()

    session_b, created = coordinator.ensure_hexrays_session(
        function_ea=0x402000,
        database_identity="sample.i64",
    )

    assert created is True
    assert coordinator.current_session(0x401000) is None
    assert coordinator.current_session(0x402000) is session_b
    event = _host_events(observed)[0]
    assert event.outcome.kind is HostDecompilationOutcomeKind.ABANDONED
    assert event.outcome.source == "next_prolog"


def test_nested_structural_callback_releases_borrowed_activation_only(monkeypatch) -> None:
    observed: list[object] = []
    monkeypatch.setattr(
        "d810.manager.decompilation_lifecycle.emit_diagnostic", observed.append
    )
    coordinator = _coordinator(_Emitter())
    parent, _ = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    coordinator.begin_native_preanalysis(parent)
    nested, created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
        callback_entry_ea=0x402000,
    )

    assert nested is parent
    assert created is False
    coordinator.mark_structural_complete()
    assert coordinator.current_session(0x401000) is parent
    assert parent.structural_complete is False
    coordinator.finish_native_preanalysis(parent)


def test_plugin_stop_drains_nested_owners_with_abandoned_outcomes(monkeypatch) -> None:
    observed: list[object] = []
    monkeypatch.setattr(
        "d810.manager.decompilation_lifecycle.emit_diagnostic", observed.append
    )
    emitter = _Emitter()
    coordinator = _coordinator(emitter)
    coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    coordinator.ensure_hexrays_session(
        function_ea=0x402000,
        database_identity="sample.i64",
    )

    coordinator.drain_active_sessions(source="plugin_stop")

    host_events = _host_events(observed)
    assert len(host_events) == 2
    assert [event.outcome.source for event in host_events] == [
        "plugin_stop",
        "plugin_stop",
    ]
    assert all(
        event.outcome.kind is HostDecompilationOutcomeKind.ABANDONED
        for event in host_events
    )
    assert coordinator.has_active_sessions is False
    assert [event for event, _payload in emitter.events if event is DecompilationEvent.SESSION_FINISHED] == [
        DecompilationEvent.SESSION_FINISHED,
        DecompilationEvent.SESSION_FINISHED,
    ]


def test_plugin_stop_releases_borrowed_activation_before_abandoning_owner(monkeypatch) -> None:
    observed: list[object] = []
    monkeypatch.setattr(
        "d810.manager.decompilation_lifecycle.emit_diagnostic", observed.append
    )
    coordinator = _coordinator(_Emitter())
    parent, _ = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    coordinator.begin_native_preanalysis(parent)
    coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
        callback_entry_ea=0x402000,
    )

    coordinator.drain_active_sessions(source="plugin_stop")

    host_events = _host_events(observed)
    assert len(host_events) == 1
    assert host_events[0].outcome.source == "plugin_stop"
    assert coordinator.has_active_sessions is False


def _rendered(source: str):
    return HostDecompilationOutcome(
        kind=HostDecompilationOutcomeKind.RENDERED,
        source=source,
        cfunc_available=True,
    )


def _failed(source: str, *, code: int | None):
    return HostDecompilationOutcome(
        kind=HostDecompilationOutcomeKind.FAILED,
        source=source,
        cfunc_available=False,
        failure_code=code,
    )
