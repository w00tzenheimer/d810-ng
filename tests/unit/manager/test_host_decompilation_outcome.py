"""Lifecycle ownership tests for host decompilation outcomes."""

from __future__ import annotations

from d810.core.decompilation_session import DecompilationEvent
from d810.core.observability_events import (
    HostDecompilationOutcome,
    HostDecompilationOutcomeKind,
    HostDecompilationOutcomeObserved,
)
from d810.manager.decompilation_lifecycle import DecompilationLifecycleCoordinator
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key()


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
    coordinator.mark_structural_complete()
    outcome = _rendered("headless")

    assert coordinator.observe_host_outcome(0x401000, outcome) is True
    assert coordinator.observe_host_outcome(0x401000, outcome) is False
    assert coordinator.current_session(0x401000) is None
    assert len(_host_events(observed)) == 1
    assert [event for event, _payload in emitter.events if event is DecompilationEvent.SESSION_FINISHED] == [
        DecompilationEvent.SESSION_FINISHED
    ]


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
