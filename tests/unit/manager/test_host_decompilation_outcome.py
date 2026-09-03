"""Lifecycle ownership tests for host decompilation outcomes."""

from __future__ import annotations

import gc
import weakref

from d810.core.decompilation_session import DecompilationEvent
from d810.core.observability_events import (
    HostDecompilationOutcome,
    HostDecompilationOutcomeKind,
    HostDecompilationOutcomeObserved,
)
from d810.core.observability_unflat import (
    UnflattenOutcomeCounters,
    note_committed_batch,
    note_unflat_counters,
    unflat_counters,
)
from d810.manager.decompilation_lifecycle import DecompilationLifecycleCoordinator
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key()

# No cross-test isolation fixture needed here (ticket d81-pqrc): unflat
# counters are owned by DecompilationSessionContext, not a process-global
# dict. Each ``_coordinator()`` call below registers ITSELF as the active
# provider (DecompilationLifecycleCoordinator.__post_init__), so a
# later-constructed coordinator naturally supersedes an earlier one -- there
# is nothing left to reset between tests.


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


def test_two_sequential_sessions_at_the_same_func_ea_start_from_fresh_counters(
    monkeypatch,
) -> None:
    """Ticket d81-pqrc: session-owned counters, not process-global function state.

    Reproduces the reviewer's report verbatim: a prior session recorded
    ``handlers_recovered=85``, a ``plan_id``, and one committed batch for
    this func_ea, then finished. A brand new top-level session at the SAME
    func_ea must get its OWN ``UnflattenOutcomeCounters`` object -- a
    different identity, every field back at its default -- not silently
    read the old run's numbers via any surviving global lookup.
    """
    monkeypatch.setattr(
        "d810.manager.decompilation_lifecycle.emit_diagnostic", lambda *a, **k: None
    )
    monkeypatch.setattr(
        "d810.manager.decompilation_lifecycle.close_observability_session", lambda: None
    )
    coordinator = _coordinator(_Emitter())

    session_old, _ = coordinator.ensure_hexrays_session(
        function_ea=0x401000, database_identity="sample.i64"
    )
    note_unflat_counters(0x401000, handlers_recovered=85, handlers_total=85, plan_id="plan-old")
    note_committed_batch(0x401000)
    old_counters = unflat_counters(0x401000)
    assert old_counters is session_old.unflat_counters
    assert old_counters.handlers_recovered == 85
    assert old_counters.committed_batches == 1

    coordinator.mark_structural_complete()
    assert coordinator.observe_host_outcome(0x401000, _rendered("headless")) is True
    assert coordinator.current_session(0x401000) is None

    session_new, created = coordinator.ensure_hexrays_session(
        function_ea=0x401000, database_identity="sample.i64"
    )
    assert created is True

    fresh = unflat_counters(0x401000)
    assert fresh is session_new.unflat_counters
    assert fresh is not old_counters
    assert fresh == UnflattenOutcomeCounters()
    assert fresh.handlers_recovered is None
    assert fresh.plan_id is None
    assert fresh.committed_batches == 0


def test_finished_session_counters_are_unreachable_after_finish(monkeypatch) -> None:
    """Ticket d81-pqrc: counters do not outlive the session that owned them.

    Once the owning session is popped and nothing else references it, its
    ``UnflattenOutcomeCounters`` is ordinary garbage -- not retained by any
    module-level cache -- and the public accessor can no longer see it.
    """
    monkeypatch.setattr(
        "d810.manager.decompilation_lifecycle.emit_diagnostic", lambda *a, **k: None
    )
    monkeypatch.setattr(
        "d810.manager.decompilation_lifecycle.close_observability_session", lambda: None
    )
    coordinator = _coordinator(_Emitter())
    session, _ = coordinator.ensure_hexrays_session(
        function_ea=0x401000, database_identity="sample.i64"
    )
    note_unflat_counters(0x401000, dag_nodes=59)
    counters_ref = weakref.ref(session.unflat_counters)
    coordinator.mark_structural_complete()

    assert coordinator.observe_host_outcome(0x401000, _rendered("headless")) is True

    # The public API sees nothing for this func_ea any more.
    assert unflat_counters(0x401000).dag_nodes is None

    # And the object itself is genuinely gone, not merely unlisted.
    del session
    gc.collect()
    assert counters_ref() is None


def test_reentrant_activation_for_the_same_func_ea_keeps_its_counters(monkeypatch) -> None:
    """A borrowed/reentrant activation must not reset counters mid-session."""
    monkeypatch.setattr(
        "d810.manager.decompilation_lifecycle.emit_diagnostic", lambda *a, **k: None
    )
    coordinator = _coordinator(_Emitter())
    session, _ = coordinator.ensure_hexrays_session(
        function_ea=0x401000, database_identity="sample.i64"
    )
    note_unflat_counters(0x401000, dag_nodes=59)

    # Same func_ea, same database identity, no active-session change: this is
    # the reentrant "current, False" branch and must not touch counters.
    reentrant_session, created = coordinator.ensure_hexrays_session(
        function_ea=0x401000, database_identity="sample.i64"
    )

    assert created is False
    assert reentrant_session.unflat_counters is session.unflat_counters
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
