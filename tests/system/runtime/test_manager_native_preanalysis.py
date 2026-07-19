"""Manager gate for session-owned pre-decompile resolver evidence."""
from __future__ import annotations

from types import SimpleNamespace

from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisSessionState,
)
from d810.hexrays.lifecycle import DecompilationEvent
from d810.manager.manager import D810Manager
from d810.optimizers.microcode.flow.jumps import computed_goto_resolver
from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
    resolver_session_state,
)


def test_preflight_starts_one_session_and_hands_its_state_to_the_resolver(
    monkeypatch,
) -> None:
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        extensions={},
        event=SimpleNamespace(function_ea=0x401000),
    )
    events: list[tuple[object, object]] = []
    calls: list[object] = []

    class _Lifecycle:
        def ensure_hexrays_session(self, **kwargs):
            calls.append(("ensure", kwargs))
            return session, True

        def begin_native_preanalysis(self, current_session):
            calls.append(("preanalysis.begin", current_session))

        def finish_native_preanalysis(self, current_session):
            calls.append(("preanalysis.finish", current_session))

    manager = D810Manager.__new__(D810Manager)
    manager.decompilation_lifecycle = _Lifecycle()
    manager._database_identity = "sample.i64"
    manager.event_emitter = SimpleNamespace(
        emit=lambda event, payload: events.append((event, payload))
    )
    resolution = SimpleNamespace(jmp_targets=(0x401100,))
    monkeypatch.setattr(
        computed_goto_resolver,
        "_has_unresolved_computed_goto",
        lambda function_ea: function_ea == 0x401000,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "resolve_and_materialize",
        lambda function_ea, *, state: calls.append(("resolve", state)) or resolution,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "prepare_detached_handler_snippets",
        lambda state: calls.append(("prepare", state)) or 3,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "discover_static_native_bootstrap_routes",
        lambda function_ea, state: calls.append(
            ("discover-bootstrap", function_ea, state)
        )
        or True,
    )

    assert manager.prepare_native_preanalysis(0x401000) == 3

    state = resolver_session_state(session)
    assert events == [(DecompilationEvent.SESSION_STARTED, session.event)]
    assert calls == [
        (
            "ensure",
            {"function_ea": 0x401000, "database_identity": "sample.i64"},
        ),
        ("resolve", state),
        ("preanalysis.begin", session),
        ("discover-bootstrap", 0x401000, state),
        ("prepare", state),
        ("preanalysis.finish", session),
    ]
    assert state.materialization is not None
    assert state.materialization.resolution is resolution
