"""Manager gate for session-owned pre-decompile resolver evidence."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisSessionState,
)
from d810.manager.manager import D810Manager
from d810.optimizers.microcode.flow.jumps import computed_goto_resolver
from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
    resolver_session_state,
)
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key()


def test_preflight_starts_one_session_and_hands_its_state_to_the_resolver(
    monkeypatch,
) -> None:
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        native_key=NATIVE_KEY,
        resolver_attachment=None,
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
        "stage_computed_goto_preanalysis",
        lambda function_ea, *, state: calls.append(("stage", state)) or resolution,
        raising=False,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "resolve_and_materialize",
        lambda *_args, **_kwargs: pytest.fail(
            "manager preflight must preserve the prepatch PREOPT source"
        ),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "prepare_detached_handler_snippets",
        lambda state: calls.append(("prepare", state)) or 3,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "prepare_terminal_return_carrier_templates",
        lambda state: calls.append(("prepare-carriers", state)) or 2,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "discover_static_native_bootstrap_routes",
        lambda function_ea, state: calls.append(
            ("discover-bootstrap", function_ea, state)
        )
        or True,
    )

    assert manager.prepare_native_preanalysis(0x401000) == 5

    state = resolver_session_state(session)
    # Session events belong to the coordinator. The manager must not mirror
    # the event when its preflight reuses that permanent lifecycle port.
    assert events == []
    assert calls == [
        (
            "ensure",
            {"function_ea": 0x401000, "database_identity": "sample.i64"},
        ),
        ("stage", state),
        ("preanalysis.begin", session),
        ("prepare-carriers", state),
        ("prepare", state),
        ("discover-bootstrap", 0x401000, state),
        ("preanalysis.finish", session),
    ]
    assert state.materialization is not None
    assert state.materialization.resolution is resolution


def test_decompile_controller_runs_one_followup_for_pending_generated_restart(
    monkeypatch,
) -> None:
    calls: list[tuple[str, int]] = []
    pending = iter((True, False))

    class _Lifecycle:
        @staticmethod
        def has_pending_generated_restart(function_ea: int) -> bool:
            calls.append(("pending", function_ea))
            return next(pending)

    manager = D810Manager.__new__(D810Manager)
    manager.decompilation_lifecycle = _Lifecycle()
    monkeypatch.setattr(
        manager,
        "prepare_native_preanalysis",
        lambda function_ea: calls.append(("prepare", function_ea)) or 0,
    )

    rounds = iter(("first", "final"))
    result = manager.decompile_with_native_preanalysis(
        0x401000,
        lambda: calls.append(("decompile", 0x401000)) or next(rounds),
        lambda: calls.append(("invalidate", 0x401000)),
    )

    assert result == "final"
    assert calls == [
        ("prepare", 0x401000),
        ("decompile", 0x401000),
        ("pending", 0x401000),
        ("prepare", 0x401000),
        ("invalidate", 0x401000),
        ("decompile", 0x401000),
        ("pending", 0x401000),
    ]
