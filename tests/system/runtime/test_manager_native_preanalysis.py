"""Manager gate for session-owned pre-decompile resolver evidence."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisSessionState,
)
from d810.core.observability_events import MutationReceiptObserved
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.ir.logical_block_proxy import LogicalBlockVersionId
from d810.hexrays.mutation.fragment_publication_lifecycle import (
    FragmentPublicationLifecycleAuthority,
)
from d810.hexrays.mutation.mba_mutation_events import (
    MbaMutationAborted,
    StructuralMutationKind,
)
from d810.manager.manager import (
    D810Manager,
    _build_current_mba_identity_index,
    _new_current_mba_mutation_gateway,
)
from d810.optimizers.microcode.flow.jumps import computed_goto_resolver
from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
    resolver_session_state,
)
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key()


def test_current_mba_identity_index_uses_only_current_mba_imported_origins(
    monkeypatch,
) -> None:
    native_preanalysis = NativePreanalysisSessionState()
    origins = ((0xFFFFFFFFFFFFFF01, 0x40A70E),)
    session = SimpleNamespace(
        native_preanalysis=native_preanalysis,
        native_key=NATIVE_KEY,
        resolver_attachment=None,
        identity_key="test-session",
        function_ea=0x40A560,
    )
    state = resolver_session_state(session)
    mba = SimpleNamespace(maturity=0, this=0x1234)
    assert state.bind_current_imported_instruction_origins(0x1234, origins)
    captured: dict[str, object] = {}
    index = SimpleNamespace(
        evidence_generation=native_preanalysis.evidence_generation,
        generation=0,
    )

    def build_index(current_mba, **kwargs):
        captured["mba"] = current_mba
        captured.update(kwargs)
        return index

    monkeypatch.setattr(
        MbaBlockIdentityIndex,
        "from_mba",
        staticmethod(build_index),
    )

    assert _build_current_mba_identity_index(session=session, mba=mba) is index
    assert captured["mba"] is mba
    assert captured["imported_instruction_origins"] == dict(origins)
    assert state.identity_index is index


def test_current_mba_identity_index_rejects_previous_mba_origins(monkeypatch) -> None:
    native_preanalysis = NativePreanalysisSessionState()
    session = SimpleNamespace(
        native_preanalysis=native_preanalysis,
        native_key=NATIVE_KEY,
        resolver_attachment=None,
        identity_key="test-session",
        function_ea=0x40A560,
    )
    state = resolver_session_state(session)
    assert state.bind_current_imported_instruction_origins(
        0x1234,
        ((0xFFFFFFFFFFFFFF01, 0x40A70E),),
    )
    captured: dict[str, object] = {}
    index = SimpleNamespace(evidence_generation=0, generation=0)

    def build_index(_mba, **kwargs):
        captured.update(kwargs)
        return index

    monkeypatch.setattr(MbaBlockIdentityIndex, "from_mba", staticmethod(build_index))

    _build_current_mba_identity_index(
        session=session,
        mba=SimpleNamespace(maturity=0, this=0x5678),
    )

    assert captured["imported_instruction_origins"] == {}


def test_current_mba_mutation_gateway_uses_session_lifecycle_authority() -> None:
    native_preanalysis = NativePreanalysisSessionState(evidence_generation=2)
    session = SimpleNamespace(
        native_preanalysis=native_preanalysis,
        native_key=NATIVE_KEY,
        identity_key="test-session",
        function_ea=0x40A560,
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id=session.identity_key,
        generation=7,
        evidence_generation=2,
        native_key=NATIVE_KEY,
        bindings=(),
    )
    event_emitter = object()

    gateway = _new_current_mba_mutation_gateway(
        session=session,
        identity_index=index,
        maturity=3,
        event_emitter=event_emitter,
    )

    assert isinstance(
        gateway.lifecycle_authority,
        FragmentPublicationLifecycleAuthority,
    )
    assert gateway.lifecycle_authority is not native_preanalysis
    assert gateway.lifecycle_authority.evidence_generation == 2
    assert gateway.identity_index is index
    assert gateway.event_emitter is event_emitter


def test_manager_preserves_applied_work_on_aborted_mutation_receipt(
    monkeypatch,
) -> None:
    observed: list[MutationReceiptObserved] = []
    monkeypatch.setattr("d810.core.observability.emit", observed.append)

    D810Manager._on_mutation_aborted(
        MbaMutationAborted(
            session_id="terminal-fragment-session",
            function_ea=0x40A560,
            maturity=1,
            mba_generation=7,
            evidence_generation=3,
            mutation_batch_id="terminal-fragment-batch",
            kind=StructuralMutationKind.FRAGMENT_PUBLICATION,
            planned_operation_count=8,
            applied_operation_count=8,
            description="publish terminal semantic fragment",
            reason=(
                "postpublication semantic validation failed: "
                "observable_return_carrier:return-value"
            ),
            discarded_version_ids=(
                LogicalBlockVersionId("logical-terminal", 1),
            ),
            fragment_plan_id="terminal-fragment",
            fragment_atomic_group_id="terminal-group",
            fragment_staged=True,
            root_publication_attempted=True,
            root_publication_succeeded=True,
            rollback_attempted=True,
            rollback_succeeded=True,
        )
    )

    assert len(observed) == 1
    assert observed[0].mutation_batch_id == "terminal-fragment-batch"
    assert observed[0].planned_operation_count == 8
    assert observed[0].applied_operation_count == 8
    assert observed[0].outcome == "aborted"
    assert "observable_return_carrier:return-value" in observed[0].reason
    assert observed[0].fragment_plan_id == "terminal-fragment"
    assert observed[0].fragment_atomic_group_id == "terminal-group"
    assert observed[0].fragment_staged
    assert observed[0].root_publication_succeeded
    assert observed[0].rollback_succeeded
    assert [
        (
            transition.proxy_token,
            transition.from_state,
            transition.to_state,
        )
        for transition in observed[0].version_transitions
    ] == [("logical-terminal", "staged", "aborted")]


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
        "prepare_terminal_return_carrier_evidence",
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
        ("invalidate", 0x401000),
        ("decompile", 0x401000),
        ("pending", 0x401000),
        ("prepare", 0x401000),
        ("invalidate", 0x401000),
        ("decompile", 0x401000),
        ("pending", 0x401000),
    ]
