"""Unit tests for manager-owned decompilation lifecycle coordination."""

from __future__ import annotations

from d810.analyses.control_flow.native_preanalysis_session import (
    BootstrapRouteEvidence,
    BootstrapRouteProofKind,
)
from d810.core.provider_phase import ProviderPhaseSnapshot
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.manager.decompilation_lifecycle import (
    DecompilationLifecycleCoordinator,
    FlowgraphReadyPayload,
)


class _PreanalysisRuntime:
    def __init__(self, calls: list[tuple[str, object]]) -> None:
        self._calls = calls

    def begin_session(self, event: object) -> None:
        self._calls.append(("preanalysis.reset", event.function_ea))

    def capture_flowgraph(
        self,
        flow_graph: object,
        *,
        func_ea: int,
        provider_phase: ProviderPhaseSnapshot,
        snapshot: object | None,
    ) -> None:
        self._calls.append(("phase.flowgraph", (flow_graph, func_ea, provider_phase)))
        self._calls.append(
            (
                "preanalysis.capture",
                (flow_graph, func_ea, provider_phase, "pre_d810", snapshot),
            )
        )

    def capture_ctree(
        self,
        cfunc: object,
        *,
        func_ea: int,
        provider_phase: ProviderPhaseSnapshot,
    ) -> None:
        self._calls.append(("phase.ctree", (cfunc, func_ea, provider_phase)))

    def finish_session(self, event: object) -> None:
        self._calls.append(("preanalysis.finish", event.function_ea))


class _AnalysisRuntime:
    def __init__(self, calls: list[tuple[str, object]]) -> None:
        self._calls = calls
        self.reset_result = True
        self.hints: object | None = None

    def begin_session(
        self,
        event: object,
        *,
        preserve_active_session: bool = False,
    ) -> bool:
        self._calls.append(
            ("runtime.reset", (event.function_ea, preserve_active_session))
        )
        return self.reset_result

    def analyze(self, func_ea: int) -> object | None:
        self._calls.append(("runtime.analyze", func_ea))
        return self.hints

    def record_rule_scope_outcome(
        self,
        *,
        func_ea: int,
        hints: object,
        apply_result: object,
        source: str,
    ) -> None:
        self._calls.append(
            ("runtime.rule-scope-outcome", (func_ea, hints, apply_result, source))
        )

    def finish_session(
        self,
        event: object,
        *,
        resume_event: object | None = None,
    ) -> None:
        del event
        self._calls.append(
            (
                "runtime.finish",
                None if resume_event is None else resume_event.function_ea,
            )
        )


class _RuleScopeService:
    def __init__(self, calls: list[tuple[str, object]]) -> None:
        self._calls = calls

    def clear_hint_state(self, func_ea: int) -> None:
        self._calls.append(("rule-scope.clear", func_ea))

    def apply_hints(self, hints: object) -> str:
        self._calls.append(("rule-scope.apply", hints))
        return "applied"


def _coordinator(
    calls: list[tuple[str, object]],
) -> tuple[DecompilationLifecycleCoordinator, _AnalysisRuntime]:
    runtime = _AnalysisRuntime(calls)
    return (
        DecompilationLifecycleCoordinator(
            preanalysis_runtime=_PreanalysisRuntime(calls),
            analysis_runtime=runtime,
            rule_scope_service=_RuleScopeService(calls),
            mba_mutation_gateway_factory=lambda **kwargs: kwargs,
        ),
        runtime,
    )


def _flowgraph_payload(
    *,
    flow_graph: object = "flow-graph",
    func_ea: int = 0x401000,
    snapshot: object | None = None,
) -> FlowgraphReadyPayload:
    return FlowgraphReadyPayload(
        flow_graph=flow_graph,
        func_ea=func_ea,
        provider_phase=ProviderPhaseSnapshot(
            provider_name="hexrays_microcode",
            provider_level=5,
            friendly_provider_level="MMAT_GLBOPT1",
        ),
        snapshot=snapshot,
    )


def test_ensure_capture_analyze_and_finish_preserve_lifecycle_order() -> None:
    calls: list[tuple[str, object]] = []
    coordinator, runtime = _coordinator(calls)
    runtime.hints = "hints"

    session, created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    coordinator.capture_flowgraph(_flowgraph_payload(snapshot="snapshot"))
    coordinator.analyze_current_function(function_ea=0x401000, source="instruction")
    result = coordinator.finish_hexrays_session()

    assert session.function_ea == 0x401000
    assert created is True
    assert session.top_level_epoch == 1
    assert result is None
    assert coordinator.current_session(0x401000) is None
    assert calls == [
        ("preanalysis.reset", 0x401000),
        ("runtime.reset", (0x401000, False)),
        ("rule-scope.clear", 0x401000),
        (
            "phase.flowgraph",
            ("flow-graph", 0x401000, _flowgraph_payload().provider_phase),
        ),
        (
            "preanalysis.capture",
            (
                "flow-graph",
                0x401000,
                _flowgraph_payload().provider_phase,
                "pre_d810",
                "snapshot",
            ),
        ),
        ("runtime.analyze", 0x401000),
        ("rule-scope.apply", "hints"),
        (
            "runtime.rule-scope-outcome",
            (0x401000, "hints", "applied", "instruction"),
        ),
        ("preanalysis.finish", 0x401000),
        ("runtime.finish", None),
    ]
    assert coordinator.current_session(0x401000) is None


def test_repeated_ensure_for_same_top_level_decompilation_reuses_epoch() -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)

    first, first_created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    repeated, repeated_created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )

    assert repeated is first
    assert first_created is True
    assert repeated_created is False
    assert calls == [
        ("preanalysis.reset", 0x401000),
        ("runtime.reset", (0x401000, False)),
        ("rule-scope.clear", 0x401000),
    ]


def test_new_session_initializes_injected_extensions_exactly_once() -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)
    initialized: list[object] = []
    coordinator.session_extension_initializer = initialized.append

    session, created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    repeated, repeated_created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )

    assert created is True
    assert repeated_created is False
    assert repeated is session
    assert initialized == [session]


def test_lifecycle_context_owns_portable_preanalysis_state_directly() -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)

    session, created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )

    assert session.native_preanalysis.evidence_generation == 0
    assert created is True
    assert session.native_preanalysis.bound_preopt_generation is None
    assert session.extensions == {}


def test_rebound_bootstrap_fact_is_published_once_on_a_real_snapshot(
    monkeypatch,
) -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)
    session, _created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    source = StableBlockIdentity.from_intervals((NativeEaInterval(0x401020, 0x401021),))
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401100, 0x401101),)
    )
    route = BootstrapRouteEvidence(
        source_identity=source,
        source_anchor_ea=0x401020,
        state=0x12345678,
        handler_identity=handler,
        handler_anchor_ea=0x401100,
        proof_kind=BootstrapRouteProofKind.STATIC_NATIVE,
    )
    assert session.native_preanalysis.merge_bootstrap_route(route)
    assert session.native_preanalysis.mark_bootstrap_route_rebound(route)
    published: list[object] = []
    import d810.core.observability as observability

    monkeypatch.setattr(observability, "emit", published.append)

    coordinator.capture_flowgraph(_flowgraph_payload(snapshot="snapshot"))
    coordinator.capture_flowgraph(_flowgraph_payload(snapshot="snapshot"))

    assert len(published) == 1
    event = published[0]
    assert event.observations[0].kind == "PreoptBootstrapRouteFact"
    assert event.observations[0].source_block is None
    assert event.observations[0].payload == {
        "source_ea": "0x401020",
        "state": "0x12345678",
        "handler_ea": "0x401100",
        "generation": 1,
        "proof_kind": "static_native",
        "rebound": True,
    }


def test_lifecycle_releases_current_mba_identity_index_when_session_finishes() -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)
    session, created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    current_index = object()

    assert created is True

    coordinator.bind_current_mba_identity_index(
        function_ea=0x401000,
        index=current_index,
    )
    assert session.current_mba_identity_index is current_index
    assert coordinator.finish_hexrays_session() is None
    assert session.current_mba_identity_index is None


def test_session_gateway_reuses_the_active_current_mba_identity_index() -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)
    session, _created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    index = type("_Index", (), {"generation": 3})()
    coordinator.bind_current_mba_identity_index(
        function_ea=0x401000,
        index=index,
    )

    gateway = coordinator.new_current_mba_mutation_gateway(
        function_ea=0x401000,
        maturity=4,
    )

    assert gateway == {
        "session": session,
        "identity_index": index,
        "maturity": 4,
        "event_emitter": None,
    }
    assert session.current_mba_identity_index is index


def test_nested_different_function_gets_a_new_epoch_and_restores_parent() -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)

    outer, outer_created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    inner, inner_created = coordinator.ensure_hexrays_session(
        function_ea=0x402000,
        database_identity="sample.i64",
    )

    assert outer.top_level_epoch == 1
    assert inner.top_level_epoch == 1
    assert outer_created is True
    assert inner_created is True
    assert coordinator.current_session(0x401000) is outer
    assert coordinator.current_session(0x402000) is inner

    assert coordinator.finish_hexrays_session() is None
    assert coordinator.current_session(0x401000) is outer
    assert coordinator.finish_hexrays_session() is None
    assert coordinator.current_session(0x401000) is None
    assert calls == [
        ("preanalysis.reset", 0x401000),
        ("runtime.reset", (0x401000, False)),
        ("rule-scope.clear", 0x401000),
        ("preanalysis.reset", 0x402000),
        ("runtime.reset", (0x402000, True)),
        ("rule-scope.clear", 0x402000),
        ("preanalysis.finish", 0x402000),
        ("runtime.finish", 0x401000),
        ("preanalysis.finish", 0x401000),
        ("runtime.finish", None),
    ]


def test_reentry_below_a_nested_child_reuses_parent_without_finishing_it() -> None:
    """A parent callback resumed during a child decompile keeps its evidence."""
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)
    parent, parent_created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    child, child_created = coordinator.ensure_hexrays_session(
        function_ea=0x402000,
        database_identity="sample.i64",
    )

    resumed_parent, resumed_created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )

    assert parent_created is True
    assert child_created is True
    assert resumed_parent is parent
    assert resumed_created is False
    assert coordinator.current_session(0x401000) is parent
    assert coordinator.current_session(0x402000) is child

    # The structural callback for the temporary reentry must not finish the
    # parent session or the nested child beneath it.
    assert coordinator.finish_hexrays_session() is None
    assert coordinator.current_session(0x401000) is parent
    assert coordinator.current_session(0x402000) is child

    assert coordinator.finish_hexrays_session() is None
    assert coordinator.current_session(0x402000) is None
    assert coordinator.current_session(0x401000) is parent
    assert coordinator.finish_hexrays_session() is None
    assert coordinator.current_session(0x401000) is None
    assert calls == [
        ("preanalysis.reset", 0x401000),
        ("runtime.reset", (0x401000, False)),
        ("rule-scope.clear", 0x401000),
        ("preanalysis.reset", 0x402000),
        ("runtime.reset", (0x402000, True)),
        ("rule-scope.clear", 0x402000),
        ("preanalysis.finish", 0x402000),
        ("runtime.finish", 0x401000),
        ("preanalysis.finish", 0x401000),
        ("runtime.finish", None),
    ]


def test_native_preanalysis_reserves_the_owner_across_an_internal_callback() -> None:
    """An internal preflight decompile cannot finish its caller's session."""
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)
    session, created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )

    assert created is True
    coordinator.begin_native_preanalysis(session)
    callback_session, callback_created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
        callback_entry_ea=0x401020,
    )

    assert callback_session is session
    assert callback_created is False
    assert coordinator.finish_hexrays_session() is None
    assert coordinator.current_session(0x401000) is session

    coordinator.finish_native_preanalysis(session)
    assert coordinator.finish_hexrays_session() is None
    assert coordinator.current_session(0x401000) is None
    assert calls == [
        ("preanalysis.reset", 0x401000),
        ("runtime.reset", (0x401000, False)),
        ("rule-scope.clear", 0x401000),
        ("preanalysis.finish", 0x401000),
        ("runtime.finish", None),
    ]


def test_analysis_without_hints_does_not_apply_or_record_rule_scope_outcome() -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)

    coordinator.analyze_current_function(function_ea=0x401000, source="ctree")

    assert calls == [("runtime.analyze", 0x401000)]
