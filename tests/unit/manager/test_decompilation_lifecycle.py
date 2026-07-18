"""Unit tests for manager-owned decompilation lifecycle coordination."""

from __future__ import annotations

from d810.core.provider_phase import ProviderPhaseSnapshot
from d810.manager.decompilation_lifecycle import (
    DecompilationLifecycleCoordinator,
    FlowgraphReadyPayload,
)


class _PreanalysisPhase:
    def __init__(self, calls: list[tuple[str, object]]) -> None:
        self._calls = calls

    def reset(self, *, func_ea: int) -> None:
        self._calls.append(("phase.reset", func_ea))

    def run_microcode_collectors(
        self,
        flow_graph: object,
        *,
        func_ea: int,
        provider_phase: ProviderPhaseSnapshot,
    ) -> None:
        self._calls.append(("phase.flowgraph", (flow_graph, func_ea, provider_phase)))

    def run_ctree_collectors(
        self,
        cfunc: object,
        *,
        func_ea: int,
        provider_phase: ProviderPhaseSnapshot,
    ) -> None:
        self._calls.append(("phase.ctree", (cfunc, func_ea, provider_phase)))


class _AnalysisRuntime:
    def __init__(self, calls: list[tuple[str, object]]) -> None:
        self._calls = calls
        self.reset_result = True
        self.hints: object | None = None

    def reset_for_func(
        self,
        func_ea: int,
        *,
        preserve_active_session: bool = False,
    ) -> bool:
        self._calls.append(("runtime.reset", (func_ea, preserve_active_session)))
        return self.reset_result

    def capture_maturity_facts(
        self,
        flow_graph: object,
        *,
        func_ea: int,
        provider_phase: ProviderPhaseSnapshot,
        phase: str,
        snapshot: object | None,
    ) -> None:
        self._calls.append(
            (
                "runtime.capture",
                (flow_graph, func_ea, provider_phase, phase, snapshot),
            )
        )

    def analyze_and_persist(self, func_ea: int) -> object | None:
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

    def mark_decompilation_finished(
        self,
        *,
        resume_func_ea: int | None = None,
    ) -> None:
        self._calls.append(("runtime.finish", resume_func_ea))


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
            preanalysis_phase=_PreanalysisPhase(calls),
            analysis_runtime=runtime,
            rule_scope_service=_RuleScopeService(calls),
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


def test_begin_capture_analyze_and_finish_preserve_lifecycle_order() -> None:
    calls: list[tuple[str, object]] = []
    coordinator, runtime = _coordinator(calls)
    runtime.hints = "hints"

    session = coordinator.begin_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    coordinator.capture_flowgraph(_flowgraph_payload(snapshot="snapshot"))
    coordinator.analyze_current_function(function_ea=0x401000, source="instruction")
    event = coordinator.finish_hexrays_session()

    assert session.function_ea == 0x401000
    assert session.top_level_epoch == 1
    assert event is not None
    assert event.function_ea == 0x401000
    assert event.top_level_epoch == 1
    assert calls == [
        ("runtime.reset", (0x401000, False)),
        ("rule-scope.clear", 0x401000),
        (
            "phase.flowgraph",
            ("flow-graph", 0x401000, _flowgraph_payload().provider_phase),
        ),
        (
            "runtime.capture",
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
        ("runtime.finish", None),
    ]
    assert coordinator.current_session(0x401000) is None


def test_repeated_begin_for_same_top_level_decompilation_reuses_epoch() -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)

    first = coordinator.begin_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    repeated = coordinator.begin_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )

    assert repeated is first
    assert calls == [
        ("runtime.reset", (0x401000, False)),
        ("rule-scope.clear", 0x401000),
    ]


def test_nested_different_function_gets_a_new_epoch_and_restores_parent() -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)

    outer = coordinator.begin_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    inner = coordinator.begin_hexrays_session(
        function_ea=0x402000,
        database_identity="sample.i64",
    )

    assert outer.top_level_epoch == 1
    assert inner.top_level_epoch == 1
    assert coordinator.current_session(0x401000) is outer
    assert coordinator.current_session(0x402000) is inner

    assert coordinator.finish_hexrays_session() is not None
    assert coordinator.current_session(0x401000) is outer
    assert coordinator.finish_hexrays_session() is not None
    assert coordinator.current_session(0x401000) is None
    assert calls == [
        ("runtime.reset", (0x401000, False)),
        ("rule-scope.clear", 0x401000),
        ("runtime.reset", (0x402000, True)),
        ("rule-scope.clear", 0x402000),
        ("runtime.finish", 0x401000),
        ("runtime.finish", None),
    ]


def test_analysis_without_hints_does_not_apply_or_record_rule_scope_outcome() -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)

    coordinator.analyze_current_function(function_ea=0x401000, source="ctree")

    assert calls == [("runtime.analyze", 0x401000)]
