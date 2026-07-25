"""Structural contract for manager-owned Hex-Rays session lifecycle wiring.

This remains a system-runtime test because it pins the real IDA hook source and
manager composition. It does not substitute a fake Hex-Rays API.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisSessionState,
)
from d810.core.provider_phase import ProviderPhaseSnapshot
from d810.core.decompilation_session import DecompilationEvent
from d810.hexrays.hooks.optblock_adapter import BlockOptimizerManager
from d810.hexrays.hooks.hexrays_hooks import HexraysDecompilationHook
from d810.manager.decompilation_lifecycle import (
    DecompilationLifecycleCoordinator,
    FlowgraphReadyPayload,
)
from d810.transforms.cfg_transaction import (
    CfgGenerationPoisoned,
    CfgTransactionFailure,
    CfgTransactionPhase,
    TransactionAttemptId,
)
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key()
_ROOT = Path(__file__).resolve().parents[4]
_HOOK = _ROOT / "src/d810/hexrays/hooks/hexrays_hooks.py"
_OPTBLOCK = _ROOT / "src/d810/hexrays/hooks/optblock_adapter.py"
_LIFECYCLE = _ROOT / "src/d810/hexrays/lifecycle.py"
_EVENTS = _ROOT / "src/d810/core/decompilation_session.py"
_MANAGER = _ROOT / "src/d810/manager/manager.py"
_COORDINATOR = _ROOT / "src/d810/manager/decompilation_lifecycle.py"
_ANALYSIS_RUNTIME = _ROOT / "src/d810/passes/runtime.py"
_PREANALYSIS_RUNTIME = _ROOT / "src/d810/passes/preanalysis_runtime.py"


def test_poisoned_generation_restart_yields_exactly_one_hook_merr_redo(
    monkeypatch,
) -> None:
    state = NativePreanalysisSessionState(evidence_generation=4)
    assert state.request_poisoned_generation_restart(
        reason="post-write fragment failure"
    )
    decision = {"request_redo": False}

    def callback(event, **kwargs) -> None:
        if (
            event is DecompilationEvent.HEXRAYS_FLOWCHART_READY
            and state.consume_generated_restart()
        ):
            kwargs["decision"]["request_redo"] = True
            kwargs["decision"]["reason"] = "poisoned_generation_restart"

    hook = SimpleNamespace(
        callback=callback,
        _decompilation_lifecycle=None,
    )
    mba = SimpleNamespace(entry_ea=0x40A560)
    monkeypatch.setattr(
        HexraysDecompilationHook,
        "_decision_for_mba",
        staticmethod(lambda _self, _mba: decision),
    )
    monkeypatch.setattr(
        HexraysDecompilationHook,
        "_function_owner_ea",
        staticmethod(lambda _mba: 0x40A560),
    )

    assert (
        HexraysDecompilationHook.flowchart(hook, object(), mba, object(), 0)
        == ida_hexrays.MERR_REDO
    )
    decision["request_redo"] = False
    assert (
        HexraysDecompilationHook.flowchart(
            hook,
            object(),
            mba,
            object(),
            0,
        )
        == 0
    )
    assert not state.has_pending_generated_restart


def test_preoptimized_hook_propagates_poison_instead_of_continuing(
    monkeypatch,
) -> None:
    failure = CfgTransactionFailure(
        attempt_id=TransactionAttemptId.new(
            "hook-preopt-poison",
            "hook-session",
            4,
        ),
        phase=CfgTransactionPhase.POISONED_RESTART_REQUIRED,
        reason="INTERR: 50856 after PREOPT insertion",
        live_mutation_started=True,
        failure_phase="stage",
        interr_code=50856,
    )

    def callback(event, **_kwargs) -> None:
        assert event is DecompilationEvent.HEXRAYS_PREOPT_READY
        raise CfgGenerationPoisoned(failure)

    hook = SimpleNamespace(
        callback=callback,
        _decompilation_lifecycle=SimpleNamespace(
            preopt_ready_was_emitted=lambda **_kwargs: False,
        ),
    )
    mba = SimpleNamespace(
        entry_ea=0x40A560,
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    monkeypatch.setattr(
        HexraysDecompilationHook,
        "_function_owner_ea",
        staticmethod(lambda _mba: 0x40A560),
    )
    monkeypatch.setattr(
        HexraysDecompilationHook,
        "_decision_for_mba",
        staticmethod(
            lambda _self, _mba, **_kwargs: {
                "request_redo": False,
                "session": object(),
            }
        ),
    )

    with pytest.raises(CfgGenerationPoisoned):
        HexraysDecompilationHook.preoptimized(hook, mba)


def _method_source(path: Path, class_name: str, method_name: str) -> str:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or node.name != class_name:
            continue
        for method in node.body:
            if isinstance(method, ast.FunctionDef) and method.name == method_name:
                return ast.get_source_segment(source, method) or ""
    raise AssertionError(f"{class_name}.{method_name} not found in {path}")


def test_hook_starts_and_finishes_typed_sessions_through_the_coordinator() -> None:
    prolog = _method_source(_HOOK, "HexraysDecompilationHook", "prolog")
    ensure_session = _method_source(
        _HOOK, "HexraysDecompilationHook", "_ensure_lifecycle_session"
    )
    decision = _method_source(_HOOK, "HexraysDecompilationHook", "_decision_for_mba")
    structural = _method_source(_HOOK, "HexraysDecompilationHook", "structural")

    assert "HexraysDecompilationHook._ensure_lifecycle_session(" in prolog
    assert "structural_callback=True" in prolog
    assert "ensure_hexrays_session" in ensure_session
    assert "DecompilationEvent.SESSION_STARTED" not in ensure_session
    assert "HexraysDecompilationHook._ensure_lifecycle_session(self, mba)" in decision
    assert "lifecycle.finish_hexrays_session()" in structural
    assert "DecompilationEvent.SESSION_FINISHED" not in structural
    assert "DecompilationEvent.STARTED" not in prolog
    assert "DecompilationEvent.FINISHED" not in structural


def test_actual_hook_lifecycle_order_is_stable_across_merr_redo(monkeypatch) -> None:
    """One generated rebuild reuses the epoch and never repeats reset/capture."""
    order: list[str] = []

    class _PreanalysisRuntime:
        def __init__(self) -> None:
            self._provider_phases: set[tuple[str, int]] = set()

        def begin_session(self, event) -> None:
            order.append(f"reset:0x{int(event.function_ea):X}")

        def capture_flowgraph(
            self,
            flow_graph,
            *,
            func_ea: int,
            provider_phase: ProviderPhaseSnapshot,
            snapshot,
        ) -> None:
            del flow_graph, func_ea, snapshot
            phase_key = (
                str(provider_phase.provider_name),
                int(provider_phase.provider_level),
            )
            if phase_key not in self._provider_phases:
                self._provider_phases.add(phase_key)
                order.append(f"flowgraph:{provider_phase.friendly_provider_level}")

        def finish_session(self, event) -> None:
            order.append(f"preanalysis-finish:0x{int(event.function_ea):X}")

    class _AnalysisRuntime:
        def begin_session(self, event, *, preserve_active_session=False) -> None:
            del event, preserve_active_session

        def finish_session(self, event, *, resume_event=None) -> None:
            del event, resume_event

    class _RuleScope:
        @staticmethod
        def clear_hint_state(function_ea: int) -> None:
            del function_ea

    class _Emitter:
        coordinator: DecompilationLifecycleCoordinator
        redo_requested = False

        def emit(self, event, *args, **kwargs) -> None:
            if event is DecompilationEvent.SESSION_STARTED:
                order.append("SESSION_STARTED")
            elif event is DecompilationEvent.HEXRAYS_FLOWCHART_READY:
                order.append("FLOWCHART")
                self.coordinator.capture_flowgraph(
                    FlowgraphReadyPayload(
                        flow_graph=object(),
                        func_ea=int(kwargs["function_ea"]),
                        provider_phase=ProviderPhaseSnapshot(
                            provider_name="hexrays_microcode",
                            provider_level=1,
                            friendly_provider_level="MMAT_PREOPTIMIZED",
                        ),
                        snapshot=None,
                    )
                )
                if not self.redo_requested:
                    self.redo_requested = True
                    kwargs["decision"]["request_redo"] = True
            elif event is DecompilationEvent.HEXRAYS_PREOPT_READY:
                order.append("PREOPT")
            elif event is DecompilationEvent.HEXRAYS_CALLS_DONE:
                order.append("CALLS")
            elif event is DecompilationEvent.SESSION_FINISHED:
                order.append("SESSION_FINISHED")

    emitter = _Emitter()
    coordinator = DecompilationLifecycleCoordinator(
        preanalysis_runtime=_PreanalysisRuntime(),
        analysis_runtime=_AnalysisRuntime(),
        rule_scope_service=_RuleScope(),
        native_preanalysis_key_provider=lambda _function_ea: NATIVE_KEY,
        event_emitter=emitter,
    )
    emitter.coordinator = coordinator
    hook = SimpleNamespace(
        callback=emitter.emit,
        _decompilation_lifecycle=coordinator,
        _database_identity="sample.i64",
        _block_optimizer=None,
    )
    mba = SimpleNamespace(entry_ea=0x401000, maturity=1)
    monkeypatch.setattr(
        HexraysDecompilationHook,
        "_function_owner_ea",
        staticmethod(lambda _mba: 0x401000),
    )

    assert HexraysDecompilationHook.prolog(hook, mba, object(), object(), 0) == 0
    assert (
        HexraysDecompilationHook.flowchart(hook, object(), mba, object(), 0)
        == ida_hexrays.MERR_REDO
    )
    assert HexraysDecompilationHook.prolog(hook, mba, object(), object(), 0) == 0
    assert HexraysDecompilationHook.flowchart(hook, object(), mba, object(), 0) == 0
    assert HexraysDecompilationHook.preoptimized(hook, mba) == 0
    assert HexraysDecompilationHook.calls_done(hook, mba) == 0
    assert HexraysDecompilationHook.structural(hook, SimpleNamespace()) == 0

    assert order == [
        "SESSION_STARTED",
        "reset:0x401000",
        "FLOWCHART",
        "flowgraph:MMAT_PREOPTIMIZED",
        "FLOWCHART",
        "PREOPT",
        "CALLS",
        "preanalysis-finish:0x401000",
        "SESSION_FINISHED",
    ]


def test_prolog_opens_diagnostics_for_top_level_session_owner(monkeypatch) -> None:
    """Nested PREOPT generation must not name the DB after its range entry."""
    import d810.core.observability as observability

    opened: list[int] = []
    reobserved: list[int] = []
    session = SimpleNamespace(function_ea=0x40A560)
    hook = SimpleNamespace(
        _decompilation_lifecycle=SimpleNamespace(
            reobserve_active_diagnostic_session=reobserved.append,
        )
    )
    mba = SimpleNamespace(entry_ea=0x40C898, maturity=1)
    monkeypatch.setattr(
        HexraysDecompilationHook,
        "_function_owner_ea",
        staticmethod(lambda _mba: 0x40C898),
    )
    monkeypatch.setattr(
        HexraysDecompilationHook,
        "_ensure_lifecycle_session",
        staticmethod(lambda _hook, _mba, **_kwargs: session),
    )
    monkeypatch.setattr(observability, "open_observability_session", opened.append)

    assert HexraysDecompilationHook.prolog(hook, mba, object(), object(), 0) == 0

    assert opened == [0x40A560]
    assert reobserved == [0x40A560]


def test_every_resolver_callback_receives_the_lifecycle_session_decision() -> None:
    build_callinfo = _method_source(_HOOK, "HexraysDecompilationHook", "build_callinfo")
    stkpnts = _method_source(_HOOK, "HexraysDecompilationHook", "stkpnts")
    preoptimized = _method_source(_HOOK, "HexraysDecompilationHook", "preoptimized")

    assert "_decision_for_mba(self, blk.mba)" in build_callinfo
    assert "_decision_for_mba(self, mba)" in stkpnts
    assert "bind_live_identity=True" not in build_callinfo
    assert "bind_live_identity=True" not in stkpnts
    assert "_decision_for_mba(" in preoptimized
    assert "bind_live_identity=True" in preoptimized


def test_live_mba_gateway_is_bound_once_per_flow_context() -> None:
    context = _method_source(
        _OPTBLOCK,
        "BlockOptimizerManager",
        "_get_or_create_flow_context",
    )

    create_branch = context.split("        else:\n", maxsplit=1)[0]
    assert "self._bind_resolver_session_state(self._flow_context, mba)" in create_branch
    assert "self._bind_mutation_gateway_port(self._flow_context, mba)" in create_branch
    assert "self._bind_semantic_native_body_materializer_port(" in create_branch


def test_pre_context_whole_mba_extension_gets_gateway_from_coordinator() -> None:
    calls: list[tuple[str, int]] = []
    gateway = object()

    class _Lifecycle:
        @staticmethod
        def build_current_mba_identity_index(*, function_ea: int, mba):
            del mba
            calls.append(("index", function_ea))
            return object()

        @staticmethod
        def new_current_mba_mutation_gateway(*, function_ea: int, maturity: int):
            calls.append(("gateway", function_ea))
            calls.append(("maturity", maturity))
            return gateway

    manager = SimpleNamespace(
        _decompilation_lifecycle=_Lifecycle(),
        current_maturity=ida_hexrays.MMAT_GLBOPT1,
    )
    mba = SimpleNamespace(
        entry_ea=0x401000,
        maturity=ida_hexrays.MMAT_GLBOPT1,
    )

    result = BlockOptimizerManager._new_coordinator_mutation_gateway(manager, mba)

    assert result is gateway
    assert calls == [
        ("index", 0x401000),
        ("gateway", 0x401000),
        ("maturity", ida_hexrays.MMAT_GLBOPT1),
    ]


def test_terminal_tail_extension_does_not_depend_on_future_flow_context() -> None:
    terminal_tail = _method_source(
        _OPTBLOCK,
        "BlockOptimizerManager",
        "_maybe_run_terminal_tail_cascade_egress_lowering",
    )

    assert "self._new_coordinator_mutation_gateway(mba)" in terminal_tail
    assert "self._flow_context.new_mba_mutation_gateway()" not in terminal_tail


def test_manager_has_one_coordinator_and_no_legacy_flowgraph_subscriber() -> None:
    source = _MANAGER.read_text(encoding="utf-8")

    assert "DecompilationLifecycleCoordinator(" in source
    assert "decompilation_lifecycle=self.decompilation_lifecycle" in source
    assert "self._capture_flowgraph_ready" in source
    assert "FlowGraphReadySubscriber" not in source


def test_coordinator_is_the_only_production_lifecycle_runtime_bridge() -> None:
    source = _COORDINATOR.read_text(encoding="utf-8")

    assert ".begin_session(" in source
    assert ".analyze(" in source
    assert ".reset_for_func(" not in source
    assert ".analyze_and_persist(" not in source
    for adapter in (
        _ROOT / "src/d810/hexrays/hooks/optinsn_adapter.py",
        _ROOT / "src/d810/hexrays/hooks/optblock_adapter.py",
        _ROOT / "src/d810/hexrays/hooks/ctree_hooks.py",
    ):
        adapter_source = adapter.read_text(encoding="utf-8")
        assert ".reset_for_func(" not in adapter_source
        assert ".analyze_and_persist(" not in adapter_source


def test_legacy_start_and_finish_enum_members_are_removed() -> None:
    source = _EVENTS.read_text(encoding="utf-8")
    adapter_source = _LIFECYCLE.read_text(encoding="utf-8")

    assert "SESSION_STARTED" in source
    assert "SESSION_FINISHED" in source
    assert "    STARTED =" not in source
    assert "    FINISHED =" not in source
    assert "from d810.hexrays.lifecycle import DecompilationEvent" not in source
    assert "import DecompilationEvent as _DecompilationEvent" in adapter_source


def test_raw_collection_and_consumer_analysis_have_distinct_owners() -> None:
    analysis_source = _ANALYSIS_RUNTIME.read_text(encoding="utf-8")
    preanalysis_source = _PREANALYSIS_RUNTIME.read_text(encoding="utf-8")
    adapter_source = _OPTBLOCK.read_text(encoding="utf-8")

    assert "class PreanalysisRuntime" in preanalysis_source
    assert "PreanalysisFactRuntime(" in preanalysis_source
    assert "def capture_flowgraph(" in preanalysis_source
    assert "def register_fact_collector(" in preanalysis_source
    assert "def validated_fact_view(" not in preanalysis_source

    assert "PreanalysisFactRuntime" not in analysis_source
    assert "PreanalysisPhase" not in analysis_source
    assert "def validated_fact_view(" in analysis_source
    assert "def capture_maturity_facts(" not in analysis_source
    assert "def collect_and_analyze(" not in analysis_source
    assert "def load_or_analyze(" not in analysis_source

    assert "self._analysis_runtime" not in adapter_source
    assert "validated_fact_view_provider" in adapter_source
    assert "planner_outcome_callback" in adapter_source
