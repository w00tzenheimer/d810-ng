"""Real-IDAPython lifecycle coverage for manager SCCP/cache ownership."""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

from d810.core import MOP_CONSTANT_CACHE, MOP_TO_AST_CACHE
from d810.core.decompilation_session import DecompilationSessionEvent
from d810.core.execution_journal import DecompilationSessionId
from d810.core.events import EventEmitter
from d810.core.execution_scope import ExecutionScopeEvent, ExecutionScopeService
from d810.evaluator.hexrays_microcode.sccp import sccp_session_stats
import d810.manager.manager as manager_module


class _CallLog:
    def __init__(self, failures: set[str] | None = None) -> None:
        self.events: list[str] = []
        self.failures = set(failures or ())

    def record(self, name: str) -> None:
        self.events.append(name)
        if name in self.failures:
            raise RuntimeError(name + " failed")


class _OptimizationStats:
    def __init__(self, calls: _CallLog) -> None:
        self._calls = calls

    def reset(self) -> None:
        self._calls.record("optimization.reset")

    def report(self) -> None:
        self._calls.record("optimization.report")


class _InstructionOptimizer:
    def __init__(self, calls: _CallLog) -> None:
        self._calls = calls

    def reset_cycle_detection(self) -> None:
        self._calls.record("instruction.cycles")

    def reset_run_later_state(self) -> None:
        self._calls.record("instruction.run_later")

    def remove(self) -> None:
        self._calls.record("instruction.remove")


class _BlockOptimizer:
    def __init__(self, calls: _CallLog) -> None:
        self._calls = calls

    def reset_pass_counter(self) -> None:
        self._calls.record("block.pass_counter")

    def reset_pipeline_tracker(self) -> None:
        self._calls.record("block.pipeline")

    def reset_perf_counters(self) -> None:
        self._calls.record("block.perf_reset")

    def report_perf_counters(self) -> None:
        self._calls.record("block.perf_report")

    def remove(self) -> None:
        self._calls.record("block.remove")


class _Hook:
    def __init__(self, calls: _CallLog) -> None:
        self._calls = calls
        self.unhooked = False

    def unhook(self) -> None:
        self.unhooked = True
        self._calls.record("hook.unhook")


class _EventEmitter:
    def __init__(self, calls: _CallLog) -> None:
        self._calls = calls
        self.cleared = False

    def clear(self) -> None:
        self.cleared = True
        self._calls.record("event.clear")


class _ExecutionScopeService:
    def __init__(self, calls: _CallLog) -> None:
        self._calls = calls

    def detach(self) -> None:
        self._calls.record("execution_scope.detach")


class _StorageRuntime:
    def __init__(self, calls: _CallLog) -> None:
        self._calls = calls
        self.closed = False

    def close(self) -> None:
        self.closed = True
        self._calls.record("storage.close")


class _AnalysisRuntime:
    def __init__(self, calls: _CallLog) -> None:
        self._calls = calls

    def flush_active_session(self) -> None:
        self._calls.record("analysis.flush")


class _Closeable:
    def __init__(self, calls: _CallLog, name: str) -> None:
        self._calls = calls
        self._name = name
        self.closed = False

    def close(self) -> None:
        self.closed = True
        self._calls.record(self._name)


class _BackendRegistry:
    def __init__(self, calls: _CallLog) -> None:
        self._calls = calls

    def close_activations(self) -> None:
        self._calls.record("plugin activations.close")


class _LogHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.INFO)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def _event(
    *,
    function_ea: int = 0x1000,
    database_identity: str = "runtime",
    top_level_epoch: int = 1,
    session_id: DecompilationSessionId | None = None,
) -> DecompilationSessionEvent:
    kwargs = {
        "function_ea": function_ea,
        "database_identity": database_identity,
        "top_level_epoch": top_level_epoch,
    }
    if session_id is not None:
        kwargs["session_id"] = session_id
    return DecompilationSessionEvent(**kwargs)


def _manager(calls: _CallLog, *, started: bool = False):
    manager = object.__new__(manager_module.D810Manager)
    manager.stats = _OptimizationStats(calls)
    manager.instruction_optimizer = _InstructionOptimizer(calls)
    manager.block_optimizer = _BlockOptimizer(calls)
    manager.hx_decompiler_hook = _Hook(calls)
    manager.start_profiling = lambda _event: calls.record("profiling.start")
    manager.stop_profiling = lambda _event=None: calls.record("profiling.stop")
    manager._start_timer = lambda: calls.record("timer.start")
    manager._stop_timer = lambda report=True: calls.record("timer.stop")
    manager._started = started
    manager._native_preanalysis_handlers_installed = True
    manager._uninstall_native_preanalysis_handlers = lambda: calls.record(
        "native.handlers.uninstall"
    )
    manager._analysis_runtime = _AnalysisRuntime(calls)
    manager._analysis_bundle = _Closeable(calls, "analysis.bundle.close")
    manager._native_patch_journal = _Closeable(calls, "native.patch.close")
    manager._native_patch_execution_journal = _Closeable(
        calls,
        "native.exec.close",
    )
    manager.backend_registry = _BackendRegistry(calls)
    manager._native_patch_gateway = None
    manager._dead_edge_normalizer = None
    manager.event_emitter = _EventEmitter(calls)
    manager.execution_scope_service = _ExecutionScopeService(calls)
    manager.function_storage_runtime = _StorageRuntime(calls)
    manager.decompilation_lifecycle = None
    manager._post_d810_runtime = None
    manager._recon_phase = None
    manager._recon_runtime = None
    manager._recon_bundle = None
    manager._flowgraph_ready_subscriber = None
    return manager


@pytest.fixture(autouse=True)
def _clear_global_session_state():
    MOP_CONSTANT_CACHE.clear(reset_stats=True)
    MOP_TO_AST_CACHE.clear(reset_stats=True)
    sccp_session_stats().reset()
    yield
    MOP_CONSTANT_CACHE.clear(reset_stats=True)
    MOP_TO_AST_CACHE.clear(reset_stats=True)
    sccp_session_stats().reset()


def test_nested_callbacks_keep_one_session_and_one_aggregate() -> None:
    calls = _CallLog()
    manager = _manager(calls)
    outer = _event()
    nested = _event()
    handler = _LogHandler()
    handler.setLevel(logging.DEBUG)
    logger = manager_module.logger
    logger.addHandler(handler)
    previous_level = logger.level
    logger.setLevel(logging.DEBUG)
    try:
        manager._on_session_started(outer)
        sccp_session_stats().requests = 1
        MOP_CONSTANT_CACHE["outer"] = 1
        MOP_CONSTANT_CACHE.lookup("outer")

        manager._on_session_started(nested)
        assert sccp_session_stats().requests == 1
        assert MOP_CONSTANT_CACHE.stats.lookups == 1

        stats = sccp_session_stats()
        stats.requests = 2
        stats.executions = 1
        stats.reuses = 1
        stats.fallbacks = 1
        stats.converged = 1
        stats.work_limit = 1
        stats.block_limit = 1
        stats.errors = 1
        stats.python_runs = 1
        stats.cython_runs = 1
        stats.cfg_events = 3
        stats.value_events = 4
        stats.adapter_seconds = 0.25
        stats.solver_seconds = 1.5
        stats.constants_exposed = 2
        stats.edges_exposed = 5
        MOP_TO_AST_CACHE["outer"] = 1
        MOP_TO_AST_CACHE.lookup("outer")
        manager._on_session_finished(nested)
        assert "profiling.stop" not in calls.events
        start_records = [
            record
            for record in handler.records
            if record.getMessage().startswith("[D810] Decompiling ")
        ]
        assert len(start_records) == 1
        assert stats.requests == 2
        assert MOP_CONSTANT_CACHE.stats.lookups == 1
        assert MOP_TO_AST_CACHE.stats.lookups == 1

        manager._on_session_finished(outer)
        assert calls.events.count("profiling.start") == 1
        assert calls.events.count("profiling.stop") == 1
        aggregate_records = [
            record for record in handler.records if isinstance(record.args, dict)
        ]
        assert len(aggregate_records) == 1
        aggregate = aggregate_records[0].args
        assert aggregate["sccp"] == {
            "requests": 2,
            "executions": 1,
            "reuses": 1,
            "fallbacks": 1,
            "converged": 1,
            "work_limit": 1,
            "block_limit": 1,
            "errors": 1,
            "python_runs": 1,
            "cython_runs": 1,
            "cfg_events": 3,
            "value_events": 4,
            "adapter_seconds": 0.25,
            "solver_seconds": 1.5,
            "constants_exposed": 2,
            "edges_exposed": 5,
        }
        assert aggregate["mop_constant_cache"]["lookups"] == 1
        assert aggregate["mop_constant_cache"]["capacity_evictions"] == 0
        assert aggregate["mop_constant_cache"]["configured_max_size"] == 4096
        assert aggregate["mop_to_ast_cache"]["lookups"] == 1
        assert aggregate["mop_to_ast_cache"]["capacity_evictions"] == 0
        assert aggregate["mop_to_ast_cache"]["configured_max_size"] == 40960
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)


def test_out_of_order_and_duplicate_finish_do_not_wipe_active_state() -> None:
    calls = _CallLog()
    manager = _manager(calls)
    outer = _event(function_ea=0x1000)
    nested = _event(function_ea=0x2000)

    manager._on_session_started(outer)
    MOP_TO_AST_CACHE["outer"] = 1
    manager._on_session_started(nested)
    manager._on_session_finished(outer)

    assert "profiling.stop" not in calls.events
    assert len(MOP_TO_AST_CACHE) == 1

    manager._on_session_finished(nested)
    manager._on_session_finished(outer)
    assert calls.events.count("profiling.stop") == 1


def test_late_finish_from_stopped_generation_cannot_finish_new_generation() -> None:
    calls = _CallLog()
    manager = _manager(calls, started=True)
    session_a = DecompilationSessionId("session-a")
    session_b = DecompilationSessionId("session-b")
    event_a = _event(session_id=session_a)
    event_b = _event(session_id=session_b)

    manager._on_session_started(event_a)
    manager.stop()
    assert calls.events.count("profiling.stop") == 1

    manager._on_session_started(event_b)
    manager._on_session_finished(event_a)
    assert calls.events.count("profiling.stop") == 1
    assert len(manager._telemetry_lifecycle_stack) == 1

    manager._on_session_finished(event_b)
    assert calls.events.count("profiling.stop") == 2
    assert not manager._telemetry_lifecycle_stack


def test_missing_session_id_fails_closed_for_distinct_legacy_events() -> None:
    calls = _CallLog()
    manager = _manager(calls)
    legacy_a = SimpleNamespace(
        function_ea=0x1000,
        database_identity="runtime",
        top_level_epoch=1,
    )
    legacy_b = SimpleNamespace(
        function_ea=0x1000,
        database_identity="runtime",
        top_level_epoch=1,
        session_id=None,
    )

    manager._on_session_started(legacy_a)
    manager._on_session_started(legacy_b)
    assert len(manager._telemetry_lifecycle_depth) == 2
    manager._on_session_finished(legacy_a)
    assert calls.events.count("profiling.stop") == 0
    assert len(manager._telemetry_lifecycle_stack) == 2

    manager._on_session_finished(legacy_b)
    assert calls.events.count("profiling.stop") == 0
    assert len(manager._telemetry_lifecycle_stack) == 1
    manager._on_session_finished(legacy_a)
    assert calls.events.count("profiling.stop") == 1
    assert not manager._telemetry_lifecycle_stack


def test_execution_scope_detach_is_idempotent_and_rebinds_once() -> None:
    service = ExecutionScopeService()
    emitter = EventEmitter()
    unrelated_calls: list[object] = []

    def unrelated(payload=None) -> None:
        unrelated_calls.append(payload)

    service.attach(emitter)
    service.attach(emitter)
    for event in ExecutionScopeEvent:
        assert len(emitter._listeners[event]) == 1
        emitter.on(event, unrelated)

    service.detach()
    service.detach()
    for event in ExecutionScopeEvent:
        assert service._on_event not in emitter._listeners[event]
        assert unrelated in emitter._listeners[event]

    service.attach(emitter)
    service.attach(emitter)
    for event in ExecutionScopeEvent:
        assert len(emitter._listeners[event]) == 2


def test_stop_detaches_execution_scope_before_clearing_emitter() -> None:
    calls = _CallLog()
    manager = _manager(calls, started=True)

    manager.stop()

    assert calls.events.index("execution_scope.detach") < calls.events.index(
        "event.clear"
    )
    assert calls.events.count("execution_scope.detach") == 1


def test_manager_stop_allows_execution_scope_rebind_after_emitter_clear() -> None:
    calls = _CallLog()
    manager = _manager(calls, started=True)
    emitter = EventEmitter()
    service = ExecutionScopeService()
    manager.event_emitter = emitter
    manager.execution_scope_service = service

    service.attach(emitter)
    service.attach(emitter)
    assert all(len(emitter._listeners[event]) == 1 for event in ExecutionScopeEvent)

    manager.stop()

    assert all(not emitter._listeners[event] for event in ExecutionScopeEvent)
    service.detach()
    service.attach(emitter)
    service.attach(emitter)
    assert all(len(emitter._listeners[event]) == 1 for event in ExecutionScopeEvent)


def test_stop_clears_closed_runtime_owners_and_preanalysis_fails_closed() -> None:
    calls = _CallLog()
    manager = _manager(calls, started=True)

    class _ClosedLifecycle:
        def ensure_hexrays_session(self, **_kwargs):
            raise AssertionError("closed lifecycle was reused")

    manager.decompilation_lifecycle = _ClosedLifecycle()
    manager._post_d810_runtime = object()
    manager._recon_phase = object()
    manager._recon_runtime = object()
    manager._recon_bundle = object()
    manager._flowgraph_ready_subscriber = object()
    manager._stage_c_topology_consumer = object()

    manager.stop()

    assert manager.decompilation_lifecycle is None
    assert manager._post_d810_runtime is None
    assert manager._recon_phase is None
    assert manager._recon_runtime is None
    assert manager._recon_bundle is None
    assert manager._flowgraph_ready_subscriber is None
    assert manager._stage_c_topology_consumer is None
    assert manager.prepare_native_preanalysis(0x1000) == 0
    with pytest.raises(RuntimeError, match="not started"):
        manager.decompile_with_native_preanalysis(
            0x1000,
            lambda: None,
            lambda: None,
        )


def test_finish_cleanup_continues_after_each_individual_failure() -> None:
    calls = _CallLog(
        {
            "profiling.stop",
            "optimization.report",
            "block.perf_report",
            "timer.stop",
        }
    )
    manager = _manager(calls)
    event = _event()
    manager._on_session_started(event)
    with pytest.raises(RuntimeError, match="profiling.stop failed"):
        manager._on_session_finished(event)

    assert {
        "profiling.stop",
        "optimization.report",
        "block.perf_report",
        "timer.stop",
    } <= set(calls.events)
    assert not manager._telemetry_lifecycle_stack

    manager._on_session_started(_event(top_level_epoch=2))
    assert calls.events.count("profiling.start") == 2


def test_stats_collection_failure_still_releases_lifecycle(monkeypatch) -> None:
    calls = _CallLog()
    manager = _manager(calls)

    def fail_summary() -> dict[str, object]:
        raise RuntimeError("stats unavailable")

    monkeypatch.setattr(manager_module, "_session_telemetry_summary", fail_summary)

    event = _event()
    manager._on_session_started(event)
    manager._on_session_finished(event)

    assert calls.events.count("profiling.stop") == 1
    assert calls.events.count("optimization.report") == 1
    assert calls.events.count("block.perf_report") == 1
    assert calls.events.count("timer.stop") == 1
    assert not manager._telemetry_lifecycle_stack


def test_logging_failure_still_releases_lifecycle(monkeypatch) -> None:
    calls = _CallLog()
    manager = _manager(calls)

    def fail_logging(*_args) -> None:
        raise RuntimeError("logging unavailable")

    monkeypatch.setattr(manager_module.logger, "info", fail_logging)

    event = _event()
    manager._on_session_started(event)
    manager._on_session_finished(event)

    assert calls.events.count("profiling.stop") == 1
    assert calls.events.count("optimization.report") == 1
    assert calls.events.count("block.perf_report") == 1
    assert calls.events.count("timer.stop") == 1
    assert not manager._telemetry_lifecycle_stack


def test_stop_discards_active_ownership_and_allows_next_session() -> None:
    calls = _CallLog()
    manager = _manager(calls)
    manager._on_session_started(_event())
    sccp_session_stats().requests = 9
    MOP_CONSTANT_CACHE["active"] = 1

    manager.stop()

    assert not manager._telemetry_lifecycle_stack
    assert not manager._telemetry_lifecycle_depth

    manager._on_session_started(_event(top_level_epoch=2))
    assert sccp_session_stats().requests == 0
    assert len(MOP_CONSTANT_CACHE) == 0


def test_stop_cleanup_continues_after_failures_and_recovers() -> None:
    calls = _CallLog({"profiling.stop", "timer.stop"})
    manager = _manager(calls)
    manager._on_session_started(_event())

    manager.stop()

    assert calls.events.count("profiling.stop") == 1
    assert calls.events.count("timer.stop") == 1
    assert not manager._telemetry_lifecycle_stack
    assert not manager._telemetry_lifecycle_depth

    manager._on_session_started(_event(top_level_epoch=2))
    assert calls.events.count("profiling.start") == 2


def test_native_handler_registration_helpers_are_reversible(monkeypatch) -> None:
    calls = _CallLog()
    manager = _manager(calls)

    import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as resolver

    monkeypatch.setattr(
        resolver,
        "install",
        lambda: calls.record("native.handlers.install"),
    )
    monkeypatch.setattr(
        resolver,
        "uninstall",
        lambda: calls.record("native.handlers.uninstall"),
    )

    manager._install_native_preanalysis_handlers()
    manager._uninstall_native_preanalysis_handlers()

    assert calls.events.count("native.handlers.install") == 1
    assert calls.events.count("native.handlers.uninstall") == 1


@pytest.mark.parametrize(
    "failure",
    [
        "instruction.remove",
        "event.clear",
        "analysis.bundle.close",
        "native.handlers.uninstall",
    ],
)
def test_started_stop_attempts_every_cleanup_step(
    monkeypatch,
    failure: str,
) -> None:
    calls = _CallLog({failure})
    manager = _manager(calls, started=True)

    import d810.manager.hexrays_frontend_normalization as frontend_module
    import d810.hexrays.preanalysis.indirect_jump_labels as labels_module

    monkeypatch.setattr(
        frontend_module,
        "uninstall_live_frontend_normalization",
        lambda: calls.record("frontend.uninstall"),
    )
    monkeypatch.setattr(
        manager_module,
        "shutdown_all_writers",
        lambda: calls.record("writers.shutdown"),
    )
    monkeypatch.setattr(
        labels_module,
        "set_indirect_materialization_default_executor",
        lambda _executor: calls.record("executor.clear"),
    )

    manager._on_session_started(_event(session_id=DecompilationSessionId("stop")))
    manager.stop()

    expected = {
        "profiling.stop",
        "timer.stop",
        "native.handlers.uninstall",
        "frontend.uninstall",
        "instruction.remove",
        "block.remove",
        "hook.unhook",
        "analysis.flush",
        "writers.shutdown",
        "event.clear",
        "executor.clear",
        "native.patch.close",
        "native.exec.close",
        "storage.close",
        "analysis.bundle.close",
        "plugin activations.close",
        "execution_scope.detach",
    }
    for name in expected:
        assert calls.events.count(name) == 1, name
    assert not manager.started
    assert not manager._telemetry_lifecycle_stack
    assert not manager._telemetry_lifecycle_depth
    if failure == "native.handlers.uninstall":
        assert manager._native_preanalysis_handlers_installed
        calls.failures.remove(failure)
        manager.stop()
        assert calls.events.count("native.handlers.uninstall") == 2
        assert not manager._native_preanalysis_handlers_installed
    else:
        assert not manager._native_preanalysis_handlers_installed
    assert manager.event_emitter.cleared
    assert manager.hx_decompiler_hook.unhooked
    assert manager.function_storage_runtime.closed
    assert manager._analysis_bundle is None
    assert manager._native_patch_journal is None
    assert manager._native_patch_execution_journal is None

    # A subsequent lifecycle callback can start cleanly after best-effort
    # teardown, even when the production stop collaborator failed.
    next_session = _event(
        top_level_epoch=2,
        session_id=DecompilationSessionId("restart"),
    )
    manager._on_session_started(next_session)
    assert sccp_session_stats().requests == 0
    manager._on_session_finished(next_session)
