"""Real-IDAPython lifecycle coverage for manager SCCP/cache ownership."""

from __future__ import annotations

import logging

import pytest

from d810.core import MOP_CONSTANT_CACHE, MOP_TO_AST_CACHE
from d810.core.decompilation_session import DecompilationSessionEvent
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
) -> DecompilationSessionEvent:
    return DecompilationSessionEvent(
        function_ea=function_ea,
        database_identity=database_identity,
        top_level_epoch=top_level_epoch,
    )


def _manager(calls: _CallLog):
    manager = object.__new__(manager_module.D810Manager)
    manager.stats = _OptimizationStats(calls)
    manager.instruction_optimizer = _InstructionOptimizer(calls)
    manager.block_optimizer = _BlockOptimizer(calls)
    manager.start_profiling = lambda _event: calls.record("profiling.start")
    manager.stop_profiling = lambda _event=None: calls.record("profiling.stop")
    manager._start_timer = lambda: calls.record("timer.start")
    manager._stop_timer = lambda report=True: calls.record("timer.stop")
    manager._started = False
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
    logger = manager_module.logger
    logger.addHandler(handler)
    previous_level = logger.level
    logger.setLevel(logging.INFO)
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
        assert not handler.records
        assert stats.requests == 2
        assert MOP_CONSTANT_CACHE.stats.lookups == 1
        assert MOP_TO_AST_CACHE.stats.lookups == 1

        manager._on_session_finished(outer)
        assert calls.events.count("profiling.start") == 1
        assert calls.events.count("profiling.stop") == 1
        assert len(handler.records) == 1
        aggregate = handler.records[0].args
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
    manager._on_session_started(_event())
    manager._on_session_finished(_event())

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

    manager._on_session_started(_event())
    manager._on_session_finished(_event())

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

    manager._on_session_started(_event())
    manager._on_session_finished(_event())

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
