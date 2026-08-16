"""Manager ownership tests for SCCP and MOP-cache session telemetry."""

from __future__ import annotations

import importlib
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from d810.core import MOP_CONSTANT_CACHE, MOP_TO_AST_CACHE
from d810.core.decompilation_session import DecompilationSessionEvent


pytest.importorskip("ida_hexrays")
manager_module = importlib.import_module("d810.manager.manager")
D810Manager = manager_module.D810Manager


@pytest.fixture(autouse=True)
def _clear_global_caches():
    original_constant = MOP_CONSTANT_CACHE.stats.configured_max_size
    original_ast = MOP_TO_AST_CACHE.stats.configured_max_size
    MOP_CONSTANT_CACHE.clear(reset_stats=True)
    MOP_TO_AST_CACHE.clear(reset_stats=True)
    yield
    MOP_CONSTANT_CACHE.reconfigure_capacity(original_constant)
    MOP_TO_AST_CACHE.reconfigure_capacity(original_ast)


def _event() -> DecompilationSessionEvent:
    return DecompilationSessionEvent(
        function_ea=0x1000,
        database_identity="unit",
        top_level_epoch=1,
    )


def _manager_for_callbacks(calls: list[str]):
    manager = object.__new__(D810Manager)
    manager.start_profiling = lambda _event: calls.append("profiling.start")
    manager.stop_profiling = lambda _event: calls.append("profiling.stop")
    manager._start_timer = lambda: calls.append("timer.start")
    manager._stop_timer = lambda: calls.append("timer.stop")
    manager.stats = SimpleNamespace(
        reset=lambda: calls.append("optimization.reset"),
        report=lambda: calls.append("optimization.report"),
    )
    manager.instruction_optimizer = SimpleNamespace(
        reset_cycle_detection=lambda: calls.append("instruction.cycles"),
        reset_run_later_state=lambda: calls.append("instruction.run_later"),
    )
    manager.block_optimizer = SimpleNamespace(
        reset_pass_counter=lambda: calls.append("block.pass_counter"),
        reset_pipeline_tracker=lambda: calls.append("block.pipeline"),
        reset_perf_counters=lambda: calls.append("block.perf_reset"),
        report_perf_counters=lambda: calls.append("block.perf_report"),
    )
    return manager


def _sccp_stats(**overrides):
    values = {
        "requests": 0,
        "executions": 0,
        "reuses": 0,
        "fallbacks": 0,
        "converged": 0,
        "work_limit": 0,
        "block_limit": 0,
        "errors": 0,
        "python_runs": 0,
        "cython_runs": 0,
        "cfg_events": 0,
        "value_events": 0,
        "adapter_seconds": 0.0,
        "solver_seconds": 0.0,
        "constants_exposed": 0,
        "edges_exposed": 0,
    }
    values.update(overrides)
    return SimpleNamespace(as_dict=lambda: dict(values))


def test_manager_start_resets_sccp_and_caches_before_profiling(monkeypatch) -> None:
    calls: list[str] = []
    manager = _manager_for_callbacks(calls)
    MOP_CONSTANT_CACHE["old"] = 1
    MOP_TO_AST_CACHE["old"] = 1
    MOP_CONSTANT_CACHE.lookup("old")
    MOP_TO_AST_CACHE.lookup("old")

    reset_sccp = Mock(side_effect=lambda: calls.append("sccp.reset"))
    monkeypatch.setattr(manager_module, "reset_sccp_session", reset_sccp)
    z3_clear = Mock(side_effect=lambda: calls.append("z3.clear"))
    monkeypatch.setattr(
        manager_module,
        "Z3MopProver",
        lambda: SimpleNamespace(clear_caches=z3_clear),
    )

    constant_clear = MOP_CONSTANT_CACHE.clear
    ast_clear = MOP_TO_AST_CACHE.clear

    def clear_constant(*, reset_stats=False):
        calls.append(f"constant.clear:{reset_stats}")
        return constant_clear(reset_stats=reset_stats)

    def clear_ast(*, reset_stats=False):
        calls.append(f"ast.clear:{reset_stats}")
        return ast_clear(reset_stats=reset_stats)

    monkeypatch.setattr(MOP_CONSTANT_CACHE, "clear", clear_constant)
    monkeypatch.setattr(MOP_TO_AST_CACHE, "clear", clear_ast)

    manager._on_session_started(_event())

    reset_sccp.assert_called_once_with()
    assert len(MOP_CONSTANT_CACHE) == 0
    assert len(MOP_TO_AST_CACHE) == 0
    assert MOP_CONSTANT_CACHE.stats.lookups == 0
    assert MOP_TO_AST_CACHE.stats.lookups == 0
    assert calls.index("sccp.reset") < calls.index("profiling.start")
    assert calls.index("constant.clear:True") < calls.index("profiling.start")
    assert calls.index("ast.clear:True") < calls.index("profiling.start")
    assert calls.count("constant.clear:True") == 1
    assert calls.count("ast.clear:True") == 1


def test_manager_finish_logs_one_coherent_sccp_and_cache_aggregate(monkeypatch) -> None:
    calls: list[str] = []
    manager = _manager_for_callbacks(calls)
    sccp_stats = _sccp_stats(
        requests=2,
        executions=1,
        reuses=1,
        fallbacks=0,
        converged=1,
        work_limit=1,
        block_limit=0,
        errors=0,
        python_runs=1,
        cython_runs=0,
        cfg_events=3,
        value_events=4,
        adapter_seconds=0.25,
        solver_seconds=1.5,
        constants_exposed=2,
        edges_exposed=5,
    )
    monkeypatch.setattr(manager_module, "sccp_session_stats", lambda: sccp_stats)
    MOP_CONSTANT_CACHE.lookup("constant")
    MOP_TO_AST_CACHE.lookup("ast")

    info_calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        manager_module.logger,
        "info",
        lambda *args: info_calls.append(args),
    )

    manager._on_session_finished(_event())

    assert len(info_calls) == 1
    message, aggregate = info_calls[0]
    assert "session" in str(message).lower()
    assert aggregate["sccp"]["requests"] == 2
    assert aggregate["sccp"]["executions"] == 1
    assert aggregate["sccp"]["reuses"] == 1
    assert aggregate["sccp"]["work_limit"] == 1
    assert aggregate["sccp"]["adapter_seconds"] == 0.25
    assert aggregate["sccp"]["solver_seconds"] == 1.5
    assert aggregate["mop_constant_cache"]["lookups"] == 1
    assert aggregate["mop_constant_cache"]["capacity_evictions"] == 0
    assert aggregate["mop_constant_cache"]["configured_max_size"] == 4096
    assert aggregate["mop_to_ast_cache"]["lookups"] == 1
    assert aggregate["mop_to_ast_cache"]["capacity_evictions"] == 0
    assert aggregate["mop_to_ast_cache"]["configured_max_size"] == 40960
    assert "profiling.stop" in calls
    assert "optimization.report" in calls
    assert "timer.stop" in calls


def test_manager_finish_keeps_lifecycle_cleanup_when_stats_collection_fails(
    monkeypatch,
) -> None:
    calls: list[str] = []
    manager = _manager_for_callbacks(calls)

    def fail_stats():
        raise RuntimeError("stats unavailable")

    monkeypatch.setattr(manager_module, "sccp_session_stats", fail_stats)
    manager._on_session_finished(_event())

    assert "profiling.stop" in calls
    assert "optimization.report" in calls
    assert "block.perf_report" in calls
    assert "timer.stop" in calls


def test_manager_finish_keeps_lifecycle_cleanup_when_logging_fails(monkeypatch) -> None:
    calls: list[str] = []
    manager = _manager_for_callbacks(calls)
    monkeypatch.setattr(manager_module, "sccp_session_stats", _sccp_stats)
    monkeypatch.setattr(
        manager_module.logger,
        "info",
        Mock(side_effect=RuntimeError("logging unavailable")),
    )

    manager._on_session_finished(_event())

    assert "profiling.stop" in calls
    assert "optimization.report" in calls
    assert "block.perf_report" in calls
    assert "timer.stop" in calls
