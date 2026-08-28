"""IDA-runtime lifecycle coverage for the Task 6 host-owned sink."""

from __future__ import annotations

from pathlib import Path

import pytest

import d810.manager.manager as manager_module
from d810.manager import D810Manager


def test_construct_stop_then_construct_again(tmp_path: Path) -> None:
    first = D810Manager(log_dir=tmp_path / "first")
    try:
        first.stop()
        second = D810Manager(log_dir=tmp_path / "second")
    finally:
        first.stop()
        if "second" in locals():
            second.stop()


def test_second_live_manager_is_refused(tmp_path: Path) -> None:
    first = D810Manager(log_dir=tmp_path / "first")
    try:
        with pytest.raises(ValueError, match="already registered"):
            D810Manager(log_dir=tmp_path / "second")
    finally:
        first.stop()


def test_full_cleanup_and_activation_release_order(tmp_path: Path) -> None:
    manager = D810Manager(log_dir=tmp_path)
    order: list[str] = []
    close_activations = manager.backend_registry.close_activations
    original_release = manager._release_mba_residual_observation
    lease = manager._mba_residual_observation_lease
    sink = manager._mba_residual_observation_sink
    assert lease is not None
    assert sink is not None

    def close_plugins() -> None:
        order.append("activations")
        close_activations()

    def release() -> None:
        order.append("lease")
        original_release()

    sink_close = sink.close

    def close_sink() -> None:
        order.append("sink")
        sink_close()

    manager.backend_registry.close_activations = close_plugins
    manager._release_mba_residual_observation = release
    sink.close = close_sink
    try:
        errors = manager.stop(full_cleanup=True)
        assert errors == ()
        assert order == ["activations", "lease", "sink"]
    finally:
        manager.backend_registry.close_activations = close_activations


def test_partial_construction_unwinds_capability(monkeypatch, tmp_path: Path) -> None:
    original = manager_module.ProfilingController

    def fail(*_args, **_kwargs):
        raise RuntimeError("construction failed")

    monkeypatch.setattr(manager_module, "ProfilingController", fail)
    with pytest.raises(RuntimeError, match="construction failed"):
        D810Manager(log_dir=tmp_path)
    monkeypatch.setattr(manager_module, "ProfilingController", original)
    manager = D810Manager(log_dir=tmp_path / "recovered")
    manager.stop()


def test_start_stop_restart_releases_and_reacquires_sink(
    monkeypatch, tmp_path: Path
) -> None:
    class NoopOptimizer:
        def __init__(self, *_args, **_kwargs):
            pass

        def configure(self, **_kwargs):
            pass

        def add_rule(self, _rule):
            pass

        def configure_validated_fact_view_provider(self, _provider):
            pass

        def remove(self):
            pass

    class NoopHook:
        def __init__(self, *_args, **_kwargs):
            pass

        def unhook(self):
            pass

    monkeypatch.setattr(manager_module, "InstructionOptimizerManager", NoopOptimizer)
    monkeypatch.setattr(manager_module, "BlockOptimizerManager", NoopOptimizer)
    monkeypatch.setattr(manager_module, "CtreeOptimizerManager", NoopOptimizer)
    monkeypatch.setattr(manager_module, "HexraysDecompilationHook", NoopHook)
    manager = D810Manager(log_dir=tmp_path)
    try:
        manager._install_pre_hexrays_preparation = lambda: None
        manager._install_native_writer_migration = lambda: None
        manager._compile_execution_scope = lambda: None
        manager._install_hooks = lambda: None
        manager.start()
        manager.stop()
        manager.start()
    finally:
        manager.stop()
