"""Regression coverage for replacing the state-owned D810 manager."""

from __future__ import annotations

import pytest

import d810.manager.manager as manager_module
from d810.manager import D810State


def _stop_state(state: D810State) -> None:
    state.unload(gui=False)


def test_load_releases_old_manager_before_acquiring_a_fresh_lease() -> None:
    state = D810State()
    try:
        # A prior lifecycle test may leave the singleton's manager unloaded.
        # Establish a fresh live manager before capturing the manager whose
        # cleanup order this test observes.
        state.reset()
        old_manager = state.manager
        old_lease = old_manager._mba_residual_observation_lease
        old_sink = old_manager._mba_residual_observation_sink
        assert old_lease is not None
        assert old_sink is not None
        order: list[str] = []

        close_activations = old_manager.backend_registry.close_activations
        release_observation = old_manager._release_mba_residual_observation
        close_sink = old_sink.close

        def close_plugins() -> None:
            order.append("activations")
            close_activations()

        def release() -> None:
            order.append("lease")
            release_observation()

        def close_store() -> None:
            order.append("store")
            close_sink()

        old_manager.backend_registry.close_activations = close_plugins
        old_manager._release_mba_residual_observation = release
        old_sink.close = close_store
        state.load(gui=False)
        new_manager = state.manager
        assert new_manager is not old_manager
        assert old_manager._mba_residual_observation_lease is None
        assert old_manager._mba_residual_observation_sink is None
        assert new_manager._mba_residual_observation_lease is not old_lease
        assert new_manager._mba_residual_observation_lease is not None
        assert order == ["activations", "lease", "store"]
    finally:
        _stop_state(state)


def test_reset_failure_leaves_a_recoverable_closed_manager(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = D810State()
    old_manager = state.manager

    def fail(*_args, **_kwargs):
        raise RuntimeError("replacement construction failed")

    monkeypatch.setattr(manager_module, "D810Manager", fail)
    try:
        with pytest.raises(RuntimeError, match="replacement construction failed"):
            state.reset()
        assert state.manager is old_manager
        assert old_manager._mba_residual_observation_lease is None
        assert old_manager._mba_residual_observation_sink is None
    finally:
        monkeypatch.undo()

    state.reset()
    assert state.manager is not old_manager
    assert state.manager._mba_residual_observation_lease is not None
    _stop_state(state)


def test_repeated_load_and_unload_are_idempotent() -> None:
    state = D810State()
    state.load(gui=False)
    first_replacement = state.manager
    state.load(gui=False)
    second_replacement = state.manager
    assert second_replacement is not first_replacement
    assert second_replacement._mba_residual_observation_lease is not None

    state.unload(gui=False)
    state.unload(gui=False)
