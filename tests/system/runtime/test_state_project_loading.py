"""Malformed project configs are skipped, never fatal (ticket lpccp-8c87).

``D810State.load()`` enumerates every project file in the config directory, so a
single malformed one used to abort the whole load: the plugin ended up with NO
project rather than skipping the bad file.  The observed trigger was a
user-local config whose ``mba-solve`` entry carried ``maturities`` inside
``options`` (the schema puts it in a per-pass ``maturity_gates``), which made
``parse_mba_solve_options`` raise all the way out of ``load()``.

IDA-dependent (``D810State`` pulls in the live manager) -> system/runtime.
"""

from __future__ import annotations

import pytest

MALFORMED = "mba-solve has unknown options: ['maturities']"


def _restore(state, index: int) -> None:
    """Put the shared singleton back on its original project."""
    try:
        state.load_project(index)
    except Exception:  # noqa: BLE001 - best effort teardown
        pass


class TestMalformedProjectIsSkipped:
    def test_load_project_returns_none_and_records_the_reason(
        self, d810_state, monkeypatch
    ) -> None:
        with d810_state() as state:
            original_index = state.current_project_index
            assert len(state.project_manager) > 1
            bad_index = 0
            bad_name = state.project_manager.get(bad_index).path.name
            real_activate = state._activate_runtime_project

            def _boom(**kwargs):
                if kwargs["project_index"] == bad_index:
                    raise ValueError(MALFORMED)
                return real_activate(**kwargs)

            monkeypatch.setattr(state, "_activate_runtime_project", _boom)
            try:
                assert state.load_project(bad_index) is None
                assert bad_name in state.invalid_projects
                assert "maturities" in state.invalid_projects[bad_name]
            finally:
                monkeypatch.undo()
                _restore(state, original_index)

    def test_load_falls_back_to_the_first_valid_project(
        self, d810_state, monkeypatch
    ) -> None:
        """A malformed preferred index must not leave the plugin idle."""
        with d810_state() as state:
            original_index = state.current_project_index
            bad_index = 0
            bad_name = state.project_manager.get(bad_index).path.name
            real_activate = state._activate_runtime_project

            def _boom(**kwargs):
                if kwargs["project_index"] == bad_index:
                    raise ValueError(MALFORMED)
                return real_activate(**kwargs)

            monkeypatch.setattr(state, "_activate_runtime_project", _boom)
            try:
                fallback = state._load_first_valid_project(bad_index)
                assert fallback is not None
                assert fallback.path.name != bad_name
            finally:
                monkeypatch.undo()
                _restore(state, original_index)

    def test_a_failed_activation_leaves_the_previous_project_intact(
        self, d810_state, monkeypatch
    ) -> None:
        """Activation validates before it mutates, so a skip is not half-applied."""
        with d810_state() as state:
            original_index = state.current_project_index
            before_project = state.current_project
            before_blk_rules = list(state.current_blk_rules)
            bad_index = 0 if original_index != 0 else 1

            import d810.manager.state as state_mod

            def _boom(_runtime_project):
                raise ValueError(MALFORMED)

            monkeypatch.setattr(state_mod, "pipeline_v2_hook_activation", _boom)
            try:
                assert state.load_project(bad_index) is None
                assert state.current_project is before_project
                assert state.current_project_index == original_index
                assert list(state.current_blk_rules) == before_blk_rules
            finally:
                monkeypatch.undo()
                _restore(state, original_index)

    def test_a_valid_project_clears_a_stale_invalid_marker(
        self, d810_state, monkeypatch
    ) -> None:
        with d810_state() as state:
            original_index = state.current_project_index
            name = state.project_manager.get(original_index).path.name
            state.invalid_projects[name] = "stale reason"
            try:
                assert state.load_project(original_index) is not None
                assert name not in state.invalid_projects
            finally:
                _restore(state, original_index)


def test_load_first_valid_project_returns_none_when_everything_is_broken(
    d810_state, monkeypatch
) -> None:
    with d810_state() as state:
        original_index = state.current_project_index
        import d810.manager.state as state_mod

        monkeypatch.setattr(
            state_mod,
            "pipeline_v2_hook_activation",
            lambda _p: (_ for _ in ()).throw(ValueError(MALFORMED)),
        )
        try:
            assert state._load_first_valid_project(original_index) is None
            assert len(state.invalid_projects) == len(state.project_manager)
        finally:
            monkeypatch.undo()
            _restore(state, original_index)


@pytest.mark.parametrize("index", [0])
def test_invalid_projects_starts_empty(d810_state, index: int) -> None:
    with d810_state() as state:
        assert isinstance(state.invalid_projects, dict)
