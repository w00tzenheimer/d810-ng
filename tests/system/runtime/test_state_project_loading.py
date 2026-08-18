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

import copy
import shlex

import pytest

MALFORMED = "mba-solve has unknown options: ['maturities']"


def _restore(state, index: int) -> None:
    """Put the shared singleton back on its original project."""
    try:
        state.load_project(index)
    except Exception:  # noqa: BLE001 - best effort teardown
        pass


def _activation_snapshot(state):
    """Capture identity-bearing state and mutable configuration for rollback tests."""

    manager = state.manager
    return {
        "project": state.current_project,
        "project_index": state.current_project_index,
        "ins_list": state.current_ins_rules,
        "blk_list": state.current_blk_rules,
        "known_ins": state.known_ins_rules,
        "known_blk": state.known_blk_rules,
        "pass_ids": state.last_config_v2_pass_ids,
        "runtime_snapshot": state.current_project_runtime_snapshot,
        "manager_config": manager.config,
        "manager_config_value": copy.deepcopy(manager.config),
        "manager_priors": manager.snapshot_function_analysis_priors(),
        "native_handlers": manager._native_preanalysis_handlers_installed,
        "ins_rule_configs": tuple(
            (rule, copy.deepcopy(getattr(rule, "config", None)))
            for rule in state.current_ins_rules
        ),
        "blk_rule_configs": tuple(
            (rule, copy.deepcopy(getattr(rule, "config", None)))
            for rule in state.current_blk_rules
        ),
    }


def _assert_activation_snapshot_unchanged(state, before) -> None:
    manager = state.manager
    assert state.current_project is before["project"]
    assert state.current_project_index == before["project_index"]
    assert state.current_ins_rules is before["ins_list"]
    assert state.current_blk_rules is before["blk_list"]
    assert state.known_ins_rules is before["known_ins"]
    assert state.known_blk_rules is before["known_blk"]
    assert state.last_config_v2_pass_ids == before["pass_ids"]
    assert state.current_project_runtime_snapshot is before["runtime_snapshot"]
    assert manager.config is before["manager_config"]
    assert manager.config == before["manager_config_value"]
    assert manager.snapshot_function_analysis_priors() == before["manager_priors"]
    assert (
        manager._native_preanalysis_handlers_installed
        == before["native_handlers"]
    )
    for rule, config in before["ins_rule_configs"] + before["blk_rule_configs"]:
        assert getattr(rule, "config", None) == config


def _load_project_with_rule(state, rules_attr: str) -> tuple[int, object]:
    """Find a real config-v2 project whose declared schedule selects a rule."""

    for index in range(len(state.project_manager)):
        if state.load_project(index) is None:
            continue
        rules = list(getattr(state, rules_attr))
        if rules:
            return index, rules[0]
    raise AssertionError(f"no project selects a {rules_attr} rule")


class TestMalformedProjectIsSkipped:
    def test_load_project_returns_none_and_records_the_reason(
        self, d810_state, monkeypatch
    ) -> None:
        with d810_state() as state:
            original_index = state.current_project_index
            assert len(state.project_manager) > 1
            bad_index = 0
            bad_name = state.project_manager.get(bad_index).path.name
            real_activate = state._activate_project

            def _boom(**kwargs):
                if kwargs["project_index"] == bad_index:
                    raise ValueError(MALFORMED)
                return real_activate(**kwargs)

            monkeypatch.setattr(state, "_activate_project", _boom)
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
            real_activate = state._activate_project

            def _boom(**kwargs):
                if kwargs["project_index"] == bad_index:
                    raise ValueError(MALFORMED)
                return real_activate(**kwargs)

            monkeypatch.setattr(state, "_activate_project", _boom)
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
            before_ins_rules = list(state.current_ins_rules)
            before_snapshot = state.current_project_runtime_snapshot
            before_pass_ids = state.last_config_v2_pass_ids
            bad_index = 0 if original_index != 0 else 1

            import d810.manager.state as state_mod

            def _boom(_project):
                raise ValueError(MALFORMED)

            monkeypatch.setattr(state_mod, "compile_config_v2_hook_schedule", _boom)
            try:
                assert state.load_project(bad_index) is None
                assert state.current_project is before_project
                assert state.current_project_index == original_index
                assert list(state.current_blk_rules) == before_blk_rules
                assert list(state.current_ins_rules) == before_ins_rules
                assert state.current_project_runtime_snapshot is before_snapshot
                assert state.last_config_v2_pass_ids == before_pass_ids
                bad_path = state.project_manager.get(bad_index).path
                assert (
                    f"migrate with: {shlex.join(('python', 'tools/migrations/migrate_project_config_v2.py', str(bad_path), '--in-place'))}"
                    in state.invalid_projects[bad_path.name]
                )
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
            "compile_config_v2_hook_schedule",
            lambda _p: (_ for _ in ()).throw(ValueError(MALFORMED)),
        )
        try:
            assert state._load_first_valid_project(original_index) is None
            assert len(state.invalid_projects) == len(state.project_manager)
        finally:
            monkeypatch.undo()
            _restore(state, original_index)


def test_config_v2_native_spine_syncs_generated_restart_consumer(
    d810_state,
    monkeypatch,
) -> None:
    """A config-v2 native spine installs its handler and removes it on fallback."""
    with d810_state() as state:
        original_index = state.current_project_index
        native_index = state.project_manager.index("hodur_flag2.json")
        other_index = state.project_manager.index("default_instruction_only.json")
        manager = state.manager
        calls: list[str] = []
        monkeypatch.setattr(
            manager,
            "_install_native_preanalysis_handlers",
            lambda: calls.append("install"),
        )
        monkeypatch.setattr(
            manager,
            "_uninstall_native_preanalysis_handlers",
            lambda: calls.append("uninstall"),
        )
        real_configure = manager.configure

        def configure_as_live_manager(**kwargs) -> None:
            manager._started = True
            try:
                real_configure(**kwargs)
            finally:
                # This state-loading test has no licensed Hex-Rays runtime,
                # so keep later rule configuration on its inert path.
                manager._started = False

        monkeypatch.setattr(manager, "configure", configure_as_live_manager)
        try:
            assert state.load_project(native_index) is not None
            assert manager.config["config_v2_native_state_machine_active"] is True
            assert state.load_project(other_index) is not None
            assert calls == ["install", "uninstall"]
        finally:
            monkeypatch.undo()
            _restore(state, original_index)


def test_instruction_rule_failure_is_transactional_after_partial_mutation(
    d810_state, monkeypatch
) -> None:
    with d810_state() as state:
        original_index = state.current_project_index
        target_index, rule = _load_project_with_rule(state, "current_ins_rules")
        before = _activation_snapshot(state)
        lifecycle_events: list[str] = []
        scope_events: list[str] = []
        import d810.manager.state as state_mod

        monkeypatch.setattr(
            state_mod,
            "emit_project_reloading",
            lambda **kwargs: lifecycle_events.append("reloading"),
        )
        monkeypatch.setattr(
            state.manager,
            "emit_execution_scope_invalidation",
            lambda *args, **kwargs: scope_events.append("invalidated"),
        )

        def mutate_then_fail(self, config):
            self.config = {"poisoned": True}
            raise RuntimeError("instruction rule staging failure")

        monkeypatch.setattr(type(rule), "configure", mutate_then_fail)
        try:
            assert state.load_project(target_index) is None
            _assert_activation_snapshot_unchanged(state, before)
            assert lifecycle_events == []
            assert scope_events == []
        finally:
            monkeypatch.undo()
            _restore(state, original_index)


def test_block_rule_failure_is_transactional_after_partial_mutation(
    d810_state, monkeypatch
) -> None:
    with d810_state() as state:
        original_index = state.current_project_index
        target_index, rule = _load_project_with_rule(state, "current_blk_rules")
        before = _activation_snapshot(state)
        lifecycle_events: list[str] = []
        scope_events: list[str] = []
        import d810.manager.state as state_mod

        monkeypatch.setattr(
            state_mod,
            "emit_project_reloading",
            lambda **kwargs: lifecycle_events.append("reloading"),
        )
        monkeypatch.setattr(
            state.manager,
            "emit_execution_scope_invalidation",
            lambda *args, **kwargs: scope_events.append("invalidated"),
        )

        def mutate_then_fail(self, config):
            self.config = {"poisoned": True}
            raise RuntimeError("block rule staging failure")

        monkeypatch.setattr(type(rule), "configure", mutate_then_fail)
        try:
            assert state.load_project(target_index) is None
            _assert_activation_snapshot_unchanged(state, before)
            assert lifecycle_events == []
            assert scope_events == []
        finally:
            monkeypatch.undo()
            _restore(state, original_index)


def test_manager_configuration_failure_rolls_back_partial_mutation(
    d810_state, monkeypatch
) -> None:
    with d810_state() as state:
        original_index = state.current_project_index
        before = _activation_snapshot(state)
        lifecycle_events: list[str] = []
        scope_events: list[str] = []
        import d810.manager.state as state_mod

        monkeypatch.setattr(
            state_mod,
            "emit_project_reloading",
            lambda **kwargs: lifecycle_events.append("reloading"),
        )
        monkeypatch.setattr(
            state.manager,
            "emit_execution_scope_invalidation",
            lambda *args, **kwargs: scope_events.append("invalidated"),
        )
        real_configure = state.manager.configure

        def mutate_then_fail(**kwargs):
            real_configure(**kwargs)
            state.manager.config["poisoned"] = True
            raise RuntimeError("manager staging failure")

        monkeypatch.setattr(state.manager, "configure", mutate_then_fail)
        try:
            assert state.load_project(original_index) is None
            _assert_activation_snapshot_unchanged(state, before)
            assert lifecycle_events == []
            assert scope_events == []
        finally:
            monkeypatch.undo()
            _restore(state, original_index)


def test_started_optimizer_configuration_failure_rolls_back_everything(
    d810_state, monkeypatch
) -> None:
    with d810_state() as state:
        original_index = state.current_project_index
        target_index, _rule = _load_project_with_rule(state, "current_ins_rules")
        manager = state.manager
        previous_started = manager._started
        previous_instruction_optimizer = getattr(manager, "instruction_optimizer", None)
        previous_block_optimizer = getattr(manager, "block_optimizer", None)

        class _Optimizer:
            def configure(self, **kwargs):
                return None

            def replace_rules(self, rules):
                return None

        manager._started = True
        manager.instruction_optimizer = _Optimizer()
        manager.block_optimizer = _Optimizer()
        before = _activation_snapshot(state)
        lifecycle_events: list[str] = []
        scope_events: list[str] = []
        import d810.manager.state as state_mod

        monkeypatch.setattr(
            state_mod,
            "emit_project_reloading",
            lambda **kwargs: lifecycle_events.append("reloading"),
        )
        monkeypatch.setattr(
            state.manager,
            "emit_execution_scope_invalidation",
            lambda *args, **kwargs: scope_events.append("invalidated"),
        )
        optimizer = manager.instruction_optimizer
        real_configure = optimizer.configure

        def mutate_then_fail(**kwargs):
            real_configure(**kwargs)
            optimizer._execution_scope_project_name = "poisoned"
            raise RuntimeError("started optimizer staging failure")

        monkeypatch.setattr(optimizer, "configure", mutate_then_fail)
        try:
            assert state.load_project(target_index) is None
            _assert_activation_snapshot_unchanged(state, before)
            assert lifecycle_events == []
            assert scope_events == []
            assert getattr(optimizer, "_execution_scope_project_name", None) != "poisoned"
        finally:
            manager._started = previous_started
            if previous_instruction_optimizer is None:
                del manager.instruction_optimizer
            else:
                manager.instruction_optimizer = previous_instruction_optimizer
            if previous_block_optimizer is None:
                del manager.block_optimizer
            else:
                manager.block_optimizer = previous_block_optimizer
            monkeypatch.undo()
            _restore(state, original_index)


def test_execution_scope_compilation_failure_rolls_back_runtime_state(
    d810_state, monkeypatch
) -> None:
    with d810_state() as state:
        original_index = state.current_project_index
        target_index, _rule = _load_project_with_rule(state, "current_ins_rules")
        manager = state.manager
        previous_started = manager._started
        previous_instruction_optimizer = getattr(manager, "instruction_optimizer", None)
        previous_block_optimizer = getattr(manager, "block_optimizer", None)

        class _Optimizer:
            def configure(self, **kwargs):
                return None

            def replace_rules(self, rules):
                return None

        manager._started = True
        manager.instruction_optimizer = _Optimizer()
        manager.block_optimizer = _Optimizer()
        before = _activation_snapshot(state)
        generation_before = manager.execution_scope_service.generation
        lifecycle_events: list[str] = []
        scope_events: list[str] = []
        import d810.manager.state as state_mod

        monkeypatch.setattr(
            state_mod,
            "emit_project_reloading",
            lambda **kwargs: lifecycle_events.append("reloading"),
        )
        monkeypatch.setattr(
            manager,
            "emit_execution_scope_invalidation",
            lambda *args, **kwargs: scope_events.append("invalidated"),
        )

        def mutate_then_fail():
            manager.execution_scope_service._generation = 999
            raise RuntimeError("execution scope compilation failure")

        monkeypatch.setattr(manager, "_compile_execution_scope", mutate_then_fail)
        try:
            assert state.load_project(target_index) is None
            _assert_activation_snapshot_unchanged(state, before)
            assert manager.execution_scope_service.generation == generation_before
            assert lifecycle_events == []
            assert scope_events == []
        finally:
            manager._started = previous_started
            if previous_instruction_optimizer is None:
                del manager.instruction_optimizer
            else:
                manager.instruction_optimizer = previous_instruction_optimizer
            if previous_block_optimizer is None:
                del manager.block_optimizer
            else:
                manager.block_optimizer = previous_block_optimizer
            monkeypatch.undo()
            _restore(state, original_index)


@pytest.mark.parametrize("index", [0])
def test_invalid_projects_starts_empty(d810_state, index: int) -> None:
    with d810_state() as state:
        assert isinstance(state.invalid_projects, dict)
