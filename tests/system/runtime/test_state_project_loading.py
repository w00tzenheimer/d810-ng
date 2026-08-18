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


def _capture_live_container(container):
    """Keep the object identity beside a content snapshot for rollback checks."""

    return container, copy.deepcopy(container)


def _live_container_snapshot(manager):
    service = manager.execution_scope_service
    snapshot = {
        "scope_active_cache": _capture_live_container(service._active_cache),
        "scope_metadata_cache": _capture_live_container(service._metadata_cache),
        "scope_hint_inferences": _capture_live_container(service._hint_inferences),
        "scope_hint_suppressions": _capture_live_container(
            service._hint_suppressions
        ),
        "instruction_scheduler": _capture_live_container(
            manager.instruction_pass_scheduler._pending_by_func
        ),
        "block_scheduler": _capture_live_container(
            manager.block_pass_scheduler._pending_by_func
        ),
    }
    optimizer = getattr(manager, "instruction_optimizer", None)
    for index, child in enumerate(
        tuple(getattr(optimizer, "instruction_optimizers", ()))
    ):
        for name in (
            "rules",
            "pattern_storage",
            "_indexed_storage",
            "_structural_rules_by_root_opcode",
            "_allowed_root_opcodes",
        ):
            value = getattr(child, name, None)
            if isinstance(value, (dict, list, set)):
                snapshot[f"instruction_child_{index}_{name}"] = _capture_live_container(
                    value
                )
    analyzer = getattr(optimizer, "analyzer", None)
    if analyzer is not None and isinstance(getattr(analyzer, "rules", None), set):
        snapshot["instruction_analyzer_rules"] = _capture_live_container(
            analyzer.rules
        )
    block_optimizer = getattr(manager, "block_optimizer", None)
    if block_optimizer is not None and isinstance(
        getattr(block_optimizer, "cfg_rules", None), list
    ):
        snapshot["block_cfg_rules"] = _capture_live_container(
            block_optimizer.cfg_rules
        )
    return snapshot


def _assert_live_container_snapshot(manager, snapshot) -> None:
    for key, (container, contents) in snapshot.items():
        if key.startswith("scope_"):
            name = key.removeprefix("scope_")
            current = getattr(manager.execution_scope_service, f"_{name}")
        elif key == "instruction_scheduler":
            current = manager.instruction_pass_scheduler._pending_by_func
        elif key == "block_scheduler":
            current = manager.block_pass_scheduler._pending_by_func
        elif key == "block_cfg_rules":
            current = manager.block_optimizer.cfg_rules
        elif key == "instruction_analyzer_rules":
            current = manager.instruction_optimizer.analyzer.rules
        else:
            _, _, index, name = key.split("_", 3)
            current = getattr(
                manager.instruction_optimizer.instruction_optimizers[int(index)],
                name,
            )
        assert current is container, key
        assert current == contents, key

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


def test_published_activation_isolated_from_raising_observers(
    d810_state,
) -> None:
    """Observer failures cannot invalidate or partially hide a live project."""

    with d810_state() as state:
        original_index = state.current_project_index
        target_index = 0 if original_index != 0 else 1
        target = state.project_manager.get(target_index)
        state.invalid_projects.pop(target.path.name, None)
        lifecycle_calls: list[str] = []
        scope_calls: list[str] = []

        from d810.core.project import (
            ProjectLifecycleEvent,
            subscribe_project_lifecycle,
            unsubscribe_project_lifecycle,
        )
        from d810.core.execution_scope import ExecutionScopeEvent

        def lifecycle_raiser(_payload):
            lifecycle_calls.append("raise")
            raise RuntimeError("lifecycle observer failure")

        def lifecycle_peer(_payload):
            lifecycle_calls.append("peer")

        def scope_raiser(_payload):
            scope_calls.append("raise")
            raise RuntimeError("scope observer failure")

        def scope_peer(_payload):
            scope_calls.append("peer")

        manager = state.manager
        event = ExecutionScopeEvent.PROJECT_PIPELINE_RELOADED
        subscribe_project_lifecycle(
            ProjectLifecycleEvent.PROJECT_RELOADING, lifecycle_raiser
        )
        subscribe_project_lifecycle(
            ProjectLifecycleEvent.PROJECT_RELOADING, lifecycle_peer
        )
        manager.event_emitter.on(event, scope_raiser)
        manager.event_emitter.on(event, scope_peer)
        try:
            assert state.load_project(target_index) is target
            assert state.current_project is target
            assert state.current_project_index == target_index
            assert state.current_project_runtime_snapshot.project.basename == (
                target.path.name
            )
            assert state.last_config_v2_pass_ids == (
                state.current_project_runtime_snapshot.effective_pass_ids
            )
            assert target.path.name not in state.invalid_projects
            assert set(lifecycle_calls) == {"raise", "peer"}
            assert set(scope_calls) == {"raise", "peer"}
        finally:
            unsubscribe_project_lifecycle(
                ProjectLifecycleEvent.PROJECT_RELOADING, lifecycle_raiser
            )
            unsubscribe_project_lifecycle(
                ProjectLifecycleEvent.PROJECT_RELOADING, lifecycle_peer
            )
            manager.event_emitter.remove(event, scope_raiser)
            manager.event_emitter.remove(event, scope_peer)
            _restore(state, original_index)


def test_tigress_profile_global_registries_roll_back_after_late_failure(
    d810_state, monkeypatch
) -> None:
    """Tigress candidate registration is restored when manager staging fails."""

    with d810_state() as state:
        original_index = state.current_project_index
        target_index = state.project_manager.index(
            "default_unflattening_tigress_indirect.json"
        )
        manager = state.manager
        import d810.core.project as project_module
        from d810.hexrays.preanalysis.indirect_jump_labels import (
            snapshot_indirect_materialization_registry,
        )

        before_cleanup = (
            project_module._project_reload_cleanup_handlers,
            dict(project_module._project_reload_cleanup_handlers),
        )
        before_fact_collectors = (
            project_module._preanalysis_fact_collector_registration_handlers,
            dict(project_module._preanalysis_fact_collector_registration_handlers),
        )
        before_indirect = snapshot_indirect_materialization_registry()
        real_configure = manager.configure

        def configure_then_fail(**kwargs):
            real_configure(**kwargs)
            raise RuntimeError("late manager activation failure")

        monkeypatch.setattr(manager, "configure", configure_then_fail)
        try:
            assert state.load_project(target_index) is None
            after_indirect = snapshot_indirect_materialization_registry()
            assert project_module._project_reload_cleanup_handlers is (
                before_cleanup[0]
            )
            assert project_module._project_reload_cleanup_handlers == before_cleanup[1]
            assert project_module._preanalysis_fact_collector_registration_handlers is (
                before_fact_collectors[0]
            )
            assert (
                project_module._preanalysis_fact_collector_registration_handlers
                == before_fact_collectors[1]
            )
            assert after_indirect.goto_table_ref is before_indirect.goto_table_ref
            assert after_indirect.goto_table_ref == before_indirect.goto_table_contents
            assert after_indirect.registered is before_indirect.registered
            assert after_indirect.executor is before_indirect.executor
            assert after_indirect.flowchart_registry[0] is (
                before_indirect.flowchart_registry[0]
            )
            assert after_indirect.flowchart_registry[0] == (
                before_indirect.flowchart_registry[1]
            )
        finally:
            monkeypatch.undo()
            _restore(state, original_index)


def test_active_tigress_state_survives_failed_non_tigress_switch(
    d810_state, monkeypatch
) -> None:
    """A failed profile switch restores the complete active Tigress registry set."""

    with d810_state() as state:
        original_index = state.current_project_index
        tigress_index = state.project_manager.index(
            "default_unflattening_tigress_indirect.json"
        )
        other_index = state.project_manager.index("default_instruction_only.json")
        manager = state.manager
        import d810.core.project as project_module
        import d810.hexrays.preanalysis.flowchart_preanalysis as flowchart_module
        from d810.hexrays.preanalysis.indirect_jump_labels import (
            snapshot_indirect_materialization_registry,
        )

        tigress = state.project_manager.get(tigress_index)
        other = state.project_manager.get(other_index)
        state.invalid_projects.pop(tigress.path.name, None)
        state.invalid_projects.pop(other.path.name, None)
        real_configure = manager.configure

        try:
            assert state.load_project(tigress_index) is tigress
            before_cleanup = (
                project_module._project_reload_cleanup_handlers,
                dict(project_module._project_reload_cleanup_handlers),
            )
            before_fact_collectors = (
                project_module._preanalysis_fact_collector_registration_handlers,
                dict(project_module._preanalysis_fact_collector_registration_handlers),
            )
            before_flowchart = (
                flowchart_module._FLOWCHART_PREANALYSIS_HANDLERS,
                dict(flowchart_module._FLOWCHART_PREANALYSIS_HANDLERS),
            )
            before_indirect = snapshot_indirect_materialization_registry()
            before_snapshot = state.current_project_runtime_snapshot
            before_pass_ids = state.last_config_v2_pass_ids

            def configure_then_fail(**kwargs):
                real_configure(**kwargs)
                raise RuntimeError("late non-Tigress profile failure")

            monkeypatch.setattr(manager, "configure", configure_then_fail)
            assert state.load_project(other_index) is None

            assert state.current_project is tigress
            assert state.current_project_index == tigress_index
            assert state.current_project_runtime_snapshot is before_snapshot
            assert state.last_config_v2_pass_ids is before_pass_ids
            assert project_module._project_reload_cleanup_handlers is (
                before_cleanup[0]
            )
            assert project_module._project_reload_cleanup_handlers == before_cleanup[1]
            assert project_module._preanalysis_fact_collector_registration_handlers is (
                before_fact_collectors[0]
            )
            assert (
                project_module._preanalysis_fact_collector_registration_handlers
                == before_fact_collectors[1]
            )
            assert flowchart_module._FLOWCHART_PREANALYSIS_HANDLERS is (
                before_flowchart[0]
            )
            assert flowchart_module._FLOWCHART_PREANALYSIS_HANDLERS == (
                before_flowchart[1]
            )
            after_indirect = snapshot_indirect_materialization_registry()
            assert after_indirect.goto_table_ref is before_indirect.goto_table_ref
            assert after_indirect.goto_table_ref == before_indirect.goto_table_contents
            assert after_indirect.registered is before_indirect.registered
            assert after_indirect.executor is before_indirect.executor
            assert after_indirect.flowchart_registry[0] is (
                before_indirect.flowchart_registry[0]
            )
            assert after_indirect.flowchart_registry[0] == (
                before_indirect.flowchart_registry[1]
            )
            assert other.path.name in state.invalid_projects
        finally:
            monkeypatch.undo()
            _restore(state, original_index)


def test_tigress_profile_registration_survives_successful_activation_once(
    d810_state,
) -> None:
    """A successful Tigress activation keeps one current materializer hook."""

    with d810_state() as state:
        original_index = state.current_project_index
        target_index = state.project_manager.index(
            "default_unflattening_tigress_indirect.json"
        )
        target = state.project_manager.get(target_index)
        import d810.core.project as project_module
        import d810.hexrays.preanalysis.flowchart_preanalysis as flowchart_module
        from d810.hexrays.preanalysis.indirect_jump_labels import (
            snapshot_indirect_materialization_registry,
        )

        try:
            assert state.load_project(target_index) is target
            first = snapshot_indirect_materialization_registry()
            assert first.registered is True
            assert (
                list(project_module._project_reload_cleanup_handlers).count(
                    "hexrays.indirect_jump_label_materialization"
                )
                == 1
            )
            assert (
                list(flowchart_module._FLOWCHART_PREANALYSIS_HANDLERS).count(
                    "hexrays.indirect_jump_label_materialization"
                )
                == 1
            )

            assert state.load_project(target_index) is target
            second = snapshot_indirect_materialization_registry()
            assert second.registered is True
            assert second.goto_table_ref == first.goto_table_contents
            assert (
                list(project_module._project_reload_cleanup_handlers).count(
                    "hexrays.indirect_jump_label_materialization"
                )
                == 1
            )
            assert (
                list(flowchart_module._FLOWCHART_PREANALYSIS_HANDLERS).count(
                    "hexrays.indirect_jump_label_materialization"
                )
                == 1
            )
        finally:
            _restore(state, original_index)


def test_started_activation_failure_restores_live_container_identity(
    d810_state, monkeypatch
) -> None:
    """Caches, dispatch indexes, rules, cfg lists, and schedulers stay live."""

    with d810_state() as state:
        original_index = state.current_project_index
        target_index, _rule = _load_project_with_rule(state, "current_ins_rules")
        manager = state.manager
        previous_started = manager._started
        previous_instruction_optimizer = getattr(manager, "instruction_optimizer", None)
        previous_block_optimizer = getattr(manager, "block_optimizer", None)

        class _Child:
            def __init__(self):
                self.rules = {"old-rule"}
                self.pattern_storage = {"pattern": "old"}
                self._indexed_storage = {"index": "old"}
                self._structural_rules_by_root_opcode = {"old": ["rule"]}
                self._allowed_root_opcodes = {"old"}

        class _Analyzer:
            def __init__(self):
                self.rules = {"old-analyzer-rule"}

        class _Optimizer:
            def __init__(self, owner):
                self.owner = owner
                self.child = _Child()
                self.instruction_optimizers = (self.child,)
                self.analyzer = _Analyzer()

            def replace_rules(self, _rules):
                self.child.rules.clear()
                self.child.rules.add("candidate-rule")
                self.child.pattern_storage["pattern"] = "candidate"
                self.child._indexed_storage["index"] = "candidate"
                self.child._structural_rules_by_root_opcode.clear()
                self.child._allowed_root_opcodes.clear()
                self.analyzer.rules.clear()
                self.analyzer.rules.add("candidate-analyzer-rule")

            def configure(self, **_kwargs):
                self.owner.instruction_pass_scheduler._pending_by_func.clear()
                self.owner.block_pass_scheduler._pending_by_func.clear()

        class _BlockOptimizer(_Optimizer):
            def __init__(self, owner):
                super().__init__(owner)
                self.cfg_rules = ["old-cfg-rule"]

        manager._started = True
        manager.instruction_optimizer = _Optimizer(manager)
        manager.block_optimizer = _BlockOptimizer(manager)
        manager.execution_scope_service._active_cache[(1, 2, 3)] = "old"
        manager.execution_scope_service._metadata_cache[1] = "old"
        manager.instruction_pass_scheduler._pending_by_func[1] = {"old": "run"}
        manager.block_pass_scheduler._pending_by_func[2] = {"old": "run"}
        before = _live_container_snapshot(manager)

        def compile_then_fail():
            manager.execution_scope_service._active_cache.clear()
            raise RuntimeError("scope failure after live container mutation")

        monkeypatch.setattr(manager, "_compile_execution_scope", compile_then_fail)
        try:
            assert state.load_project(target_index) is None
            _assert_live_container_snapshot(manager, before)
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


def test_started_activation_failure_restores_real_pattern_storage_objects(
    d810_state, monkeypatch
) -> None:
    """PatternOptimizer reset/rebind does not strand its real dispatch stores."""

    with d810_state() as state:
        original_index = state.current_project_index
        target_index, _rule = _load_project_with_rule(state, "current_ins_rules")
        manager = state.manager
        previous_started = manager._started
        previous_instruction_optimizer = getattr(manager, "instruction_optimizer", None)
        previous_block_optimizer = getattr(manager, "block_optimizer", None)

        from d810.optimizers.microcode.instructions.pattern_matching.handler import (
            PatternOptimizer,
            PatternStorage,
        )
        from d810.optimizers.microcode.instructions.pattern_matching.pattern_speedups import (
            OpcodeIndexedStorage,
        )

        child = PatternOptimizer([], manager.stats, log_dir=manager.log_dir)
        # Use the production Python storage class directly so this regression
        # exercises the manager's custom ``__dict__`` restoration branch even
        # when the runtime selects the optional Cython matcher backend.
        child._indexed_storage = OpcodeIndexedStorage()
        assert isinstance(child.pattern_storage, PatternStorage)
        assert isinstance(child._indexed_storage, OpcodeIndexedStorage)
        child.pattern_storage.next_layer_patterns[("old",)] = PatternStorage(depth=2)
        resolved_marker = object()
        child.pattern_storage.rule_resolved.append(resolved_marker)
        child._indexed_storage._by_opcode[0x123] = []

        old_pattern_storage = child.pattern_storage
        old_pattern_layers = old_pattern_storage.next_layer_patterns
        old_pattern_resolved = old_pattern_storage.rule_resolved
        old_pattern_contents = (
            old_pattern_storage.depth,
            dict(old_pattern_layers),
            list(old_pattern_resolved),
        )
        old_indexed_storage = child._indexed_storage
        old_indexed_by_opcode = old_indexed_storage._by_opcode
        old_indexed_contents = (
            dict(old_indexed_by_opcode),
            old_indexed_storage._total_patterns,
        )

        class _Analyzer:
            def __init__(self):
                self.rules = {"old-analyzer-rule"}

        class _InstructionOptimizer:
            def __init__(self, owner):
                self.owner = owner
                self.instruction_optimizers = (child,)
                self.analyzer = _Analyzer()

            def replace_rules(self, _rules):
                # This is the real PatternOptimizer reset path: it clears the
                # rule set and rebinds both production dispatch storages.
                child.reset_rules()
                self.analyzer.rules.clear()
                self.analyzer.rules.add("candidate-analyzer-rule")

            def configure(self, **_kwargs):
                self.owner.instruction_pass_scheduler._pending_by_func.clear()
                self.owner.block_pass_scheduler._pending_by_func.clear()

        class _BlockOptimizer:
            def __init__(self, owner):
                self.owner = owner
                self.cfg_rules = ["old-cfg-rule"]

            def replace_rules(self, _rules):
                self.cfg_rules[:] = ["candidate-cfg-rule"]

            def configure(self, **_kwargs):
                self.owner.instruction_pass_scheduler._pending_by_func.clear()
                self.owner.block_pass_scheduler._pending_by_func.clear()

        manager._started = True
        manager.instruction_optimizer = _InstructionOptimizer(manager)
        manager.block_optimizer = _BlockOptimizer(manager)
        manager.execution_scope_service._active_cache[(1, 2, 3)] = "old"
        manager.instruction_pass_scheduler._pending_by_func[1] = {"old": "run"}

        def compile_then_fail():
            manager.execution_scope_service._active_cache.clear()
            raise RuntimeError("scope failure after real storage rebind")

        monkeypatch.setattr(manager, "_compile_execution_scope", compile_then_fail)
        try:
            assert state.load_project(target_index) is None
            restored_child = manager.instruction_optimizer.instruction_optimizers[0]
            assert restored_child is child
            assert restored_child.pattern_storage is old_pattern_storage
            assert restored_child.pattern_storage.depth == old_pattern_contents[0]
            assert restored_child.pattern_storage.next_layer_patterns == (
                old_pattern_contents[1]
            )
            assert restored_child.pattern_storage.rule_resolved == (
                old_pattern_contents[2]
            )
            assert restored_child._indexed_storage is old_indexed_storage
            assert restored_child._indexed_storage._by_opcode == (
                old_indexed_contents[0]
            )
            assert restored_child._indexed_storage._total_patterns == (
                old_indexed_contents[1]
            )
            # The manager must restore the original live containers rather
            # than only equivalent copies of the custom storage state.
            assert restored_child.pattern_storage.next_layer_patterns is old_pattern_layers
            assert restored_child.pattern_storage.rule_resolved is old_pattern_resolved
            assert restored_child._indexed_storage._by_opcode is old_indexed_by_opcode
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
