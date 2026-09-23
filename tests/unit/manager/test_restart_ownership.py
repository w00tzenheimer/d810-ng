"""Regression for plugin implementation ownership across stop/start."""

from __future__ import annotations

import ast
import contextlib
import dataclasses
from copy import deepcopy
from pathlib import Path
from types import MethodType, SimpleNamespace

import pytest

from d810.capabilities.plugin_host import (
    PluginCapabilityAccessError,
    PluginHostCapabilityRegistry,
)
from d810.core.plugins import (
    PLUGIN_API_VERSION,
    BackendManifest,
    BackendRegistry,
    BackendSpec,
    ImplementationOwnership,
)
from d810.mba.extension_api import (
    D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,
    MbaResidualObservationSink,
)
from d810.mba.residual_observation_lifecycle import MbaResidualObservationLifecycle
from d810.manager.project_runtime import (
    ExternalImplementationRestartRecipe,
    ProjectRuntimeSnapshot,
)


_ROOT = Path(__file__).resolve().parents[3]


def _class_methods(path: Path, class_name: str) -> dict[str, object]:
    """Execute class method bodies without importing their IDA-only module."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    class_node = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == class_name
    )
    methods = [
        node
        for node in class_node.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    for method in methods:
        method.decorator_list = []
    module = ast.Module(
        body=[
            ast.ImportFrom(
                module="__future__",
                names=[ast.alias(name="annotations")],
                level=0,
            ),
            *methods,
        ],
        type_ignores=[],
    )
    namespace = {
        "dataclasses": dataclasses,
        "contextlib": contextlib,
        "ImplementationOwnership": ImplementationOwnership,
        "InstructionOptimizationRule": object,
        "FlowOptimizationRule": object,
        "_ExternalImplementationBinding": lambda *, ownership, lane: SimpleNamespace(
            ownership=ownership,
            lane=lane,
            candidate=ownership.candidate,
            instance=ownership.instance,
        ),
        "_release_implementation_instances": (
            lambda registry, ownership: registry.release_implementation_instances(
                ownership
            )
        ),
        "ensure_hexrays_available": lambda **_kwargs: True,
        "load_optimizer_registries": lambda: None,
        "logger": SimpleNamespace(
            debug=lambda *_args, **_kwargs: None,
            error=lambda *_args, **_kwargs: None,
            info=lambda *_args, **_kwargs: None,
            warning=lambda *_args, **_kwargs: None,
        ),
        "shutdown_all_writers": lambda: None,
    }
    exec(compile(ast.fix_missing_locations(module), str(path), "exec"), namespace)
    return {name: namespace[name] for name in (node.name for node in methods)}


_STATE_METHODS = _class_methods(_ROOT / "src/d810/manager/state.py", "D810State")
_MANAGER_METHODS = _class_methods(
    _ROOT / "src/d810/manager/manager.py", "D810Manager"
)


def test_state_load_populates_optimizer_registry_before_project_activation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class ProjectManager:
        def __len__(self) -> int:
            return 1

    class Config:
        def get(self, name: str, default=None):
            assert name == "last_project_index"
            return 0

    state = SimpleNamespace()

    def reset(*, d810_config=None) -> None:
        events.append("reset")
        state.d810_config = Config()
        state.project_manager = ProjectManager()
        state.invalid_projects = {}

    state.reset = reset
    state._build_known_instruction_rules = lambda: events.append("instruction") or []
    state._build_known_block_rules = lambda: events.append("block") or []
    state._load_first_valid_project = (
        lambda _preferred: events.append("activate") or object()
    )
    monkeypatch.setitem(
        _STATE_METHODS["load"].__globals__,
        "load_optimizer_registries",
        lambda: events.append("registry"),
    )

    _STATE_METHODS["load"](state, gui=False)

    assert events == ["reset", "registry", "instruction", "block", "activate"]


class _Host:
    def require(self, capability):
        raise AssertionError(f"unexpected capability request: {capability!r}")

    def optional(self, _capability):
        return None


class _OwnedRule:
    name = "owned-rule"

    def __init__(self, activation: "_OwnedActivation") -> None:
        self.activation = activation
        self.released = False
        self.work_calls = 0
        self.worked_after_release = False
        self.configure_calls = 0
        self.configuration = None
        self.log_dir = None
        self.services = None
        self.residual_sink = None

    def bind_plugin_services(self, services: object) -> None:
        self.services = services
        if self.activation.plugin.require_residual_capability:
            self.residual_sink = services.host.require(MbaResidualObservationSink)

    def configure(self, configuration: dict[str, object]) -> None:
        self.configure_calls += 1
        self.configuration_before_mutation = deepcopy(configuration)
        self.configuration = configuration
        if self.activation.plugin.mutate_configurations:
            nested = configuration["nested"]
            nested["items"].append(f"generation-{self.activation.generation}")
            nested["mapping"]["token"] = f"generation-{self.activation.generation}"
        if self.activation.plugin.configuration_failures:
            self.activation.plugin.configuration_failures -= 1
            raise RuntimeError("configuration restart failure")

    def set_log_dir(self, log_dir: Path) -> None:
        self.log_dir = log_dir

    def work(self) -> None:
        self.work_calls += 1
        self.worked_after_release = self.released or self.activation.closed


class _OwnedActivation:
    def __init__(self, plugin: "_OwnedPlugin", generation: int) -> None:
        self.plugin = plugin
        self.generation = generation
        self.closed = False
        self.close_calls = 0
        self.release_calls: list[_OwnedRule] = []
        self.rules: list[_OwnedRule] = []

    def create_implementation(self, _implementation_id: str) -> _OwnedRule:
        if self.plugin.factory_failures:
            self.plugin.factory_failures -= 1
            raise RuntimeError("factory restart failure")
        rule = _OwnedRule(self)
        self.rules.append(rule)
        return rule

    def capability_offers(self) -> tuple:
        return ()

    def release_implementation(self, implementation: object) -> None:
        assert any(implementation is rule for rule in self.rules)
        rule = implementation
        assert isinstance(rule, _OwnedRule)
        self.release_calls.append(rule)
        self.plugin.lifecycle_events.append("plugin.release")
        rule.released = True
        if self.plugin.release_failures:
            self.plugin.release_failures -= 1
            raise RuntimeError("release cleanup failure")

    def close(self) -> None:
        self.close_calls += 1
        self.plugin.lifecycle_events.append("plugin.close")
        if self.plugin.close_failures:
            self.plugin.close_failures -= 1
            raise RuntimeError("activation cleanup failure")
        self.closed = True


class _OwnedPlugin:
    def __init__(self) -> None:
        self.activations: list[_OwnedActivation] = []
        self.factory_failures = 0
        self.configuration_failures = 0
        self.mutate_configurations = False
        self.release_failures = 0
        self.close_failures = 0
        self.require_residual_capability = False
        self.lifecycle_events: list[str] = []

    def activate(self, _context) -> _OwnedActivation:
        activation = _OwnedActivation(self, len(self.activations))
        self.activations.append(activation)
        return activation


class _BuiltinRule:
    name = "builtin-rule"


class _ProjectManager:
    def __init__(self, project: object) -> None:
        self.project = project

    def get(self, index: int) -> object:
        assert index == 0
        return self.project


class _Config:
    def __init__(self) -> None:
        self.values = {"generate_z3_code": False}

    def get(self, name: str, default=None):
        return self.values.get(name, default)

    def set(self, name: str, value: object) -> None:
        self.values[name] = value

    def save(self) -> None:
        return None


class _ResidualStore:
    def __init__(self) -> None:
        self.closed = False

    def record_attempt(self, _attempt):
        raise AssertionError("the restart-order test does not record observations")

    def close(self) -> None:
        self.closed = True


def _residual_lifecycle(host_registry: PluginHostCapabilityRegistry):
    stores: list[_ResidualStore] = []

    def new_store() -> _ResidualStore:
        store = _ResidualStore()
        stores.append(store)
        return store

    lifecycle = MbaResidualObservationLifecycle(
        store_factory=new_store,
        registry_factory=lambda: host_registry,
    )
    lifecycle.stores = stores
    lifecycle.start()
    return lifecycle


def _registry(
    plugin: _OwnedPlugin,
    host_registry: PluginHostCapabilityRegistry | None = None,
) -> BackendRegistry:
    pass_id = "mba-solve" if host_registry is not None else "owned-pass"
    backend_name = "cobra" if host_registry is not None else "owned"
    rule_name = "cobra-solve" if host_registry is not None else "owned-rule"
    manifest = BackendManifest(
        name=backend_name,
        api_version=PLUGIN_API_VERSION,
        provides=lambda: plugin,
        requires=(
            (D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,)
            if plugin.require_residual_capability
            else ()
        ),
        implements={pass_id: rule_name},
    )
    kwargs = {}
    if host_registry is not None:
        kwargs = {
            "host": host_registry,
            "requirement_validator": host_registry.validate,
            "host_view_factory": host_registry.view_for,
            "implementation_host_view_factory": (
                host_registry.bind_implementation_view
            ),
        }
    else:
        kwargs = {
            "host_view_factory": lambda _requirements, _identity: _Host(),
            "requirement_validator": lambda _requirements: None,
        }
    registry = BackendRegistry(
        source=lambda: (
            BackendSpec(
                name=backend_name,
                origin="owned-wheel",
                load_manifest=lambda: manifest,
            ),
        ),
        **kwargs,
    )
    registry.test_pass_id = pass_id
    registry.test_rule_name = rule_name
    return registry


def _stopped_manager(
    registry: BackendRegistry,
    residual_lifecycle: MbaResidualObservationLifecycle | None = None,
):
    """Build only the real manager.stop() surface needed by this regression."""
    class Manager:
        stop = _MANAGER_METHODS["stop"]

        def _prepare_plugin_host_capabilities(self) -> bool:
            return _MANAGER_METHODS["_prepare_plugin_host_capabilities"](self)

        def _discard_telemetry_lifecycle(self) -> bool:
            self._telemetry_lifecycle_stack.clear()
            self._telemetry_lifecycle_depth.clear()
            return False

        def _uninstall_native_preanalysis_handlers_if_installed(self) -> None:
            return None

        def _safe_lifecycle_step(self, label, callback, *args) -> bool:
            if label in {
                "plugin activations.close",
                "mba residual observation.release",
            }:
                callback(*args)
            return True

        def _initialize_mba_residual_observation(self) -> None:
            lifecycle = self._mba_residual_observation_lifecycle
            if lifecycle is None:
                self._mba_residual_observation_sink = object()
                self._mba_residual_observation_lease = object()
                return
            if lifecycle.started:
                lifecycle.restart()
            else:
                lifecycle.start()
            self._mba_residual_observation_sink = lifecycle.sink
            self._mba_residual_observation_lease = lifecycle.lease

        def _release_mba_residual_observation(self, full_cleanup=False) -> None:
            self.lifecycle_events.append("capability.release")
            lifecycle = self._mba_residual_observation_lifecycle
            self._mba_residual_observation_lease = None
            self._mba_residual_observation_sink = None
            if lifecycle is None:
                return
            if full_cleanup:
                self._mba_residual_observation_lifecycle = None
                lifecycle.close()
            else:
                lifecycle.stop()
            if self.capability_release_failure is not None:
                raise self.capability_release_failure

        @property
        def started(self) -> bool:
            return self._started

        def configure_instruction_optimizer(self, rules, **_kwargs) -> None:
            self.instruction_optimizer_rules = list(rules)

        def configure_block_optimizer(self, rules, **_kwargs) -> None:
            self.block_optimizer_rules = list(rules)

        def configure_external_implementation_bindings(self, bindings) -> None:
            self._external_implementation_bindings = dict(bindings)

        def configure_preparation_scripts(self, *_args, **_kwargs) -> None:
            return None

        def stop_profiling(self, *_args) -> None:
            return None

        def start(self) -> None:
            if self._started:
                self.stop()
            self._prepare_plugin_host_capabilities()
            self.start_calls += 1
            self._started = True

    manager = Manager()
    manager._started = False
    manager._telemetry_lifecycle_stack = []
    manager._telemetry_lifecycle_depth = {}
    manager._native_preanalysis_handlers_installed = False
    manager.execution_scope_service = SimpleNamespace(detach=lambda: None)
    manager._idb_preparation_journal = None
    manager.backend_registry = registry
    manager._mba_residual_observation_lifecycle = residual_lifecycle
    manager._mba_residual_observation_lease = (
        residual_lifecycle.lease if residual_lifecycle is not None else None
    )
    manager._mba_residual_observation_sink = (
        residual_lifecycle.sink if residual_lifecycle is not None else None
    )
    manager.capability_release_failure = None
    manager.lifecycle_events = []
    manager._constant_simplification_schedule = None
    manager.instruction_pass_scheduler = object()
    manager.block_pass_scheduler = object()
    manager._external_implementation_bindings = {}
    manager.pre_hex_preparation = None
    manager._post_d810_runtime = None
    manager.instruction_optimizer = SimpleNamespace(remove=lambda: None)
    manager.block_optimizer = SimpleNamespace(remove=lambda: None)
    manager.hx_decompiler_hook = SimpleNamespace(unhook=lambda: None)
    manager._analysis_runtime = None
    manager.event_emitter = SimpleNamespace(clear=lambda: None)
    manager._native_materialization_executor = None
    manager._native_patch_journal = None
    manager._native_patch_gateway = None
    manager._dead_edge_normalizer = None
    manager.decompilation_lifecycle = None
    manager._native_patch_execution_journal = None
    manager.function_storage_runtime = SimpleNamespace(close=lambda: None)
    manager._analysis_bundle = None
    manager._preanalysis_runtime = None
    manager._database_identity = ""
    manager.start_calls = 0
    return manager


def _state_with_owned_project(
    registry: BackendRegistry,
    residual_lifecycle: MbaResidualObservationLifecycle | None = None,
) -> object:
    class State:
        pass

    for name, method in _STATE_METHODS.items():
        setattr(State, name, method)

    manager = _stopped_manager(registry, residual_lifecycle)
    state = object.__new__(State)
    project = SimpleNamespace(
        path=Path("owned-project.json"),
        additional_configuration={},
    )
    state.manager = manager
    state.project_manager = _ProjectManager(project)
    state.d810_config = _Config()
    state.invalid_projects = {}
    state.current_project_index = 0
    state.current_project = project
    state.current_ins_rules = []
    state.current_blk_rules = []
    state.known_ins_rules = []
    state.known_blk_rules = []
    state.current_project_runtime_snapshot = None
    state._project_ownership_needs_reactivation = False
    state._is_loaded = True
    state.log_dir = Path("restart-ownership-logs")
    state.project_reload_events = []
    state._register_backend_analysis_providers = lambda: None

    def _activate_project(self, *, project_index: int, project: object):
        candidate = registry.require_unique_implementation(
            registry.test_pass_id, install_hint="owned-package"
        )
        implementation = registry.activate_implementation(candidate)
        activation = registry.activation_for_candidate(candidate)
        implementation.bind_plugin_services(registry.plugin_rule_services(candidate))
        ownership = ImplementationOwnership(candidate, implementation)
        recipe = ExternalImplementationRestartRecipe(
            binding_key=(
                registry.test_pass_id,
                registry.test_rule_name,
                "instruction",
            ),
            ownership=ownership,
            resolved_configuration={
                "token": "stable",
                "nested": {
                    "items": ["stable"],
                    "mapping": {"token": "stable"},
                },
            },
        )
        implementation.configure(recipe.fresh_configuration())
        implementation.set_log_dir(self.log_dir)
        builtin = _BuiltinRule()
        self.current_project_index = project_index
        self.current_project = project
        self.known_ins_rules = [builtin, implementation]
        self.current_ins_rules = [builtin, implementation]
        self.known_blk_rules = []
        self.current_blk_rules = []
        self.manager.configure_external_implementation_bindings(
            {
                (
                    registry.test_pass_id,
                    registry.test_rule_name,
                    "instruction",
                ): implementation
            }
        )
        self.manager.configure_instruction_optimizer(self.current_ins_rules)
        self.manager.configure_block_optimizer(())
        self.current_project_runtime_snapshot = ProjectRuntimeSnapshot(
            project=SimpleNamespace(
                basename=project.path.name,
                path=project.path,
                description="owned test project",
            ),
            effective_pass_ids=("builtin-pass", "owned-pass"),
            activated_plugins=(activation,),
            activated_implementations=(
                ownership,
            ),
            external_implementation_restart_recipes=(recipe,),
        )
        self._project_ownership_needs_reactivation = False
        self.project_reload_events.append(project.path.name)
        return project

    state._activate_project = MethodType(_activate_project, state)
    return state


def _load_owned_project(state):
    assert state.load_project(0) is state.current_project
    builtin = next(rule for rule in state.current_ins_rules if isinstance(rule, _BuiltinRule))
    external = next(rule for rule in state.current_ins_rules if isinstance(rule, _OwnedRule))
    invariants = {
        "builtin": builtin,
        "effective_pass_ids": state.current_project_runtime_snapshot.effective_pass_ids,
        "project": state.current_project_runtime_snapshot.project,
        "preparation_scripts": (
            state.current_project_runtime_snapshot.preparation_scripts
        ),
        "instruction_scheduler": state.manager.instruction_pass_scheduler,
        "block_scheduler": state.manager.block_pass_scheduler,
        "constant_schedule": state.manager._constant_simplification_schedule,
    }
    state.project_reload_events.clear()
    return external, invariants


def _configured_external(state) -> _OwnedRule:
    rules = [rule for rule in state.manager.instruction_optimizer_rules if isinstance(rule, _OwnedRule)]
    assert len(rules) == 1
    return rules[0]


def _assert_preserved(state, invariants) -> None:
    builtin = next(rule for rule in state.current_ins_rules if isinstance(rule, _BuiltinRule))
    assert builtin is invariants["builtin"]
    assert state.current_project_runtime_snapshot.effective_pass_ids is invariants[
        "effective_pass_ids"
    ]
    assert state.current_project_runtime_snapshot.project is invariants["project"]
    assert (
        state.current_project_runtime_snapshot.preparation_scripts
        is invariants["preparation_scripts"]
    )
    assert state.manager.instruction_pass_scheduler is invariants[
        "instruction_scheduler"
    ]
    assert state.manager.block_pass_scheduler is invariants["block_scheduler"]
    assert state.manager._constant_simplification_schedule is invariants[
        "constant_schedule"
    ]
    assert state.project_reload_events == []


def _exception_messages(error: BaseException) -> list[str]:
    messages = [str(error)]
    if isinstance(error, BaseExceptionGroup):
        for nested in error.exceptions:
            messages.extend(_exception_messages(nested))
    return messages


def _activation_observations(plugin: _OwnedPlugin) -> list[dict[str, object]]:
    return [
        {
            "work_calls": [rule.work_calls for rule in activation.rules],
            "worked_after_release": [
                rule.worked_after_release for rule in activation.rules
            ],
            "release_calls": len(activation.release_calls),
            "close_calls": activation.close_calls,
        }
        for activation in plugin.activations
    ]


def test_real_capability_preparation_is_idempotent_and_precedes_restart_rebind() -> None:
    plugin = _OwnedPlugin()
    plugin.require_residual_capability = True
    host_registry = PluginHostCapabilityRegistry()
    lifecycle = _residual_lifecycle(host_registry)
    registry = _registry(plugin, host_registry)
    state = _state_with_owned_project(registry, lifecycle)

    _load_owned_project(state)
    initial_sink = lifecycle.sink
    initial_lease = lifecycle.lease
    assert state.manager._prepare_plugin_host_capabilities() is False
    assert state.manager._prepare_plugin_host_capabilities() is False
    assert lifecycle.sink is initial_sink
    assert lifecycle.lease is initial_lease
    assert len(lifecycle.stores) == 1

    relay = lifecycle.relay
    state.manager.stop()
    with pytest.raises(PluginCapabilityAccessError, match="missing host capability"):
        host_registry.validate((D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,))

    state.start_d810()
    working = _configured_external(state)

    assert working.residual_sink is not None
    assert lifecycle.relay is relay
    assert len(lifecycle.stores) == 2
    host_registry.validate((D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,))
    state.stop_d810()


@pytest.mark.parametrize(
    ("failure_field", "message"),
    (
        ("factory_failures", "factory restart failure"),
        ("configuration_failures", "configuration restart failure"),
    ),
)
def test_real_capability_restart_failure_releases_generation_and_retry_reacquires(
    failure_field: str,
    message: str,
) -> None:
    plugin = _OwnedPlugin()
    plugin.require_residual_capability = True
    host_registry = PluginHostCapabilityRegistry()
    lifecycle = _residual_lifecycle(host_registry)
    registry = _registry(plugin, host_registry)
    state = _state_with_owned_project(registry, lifecycle)

    _load_owned_project(state)
    relay = lifecycle.relay
    state.manager.stop()
    setattr(plugin, failure_field, 1)

    with pytest.raises(Exception, match=message):
        state.start_d810()

    assert state.manager.started is False
    assert lifecycle.relay is relay
    assert lifecycle.started is False
    with pytest.raises(PluginCapabilityAccessError, match="missing host capability"):
        host_registry.validate((D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,))

    state.start_d810()
    working = _configured_external(state)
    assert working.residual_sink is not None
    assert lifecycle.relay is relay
    assert len(lifecycle.stores) == 3
    state.stop_d810()


def test_failed_rebind_does_not_release_a_preexisting_capability_generation() -> None:
    plugin = _OwnedPlugin()
    plugin.require_residual_capability = True
    host_registry = PluginHostCapabilityRegistry()
    lifecycle = _residual_lifecycle(host_registry)
    registry = _registry(plugin, host_registry)
    state = _state_with_owned_project(registry, lifecycle)

    _load_owned_project(state)
    sink = lifecycle.sink
    lease = lifecycle.lease
    registry.close_activations()
    plugin.configuration_failures = 1

    with pytest.raises(Exception, match="configuration restart failure"):
        state.start_d810()

    assert lifecycle.started is True
    assert lifecycle.sink is sink
    assert lifecycle.lease is lease
    host_registry.validate((D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,))
    state.stop_d810()


def test_capability_cleanup_failure_preserves_nested_plugin_cleanup_failures() -> None:
    plugin = _OwnedPlugin()
    plugin.require_residual_capability = True
    host_registry = PluginHostCapabilityRegistry()
    lifecycle = _residual_lifecycle(host_registry)
    registry = _registry(plugin, host_registry)
    state = _state_with_owned_project(registry, lifecycle)

    _load_owned_project(state)
    state.manager.stop()
    state.manager.lifecycle_events = plugin.lifecycle_events
    plugin.lifecycle_events.clear()
    plugin.configuration_failures = 1
    plugin.release_failures = 1
    plugin.close_failures = 1
    state.manager.capability_release_failure = RuntimeError(
        "capability generation cleanup failure"
    )

    with pytest.raises(BaseExceptionGroup) as raised:
        state.start_d810()

    messages = _exception_messages(raised.value)
    assert any("configuration restart failure" in message for message in messages)
    assert any("release cleanup failure" in message for message in messages)
    assert any("activation cleanup failure" in message for message in messages)
    assert any(
        "capability generation cleanup failure" in message for message in messages
    )
    assert plugin.lifecycle_events == [
        "plugin.release",
        "plugin.close",
        "capability.release",
    ]
    assert lifecycle.started is False
    with pytest.raises(PluginCapabilityAccessError, match="missing host capability"):
        host_registry.validate((D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,))


def test_state_stop_restart_rebinds_only_external_and_cleans_working_generation_once() -> None:
    """The runner's already-stopped baseline stop retires only generation zero."""
    plugin = _OwnedPlugin()
    registry = _registry(plugin)
    state = _state_with_owned_project(registry)

    old_external, invariants = _load_owned_project(state)
    state.stop_d810()  # The runner's baseline stop is already-stopped.
    state.start_d810()
    working = _configured_external(state)
    working.work()
    state.stop_d810()  # Actual post-work cleanup.
    state.unload(gui=False)  # Repeated stop stays safe.

    _assert_preserved(state, invariants)
    assert working is not old_external
    assert working.configuration == {
        "token": "stable",
        "nested": {
            "items": ["stable"],
            "mapping": {"token": "stable"},
        },
    }
    assert working.configure_calls == 1
    assert working.services is not None
    assert _activation_observations(plugin) == [
        {
            "work_calls": [0],
            "worked_after_release": [False],
            "release_calls": 1,
            "close_calls": 1,
        },
        {
            "work_calls": [1],
            "worked_after_release": [False],
            "release_calls": 1,
            "close_calls": 1,
        },
    ]


def test_direct_manager_stop_detects_exact_retired_owner_not_active_candidate() -> None:
    """Candidate-level active state cannot legitimize the snapshot's stale object."""
    plugin = _OwnedPlugin()
    registry = _registry(plugin)
    state = _state_with_owned_project(registry)
    old_external, invariants = _load_owned_project(state)
    candidate = state.current_project_runtime_snapshot.activated_implementations[
        0
    ].candidate

    state.manager.stop()
    foreign = registry.activate_implementation(candidate)
    state.start_d810()
    working = _configured_external(state)
    working.work()
    state.stop_d810()
    state.unload(gui=False)

    _assert_preserved(state, invariants)
    assert working is not old_external
    assert working is not foreign
    assert working.activation is foreign.activation
    assert working.worked_after_release is False
    assert plugin.activations[0].close_calls == 1
    assert plugin.activations[1].release_calls == [foreign, working]
    assert plugin.activations[1].close_calls == 1


def test_direct_full_cleanup_restart_recreates_external_without_project_reload() -> None:
    plugin = _OwnedPlugin()
    registry = _registry(plugin)
    state = _state_with_owned_project(registry)
    old_external, invariants = _load_owned_project(state)

    assert state.manager.stop(full_cleanup=True) == ()
    state.start_d810()
    working = _configured_external(state)
    working.work()
    state.stop_d810()
    state.unload(gui=False)

    _assert_preserved(state, invariants)
    assert working is not old_external
    assert working.worked_after_release is False
    assert [activation.close_calls for activation in plugin.activations] == [1, 1]
    assert [len(activation.release_calls) for activation in plugin.activations] == [
        1,
        1,
    ]


def test_repeated_start_stops_then_rebinds_the_retired_live_generation() -> None:
    plugin = _OwnedPlugin()
    registry = _registry(plugin)
    state = _state_with_owned_project(registry)
    old_external, invariants = _load_owned_project(state)

    state.start_d810()
    first_started = _configured_external(state)
    state.start_d810()
    second_started = _configured_external(state)
    second_started.work()
    state.stop_d810()
    state.unload(gui=False)

    _assert_preserved(state, invariants)
    assert first_started is old_external
    assert second_started is not first_started
    assert second_started.worked_after_release is False
    assert [activation.close_calls for activation in plugin.activations] == [1, 1]


@pytest.mark.parametrize(
    ("failure_field", "message"),
    (
        ("factory_failures", "factory restart failure"),
        ("configuration_failures", "configuration restart failure"),
    ),
)
def test_failed_local_rebind_stays_stopped_and_retry_publishes_one_fresh_generation(
    failure_field: str,
    message: str,
) -> None:
    plugin = _OwnedPlugin()
    registry = _registry(plugin)
    state = _state_with_owned_project(registry)
    old_external, invariants = _load_owned_project(state)
    state.manager.stop()
    setattr(plugin, failure_field, 1)

    error = None
    try:
        state.start_d810()
    except RuntimeError as exc:
        error = exc
    first_retry_started = state.manager.started
    first_retry_rule = _configured_external(state)

    state.start_d810()
    working = _configured_external(state)
    working.work()
    state.stop_d810()
    state.unload(gui=False)

    _assert_preserved(state, invariants)
    assert error is not None and message in str(error)
    assert first_retry_started is False
    assert first_retry_rule is old_external
    assert working is not old_external
    assert working.worked_after_release is False
    assert working.configure_calls == 1
    assert working.configuration == {
        "token": "stable",
        "nested": {
            "items": ["stable"],
            "mapping": {"token": "stable"},
        },
    }
    assert len(plugin.activations) == 3
    assert [activation.close_calls for activation in plugin.activations] == [1, 1, 1]


def test_mutating_plugin_cannot_poison_initial_or_failed_retry_recipe() -> None:
    plugin = _OwnedPlugin()
    plugin.mutate_configurations = True
    registry = _registry(plugin)
    state = _state_with_owned_project(registry)
    old_external, invariants = _load_owned_project(state)
    snapshot = state.current_project_runtime_snapshot
    original_recipe = snapshot.external_implementation_restart_recipes[0]
    expected_configuration = {
        "token": "stable",
        "nested": {
            "items": ["stable"],
            "mapping": {"token": "stable"},
        },
    }
    assert original_recipe.fresh_configuration() == expected_configuration
    assert old_external.configuration_before_mutation == expected_configuration
    assert old_external.configuration != expected_configuration

    state.manager.stop()
    plugin.configuration_failures = 1
    with pytest.raises(RuntimeError, match="configuration restart failure"):
        state.start_d810()

    assert state.manager.started is False
    assert state.current_project_runtime_snapshot is snapshot
    assert original_recipe.fresh_configuration() == expected_configuration
    failed = plugin.activations[1].rules[0]
    assert failed.configuration_before_mutation == expected_configuration

    state.start_d810()
    working = _configured_external(state)
    working.work()
    state.stop_d810()
    state.unload(gui=False)

    _assert_preserved(state, invariants)
    assert working.configuration_before_mutation == expected_configuration
    assert working.configuration != expected_configuration
    assert working.worked_after_release is False
    assert len({id(old_external.configuration), id(failed.configuration), id(working.configuration)}) == 3


@pytest.mark.parametrize(
    "corruption",
    ("current-list", "known-list", "manager-map", "snapshot-owners"),
)
def test_restart_prevalidates_every_replacement_surface_before_staging(
    corruption: str,
) -> None:
    plugin = _OwnedPlugin()
    registry = _registry(plugin)
    state = _state_with_owned_project(registry)
    old_external, _invariants = _load_owned_project(state)
    snapshot = state.current_project_runtime_snapshot
    state.manager.stop()

    if corruption == "current-list":
        state.current_ins_rules = [state.current_ins_rules[0]]
    elif corruption == "known-list":
        state.known_ins_rules = [state.known_ins_rules[0]]
    elif corruption == "manager-map":
        state.manager._external_implementation_bindings = {}
    else:
        state.current_project_runtime_snapshot = dataclasses.replace(
            snapshot,
            activated_implementations=(),
        )

    with pytest.raises(RuntimeError, match="external restart ownership is inconsistent"):
        state.start_d810()

    assert state.manager.started is False
    assert len(plugin.activations) == 1
    assert old_external.released is True
    assert state.project_reload_events == []


def test_failed_restart_preserves_primary_and_cleanup_failures() -> None:
    plugin = _OwnedPlugin()
    registry = _registry(plugin)
    state = _state_with_owned_project(registry)
    _old_external, _invariants = _load_owned_project(state)
    state.manager.stop()
    plugin.configuration_failures = 1
    plugin.release_failures = 1
    plugin.close_failures = 1

    with pytest.raises(BaseExceptionGroup) as raised:
        state.start_d810()

    errors = raised.value.exceptions
    assert isinstance(errors[0], RuntimeError)
    assert str(errors[0]) == "configuration restart failure"
    assert any("release cleanup failure" in str(error) for error in errors[1:])
    assert any("activation cleanup failure" in str(error) for error in errors[1:])
    assert state.manager.started is False
    assert state.project_reload_events == []


def test_failed_restart_never_closes_or_releases_unrelated_live_ownership() -> None:
    plugin = _OwnedPlugin()
    registry = _registry(plugin)
    state = _state_with_owned_project(registry)
    _old_external, invariants = _load_owned_project(state)
    candidate = state.current_project_runtime_snapshot.activated_implementations[
        0
    ].candidate
    state.manager.stop()
    foreign = registry.activate_implementation(candidate)
    plugin.configuration_failures = 1

    with pytest.raises(RuntimeError, match="configuration restart failure"):
        state.start_d810()

    foreign_activation = foreign.activation
    assert foreign.released is False
    assert foreign_activation.close_calls == 0
    assert foreign_activation.release_calls != [foreign]
    assert state.manager.started is False

    state.start_d810()
    working = _configured_external(state)
    working.work()
    state.stop_d810()
    state.unload(gui=False)

    _assert_preserved(state, invariants)
    assert working is not foreign
    assert working.worked_after_release is False
    assert foreign_activation.release_calls[0] is not foreign
    assert foreign_activation.release_calls[-2:] == [foreign, working]
    assert foreign_activation.close_calls == 1
