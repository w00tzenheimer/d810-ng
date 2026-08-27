from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from d810.core.config import ProjectConfiguration, RuleConfiguration
from d810.core.plugins import (
    BackendManifest,
    PassImplementationCandidate,
    PassImplementationMisdeclared,
    PluginIdentity,
    PluginRuleServices,
)
from d810.manager import state as state_module
from d810.manager.project_runtime import ProjectIdentitySnapshot, ProjectRuntimeSnapshot
from d810.passes.config_v2_hook_runtime import ConfigV2HookSchedule
from d810.passes.pass_pipeline import PipelineConfigError


class _Activation:
    def __init__(self, name: str) -> None:
        self.name = name
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


class _Rule(state_module.InstructionOptimizationRule):
    name = "ExternalRule"

    def check_and_replace(self, _blk, _ins):
        return None


class _Manager:
    started = False

    def __init__(self, registry) -> None:
        self.backend_registry = registry
        self.instruction_optimizer_config = {}
        self.block_optimizer_config = {}
        self.config = {}

    def configure_constant_simplification_schedule(self, _schedule) -> None:
        return None

    def configure_instruction_optimizer(self, _rules, **_kwargs) -> None:
        return None

    def configure_block_optimizer(self, _rules, **_kwargs) -> None:
        return None

    def configure(self, **_kwargs) -> None:
        return None

    def emit_execution_scope_invalidation(self, *_args, **_kwargs) -> None:
        return None


class _Registry:
    def __init__(self, implementation, *, declared_name="ExternalRule") -> None:
        self.implementation = implementation
        self.new_activation = _Activation("new")
        self.old_activation = None
        self.factory_calls = 0
        self.close_calls: list[tuple[object, ...]] = []
        self.discarded: list[tuple[object, ...]] = []
        self.candidate = PassImplementationCandidate(
            pass_id="external-pass",
            backend_name="external",
            backend_origin="external-wheel",
            rule_modules=(),
            rule_name=declared_name,
        )
        self.manifest = BackendManifest(
            name="external",
            api_version=1,
            provides=lambda: object(),
            implements={"external-pass": declared_name},
        )

    def implementation_declarations_for(self, pass_id: str):
        assert pass_id == "external-pass"
        return ((self.candidate, self.manifest),)

    def activate_implementation(self, candidate):
        assert candidate is self.candidate
        self.factory_calls += 1
        if isinstance(self.implementation, BaseException):
            raise self.implementation
        return self.implementation

    def plugin_rule_services(self, candidate):
        assert candidate is self.candidate
        return PluginRuleServices(
            plugin=PluginIdentity("external", "external", "1", "external-wheel"),
            host=SimpleNamespace(),
        )

    def activation_for_candidate(self, candidate):
        assert candidate is self.candidate
        return self.new_activation

    def close_activations_except(self, keep):
        kept = tuple(keep)
        self.close_calls.append(kept)
        if self.new_activation not in kept:
            self.new_activation.close()
        if self.old_activation is not None and self.old_activation not in kept:
            self.old_activation.close()

    def discard_implementation_instances(self, staged):
        self.discarded.append(tuple(staged))


def _project(name: str) -> ProjectConfiguration:
    return ProjectConfiguration(path=Path(name), description=name)


def _snapshot(project: ProjectConfiguration, activation: object, *implementations):
    return ProjectRuntimeSnapshot(
        project=ProjectIdentitySnapshot(
            basename=project.path.name,
            path=project.path,
            description=project.description,
        ),
        effective_pass_ids=("old-pass",),
        activated_plugins=(activation,),
        activated_implementations=tuple(implementations),
    )


def _state(registry, old_project, old_snapshot):
    state = object.__new__(state_module.D810State)
    state.manager = _Manager(registry)
    state.d810_config = SimpleNamespace(get=lambda _name, default=None: default)
    state.log_dir = Path(".")
    state.current_project_runtime_snapshot = old_snapshot
    state.current_project = old_project
    state.current_project_index = 0
    state.current_ins_rules = ["old-ins"]
    state.current_blk_rules = ["old-blk"]
    state.known_ins_rules = ["old-known-ins"]
    state.known_blk_rules = ["old-known-blk"]
    state.last_config_v2_pass_ids = ("old-pass",)
    state.current_certified_catalogue_snapshot = None
    state.current_shadow_matcher_parity_ledger = None
    state._capture_project_activation_state = lambda: {"old": True}
    state._restore_project_activation_state = lambda *_args: None
    state._build_known_instruction_rules = lambda: []
    state._build_known_block_rules = lambda: []
    return state


def _patch_activation(monkeypatch, *, binding_name="ExternalRule"):
    schedule = ConfigV2HookSchedule(
        configured_pass_ids=("external-pass",),
        instruction_bindings=(
            RuleConfiguration(name=binding_name, is_activated=True, config={}),
        ),
    )
    monkeypatch.setattr(
        state_module, "compile_config_v2_hook_schedule", lambda _project: schedule
    )
    monkeypatch.setattr(
        state_module, "prepare_project_activation_cleanups", lambda: None
    )
    monkeypatch.setattr(
        state_module, "resolve_arch_config", lambda config: dict(config)
    )
    monkeypatch.setattr(state_module, "emit_project_reloading", lambda **_kwargs: None)
    return schedule


def test_wrong_type_rolls_back_project_and_closes_staged_activation(monkeypatch):
    registry = _Registry(object())
    old_activation = _Activation("old")
    old_project = _project("old.json")
    old_snapshot = _snapshot(old_project, old_activation, "old-ins")
    registry.old_activation = old_activation
    state = _state(registry, old_project, old_snapshot)
    _patch_activation(monkeypatch)
    monkeypatch.setattr(
        state_module,
        "build_project_runtime_snapshot",
        lambda **_kwargs: pytest.fail("wrong type must fail before publication"),
    )

    with pytest.raises(TypeError, match="InstructionOptimizationRule"):
        state._activate_project(project_index=1, project=_project("new.json"))

    assert state.current_project is old_project
    assert state.current_project_runtime_snapshot is old_snapshot
    assert state.current_ins_rules == ["old-ins"]
    assert registry.factory_calls == 1
    assert registry.close_calls == [(old_activation,)]
    assert registry.new_activation.close_calls == 1
    assert registry.discarded == [(registry.implementation,)]


def test_factory_failure_preserves_prior_project_and_closes_staged_activation(
    monkeypatch,
):
    error = PassImplementationMisdeclared(
        "external-pass",
        backend_name="external",
        backend_origin="external-wheel",
        reason="factory failed",
    )
    registry = _Registry(error)
    old_activation = _Activation("old")
    old_project = _project("old.json")
    old_snapshot = _snapshot(old_project, old_activation, "old-ins")
    registry.old_activation = old_activation
    state = _state(registry, old_project, old_snapshot)
    _patch_activation(monkeypatch)

    with pytest.raises(PassImplementationMisdeclared):
        state._activate_project(project_index=1, project=_project("new.json"))

    assert state.current_project is old_project
    assert state.current_project_runtime_snapshot is old_snapshot
    assert registry.close_calls == [(old_activation,)]
    assert registry.new_activation.close_calls == 1


def test_duplicate_instance_failure_preserves_prior_project(monkeypatch):
    error = PassImplementationMisdeclared(
        "external-pass",
        backend_name="external",
        backend_origin="external-wheel",
        reason="implementation factory reused an instance",
    )
    registry = _Registry(error)
    old_activation = _Activation("old")
    old_project = _project("old.json")
    old_snapshot = _snapshot(old_project, old_activation, "old-ins")
    registry.old_activation = old_activation
    state = _state(registry, old_project, old_snapshot)
    _patch_activation(monkeypatch)

    with pytest.raises(PassImplementationMisdeclared, match="reused"):
        state._activate_project(project_index=1, project=_project("new.json"))

    assert state.current_project is old_project
    assert state.current_project_runtime_snapshot is old_snapshot
    assert registry.close_calls == [(old_activation,)]
    assert registry.new_activation.close_calls == 1


def test_undeclared_binding_rolls_back_without_publishing(monkeypatch):
    registry = _Registry(object(), declared_name="DeclaredRule")
    old_activation = _Activation("old")
    old_project = _project("old.json")
    old_snapshot = _snapshot(old_project, old_activation, "old-ins")
    registry.old_activation = old_activation
    state = _state(registry, old_project, old_snapshot)
    _patch_activation(monkeypatch, binding_name="UndeclaredRule")

    with pytest.raises(PipelineConfigError, match="unregistered"):
        state._activate_project(project_index=1, project=_project("new.json"))

    assert state.current_project_runtime_snapshot is old_snapshot
    assert registry.factory_calls == 0
    assert registry.close_calls == [(old_activation,)]
    assert registry.new_activation.close_calls == 1


def test_success_publishes_before_closing_superseded_activation(monkeypatch):
    rule = _Rule()
    registry = _Registry(rule)
    old_activation = _Activation("old")
    old_project = _project("old.json")
    old_snapshot = _snapshot(old_project, old_activation, "old-ins")
    registry.old_activation = old_activation
    state = _state(registry, old_project, old_snapshot)
    _patch_activation(monkeypatch)
    new_project = _project("new.json")
    new_snapshot = _snapshot(new_project, registry.new_activation, rule)

    def build(**kwargs):
        assert kwargs["activated_plugins"] == (registry.new_activation,)
        assert kwargs["activated_implementations"] == (rule,)
        return new_snapshot

    monkeypatch.setattr(state_module, "build_project_runtime_snapshot", build)
    state._activate_project(project_index=1, project=new_project)

    assert state.current_project_runtime_snapshot is new_snapshot
    assert registry.close_calls == [(registry.new_activation,)]
    assert old_activation.close_calls == 1
    assert registry.new_activation.close_calls == 0
