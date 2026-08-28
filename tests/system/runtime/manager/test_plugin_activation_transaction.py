from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from d810.core.config import ProjectConfiguration, RuleConfiguration
from d810.core.plugins import (
    BackendManifest,
    BackendRegistry,
    BackendSpec,
    ImplementationOwnership,
    PassImplementationAmbiguous,
    PassImplementationCandidate,
    PassImplementationMisdeclared,
    PassImplementationUnavailable,
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


class _OpaqueBindingRule(state_module.InstructionOptimizationRule):
    name = "RuntimeRule"

    def __init__(self):
        super().__init__()
        self.configure_calls = 0
        self.log_dir_calls = 0
        self.bound_services = []

    def bind_plugin_services(self, services):
        self.bound_services.append(services)
        super().bind_plugin_services(services)

    def configure(self, _config):
        self.configure_calls += 1

    def set_log_dir(self, _log_dir):
        self.log_dir_calls += 1

    def check_and_replace(self, _blk, _ins):
        return None


class _InternalOpaqueNameRule(state_module.InstructionOptimizationRule):
    name = "opaque-implementation-id"

    def __init__(self):
        super().__init__()
        self.configure_calls = 0

    def configure(self, _config):
        self.configure_calls += 1

    def check_and_replace(self, _blk, _ins):
        return None


class _Manager:
    def __init__(self, registry) -> None:
        self.started = False
        self.backend_registry = registry
        self.instruction_optimizer_config = {}
        self.block_optimizer_config = {}
        self.config = {}
        self.runtime_lane = "old"
        self.fail_at = None
        self.execution_scope_service = SimpleNamespace()
        self.instruction_pass_scheduler = SimpleNamespace()
        self.block_pass_scheduler = SimpleNamespace()

    def function_analysis_priors_for_ea(self, _ea):
        return None

    def snapshot_project_activation_state(self):
        return {
            "config": dict(self.config),
            "runtime_lane": self.runtime_lane,
        }

    def restore_project_activation_state(self, snapshot):
        self.config = dict(snapshot["config"])
        self.runtime_lane = snapshot["runtime_lane"]

    def invalidate_runtime_after_activation_rollback(self):
        return ()

    def configure_constant_simplification_schedule(self, _schedule) -> None:
        return None

    def configure_instruction_optimizer(self, _rules, **_kwargs) -> None:
        self.runtime_lane = "candidate-ins"
        if self.fail_at == "instruction-configure":
            raise RuntimeError("instruction configure failed")

    def configure_block_optimizer(self, _rules, **_kwargs) -> None:
        self.runtime_lane = "candidate-blk"
        if self.fail_at == "block-configure":
            raise RuntimeError("block configure failed")

    def configure(self, **_kwargs) -> None:
        self.config = dict(_kwargs)
        if self.fail_at == "manager-configure":
            raise RuntimeError("manager configure failed")

    def emit_execution_scope_invalidation(self, *_args, **_kwargs) -> None:
        return None

    def _compile_execution_scope(self) -> None:
        self.runtime_lane = "candidate-execution-scope"
        if self.fail_at == "execution-scope":
            raise RuntimeError("execution scope compile failed")


class _Registry:
    def __init__(
        self, implementation, *, declared_name="ExternalRule", services_error=None
    ) -> None:
        self.implementation = implementation
        self.new_activation = _Activation("new")
        self.old_activation = None
        self.factory_calls = 0
        self.close_calls: list[tuple[object, ...]] = []
        self.discarded: list[tuple[object, ...]] = []
        self.services_error = services_error
        self.state = None
        self.expected_snapshot = None
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
        if self.services_error is not None:
            raise self.services_error
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
            if self.expected_snapshot is not None:
                assert (
                    self.state.current_project_runtime_snapshot
                    is self.expected_snapshot
                )
                assert self.state.current_ins_rules == [self.implementation]
            self.old_activation.close()

    def discard_implementation_instances(self, staged):
        self.discarded.append(tuple(staged))


class _AmbiguousRegistry(_Registry):
    def __init__(self, implementation):
        super().__init__(implementation)
        self.second_candidate = PassImplementationCandidate(
            pass_id=self.candidate.pass_id,
            backend_name="second-external",
            backend_origin="second-external-wheel",
            rule_modules=(),
            rule_name=self.candidate.rule_name,
        )
        self.second_manifest = BackendManifest(
            name="second-external",
            api_version=1,
            provides=lambda: object(),
            implements={"external-pass": self.second_candidate.rule_name},
        )
        self.activated_candidates = []

    def implementation_declarations_for(self, pass_id: str):
        assert pass_id == "external-pass"
        return (
            (self.candidate, self.manifest),
            (self.second_candidate, self.second_manifest),
        )

    def activate_implementation(self, candidate):
        self.activated_candidates.append(candidate)
        return super().activate_implementation(self.candidate)


def _project(name: str) -> ProjectConfiguration:
    return ProjectConfiguration(path=Path(name), description=name)


def _snapshot(project: ProjectConfiguration, activation: object, *implementations):
    old_candidate = PassImplementationCandidate(
        pass_id="old-pass",
        backend_name="old-backend",
        backend_origin="old-origin",
        rule_modules=(),
        rule_name="OldRule",
    )
    return ProjectRuntimeSnapshot(
        project=ProjectIdentitySnapshot(
            basename=project.path.name,
            path=project.path,
            description=project.description,
        ),
        effective_pass_ids=("old-pass",),
        activated_plugins=(activation,),
        activated_implementations=tuple(
            ImplementationOwnership(old_candidate, implementation)
            for implementation in implementations
        ),
    )


def _state(registry, old_project, old_snapshot):
    state = object.__new__(state_module.D810State)
    state.manager = _Manager(registry)
    registry.state = state
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


def _patch_activation(
    monkeypatch, *, binding_name="ExternalRule", block_binding_name=None
):
    schedule = ConfigV2HookSchedule(
        configured_pass_ids=("external-pass",),
        instruction_bindings=(
            RuleConfiguration(name=binding_name, is_activated=True, config={}),
        ),
        block_bindings=(
            (RuleConfiguration(name=block_binding_name, is_activated=True, config={}),)
            if block_binding_name is not None
            else ()
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
    assert len(registry.discarded) == 1
    assert registry.discarded[0][0].instance is registry.implementation
    assert registry.discarded[0][0].candidate is registry.candidate


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


def test_service_lookup_failure_discards_staged_implementation(monkeypatch):
    registry = _Registry(_Rule(), services_error=RuntimeError("services unavailable"))
    old_activation = _Activation("old")
    old_project = _project("old.json")
    old_snapshot = _snapshot(old_project, old_activation, "old-ins")
    registry.old_activation = old_activation
    state = _state(registry, old_project, old_snapshot)
    _patch_activation(monkeypatch)

    with pytest.raises(RuntimeError, match="services unavailable"):
        state._activate_project(project_index=1, project=_project("new.json"))

    assert state.current_project_runtime_snapshot is old_snapshot
    assert registry.close_calls == [(old_activation,)]
    assert registry.new_activation.close_calls == 1
    assert len(registry.discarded) == 1
    assert registry.discarded[0][0].instance is registry.implementation


def test_manager_configuration_failure_restores_manager_and_state_lanes(monkeypatch):
    registry = _Registry(_Rule())
    old_activation = _Activation("old")
    old_project = _project("old.json")
    old_snapshot = _snapshot(old_project, old_activation, "old-ins")
    registry.old_activation = old_activation
    state = _state(registry, old_project, old_snapshot)
    state._capture_project_activation_state = (
        state_module.D810State._capture_project_activation_state.__get__(state)
    )
    state._restore_project_activation_state = (
        state_module.D810State._restore_project_activation_state.__get__(state)
    )
    state.manager.fail_at = "manager-configure"
    before = state.manager.snapshot_project_activation_state()
    _patch_activation(monkeypatch)

    with pytest.raises(RuntimeError, match="manager configure failed"):
        state._activate_project(project_index=1, project=_project("new.json"))

    assert state.current_project is old_project
    assert state.current_project_runtime_snapshot is old_snapshot
    assert state.manager.snapshot_project_activation_state() == before
    assert registry.new_activation.close_calls == 1


def test_bind_failure_is_inside_transaction_and_closes_staged_activation(monkeypatch):
    registry = _Registry(_Rule())
    old_activation = _Activation("old")
    old_project = _project("old.json")
    old_snapshot = _snapshot(old_project, old_activation, "old-ins")
    registry.old_activation = old_activation
    state = _state(registry, old_project, old_snapshot)
    _patch_activation(monkeypatch)

    def fail_bind(_self, _services):
        raise RuntimeError("bind failed")

    monkeypatch.setattr(
        state_module.InstructionOptimizationRule,
        "bind_plugin_services",
        fail_bind,
    )
    with pytest.raises(RuntimeError, match="bind failed"):
        state._activate_project(project_index=1, project=_project("new.json"))

    assert state.current_project_runtime_snapshot is old_snapshot
    assert registry.new_activation.close_calls == 1
    assert len(registry.discarded) == 1


def test_execution_scope_failure_restores_manager_and_state_lanes(monkeypatch):
    registry = _Registry(_Rule())
    old_activation = _Activation("old")
    old_project = _project("old.json")
    old_snapshot = _snapshot(old_project, old_activation, "old-ins")
    registry.old_activation = old_activation
    state = _state(registry, old_project, old_snapshot)
    state._capture_project_activation_state = (
        state_module.D810State._capture_project_activation_state.__get__(state)
    )
    state._restore_project_activation_state = (
        state_module.D810State._restore_project_activation_state.__get__(state)
    )
    state.manager.started = True
    state.manager.fail_at = "execution-scope"
    state.manager.instruction_optimizer = SimpleNamespace(
        configure=lambda **_kwargs: None
    )
    state.manager.block_optimizer = SimpleNamespace(configure=lambda **_kwargs: None)
    before = state.manager.snapshot_project_activation_state()
    _patch_activation(monkeypatch)

    with pytest.raises(RuntimeError, match="execution scope compile failed"):
        state._activate_project(project_index=1, project=_project("new.json"))

    assert state.current_project is old_project
    assert state.current_project_runtime_snapshot is old_snapshot
    assert state.manager.snapshot_project_activation_state() == before
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


def test_opaque_external_binding_selects_owned_instance_once(monkeypatch):
    external_rule = _OpaqueBindingRule()
    registry = _Registry(external_rule, declared_name="opaque-implementation-id")
    old_activation = _Activation("old")
    old_project = _project("old.json")
    old_snapshot = _snapshot(old_project, old_activation, "old-ins")
    registry.old_activation = old_activation
    state = _state(registry, old_project, old_snapshot)
    internal_rule = _InternalOpaqueNameRule()
    state._build_known_instruction_rules = lambda: [internal_rule]
    _patch_activation(monkeypatch, binding_name="opaque-implementation-id")
    new_project = _project("new.json")
    new_snapshot = _snapshot(new_project, registry.new_activation, external_rule)
    registry.expected_snapshot = new_snapshot
    monkeypatch.setattr(
        state_module, "build_project_runtime_snapshot", lambda **_kwargs: new_snapshot
    )

    state._activate_project(project_index=1, project=new_project)

    assert state.current_ins_rules == [external_rule]
    assert external_rule.name == "RuntimeRule"
    assert external_rule.configure_calls == 1
    assert external_rule.log_dir_calls == 1
    assert len(external_rule.bound_services) == 1
    assert internal_rule.configure_calls == 0


def test_opaque_external_binding_rejects_multiple_owners():
    first = PassImplementationCandidate(
        pass_id="first-pass",
        backend_name="first-backend",
        backend_origin="first-origin",
        rule_modules=(),
        rule_name="opaque-implementation-id",
    )
    second = PassImplementationCandidate(
        pass_id="second-pass",
        backend_name="second-backend",
        backend_origin="second-origin",
        rule_modules=(),
        rule_name="opaque-implementation-id",
    )
    bindings = {
        (first.pass_id, first.rule_name): state_module._ExternalImplementationBinding(
            ImplementationOwnership(first, _Rule()), "instruction"
        ),
        (second.pass_id, second.rule_name): state_module._ExternalImplementationBinding(
            ImplementationOwnership(second, _Rule()), "instruction"
        ),
    }

    with pytest.raises(PipelineConfigError, match="binding .* ambiguous"):
        state_module._external_binding_for_name(
            "opaque-implementation-id", "instruction", bindings
        )


def test_external_instruction_binding_does_not_capture_same_name_block_binding(
    monkeypatch,
):
    external_rule = _OpaqueBindingRule()
    registry = _Registry(external_rule, declared_name="opaque-implementation-id")
    old_activation = _Activation("old")
    old_project = _project("old.json")
    old_snapshot = _snapshot(old_project, old_activation, "old-ins")
    registry.old_activation = old_activation
    state = _state(registry, old_project, old_snapshot)
    block_rule = _InternalOpaqueNameRule()
    state._build_known_block_rules = lambda: [block_rule]
    _patch_activation(
        monkeypatch,
        binding_name="opaque-implementation-id",
        block_binding_name="opaque-implementation-id",
    )
    new_project = _project("new.json")
    new_snapshot = _snapshot(new_project, registry.new_activation, external_rule)
    registry.expected_snapshot = new_snapshot
    monkeypatch.setattr(
        state_module, "build_project_runtime_snapshot", lambda **_kwargs: new_snapshot
    )

    state._activate_project(project_index=1, project=new_project)

    assert state.current_ins_rules == [external_rule]
    assert state.current_blk_rules == [block_rule]
    assert external_rule.configure_calls == 1
    assert external_rule.log_dir_calls == 1
    assert block_rule.configure_calls == 1


def test_ambiguous_external_declarations_abort_before_activation(monkeypatch):
    registry = _AmbiguousRegistry(_Rule())
    old_activation = _Activation("old")
    old_project = _project("old.json")
    old_snapshot = _snapshot(old_project, old_activation, "old-ins")
    registry.old_activation = old_activation
    state = _state(registry, old_project, old_snapshot)
    _patch_activation(monkeypatch)

    with pytest.raises(PassImplementationAmbiguous):
        state._activate_project(project_index=1, project=_project("new.json"))

    assert registry.activated_candidates == []
    assert state.current_project is old_project
    assert state.current_project_runtime_snapshot is old_snapshot
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
    registry.expected_snapshot = new_snapshot

    def build(**kwargs):
        assert kwargs["activated_plugins"] == (registry.new_activation,)
        assert kwargs["activated_implementations"][0].instance is rule
        assert kwargs["activated_implementations"][0].candidate is registry.candidate
        return new_snapshot

    monkeypatch.setattr(state_module, "build_project_runtime_snapshot", build)
    state._activate_project(project_index=1, project=new_project)

    assert state.current_project_runtime_snapshot is new_snapshot
    assert registry.close_calls == [(registry.new_activation,)]
    assert old_activation.close_calls == 1
    assert registry.new_activation.close_calls == 0


def test_real_registry_retains_shared_activation_and_exact_new_implementation(
    monkeypatch,
):
    old_rule = _Rule()
    new_rule = _Rule()

    class RealActivation:
        def __init__(self):
            self.calls = 0
            self.close_calls = 0

        def create_implementation(self, _implementation_id):
            self.calls += 1
            return old_rule if self.calls == 1 else new_rule

        def capability_offers(self):
            return ()

        def close(self):
            self.close_calls += 1

    activation = RealActivation()
    plugin = type("Plugin", (), {"activate": lambda self, _context: activation})()
    manifest = BackendManifest(
        name="external",
        api_version=1,
        provides=lambda: plugin,
        implements={"external-pass": "ExternalRule"},
    )
    registry = BackendRegistry(
        source=lambda: (
            BackendSpec(
                name="external",
                origin="external-wheel",
                load_manifest=lambda: manifest,
            ),
        ),
        host_view_factory=lambda _requirements, _identity: SimpleNamespace(),
        requirement_validator=lambda _requirements: None,
    )
    candidate = registry.require_unique_implementation(
        "external-pass", install_hint="external-package"
    )
    shared_activation = registry.activate(candidate.backend_name)
    registry.activate_implementation(candidate)
    old_project = _project("old.json")
    old_snapshot = _snapshot(old_project, shared_activation, old_rule)
    old_snapshot = ProjectRuntimeSnapshot(
        project=old_snapshot.project,
        effective_pass_ids=old_snapshot.effective_pass_ids,
        activated_plugins=(shared_activation,),
        activated_implementations=(ImplementationOwnership(candidate, old_rule),),
    )
    state = _state(registry, old_project, old_snapshot)
    _patch_activation(monkeypatch)
    new_project = _project("new.json")
    new_snapshot = _snapshot(new_project, shared_activation, new_rule)
    new_snapshot = ProjectRuntimeSnapshot(
        project=new_snapshot.project,
        effective_pass_ids=new_snapshot.effective_pass_ids,
        activated_plugins=(shared_activation,),
        activated_implementations=(ImplementationOwnership(candidate, new_rule),),
    )
    monkeypatch.setattr(
        state_module, "build_project_runtime_snapshot", lambda **_kwargs: new_snapshot
    )

    state._activate_project(project_index=1, project=new_project)

    assert state.current_project_runtime_snapshot is new_snapshot
    assert activation.close_calls == 0
    assert registry._implementation_instances[candidate] == [new_rule]
    assert registry.implementation_is_active(candidate)


def test_real_registry_rollback_preserves_shared_prior_activation(monkeypatch):
    old_rule = _Rule()
    failure = PassImplementationMisdeclared(
        "external-pass",
        backend_name="external",
        backend_origin="external-wheel",
        reason="second factory failed",
    )

    class RealActivation:
        def __init__(self):
            self.calls = 0
            self.close_calls = 0

        def create_implementation(self, _implementation_id):
            self.calls += 1
            if self.calls == 1:
                return old_rule
            raise failure

        def capability_offers(self):
            return ()

        def close(self):
            self.close_calls += 1

    activation = RealActivation()
    plugin = type("Plugin", (), {"activate": lambda self, _context: activation})()
    manifest = BackendManifest(
        name="external",
        api_version=1,
        provides=lambda: plugin,
        implements={"external-pass": "ExternalRule"},
    )
    registry = BackendRegistry(
        source=lambda: (
            BackendSpec(
                name="external",
                origin="external-wheel",
                load_manifest=lambda: manifest,
            ),
        ),
        host_view_factory=lambda _requirements, _identity: SimpleNamespace(),
        requirement_validator=lambda _requirements: None,
    )
    candidate = registry.require_unique_implementation(
        "external-pass", install_hint="external-package"
    )
    shared_activation = registry.activate(candidate.backend_name)
    registry.activate_implementation(candidate)
    old_project = _project("old.json")
    old_snapshot = ProjectRuntimeSnapshot(
        project=ProjectIdentitySnapshot(
            basename="old.json",
            path=old_project.path,
            description=old_project.description,
        ),
        effective_pass_ids=("old-pass",),
        activated_plugins=(shared_activation,),
        activated_implementations=(ImplementationOwnership(candidate, old_rule),),
    )
    state = _state(registry, old_project, old_snapshot)
    _patch_activation(monkeypatch)

    with pytest.raises(PassImplementationUnavailable, match="second factory"):
        state._activate_project(project_index=1, project=_project("new.json"))

    assert state.current_project_runtime_snapshot is old_snapshot
    assert activation.close_calls == 0
    assert registry._implementation_instances[candidate] == [old_rule]
    assert registry.implementation_is_active(candidate)
