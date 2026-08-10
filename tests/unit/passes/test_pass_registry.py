"""PassRegistry conformance for PipelineConfig v2."""

from __future__ import annotations

import pytest

from d810.core.deobfuscation_case import StrategyWorkflowStage
from d810.core.pass_editor_spec import PassEditorSpec
from d810.families.state_machine_cff.pipeline import (
    standard_state_machine_passes,
    state_machine_pass_registry,
)
from d810.passes.pass_pipeline import PipelineConfig, PassResult
from d810.passes import pass_pipeline as pp
from d810.passes.execution_stages import ExecutionPipeline, ExecutionStageDescriptor
from d810.passes.registry import (
    DuplicatePassIdError,
    PassRegistry,
    UnknownPassIdError,
)
from d810.passes.state_machine_options import StateMachineCffOptions


class _FakePass:
    name = "fake"

    def run(self, ctx):
        return PassResult()


def test_registry_rejects_duplicate_pass_ids():
    registry = PassRegistry()
    registry.register("fake", _FakePass)

    with pytest.raises(DuplicatePassIdError, match="duplicate pass id"):
        registry.register("fake", _FakePass)


def test_registry_rejects_duplicate_configured_pass_ids():
    registry = PassRegistry()
    registry.register_configured("fake", lambda config: _FakePass(), public=False)

    with pytest.raises(DuplicatePassIdError, match="duplicate pass id"):
        registry.register("fake", _FakePass)

    with pytest.raises(DuplicatePassIdError, match="duplicate pass id"):
        registry.register_configured("fake", lambda config: _FakePass())


def test_registry_rejects_unknown_pass_ids():
    registry = PassRegistry()

    with pytest.raises(UnknownPassIdError, match="unknown pass id"):
        registry.build_spec(PipelineConfig(pass_id="missing"))


def test_state_machine_wrapper_pass_id_remains_unregistered():
    registry = state_machine_pass_registry()

    with pytest.raises(UnknownPassIdError, match="state-machine-cff-unflattener"):
        registry.build_spec(PipelineConfig(pass_id="state-machine-cff-unflattener"))


def test_state_machine_pass_ids_resolve_to_pass_specs():
    registry = state_machine_pass_registry()
    original_specs = standard_state_machine_passes()

    rebuilt_specs = tuple(registry.build_spec(spec.config) for spec in original_specs)

    assert [spec.pass_id for spec in rebuilt_specs] == [
        "recover_dispatcher",
        "recover_state_transitions",
        "plan_semantic_regions",
        "lower_state_machine",
        "cleanup_residual_dispatcher",
    ]
    assert [spec.config for spec in rebuilt_specs] == [
        spec.config for spec in original_specs
    ]
    for spec in rebuilt_specs:
        assert spec.pass_factory().name == spec.pass_id


def test_state_machine_registry_builds_typed_threshold_into_recovery_pass():
    registry = state_machine_pass_registry()
    template = registry.config_template_for("recover_dispatcher")

    spec = registry.build_spec(
        PipelineConfig(
            pass_id="recover_dispatcher",
            maturity_gates=template.maturity_gates,
            granularity=template.granularity,
            requirements=template.requirements,
            analyses=template.analyses,
            preservation=template.preservation,
            scheduler_policy=template.scheduler_policy,
            backend_route=template.backend_route,
            safety_policy=template.safety_policy,
            contract=template.contract,
            workflow_stage=template.workflow_stage,
            options={"min_state_constant": 0x8000},
        )
    )

    recovery_pass = spec.pass_factory()
    assert recovery_pass.options == StateMachineCffOptions(min_state_constant=0x8000)


def test_registry_build_spec_preserves_native_pass_contract():
    registry = PassRegistry()
    registry.register("fake", _FakePass)
    contract = pp.PassContract(
        scope=pp.PassScope.FACT,
        requires=pp.PassRequires(
            analyses=frozenset({"dominators"}),
            evidence=frozenset({"dispatcher_predicates"}),
        ),
        invalidates=pp.PassInvalidates(facts=frozenset({"stale_cfg_shape"})),
    )

    spec = registry.build_spec(PipelineConfig(pass_id="fake", contract=contract))

    assert spec.contract is contract
    assert spec.config.contract is contract
    assert spec.config.contract.requires.analyses == frozenset({"dominators"})
    assert spec.config.contract.requires.evidence == frozenset(
        {"dispatcher_predicates"}
    )
    assert spec.config.contract.invalidates.facts == frozenset({"stale_cfg_shape"})


def test_registry_build_spec_preserves_pass_options_metadata():
    registry = PassRegistry()
    registry.register("fake", _FakePass)
    options = {"max_passes": 3, "mode": "conservative"}

    spec = registry.build_spec(PipelineConfig(pass_id="fake", options=options))

    assert spec.options == options
    assert spec.config.options == options


def test_registry_build_spec_preserves_display_only_workflow_stage():
    registry = PassRegistry()
    registry.register("fake", _FakePass)
    config = PipelineConfig(
        pass_id="fake",
        workflow_stage=StrategyWorkflowStage.CANONICAL_TRANSFORM,
    )

    spec = registry.build_spec(config)

    assert spec.workflow_stage is StrategyWorkflowStage.CANONICAL_TRANSFORM
    assert spec.config.workflow_stage is StrategyWorkflowStage.CANONICAL_TRANSFORM


def test_registry_configured_factory_receives_full_pipeline_config():
    seen = []

    class _ConfiguredPass:
        name = "configured"

        def __init__(self, config):
            self.config = config

        def run(self, ctx):
            return PassResult()

    registry = PassRegistry()
    registry.register_configured(
        "configured",
        lambda config: seen.append(config) or _ConfiguredPass(config),
        public=False,
    )
    config = PipelineConfig(
        pass_id="configured",
        options={"transforms": ["b", "a"]},
    )

    spec = registry.build_spec(config)
    assert seen == [config]
    built = spec.pass_factory()

    assert isinstance(built, _ConfiguredPass)
    assert seen == [config, config]
    assert built.config.options["transforms"] == ["b", "a"]
    assert spec.options == config.options


def test_registry_exposes_deterministic_read_only_catalog_metadata():
    registry = PassRegistry()
    template = PipelineConfig(
        pass_id="zeta",
        options={"mode": "default"},
    )
    registry.register_configured(
        "zeta",
        lambda config: _FakePass(),
        config_template=template,
        stages=(
            ExecutionStageDescriptor(
                pass_id="zeta",
                stage_id="zeta",
                pipeline=ExecutionPipeline.FLOW,
                implementation_name="ZetaTransform",
            ),
        ),
        public=False,
    )
    registry.register(
        "alpha",
        _FakePass,
        config_template=PipelineConfig(pass_id="alpha"),
        public=False,
    )

    assert registry.registered_pass_ids() == ("alpha", "zeta")
    assert registry.config_template_for("zeta") is template
    assert tuple(stage.stage_id for stage in registry.stages_for("zeta")) == ("zeta",)
    assert registry.is_configured("zeta") is True
    assert registry.is_configured("alpha") is False
    with pytest.raises(TypeError):
        template.options["new"] = True


def test_registry_catalog_rejects_unknown_metadata_lookup():
    registry = PassRegistry()

    with pytest.raises(UnknownPassIdError, match="unknown pass id"):
        registry.config_template_for("missing")


def test_registry_separates_public_catalog_from_compatibility_ids():
    registry = PassRegistry()
    registry.register("public", _FakePass)
    registry.register("compat", _FakePass, public=False)

    assert registry.registered_pass_ids() == ("compat", "public")
    assert registry.public_pass_ids() == ("public",)
    assert registry.build_spec(PipelineConfig(pass_id="compat")).pass_id == "compat"


def test_registry_retains_the_explicit_editor_spec_for_a_registered_pass():
    registry = PassRegistry()
    editor_spec = PassEditorSpec.summary()

    registry.register("public", _FakePass, editor_spec=editor_spec)
    registry.register("compat", _FakePass, public=False)

    assert registry.editor_spec_for("public") is editor_spec
    assert registry.editor_spec_for("compat") is None
