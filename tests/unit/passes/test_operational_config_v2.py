"""Operational config-v2 pass registry composition tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration
from d810.core.config_v2_defaults import CONFIG_V2_SUPPORTED_DEFAULT_MAPPINGS
from d810.core.pass_editor_spec import PassEditorSpec
from d810.passes.module_pass_manager import ModulePassManager
from d810.passes.operational_config_v2 import (
    CONFIG_V2_OPERATIONAL_REGISTRY_NAME,
    operational_config_v2_pass_registry,
)
from d810.passes.pipeline_config_parser import pass_specs_from_project_config
from d810.passes.registry import UnknownPassIdError

_CONF_DIR = Path("src/d810/conf")
_STATE_MACHINE_NATIVE_PIPELINE = [
    "recover_dispatcher",
    "recover_state_transitions",
    "plan_semantic_regions",
    "lower_state_machine",
    "cleanup_residual_dispatcher",
]
# Every bundled config-v2 canary is a runtime config the operational registry
# must be able to build. Derived from the routing table so it cannot drift.
_BUNDLED_CANARIES = tuple(
    mapping.runtime_config for mapping in CONFIG_V2_SUPPORTED_DEFAULT_MAPPINGS
)


def _canary(config_name: str) -> ProjectConfiguration:
    return ProjectConfiguration.from_file(
        _CONF_DIR / f"{config_name}_config_v2_canary.json"
    )


@pytest.mark.parametrize(
    ("config_name", "expected_pass_ids"),
    [
        (
            "default_instruction_only",
            ["constant-simplification", "mba-simplify", "jump-fixer"],
        ),
        (
            "default_indirect_resolution",
            ["indirect-branch-resolver", "indirect-call-resolver"],
        ),
        (
            "example_libobfuscated_no_fixprecedessor",
            [
                "constant-simplification",
                "mba-simplify",
                "simple-flattening-cleanup-unflattener",
                "jump-fixer",
            ],
        ),
        (
            "default_unflattening_tigress_indirect",
            ["mba-simplify", *_STATE_MACHINE_NATIVE_PIPELINE, "jump-fixer"],
        ),
        (
            "hodur_flag2",
            [*_STATE_MACHINE_NATIVE_PIPELINE, "jump-fixer"],
        ),
    ],
)
def test_operational_registry_builds_canary(config_name, expected_pass_ids):
    specs = pass_specs_from_project_config(
        _canary(config_name),
        operational_config_v2_pass_registry(),
    )

    assert [spec.pass_id for spec in specs] == expected_pass_ids


@pytest.mark.parametrize("canary_name", _BUNDLED_CANARIES)
def test_operational_registry_builds_all_bundled_canaries(canary_name):
    canary = ProjectConfiguration.from_file(_CONF_DIR / canary_name)

    specs = pass_specs_from_project_config(
        canary,
        operational_config_v2_pass_registry(),
    )

    assert specs


def test_operational_registry_keeps_state_machine_wrapper_unregistered():
    registry = operational_config_v2_pass_registry()

    with pytest.raises(UnknownPassIdError, match="state-machine-cff-unflattener"):
        pass_specs_from_project_config(
            {"pipeline_v2": [{"pass_id": "state-machine-cff-unflattener"}]},
            registry,
        )


def test_module_pass_manager_exposes_default_operational_registry():
    manager = ModulePassManager()

    specs = manager.pass_specs_from_project_config(
        _canary("default_instruction_only"),
        CONFIG_V2_OPERATIONAL_REGISTRY_NAME,
    )

    assert [spec.pass_id for spec in specs] == [
        "constant-simplification",
        "mba-simplify",
        "jump-fixer",
    ]


def test_operational_registry_builds_public_constant_simplification_bundle():
    registry = operational_config_v2_pass_registry()

    spec = registry.build_spec(registry.config_template_for("constant-simplification"))

    assert spec.pass_id == "constant-simplification"
    assert "constant-simplification" in registry.public_pass_ids()
    assert "global-constant-inliner" not in registry.public_pass_ids()
    assert "forward-constant-propagation" not in registry.public_pass_ids()


def test_operational_registry_catalog_templates_all_build_and_explain_stages():
    registry = operational_config_v2_pass_registry()

    assert registry.registered_pass_ids() == tuple(
        sorted(registry.registered_pass_ids())
    )
    specs = tuple(
        registry.build_spec(registry.config_template_for(pass_id))
        for pass_id in registry.registered_pass_ids()
    )

    assert tuple(spec.pass_id for spec in specs) == registry.registered_pass_ids()
    assert tuple(stage.stage_id for stage in registry.stages_for("jump-fixer")) == (
        "jump-fixer",
    )
    assert tuple(
        stage.stage_id for stage in registry.stages_for("recover_dispatcher")
    ) == ("recover_dispatcher",)
    cleanup_options = registry.config_template_for(
        "simple-flattening-cleanup-unflattener"
    ).options
    assert not {"legacy_rule", "legacy_rule_options", "native_pipeline"}.intersection(
        cleanup_options
    )


def test_all_public_config_v2_passes_declare_closed_editor_specs():
    registry = operational_config_v2_pass_registry()

    assert all(
        isinstance(registry.editor_spec_for(pass_id), PassEditorSpec)
        for pass_id in registry.public_pass_ids()
    )
