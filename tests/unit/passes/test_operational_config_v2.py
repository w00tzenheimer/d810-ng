"""Operational config-v2 pass registry composition tests."""
from __future__ import annotations

from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration
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
_BUILDABLE_GENERATED_SHADOWS = [
    "bogus_loops",
    "default",
    "default_indirect_resolution",
    "default_instruction_only",
    "default_unflattening_approov",
    "default_unflattening_approov_s1a",
    "default_unflattening_switch_case",
    "default_unflattening_tigress_engine",
    "default_unflattening_tigress_engine_transition_facts",
    "default_unflattening_tigress_indirect",
    "eidolon",
    "example_anel",
    "example_hodur",
    "example_libobfuscated_abc",
    "flatfold",
    "flatfold_no_predicate_loop_fix",
    "hodur_deobfuscation",
    "hodur_flag2",
    "hodur_flag2_s1a",
    "hodur_flag2_with_fcp",
    "hodur_glbopt2_only",
]


@pytest.mark.parametrize(
    ("config_name", "expected_pass_ids"),
    [
        (
            "default_instruction_only",
            ["mba-simplify", "global-constant-inliner", "jump-fixer"],
        ),
        (
            "default_indirect_resolution",
            ["indirect-branch-resolver", "indirect-call-resolver"],
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
def test_operational_registry_builds_clean_generated_shadows(
    config_name,
    expected_pass_ids,
):
    shadow = ProjectConfiguration.from_file(
        _CONF_DIR / f"{config_name}.pipeline_v2.json"
    )

    specs = pass_specs_from_project_config(
        shadow,
        operational_config_v2_pass_registry(),
    )

    assert [spec.pass_id for spec in specs] == expected_pass_ids


@pytest.mark.parametrize("config_name", _BUILDABLE_GENERATED_SHADOWS)
def test_operational_registry_builds_all_currently_supported_generated_shadows(
    config_name,
):
    shadow = ProjectConfiguration.from_file(
        _CONF_DIR / f"{config_name}.pipeline_v2.json"
    )

    specs = pass_specs_from_project_config(
        shadow,
        operational_config_v2_pass_registry(),
    )

    assert specs


def test_operational_registry_keeps_state_machine_wrapper_unregistered():
    registry = operational_config_v2_pass_registry()

    with pytest.raises(UnknownPassIdError, match="state-machine-cff-unflattener"):
        pass_specs_from_project_config(
            {"pipeline_v2": [{"pass": "state-machine-cff-unflattener"}]},
            registry,
        )


def test_operational_registry_still_fails_on_unregistered_block_level_egglog():
    shadow = ProjectConfiguration.from_file(
        _CONF_DIR / "example_libobfuscated.pipeline_v2.json"
    )

    with pytest.raises(UnknownPassIdError, match="block-level-egglog-optimizer"):
        pass_specs_from_project_config(shadow, operational_config_v2_pass_registry())


def test_module_pass_manager_exposes_default_operational_registry():
    shadow = ProjectConfiguration.from_file(
        _CONF_DIR / "default_instruction_only.pipeline_v2.json"
    )
    manager = ModulePassManager()

    specs = manager.pass_specs_from_project_config(
        shadow,
        CONFIG_V2_OPERATIONAL_REGISTRY_NAME,
    )

    assert [spec.pass_id for spec in specs] == [
        "mba-simplify",
        "global-constant-inliner",
        "jump-fixer",
    ]
