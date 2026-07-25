"""Operational config-v2 pass registry composition tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration
from d810.core.config_v2_defaults import CONFIG_V2_SUPPORTED_DEFAULT_MAPPINGS
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
            ["mba-simplify", "global-constant-inliner", "jump-fixer"],
        ),
        (
            "default_indirect_resolution",
            ["indirect-branch-resolver", "indirect-call-resolver"],
        ),
        (
            "example_libobfuscated_no_fixprecedessor",
            [
                "mba-simplify",
                "forward-constant-propagation",
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
            {"pipeline_v2": [{"pass": "state-machine-cff-unflattener"}]},
            registry,
        )


def test_module_pass_manager_exposes_default_operational_registry():
    manager = ModulePassManager()

    specs = manager.pass_specs_from_project_config(
        _canary("default_instruction_only"),
        CONFIG_V2_OPERATIONAL_REGISTRY_NAME,
    )

    assert [spec.pass_id for spec in specs] == [
        "mba-simplify",
        "global-constant-inliner",
        "jump-fixer",
    ]
