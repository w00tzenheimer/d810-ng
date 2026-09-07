"""Config-v2 wiring tests for the narrow rotate-idiom recovery stage."""

from __future__ import annotations

import json
from pathlib import Path

from d810.core.config import ProjectConfiguration
from d810.passes.config_v2_hook_runtime import compile_config_v2_hook_schedule
from d810.passes.execution_stages import (
    ExecutionHost,
    ExecutionOwnership,
    IRScope,
)
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry
from d810.passes.pipeline_config_parser import pass_specs_from_project_config


_ROOT = Path(__file__).resolve().parents[3]
_PROFILE = _ROOT / "src/d810/conf/eidolon_v3_const_solve.json"


def _profile() -> ProjectConfiguration:
    return ProjectConfiguration(
        path=_PROFILE,
        **json.loads(_PROFILE.read_text(encoding="utf-8")),
    )


def test_eid_profile_places_rotate_recovery_directly_after_mba_solve() -> None:
    pass_ids = [
        entry["pass_id"]
        for entry in _profile().additional_configuration["pipeline_v2"]
    ]
    mba_solve_index = pass_ids.index("mba-solve")
    assert pass_ids[mba_solve_index + 1] == "rotate-idiom-recovery"


def test_rotate_registry_declares_one_hosted_block_stage_without_portable_adapter():
    registry = operational_config_v2_pass_registry()

    stages = registry.stages_for("rotate-idiom-recovery")

    assert len(stages) == 1
    assert stages[0].ownership is ExecutionOwnership.HEXRAYS_HOSTED
    assert stages[0].host is ExecutionHost.HEXRAYS_OPTBLOCK
    assert stages[0].scope is IRScope.BLOCK
    assert registry.is_hosted("rotate-idiom-recovery") is True

    spec = registry.build_spec(registry.config_template_for("rotate-idiom-recovery"))
    assert spec.pass_factory is None


def test_hosted_rotate_config_is_validated_but_not_sent_to_portable_specs():
    project = ProjectConfiguration(
        path=Path("rotate-only.runtime-config-v2.json"),
        additional_configuration={
            "pipeline_v2": [
                {
                    "pass_id": "rotate-idiom-recovery",
                    "options": {"maturities": ["GLOBAL_OPTIMIZED"]},
                }
            ]
        },
    )

    specs = pass_specs_from_project_config(
        project, operational_config_v2_pass_registry()
    )

    assert specs == ()


def test_hook_bridge_exposes_rotate_recovery_as_a_global_flow_rule() -> None:
    activation = compile_config_v2_hook_schedule(_profile())

    assert "rotate-idiom-recovery" in activation.configured_pass_ids
    assert [rule.name for rule in activation.block_bindings].count(
        "RotateIdiomRecoveryBlockRule"
    ) == 1
    rule = next(
        rule
        for rule in activation.block_bindings
        if rule.name == "RotateIdiomRecoveryBlockRule"
    )
    assert rule.config == {"maturities": ["GLOBAL_OPTIMIZED"]}
