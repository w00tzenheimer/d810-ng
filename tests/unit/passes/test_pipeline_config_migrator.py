"""Legacy ProjectConfiguration to PipelineConfig v2 shadow migration tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration, RuleConfiguration
from d810.passes.pass_pipeline import PipelineConfigError
from d810.passes.pipeline_config_migrator import (
    legacy_project_config_to_pipeline_v2_shadow,
    legacy_project_file_to_pipeline_v2_shadow,
)


_REPO_ROOT = Path(__file__).resolve().parents[3]
_CONF_DIR = _REPO_ROOT / "src" / "d810" / "conf"


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "config_name",
    [
        "default_instruction_only",
        "example_libobfuscated",
    ],
)
def test_legacy_migrator_matches_checked_in_shadow(config_name):
    legacy_path = _CONF_DIR / f"{config_name}.json"
    shadow_path = _CONF_DIR / f"{config_name}.pipeline_v2.json"

    generated = legacy_project_file_to_pipeline_v2_shadow(legacy_path)

    assert generated == _load_json(shadow_path)


@pytest.mark.parametrize(
    "config_name",
    [
        "default_instruction_only",
        "example_libobfuscated",
    ],
)
def test_legacy_migrator_uses_explicit_instruction_rule_includes(config_name):
    legacy_path = _CONF_DIR / f"{config_name}.json"
    legacy = ProjectConfiguration.from_file(legacy_path)
    generated = legacy_project_file_to_pipeline_v2_shadow(legacy_path)

    instruction_entry = generated["additional_configuration"]["pipeline_v2"][0]
    rules = instruction_entry["rules"]

    assert "include_groups" not in rules
    assert "exclude_groups" not in rules
    assert rules["include"] == [
        rule.name
        for rule in legacy.ins_rules
        if rule.is_activated
    ]
    assert rules["exclude"] == []


@pytest.mark.parametrize(
    "config_name",
    [
        "default_instruction_only",
        "example_libobfuscated",
    ],
)
def test_legacy_migrator_preserves_non_empty_instruction_rule_options(config_name):
    legacy_path = _CONF_DIR / f"{config_name}.json"
    legacy = ProjectConfiguration.from_file(legacy_path)
    generated = legacy_project_file_to_pipeline_v2_shadow(legacy_path)

    instruction_entry = generated["additional_configuration"]["pipeline_v2"][0]

    assert instruction_entry["rules"]["options"] == {
        rule.name: rule.config
        for rule in legacy.ins_rules
        if rule.is_activated and rule.config
    }


@pytest.mark.parametrize(
    "config_name",
    [
        "default_instruction_only",
        "example_libobfuscated",
    ],
)
def test_legacy_migrator_keeps_z3_capability_for_current_shadow_configs(config_name):
    generated = legacy_project_file_to_pipeline_v2_shadow(
        _CONF_DIR / f"{config_name}.json"
    )

    instruction_entry = generated["additional_configuration"]["pipeline_v2"][0]

    assert instruction_entry["requires"]["capabilities"] == [
        "local_instruction_rewrite",
        "z3_solver",
    ]


def test_legacy_migrator_omits_z3_capability_without_solver_backed_rules():
    project = ProjectConfiguration(
        path=Path("no_z3.json"),
        ins_rules=[
            RuleConfiguration(
                name="FoldReadonlyDataRule",
                is_activated=True,
            ),
            RuleConfiguration(
                name="Z3ConstantOptimization",
                is_activated=False,
            ),
        ],
    )

    generated = legacy_project_config_to_pipeline_v2_shadow(project)

    instruction_entry = generated["additional_configuration"]["pipeline_v2"][0]
    assert instruction_entry["requires"]["capabilities"] == [
        "local_instruction_rewrite"
    ]


@pytest.mark.parametrize("rule_name", ["Z3ConstantOptimization", "Z3setzRuleGeneric"])
def test_legacy_migrator_adds_z3_capability_for_solver_backed_rules(rule_name):
    project = ProjectConfiguration(
        path=Path("with_z3.json"),
        ins_rules=[
            RuleConfiguration(
                name="FoldReadonlyDataRule",
                is_activated=True,
            ),
            RuleConfiguration(
                name=rule_name,
                is_activated=True,
            ),
        ],
    )

    generated = legacy_project_config_to_pipeline_v2_shadow(project)

    instruction_entry = generated["additional_configuration"]["pipeline_v2"][0]
    assert instruction_entry["requires"]["capabilities"] == [
        "local_instruction_rewrite",
        "z3_solver",
    ]


def test_legacy_migrator_preserves_example_additional_pipeline_metadata():
    generated = legacy_project_file_to_pipeline_v2_shadow(
        _CONF_DIR / "example_libobfuscated.json"
    )

    assert generated["additional_configuration"]["pipeline_v2_shadow"] == {
        "source_config": "example_libobfuscated.json",
        "runtime_source": "legacy",
        "enable_pass_pipeline": True,
    }


def test_legacy_migrator_maps_default_instruction_block_rules_explicitly():
    generated = legacy_project_file_to_pipeline_v2_shadow(
        _CONF_DIR / "default_instruction_only.json"
    )
    pipeline_v2 = generated["additional_configuration"]["pipeline_v2"]

    assert [entry["pass"] for entry in pipeline_v2] == [
        "mba-simplify",
        "global-constant-inliner",
        "jump-fixer",
    ]
    assert pipeline_v2[1]["migration"] == {
        "source_config": "default_instruction_only.json",
        "source_section": "blk_rules",
        "source_rule": "GlobalConstantInliner",
    }
    assert pipeline_v2[2]["options"]["legacy_rule"] == "JumpFixer"
    assert "JmpRuleZ3Const" in pipeline_v2[2]["options"]["enabled_rules"]


def test_legacy_migrator_rejects_unknown_active_block_rules():
    project = ProjectConfiguration(
        path=Path("unknown.json"),
        blk_rules=[
            RuleConfiguration(
                name="UnsupportedLegacyRule",
                is_activated=True,
            )
        ],
    )

    with pytest.raises(
        PipelineConfigError,
        match="unsupported legacy block rule",
    ):
        legacy_project_config_to_pipeline_v2_shadow(project)


def test_legacy_migrator_ignores_unknown_inactive_block_rules():
    project = ProjectConfiguration(
        path=Path("inactive.json"),
        ins_rules=[
            RuleConfiguration(
                name="FoldReadonlyDataRule",
                is_activated=True,
            )
        ],
        blk_rules=[
            RuleConfiguration(
                name="UnsupportedLegacyRule",
                is_activated=False,
            )
        ],
    )

    generated = legacy_project_config_to_pipeline_v2_shadow(project)

    pipeline_v2 = generated["additional_configuration"]["pipeline_v2"]
    assert [entry["pass"] for entry in pipeline_v2] == ["mba-simplify"]
