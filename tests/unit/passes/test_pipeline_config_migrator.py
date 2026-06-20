"""Legacy ProjectConfiguration to PipelineConfig v2 shadow migration tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration, RuleConfiguration
from d810.passes.pass_pipeline import PipelineConfigError
from d810.passes.pipeline_config_migrator import (
    LegacyConfigMigrationStatus,
    inventory_legacy_config_directory,
    inventory_legacy_project_config,
    legacy_project_config_to_pipeline_v2_shadow,
    legacy_project_file_to_pipeline_v2_shadow,
)


_REPO_ROOT = Path(__file__).resolve().parents[3]
_CONF_DIR = _REPO_ROOT / "src" / "d810" / "conf"


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _inventory_by_name():
    return {
        item.config_name: item
        for item in inventory_legacy_config_directory(_CONF_DIR)
    }


@pytest.mark.parametrize(
    "config_name",
    [
        "default_unflattening_switch_case",
        "default_unflattening_tigress_engine",
        "default_unflattening_tigress_engine_transition_facts",
        "default_unflattening_tigress_indirect",
        "default_instruction_only",
        "example_libobfuscated",
        "hodur_deobfuscation",
        "hodur_flag2",
        "hodur_flag2_s1a",
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


def test_legacy_inventory_reports_unknown_active_block_rules_structurally():
    project = ProjectConfiguration(
        path=Path("unknown.json"),
        blk_rules=[
            RuleConfiguration(
                name="UnsupportedLegacyRule",
                is_activated=True,
            )
        ],
    )

    item = inventory_legacy_project_config(project)

    assert item.status is LegacyConfigMigrationStatus.UNSUPPORTED
    assert item.config_name == "unknown.json"
    assert item.active_instruction_rules == 0
    assert item.active_block_rules == ("UnsupportedLegacyRule",)
    assert "UnsupportedLegacyRule" in item.reason
    assert item.to_dict()["status"] == "unsupported"


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


def test_empty_legacy_config_is_inventory_empty_and_not_generated():
    project = ProjectConfiguration(path=Path("empty.json"))

    item = inventory_legacy_project_config(project)

    assert item.status is LegacyConfigMigrationStatus.EMPTY
    assert item.active_instruction_rules == 0
    assert item.active_block_rules == ()
    assert item.reason == "no active legacy rules"
    with pytest.raises(PipelineConfigError, match="no active legacy rules"):
        legacy_project_config_to_pipeline_v2_shadow(project)


def test_checked_in_pipeline_v2_shadows_are_not_empty_pipeline_payloads():
    for path in sorted(_CONF_DIR.glob("*.pipeline_v2.json")):
        payload = _load_json(path)
        assert payload["additional_configuration"]["pipeline_v2"]


def test_repo_legacy_config_inventory_reports_current_state():
    inventory = _inventory_by_name()

    assert len(inventory) == 27
    assert [
        item.config_name
        for item in inventory.values()
        if item.status is LegacyConfigMigrationStatus.EMPTY
    ] == []
    assert {
        item.config_name
        for item in inventory.values()
        if item.status is LegacyConfigMigrationStatus.UNSUPPORTED
    } == {
        "default.json",
        "default_indirect_resolution.json",
        "default_unflattening_ollvm.json",
        "default_unflattening_ollvm_s1a_fair.json",
        "example_libobfuscated_no_fixprecedessor.json",
        "identity_call.json",
        "state_machine_loops.json",
    }
    assert {
        item.config_name
        for item in inventory.values()
        if item.status is LegacyConfigMigrationStatus.MIGRATABLE
    } == {
        "bogus_loops.json",
        "default_instruction_only.json",
        "default_unflattening_approov.json",
        "default_unflattening_approov_s1a.json",
        "default_unflattening_switch_case.json",
        "default_unflattening_tigress_engine.json",
        "default_unflattening_tigress_engine_transition_facts.json",
        "default_unflattening_tigress_indirect.json",
        "eidolon.json",
        "example_anel.json",
        "example_hodur.json",
        "example_libobfuscated.json",
        "example_libobfuscated_abc.json",
        "flatfold.json",
        "flatfold_no_predicate_loop_fix.json",
        "hodur_deobfuscation.json",
        "hodur_flag2.json",
        "hodur_flag2_s1a.json",
        "hodur_flag2_with_fcp.json",
        "hodur_glbopt2_only.json",
    }


def test_repo_inventory_excludes_options_and_existing_shadow_configs():
    inventory = _inventory_by_name()

    assert "options.json" not in inventory
    assert "default_instruction_only.pipeline_v2.json" not in inventory
    assert "example_libobfuscated.pipeline_v2.json" not in inventory


def test_repo_inventory_surfaces_unsupported_reasons():
    inventory = _inventory_by_name()

    assert "IndirectCallResolver" in inventory["default.json"].reason
    assert inventory["default_unflattening_ollvm.json"].status is (
        LegacyConfigMigrationStatus.UNSUPPORTED
    )
    assert (
        "SimpleFlatteningCleanupUnflattener"
        in inventory["default_unflattening_ollvm.json"].reason
    )
    assert (
        "SimpleFlatteningCleanupUnflattener"
        in inventory["example_libobfuscated_no_fixprecedessor.json"].reason
    )
    assert "IdentityCallResolver" in inventory["identity_call.json"].reason


@pytest.mark.parametrize(
    ("config_name", "expected_instruction_rules", "expected_block_rules"),
    [
        (
            "hodur_flag2",
            0,
            ["StateMachineCffUnflattener", "JumpFixer"],
        ),
        (
            "hodur_flag2_s1a",
            0,
            ["StateMachineCffUnflattener", "JumpFixer"],
        ),
        (
            "hodur_deobfuscation",
            182,
            ["JumpFixer"],
        ),
    ],
)
def test_hodur_generated_shadows_preserve_legacy_rule_shape(
    config_name,
    expected_instruction_rules,
    expected_block_rules,
):
    legacy_path = _CONF_DIR / f"{config_name}.json"
    legacy = ProjectConfiguration.from_file(legacy_path)
    generated = legacy_project_file_to_pipeline_v2_shadow(legacy_path)
    pipeline_v2 = generated["additional_configuration"]["pipeline_v2"]
    active_instruction_rules = [
        rule for rule in legacy.ins_rules if rule.is_activated
    ]
    active_block_rules = [
        rule for rule in legacy.blk_rules if rule.is_activated
    ]

    assert len(active_instruction_rules) == expected_instruction_rules
    assert [rule.name for rule in active_block_rules] == expected_block_rules
    if active_instruction_rules:
        instruction_entry = pipeline_v2[0]
        assert instruction_entry["pass"] == "mba-simplify"
        assert instruction_entry["rules"]["include"] == [
            rule.name for rule in active_instruction_rules
        ]
        assert instruction_entry["rules"]["options"] == {
            rule.name: rule.config
            for rule in active_instruction_rules
            if rule.config
        }
        assert "include_groups" not in instruction_entry["rules"]
        assert "exclude_groups" not in instruction_entry["rules"]
        block_entries = pipeline_v2[1:]
    else:
        block_entries = pipeline_v2

    assert [
        entry["migration"]["source_rule"]
        for entry in block_entries
    ] == expected_block_rules
    for entry, rule in zip(block_entries, active_block_rules):
        options = dict(entry["options"])
        assert options.pop("legacy_rule") == rule.name
        options.pop("native_pipeline", None)
        assert options == rule.config


@pytest.mark.parametrize(
    ("config_name", "expected_instruction_rules", "expected_block_rules"),
    [
        (
            "default_unflattening_tigress_engine",
            0,
            ["StateMachineCffUnflattener"],
        ),
        (
            "default_unflattening_tigress_engine_transition_facts",
            4,
            ["ForwardConstantPropagationRule", "StateMachineCffUnflattener"],
        ),
        (
            "default_unflattening_tigress_indirect",
            7,
            ["StateMachineCffUnflattener", "JumpFixer"],
        ),
        (
            "default_unflattening_switch_case",
            178,
            ["MbaStatePreconditioner", "JumpFixer"],
        ),
    ],
)
def test_tigress_switch_generated_shadows_preserve_legacy_rule_shape(
    config_name,
    expected_instruction_rules,
    expected_block_rules,
):
    legacy_path = _CONF_DIR / f"{config_name}.json"
    legacy = ProjectConfiguration.from_file(legacy_path)
    generated = legacy_project_file_to_pipeline_v2_shadow(legacy_path)
    pipeline_v2 = generated["additional_configuration"]["pipeline_v2"]
    active_instruction_rules = [
        rule for rule in legacy.ins_rules if rule.is_activated
    ]
    active_block_rules = [
        rule for rule in legacy.blk_rules if rule.is_activated
    ]

    assert len(active_instruction_rules) == expected_instruction_rules
    assert [rule.name for rule in active_block_rules] == expected_block_rules
    if active_instruction_rules:
        instruction_entry = pipeline_v2[0]
        assert instruction_entry["pass"] == "mba-simplify"
        assert instruction_entry["rules"]["include"] == [
            rule.name for rule in active_instruction_rules
        ]
        assert instruction_entry["rules"]["options"] == {
            rule.name: rule.config
            for rule in active_instruction_rules
            if rule.config
        }
        assert "include_groups" not in instruction_entry["rules"]
        assert "exclude_groups" not in instruction_entry["rules"]
        block_entries = pipeline_v2[1:]
    else:
        block_entries = pipeline_v2

    assert [
        entry["migration"]["source_rule"]
        for entry in block_entries
    ] == expected_block_rules
    for entry, rule in zip(block_entries, active_block_rules):
        options = dict(entry["options"])
        assert options.pop("legacy_rule") == rule.name
        options.pop("native_pipeline", None)
        assert options == rule.config
