"""Regression coverage for bundled constant-simplification profile migration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration
from d810.manager.config_v2_editing import ConfigV2EditingService
from d810.passes.constant_simplification_options import (
    AGGRESSIVE_MEMORY_POLICY,
    CONSTANT_STAGE_IDS,
    compile_constant_simplification_schedule,
)
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry
from d810.passes.pipeline_config_parser import pipeline_configs_from_project_config
from d810.passes.pass_pipeline import PipelineConfigError


CONF_DIR = Path("src/d810/conf")
LEGACY_KEYS = {
    "memory_policy",
    "rva_guard",
    "allow_executable_readonly",
    "persist_global_const_annotations",
}
EXPECTED_MEMORY_POLICIES = {
    "constant_stage_controls_config_v2_canary.json": AGGRESSIVE_MEMORY_POLICY,
    "dead_store_elimination_fixture_config_v2_canary.json": AGGRESSIVE_MEMORY_POLICY,
    "default_instruction_only_config_v2_canary.json": AGGRESSIVE_MEMORY_POLICY,
    "default_unflattening_ollvm_config_v2_canary.json": AGGRESSIVE_MEMORY_POLICY,
    "default_unflattening_tigress_engine_transition_facts_config_v2_canary.json": "strict",
    "eidolon_v3_const_solve.json": AGGRESSIVE_MEMORY_POLICY,
    "eidolon_v4_const_simplify_solve.json": AGGRESSIVE_MEMORY_POLICY,
    "example_hodur_config_v2_canary.json": "strict",
    "example_libobfuscated_abc_config_v2_canary.json": "strict",
    "example_libobfuscated_config_v2_canary.json": AGGRESSIVE_MEMORY_POLICY,
    "example_libobfuscated_no_fixprecedessor_config_v2_canary.json": "strict",
    "flatfold_config_v2_canary.json": AGGRESSIVE_MEMORY_POLICY,
    "hodur_flag2_s1a_config_v2_canary_constant_simplification.json": AGGRESSIVE_MEMORY_POLICY,
    "hodur_flag2_with_fcp_config_v2_canary.json": "strict",
}


def _constant_entries() -> tuple[tuple[Path, dict[str, object], dict[str, object]], ...]:
    entries: list[tuple[Path, dict[str, object], dict[str, object]]] = []
    for path in sorted(CONF_DIR.rglob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        additional = document.get("additional_configuration", {})
        if not isinstance(additional, dict):
            continue
        pipeline = additional.get("pipeline_v2", [])
        if not isinstance(pipeline, list):
            continue
        for entry in pipeline:
            if isinstance(entry, dict) and entry.get("pass_id") == "constant-simplification":
                entries.append((path, document, entry))
    return tuple(entries)


def test_all_bundled_constant_profiles_are_canonical_and_compile() -> None:
    registry = operational_config_v2_pass_registry()
    entries = _constant_entries()

    assert {path.name for path, _document, _entry in entries} == set(
        EXPECTED_MEMORY_POLICIES
    )
    for path, document, entry in entries:
        options = entry["options"]
        assert set(options) == {"preparation", "stages"}, path
        assert not LEGACY_KEYS.intersection(options), path

        project = ProjectConfiguration(
            path=path,
            description=str(document.get("description", "")),
            additional_configuration=document["additional_configuration"],
        )
        config = next(
            item
            for item in pipeline_configs_from_project_config(project)
            if item.pass_id == "constant-simplification"
        )
        registry.build_spec(config)
        schedule = compile_constant_simplification_schedule(config)
        assert schedule.preparation.enabled is False
        assert schedule.preparation.discover_bounded_tables is True
        assert tuple(stage.stage_id for stage in schedule.stages) == CONSTANT_STAGE_IDS
        assert all(stage.enabled for stage in schedule.stages)
        readonly = schedule.stage("fold-readonly-data")
        assert readonly.options["memory_policy"] == EXPECTED_MEMORY_POLICIES[path.name]
        assert readonly.options["allow_executable_readonly"] is False
        expected_rva_guard = path.name not in {
            "eidolon_v3_const_solve.json",
            "eidolon_v4_const_simplify_solve.json",
            "hodur_flag2_s1a_config_v2_canary_constant_simplification.json",
        }
        assert readonly.options["rva_guard"] is expected_rva_guard
        assert all(
            stage.requested_maturities == stage.supported_maturities
            for stage in schedule.stages
        )


@pytest.mark.parametrize(
    "profile_name",
    ("eidolon_v3_const_solve.json", "eidolon_v4_const_simplify_solve.json"),
)
def test_eid_profiles_preserve_aggressive_no_rva_behavior(profile_name: str) -> None:
    path = CONF_DIR / profile_name
    document = json.loads(path.read_text(encoding="utf-8"))
    entry = next(
        item
        for item in document["additional_configuration"]["pipeline_v2"]
        if item["pass_id"] == "constant-simplification"
    )
    assert entry["options"]["stages"]["fold-readonly-data"] == {
        "enabled": True,
        "maturities": [
            "CANONICAL",
            "LOCAL_OPTIMIZED",
            "CALL_MODELED",
            "GLOBAL_ANALYZED",
            "STRUCTURED",
        ],
        "memory_policy": AGGRESSIVE_MEMORY_POLICY,
        "rva_guard": False,
        "allow_executable_readonly": False,
    }


def test_external_legacy_profile_saves_as_canonical_without_behavior_change(
    tmp_path: Path,
) -> None:
    source_document = json.loads(
        (CONF_DIR / "eidolon_v3_const_solve.json").read_text(encoding="utf-8")
    )
    legacy_entry = next(
        item
        for item in source_document["additional_configuration"]["pipeline_v2"]
        if item["pass_id"] == "constant-simplification"
    )
    legacy_entry["options"] = {
        "memory_policy": AGGRESSIVE_MEMORY_POLICY,
        "rva_guard": False,
        "allow_executable_readonly": False,
        "persist_global_const_annotations": True,
    }
    legacy_entry["maturity_gates"] = ["GLOBAL_ANALYZED", "STRUCTURED"]
    source = tmp_path / "legacy.json"
    destination = tmp_path / "canonical.json"
    source.write_text(json.dumps(source_document), encoding="utf-8")

    source_project = ProjectConfiguration.from_file(source)
    legacy_config = next(
        config
        for config in pipeline_configs_from_project_config(source_project)
        if config.pass_id == "constant-simplification"
    )
    legacy_schedule = compile_constant_simplification_schedule(legacy_config)

    service = ConfigV2EditingService()
    draft = service.create_draft(source_project, destination=destination)
    validation = service.validate(draft)
    assert validation.valid is True
    service.save(draft, validation)

    saved_document = json.loads(destination.read_text(encoding="utf-8"))
    saved_entry = next(
        item
        for item in saved_document["additional_configuration"]["pipeline_v2"]
        if item["pass_id"] == "constant-simplification"
    )
    assert set(saved_entry["options"]) == {"preparation", "stages"}
    assert not LEGACY_KEYS.intersection(saved_entry["options"])

    saved_config = next(
        config
        for config in pipeline_configs_from_project_config(
            ProjectConfiguration.from_file(destination)
        )
        if config.pass_id == "constant-simplification"
    )
    assert compile_constant_simplification_schedule(saved_config) == legacy_schedule
    assert saved_config.maturity_gates == legacy_config.maturity_gates


def test_external_mixed_legacy_and_canonical_options_remain_an_error() -> None:
    with pytest.raises(PipelineConfigError, match="cannot mix legacy options"):
        pipeline_configs_from_project_config(
            {
                "pipeline_v2": [
                    {
                        "pass_id": "constant-simplification",
                        "options": {
                            "persist_global_const_annotations": False,
                            "preparation": {},
                        },
                    }
                ]
            }
        )
