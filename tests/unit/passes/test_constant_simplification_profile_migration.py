"""Regression coverage for bundled constant-simplification profile migration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration
from d810.passes.constant_simplification_options import (
    AGGRESSIVE_MEMORY_POLICY,
    CONSTANT_STAGE_IDS,
    compile_constant_simplification_schedule,
)
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry
from d810.passes.pipeline_config_parser import pipeline_configs_from_project_config


CONF_DIR = Path("src/d810/conf")
LEGACY_KEYS = {
    "memory_policy",
    "rva_guard",
    "allow_executable_readonly",
    "persist_global_const_annotations",
}
EXPECTED_MEMORY_POLICIES = {
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
    for path in sorted(CONF_DIR.glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        pipeline = document.get("additional_configuration", {}).get("pipeline_v2", [])
        for entry in pipeline:
            if entry.get("pass_id") == "constant-simplification":
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

