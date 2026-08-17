"""Characterization and safety tests for the offline legacy migrator."""

from __future__ import annotations

import copy
import json
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from d810.core import typing
import d810.core.project_config_persistence as project_persistence
from d810.passes.pass_pipeline import PipelineConfig
import tools.migrations.migrate_project_config_v2 as migration_cli
import tools.migrations.legacy_project_config as legacy_migrator
from tools.migrations.legacy_project_config import (
    LegacyMigrationError,
    _validate_known_template_resource,
    is_canonical_v2_document,
    migrate_legacy_document,
)


CONF_DIR = Path(__file__).resolve().parents[3] / "src" / "d810" / "conf"
REPO_ROOT = Path(__file__).resolve().parents[3]
CLI_PATH = REPO_ROOT / "tools" / "migrations" / "migrate_project_config_v2.py"
KNOWN_RESOURCE_PATH = (
    Path(__file__).resolve().parents[3]
    / "tools"
    / "migrations"
    / "data"
    / "known_config_v2_templates.json"
)


def _write_legacy(path: Path) -> Path:
    """Write a small generic legacy project for subprocess CLI coverage."""

    path.write_text(
        json.dumps(
            {
                "description": "legacy fixture",
                "ins_rules": [],
                "blk_rules": [
                    {
                        "name": "IdentityCallResolver",
                        "is_activated": True,
                        "config": {},
                    }
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(
        (str(REPO_ROOT / "src"), str(REPO_ROOT), environment.get("PYTHONPATH", ""))
    )
    return subprocess.run(
        [sys.executable, str(CLI_PATH), *arguments],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

# Keep this historical data local to the test.  The routing module is removed
# later in the cutover, but these source/donor pairs remain the migration
# acceptance contract.
LEGACY_CANARY_PAIRS = (
    ("default_instruction_only.json", "default_instruction_only_config_v2_canary.json"),
    (
        "default_unflattening_tigress_engine.json",
        "default_unflattening_tigress_engine_config_v2_canary.json",
    ),
    ("hodur_flag2.json", "hodur_flag2_config_v2_canary.json"),
    ("hodur_glbopt2_only.json", "hodur_glbopt2_only_config_v2_canary.json"),
    ("eidolon.json", "eidolon_config_v2_canary.json"),
    (
        "default_unflattening_approov.json",
        "default_unflattening_approov_config_v2_canary.json",
    ),
    (
        "default_unflattening_approov_s1a.json",
        "default_unflattening_approov_s1a_config_v2_canary.json",
    ),
    ("hodur_flag2_s1a.json", "hodur_flag2_s1a_config_v2_canary.json"),
    ("hodur_flag2_with_fcp.json", "hodur_flag2_with_fcp_config_v2_canary.json"),
    ("identity_call.json", "identity_call_config_v2_canary.json"),
    (
        "default_unflattening_tigress_engine_transition_facts.json",
        "default_unflattening_tigress_engine_transition_facts_config_v2_canary.json",
    ),
    ("example_libobfuscated_abc.json", "example_libobfuscated_abc_config_v2_canary.json"),
    ("flatfold.json", "flatfold_config_v2_canary.json"),
    ("example_hodur.json", "example_hodur_config_v2_canary.json"),
    ("default_unflattening_ollvm.json", "default_unflattening_ollvm_config_v2_canary.json"),
    (
        "default_indirect_resolution.json",
        "default_indirect_resolution_config_v2_canary.json",
    ),
    (
        "default_unflattening_tigress_indirect.json",
        "default_unflattening_tigress_indirect_config_v2_canary.json",
    ),
    ("default.json", "default_config_v2_canary.json"),
    (
        "example_libobfuscated_no_fixprecedessor.json",
        "example_libobfuscated_no_fixprecedessor_config_v2_canary.json",
    ),
    ("bogus_loops.json", "bogus_loops_config_v2_canary.json"),
    ("example_libobfuscated.json", "example_libobfuscated_config_v2_canary.json"),
)

KNOWN_LEGACY_FINGERPRINTS = {
    "default_instruction_only.json": "b3f0944b2119e880d2976821953ebf2c50f2646a18a1898ee7ffc0d636c02ab2",
    "default_unflattening_tigress_engine.json": "1d343499a5cb0dec68b2a7efedf3237703dce6fc39b2aae61186feb1a0471db2",
    "hodur_flag2.json": "2c57256b924f15329eb0166edbfc693f19f56d57a4e317b2c1d03d5458fbc9eb",
    "hodur_glbopt2_only.json": "c6a288756aed1880a54981c5cf596bbb5abddc09e74cefd2c6af60406445c986",
    "eidolon.json": "bc241830174e4e5433a0b7d3aaac3f042d56978e9e77c6ed46d000c76cbbcd6c",
    "default_unflattening_approov.json": "83f454590e43ae04800cff57670a33e06185cd66ff7daf2141e1f84f62d1c9ac",
    "default_unflattening_approov_s1a.json": "1ca9be3289dd1ef4ec4893434612dbafaed5058bc12b2422ca86218ed51eda05",
    "hodur_flag2_s1a.json": "11d0f3aa77a291c12715550156585afe577010e865faaf55bdf04b4f2aef2e63",
    "hodur_flag2_with_fcp.json": "8bbdc05360b7d3f5fe9c345c19a70d8d5269fc0f6d64c5b49bef42ac8e52ae10",
    "identity_call.json": "cd035f21e1ba345d0a6108616344375f1e93866a8cfdee23c6f6770224525339",
    "default_unflattening_tigress_engine_transition_facts.json": "33a35478e5adcf6b952ec30f30727524a31f721c1d502c89f80165c9b01c4750",
    "example_libobfuscated_abc.json": "dcf343cfb6ce6f701e5954c64607d8cd8a3512345d1f3057f2be7cf7a006fa5e",
    "flatfold.json": "fb2f480fcc9088f637a83c9ed5fc9354ed9c40ae61f0fe134ae7f237160d56dd",
    "example_hodur.json": "859f94847f7796fb4166b2a7feb70d927a0c54fb50c3f750c7209cddb8c8e6c0",
    "default_unflattening_ollvm.json": "176a9441b7c866ca37d174c9bf3bcd494521acd94c4ec29c55d115cd951451cb",
    "default_indirect_resolution.json": "3ad2011d8a652b62a1d7c33a4c42f43a9c66f95d8bd4ce42a48f0514baa2a3ee",
    "default_unflattening_tigress_indirect.json": "2101314f6b7a8213922818e88b4c8aa54d57048aa83dc2c414e6640b74ea9ec9",
    "default.json": "3ad2011d8a652b62a1d7c33a4c42f43a9c66f95d8bd4ce42a48f0514baa2a3ee",
    "example_libobfuscated_no_fixprecedessor.json": "9bf4606216bfe471d526b1f12d19cb6da17fdd7a542c51f8283ab350da98c457",
    "bogus_loops.json": "a1c7a9b5ce95589848c0444413af458e33c599093f722dc89617bbf081a16945",
    "example_libobfuscated.json": "0e24934ca11872a24d65384967a9830fb567caf2d9b64ae4e15b88ec2d49f546",
}


def _load(name: str) -> dict[str, typing.Any]:
    return json.loads((CONF_DIR / name).read_text(encoding="utf-8"))


def _pipeline(document: dict[str, typing.Any]) -> list[tuple[str, dict[str, typing.Any]]]:
    additional = document.get("additional_configuration", {})
    return [
        (entry["pass_id"], entry.get("options", {}))
        for entry in additional.get("pipeline_v2", [])
    ]


def _pipeline_entries(document: dict[str, typing.Any]) -> list[dict[str, typing.Any]]:
    additional = document.get("additional_configuration", {})
    return list(additional.get("pipeline_v2", []))


def _normalized_pipeline_entries(
    document: dict[str, typing.Any],
) -> list[dict[str, typing.Any]]:
    return [PipelineConfig.from_dict(entry).to_dict() for entry in _pipeline_entries(document)]


@pytest.mark.parametrize("source_name", tuple(KNOWN_LEGACY_FINGERPRINTS))
def test_historical_legacy_fingerprint_is_frozen(source_name: str) -> None:
    encoded = json.dumps(
        _load(source_name),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    assert hashlib.sha256(encoded).hexdigest() == KNOWN_LEGACY_FINGERPRINTS[source_name]


def test_known_template_resource_is_readable_and_self_consistent() -> None:
    resource = json.loads(KNOWN_RESOURCE_PATH.read_text(encoding="utf-8"))
    assert list(resource) == sorted(KNOWN_LEGACY_FINGERPRINTS)
    validated = _validate_known_template_resource(resource)
    assert list(validated) == sorted(KNOWN_LEGACY_FINGERPRINTS)


def test_known_template_resource_rejects_corruption_with_context() -> None:
    resource = json.loads(KNOWN_RESOURCE_PATH.read_text(encoding="utf-8"))

    fingerprint_corrupt = copy.deepcopy(resource)
    fingerprint_corrupt["default.json"]["fingerprint"] = "0" * 64
    with pytest.raises(LegacyMigrationError, match=re.escape("default.json.fingerprint")):
        _validate_known_template_resource(fingerprint_corrupt)

    pipeline_corrupt = copy.deepcopy(resource)
    pipeline_corrupt["default.json"]["pipeline_v2"][0]["pass_id"] = "unknown-pass"
    with pytest.raises(LegacyMigrationError, match=re.escape("default.json.pipeline_v2[0]")):
        _validate_known_template_resource(pipeline_corrupt)

    key_corrupt = copy.deepcopy(resource)
    key_corrupt["not-a-known-project.json"] = key_corrupt.pop("default.json")
    with pytest.raises(LegacyMigrationError, match=re.escape("known_config_v2_templates.json")):
        _validate_known_template_resource(key_corrupt)


@pytest.mark.parametrize("source_name,canary_name", LEGACY_CANARY_PAIRS)
def test_mapped_bundled_portfolio_migrates_to_current_canary_semantics(
    source_name: str, canary_name: str
) -> None:
    migrated = migrate_legacy_document(_load(source_name), source_name=source_name)
    expected = _load(canary_name)

    expected_pipeline = _normalized_pipeline_entries(expected)
    assert _pipeline_entries(migrated) == expected_pipeline
    expected_owned = {
        key: value
        for key, value in expected.get("additional_configuration", {}).items()
        if key not in {"pipeline_v2_mode", "config_v2_canary"}
    }
    expected_owned["pipeline_v2"] = expected_pipeline
    assert migrated["additional_configuration"] == expected_owned
    assert _pipeline(migrated) == _pipeline(expected)
    assert migrated.get("ins_rules", []) == []
    assert migrated.get("blk_rules", []) == []


@pytest.mark.parametrize("source_name", tuple(KNOWN_LEGACY_FINGERPRINTS))
def test_known_migration_descriptions_are_canonical(source_name: str) -> None:
    migrated = migrate_legacy_document(_load(source_name), source_name=source_name)
    description = migrated["description"]
    assert description == f"Canonical config-v2 project for {source_name}."
    lowered = description.lower()
    for forbidden in ("legacy", "statemachinecffunflattener", "canary", "shadow", "alternate runtime"):
        assert forbidden not in lowered


def test_known_migration_does_not_read_donor_canary_files(monkeypatch: pytest.MonkeyPatch) -> None:
    source_name = "default.json"
    source = _load(source_name)
    original_read_text = Path.read_text

    def guarded_read_text(path: Path, *args: typing.Any, **kwargs: typing.Any) -> str:
        if "config_v2_canary" in path.name:
            raise AssertionError(f"donor canary read: {path}")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)
    monkeypatch.setattr(legacy_migrator, "_KNOWN_DONOR_TEMPLATES", None)
    migrated = migrate_legacy_document(source, source_name=source_name)
    assert _pipeline_entries(migrated)


@pytest.mark.parametrize(
    ("document", "needle"),
    (
        (
            {
                "ins_rules": [
                    {"name": "UnknownInstructionRule", "is_activated": True, "config": {}}
                ]
            },
            "ins_rules[0].name",
        ),
        (
            {
                "blk_rules": [
                    {"name": "UnknownBlockRule", "is_activated": True, "config": {}}
                ]
            },
            "blk_rules[0].name",
        ),
        (
            {
                "blk_rules": [
                    {
                        "name": "JumpFixer",
                        "is_activated": True,
                        "config": {"unsupported_option": True},
                    }
                ]
            },
            "blk_rules[0].config.unsupported_option",
        ),
        (
            {
                "ins_rules": [
                    {"name": "AddXor_Rule_1", "is_activated": True, "config": {}},
                ],
                "additional_configuration": {
                    "pipeline_v2": [{"pass_id": "jump-fixer", "options": {}}]
                },
            },
            "mixed v2 and active legacy configuration",
        ),
        (
            {
                "ins_rules": [
                    {"name": "AddXor_Rule_1", "is_activated": True, "config": {}},
                    {
                        "name": "IdentityCallResolver",
                        "is_activated": True,
                        "config": {},
                    },
                ]
            },
            "ins_rules[1].name",
        ),
        (
            {
                "ins_rules": [
                    {
                        "name": "FoldReadonlyDataRule",
                        "is_activated": True,
                        "config": {},
                    },
                    {
                        "name": "ConstantSubtreeFoldRule",
                        "is_activated": True,
                        "config": {},
                    },
                    {
                        "name": "FoldReadonlyDataRule",
                        "is_activated": True,
                        "config": {},
                    },
                ],
                "blk_rules": [
                    {
                        "name": "ForwardConstantPropagationRule",
                        "is_activated": True,
                        "config": {},
                    }
                ],
            },
            "ins_rules[2].name",
        ),
        (
            {
                "blk_rules": [
                    {"name": "JumpFixer", "is_activated": True, "config": {}},
                    {"name": "JumpFixer", "is_activated": True, "config": {}},
                ]
            },
            "blk_rules[1].name",
        ),
        (
            {
                "blk_rules": [
                    {
                        "name": "IdentityCallResolver",
                        "is_activated": True,
                        "config": {},
                    },
                    {
                        "name": "IdentityCallResolver",
                        "is_activated": True,
                        "config": {},
                    },
                ]
            },
            "blk_rules[1].name",
        ),
        (
            {
                "ins_rules": [
                    {"name": "JumpFixer", "is_activated": True, "config": {}},
                ],
                "blk_rules": [
                    {"name": "JumpFixer", "is_activated": True, "config": {}},
                ],
            },
            "ins_rules[0].name",
        ),
        (
            {
                "ins_rules": [
                    {"name": "AddXor_Rule_1", "is_activated": True, "config": {}},
                ],
                "blk_rules": [
                    {
                        "name": "AddXor_Rule_1",
                        "is_activated": True,
                        "config": {},
                    },
                ],
            },
            "blk_rules[0].name",
        ),
        (
            {
                "blk_rules": [
                    {
                        "name": "IdentityCallResolver",
                        "is_activated": True,
                        "config": {"max_search_instructions": "bad"},
                    },
                ]
            },
            "blk_rules[0].config.max_search_instructions",
        ),
        (
            {"ins_rules": [{"name": "AddXor_Rule_1", "is_activated": True}]},
            "ins_rules[0].config",
        ),
        (
            {
                "ins_rules": [
                    {"name": "AddXor_Rule_1", "is_activated": False, "config": {}}
                ]
            },
            "empty pipeline_v2",
        ),
    ),
)
def test_legacy_migration_rejects_unsupported_input(
    document: dict[str, typing.Any], needle: str
) -> None:
    with pytest.raises(LegacyMigrationError, match=re.escape(needle)):
        migrate_legacy_document(document, source_name="custom.json")


def test_canonical_v2_documents_are_normalized_and_idempotent() -> None:
    canary = _load("hodur_flag2_config_v2_canary.json")
    assert not is_canonical_v2_document(canary)

    migrated = migrate_legacy_document(canary, source_name="hodur_flag2.json")
    assert is_canonical_v2_document(migrated)
    assert migrated.get("ins_rules", []) == []
    assert migrated.get("blk_rules", []) == []
    assert "pipeline_v2_mode" not in migrated["additional_configuration"]
    assert "config_v2_canary" not in migrated["additional_configuration"]

    normalized_again = migrate_legacy_document(migrated, source_name="hodur_flag2.json")
    assert normalized_again == migrated

    def encoded(value: object) -> str:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    assert encoded(normalized_again) == encoded(migrated)


def test_canonical_v2_input_uses_normalized_typed_shapes() -> None:
    migrated = migrate_legacy_document(
        {
            "description": "custom",
            "additional_configuration": {
                "pipeline_v2": [
                    {
                        "pass_id": "jump-fixer",
                        "scheduler_policy": "WORKLIST",
                        "options": None,
                    }
                ]
            },
        },
        source_name="custom.json",
    )

    entry = _pipeline_entries(migrated)[0]
    assert entry["scheduler_policy"] == "worklist"
    assert entry["options"] == {}
    assert entry["target"] == {
        "include_eas": [],
        "exclude_eas": [],
        "tags_any": [],
        "tags_all": [],
    }
    assert entry["contract"]["maturity"] == {
        "min": None,
        "max": None,
        "preferred": None,
    }


def test_custom_typed_projection_preserves_order_and_rejects_unknown_mba_options() -> None:
    document = {
        "description": "custom",
        "ins_rules": [
            {"name": "AddXor_Rule_1", "is_activated": True, "config": {}},
            {
                "name": "Z3ConstantOptimization",
                "is_activated": True,
                "config": {"min_nb_opcode": 4, "min_nb_constant": 3},
            },
        ],
        "blk_rules": [],
    }
    migrated = migrate_legacy_document(document, source_name="custom.json")
    assert [item[0] for item in _pipeline(migrated)] == ["mba-simplify"]
    options = _pipeline(migrated)[0][1]
    assert options["transforms"] == ["add-xor-1", "z-3-constant-optimization"]
    assert options["transform_options"] == {
        "z-3-constant-optimization": {"min_nb_opcode": 4, "min_nb_constant": 3}
    }

    unsupported = {
        **document,
        "ins_rules": [
            {"name": "AddXor_Rule_1", "is_activated": True, "config": {"limit": 2}}
        ],
    }
    with pytest.raises(
        LegacyMigrationError,
        match=re.escape("ins_rules[0].config.limit"),
    ):
        migrate_legacy_document(unsupported, source_name="custom.json")


def test_cli_defaults_to_stdout_without_writing(tmp_path: Path) -> None:
    source = _write_legacy(tmp_path / "project.json")
    original = source.read_bytes()

    result = _run_cli(str(source))

    assert result.returncode == 0
    assert result.stderr == ""
    migrated = json.loads(result.stdout)
    assert migrated["additional_configuration"]["pipeline_v2"]
    assert source.read_bytes() == original
    assert not list(tmp_path.glob(".*.tmp"))


def test_cli_explicit_output_creates_destination_without_changing_source(
    tmp_path: Path,
) -> None:
    source = _write_legacy(tmp_path / "project.json")
    destination = tmp_path / "migrated.json"
    original = source.read_bytes()
    stdout_result = _run_cli(str(source))
    assert stdout_result.returncode == 0

    result = _run_cli(str(source), "--output", str(destination))

    assert result.returncode == 0
    assert result.stderr == ""
    assert destination.exists()
    assert destination.read_bytes().endswith(b"\n")
    assert destination.read_text(encoding="utf-8") == stdout_result.stdout
    assert source.read_bytes() == original
    assert json.loads(destination.read_text(encoding="utf-8"))["additional_configuration"][
        "pipeline_v2"
    ]
    assert not list(tmp_path.glob(".*.tmp"))


def test_cli_output_refuses_to_overwrite_existing_destination(tmp_path: Path) -> None:
    source = _write_legacy(tmp_path / "project.json")
    destination = tmp_path / "migrated.json"
    destination.write_text("keep me\n", encoding="utf-8")

    result = _run_cli(str(source), "--output", str(destination))

    assert result.returncode == 1
    assert "already exists" in result.stderr
    assert destination.read_text(encoding="utf-8") == "keep me\n"
    assert not list(tmp_path.glob(".*.tmp"))


def test_cli_in_place_replacement_is_canonical_and_atomic(tmp_path: Path) -> None:
    source = _write_legacy(tmp_path / "project.json")

    result = _run_cli(str(source), "--in-place")

    assert result.returncode == 0
    assert result.stderr == ""
    migrated = json.loads(source.read_text(encoding="utf-8"))
    assert migrated["additional_configuration"]["pipeline_v2"]
    assert "blk_rules" not in migrated
    assert not list(tmp_path.glob(f".{source.name}.*.tmp"))


def test_cli_validation_failure_keeps_source_and_cleans_temporary_files(
    tmp_path: Path,
) -> None:
    source = tmp_path / "bad.json"
    source.write_text(
        json.dumps(
            {
                "ins_rules": [
                    {
                        "name": "UnknownInstructionRule",
                        "is_activated": True,
                        "config": {},
                    }
                ]
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    original = source.read_bytes()

    result = _run_cli(str(source), "--in-place")

    assert result.returncode == 1
    assert "ins_rules[0].name" in result.stderr
    assert source.read_bytes() == original
    assert not list(tmp_path.glob(f".{source.name}.*.tmp"))


def test_cli_replace_failure_cleans_staged_file_and_preserves_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _write_legacy(tmp_path / "project.json")
    original = source.read_bytes()
    migrated = migration_cli._migrate_path(source)

    def fail_replace(_temporary: str | os.PathLike[str], _destination: Path) -> None:
        raise OSError("injected replace failure")

    monkeypatch.setattr(project_persistence.os, "replace", fail_replace)

    with pytest.raises(migration_cli.MigrationCliError, match="atomically write"):
        migration_cli._write_atomically(source, migrated, refuse_existing=False)

    assert source.read_bytes() == original
    assert not list(tmp_path.glob(f".{source.name}.*.tmp"))


def test_cli_check_reports_every_legacy_file_in_stable_order(tmp_path: Path) -> None:
    _write_legacy(tmp_path / "b.json")
    _write_legacy(tmp_path / "a.json")

    result = _run_cli(str(tmp_path), "--check")

    assert result.returncode == 1
    assert result.stdout == ""
    lines = [line for line in result.stderr.splitlines() if line]
    assert [line.split(":", 1)[0] for line in lines] == [
        str(tmp_path / "a.json"),
        str(tmp_path / "b.json"),
    ]
    for name in ("a.json", "b.json"):
        assert (
            f"python tools/migrations/migrate_project_config_v2.py "
            f"{tmp_path / name} --in-place"
        ) in result.stderr
    assert not list(tmp_path.glob(".*.tmp"))


def test_cli_check_reports_malformed_json_and_other_legacy_files(tmp_path: Path) -> None:
    _write_legacy(tmp_path / "legacy.json")
    (tmp_path / "invalid.json").write_text("{not-json", encoding="utf-8")

    result = _run_cli(str(tmp_path), "--check")

    assert result.returncode == 1
    assert "invalid.json" in result.stderr
    assert "invalid JSON" in result.stderr
    assert "legacy.json" in result.stderr


def test_cli_check_accepts_clean_v2_directory(tmp_path: Path) -> None:
    source = _write_legacy(tmp_path / "project.json")
    migrated = json.loads(_run_cli(str(source)).stdout)
    source.write_text(json.dumps(migrated, indent=2) + "\n", encoding="utf-8")

    result = _run_cli(str(tmp_path), "--check")

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""


@pytest.mark.parametrize(
    "arguments",
    (
        ("--output", "destination.json", "--in-place"),
        ("--output", "destination.json", "--check"),
        ("--check", "--in-place"),
    ),
)
def test_cli_rejects_ambiguous_argument_combinations(
    tmp_path: Path, arguments: tuple[str, ...]
) -> None:
    source = _write_legacy(tmp_path / "project.json")

    result = _run_cli(str(source), *arguments)

    assert result.returncode == 2
    assert "error:" in result.stderr
    assert "usage:" in result.stderr


def test_cli_rejects_directory_without_check_and_output_for_directory(
    tmp_path: Path,
) -> None:
    _write_legacy(tmp_path / "project.json")

    no_check = _run_cli(str(tmp_path))
    with_output = _run_cli(str(tmp_path), "--output", str(tmp_path / "out.json"))

    assert no_check.returncode == 2
    assert "directory input requires --check" in no_check.stderr
    assert with_output.returncode == 2
    assert "--output cannot be used with directory input" in with_output.stderr
