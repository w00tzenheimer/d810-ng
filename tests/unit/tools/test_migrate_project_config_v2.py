"""Characterization and safety tests for the offline legacy migrator."""

from __future__ import annotations

import copy
import errno
import json
import os
import re
import stat
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


def _run_cli(
    *arguments: str, timeout: float = 10
) -> subprocess.CompletedProcess[str]:
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
        timeout=timeout,
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

# These are the identities of the legacy documents at the current
# config-recon-mainline cutover point.  Keep this small compatibility ledger
# explicit: the bundled runtime presets are canonical v2 now, but migration
# must continue to recognize the last legacy inputs that users can still
# present to the offline migrator.
LATEST_MAINLINE_LEGACY_FINGERPRINTS = {
    "eidolon.json": "435dac2b0c3aa6c8a7fc00188b1cd5e25d57d17e288d6f703fad2f34cc836995",
    "default_unflattening_tigress_engine_transition_facts.json": (
        "dbc9188afe30a2aa64f46a457293a68412e3f8462bd9e54743edd2ffdc4b179b"
    ),
}

LEGACY_MIGRATION_FIXTURE_DIR = (
    Path(__file__).resolve().parents[2] / "fixtures" / "migration_legacy"
)
LEGACY_MIGRATION_FIXTURES = {
    "eidolon.json": (
        "eidolon_historical.json",
        "eidolon_mainline.json",
    ),
    "default_unflattening_tigress_engine_transition_facts.json": (
        "tigress_transition_facts_historical.json",
        "tigress_transition_facts_mainline.json",
    ),
}


def _load(name: str) -> dict[str, typing.Any]:
    return json.loads((CONF_DIR / name).read_text(encoding="utf-8"))


def _load_legacy_fixture(name: str) -> dict[str, typing.Any]:
    """Load a committed historical migration corpus document."""

    return json.loads((LEGACY_MIGRATION_FIXTURE_DIR / name).read_text(encoding="utf-8"))


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
def test_historical_legacy_fingerprint_catalogue_is_frozen(source_name: str) -> None:
    # The bundled source files are canonical v2 now, so the old legacy
    # documents are intentionally no longer shipped as runtime fixtures.  The
    # readable migration resource is the durable record of each historical
    # source identity and is independently validated below.
    resource = json.loads(KNOWN_RESOURCE_PATH.read_text(encoding="utf-8"))
    assert resource[source_name]["fingerprint"] == KNOWN_LEGACY_FINGERPRINTS[source_name]


@pytest.mark.parametrize(
    "source_name", tuple(LATEST_MAINLINE_LEGACY_FINGERPRINTS)
)
def test_latest_mainline_legacy_identities_are_catalogued(source_name: str) -> None:
    """The migration catalogue follows the current mainline legacy corpus."""

    resource = json.loads(KNOWN_RESOURCE_PATH.read_text(encoding="utf-8"))
    alias = LATEST_MAINLINE_LEGACY_FINGERPRINTS[source_name]
    assert resource[source_name]["fingerprint_aliases"] == [alias]
    assert legacy_migrator._KNOWN_BY_IDENTITY[(source_name, alias)] is (
        legacy_migrator._KNOWN_BY_IDENTITY[
            (source_name, KNOWN_LEGACY_FINGERPRINTS[source_name])
        ]
    )


@pytest.mark.parametrize("source_name", tuple(LATEST_MAINLINE_LEGACY_FINGERPRINTS))
def test_historical_and_latest_mainline_documents_use_same_donor(
    source_name: str,
) -> None:
    """Both real legacy snapshots resolve through the frozen donor projection."""

    catalogue = json.loads(KNOWN_RESOURCE_PATH.read_text(encoding="utf-8"))[source_name]
    expected = {
        "description": catalogue["description"],
        "additional_configuration": {
            **catalogue["owned_additional_configuration"],
            "pipeline_v2": catalogue["pipeline_v2"],
        },
    }
    historical_name, latest_name = LEGACY_MIGRATION_FIXTURES[source_name]
    historical = _load_legacy_fixture(historical_name)
    latest = _load_legacy_fixture(latest_name)

    assert migrate_legacy_document(historical, source_name=source_name) == expected
    assert migrate_legacy_document(latest, source_name=source_name) == expected


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

    aliases_corrupt = copy.deepcopy(resource)
    aliases_corrupt["eidolon.json"]["fingerprint_aliases"] = ["0" * 64]
    with pytest.raises(
        LegacyMigrationError, match=re.escape("eidolon.json.fingerprint_aliases")
    ):
        _validate_known_template_resource(aliases_corrupt)

    pipeline_corrupt = copy.deepcopy(resource)
    pipeline_corrupt["default.json"]["pipeline_v2"][0]["pass_id"] = "unknown-pass"
    with pytest.raises(LegacyMigrationError, match=re.escape("default.json.pipeline_v2[0]")):
        _validate_known_template_resource(pipeline_corrupt)

    key_corrupt = copy.deepcopy(resource)
    key_corrupt["not-a-known-project.json"] = key_corrupt.pop("default.json")
    with pytest.raises(LegacyMigrationError, match=re.escape("known_config_v2_templates.json")):
        _validate_known_template_resource(key_corrupt)


@pytest.mark.parametrize(
    ("payload", "duplicate_key"),
    (
        ('{"default.json": {}, "default.json": {}}', "default.json"),
        (
            '{"default.json": {"owned_additional_configuration": '
            '{"idb_key": 1, "idb_key": 2}}}',
            "idb_key",
        ),
    ),
)
def test_known_template_loader_rejects_root_and_nested_duplicate_keys(
    monkeypatch, payload: str, duplicate_key: str
) -> None:
    class _FakeResource:
        name = "known_config_v2_templates.json"

        def read_text(self, **kwargs):
            return payload

    monkeypatch.setattr(
        legacy_migrator, "_KNOWN_TEMPLATE_RESOURCE_PATH", _FakeResource()
    )

    with pytest.raises(LegacyMigrationError) as raised:
        legacy_migrator._load_known_template_resource()

    message = str(raised.value)
    assert "known_config_v2_templates.json" in message
    assert duplicate_key in message
    assert "duplicate JSON object key" in message


@pytest.mark.parametrize("source_name", tuple(KNOWN_LEGACY_FINGERPRINTS))
def test_mapped_bundled_portfolio_migrates_to_catalogue_semantics(
    source_name: str
) -> None:
    migrated = migrate_legacy_document(_load(source_name), source_name=source_name)
    catalogue = json.loads(KNOWN_RESOURCE_PATH.read_text(encoding="utf-8"))[source_name]
    expected = {
        "description": catalogue["description"],
        "additional_configuration": {
            **catalogue["owned_additional_configuration"],
            "pipeline_v2": catalogue["pipeline_v2"],
        },
    }

    expected_pipeline = _normalized_pipeline_entries(expected)
    assert _pipeline_entries(migrated) == expected_pipeline
    expected_owned = {
        key: value
        for key, value in expected.get("additional_configuration", {}).items()
        if key not in {"pipeline_v2_mode", "config_v2_" + "canary"}
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


def test_known_migration_does_not_read_bundled_project_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_name = "default.json"
    source = _load(source_name)
    original_read_text = Path.read_text

    def guarded_read_text(path: Path, *args: typing.Any, **kwargs: typing.Any) -> str:
        if path.parent == CONF_DIR:
            raise AssertionError(f"bundled project read: {path}")
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


def test_canonical_v2_documents_are_normalized_and_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Build the input from the readable migration resource and retain transient
    # fields and empty legacy sections so this exercises normalization.
    original_read_text = Path.read_text

    def guarded_read_text(path: Path, *args: typing.Any, **kwargs: typing.Any) -> str:
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)
    resource = json.loads(KNOWN_RESOURCE_PATH.read_text(encoding="utf-8"))
    template = resource["hodur_flag2.json"]
    canonical = {
        "description": template["description"],
        "additional_configuration": {
            **copy.deepcopy(template["owned_additional_configuration"]),
            "pipeline_v2": copy.deepcopy(template["pipeline_v2"]),
        },
    }
    document = copy.deepcopy(canonical)
    document["ins_rules"] = []
    document["blk_rules"] = []
    document["additional_configuration"]["pipeline_v2_mode"] = "config-v2"
    document["additional_configuration"]["config_v2_" + "canary"] = True

    assert not is_canonical_v2_document(document)

    migrated = migrate_legacy_document(document, source_name="hodur_flag2.json")
    assert is_canonical_v2_document(migrated)
    assert migrated == canonical
    assert migrated.get("ins_rules", []) == []
    assert migrated.get("blk_rules", []) == []
    assert "pipeline_v2_mode" not in migrated["additional_configuration"]
    assert "config_v2_" + "canary" not in migrated["additional_configuration"]

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
    assert lines == [
        f"{tmp_path / 'a.json'}: legacy project requires migration; migrate with: "
        f"python tools/migrations/migrate_project_config_v2.py {tmp_path / 'a.json'} --in-place",
        f"{tmp_path / 'b.json'}: legacy project requires migration; migrate with: "
        f"python tools/migrations/migrate_project_config_v2.py {tmp_path / 'b.json'} --in-place",
    ]
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


def test_cli_output_publish_is_atomic_no_clobber_when_creator_races(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    source = _write_legacy(tmp_path / "project.json")
    destination = tmp_path / "migrated.json"
    real_link = migration_cli.os.link

    def create_destination_then_publish(
        staged: Path, target: Path, **kwargs: object
    ) -> None:
        target.write_text("creator-owned\n", encoding="utf-8")
        real_link(staged, target, **kwargs)

    monkeypatch.setattr(migration_cli.os, "link", create_destination_then_publish)

    status = migration_cli.main([str(source), "--output", str(destination)])
    captured = capsys.readouterr()

    assert status == 1
    assert captured.out == ""
    assert captured.err == f"error: {destination}: destination already exists\n"
    assert destination.read_text(encoding="utf-8") == "creator-owned\n"
    assert not list(tmp_path.glob(f".{destination.name}.*.tmp"))


def test_cli_output_refuses_dangling_destination_symlink(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = _write_legacy(tmp_path / "project.json")
    destination = tmp_path / "migrated.json"
    missing_target = tmp_path / "not-created.json"
    destination.symlink_to(missing_target)

    status = migration_cli.main([str(source), "--output", str(destination)])
    captured = capsys.readouterr()

    assert status == 1
    assert captured.out == ""
    assert captured.err == f"error: {destination}: destination already exists\n"
    assert destination.is_symlink()
    assert not missing_target.exists()
    assert not list(tmp_path.glob(f".{destination.name}.*.tmp"))


def test_cli_public_in_place_replace_failure_is_controlled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = _write_legacy(tmp_path / "project.json")
    original = source.read_bytes()

    def fail_replace(_temporary: Path, _destination: Path) -> None:
        raise OSError("injected replace failure")

    monkeypatch.setattr(project_persistence.os, "replace", fail_replace)

    status = migration_cli.main([str(source), "--in-place"])
    captured = capsys.readouterr()

    assert status == 1
    assert captured.out == ""
    assert captured.err == (
        f"error: Could not atomically write project configuration {source}\n"
    )
    assert "Traceback" not in captured.err
    assert source.read_bytes() == original
    assert not list(tmp_path.glob(f".{source.name}.*.tmp"))


def test_cli_rejects_invalid_utf8_without_traceback(tmp_path: Path) -> None:
    source = tmp_path / "invalid.json"
    source.write_bytes(b"{\xff\n")

    result = _run_cli(str(source))

    assert result.returncode == 1
    assert "invalid UTF-8" in result.stderr
    assert "Traceback" not in result.stderr
    assert not list(tmp_path.glob(f".{source.name}.*.tmp"))


def test_cli_rejects_symlink_input_without_opening_target(tmp_path: Path) -> None:
    target = _write_legacy(tmp_path / "target.json")
    source = tmp_path / "project.json"
    source.symlink_to(target)

    result = _run_cli(str(source))

    assert result.returncode == 2
    assert "symlink" in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_rejects_dangling_symlink_input(tmp_path: Path) -> None:
    source = tmp_path / "project.json"
    source.symlink_to(tmp_path / "missing.json")

    result = _run_cli(str(source))

    assert result.returncode == 2
    assert "symlink" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO inputs are POSIX-only")
def test_cli_rejects_fifo_input_without_blocking(tmp_path: Path) -> None:
    source = tmp_path / "project.json"
    os.mkfifo(source)

    result = _run_cli(str(source), timeout=2)

    assert result.returncode == 2
    assert "regular file" in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_check_reports_unreadable_directory_even_when_privileged(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "unreadable"
    directory.mkdir()
    directory.chmod(0)
    try:
        result = _run_cli(str(directory), "--check")
    finally:
        directory.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    assert result.returncode == 1
    assert "read/search permission bits" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO entries are POSIX-only")
def test_cli_check_reports_special_json_entries_instead_of_skipping(
    tmp_path: Path,
) -> None:
    special = tmp_path / "special.json"
    os.mkfifo(special)

    result = _run_cli(str(tmp_path), "--check", timeout=2)

    assert result.returncode == 1
    assert (
        f"{special}: special/non-regular JSON directory entry; "
        "migration command is not applicable"
    ) in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_check_rejects_directory_symlink(tmp_path: Path) -> None:
    target = tmp_path / "projects"
    target.mkdir()
    directory = tmp_path / "projects-link"
    directory.symlink_to(target, target_is_directory=True)

    result = _run_cli(str(directory), "--check")

    assert result.returncode == 2
    assert "symlink" in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_output_transient_staged_cleanup_failure_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = _write_legacy(tmp_path / "project.json")
    destination = tmp_path / "migrated.json"
    real_remove = migration_cli._remove_staged_path
    attempts = 0

    def fail_once_then_remove(path: Path) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("transient unlink failure")
        real_remove(path)

    monkeypatch.setattr(migration_cli, "_remove_staged_path", fail_once_then_remove)

    status = migration_cli.main([str(source), "--output", str(destination)])
    captured = capsys.readouterr()

    assert status == 0
    assert captured.out == ""
    assert captured.err == ""
    assert destination.exists()
    assert attempts == 2
    assert not list(tmp_path.glob(f".{destination.name}.*.tmp"))


def test_cli_output_persistent_staged_cleanup_failure_reports_committed_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = _write_legacy(tmp_path / "project.json")
    destination = tmp_path / "migrated.json"

    def always_fail(_path: Path) -> None:
        raise OSError("persistent unlink failure")

    monkeypatch.setattr(migration_cli, "_remove_staged_path", always_fail)

    status = migration_cli.main([str(source), "--output", str(destination)])
    captured = capsys.readouterr()
    leaked = list(tmp_path.glob(f".{destination.name}.*.tmp"))

    assert status == 1
    assert captured.out == ""
    assert destination.exists()
    assert len(leaked) == 1
    assert captured.err == (
        f"warning: destination committed at {destination}; staged cleanup failed "
        f"after 2 attempts; leaked staging path: {leaked[0]}\n"
    )
    assert str(leaked[0]) in captured.err


def test_cli_output_failed_publish_cleanup_failure_preserves_primary_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = _write_legacy(tmp_path / "project.json")
    destination = tmp_path / "migrated.json"

    def fail_link(_staged: Path, _target: Path, **_kwargs: object) -> None:
        raise FileExistsError(errno.EEXIST, "destination exists")

    def fail_remove(_path: Path) -> None:
        raise OSError("persistent unlink failure")

    monkeypatch.setattr(migration_cli.os, "link", fail_link)
    monkeypatch.setattr(migration_cli, "_remove_staged_path", fail_remove)

    status = migration_cli.main([str(source), "--output", str(destination)])
    captured = capsys.readouterr()
    leaked = list(tmp_path.glob(f".{destination.name}.*.tmp"))

    assert status == 1
    assert not destination.exists()
    assert len(leaked) == 1
    assert captured.err == (
        f"error: {destination}: destination already exists; staged cleanup failed "
        f"after 2 attempts; leaked staging path: {leaked[0]}\n"
    )


@pytest.mark.parametrize(
    "error",
    (
        OSError(errno.EXDEV, "cross-device link"),
        PermissionError(errno.EACCES, "permission denied"),
        OSError(errno.EOPNOTSUPP, "hard links unsupported"),
    ),
)
def test_cli_output_link_capability_errors_are_controlled_and_clean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: OSError,
) -> None:
    source = _write_legacy(tmp_path / "project.json")
    destination = tmp_path / "migrated.json"

    def fail_link(_staged: Path, _target: Path, **_kwargs: object) -> None:
        raise error

    monkeypatch.setattr(migration_cli.os, "link", fail_link)

    status = migration_cli.main([str(source), "--output", str(destination)])
    captured = capsys.readouterr()

    assert status == 1
    assert captured.err.startswith(
        f"error: {destination}: atomic no-clobber publish failed:"
    )
    assert "Traceback" not in captured.err
    assert not destination.exists()
    assert not list(tmp_path.glob(f".{destination.name}.*.tmp"))


def test_cli_single_file_swap_before_consumption_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = _write_legacy(tmp_path / "project.json")
    original = tmp_path / "project-original.json"
    attacker = _write_legacy(tmp_path / "attacker.json")
    real_open = migration_cli._open_single_file_descriptor

    def swap_then_open(path: Path) -> int:
        path.rename(original)
        path.symlink_to(attacker)
        return real_open(path)

    monkeypatch.setattr(migration_cli, "_open_single_file_descriptor", swap_then_open)

    status = migration_cli.main([str(source)])
    captured = capsys.readouterr()

    assert status == 1
    assert captured.out == ""
    assert "symlink" in captured.err or "regular" in captured.err
    assert "attacker.json" not in captured.out
    assert source.is_symlink()
    assert original.exists()


def test_cli_single_file_replacement_before_consumption_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = _write_legacy(tmp_path / "project.json")
    original = tmp_path / "project-original.json"
    real_open = migration_cli._open_single_file_descriptor

    def replace_then_open(path: Path) -> int:
        path.rename(original)
        _write_legacy(path)
        return real_open(path)

    monkeypatch.setattr(migration_cli, "_open_single_file_descriptor", replace_then_open)

    status = migration_cli.main([str(source)])
    captured = capsys.readouterr()

    assert status == 1
    assert captured.out == ""
    assert "changed" in captured.err
    assert original.exists()
    assert source.exists()


def test_cli_directory_swap_before_enumeration_uses_stable_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory = tmp_path / "projects"
    directory.mkdir()
    original = tmp_path / "projects-original"
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    _write_legacy(attacker / "attacker.json")
    real_open = migration_cli._open_directory_handle

    def open_then_swap(path: Path) -> int:
        descriptor = real_open(path)
        path.rename(original)
        path.symlink_to(attacker, target_is_directory=True)
        return descriptor

    monkeypatch.setattr(migration_cli, "_open_directory_handle", open_then_swap)

    status = migration_cli.main([str(directory), "--check"])
    captured = capsys.readouterr()

    assert status == 0
    assert captured.out == ""
    assert captured.err == ""
    assert "attacker.json" not in captured.err
    assert directory.is_symlink()
    assert original.is_dir()


def test_cli_directory_replacement_before_enumeration_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory = tmp_path / "projects"
    directory.mkdir()
    original = tmp_path / "projects-original"
    real_open = migration_cli._open_directory_handle

    def replace_then_open(path: Path) -> int:
        path.rename(original)
        path.mkdir()
        _write_legacy(path / "attacker.json")
        return real_open(path)

    monkeypatch.setattr(migration_cli, "_open_directory_handle", replace_then_open)

    status = migration_cli.main([str(directory), "--check"])
    captured = capsys.readouterr()

    assert status == 1
    assert captured.out == ""
    assert "changed" in captured.err
    assert "attacker.json" not in captured.err
    assert original.is_dir()
    assert directory.is_dir()


def test_cli_directory_child_swap_before_open_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory = tmp_path / "projects"
    directory.mkdir()
    child = _write_legacy(directory / "project.json")
    original = directory / "project-original.json"
    attacker = _write_legacy(tmp_path / "attacker.json")
    real_open = migration_cli._open_directory_child_descriptor

    def swap_then_open(
        directory_fd: int, name: str, expected_stat: os.stat_result
    ) -> int:
        child.rename(original)
        child.symlink_to(attacker)
        return real_open(directory_fd, name, expected_stat)

    monkeypatch.setattr(
        migration_cli, "_open_directory_child_descriptor", swap_then_open
    )

    status = migration_cli.main([str(directory), "--check"])
    captured = capsys.readouterr()

    assert status == 1
    assert "changed" in captured.err or "symlink" in captured.err
    assert "attacker.json" not in captured.err
    assert child.is_symlink()
    assert original.exists()


def test_cli_output_verifies_normal_link_identity_and_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = _write_legacy(tmp_path / "project.json")
    destination = tmp_path / "migrated.json"
    migrated = migration_cli._migrate_path(source)
    expected_bytes = migration_cli._canonical_json(migrated).encode("utf-8")
    real_link = migration_cli.os.link
    link_identities: list[tuple[int, int]] = []

    def record_link(staged: Path, target: Path, **kwargs: object) -> None:
        real_link(staged, target, **kwargs)
        link_identities.append((staged.stat().st_ino, target.stat().st_ino))

    monkeypatch.setattr(migration_cli.os, "link", record_link)

    status = migration_cli.main([str(source), "--output", str(destination)])
    captured = capsys.readouterr()

    assert status == 0
    assert captured.err == ""
    assert link_identities and link_identities[0][0] == link_identities[0][1]
    assert destination.read_bytes() == expected_bytes
    assert not list(tmp_path.glob(f".{destination.name}.*.tmp"))


@pytest.mark.parametrize(
    "tamper_kind",
    (
        "invalid",
        "same_size_valid",
    ),
)
def test_cli_output_rejects_replaced_staged_bytes_after_link(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tamper_kind: str,
) -> None:
    source = _write_legacy(tmp_path / "project.json")
    destination = tmp_path / "migrated.json"
    migrated = migration_cli._migrate_path(source)
    canonical_bytes = migration_cli._canonical_json(migrated).encode("utf-8")
    if tamper_kind == "invalid":
        tampered_bytes = b"tampered, not json\n"
    else:
        tampered_bytes = canonical_bytes.replace(
            b"legacy fixture", b"legacy payload"
        )
        assert len(tampered_bytes) == len(canonical_bytes)
        assert tampered_bytes != canonical_bytes
    real_link = migration_cli.os.link

    def replace_staged_then_link(
        staged: Path, target: Path, **kwargs: object
    ) -> None:
        staged.unlink()
        staged.write_bytes(tampered_bytes)
        real_link(staged, target, **kwargs)

    monkeypatch.setattr(migration_cli.os, "link", replace_staged_then_link)

    status = migration_cli.main([str(source), "--output", str(destination)])
    captured = capsys.readouterr()

    assert status == 1
    assert "destination committed but integrity verification failed" in captured.err
    assert "staged path retained" in captured.err
    assert "Traceback" not in captured.err
    assert destination.read_bytes() == tampered_bytes
    assert len(list(tmp_path.glob(f".{destination.name}.*.tmp"))) == 1


def test_cli_single_file_open_verification_close_failure_is_controlled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = _write_legacy(tmp_path / "project.json")
    real_close = migration_cli.os.close
    bad_descriptor: int | None = None

    def fail_fstat(descriptor: int) -> os.stat_result:
        nonlocal bad_descriptor
        bad_descriptor = descriptor
        raise OSError("injected input fstat failure")

    def fail_close(descriptor: int) -> None:
        if descriptor == bad_descriptor:
            raise OSError("injected input close failure")
        real_close(descriptor)

    monkeypatch.setattr(migration_cli.os, "fstat", fail_fstat)
    monkeypatch.setattr(migration_cli.os, "close", fail_close)

    status = migration_cli.main([str(source)])
    captured = capsys.readouterr()

    assert status == 1
    assert "could not verify input" in captured.err
    assert "descriptor close failed" in captured.err
    assert "Traceback" not in captured.err


def test_cli_child_open_verification_close_failure_is_controlled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory = tmp_path / "projects"
    directory.mkdir()
    _write_legacy(directory / "project.json")
    real_fstat = migration_cli.os.fstat
    real_close = migration_cli.os.close
    calls = 0
    bad_descriptor: int | None = None

    def fail_child_fstat(descriptor: int) -> os.stat_result:
        nonlocal calls, bad_descriptor
        calls += 1
        if calls == 3:
            bad_descriptor = descriptor
            raise OSError("injected child fstat failure")
        return real_fstat(descriptor)

    def fail_close(descriptor: int) -> None:
        if descriptor == bad_descriptor:
            raise OSError("injected child close failure")
        real_close(descriptor)

    monkeypatch.setattr(migration_cli.os, "fstat", fail_child_fstat)
    monkeypatch.setattr(migration_cli.os, "close", fail_close)

    status = migration_cli.main([str(directory), "--check"])
    captured = capsys.readouterr()

    assert status == 1
    assert "could not verify during directory check" in captured.err
    assert "descriptor close failed" in captured.err
    assert "Traceback" not in captured.err


def test_cli_expected_stat_close_failure_is_controlled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = _write_legacy(tmp_path / "project.json")
    real_fstat = migration_cli.os.fstat
    real_close = migration_cli.os.close
    calls = 0
    bad_descriptor: int | None = None

    def fail_expected_fstat(descriptor: int) -> os.stat_result:
        nonlocal calls, bad_descriptor
        calls += 1
        if calls == 2:
            bad_descriptor = descriptor
            raise OSError("injected expected-stat fstat failure")
        return real_fstat(descriptor)

    def fail_close(descriptor: int) -> None:
        if descriptor == bad_descriptor:
            raise OSError("injected expected-stat close failure")
        real_close(descriptor)

    monkeypatch.setattr(migration_cli.os, "fstat", fail_expected_fstat)
    monkeypatch.setattr(migration_cli.os, "close", fail_close)

    status = migration_cli.main([str(source)])
    captured = capsys.readouterr()

    assert status == 1
    assert "could not verify input" in captured.err
    assert "descriptor close failed" in captured.err
    assert "Traceback" not in captured.err


def test_cli_directory_verification_close_failure_is_controlled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory = tmp_path / "projects"
    directory.mkdir()
    real_close = migration_cli.os.close
    bad_descriptor: int | None = None

    def fail_directory_fstat(descriptor: int) -> os.stat_result:
        nonlocal bad_descriptor
        bad_descriptor = descriptor
        raise OSError("injected directory fstat failure")

    def fail_close(descriptor: int) -> None:
        if descriptor == bad_descriptor:
            raise OSError("injected directory close failure")
        real_close(descriptor)

    monkeypatch.setattr(migration_cli.os, "fstat", fail_directory_fstat)
    monkeypatch.setattr(migration_cli.os, "close", fail_close)

    status = migration_cli.main([str(directory), "--check"])
    captured = capsys.readouterr()

    assert status == 1
    assert "could not inspect directory" in captured.err
    assert "descriptor close failed" in captured.err
    assert "Traceback" not in captured.err


def test_cli_final_directory_close_failure_is_not_clean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory = tmp_path / "projects"
    directory.mkdir()
    real_open = migration_cli._open_directory_handle
    real_close = migration_cli.os.close
    directory_descriptor: int | None = None

    def capture_directory_descriptor(path: Path) -> int:
        nonlocal directory_descriptor
        directory_descriptor = real_open(path)
        return directory_descriptor

    def fail_final_close(descriptor: int) -> None:
        if descriptor == directory_descriptor:
            raise OSError("injected final directory close failure")
        real_close(descriptor)

    monkeypatch.setattr(
        migration_cli, "_open_directory_handle", capture_directory_descriptor
    )
    monkeypatch.setattr(migration_cli.os, "close", fail_final_close)

    status = migration_cli.main([str(directory), "--check"])
    captured = capsys.readouterr()

    assert status == 1
    assert "descriptor close failed" in captured.err
    assert "Traceback" not in captured.err
