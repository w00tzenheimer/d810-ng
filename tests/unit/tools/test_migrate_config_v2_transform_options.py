"""Contract tests for the deliberate config-v2 MBA options migration."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


_SCRIPT_PATH = (
    Path(__file__).resolve().parents[3]
    / "tools"
    / "migrate_config_v2_transform_options.py"
)


def _migration_module():
    spec = importlib.util.spec_from_file_location(
        "migrate_config_v2_transform_options",
        _SCRIPT_PATH,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _mba_document(transform_options: dict[str, object]) -> dict[str, object]:
    return {
        "additional_configuration": {
            "pipeline_v2": [
                {
                    "pass_id": "mba-simplify",
                    "options": {
                        "transforms": ["add-xor-1", "z-3-constant-optimization"],
                        "transform_options": transform_options,
                    },
                }
            ]
        }
    }


def test_migration_removes_only_legacy_inert_transform_options() -> None:
    migration = _migration_module()
    document = _mba_document(
        {
            "add-xor-1": {
                "dump_intermediate_microcode": False,
                "maturities": None,
            },
            "z-3-constant-optimization": {
                "min_nb_opcode": 4,
                "min_nb_constant": 3,
                "dump_intermediate_microcode": None,
            },
        }
    )

    assert migration.migrate_document(document) is True
    assert document["additional_configuration"]["pipeline_v2"][0]["options"] == {
        "transforms": ["add-xor-1", "z-3-constant-optimization"],
        "transform_options": {
            "z-3-constant-optimization": {
                "min_nb_opcode": 4,
                "min_nb_constant": 3,
            }
        },
    }


def test_migration_refuses_transform_settings_without_a_typed_editor_field() -> None:
    migration = _migration_module()
    document = _mba_document({"add-xor-1": {"limit": 3}})

    with pytest.raises(migration.MigrationError, match="add-xor-1.limit"):
        migration.migrate_document(document)
