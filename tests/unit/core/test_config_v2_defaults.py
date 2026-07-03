"""Tests for supported config-v2 default routing policy."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration
from d810.core.config_v2_defaults import (
    CONFIG_V2_SUPPORTED_DEFAULT_MAPPINGS,
    bundled_config_path,
    format_config_v2_default_selection_status,
    is_bundled_project_config,
    select_config_v2_default_project,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CONF_DIR = _REPO_ROOT / "src" / "d810" / "conf"


def _project(name: str) -> ProjectConfiguration:
    return ProjectConfiguration.from_file(_CONF_DIR / name)


def _write_user_project(tmp_path: Path, name: str) -> ProjectConfiguration:
    path = tmp_path / "cfg" / "d810" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "description": "user override",
                "ins_rules": [],
                "blk_rules": [],
                "additional_configuration": {},
            }
        ),
        encoding="utf-8",
    )
    return ProjectConfiguration.from_file(path)


@pytest.mark.parametrize("mapping", CONFIG_V2_SUPPORTED_DEFAULT_MAPPINGS)
def test_bundled_supported_source_routes_to_bundled_canary(mapping):
    source = _project(mapping.source_config)

    selection = select_config_v2_default_project(source)

    assert selection is not None
    assert selection.routed is True
    assert selection.mapping == mapping
    assert selection.source_project.path == source.path
    assert selection.runtime_project.path == bundled_config_path(mapping.runtime_config)
    assert is_bundled_project_config(selection.source_project)
    assert is_bundled_project_config(selection.runtime_project)


@pytest.mark.parametrize("mapping", CONFIG_V2_SUPPORTED_DEFAULT_MAPPINGS)
def test_user_source_override_with_supported_basename_does_not_route(tmp_path, mapping):
    source = _write_user_project(tmp_path, mapping.source_config)

    assert select_config_v2_default_project(source) is None


@pytest.mark.parametrize("mapping", CONFIG_V2_SUPPORTED_DEFAULT_MAPPINGS)
def test_bundled_canary_direct_selection_is_self_consistent(mapping):
    canary = _project(mapping.runtime_config)

    selection = select_config_v2_default_project(canary)

    assert selection is not None
    assert selection.routed is False
    assert selection.source_project.path == canary.path
    assert selection.runtime_project.path == canary.path
    assert selection.mapping == mapping


@pytest.mark.parametrize("mapping", CONFIG_V2_SUPPORTED_DEFAULT_MAPPINGS)
def test_user_canary_basename_gets_no_default_trust(tmp_path, mapping):
    canary = _write_user_project(tmp_path, mapping.runtime_config)

    assert select_config_v2_default_project(canary) is None


def test_supported_default_status_is_auditable():
    source = _project("default_instruction_only.json")
    selection = select_config_v2_default_project(source)
    assert selection is not None

    status = format_config_v2_default_selection_status(selection=selection)

    assert "CONFIG_V2_SUPPORTED_DEFAULT" in status
    assert "source_project='default_instruction_only.json'" in status
    assert "runtime_project='default_instruction_only_config_v2_canary.json'" in status
    assert "routed=True" in status
    assert "pipeline_v2_mode='config-v2'" in status
    assert "expected_pass_ids=" in status
