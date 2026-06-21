"""Unit tests for the explicit config-v2 CI runtime rehearsal switch."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from d810.core.config import ProjectConfiguration
from d810.testing.config_v2_rehearsal import (
    CONFIG_V2_CI_REHEARSAL_ENV,
    CONFIG_V2_CI_REHEARSAL_MAPPINGS,
    ConfigV2RehearsalError,
    config_v2_ci_rehearsal_enabled,
    config_v2_ci_rehearsal_selection,
    format_config_v2_ci_rehearsal_status,
    validate_config_v2_ci_rehearsal_state,
)


def test_config_v2_ci_rehearsal_defaults_off():
    assert config_v2_ci_rehearsal_enabled({}) is False
    assert config_v2_ci_rehearsal_selection("default_instruction_only.json", {}) is None


@pytest.mark.parametrize("value", ["0", "false", "no", "off", ""])
def test_config_v2_ci_rehearsal_accepts_disabled_values(value):
    environ = {CONFIG_V2_CI_REHEARSAL_ENV: value}

    assert config_v2_ci_rehearsal_enabled(environ) is False
    assert config_v2_ci_rehearsal_selection("default_instruction_only.json", environ) is None


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", "config-v2"])
def test_config_v2_ci_rehearsal_accepts_enabled_values(value):
    environ = {CONFIG_V2_CI_REHEARSAL_ENV: value}

    assert config_v2_ci_rehearsal_enabled(environ) is True


def test_config_v2_ci_rehearsal_rejects_unknown_switch_value():
    with pytest.raises(ConfigV2RehearsalError, match=CONFIG_V2_CI_REHEARSAL_ENV):
        config_v2_ci_rehearsal_enabled({CONFIG_V2_CI_REHEARSAL_ENV: "maybe"})


def test_config_v2_ci_rehearsal_maps_supported_source_to_canary():
    selection = config_v2_ci_rehearsal_selection(
        "default_instruction_only.json",
        {CONFIG_V2_CI_REHEARSAL_ENV: "1"},
    )

    assert selection is not None
    assert selection.runtime_config == "default_instruction_only_config_v2_canary.json"
    assert selection.expected_pass_ids == (
        "mba-simplify",
        "global-constant-inliner",
        "jump-fixer",
    )


def test_config_v2_ci_rehearsal_accepts_supported_canary_name():
    mapping = CONFIG_V2_CI_REHEARSAL_MAPPINGS[0]

    selection = config_v2_ci_rehearsal_selection(
        mapping.runtime_config,
        {CONFIG_V2_CI_REHEARSAL_ENV: "1"},
    )

    assert selection == mapping


def test_config_v2_ci_rehearsal_fails_closed_for_unsupported_project():
    with pytest.raises(ConfigV2RehearsalError, match="supports only"):
        config_v2_ci_rehearsal_selection(
            "default_unflattening_ollvm.json",
            {CONFIG_V2_CI_REHEARSAL_ENV: "1"},
        )


def _state_for_selection(*, mapping, mode="config-v2", pass_ids=None):
    project = ProjectConfiguration(
        path=Path(mapping.runtime_config),
        description="test",
        ins_rules=[],
        blk_rules=[],
        additional_configuration={"pipeline_v2_mode": mode},
    )
    return SimpleNamespace(
        current_project=project,
        last_pipeline_v2_hook_mode="config-v2",
        last_pipeline_v2_hook_pass_ids=(
            mapping.expected_pass_ids if pass_ids is None else pass_ids
        ),
    )


def test_validate_config_v2_ci_rehearsal_state_accepts_expected_runtime_source():
    mapping = CONFIG_V2_CI_REHEARSAL_MAPPINGS[0]
    state = _state_for_selection(mapping=mapping)

    validate_config_v2_ci_rehearsal_state(state=state, selection=mapping)


def test_validate_config_v2_ci_rehearsal_state_rejects_non_config_v2_mode():
    mapping = CONFIG_V2_CI_REHEARSAL_MAPPINGS[0]
    state = _state_for_selection(mapping=mapping, mode="legacy")

    with pytest.raises(ConfigV2RehearsalError, match="pipeline_v2_mode"):
        validate_config_v2_ci_rehearsal_state(state=state, selection=mapping)


def test_validate_config_v2_ci_rehearsal_state_rejects_pass_id_drift():
    mapping = CONFIG_V2_CI_REHEARSAL_MAPPINGS[0]
    state = _state_for_selection(mapping=mapping, pass_ids=("mba-simplify",))

    with pytest.raises(ConfigV2RehearsalError, match="pass ids drifted"):
        validate_config_v2_ci_rehearsal_state(state=state, selection=mapping)


def test_format_config_v2_ci_rehearsal_status_contains_auditable_runtime_source():
    mapping = CONFIG_V2_CI_REHEARSAL_MAPPINGS[0]

    status = format_config_v2_ci_rehearsal_status(selection=mapping)

    assert "CONFIG_V2_CI_REHEARSAL" in status
    assert f"source_project={mapping.source_config!r}" in status
    assert f"runtime_project={mapping.runtime_config!r}" in status
    assert "pipeline_v2_mode='config-v2'" in status
    assert f"expected_pass_ids={mapping.expected_pass_ids!r}" in status
