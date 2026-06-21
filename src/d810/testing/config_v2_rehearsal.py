"""Explicit config-v2 runtime-source rehearsal switch for system tests."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from d810.core.typing import Mapping

CONFIG_V2_CI_REHEARSAL_ENV = "D810_CONFIG_V2_CI_REHEARSAL"
CONFIG_V2_CI_REHEARSAL_ENABLED_VALUES = frozenset(
    ("1", "true", "yes", "on", "config-v2")
)
CONFIG_V2_CI_REHEARSAL_DISABLED_VALUES = frozenset(("", "0", "false", "no", "off"))


class ConfigV2RehearsalError(RuntimeError):
    """Raised when the explicit config-v2 CI rehearsal switch cannot run safely."""


@dataclass(frozen=True)
class ConfigV2RehearsalSelection:
    source_config: str
    runtime_config: str
    parity_row: str
    expected_pass_ids: tuple[str, ...]


CONFIG_V2_CI_REHEARSAL_MAPPINGS: tuple[ConfigV2RehearsalSelection, ...] = (
    ConfigV2RehearsalSelection(
        source_config="default_instruction_only.json",
        runtime_config="default_instruction_only_config_v2_canary.json",
        parity_row="default_instruction_only_config_v2_canary_mba",
        expected_pass_ids=(
            "mba-simplify",
            "global-constant-inliner",
            "jump-fixer",
        ),
    ),
    ConfigV2RehearsalSelection(
        source_config="default_unflattening_tigress_engine.json",
        runtime_config="default_unflattening_tigress_engine_config_v2_canary.json",
        parity_row="tigress_engine_config_v2_canary_spine",
        expected_pass_ids=(
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
        ),
    ),
    ConfigV2RehearsalSelection(
        source_config="hodur_flag2.json",
        runtime_config="hodur_flag2_config_v2_canary.json",
        parity_row="hodur_flag2_config_v2_canary_mixed",
        expected_pass_ids=(
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
            "jump-fixer",
        ),
    ),
)

_MAPPINGS_BY_SOURCE = {
    mapping.source_config: mapping for mapping in CONFIG_V2_CI_REHEARSAL_MAPPINGS
}
_MAPPINGS_BY_RUNTIME = {
    mapping.runtime_config: mapping for mapping in CONFIG_V2_CI_REHEARSAL_MAPPINGS
}


def config_v2_ci_rehearsal_enabled(
    environ: Mapping[str, str] | None = None,
) -> bool:
    env = environ if environ is not None else __import__("os").environ
    raw = str(env.get(CONFIG_V2_CI_REHEARSAL_ENV, "")).strip().lower()
    if raw in CONFIG_V2_CI_REHEARSAL_ENABLED_VALUES:
        return True
    if raw in CONFIG_V2_CI_REHEARSAL_DISABLED_VALUES:
        return False
    raise ConfigV2RehearsalError(
        f"{CONFIG_V2_CI_REHEARSAL_ENV} must be one of "
        f"{sorted(CONFIG_V2_CI_REHEARSAL_ENABLED_VALUES | CONFIG_V2_CI_REHEARSAL_DISABLED_VALUES)!r}; "
        f"got {raw!r}"
    )


def config_v2_ci_rehearsal_selection(
    project_name: str,
    environ: Mapping[str, str] | None = None,
) -> ConfigV2RehearsalSelection | None:
    if not config_v2_ci_rehearsal_enabled(environ):
        return None
    if project_name in _MAPPINGS_BY_SOURCE:
        return _MAPPINGS_BY_SOURCE[project_name]
    if project_name in _MAPPINGS_BY_RUNTIME:
        return _MAPPINGS_BY_RUNTIME[project_name]
    supported = ", ".join(sorted(_MAPPINGS_BY_SOURCE))
    raise ConfigV2RehearsalError(
        f"{CONFIG_V2_CI_REHEARSAL_ENV} supports only config-v2 canary-backed "
        f"source projects ({supported}); got {project_name!r}"
    )


def validate_config_v2_ci_rehearsal_state(
    *,
    state,
    selection: ConfigV2RehearsalSelection,
) -> None:
    current_project = getattr(state, "current_project", None)
    current_project_name = (
        Path(getattr(current_project, "path", "")).name
        if current_project is not None
        else None
    )
    if current_project_name != selection.runtime_config:
        raise ConfigV2RehearsalError(
            "config-v2 CI rehearsal loaded the wrong project: "
            f"expected {selection.runtime_config!r}, got {current_project_name!r}"
        )

    additional_configuration = dict(
        getattr(current_project, "additional_configuration", {}) or {}
    )
    mode = additional_configuration.get("pipeline_v2_mode")
    if mode != "config-v2":
        raise ConfigV2RehearsalError(
            "config-v2 CI rehearsal requires pipeline_v2_mode='config-v2'; "
            f"got {mode!r}"
        )

    hook_mode = getattr(state, "last_pipeline_v2_hook_mode", None)
    if hook_mode != "config-v2":
        raise ConfigV2RehearsalError(
            "config-v2 CI rehearsal did not activate config-v2 hooks; "
            f"got hook mode {hook_mode!r}"
        )

    hook_pass_ids = tuple(getattr(state, "last_pipeline_v2_hook_pass_ids", ()))
    if hook_pass_ids != selection.expected_pass_ids:
        raise ConfigV2RehearsalError(
            "config-v2 CI rehearsal hook pass ids drifted: "
            f"expected {selection.expected_pass_ids!r}, got {hook_pass_ids!r}"
        )


def format_config_v2_ci_rehearsal_status(
    *,
    selection: ConfigV2RehearsalSelection,
) -> str:
    return (
        "CONFIG_V2_CI_REHEARSAL "
        f"source_project={selection.source_config!r} "
        f"runtime_project={selection.runtime_config!r} "
        "pipeline_v2_mode='config-v2' "
        f"expected_pass_ids={selection.expected_pass_ids!r}"
    )
