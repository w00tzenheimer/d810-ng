"""Supported config-v2 default routing policy.

This module is deliberately about selection policy only. The config-v2 hook
bridge still derives executable hook rules from an explicit runtime
``ProjectConfiguration``.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from d810.core.config import ProjectConfiguration
from d810.core.typing import Mapping

CONFIG_V2_SUPPORTED_DEFAULTS_ENV = "D810_CONFIG_V2_SUPPORTED_DEFAULTS"
CONFIG_V2_SUPPORTED_DEFAULTS_ENABLED_VALUES = frozenset(
    ("1", "true", "yes", "on", "config-v2")
)
CONFIG_V2_SUPPORTED_DEFAULTS_DISABLED_VALUES = frozenset(
    ("", "0", "false", "no", "off", "legacy", "existing")
)


class ConfigV2DefaultRoutingError(RuntimeError):
    """Raised when supported config-v2 default routing is configured unsafely."""


@dataclass(frozen=True)
class ConfigV2DefaultMapping:
    source_config: str
    runtime_config: str
    parity_row: str
    expected_pass_ids: tuple[str, ...]


@dataclass(frozen=True)
class ConfigV2DefaultSelection:
    source_project: ProjectConfiguration
    runtime_project: ProjectConfiguration
    mapping: ConfigV2DefaultMapping
    routed: bool

    @property
    def source_config(self) -> str:
        return self.source_project.path.name

    @property
    def runtime_config(self) -> str:
        return self.runtime_project.path.name

    @property
    def expected_pass_ids(self) -> tuple[str, ...]:
        return self.mapping.expected_pass_ids


CONFIG_V2_SUPPORTED_DEFAULT_MAPPINGS: tuple[ConfigV2DefaultMapping, ...] = (
    ConfigV2DefaultMapping(
        source_config="default_instruction_only.json",
        runtime_config="default_instruction_only_config_v2_canary.json",
        parity_row="default_instruction_only_config_v2_canary_mba",
        expected_pass_ids=(
            "mba-simplify",
            "global-constant-inliner",
            "jump-fixer",
        ),
    ),
    ConfigV2DefaultMapping(
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
    ConfigV2DefaultMapping(
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
    mapping.source_config: mapping for mapping in CONFIG_V2_SUPPORTED_DEFAULT_MAPPINGS
}
_MAPPINGS_BY_RUNTIME = {
    mapping.runtime_config: mapping for mapping in CONFIG_V2_SUPPORTED_DEFAULT_MAPPINGS
}


def bundled_config_dir() -> Path:
    """Return the built-in project configuration directory."""
    return Path(__file__).resolve().parent.parent / "conf"


def bundled_config_path(config_name: str) -> Path:
    return bundled_config_dir() / config_name


def is_bundled_project_config(project: ProjectConfiguration) -> bool:
    """Return true only for checked-in bundled project configs.

    User configs intentionally override bundled configs by basename elsewhere in
    the configuration loader. Default routing must therefore verify provenance
    by path, not by filename alone.
    """
    try:
        project_path = project.path.resolve()
        conf_dir = bundled_config_dir().resolve()
    except Exception:
        project_path = Path(project.path)
        conf_dir = bundled_config_dir()
    return project_path.parent == conf_dir and project_path.exists()


def config_v2_supported_defaults_enabled(
    environ: Mapping[str, str] | None = None,
) -> bool:
    env = environ if environ is not None else os.environ
    if CONFIG_V2_SUPPORTED_DEFAULTS_ENV not in env:
        return True
    raw = str(env.get(CONFIG_V2_SUPPORTED_DEFAULTS_ENV, "")).strip().lower()
    if raw in CONFIG_V2_SUPPORTED_DEFAULTS_ENABLED_VALUES:
        return True
    if raw in CONFIG_V2_SUPPORTED_DEFAULTS_DISABLED_VALUES:
        return False
    raise ConfigV2DefaultRoutingError(
        f"{CONFIG_V2_SUPPORTED_DEFAULTS_ENV} must be one of "
        f"{sorted(CONFIG_V2_SUPPORTED_DEFAULTS_ENABLED_VALUES | CONFIG_V2_SUPPORTED_DEFAULTS_DISABLED_VALUES)!r}; "
        f"got {raw!r}"
    )


def select_config_v2_default_project(
    source_project: ProjectConfiguration,
    *,
    environ: Mapping[str, str] | None = None,
) -> ConfigV2DefaultSelection | None:
    """Select a bundled config-v2 canary for supported bundled source configs."""
    if not config_v2_supported_defaults_enabled(environ):
        return None

    project_name = source_project.path.name
    mapping = _MAPPINGS_BY_SOURCE.get(project_name)
    if mapping is not None:
        if not is_bundled_project_config(source_project):
            return None
        runtime_project = ProjectConfiguration.from_file(
            bundled_config_path(mapping.runtime_config)
        )
        if not is_bundled_project_config(runtime_project):
            raise ConfigV2DefaultRoutingError(
                "supported config-v2 default routing requires bundled canary "
                f"{mapping.runtime_config!r}"
            )
        return ConfigV2DefaultSelection(
            source_project=source_project,
            runtime_project=runtime_project,
            mapping=mapping,
            routed=True,
        )

    mapping = _MAPPINGS_BY_RUNTIME.get(project_name)
    if mapping is None:
        return None
    if not is_bundled_project_config(source_project):
        return None
    return ConfigV2DefaultSelection(
        source_project=source_project,
        runtime_project=source_project,
        mapping=mapping,
        routed=False,
    )


def format_config_v2_default_selection_status(
    *,
    selection: ConfigV2DefaultSelection,
) -> str:
    return (
        "CONFIG_V2_SUPPORTED_DEFAULT "
        f"source_project={selection.source_config!r} "
        f"runtime_project={selection.runtime_config!r} "
        f"routed={selection.routed!r} "
        "pipeline_v2_mode='config-v2' "
        f"expected_pass_ids={selection.expected_pass_ids!r}"
    )
