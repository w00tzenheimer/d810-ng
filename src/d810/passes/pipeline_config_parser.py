"""Shadow parsing helpers for optional PipelineConfig v2 project config."""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum

from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError
from d810.passes.registry import PassRegistry


class PipelineV2Mode(str, Enum):
    """Explicit runtime mode for optional project ``pipeline_v2`` payloads."""

    LEGACY = "legacy"
    SHADOW_CHECK = "shadow-check"
    CONFIG_V2 = "config-v2"


def _project_additional_config(project_config) -> Mapping:
    if isinstance(project_config, Mapping):
        config = project_config
    else:
        config = getattr(project_config, "additional_configuration", None)
        if config is None:
            config = {}
    if not isinstance(config, Mapping):
        raise PipelineConfigError("project additional_configuration must be a mapping")
    return config


def pipeline_configs_from_project_config(project_config) -> tuple[PipelineConfig, ...]:
    """Return optional ``pipeline_v2`` configs without changing project loading.

    Accepts either a loaded ProjectConfiguration-like object with
    ``additional_configuration`` or a plain mapping. Missing ``pipeline_v2`` is a
    no-op; malformed payloads fail loudly for diagnostics/shadow comparison.
    """
    config = _project_additional_config(project_config)
    payload = config.get("pipeline_v2")
    if payload is None:
        return ()
    if isinstance(payload, Mapping) or not isinstance(payload, (list, tuple)):
        raise PipelineConfigError("pipeline_v2 must be a sequence of pass configs")
    if not payload:
        raise PipelineConfigError("pipeline_v2 must contain at least one pass config")
    source_path = getattr(project_config, "path", None)
    source_prefix = "" if source_path is None else f"{source_path}: "
    configs: list[PipelineConfig] = []
    for index, item in enumerate(payload):
        if isinstance(item, Mapping) and "pass" in item:
            raise PipelineConfigError(
                f"{source_prefix}pipeline_v2[{index}] uses the removed "
                "direct-contract schema; regenerate it with the config-v2 editor "
                "so the entry uses pass_id and typed pass options"
            )
        try:
            configs.append(PipelineConfig.from_dict(item))
        except PipelineConfigError as exc:
            raise PipelineConfigError(
                f"{source_prefix}pipeline_v2[{index}]: {exc}"
            ) from exc
    return tuple(configs)


def pipeline_v2_mode_from_project_config(project_config) -> PipelineV2Mode:
    """Return the explicit ``pipeline_v2`` execution mode."""
    config = _project_additional_config(project_config)
    if "require_pipeline_v2_shadow_match" in config:
        raise PipelineConfigError(
            "require_pipeline_v2_shadow_match is a former field; "
            "use pipeline_v2_mode='shadow-check'"
        )
    if "pipeline_v2_mode" not in config:
        return PipelineV2Mode.LEGACY

    value = config["pipeline_v2_mode"]
    if not isinstance(value, str):
        raise PipelineConfigError("pipeline_v2_mode must be a string")
    try:
        mode = PipelineV2Mode(value)
    except ValueError as exc:
        allowed = ", ".join(mode.value for mode in PipelineV2Mode)
        raise PipelineConfigError(
            f"pipeline_v2_mode must be one of: {allowed}"
        ) from exc
    return mode


def pass_specs_from_project_config(
    project_config,
    registry: PassRegistry,
):
    """Build shadow PassSpecs from optional project ``pipeline_v2`` config."""
    return tuple(
        registry.build_spec(config)
        for config in pipeline_configs_from_project_config(project_config)
    )
