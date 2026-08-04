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
    return tuple(PipelineConfig.from_dict(item) for item in payload)


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
