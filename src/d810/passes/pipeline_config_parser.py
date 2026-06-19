"""Shadow parsing helpers for optional PipelineConfig v2 project config."""
from __future__ import annotations

from collections.abc import Mapping

from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError
from d810.passes.registry import PassRegistry


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


def pipeline_v2_shadow_match_required(project_config) -> bool:
    """Return whether live execution should fail on explicit ``pipeline_v2`` drift."""
    config = _project_additional_config(project_config)
    if "require_pipeline_v2_shadow_match" not in config:
        return False
    value = config["require_pipeline_v2_shadow_match"]
    if not isinstance(value, bool):
        raise PipelineConfigError(
            "require_pipeline_v2_shadow_match must be a boolean"
        )
    return value


def pass_specs_from_project_config(
    project_config,
    registry: PassRegistry,
):
    """Build shadow PassSpecs from optional project ``pipeline_v2`` config."""
    return tuple(
        registry.build_spec(config)
        for config in pipeline_configs_from_project_config(project_config)
    )
