"""Shadow parsing helpers for optional PipelineConfig v2 project config."""
from __future__ import annotations

from collections.abc import Mapping

from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError


def pipeline_configs_from_project_config(project_config) -> tuple[PipelineConfig, ...]:
    """Return optional ``pipeline_v2`` configs without changing project loading.

    Accepts either a loaded ProjectConfiguration-like object with
    ``additional_configuration`` or a plain mapping. Missing ``pipeline_v2`` is a
    no-op; malformed payloads fail loudly for diagnostics/shadow comparison.
    """
    if isinstance(project_config, Mapping):
        config = project_config
    else:
        config = getattr(project_config, "additional_configuration", {}) or {}
    if not isinstance(config, Mapping):
        raise PipelineConfigError("project additional_configuration must be a mapping")

    payload = config.get("pipeline_v2")
    if payload is None:
        return ()
    if isinstance(payload, Mapping) or not isinstance(payload, (list, tuple)):
        raise PipelineConfigError("pipeline_v2 must be a sequence of pass configs")
    return tuple(PipelineConfig.from_dict(item) for item in payload)
