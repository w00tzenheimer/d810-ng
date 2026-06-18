"""Shadow comparison helpers for optional PipelineConfig v2 cutover."""
from __future__ import annotations

from dataclasses import dataclass

from d810.passes.pass_pipeline import PipelineConfig, PassSpec
from d810.passes.pipeline_config_parser import pipeline_configs_from_project_config
from d810.passes.registry import PassRegistry


@dataclass(frozen=True)
class PipelineShadowComparison:
    """Result of comparing project ``pipeline_v2`` configs to the live family pipeline."""

    configured_configs: tuple[PipelineConfig, ...]
    configured_pass_ids: tuple[str, ...]
    live_pass_ids: tuple[str, ...]
    matches: bool

    @property
    def enabled(self) -> bool:
        """Return whether the project provided a ``pipeline_v2`` shadow payload."""
        return bool(self.configured_configs)


def compare_pipeline_v2_shadow(
    *,
    project_config,
    registry: PassRegistry,
    live_specs: tuple[PassSpec, ...],
) -> PipelineShadowComparison:
    """Build configured specs through ``registry`` and compare to live specs.

    This is diagnostic-only: existing family pipelines remain the runtime source of
    truth until project JSON explicitly cuts over to PipelineConfig v2.
    """
    configured_configs = pipeline_configs_from_project_config(project_config)
    if not configured_configs:
        return PipelineShadowComparison(
            configured_configs=(),
            configured_pass_ids=(),
            live_pass_ids=tuple(spec.pass_id for spec in live_specs),
            matches=True,
        )

    configured_specs = tuple(
        registry.build_spec(config) for config in configured_configs
    )
    return PipelineShadowComparison(
        configured_configs=configured_configs,
        configured_pass_ids=tuple(spec.pass_id for spec in configured_specs),
        live_pass_ids=tuple(spec.pass_id for spec in live_specs),
        matches=tuple(spec.config for spec in configured_specs)
        == tuple(spec.config for spec in live_specs),
    )
