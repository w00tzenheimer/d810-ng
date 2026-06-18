"""Shadow comparison helpers for optional PipelineConfig v2 cutover."""
from __future__ import annotations

from dataclasses import dataclass

from d810.passes.pass_pipeline import PipelineConfig, PassSpec
from d810.passes.pipeline_config_parser import (
    pipeline_configs_from_project_config,
    pass_specs_from_project_config,
)
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


@dataclass(frozen=True)
class PipelineSpecComparison:
    """Ordered comparison between two PassSpec sequences."""

    left_pass_ids: tuple[str, ...]
    right_pass_ids: tuple[str, ...]
    missing_pass_ids: tuple[str, ...]
    extra_pass_ids: tuple[str, ...]
    pass_ids_match: bool
    configs_match: bool

    @property
    def matches(self) -> bool:
        """Return whether both pass order and full PipelineConfig values match."""
        return self.pass_ids_match and self.configs_match


def compare_pipeline_specs(
    left: tuple[PassSpec, ...],
    right: tuple[PassSpec, ...],
) -> PipelineSpecComparison:
    """Compare two pass pipelines without executing either one."""
    left_ids = tuple(spec.pass_id for spec in left)
    right_ids = tuple(spec.pass_id for spec in right)
    right_set = set(right_ids)
    left_set = set(left_ids)
    return PipelineSpecComparison(
        left_pass_ids=left_ids,
        right_pass_ids=right_ids,
        missing_pass_ids=tuple(pass_id for pass_id in right_ids if pass_id not in left_set),
        extra_pass_ids=tuple(pass_id for pass_id in left_ids if pass_id not in right_set),
        pass_ids_match=left_ids == right_ids,
        configs_match=tuple(spec.config for spec in left)
        == tuple(spec.config for spec in right),
    )


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

    configured_specs = pass_specs_from_project_config(project_config, registry)
    spec_comparison = compare_pipeline_specs(configured_specs, live_specs)
    return PipelineShadowComparison(
        configured_configs=configured_configs,
        configured_pass_ids=tuple(spec.pass_id for spec in configured_specs),
        live_pass_ids=tuple(spec.pass_id for spec in live_specs),
        matches=spec_comparison.matches,
    )
