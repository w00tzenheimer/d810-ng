"""Config-v2 adapter for D810 MBA instruction simplification."""

from __future__ import annotations

from dataclasses import dataclass

from d810.core.deobfuscation_case import StrategyWorkflowStage
from d810.core.pass_ids import PassId
from d810.passes.mba_transform_catalog import mba_transform_editor_spec
from d810.core.typing import Mapping, Protocol
from d810.ir.maturity import IRMaturity
from d810.passes.pass_pipeline import (
    FunctionPipelineContext,
    PipelineConfig,
    PipelinePass,
    PassResult,
)
from d810.passes.registry import PassRegistry
from d810.passes.mba_transform_options import (
    MbaSimplifyOptions,
    mba_transform_stages,
    parse_mba_simplify_options,
)

#: Back-reference to the shared vocabulary; see :mod:`d810.core.pass_ids`.
MBA_SIMPLIFY_PASS_ID = PassId.MBA_SIMPLIFY


@dataclass(frozen=True)
class MbaSimplifyRequest:
    """Selected instruction-rule work requested by the config-v2 adapter."""

    live_source: object
    func_ea: int
    maturity: IRMaturity
    rule_names: tuple[str, ...]
    rule_options: Mapping[str, Mapping[str, object]]


class MbaSimplifyCapability(Protocol):
    """Backend-provided executor for selected MBA instruction rules."""

    def run_mba_simplify(self, request: MbaSimplifyRequest) -> PassResult: ...


@dataclass(frozen=True)
class MbaSimplifyPass(PipelinePass):
    """Run selected MBA transforms through an explicit backend capability."""

    transform_ids: tuple[str, ...]
    implementation_names: tuple[str, ...]
    transform_options: Mapping[str, Mapping[str, object]]
    name: str = MBA_SIMPLIFY_PASS_ID

    def __post_init__(self) -> None:
        if len(self.transform_ids) != len(self.implementation_names):
            raise ValueError("transform and implementation counts must match")

    def run(self, context: FunctionPipelineContext) -> PassResult:
        if not self.transform_ids:
            return PassResult()
        capability = context.capabilities.require(MbaSimplifyCapability)
        implementation_options = {
            implementation_name: self.transform_options[transform_id]
            for transform_id, implementation_name in zip(
                self.transform_ids,
                self.implementation_names,
                strict=True,
            )
            if transform_id in self.transform_options
        }
        return capability.run_mba_simplify(
            MbaSimplifyRequest(
                live_source=context.source.live_source,
                func_ea=int(context.source.func_ea),
                maturity=context.maturity,
                rule_names=self.implementation_names,
                rule_options=implementation_options,
            )
        )


def build_mba_simplify_pass(
    config: PipelineConfig,
    registry: PassRegistry | None = None,
) -> MbaSimplifyPass:
    """Build ``mba-simplify`` from stable pass-owned transform IDs."""
    active_registry = registry or mba_simplify_pass_registry()
    options: MbaSimplifyOptions = parse_mba_simplify_options(
        config,
        active_registry,
    )
    implementation_by_id = {
        stage.stage_id: stage.implementation_name
        for stage in active_registry.stages_for(MBA_SIMPLIFY_PASS_ID)
    }
    return MbaSimplifyPass(
        transform_ids=options.transform_ids,
        implementation_names=tuple(
            implementation_by_id[transform_id]
            for transform_id in options.transform_ids
        ),
        transform_options=options.transform_options,
    )


def register_mba_simplify_pass(registry: PassRegistry) -> PassRegistry:
    """Register the config-aware ``mba-simplify`` pass factory."""
    stages = mba_transform_stages()
    registry.register_configured(
        MBA_SIMPLIFY_PASS_ID,
        lambda config: build_mba_simplify_pass(config, registry),
        config_template=PipelineConfig(
            pass_id=MBA_SIMPLIFY_PASS_ID,
            workflow_stage=StrategyWorkflowStage.FRONTEND_NORMALIZATION,
            options={"transforms": [], "transform_options": {}},
        ),
        stages=stages,
        transform_ids=tuple(stage.stage_id for stage in stages),
        editor_spec=mba_transform_editor_spec(),
    )
    return registry


def mba_simplify_pass_registry() -> PassRegistry:
    """Return a registry containing only executable MBA simplification adapters."""
    return register_mba_simplify_pass(PassRegistry())


__all__ = [
    "MBA_SIMPLIFY_PASS_ID",
    "MbaSimplifyCapability",
    "MbaSimplifyPass",
    "MbaSimplifyRequest",
    "build_mba_simplify_pass",
    "mba_simplify_pass_registry",
    "register_mba_simplify_pass",
]
