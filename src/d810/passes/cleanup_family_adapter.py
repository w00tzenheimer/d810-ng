"""Config-v2 adapter boundary for the live cleanup-family rule."""

from __future__ import annotations

from dataclasses import dataclass

from d810.core.deobfuscation_case import StrategyWorkflowStage
from d810.core.pass_editor_spec import PassEditorSpec
from d810.core.pass_ids import PassId
from d810.core.typing import Mapping, Protocol
from d810.ir.maturity import IRMaturity
from d810.passes.pass_pipeline import (
    FunctionPipelineContext,
    PipelineConfig,
    PipelineConfigError,
    PipelinePass,
    PassResult,
)
from d810.passes.registry import PassRegistry
from d810.passes.execution_stages import ExecutionPipeline, ExecutionStageDescriptor

CLEANUP_FAMILY_ADAPTER_CAPABILITY = "cleanup_family_adapter"
#: Back-reference to the shared vocabulary; see :mod:`d810.core.pass_ids`.
SIMPLE_FLATTENING_CLEANUP_PASS_ID = PassId.SIMPLE_FLATTENING_CLEANUP
SIMPLE_FLATTENING_CLEANUP_RULE = "SimpleFlatteningCleanupUnflattener"


@dataclass(frozen=True)
class CleanupFamilyAdapterRequest:
    """Selected cleanup-family work requested by a config-v2 adapter."""

    live_source: object
    func_ea: int
    maturity: IRMaturity
    pass_id: str
    implementation_name: str
    transform_options: Mapping[str, object]


class CleanupFamilyAdapterCapability(Protocol):
    """Backend-provided executor for one configured cleanup-family rule."""

    def run_cleanup_family_rule(
        self, request: CleanupFamilyAdapterRequest
    ) -> PassResult: ...


@dataclass(frozen=True)
class CleanupFamilyAdapterPass(PipelinePass):
    """Route a config-v2 cleanup-family pass to an explicit backend capability."""

    implementation_name: str
    transform_options: Mapping[str, object]
    name: str = SIMPLE_FLATTENING_CLEANUP_PASS_ID

    def run(self, context: FunctionPipelineContext) -> PassResult:
        capability = context.capabilities.require(CleanupFamilyAdapterCapability)
        return capability.run_cleanup_family_rule(
            CleanupFamilyAdapterRequest(
                live_source=context.source.live_source,
                func_ea=int(context.source.func_ea),
                maturity=context.maturity,
                pass_id=self.name,
                implementation_name=self.implementation_name,
                transform_options=self.transform_options,
            )
        )


def build_cleanup_family_adapter_pass(
    config: PipelineConfig,
) -> CleanupFamilyAdapterPass:
    """Build the cleanup-family adapter from one config-v2 pass entry."""
    if config.pass_id != SIMPLE_FLATTENING_CLEANUP_PASS_ID:
        raise PipelineConfigError(
            f"unsupported cleanup-family pass id: {config.pass_id!r}"
        )
    forbidden = {"legacy_rule", "legacy_rule_options", "native_pipeline"}.intersection(
        config.options
    )
    if forbidden:
        raise PipelineConfigError(
            "former cleanup option(s) are unsupported: " + ", ".join(sorted(forbidden))
        )
    return CleanupFamilyAdapterPass(
        implementation_name=SIMPLE_FLATTENING_CLEANUP_RULE,
        transform_options=dict(config.options),
    )


def register_cleanup_family_adapter_passes(registry: PassRegistry) -> PassRegistry:
    """Register config-v2 cleanup-family adapter pass ids."""
    registry.register_configured(
        SIMPLE_FLATTENING_CLEANUP_PASS_ID,
        build_cleanup_family_adapter_pass,
        config_template=PipelineConfig(
            pass_id=SIMPLE_FLATTENING_CLEANUP_PASS_ID,
            workflow_stage=StrategyWorkflowStage.CANONICAL_TRANSFORM,
            options={},
        ),
        stages=(
            ExecutionStageDescriptor(
                SIMPLE_FLATTENING_CLEANUP_PASS_ID,
                SIMPLE_FLATTENING_CLEANUP_PASS_ID,
                ExecutionPipeline.FLOW,
                SIMPLE_FLATTENING_CLEANUP_RULE,
            ),
        ),
        editor_spec=PassEditorSpec.summary(),
    )
    return registry


def cleanup_family_adapter_pass_registry() -> PassRegistry:
    """Return a registry containing cleanup-family adapter pass ids."""
    return register_cleanup_family_adapter_passes(PassRegistry())


__all__ = [
    "CLEANUP_FAMILY_ADAPTER_CAPABILITY",
    "SIMPLE_FLATTENING_CLEANUP_PASS_ID",
    "SIMPLE_FLATTENING_CLEANUP_RULE",
    "CleanupFamilyAdapterCapability",
    "CleanupFamilyAdapterPass",
    "CleanupFamilyAdapterRequest",
    "build_cleanup_family_adapter_pass",
    "cleanup_family_adapter_pass_registry",
    "register_cleanup_family_adapter_passes",
]
