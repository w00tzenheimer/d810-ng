"""Config-v2 adapter for strict 64-bit rotate idiom recovery.

This is intentionally a narrow structural lift, not an algebraic solver and
not an Egglog vocabulary extension.  It is enabled only by the Eidolon
constant-solve profile while we gather further idioms.
"""

from __future__ import annotations

from dataclasses import dataclass

from d810.core.deobfuscation_case import StrategyWorkflowStage
from d810.core.pass_ids import PassId
from d810.core.typing import Mapping
from d810.ir.maturity import IRMaturity
from d810.passes.execution_stages import ExecutionPipeline, ExecutionStageDescriptor
from d810.passes.pass_pipeline import (
    FunctionPipelineContext,
    PassResult,
    PipelineConfig,
    PipelineConfigError,
    PipelinePass,
)
from d810.passes.registry import PassRegistry


ROTATE_IDIOM_RECOVERY_PASS_ID = PassId.ROTATE_IDIOM_RECOVERY
ROTATE_IDIOM_RECOVERY_STAGE_ID = "rotate-idiom-recovery"
ROTATE_IDIOM_RECOVERY_IMPLEMENTATION = "RotateIdiomRecoveryBlockRule"
DEFAULT_MATURITIES = ("GLOBAL_OPTIMIZED",)


@dataclass(frozen=True)
class RotateIdiomRecoveryPass(PipelinePass):
    """Portable descriptor; the native instruction rule does the lifting."""

    maturities: tuple[str, ...] = DEFAULT_MATURITIES
    name: str = ROTATE_IDIOM_RECOVERY_PASS_ID

    def run(self, context: FunctionPipelineContext) -> PassResult:
        del context
        return PassResult()


def parse_rotate_idiom_recovery_options(config: PipelineConfig) -> tuple[str, ...]:
    if config.pass_id != ROTATE_IDIOM_RECOVERY_PASS_ID:
        raise PipelineConfigError(
            f"expected {ROTATE_IDIOM_RECOVERY_PASS_ID!r}, got {config.pass_id!r}"
        )
    options: Mapping[str, object] = config.options or {}
    unknown = set(options) - {"maturities"}
    if unknown:
        raise PipelineConfigError(
            "rotate-idiom-recovery has unknown options: " + repr(sorted(unknown))
        )
    raw = options.get("maturities", DEFAULT_MATURITIES)
    if isinstance(raw, str) or not isinstance(raw, (list, tuple)):
        raise PipelineConfigError(
            "rotate-idiom-recovery options.maturities must be a list of names"
        )
    maturities = tuple(raw)
    if maturities != DEFAULT_MATURITIES:
        raise PipelineConfigError(
            "rotate-idiom-recovery is restricted to GLOBAL_OPTIMIZED"
        )
    if any(value not in {member.name for member in IRMaturity} for value in maturities):
        raise PipelineConfigError(
            "rotate-idiom-recovery options.maturities must name supported IR maturities"
        )
    return maturities


def build_rotate_idiom_recovery_pass(
    config: PipelineConfig,
) -> RotateIdiomRecoveryPass:
    return RotateIdiomRecoveryPass(
        maturities=parse_rotate_idiom_recovery_options(config),
    )


def register_rotate_idiom_recovery_pass(registry: PassRegistry) -> PassRegistry:
    registry.register_configured(
        ROTATE_IDIOM_RECOVERY_PASS_ID,
        build_rotate_idiom_recovery_pass,
        config_template=PipelineConfig(
            pass_id=ROTATE_IDIOM_RECOVERY_PASS_ID,
            workflow_stage=StrategyWorkflowStage.FRONTEND_NORMALIZATION,
            options={"maturities": list(DEFAULT_MATURITIES)},
        ),
        stages=(
            ExecutionStageDescriptor(
                pass_id=ROTATE_IDIOM_RECOVERY_PASS_ID,
                stage_id=ROTATE_IDIOM_RECOVERY_STAGE_ID,
                pipeline=ExecutionPipeline.FLOW,
                implementation_name=ROTATE_IDIOM_RECOVERY_IMPLEMENTATION,
            ),
        ),
        public=False,
    )
    return registry


__all__ = [
    "ROTATE_IDIOM_RECOVERY_IMPLEMENTATION",
    "ROTATE_IDIOM_RECOVERY_PASS_ID",
    "ROTATE_IDIOM_RECOVERY_STAGE_ID",
    "RotateIdiomRecoveryPass",
    "build_rotate_idiom_recovery_pass",
    "parse_rotate_idiom_recovery_options",
    "register_rotate_idiom_recovery_pass",
]
