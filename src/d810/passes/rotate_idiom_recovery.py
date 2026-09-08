"""Config-v2 adapter for strict 64-bit rotate idiom recovery.

This is intentionally a narrow structural lift, not an algebraic solver and
not an e-graph vocabulary extension.  It is enabled only by the Eid
constant-solve profile while we gather further idioms.
"""

from __future__ import annotations

from d810.core.config import RuleConfiguration
from d810.core.deobfuscation_case import StrategyWorkflowStage
from d810.core.pass_editor_spec import PassEditorSpec
from d810.core.pass_ids import PassId
from d810.core.typing import Mapping
from d810.ir.maturity import IRMaturity
from d810.passes.execution_stages import (
    ExecutionHost,
    ExecutionOwnership,
    ExecutionPipeline,
    ExecutionStageDescriptor,
    IRScope,
)
from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError
from d810.passes.registry import PassRegistry


ROTATE_IDIOM_RECOVERY_PASS_ID = PassId.ROTATE_IDIOM_RECOVERY
ROTATE_IDIOM_RECOVERY_STAGE_ID = "rotate-idiom-recovery"
ROTATE_IDIOM_RECOVERY_IMPLEMENTATION = "RotateIdiomRecoveryBlockRule"
DEFAULT_MATURITIES = ("GLOBAL_OPTIMIZED",)


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


def build_rotate_idiom_recovery_rule(config: PipelineConfig) -> RuleConfiguration:
    """Validate config-v2 options and produce the live block-rule payload."""
    return RuleConfiguration(
        name=ROTATE_IDIOM_RECOVERY_IMPLEMENTATION,
        is_activated=True,
        config={"maturities": list(parse_rotate_idiom_recovery_options(config))},
    )


def register_rotate_idiom_recovery_pass(registry: PassRegistry) -> PassRegistry:
    registry.register_configured_stage(
        ROTATE_IDIOM_RECOVERY_PASS_ID,
        build_rotate_idiom_recovery_rule,
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
                ownership=ExecutionOwnership.HEXRAYS_HOSTED,
                host=ExecutionHost.HEXRAYS_OPTBLOCK,
                scope=IRScope.BLOCK,
            ),
        ),
        editor_spec=PassEditorSpec.summary(),
        public=False,
    )
    return registry


__all__ = [
    "ROTATE_IDIOM_RECOVERY_IMPLEMENTATION",
    "ROTATE_IDIOM_RECOVERY_PASS_ID",
    "ROTATE_IDIOM_RECOVERY_STAGE_ID",
    "build_rotate_idiom_recovery_rule",
    "parse_rotate_idiom_recovery_options",
    "register_rotate_idiom_recovery_pass",
]
