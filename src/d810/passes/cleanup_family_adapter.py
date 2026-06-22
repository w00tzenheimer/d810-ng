"""Config-v2 adapter boundary for the live cleanup-family rule."""
from __future__ import annotations

from dataclasses import dataclass

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

CLEANUP_FAMILY_ADAPTER_CAPABILITY = "cleanup_family_adapter"
SIMPLE_FLATTENING_CLEANUP_PASS_ID = "simple-flattening-cleanup-unflattener"
SIMPLE_FLATTENING_CLEANUP_RULE = "SimpleFlatteningCleanupUnflattener"


@dataclass(frozen=True)
class CleanupFamilyAdapterRequest:
    """Selected cleanup-family work requested by a config-v2 adapter."""

    live_source: object
    func_ea: int
    maturity: IRMaturity
    pass_id: str
    legacy_rule: str
    rule_options: Mapping[str, object]


class CleanupFamilyAdapterCapability(Protocol):
    """Backend-provided executor for one configured cleanup-family rule."""

    def run_cleanup_family_rule(self, request: CleanupFamilyAdapterRequest) -> PassResult:
        ...


@dataclass(frozen=True)
class CleanupFamilyAdapterPass(PipelinePass):
    """Route a config-v2 cleanup-family pass to an explicit backend capability."""

    legacy_rule: str
    rule_options: Mapping[str, object]
    name: str = SIMPLE_FLATTENING_CLEANUP_PASS_ID

    def run(self, context: FunctionPipelineContext) -> PassResult:
        capability = context.capabilities.require(CleanupFamilyAdapterCapability)
        return capability.run_cleanup_family_rule(
            CleanupFamilyAdapterRequest(
                live_source=context.source.live_source,
                func_ea=int(context.source.func_ea),
                maturity=context.maturity,
                pass_id=self.name,
                legacy_rule=self.legacy_rule,
                rule_options=self.rule_options,
            )
        )


def _rules_are_empty(config: PipelineConfig) -> bool:
    rules = config.rules
    return not (
        rules.include_groups
        or rules.include
        or rules.include_order
        or rules.exclude_groups
        or rules.exclude
        or rules.exclude_order
        or rules.options
    )


def build_cleanup_family_adapter_pass(
    config: PipelineConfig,
) -> CleanupFamilyAdapterPass:
    """Build the cleanup-family adapter from one config-v2 pass entry."""
    if config.pass_id != SIMPLE_FLATTENING_CLEANUP_PASS_ID:
        raise PipelineConfigError(
            f"unsupported cleanup-family pass id: {config.pass_id!r}"
        )
    if not _rules_are_empty(config):
        raise PipelineConfigError(
            f"{config.pass_id} uses rules.*; rules.* is not executable"
        )
    legacy_rule = config.options.get("legacy_rule")
    if legacy_rule != SIMPLE_FLATTENING_CLEANUP_RULE:
        raise PipelineConfigError(
            f"{config.pass_id} must declare "
            f"options.legacy_rule={SIMPLE_FLATTENING_CLEANUP_RULE!r}"
        )
    rule_options = {
        key: value
        for key, value in config.options.items()
        if key != "legacy_rule"
    }
    return CleanupFamilyAdapterPass(
        legacy_rule=SIMPLE_FLATTENING_CLEANUP_RULE,
        rule_options=rule_options,
    )


def register_cleanup_family_adapter_passes(registry: PassRegistry) -> PassRegistry:
    """Register config-v2 cleanup-family adapter pass ids."""
    registry.register_configured(
        SIMPLE_FLATTENING_CLEANUP_PASS_ID,
        build_cleanup_family_adapter_pass,
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
