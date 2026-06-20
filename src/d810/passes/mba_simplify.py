"""Config-v2 adapter for D810 MBA instruction simplification."""
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

MBA_SIMPLIFY_PASS_ID = "mba-simplify"


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
    """Run selected legacy instruction rewrite rules through an explicit capability."""

    rule_names: tuple[str, ...]
    rule_options: Mapping[str, Mapping[str, object]]
    name: str = MBA_SIMPLIFY_PASS_ID

    def run(self, context: FunctionPipelineContext) -> PassResult:
        if not self.rule_names:
            return PassResult()
        capability = context.capabilities.require(MbaSimplifyCapability)
        return capability.run_mba_simplify(
            MbaSimplifyRequest(
                live_source=context.source.live_source,
                func_ea=int(context.source.func_ea),
                maturity=context.maturity,
                rule_names=self.rule_names,
                rule_options=self.rule_options,
            )
        )


def build_mba_simplify_pass(config: PipelineConfig) -> MbaSimplifyPass:
    """Build ``mba-simplify`` from its durable config-v2 rule selection."""
    if config.rules.include_groups or config.rules.exclude_groups:
        raise PipelineConfigError(
            "mba-simplify config-v2 execution requires explicit rules.include/exclude; "
            "rule groups are migration metadata only"
        )
    excluded = config.rules.exclude
    selected = tuple(
        rule_name for rule_name in config.rules.include_order if rule_name not in excluded
    )
    unknown_options = tuple(
        sorted(set(config.rules.options) - set(config.rules.include))
    )
    if unknown_options:
        raise PipelineConfigError(
            "mba-simplify rules.options entries must reference included rules: "
            f"{list(unknown_options)}"
        )
    selected_options = {
        rule_name: config.rules.options[rule_name]
        for rule_name in selected
        if rule_name in config.rules.options
    }
    return MbaSimplifyPass(
        rule_names=selected,
        rule_options=selected_options,
    )


def register_mba_simplify_pass(registry: PassRegistry) -> PassRegistry:
    """Register the config-aware ``mba-simplify`` pass factory."""
    registry.register_configured(MBA_SIMPLIFY_PASS_ID, build_mba_simplify_pass)
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
