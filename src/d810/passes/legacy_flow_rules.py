"""Config-v2 adapters for simple legacy flow-rule pass ids."""
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

LEGACY_FLOW_RULE_ADAPTER_CAPABILITY = "legacy_flow_rule_adapter"

_SIMPLE_FLOW_RULE_PASS_IDS: Mapping[str, str] = {
    "global-constant-inliner": "GlobalConstantInliner",
    "forward-constant-propagation": "ForwardConstantPropagationRule",
    "mba-state-preconditioner": "MbaStatePreconditioner",
    "jump-fixer": "JumpFixer",
}


@dataclass(frozen=True)
class LegacyFlowRuleRequest:
    """Selected legacy flow-rule work requested by a config-v2 adapter."""

    live_source: object
    func_ea: int
    maturity: IRMaturity
    pass_id: str
    legacy_rule: str
    rule_options: Mapping[str, object]


class LegacyFlowRuleAdapterCapability(Protocol):
    """Backend-provided executor for one configured legacy flow rule."""

    def run_legacy_flow_rule(self, request: LegacyFlowRuleRequest) -> PassResult: ...


@dataclass(frozen=True)
class LegacyFlowRuleAdapterPass(PipelinePass):
    """Route a simple config-v2 block pass to a backend-provided legacy rule adapter."""

    legacy_rule: str
    rule_options: Mapping[str, object]
    name: str

    def run(self, context: FunctionPipelineContext) -> PassResult:
        capability = context.capabilities.require(LegacyFlowRuleAdapterCapability)
        return capability.run_legacy_flow_rule(
            LegacyFlowRuleRequest(
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


def build_legacy_flow_rule_pass(config: PipelineConfig) -> LegacyFlowRuleAdapterPass:
    """Build a simple legacy flow-rule adapter from a config-v2 pass entry."""
    try:
        expected_rule = _SIMPLE_FLOW_RULE_PASS_IDS[config.pass_id]
    except KeyError as exc:
        raise PipelineConfigError(
            f"unsupported legacy flow-rule pass id: {config.pass_id!r}"
        ) from exc
    if not _rules_are_empty(config):
        raise PipelineConfigError(
            f"{config.pass_id} uses pass-level options; rules.* is not executable"
        )
    legacy_rule = config.options.get("legacy_rule")
    if legacy_rule != expected_rule:
        raise PipelineConfigError(
            f"{config.pass_id} must declare options.legacy_rule={expected_rule!r}"
        )
    rule_options = {
        key: value
        for key, value in config.options.items()
        if key != "legacy_rule"
    }
    return LegacyFlowRuleAdapterPass(
        name=config.pass_id,
        legacy_rule=expected_rule,
        rule_options=rule_options,
    )


def register_legacy_flow_rule_passes(registry: PassRegistry) -> PassRegistry:
    """Register the simple config-aware legacy flow-rule adapter pass ids."""
    for pass_id in sorted(_SIMPLE_FLOW_RULE_PASS_IDS):
        registry.register_configured(pass_id, build_legacy_flow_rule_pass)
    return registry


def legacy_flow_rule_pass_registry() -> PassRegistry:
    """Return a registry containing simple legacy flow-rule adapters."""
    return register_legacy_flow_rule_passes(PassRegistry())


def simple_legacy_flow_rule_pass_ids() -> Mapping[str, str]:
    """Return supported config-v2 pass ids mapped to legacy rule names."""
    return dict(_SIMPLE_FLOW_RULE_PASS_IDS)


__all__ = [
    "LEGACY_FLOW_RULE_ADAPTER_CAPABILITY",
    "LegacyFlowRuleAdapterCapability",
    "LegacyFlowRuleAdapterPass",
    "LegacyFlowRuleRequest",
    "build_legacy_flow_rule_pass",
    "legacy_flow_rule_pass_registry",
    "register_legacy_flow_rule_passes",
    "simple_legacy_flow_rule_pass_ids",
]
