"""One public constant-simplification bundle over private live hook stages."""

from __future__ import annotations

from dataclasses import dataclass

from d810.core.config import RuleConfiguration
from d810.core.deobfuscation_case import StrategyWorkflowStage
from d810.passes.pass_pipeline import (
    FunctionPipelineContext,
    PipelineConfig,
    PipelineConfigError,
    PipelinePass,
    PassResult,
)
from d810.passes.registry import PassRegistry

CONSTANT_SIMPLIFICATION_PASS_ID = "constant-simplification"
STRICT_MEMORY_POLICY = "strict"
AGGRESSIVE_MEMORY_POLICY = "aggressive_no_direct_writes"
_MEMORY_POLICIES = frozenset({STRICT_MEMORY_POLICY, AGGRESSIVE_MEMORY_POLICY})
_OPTION_NAMES = frozenset({"memory_policy", "allow_executable_readonly"})


@dataclass(frozen=True, slots=True)
class ConstantSimplificationOptions:
    """Validated public options for the logical constant pipeline."""

    memory_policy: str = STRICT_MEMORY_POLICY
    allow_executable_readonly: bool = False


@dataclass(frozen=True, slots=True)
class ConstantSimplificationHookRules:
    """Private rule activations owned by the public bundle."""

    instruction_rules: tuple[RuleConfiguration, ...]
    block_rules: tuple[RuleConfiguration, ...]


@dataclass(frozen=True, slots=True)
class ConstantSimplificationPass(PipelinePass):
    """Portable descriptor; the live hook bridge executes its private stages."""

    options: ConstantSimplificationOptions
    name: str = CONSTANT_SIMPLIFICATION_PASS_ID

    def run(self, context: FunctionPipelineContext) -> PassResult:
        return PassResult()


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


def _parse_options(config: PipelineConfig) -> ConstantSimplificationOptions:
    if config.pass_id != CONSTANT_SIMPLIFICATION_PASS_ID:
        raise PipelineConfigError(
            f"expected {CONSTANT_SIMPLIFICATION_PASS_ID!r}, got {config.pass_id!r}"
        )
    if not _rules_are_empty(config):
        raise PipelineConfigError(
            "constant-simplification owns its private rules; rules.* must be empty"
        )
    unknown = tuple(sorted(set(config.options) - _OPTION_NAMES))
    if unknown:
        raise PipelineConfigError(
            f"constant-simplification has unknown options: {list(unknown)}"
        )
    memory_policy = config.options.get("memory_policy", STRICT_MEMORY_POLICY)
    if not isinstance(memory_policy, str) or memory_policy not in _MEMORY_POLICIES:
        raise PipelineConfigError(
            "constant-simplification options.memory_policy must be one of: "
            f"{', '.join(sorted(_MEMORY_POLICIES))}"
        )
    dangerous = config.options.get("allow_executable_readonly", False)
    if not isinstance(dangerous, bool):
        raise PipelineConfigError(
            "constant-simplification options.allow_executable_readonly must be boolean"
        )
    return ConstantSimplificationOptions(
        memory_policy=memory_policy,
        allow_executable_readonly=dangerous,
    )


def build_constant_simplification_pass(
    config: PipelineConfig,
) -> ConstantSimplificationPass:
    """Validate and build the logical public pass descriptor."""
    return ConstantSimplificationPass(options=_parse_options(config))


def _rule(name: str, options: dict[str, object] | None = None) -> RuleConfiguration:
    return RuleConfiguration(
        name=name,
        is_activated=True,
        config={} if options is None else options,
    )


def constant_simplification_hook_rules(
    config: PipelineConfig,
) -> ConstantSimplificationHookRules:
    """Expand the logical pass into its ordered live Hex-Rays stages."""
    options = _parse_options(config)
    memory_options: dict[str, object] = {}
    if options.memory_policy == AGGRESSIVE_MEMORY_POLICY:
        memory_options["fold_writable_constants"] = True
    if options.allow_executable_readonly:
        memory_options["allow_executable_readonly"] = True
    return ConstantSimplificationHookRules(
        instruction_rules=(
            _rule("FoldReadonlyDataRule", memory_options),
            _rule("ConstantSubtreeFoldRule"),
        ),
        block_rules=(_rule("ForwardConstantPropagationRule"),),
    )


def register_constant_simplification_pass(registry: PassRegistry) -> PassRegistry:
    """Register the one public constant-simplification operation."""
    registry.register_configured(
        CONSTANT_SIMPLIFICATION_PASS_ID,
        build_constant_simplification_pass,
        config_template=PipelineConfig(
            pass_id=CONSTANT_SIMPLIFICATION_PASS_ID,
            workflow_stage=StrategyWorkflowStage.FRONTEND_NORMALIZATION,
            options={
                "memory_policy": STRICT_MEMORY_POLICY,
                "allow_executable_readonly": False,
            },
        ),
        transforms=(
            "FoldReadonlyDataRule",
            "ConstantSubtreeFoldRule",
            "ForwardConstantPropagationRule",
        ),
    )
    return registry


__all__ = [
    "AGGRESSIVE_MEMORY_POLICY",
    "CONSTANT_SIMPLIFICATION_PASS_ID",
    "ConstantSimplificationHookRules",
    "ConstantSimplificationOptions",
    "ConstantSimplificationPass",
    "STRICT_MEMORY_POLICY",
    "build_constant_simplification_pass",
    "constant_simplification_hook_rules",
    "register_constant_simplification_pass",
]
