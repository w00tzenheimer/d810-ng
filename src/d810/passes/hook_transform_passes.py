"""Registered passes backed by one private Hex-Rays hook transform."""

from __future__ import annotations

from dataclasses import dataclass

from d810.core.deobfuscation_case import StrategyWorkflowStage
from d810.core.pass_editor_spec import (
    FieldControlKind,
    FieldEditorSpec,
    PassEditorSpec,
)
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

HOOK_TRANSFORM_CAPABILITY = "hook_transform_adapter"

_IMPLEMENTATION_BY_PASS_ID: Mapping[str, str] = {
    "forward-constant-propagation": "ForwardConstantPropagationRule",
    "identity-call-resolver": "IdentityCallResolver",
    "indirect-branch-resolver": "IndirectBranchResolver",
    "indirect-call-resolver": "IndirectCallResolver",
    "mba-state-preconditioner": "MbaStatePreconditioner",
    "jump-fixer": "JumpFixer",
    "single-trip-loop-peel": "SingleTripLoopPeel",
}

#: The jump-fixer pass id, named because its editor spec is built specially.
JUMP_FIXER_PASS_ID = "jump-fixer"

#: Rule names selectable in the jump-fixer pass.
#:
#: Declared as data rather than imported from
#: ``d810.optimizers.microcode.flow.jumps``: this layer must not import
#: optimizers (enforced by the "Layered architecture prevents upward imports"
#: import-linter contract), and ``_IMPLEMENTATION_BY_PASS_ID`` above already
#: names implementation classes the same way. Keep in sync when adding a rule --
#: an unlisted rule still works from JSON, it is only invisible in the UI.
JUMP_FIXER_RULE_NAMES: tuple[str, ...] = (
    "CompareConstantRule1",
    "CompareConstantRule2",
    "CompareConstantRule3",
    "CompareConstantRule4",
    "JaeRule1",
    "JbRule1",
    "JmpRuleFlagsOpaquePredicate",
    "JmpRuleReachingConst",
    "JmpRuleZ3Const",
    "JnzRule1",
    "JnzRule2",
    "JnzRule3",
    "JnzRule4",
    "JnzRule5",
    "JnzRule6",
    "JnzRule7",
    "JnzRule8",
    "JnzRuleModIdentity",
    "JnzRuleSmodSubIdentity",
    "JnzRuleUmodAddIdentity",
    "JnzRuleUmodSubIdentity",
)

#: Enabled by default: the historical set, which excludes the newer rules so
#: that adding one never changes behaviour for an existing project silently.
_JUMP_FIXER_DEFAULT_RULES: tuple[str, ...] = tuple(
    name for name in JUMP_FIXER_RULE_NAMES if name != "JmpRuleFlagsOpaquePredicate"
)

_WORKFLOW_STAGE_BY_PASS_ID: Mapping[str, StrategyWorkflowStage] = {
    "forward-constant-propagation": StrategyWorkflowStage.FRONTEND_NORMALIZATION,
    "identity-call-resolver": StrategyWorkflowStage.CANONICAL_ANALYSIS,
    "indirect-branch-resolver": StrategyWorkflowStage.CANONICAL_ANALYSIS,
    "indirect-call-resolver": StrategyWorkflowStage.CANONICAL_ANALYSIS,
    "jump-fixer": StrategyWorkflowStage.BACKEND_PUBLICATION,
    "mba-state-preconditioner": StrategyWorkflowStage.FRONTEND_NORMALIZATION,
    "single-trip-loop-peel": StrategyWorkflowStage.CANONICAL_TRANSFORM,
}


@dataclass(frozen=True)
class HookTransformRequest:
    """Selected private hook-transform work requested by a registered pass."""

    live_source: object
    func_ea: int
    maturity: IRMaturity
    pass_id: str
    implementation_name: str
    transform_options: Mapping[str, object]


class HookTransformCapability(Protocol):
    """Backend-provided executor for one registered hook transform."""

    def run_hook_transform(self, request: HookTransformRequest) -> PassResult: ...


@dataclass(frozen=True)
class HookTransformPass(PipelinePass):
    """Route a registered block pass to a backend-provided hook transform."""

    implementation_name: str
    transform_options: Mapping[str, object]
    name: str

    def run(self, context: FunctionPipelineContext) -> PassResult:
        capability = context.capabilities.require(HookTransformCapability)
        return capability.run_hook_transform(
            HookTransformRequest(
                live_source=context.source.live_source,
                func_ea=int(context.source.func_ea),
                maturity=context.maturity,
                pass_id=self.name,
                implementation_name=self.implementation_name,
                transform_options=self.transform_options,
            )
        )


def build_hook_transform_pass(config: PipelineConfig) -> HookTransformPass:
    """Build a one-transform hook pass from its stable pass registration."""
    forbidden = {"legacy_rule", "legacy_rule_options", "native_pipeline"}.intersection(
        config.options
    )
    if forbidden:
        raise PipelineConfigError(
            "former hook-transform option(s) are unsupported: "
            + ", ".join(sorted(forbidden))
        )
    try:
        implementation_name = _IMPLEMENTATION_BY_PASS_ID[config.pass_id]
    except KeyError as exc:
        raise PipelineConfigError(
            f"unsupported hook-transform pass id: {config.pass_id!r}"
        ) from exc
    return HookTransformPass(
        name=config.pass_id,
        implementation_name=implementation_name,
        transform_options=dict(config.options),
    )


def _editor_spec_for(pass_id: str) -> PassEditorSpec:
    """Only jump-fixer has anything to edit; the rest stay summary-only."""
    if pass_id != JUMP_FIXER_PASS_ID:
        return PassEditorSpec.summary()
    return PassEditorSpec.fields_editor(
        (
            FieldEditorSpec(
                field_id="enabled_rules",
                label="Enabled rules",
                path=("enabled_rules",),
                control=FieldControlKind.STRING_LIST,
                description=(
                    "Which jump rewrites run. Rules not listed here never fire, "
                    "whatever the microcode looks like."
                ),
                choices=JUMP_FIXER_RULE_NAMES,
            ),
        )
    )


def register_hook_transform_passes(registry: PassRegistry) -> PassRegistry:
    """Register simple config-aware hook-transform pass IDs."""
    for pass_id in sorted(_IMPLEMENTATION_BY_PASS_ID):
        implementation_name = _IMPLEMENTATION_BY_PASS_ID[pass_id]
        registry.register_configured(
            pass_id,
            build_hook_transform_pass,
            config_template=PipelineConfig(
                pass_id=pass_id,
                workflow_stage=_WORKFLOW_STAGE_BY_PASS_ID[pass_id],
                options=(
                    {"enabled_rules": list(_JUMP_FIXER_DEFAULT_RULES)}
                    if pass_id == JUMP_FIXER_PASS_ID
                    else {}
                ),
            ),
            stages=(
                ExecutionStageDescriptor(
                    pass_id,
                    pass_id,
                    ExecutionPipeline.FLOW,
                    implementation_name,
                ),
            ),
            editor_spec=_editor_spec_for(pass_id),
            public=pass_id != "forward-constant-propagation",
        )
    return registry


def hook_transform_pass_registry() -> PassRegistry:
    """Return a registry containing the one-transform hook passes."""
    return register_hook_transform_passes(PassRegistry())


def hook_transform_implementations() -> Mapping[str, str]:
    """Return stable pass IDs mapped to private implementation names."""
    return dict(_IMPLEMENTATION_BY_PASS_ID)


__all__ = [
    "HOOK_TRANSFORM_CAPABILITY",
    "HookTransformCapability",
    "HookTransformPass",
    "HookTransformRequest",
    "build_hook_transform_pass",
    "hook_transform_implementations",
    "hook_transform_pass_registry",
    "register_hook_transform_passes",
]
