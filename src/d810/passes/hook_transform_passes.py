"""Registered passes backed by one private Hex-Rays hook transform."""

from __future__ import annotations

from dataclasses import dataclass

from d810.core.deobfuscation_case import StrategyWorkflowStage
from d810.core.pass_editor_spec import (
    AdvisoryTone,
    FieldControlKind,
    FieldEditorSpec,
    PassEditorSpec,
    RuleEditorSpec,
    TransformCost,
    VerificationStatus,
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

_JUMP_RULE_REFERENCE = "D810 jump-fixer rule catalog."
_UNCLASSIFIED_VERIFICATION = (
    "No per-rule semantic-verification classification is recorded yet."
)


def _jump_rule(
    rule_id: str,
    label: str,
    description: str,
    *,
    family_id: str,
    family_label: str,
    subfamily_id: str,
    subfamily_label: str,
    default_selected: bool = True,
    experimental: bool = False,
    experimental_reason: str = "",
    advisory: AdvisoryTone = AdvisoryTone.NONE,
    advisory_reason: str = "",
    verification: VerificationStatus = VerificationStatus.UNAVAILABLE,
    verification_reason: str = _UNCLASSIFIED_VERIFICATION,
    cost: TransformCost = TransformCost.UNKNOWN,
    cost_detail: str = "",
) -> RuleEditorSpec:
    """Declare one jump-fixer rule without importing private optimizer modules."""
    return RuleEditorSpec(
        rule_id=rule_id,
        label=label,
        family_id=family_id,
        family_label=family_label,
        subfamily_id=subfamily_id,
        subfamily_label=subfamily_label,
        description=description,
        reference=_JUMP_RULE_REFERENCE,
        default_selected=default_selected,
        experimental=experimental,
        experimental_reason=experimental_reason,
        advisory=advisory,
        advisory_reason=advisory_reason,
        verification=verification,
        verification_reason=verification_reason,
        cost=cost,
        cost_detail=cost_detail,
    )


#: Every rule is public editor data. This layer intentionally names metadata
#: rather than importing ``d810.optimizers.microcode.flow.jumps``: passes may
#: not import optimizers. Adding a runtime rule therefore requires adding one
#: declarative entry here; the registration contract rejects JSON-only rules.
JUMP_FIXER_RULE_SPECS: tuple[RuleEditorSpec, ...] = (
    _jump_rule(
        "CompareConstantRule1", "Compare constant 1",
        "Rewrite a masked comparison with a known constant.",
        family_id="comparison-rewrites", family_label="Comparison rewrites",
        subfamily_id="masked-constants", subfamily_label="Masked constants",
    ),
    _jump_rule(
        "CompareConstantRule2", "Compare constant 2",
        "Rewrite a composed bitwise comparison with a known constant.",
        family_id="comparison-rewrites", family_label="Comparison rewrites",
        subfamily_id="masked-constants", subfamily_label="Masked constants",
    ),
    _jump_rule(
        "CompareConstantRule3", "Compare constant 3",
        "Rewrite an arithmetic-and-mask comparison with a known constant.",
        family_id="comparison-rewrites", family_label="Comparison rewrites",
        subfamily_id="masked-constants", subfamily_label="Masked constants",
    ),
    _jump_rule(
        "CompareConstantRule4", "Compare constant 4",
        "Rewrite a signed comparison hidden by a composed bitwise expression.",
        family_id="comparison-rewrites", family_label="Comparison rewrites",
        subfamily_id="masked-constants", subfamily_label="Masked constants",
    ),
    _jump_rule(
        "JaeRule1", "Unsigned above-or-equal identity",
        "Collapse an unsigned above-or-equal jump through its known identity.",
        family_id="comparison-rewrites", family_label="Comparison rewrites",
        subfamily_id="unsigned-identities", subfamily_label="Unsigned identities",
    ),
    _jump_rule(
        "JbRule1", "Unsigned below identity",
        "Collapse an unsigned below jump through its known identity.",
        family_id="comparison-rewrites", family_label="Comparison rewrites",
        subfamily_id="unsigned-identities", subfamily_label="Unsigned identities",
    ),
    _jump_rule(
        "JmpRuleFlagsOpaquePredicate", "Flags-register opaque predicate",
        "Resolve jz/jnz predicates that compare a full EFLAGS/RFLAGS read with zero.",
        family_id="opaque-predicates", family_label="Opaque predicates",
        subfamily_id="flags-register", subfamily_label="Flags register",
        default_selected=False,
        experimental=True,
        experimental_reason=(
            "New flags-register recognition. Review the matched helper and target "
            "before enabling it on an unfamiliar binary."
        ),
    ),
    _jump_rule(
        "JmpRuleReachingConst", "Reaching-constant branch",
        "Fold a conditional branch when its operands are constant on the incoming path.",
        family_id="constant-recovery", family_label="Constant recovery",
        subfamily_id="path-constants", subfamily_label="Path constants",
    ),
    _jump_rule(
        "JmpRuleZ3Const", "SMT constant branch",
        "Use an SMT-backed proof to fold a conditional branch with constant operands.",
        family_id="constant-recovery", family_label="Constant recovery",
        subfamily_id="symbolic-proof", subfamily_label="Symbolic proof",
        advisory=AdvisoryTone.WARNING,
        advisory_reason=(
            "Symbolic proof can be materially slower than pattern rules on complex "
            "expressions."
        ),
        cost=TransformCost.PROOF_EXPENSIVE,
    ),
    *(
        _jump_rule(
            f"JnzRule{number}", f"Boolean opaque predicate {number}",
            "Collapse a recognized jz/jnz boolean opaque-predicate identity.",
            family_id="opaque-predicates", family_label="Opaque predicates",
            subfamily_id="boolean-identities", subfamily_label="Boolean identities",
        )
        for number in range(1, 9)
    ),
    _jump_rule(
        "JnzRuleModIdentity", "Modulo parity opaque predicate",
        "Recognize x * (x + 1) modulo 2 as an always-even predicate.",
        family_id="opaque-predicates", family_label="Opaque predicates",
        subfamily_id="modulo-parity", subfamily_label="Modulo parity",
    ),
    _jump_rule(
        "JnzRuleSmodSubIdentity", "Signed modulo subtraction predicate",
        "Recognize x * (x - 1) signed modulo 2 as an always-even predicate.",
        family_id="opaque-predicates", family_label="Opaque predicates",
        subfamily_id="modulo-parity", subfamily_label="Modulo parity",
    ),
    _jump_rule(
        "JnzRuleUmodAddIdentity", "Unsigned modulo addition predicate",
        "Recognize x * (x + 1) unsigned modulo 2 as an always-even predicate.",
        family_id="opaque-predicates", family_label="Opaque predicates",
        subfamily_id="modulo-parity", subfamily_label="Modulo parity",
    ),
    _jump_rule(
        "JnzRuleUmodSubIdentity", "Unsigned modulo subtraction predicate",
        "Recognize x * (x - 1) unsigned modulo 2 as an always-even predicate.",
        family_id="opaque-predicates", family_label="Opaque predicates",
        subfamily_id="modulo-parity", subfamily_label="Modulo parity",
    ),
)

JUMP_FIXER_RULE_NAMES: tuple[str, ...] = tuple(
    item.rule_id for item in JUMP_FIXER_RULE_SPECS
)


_JUMP_FIXER_DEFAULT_RULES: tuple[str, ...] = tuple(
    item.rule_id for item in JUMP_FIXER_RULE_SPECS if item.default_selected
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


_EDITOR_FIELDS_BY_PASS_ID: Mapping[str, tuple[FieldEditorSpec, ...]] = {
    "identity-call-resolver": (
        FieldEditorSpec(
            field_id="enable_experimental",
            label="Enable experimental resolver",
            path=("enable_experimental",),
            control=FieldControlKind.BOOLEAN,
            description="Enable the identity-call resolver scaffold.",
            default=False,
            experimental=True,
            experimental_reason=(
                "The resolver is an opt-in scaffold and remains disabled by default."
            ),
        ),
        FieldEditorSpec(
            field_id="max_trampoline_depth",
            label="Maximum trampoline depth",
            path=("max_trampoline_depth",),
            control=FieldControlKind.INTEGER,
            description="Maximum depth while following a trampoline chain.",
            default=32,
            minimum=1,
            maximum=256,
        ),
        FieldEditorSpec(
            field_id="max_search_instructions",
            label="Maximum search instructions",
            path=("max_search_instructions",),
            control=FieldControlKind.INTEGER,
            description="Maximum instructions scanned when pairing a call and icall.",
            default=30,
            minimum=1,
            maximum=1024,
        ),
    ),
    "indirect-branch-resolver": (
        FieldEditorSpec(
            field_id="table_entry_size",
            label="Jump-table entry size",
            path=("table_entry_size",),
            control=FieldControlKind.INTEGER,
            description="Size in bytes of one indirect jump-table entry.",
            default=8,
            minimum=1,
            maximum=32,
        ),
        FieldEditorSpec(
            field_id="candidate_max_depth",
            label="Candidate traversal depth",
            path=("candidate_max_depth",),
            control=FieldControlKind.INTEGER,
            description="Maximum predecessor depth while collecting jump candidates.",
            default=8,
            minimum=0,
            maximum=256,
        ),
    ),
    "indirect-call-resolver": (
        FieldEditorSpec(
            field_id="table_entry_size",
            label="Call-table entry size",
            path=("table_entry_size",),
            control=FieldControlKind.INTEGER,
            description="Size in bytes of one indirect call-table entry.",
            default=8,
            minimum=1,
            maximum=32,
        ),
    ),
    "mba-state-preconditioner": (
        FieldEditorSpec(
            field_id="max_optimize_local_rounds",
            label="Maximum local optimization rounds",
            path=("max_optimize_local_rounds",),
            control=FieldControlKind.INTEGER,
            description="Maximum local optimizer rounds for one function and maturity.",
            default=2,
            minimum=0,
            maximum=64,
        ),
        FieldEditorSpec(
            field_id="require_unflattening_gate",
            label="Require unflattening gate",
            path=("require_unflattening_gate",),
            control=FieldControlKind.BOOLEAN,
            description="Run only when the typed unflattening gate allows it.",
            default=True,
            advisory=AdvisoryTone.WARNING,
            advisory_reason=(
                "Disabling this runs the preconditioner outside the structural "
                "unflattening gate."
            ),
        ),
        FieldEditorSpec(
            field_id="verify_after_round",
            label="Verify after each round",
            path=("verify_after_round",),
            control=FieldControlKind.BOOLEAN,
            description="Run microcode verification after each local optimization round.",
            default=True,
            advisory=AdvisoryTone.WARNING,
            advisory_reason=(
                "Disabling verification reduces safeguards around each local mutation."
            ),
        ),
    ),
    JUMP_FIXER_PASS_ID: (
        FieldEditorSpec(
            field_id="dump_intermediate_microcode",
            label="Dump intermediate microcode",
            path=("dump_intermediate_microcode",),
            control=FieldControlKind.BOOLEAN,
            description="Write intermediate microcode snapshots for this pass.",
            default=False,
        ),
        FieldEditorSpec(
            field_id="preserve_z3_discarded_side_effects",
            label="Preserve discarded symbolic side effects",
            path=("preserve_z3_discarded_side_effects",),
            control=FieldControlKind.BOOLEAN,
            description=(
                "Keep side-effectful corridors discarded by the symbolic jump proof."
            ),
            default=False,
            advisory=AdvisoryTone.WARNING,
            advisory_reason=(
                "This safety mode can retain control-flow corridors that would "
                "otherwise be simplified."
            ),
        ),
        FieldEditorSpec(
            field_id="preserve_z3_discarded_side_effect_depth",
            label="Discarded-corridor depth",
            path=("preserve_z3_discarded_side_effect_depth",),
            control=FieldControlKind.INTEGER,
            description="Maximum depth inspected for discarded symbolic side effects.",
            default=3,
            minimum=0,
            maximum=64,
        ),
        FieldEditorSpec(
            field_id="preserve_z3_discarded_side_effect_constants",
            label="Required side-effect constants",
            path=("preserve_z3_discarded_side_effect_constants",),
            control=FieldControlKind.STRING_LIST,
            description="Constant markers required before preserving a discarded corridor.",
            default=[],
        ),
    ),
}


def _editor_spec_for(pass_id: str) -> PassEditorSpec:
    """Return the closed typed editor contract for one public hook pass."""
    fields = _EDITOR_FIELDS_BY_PASS_ID.get(pass_id, ())
    if pass_id == JUMP_FIXER_PASS_ID:
        return PassEditorSpec.rule_catalog(JUMP_FIXER_RULE_SPECS, fields=fields)
    if fields:
        return PassEditorSpec.fields_editor(fields)
    return PassEditorSpec.summary()


def register_hook_transform_passes(registry: PassRegistry) -> PassRegistry:
    """Register simple config-aware hook-transform pass IDs."""
    for pass_id in sorted(_IMPLEMENTATION_BY_PASS_ID):
        implementation_name = _IMPLEMENTATION_BY_PASS_ID[pass_id]
        editor_spec = _editor_spec_for(pass_id)
        registry.register_configured(
            pass_id,
            build_hook_transform_pass,
            config_template=PipelineConfig(
                pass_id=pass_id,
                workflow_stage=_WORKFLOW_STAGE_BY_PASS_ID[pass_id],
                options=editor_spec.default_options(),
            ),
            stages=(
                ExecutionStageDescriptor(
                    pass_id,
                    pass_id,
                    ExecutionPipeline.FLOW,
                    implementation_name,
                ),
            ),
            editor_spec=editor_spec,
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
    "JUMP_FIXER_PASS_ID",
    "JUMP_FIXER_RULE_NAMES",
    "JUMP_FIXER_RULE_SPECS",
    "HookTransformCapability",
    "HookTransformPass",
    "HookTransformRequest",
    "build_hook_transform_pass",
    "hook_transform_implementations",
    "hook_transform_pass_registry",
    "register_hook_transform_passes",
]
