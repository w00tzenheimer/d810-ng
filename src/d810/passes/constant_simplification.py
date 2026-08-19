"""One public constant-simplification bundle over private live hook stages."""

from __future__ import annotations

from dataclasses import dataclass

from d810.core.config import RuleConfiguration
from d810.core.deobfuscation_case import StrategyWorkflowStage
from d810.core.pass_ids import PassId
from d810.core.pass_editor_spec import (
    AdvisoryTone,
    FieldControlKind,
    FieldEditorSpec,
    PassEditorSpec,
)
from d810.ir.maturity import IRMaturity
from d810.passes.pass_pipeline import (
    FunctionPipelineContext,
    PipelineConfig,
    PipelinePass,
    PassResult,
)
from d810.passes.registry import PassRegistry
from d810.passes.execution_stages import (
    ExecutionPipeline,
    ExecutionStageDescriptor,
)
from d810.passes.constant_simplification_options import (
    AGGRESSIVE_MEMORY_POLICY as COMPILED_AGGRESSIVE_MEMORY_POLICY,
    CompiledConstantSimplificationSchedule,
    CompiledConstantStage,
    STRICT_MEMORY_POLICY as COMPILED_STRICT_MEMORY_POLICY,
    StageLifecycleDomain,
    _PROVIDER_BY_IR,
    compile_constant_simplification_schedule,
)

#: Back-reference to the shared vocabulary; see :mod:`d810.core.pass_ids`.
CONSTANT_SIMPLIFICATION_PASS_ID = PassId.CONSTANT_SIMPLIFICATION
STRICT_MEMORY_POLICY = COMPILED_STRICT_MEMORY_POLICY
AGGRESSIVE_MEMORY_POLICY = COMPILED_AGGRESSIVE_MEMORY_POLICY


@dataclass(frozen=True, slots=True)
class ConstantSimplificationOptions:
    """Validated public options for the logical constant pipeline."""

    memory_policy: str = STRICT_MEMORY_POLICY
    allow_executable_readonly: bool = False
    persist_global_const_annotations: bool = False
    #: How the pointer-like veto is answered. True keeps a veto but prefers a
    #: def-use "is this value dereferenced?" answer over the value-shape guess;
    #: False drops the veto entirely. Orthogonal to ``memory_policy``, which
    #: decides which memory may be folded at all.
    rva_guard: bool = True


@dataclass(frozen=True, slots=True)
class ConstantSimplificationHookRules:
    """Private rule activations owned by the public bundle."""

    instruction_rules: tuple[RuleConfiguration, ...]
    block_rules: tuple[RuleConfiguration, ...]


@dataclass(frozen=True, slots=True)
class ConstantSimplificationPass(PipelinePass):
    """Portable descriptor; the live hook bridge executes its private stages."""

    options: CompiledConstantSimplificationSchedule
    name: str = CONSTANT_SIMPLIFICATION_PASS_ID

    def run(self, context: FunctionPipelineContext) -> PassResult:
        return PassResult()


def _parse_options(config: PipelineConfig) -> CompiledConstantSimplificationSchedule:
    return compile_constant_simplification_schedule(
        config,
        constant_simplification_stage_descriptors(),
    )


def constant_simplification_stage_descriptors() -> tuple[ExecutionStageDescriptor, ...]:
    """Return the portable registration authority for the three live stages."""

    return _CONSTANT_STAGE_DESCRIPTORS


_CONSTANT_STAGE_DESCRIPTORS = (
    ExecutionStageDescriptor(
        CONSTANT_SIMPLIFICATION_PASS_ID,
        "fold-readonly-data",
        ExecutionPipeline.INSTRUCTION,
        "FoldReadonlyDataRule",
        lifecycle_domain=StageLifecycleDomain.MICROCODE,
        supported_maturities=(
            IRMaturity.CANONICAL,
            IRMaturity.LOCAL_OPTIMIZED,
            IRMaturity.CALL_MODELED,
            IRMaturity.GLOBAL_ANALYZED,
            IRMaturity.STRUCTURED,
        ),
    ),
    ExecutionStageDescriptor(
        CONSTANT_SIMPLIFICATION_PASS_ID,
        "fold-constant-subtree",
        ExecutionPipeline.INSTRUCTION,
        "ConstantSubtreeFoldRule",
        lifecycle_domain=StageLifecycleDomain.MICROCODE,
        supported_maturities=(
            IRMaturity.LOCAL_OPTIMIZED,
            IRMaturity.CALL_MODELED,
            IRMaturity.GLOBAL_ANALYZED,
            IRMaturity.GLOBAL_OPTIMIZED,
            IRMaturity.STRUCTURED,
        ),
    ),
    ExecutionStageDescriptor(
        CONSTANT_SIMPLIFICATION_PASS_ID,
        "forward-constants",
        ExecutionPipeline.FLOW,
        "ForwardConstantPropagationRule",
        lifecycle_domain=StageLifecycleDomain.MICROCODE,
        supported_maturities=(
            IRMaturity.CALL_MODELED,
            IRMaturity.GLOBAL_ANALYZED,
            IRMaturity.GLOBAL_OPTIMIZED,
            IRMaturity.STRUCTURED,
        ),
    ),
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


def constant_simplification_provider_maturities(
    maturities: tuple[IRMaturity, ...],
) -> tuple[str, ...]:
    """Map compiled portable maturities to the private Hex-Rays vocabulary.

    The compiled schedule remains the authority.  This is only the one-way
    spelling conversion required at the private rule boundary.
    """

    try:
        return tuple(_PROVIDER_BY_IR[maturity] for maturity in maturities)
    except KeyError as exc:
        raise ValueError(
            f"constant-simplification has no provider maturity for {exc.args[0]!r}"
        ) from exc


def _constant_stage_rule_config(
    stage: CompiledConstantStage,
    *,
    forward_constant_options: dict[str, object] | None,
) -> RuleConfiguration:
    config: dict[str, object] = {
        "maturities": list(
            constant_simplification_provider_maturities(stage.effective_maturities)
        )
    }
    if stage.stage_id == "fold-readonly-data":
        config.update(stage.options)
        if stage.options["memory_policy"] == AGGRESSIVE_MEMORY_POLICY:
            # This is the private spelling; the public schedule deliberately
            # retains its policy vocabulary.
            config["fold_writable_constants"] = True
    elif stage.stage_id == "forward-constants" and forward_constant_options:
        # The state-machine path may add execution-only options, but it may
        # not replace the compiled maturity set.
        config.update(
            {
                key: value
                for key, value in forward_constant_options.items()
                if key != "maturities"
            }
        )
    return _rule(stage.implementation_name or "", config)


def constant_simplification_hook_rules(
    config: PipelineConfig,
    *,
    forward_constant_options: dict[str, object] | None = None,
    schedule: CompiledConstantSimplificationSchedule | None = None,
) -> ConstantSimplificationHookRules:
    """Expand the logical pass into its ordered live Hex-Rays stages."""
    compiled = schedule if schedule is not None else _parse_options(config)
    instruction_rules: list[RuleConfiguration] = []
    block_rules: list[RuleConfiguration] = []
    for stage in compiled.stages:
        if not stage.enabled:
            continue
        rule = _constant_stage_rule_config(
            stage,
            forward_constant_options=forward_constant_options,
        )
        if stage.pipeline is ExecutionPipeline.INSTRUCTION:
            instruction_rules.append(rule)
        elif stage.pipeline is ExecutionPipeline.FLOW:
            block_rules.append(rule)
        else:
            raise ValueError(
                f"constant-simplification stage {stage.stage_id} has unsupported "
                f"pipeline {stage.pipeline!r}"
            )
    return ConstantSimplificationHookRules(
        instruction_rules=tuple(instruction_rules),
        block_rules=tuple(block_rules),
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
                "rva_guard": True,
                "allow_executable_readonly": False,
                "persist_global_const_annotations": False,
            },
        ),
        stages=constant_simplification_stage_descriptors(),
        editor_spec=PassEditorSpec.fields_editor(
            (
                FieldEditorSpec(
                    field_id="memory_policy",
                    label="Memory policy",
                    path=("memory_policy",),
                    control=FieldControlKind.ENUM,
                    description="Controls which read-only memory values may be materialized.",
                    choices=(STRICT_MEMORY_POLICY, AGGRESSIVE_MEMORY_POLICY),
                    default=STRICT_MEMORY_POLICY,
                ),
                FieldEditorSpec(
                    field_id="rva_guard",
                    label="RVA guard",
                    path=("rva_guard",),
                    control=FieldControlKind.BOOLEAN,
                    description=(
                        "Veto folds whose value is used as an address. On, the "
                        "veto is answered by microcode def-use where provable "
                        "and by the value-shape heuristic otherwise; off, there "
                        "is no veto."
                    ),
                    default=True,
                ),
                FieldEditorSpec(
                    field_id="persist_global_const_annotations",
                    label="Persist proven global constants in IDB",
                    path=("persist_global_const_annotations",),
                    control=FieldControlKind.BOOLEAN,
                    description=(
                        "Apply proven global const types through D810's reversible "
                        "IDB preparation journal. Restore them from the "
                        "Deobfuscation Workbench."
                    ),
                    default=False,
                ),
                FieldEditorSpec(
                    field_id="allow_executable_readonly",
                    label="Allow executable read-only memory",
                    path=("allow_executable_readonly",),
                    control=FieldControlKind.BOOLEAN,
                    description="Very dangerous override for executable read-only memory.",
                    default=False,
                    advisory=AdvisoryTone.DANGER,
                    advisory_reason=(
                        "Executable read-only data may be code or mixed code/data. "
                        "Enable only when you have independently established that the "
                        "selected memory is safe to materialize."
                    ),
                ),
            )
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
    "constant_simplification_provider_maturities",
    "constant_simplification_stage_descriptors",
    "register_constant_simplification_pass",
]
