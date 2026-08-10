"""One public constant-simplification bundle over private live hook stages."""

from __future__ import annotations

from dataclasses import dataclass

from d810.core.config import RuleConfiguration
from d810.core.deobfuscation_case import StrategyWorkflowStage
from d810.core.pass_ids import PassId
from d810.core.pass_editor_spec import (
    FieldControlKind,
    FieldEditorSpec,
    PassEditorSpec,
)
from d810.passes.pass_pipeline import (
    FunctionPipelineContext,
    PipelineConfig,
    PipelineConfigError,
    PipelinePass,
    PassResult,
)
from d810.passes.registry import PassRegistry
from d810.passes.execution_stages import ExecutionPipeline, ExecutionStageDescriptor

#: Back-reference to the shared vocabulary; see :mod:`d810.core.pass_ids`.
CONSTANT_SIMPLIFICATION_PASS_ID = PassId.CONSTANT_SIMPLIFICATION
STRICT_MEMORY_POLICY = "strict"
AGGRESSIVE_MEMORY_POLICY = "aggressive_no_direct_writes"
_MEMORY_POLICIES = frozenset({STRICT_MEMORY_POLICY, AGGRESSIVE_MEMORY_POLICY})
_OPTION_NAMES = frozenset({"memory_policy", "allow_executable_readonly", "rva_guard"})


@dataclass(frozen=True, slots=True)
class ConstantSimplificationOptions:
    """Validated public options for the logical constant pipeline."""

    memory_policy: str = STRICT_MEMORY_POLICY
    allow_executable_readonly: bool = False
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

    options: ConstantSimplificationOptions
    name: str = CONSTANT_SIMPLIFICATION_PASS_ID

    def run(self, context: FunctionPipelineContext) -> PassResult:
        return PassResult()


def _parse_options(config: PipelineConfig) -> ConstantSimplificationOptions:
    if config.pass_id != CONSTANT_SIMPLIFICATION_PASS_ID:
        raise PipelineConfigError(
            f"expected {CONSTANT_SIMPLIFICATION_PASS_ID!r}, got {config.pass_id!r}"
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
    rva_guard = config.options.get("rva_guard", True)
    if not isinstance(rva_guard, bool):
        raise PipelineConfigError(
            "constant-simplification options.rva_guard must be boolean"
        )
    return ConstantSimplificationOptions(
        memory_policy=memory_policy,
        allow_executable_readonly=dangerous,
        rva_guard=rva_guard,
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
    memory_options: dict[str, object] = {
        # Private bundle-owned behavior. Direct/legacy activation of the
        # implementation rule does not persist IDB type metadata.
        "persist_global_const_annotations": True,
        "rva_guard": options.rva_guard,
    }
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
                "rva_guard": True,
                "allow_executable_readonly": False,
            },
        ),
        stages=(
            ExecutionStageDescriptor(
                CONSTANT_SIMPLIFICATION_PASS_ID,
                "fold-readonly-data",
                ExecutionPipeline.INSTRUCTION,
                "FoldReadonlyDataRule",
            ),
            ExecutionStageDescriptor(
                CONSTANT_SIMPLIFICATION_PASS_ID,
                "fold-constant-subtree",
                ExecutionPipeline.INSTRUCTION,
                "ConstantSubtreeFoldRule",
            ),
            ExecutionStageDescriptor(
                CONSTANT_SIMPLIFICATION_PASS_ID,
                "forward-constants",
                ExecutionPipeline.FLOW,
                "ForwardConstantPropagationRule",
            ),
        ),
        editor_spec=PassEditorSpec.fields_editor(
            (
                FieldEditorSpec(
                    field_id="memory_policy",
                    label="Memory policy",
                    path=("memory_policy",),
                    control=FieldControlKind.ENUM,
                    description="Controls which read-only memory values may be materialized.",
                    choices=(STRICT_MEMORY_POLICY, AGGRESSIVE_MEMORY_POLICY),
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
                ),
                FieldEditorSpec(
                    field_id="allow_executable_readonly",
                    label="Allow executable read-only memory",
                    path=("allow_executable_readonly",),
                    control=FieldControlKind.BOOLEAN,
                    description="Very dangerous override for executable read-only memory.",
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
    "register_constant_simplification_pass",
]
