"""Private config-v2 stage for bounded Egglog MBA extraction."""

from __future__ import annotations

import warnings
from dataclasses import dataclass

from d810.core.pass_ids import PassId
from d810.core.pass_editor_spec import (
    AdvisoryTone,
    FieldControlKind,
    FieldEditorSpec,
    PassEditorSpec,
)
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

MBA_EGGLOG_PASS_ID = PassId.MBA_EGGLOG
MBA_EGGLOG_STAGE_ID = "mba-egglog"
MBA_EGGLOG_IMPLEMENTATION = "EgglogOptimizer"
DEFAULT_MATURITIES = ("GLOBAL_OPTIMIZED",)
DEFAULT_FAMILIES = ("add",)
MBA_EGGLOG_FAMILIES = ("add", "and", "bnot", "mul", "neg", "or", "sub", "xor")


@dataclass(frozen=True)
class MbaEgglogOptions:
    """Validated portable options for one bounded Egglog extraction."""

    max_leaves: int = 2
    max_operator_nodes: int = 10
    max_degree: int = 1
    saturation_rounds: int = 2
    max_eclasses: int = 64
    max_enodes: int = 128
    max_rule_firings: int = 32
    cross_block_constant_preparation: bool = False
    cross_block_def_use_preparation: bool = False
    time_budget_ms: int = 3
    function_time_budget_ms: int | None = None
    residual_only: bool = False
    require_proof: bool = True
    collect_stage_timings: bool = False
    execution_mode: str = "interactive"
    native_proof_mode: str = "legacy"
    families: tuple[str, ...] = DEFAULT_FAMILIES
    maturities: tuple[str, ...] = DEFAULT_MATURITIES


@dataclass(frozen=True)
class MbaEgglogPass(PipelinePass):
    """Portable descriptor; the live hook stage performs the extraction."""

    max_leaves: int = 2
    max_operator_nodes: int = 10
    max_degree: int = 1
    saturation_rounds: int = 2
    max_eclasses: int = 64
    max_enodes: int = 128
    max_rule_firings: int = 32
    cross_block_constant_preparation: bool = False
    cross_block_def_use_preparation: bool = False
    time_budget_ms: int = 3
    function_time_budget_ms: int | None = None
    residual_only: bool = False
    require_proof: bool = True
    collect_stage_timings: bool = False
    execution_mode: str = "interactive"
    native_proof_mode: str = "legacy"
    families: tuple[str, ...] = DEFAULT_FAMILIES
    maturities: tuple[str, ...] = DEFAULT_MATURITIES
    name: str = MBA_EGGLOG_PASS_ID

    def run(self, context: FunctionPipelineContext) -> PassResult:
        return PassResult()


def parse_mba_egglog_options(
    config: PipelineConfig,
) -> MbaEgglogOptions:
    if config.pass_id != MBA_EGGLOG_PASS_ID:
        raise PipelineConfigError(
            f"expected {MBA_EGGLOG_PASS_ID!r}, got {config.pass_id!r}"
        )
    options: Mapping[str, object] = config.options or {}
    unknown = set(options) - {
        "max_leaves",
        "max_operator_nodes",
        "max_degree",
        "saturation_rounds",
        "rounds",
        "max_eclasses",
        "max_enodes",
        "max_rule_firings",
        "cross_block_constant_preparation",
        "cross_block_def_use_preparation",
        "time_budget_ms",
        "function_time_budget_ms",
        "residual_only",
        "require_proof",
        "collect_stage_timings",
        "execution_mode",
        "native_proof_mode",
        "families",
        "maturities",
    }
    if unknown:
        raise PipelineConfigError(f"mba-egglog has unknown options: {sorted(unknown)}")
    if "rounds" in options and "saturation_rounds" in options:
        raise PipelineConfigError(
            "mba-egglog options.rounds and options.saturation_rounds cannot both be set"
        )
    if "rounds" in options:
        warnings.warn(
            "mba-egglog options.rounds is deprecated; use saturation_rounds",
            DeprecationWarning,
            stacklevel=2,
        )
    max_leaves = options.get("max_leaves", 2)
    max_operator_nodes = options.get("max_operator_nodes", 10)
    max_degree = options.get("max_degree", 1)
    saturation_rounds = options.get("saturation_rounds", options.get("rounds", 2))
    max_eclasses = options.get("max_eclasses", 64)
    max_enodes = options.get("max_enodes", 128)
    max_rule_firings = options.get("max_rule_firings", 32)
    cross_block_constant_preparation = options.get(
        "cross_block_constant_preparation", False
    )
    cross_block_def_use_preparation = options.get(
        "cross_block_def_use_preparation", False
    )
    time_budget_ms = options.get("time_budget_ms", 3)
    function_time_budget_ms = options.get("function_time_budget_ms")
    residual_only = options.get("residual_only", False)
    require_proof = options.get("require_proof", True)
    collect_stage_timings = options.get("collect_stage_timings", False)
    execution_mode = options.get("execution_mode", "interactive")
    native_proof_mode = options.get("native_proof_mode", "legacy")
    families = options.get("families", list(DEFAULT_FAMILIES))
    maturities = options.get("maturities", DEFAULT_MATURITIES)
    if (
        not isinstance(max_leaves, int)
        or isinstance(max_leaves, bool)
        or not 1 <= max_leaves <= 8
    ):
        raise PipelineConfigError(
            "mba-egglog options.max_leaves must be an integer from 1 to 8"
        )

    for name, value in (
        ("max_operator_nodes", max_operator_nodes),
        ("max_eclasses", max_eclasses),
        ("max_enodes", max_enodes),
        ("max_rule_firings", max_rule_firings),
        ("time_budget_ms", time_budget_ms),
    ):
        if type(value) is not int or value <= 0:
            raise PipelineConfigError(
                f"mba-egglog options.{name} must be a positive integer"
            )
    if function_time_budget_ms is not None and (
        type(function_time_budget_ms) is not int
        or not 0 <= function_time_budget_ms <= 5_000
    ):
        raise PipelineConfigError(
            "mba-egglog options.function_time_budget_ms must be an integer from 0 to 5000"
        )
    if function_time_budget_ms == 0:
        function_time_budget_ms = None
    if type(residual_only) is not bool:
        raise PipelineConfigError("mba-egglog options.residual_only must be boolean")
    if type(max_degree) is not int or max_degree not in (1, 2):
        raise PipelineConfigError(
            "mba-egglog options.max_degree must be exactly 1 or 2"
        )
    if type(cross_block_constant_preparation) is not bool:
        raise PipelineConfigError(
            "mba-egglog options.cross_block_constant_preparation must be boolean"
        )
    if type(cross_block_def_use_preparation) is not bool:
        raise PipelineConfigError(
            "mba-egglog options.cross_block_def_use_preparation must be boolean"
        )
    if type(saturation_rounds) is not int or not 1 <= saturation_rounds <= 6:
        raise PipelineConfigError(
            "mba-egglog options.saturation_rounds must be an integer from 1 to 6"
        )
    if require_proof is not True:
        raise PipelineConfigError("mba-egglog native proof is mandatory")
    if type(collect_stage_timings) is not bool:
        raise PipelineConfigError(
            "mba-egglog options.collect_stage_timings must be a boolean"
        )
    if type(execution_mode) is not str or execution_mode not in {
        "interactive",
        "noninteractive",
    }:
        raise PipelineConfigError(
            "mba-egglog options.execution_mode must be interactive or noninteractive"
        )
    if native_proof_mode not in {"legacy", "shadow"}:
        raise PipelineConfigError(
            "mba-egglog options.native_proof_mode must be legacy or shadow; "
            "enforced is not rollout-authorized"
        )
    if (
        not isinstance(families, list)
        or not families
        or any(type(value) is not str for value in families)
    ):
        raise PipelineConfigError(
            "mba-egglog options.families must be a nonempty list of names"
        )
    resolved_families = tuple(families)
    if len(set(resolved_families)) != len(resolved_families):
        raise PipelineConfigError("mba-egglog options.families must be unique")
    unsupported_families = tuple(
        family for family in resolved_families if family not in MBA_EGGLOG_FAMILIES
    )
    if unsupported_families:
        raise PipelineConfigError(
            "mba-egglog options.families must name supported families; got "
            + ", ".join(unsupported_families)
        )
    if (
        isinstance(maturities, str)
        or not isinstance(maturities, (list, tuple))
        or any(type(value) is not str for value in maturities)
    ):
        raise PipelineConfigError(
            "mba-egglog options.maturities must be a list of names"
        )
    resolved = tuple(maturities)
    if not resolved or any(
        value not in {member.name for member in IRMaturity} for value in resolved
    ):
        raise PipelineConfigError(
            "mba-egglog options.maturities must name supported IR maturities"
        )
    return MbaEgglogOptions(
        max_leaves=max_leaves,
        max_operator_nodes=max_operator_nodes,
        max_degree=max_degree,
        saturation_rounds=saturation_rounds,
        max_eclasses=max_eclasses,
        max_enodes=max_enodes,
        max_rule_firings=max_rule_firings,
        cross_block_constant_preparation=cross_block_constant_preparation,
        cross_block_def_use_preparation=cross_block_def_use_preparation,
        time_budget_ms=time_budget_ms,
        function_time_budget_ms=function_time_budget_ms,
        residual_only=residual_only,
        require_proof=require_proof,
        collect_stage_timings=collect_stage_timings,
        execution_mode=execution_mode,
        native_proof_mode=native_proof_mode,
        families=resolved_families,
        maturities=resolved,
    )


def build_mba_egglog_pass(config: PipelineConfig) -> MbaEgglogPass:
    options = parse_mba_egglog_options(config)
    return MbaEgglogPass(
        max_leaves=options.max_leaves,
        max_operator_nodes=options.max_operator_nodes,
        max_degree=options.max_degree,
        saturation_rounds=options.saturation_rounds,
        max_eclasses=options.max_eclasses,
        max_enodes=options.max_enodes,
        max_rule_firings=options.max_rule_firings,
        cross_block_constant_preparation=options.cross_block_constant_preparation,
        cross_block_def_use_preparation=options.cross_block_def_use_preparation,
        time_budget_ms=options.time_budget_ms,
        function_time_budget_ms=options.function_time_budget_ms,
        residual_only=options.residual_only,
        require_proof=options.require_proof,
        collect_stage_timings=options.collect_stage_timings,
        execution_mode=options.execution_mode,
        native_proof_mode=options.native_proof_mode,
        families=options.families,
        maturities=options.maturities,
    )


def mba_egglog_editor_spec() -> PassEditorSpec:
    """Return the complete public config-v2 editor contract for Egglog."""
    maturity_choices = tuple(member.name for member in IRMaturity)
    return PassEditorSpec.fields_editor(
        (
            FieldEditorSpec(
                field_id="max_leaves",
                label="Maximum leaves",
                path=("max_leaves",),
                control=FieldControlKind.INTEGER,
                description="Reject candidates with more live leaves before extraction.",
                minimum=1,
                maximum=8,
                default=2,
            ),
            FieldEditorSpec(
                field_id="max_operator_nodes",
                label="Maximum operator nodes",
                path=("max_operator_nodes",),
                control=FieldControlKind.INTEGER,
                description="Reject candidate roots that exceed this operator budget.",
                minimum=1,
                default=10,
            ),
            FieldEditorSpec(
                field_id="max_degree",
                label="Maximum derivation degree",
                path=("max_degree",),
                control=FieldControlKind.INTEGER,
                description="Maximum number of certified identities in one extraction.",
                minimum=1,
                maximum=2,
                default=1,
            ),
            FieldEditorSpec(
                field_id="saturation_rounds",
                label="Saturation rounds",
                path=("saturation_rounds",),
                control=FieldControlKind.INTEGER,
                description="Maximum bounded Egglog rounds after admission.",
                minimum=1,
                maximum=6,
                default=2,
            ),
            FieldEditorSpec(
                field_id="max_eclasses",
                label="Maximum e-classes",
                path=("max_eclasses",),
                control=FieldControlKind.INTEGER,
                description="Fail closed when the projected or observed e-class cap is reached.",
                minimum=1,
                default=64,
            ),
            FieldEditorSpec(
                field_id="max_enodes",
                label="Maximum e-nodes",
                path=("max_enodes",),
                control=FieldControlKind.INTEGER,
                description="Fail closed when the projected or observed e-node cap is reached.",
                minimum=1,
                default=128,
            ),
            FieldEditorSpec(
                field_id="max_rule_firings",
                label="Maximum rule firings",
                path=("max_rule_firings",),
                control=FieldControlKind.INTEGER,
                description="Bound the certified rewrite work for one candidate.",
                minimum=1,
                default=32,
            ),
            FieldEditorSpec(
                field_id="cross_block_constant_preparation",
                label="Prepare cross-block constants",
                path=("cross_block_constant_preparation",),
                control=FieldControlKind.BOOLEAN,
                description="Inline one safe reaching constant before root extraction.",
                default=False,
                experimental=True,
                experimental_reason="Cross-block preparation is bounded but has narrower native coverage.",
            ),
            FieldEditorSpec(
                field_id="cross_block_def_use_preparation",
                label="Prepare cross-block def-use",
                path=("cross_block_def_use_preparation",),
                control=FieldControlKind.BOOLEAN,
                description="Traverse one safe reaching def-use edge before root extraction.",
                default=False,
                experimental=True,
                experimental_reason="Cross-block traversal is bounded but has narrower native coverage.",
            ),
            FieldEditorSpec(
                field_id="time_budget_ms",
                label="Candidate telemetry budget (ms)",
                path=("time_budget_ms",),
                control=FieldControlKind.INTEGER,
                description="Admission and post-run telemetry budget for one candidate.",
                minimum=1,
                default=3,
                advisory=AdvisoryTone.WARNING,
                advisory_reason="Budgets below 50 ms deliberately do not invoke Egglog.",
            ),
            FieldEditorSpec(
                field_id="function_time_budget_ms",
                label="Function budget (ms; 0 disables)",
                path=("function_time_budget_ms",),
                control=FieldControlKind.INTEGER,
                description="Optional aggregate function budget; zero means no function cap.",
                minimum=0,
                maximum=5_000,
                default=0,
            ),
            FieldEditorSpec(
                field_id="residual_only",
                label="Residual candidates only",
                path=("residual_only",),
                control=FieldControlKind.BOOLEAN,
                description="Run only after the configured direct MBA catalogue leaves a residual.",
                default=False,
            ),
            FieldEditorSpec(
                field_id="require_proof",
                label="Require native proof",
                path=("require_proof",),
                control=FieldControlKind.BOOLEAN,
                description="Every reconstructed candidate requires native equivalence proof.",
                default=True,
                read_only=True,
            ),
            FieldEditorSpec(
                field_id="collect_stage_timings",
                label="Collect stage timings",
                path=("collect_stage_timings",),
                control=FieldControlKind.BOOLEAN,
                description="Record per-stage Egglog timing telemetry.",
                default=False,
            ),
            FieldEditorSpec(
                field_id="execution_mode",
                label="Execution mode",
                path=("execution_mode",),
                control=FieldControlKind.ENUM,
                description="Select interactive or noninteractive Egglog admission semantics.",
                choices=("interactive", "noninteractive"),
                default="interactive",
            ),
            FieldEditorSpec(
                field_id="native_proof_mode",
                label="Native proof mode",
                path=("native_proof_mode",),
                control=FieldControlKind.ENUM,
                description="Use the rollout-authorized native proof implementation.",
                choices=("legacy", "shadow"),
                default="legacy",
            ),
            FieldEditorSpec(
                field_id="families",
                label="Certified rule families",
                path=("families",),
                control=FieldControlKind.STRING_LIST,
                description="Ordered subset of certified MBA rule families available to Egglog.",
                choices=MBA_EGGLOG_FAMILIES,
                default=list(DEFAULT_FAMILIES),
            ),
            FieldEditorSpec(
                field_id="maturities",
                label="Maturities",
                path=("maturities",),
                control=FieldControlKind.STRING_LIST,
                description="Hex-Rays maturities at which Egglog candidate roots may run.",
                choices=maturity_choices,
                default=list(DEFAULT_MATURITIES),
            ),
        )
    )


def register_mba_egglog_pass(registry: PassRegistry) -> PassRegistry:
    registry.register_configured(
        MBA_EGGLOG_PASS_ID,
        build_mba_egglog_pass,
        config_template=PipelineConfig(
            pass_id=MBA_EGGLOG_PASS_ID,
            options={
                "max_leaves": 2,
                "max_operator_nodes": 10,
                "max_degree": 1,
                "saturation_rounds": 2,
                "max_eclasses": 64,
                "max_enodes": 128,
                "max_rule_firings": 32,
                "cross_block_constant_preparation": False,
                "cross_block_def_use_preparation": False,
                "time_budget_ms": 3,
                "function_time_budget_ms": 0,
                "residual_only": False,
                "require_proof": True,
                "collect_stage_timings": False,
                "execution_mode": "interactive",
                "native_proof_mode": "legacy",
                "families": list(DEFAULT_FAMILIES),
                "maturities": list(DEFAULT_MATURITIES),
            },
        ),
        stages=(
            ExecutionStageDescriptor(
                pass_id=MBA_EGGLOG_PASS_ID,
                stage_id=MBA_EGGLOG_STAGE_ID,
                pipeline=ExecutionPipeline.INSTRUCTION,
                implementation_name=MBA_EGGLOG_IMPLEMENTATION,
            ),
        ),
        editor_spec=mba_egglog_editor_spec(),
    )
    return registry


__all__ = [
    "MBA_EGGLOG_IMPLEMENTATION",
    "MBA_EGGLOG_FAMILIES",
    "MBA_EGGLOG_PASS_ID",
    "MBA_EGGLOG_STAGE_ID",
    "MbaEgglogOptions",
    "build_mba_egglog_pass",
    "mba_egglog_editor_spec",
    "parse_mba_egglog_options",
    "register_mba_egglog_pass",
]
