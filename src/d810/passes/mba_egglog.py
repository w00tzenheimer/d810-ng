"""Private config-v2 stage for bounded Egglog MBA extraction."""

from __future__ import annotations

from dataclasses import dataclass

from d810.core.pass_ids import PassId
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
class MbaEgglogPass(PipelinePass):
    """Portable descriptor; the live hook stage performs the extraction."""

    max_leaves: int = 2
    rounds: int = 3
    require_proof: bool = True
    families: tuple[str, ...] = DEFAULT_FAMILIES
    maturities: tuple[str, ...] = DEFAULT_MATURITIES
    name: str = MBA_EGGLOG_PASS_ID

    def run(self, context: FunctionPipelineContext) -> PassResult:
        return PassResult()


def parse_mba_egglog_options(
    config: PipelineConfig,
) -> tuple[int, int, bool, tuple[str, ...], tuple[str, ...]]:
    if config.pass_id != MBA_EGGLOG_PASS_ID:
        raise PipelineConfigError(
            f"expected {MBA_EGGLOG_PASS_ID!r}, got {config.pass_id!r}"
        )
    options: Mapping[str, object] = config.options or {}
    unknown = set(options) - {
        "max_leaves",
        "rounds",
        "require_proof",
        "families",
        "maturities",
    }
    if unknown:
        raise PipelineConfigError(f"mba-egglog has unknown options: {sorted(unknown)}")
    max_leaves = options.get("max_leaves", 2)
    rounds = options.get("rounds", 3)
    require_proof = options.get("require_proof", True)
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
    if not isinstance(rounds, int) or isinstance(rounds, bool) or not 1 <= rounds <= 6:
        raise PipelineConfigError(
            "mba-egglog options.rounds must be an integer from 1 to 6"
        )
    if require_proof is not True:
        raise PipelineConfigError("mba-egglog native proof is mandatory")
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
    if isinstance(maturities, str) or not isinstance(maturities, (list, tuple)):
        raise PipelineConfigError(
            "mba-egglog options.maturities must be a list of names"
        )
    resolved = tuple(str(value) for value in maturities)
    if not resolved or any(
        value not in {member.name for member in IRMaturity} for value in resolved
    ):
        raise PipelineConfigError(
            "mba-egglog options.maturities must name supported IR maturities"
        )
    return max_leaves, rounds, require_proof, resolved_families, resolved


def build_mba_egglog_pass(config: PipelineConfig) -> MbaEgglogPass:
    max_leaves, rounds, require_proof, families, maturities = parse_mba_egglog_options(
        config
    )
    return MbaEgglogPass(
        max_leaves=max_leaves,
        rounds=rounds,
        require_proof=require_proof,
        families=families,
        maturities=maturities,
    )


def register_mba_egglog_pass(registry: PassRegistry) -> PassRegistry:
    registry.register_configured(
        MBA_EGGLOG_PASS_ID,
        build_mba_egglog_pass,
        config_template=PipelineConfig(
            pass_id=MBA_EGGLOG_PASS_ID,
            options={
                "max_leaves": 2,
                "rounds": 3,
                "require_proof": True,
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
        public=False,
    )
    return registry


__all__ = [
    "MBA_EGGLOG_IMPLEMENTATION",
    "MBA_EGGLOG_FAMILIES",
    "MBA_EGGLOG_PASS_ID",
    "MBA_EGGLOG_STAGE_ID",
    "build_mba_egglog_pass",
    "parse_mba_egglog_options",
    "register_mba_egglog_pass",
]
