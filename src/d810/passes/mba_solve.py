"""Config-v2 adapter for solver-based MBA simplification.

Sibling of ``mba_simplify``, and deliberately not a replacement for it. The two
answer different questions:

* ``mba-simplify`` applies 203 pattern-matched *identities*. On
  coefficient-based linear MBA it fires zero times.
* ``mba-solve`` hands the expression to a solver (CoBRA), which derives the
  simplification instead of recognising it.

Off by default. The pass carries no CoBRA import itself -- the work happens
behind a capability, exactly as ``mba-simplify`` does -- so the layering stays
``passes -> backends`` and nothing here depends on IDA.

Design and measurements:
``docs/plans/2026-08-06-cobra-mba-solve-integration.md``
"""

from __future__ import annotations

from dataclasses import dataclass

from d810.core.deobfuscation_case import StrategyWorkflowStage
from d810.core.typing import Mapping, Protocol
from d810.ir.maturity import IRMaturity
from d810.passes.pass_pipeline import (
    FunctionPipelineContext,
    PassResult,
    PipelineConfig,
    PipelinePass,
)
from d810.passes.execution_stages import (
    ExecutionPipeline,
    ExecutionStageDescriptor,
)
from d810.passes.registry import PassRegistry

MBA_SOLVE_PASS_ID = "mba-solve"

#: The instruction rule that implements this pass.
MBA_SOLVE_IMPLEMENTATION = "CobraSolveRule"
#: Stable stage id, mirroring ``mba-simplify``'s ``mba_transform_id`` scheme.
MBA_SOLVE_STAGE_ID = "cobra-solve"

#: Signature cost is 2**n evaluations for n leaves, so this is the real
#: throttle: 256 evaluations at 8 versus 65,536 at 16.
DEFAULT_MAX_LEAVES = 8


@dataclass(frozen=True)
class MbaSolveRequest:
    """Solver-based simplification requested by the config-v2 adapter."""

    live_source: object
    func_ea: int
    maturity: IRMaturity
    max_leaves: int
    require_proof: bool


class MbaSolveCapability(Protocol):
    """Backend-provided executor for solver-based MBA simplification."""

    def run_mba_solve(self, request: MbaSolveRequest) -> PassResult: ...


@dataclass(frozen=True)
class MbaSolvePass(PipelinePass):
    """Simplify MBA expressions through an external solver."""

    max_leaves: int = DEFAULT_MAX_LEAVES
    require_proof: bool = True
    name: str = MBA_SOLVE_PASS_ID

    def __post_init__(self) -> None:
        if self.max_leaves < 1:
            raise ValueError("max_leaves must be >= 1")
        if self.max_leaves > 16:
            # 2**17 evaluations per candidate and climbing; refuse rather than
            # silently make detection quadratic in wall-clock.
            raise ValueError("max_leaves above 16 is not supported")

    def run(self, context: FunctionPipelineContext) -> PassResult:
        capability = context.capabilities.require(MbaSolveCapability)
        return capability.run_mba_solve(
            MbaSolveRequest(
                live_source=context.source.live_source,
                func_ea=int(context.source.func_ea),
                maturity=context.maturity,
                max_leaves=self.max_leaves,
                require_proof=self.require_proof,
            )
        )


def parse_mba_solve_options(config: PipelineConfig) -> tuple[int, bool]:
    """Validate ``mba-solve`` options, rejecting unknown keys loudly."""
    options: Mapping[str, object] = config.options or {}
    unknown = set(options) - {"max_leaves", "require_proof"}
    if unknown:
        raise ValueError(f"mba-solve has unknown options: {sorted(unknown)}")

    max_leaves = options.get("max_leaves", DEFAULT_MAX_LEAVES)
    if not isinstance(max_leaves, int) or isinstance(max_leaves, bool):
        raise ValueError("mba-solve options.max_leaves must be an integer")

    require_proof = options.get("require_proof", True)
    if not isinstance(require_proof, bool):
        raise ValueError("mba-solve options.require_proof must be a boolean")

    return max_leaves, require_proof


def build_mba_solve_pass(config: PipelineConfig) -> MbaSolvePass:
    max_leaves, require_proof = parse_mba_solve_options(config)
    return MbaSolvePass(max_leaves=max_leaves, require_proof=require_proof)


def mba_solve_stages() -> tuple[ExecutionStageDescriptor, ...]:
    """Bind the pass id to its instruction-rule implementation.

    Declaring a stage is not bookkeeping: the runtime derives each pass's
    ``allowed_rule_names`` from its stage descriptors, and a rule outside that
    allowlist is skipped at dispatch (``instructions/handler.py``).  Registering
    without stages therefore produces a pass whose rule is loaded, configured
    and accepted by an optimizer -- and then silently never invoked.
    """
    return (
        ExecutionStageDescriptor(
            pass_id=MBA_SOLVE_PASS_ID,
            stage_id=MBA_SOLVE_STAGE_ID,
            pipeline=ExecutionPipeline.INSTRUCTION,
            implementation_name=MBA_SOLVE_IMPLEMENTATION,
        ),
    )


def register_mba_solve_pass(registry: PassRegistry) -> PassRegistry:
    """Register the config-aware ``mba-solve`` pass factory."""
    stages = mba_solve_stages()
    registry.register_configured(
        MBA_SOLVE_PASS_ID,
        build_mba_solve_pass,
        config_template=PipelineConfig(
            pass_id=MBA_SOLVE_PASS_ID,
            workflow_stage=StrategyWorkflowStage.FRONTEND_NORMALIZATION,
            options={"max_leaves": DEFAULT_MAX_LEAVES, "require_proof": True},
        ),
        stages=stages,
        transform_ids=tuple(stage.stage_id for stage in stages),
    )
    return registry


def mba_solve_pass_registry() -> PassRegistry:
    return register_mba_solve_pass(PassRegistry())


__all__ = [
    "DEFAULT_MAX_LEAVES",
    "MBA_SOLVE_PASS_ID",
    "MbaSolveCapability",
    "MbaSolvePass",
    "MbaSolveRequest",
    "build_mba_solve_pass",
    "mba_solve_pass_registry",
    "parse_mba_solve_options",
    "register_mba_solve_pass",
]
