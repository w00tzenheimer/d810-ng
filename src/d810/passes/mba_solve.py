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

from d810.core import getLogger
from d810.core.deobfuscation_case import StrategyWorkflowStage
from d810.core.pass_ids import PassId
from d810.core.pass_editor_spec import (
    FieldControlKind,
    FieldEditorSpec,
    PassEditorSpec,
)
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

logger = getLogger(__name__)

#: Back-reference to the shared vocabulary; see :mod:`d810.core.pass_ids`.
MBA_SOLVE_PASS_ID = PassId.MBA_SOLVE

#: Stable stage id, mirroring ``mba-simplify``'s ``mba_transform_id`` scheme.
MBA_SOLVE_STAGE_ID = "mba-solve"


def mba_solve_implementation() -> str | None:
    """The rule class implementing this pass, as declared by an extension.

    d810 ships no MBA solver. Naming one here (``"CobraSolveRule"``) put a
    vendor's class name in core: d810 could host exactly one solver, and the
    name outlived the backend being extracted into its own distribution.

    Returns None when no extension declares an implementation -- the honest
    answer, and what stops this pass from claiming a rule that will never
    register.
    """
    from d810.backends import registry

    return registry().implementation_for(MBA_SOLVE_PASS_ID)

#: Signature cost is 2**n evaluations for n leaves, so this is the real
#: throttle: 256 evaluations at 8 versus 65,536 at 16.
DEFAULT_MAX_LEAVES = 8

#: Maturities the rule runs at, in the portable ``IRMaturity`` vocabulary --
#: this layer must stay hexrays-agnostic, so the rule maps these to ``MMAT_*``.
#:
#: GLOBAL_OPTIMIZED (MMAT_GLBOPT2) only, and this is the single most important
#: setting in the pass.  Measured on VM_DecryptPacket, decompiling one function:
#:
#:     CALL_MODELED      61 rewrites,  87.6 min, NEVER COMPLETED
#:     GLOBAL_ANALYZED   40 rewrites,  26+  min, NEVER COMPLETED
#:     GLOBAL_OPTIMIZED  17 rewrites,  46.2 s,   completed, 626 -> 563 lines
#:
#: The earlier choice was made on CANDIDATE COUNT -- 55 candidates at
#: GLOBAL_ANALYZED versus 10 at GLOBAL_OPTIMIZED -- which is the wrong measure.
#: By GLOBAL_OPTIMIZED Hex-Rays has already folded aggressively, so the
#: microcode is far smaller: fewer instructions to walk, fewer re-optimisation
#: passes over the same addresses, and a much better cost per useful rewrite.
#: 17 rewrites that finish beat 40 that never do.
#:
#: Adding an earlier maturity back is not free capability -- it is what made
#: this pass unusable.  Re-measure end-to-end before changing this.
DEFAULT_MATURITIES = ("GLOBAL_OPTIMIZED",)


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
    maturities: tuple[str, ...] = DEFAULT_MATURITIES
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


def parse_mba_solve_options(
    config: PipelineConfig,
) -> tuple[int, bool, tuple[str, ...]]:
    """Validate ``mba-solve`` options, rejecting unknown keys loudly."""
    options: Mapping[str, object] = config.options or {}
    unknown = set(options) - {"max_leaves", "require_proof", "maturities"}
    if unknown:
        raise ValueError(f"mba-solve has unknown options: {sorted(unknown)}")

    max_leaves = options.get("max_leaves", DEFAULT_MAX_LEAVES)
    if not isinstance(max_leaves, int) or isinstance(max_leaves, bool):
        raise ValueError("mba-solve options.max_leaves must be an integer")

    require_proof = options.get("require_proof", True)
    if not isinstance(require_proof, bool):
        raise ValueError("mba-solve options.require_proof must be a boolean")

    raw = options.get("maturities", DEFAULT_MATURITIES)
    if isinstance(raw, str) or not isinstance(raw, (list, tuple)):
        raise ValueError("mba-solve options.maturities must be a list of names")
    maturities = tuple(str(name) for name in raw)
    if not maturities:
        # An empty list would disable the rule everywhere while still looking
        # configured -- refuse rather than silently do nothing.
        raise ValueError("mba-solve options.maturities must not be empty")
    valid = {member.name for member in IRMaturity}
    bad = sorted(set(maturities) - valid)
    if bad:
        raise ValueError(
            f"mba-solve options.maturities has unknown names: {bad}; "
            f"valid names are {sorted(valid)}"
        )

    return max_leaves, require_proof, maturities


def build_mba_solve_pass(config: PipelineConfig) -> MbaSolvePass:
    max_leaves, require_proof, maturities = parse_mba_solve_options(config)
    return MbaSolvePass(
        max_leaves=max_leaves,
        require_proof=require_proof,
        maturities=maturities,
    )


def mba_solve_stages() -> tuple[ExecutionStageDescriptor, ...]:
    """Bind the pass id to its instruction-rule implementation.

    Declaring a stage is not bookkeeping: the runtime derives each pass's
    ``allowed_rule_names`` from its stage descriptors, and a rule outside that
    allowlist is skipped at dispatch (``instructions/handler.py``).  Registering
    without stages therefore produces a pass whose rule is loaded, configured
    and accepted by an optimizer -- and then silently never invoked.
    """
    implementation = mba_solve_implementation()
    if implementation is None:
        # No installed extension implements mba-solve, so there is no rule to
        # allowlist. Returning a descriptor naming a class that will never
        # register would produce a pass that is loaded, configured and then
        # silently never invoked -- the exact failure this docstring warns
        # about. `d810cli backends` is where the absence is visible.
        logger.info(
            "mba-solve has no implementation: no installed backend declares "
            "one (install d810-cobra to enable it)"
        )
        return ()
    return (
        ExecutionStageDescriptor(
            pass_id=MBA_SOLVE_PASS_ID,
            stage_id=MBA_SOLVE_STAGE_ID,
            pipeline=ExecutionPipeline.INSTRUCTION,
            implementation_name=implementation,
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
            options={
                "max_leaves": DEFAULT_MAX_LEAVES,
                "require_proof": True,
                "maturities": list(DEFAULT_MATURITIES),
            },
        ),
        stages=stages,
        transform_ids=tuple(stage.stage_id for stage in stages),
        editor_spec=PassEditorSpec.fields_editor(
            (
                FieldEditorSpec(
                    field_id="max_leaves",
                    label="Maximum leaves",
                    path=("max_leaves",),
                    control=FieldControlKind.INTEGER,
                    description="Limits solver signature growth per candidate.",
                    minimum=1,
                    maximum=16,
                    default=DEFAULT_MAX_LEAVES,
                ),
                FieldEditorSpec(
                    field_id="require_proof",
                    label="Require proof",
                    path=("require_proof",),
                    control=FieldControlKind.BOOLEAN,
                    description="Reject a solver rewrite unless its proof is available.",
                    default=True,
                ),
                FieldEditorSpec(
                    field_id="maturities",
                    label="Maturities",
                    path=("maturities",),
                    control=FieldControlKind.STRING_LIST,
                    description="Hex-Rays maturities at which solver work may run.",
                    default=list(DEFAULT_MATURITIES),
                ),
            )
        ),
    )
    return registry


def mba_solve_pass_registry() -> PassRegistry:
    return register_mba_solve_pass(PassRegistry())


__all__ = [
    "DEFAULT_MATURITIES",
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
