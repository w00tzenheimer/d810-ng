"""Portable unflatten pass shape: the canonical five-pass state-machine spine.

The five-pass spine is dispatcher-shape neutral: every standard kind (equality-chain, condition-chain,
switch-table) runs the SAME passes, which re-derive their own evidence from ``ctx.graph``.
This module owns the canonical 5-tuple — the DRY source consumed by the family
``pipeline_for`` (``HodurFamily``; ``ApproovFamily`` for the switch-table kind).

Layer: families -> passes/capabilities is downward; this module is NEVER imported by
``analyses``/``passes``.
"""
from __future__ import annotations

from d810.passes.pass_pipeline import (
    AnalysisContract,
    FactRequirement,
    MaturityRange,
    PassContract,
    PassInvalidates,
    PassOutputs,
    PassPreserves,
    PassRequires,
    PassSafety,
    PassScope,
    PassSpec,
    default,
    live_mba,
    no_caps,
)
from d810.passes.registry import PassRegistry
from d810.ir.maturity import IRMaturity
from d810.passes.unflatten.state_machine import (
    CleanupResidualDispatcher,
    LowerStateMachine,
    PlanSemanticRegions,
    RecoverDispatcher,
    RecoverStateTransitions,
)

__all__ = [
    "CLEANUP_ANALYSES",
    "DISPATCHER_ANALYSES",
    "LOWER_ANALYSES",
    "REGION_ANALYSES",
    "TRANSITION_ANALYSES",
    "register_state_machine_passes",
    "state_machine_pass_spec",
    "standard_state_machine_passes",
    "state_machine_pass_registry",
]

DISPATCHER_ANALYSES = AnalysisContract(
    provided=frozenset(
        {
            "dispatcher_model",
            "recover_dispatcher",
            "recovered_machine",
        }
    )
)
TRANSITION_ANALYSES = AnalysisContract(
    required=frozenset({"recover_dispatcher"}),
    provided=frozenset(
        {
            "recover_state_transitions",
            "transition_result",
            "valrange_confirmable_count",
        }
    ),
)
REGION_ANALYSES = AnalysisContract(
    required=frozenset({"recover_dispatcher", "transition_result"}),
    provided=frozenset({"plan_semantic_regions"}),
)
LOWER_ANALYSES = AnalysisContract(
    required=frozenset(
        {
            "plan_semantic_regions",
            "recover_dispatcher",
            "transition_result",
        }
    ),
    provided=frozenset({"lower_state_machine_plan_metadata"}),
)
CLEANUP_ANALYSES = AnalysisContract()

STATE_MACHINE_MATURITY = MaturityRange(
    min=IRMaturity.CALL_MODELED,
    max=IRMaturity.GLOBAL_ANALYZED,
    preferred=IRMaturity.GLOBAL_ANALYZED,
)
ROLE_DISPATCHER_FACT = "role.dispatcher"
IR_BRANCH_TARGET_EVIDENCE = "ir.branch_target"
IR_STATE_VARIABLE_WRITE_EVIDENCE = "ir.state_variable_write"
RECOVERED_STATE_TRANSITION_FACT = "recovered.state_transition"
RECOVERED_REGION_FACT = "recovered.region"
RECOVERED_CFG_EDGE_FACT = "recovered.cfg_edge"
STALE_CFG_SHAPE_FACT = "ir.cfg_shape.stale"


def _state_machine_contract(
    *,
    requires_analyses: frozenset[str] = frozenset(),
    requires_evidence: frozenset[str] = frozenset(),
    requires_facts: frozenset[str] = frozenset(),
    outputs_facts: frozenset[str] = frozenset(),
    preserves_analyses: frozenset[str] = frozenset(),
    preserves_facts: frozenset[str] = frozenset(),
    invalidates_analyses: frozenset[str] = frozenset(),
    invalidates_facts: frozenset[str] = frozenset(),
    safety: PassSafety = PassSafety(),
) -> PassContract:
    return PassContract(
        scope=PassScope.FUNCTION,
        # Standard CFF families declare GLOBAL_ANALYZED; indirect-table variants can
        # enter at CALL_MODELED, so the native contract records the full supported range.
        maturity=STATE_MACHINE_MATURITY,
        requires=PassRequires(
            analyses=requires_analyses,
            evidence=requires_evidence,
            facts=FactRequirement(required=requires_facts),
        ),
        outputs=PassOutputs(facts=outputs_facts),
        preserves=PassPreserves(
            analyses=preserves_analyses,
            facts=preserves_facts,
        ),
        invalidates=PassInvalidates(
            analyses=invalidates_analyses,
            facts=invalidates_facts,
        ),
        safety=safety,
    )


DISPATCHER_CONTRACT = _state_machine_contract(
    outputs_facts=frozenset({ROLE_DISPATCHER_FACT}),
)
TRANSITION_CONTRACT = _state_machine_contract(
    requires_analyses=TRANSITION_ANALYSES.required,
    requires_evidence=frozenset(
        {IR_BRANCH_TARGET_EVIDENCE, IR_STATE_VARIABLE_WRITE_EVIDENCE}
    ),
    requires_facts=frozenset({ROLE_DISPATCHER_FACT}),
    outputs_facts=frozenset({RECOVERED_STATE_TRANSITION_FACT}),
)
REGION_CONTRACT = _state_machine_contract(
    requires_analyses=REGION_ANALYSES.required,
    requires_facts=frozenset(
        {ROLE_DISPATCHER_FACT, RECOVERED_STATE_TRANSITION_FACT}
    ),
    outputs_facts=frozenset({RECOVERED_REGION_FACT}),
)
MUTATING_STATE_MACHINE_PRESERVED_ANALYSES = frozenset({"function_boundaries"})
MUTATING_STATE_MACHINE_INVALIDATED_ANALYSES = frozenset(
    {"dominators", "loop_info", "postdominators", "regions"}
)
MUTATING_STATE_MACHINE_PRESERVED_FACTS = frozenset(
    {"raw_instruction_addresses", RECOVERED_CFG_EDGE_FACT}
)
MUTATING_STATE_MACHINE_INVALIDATED_FACTS = frozenset({STALE_CFG_SHAPE_FACT})
MUTATING_STATE_MACHINE_SAFETY = PassSafety(policy="golden", requires_oracle=True)

LOWER_CONTRACT = _state_machine_contract(
    requires_analyses=LOWER_ANALYSES.required,
    requires_facts=frozenset(
        {
            ROLE_DISPATCHER_FACT,
            RECOVERED_REGION_FACT,
            RECOVERED_STATE_TRANSITION_FACT,
        }
    ),
    outputs_facts=frozenset({RECOVERED_CFG_EDGE_FACT}),
    preserves_analyses=MUTATING_STATE_MACHINE_PRESERVED_ANALYSES,
    preserves_facts=MUTATING_STATE_MACHINE_PRESERVED_FACTS,
    invalidates_analyses=MUTATING_STATE_MACHINE_INVALIDATED_ANALYSES,
    invalidates_facts=MUTATING_STATE_MACHINE_INVALIDATED_FACTS,
    safety=MUTATING_STATE_MACHINE_SAFETY,
)
CLEANUP_CONTRACT = _state_machine_contract(
    preserves_analyses=MUTATING_STATE_MACHINE_PRESERVED_ANALYSES,
    preserves_facts=MUTATING_STATE_MACHINE_PRESERVED_FACTS,
    invalidates_analyses=MUTATING_STATE_MACHINE_INVALIDATED_ANALYSES,
    invalidates_facts=MUTATING_STATE_MACHINE_INVALIDATED_FACTS,
    safety=MUTATING_STATE_MACHINE_SAFETY,
)


_CONTRACTS_BY_PASS_ID = {
    "recover_dispatcher": DISPATCHER_CONTRACT,
    "recover_state_transitions": TRANSITION_CONTRACT,
    "plan_semantic_regions": REGION_CONTRACT,
    "lower_state_machine": LOWER_CONTRACT,
    "cleanup_residual_dispatcher": CLEANUP_CONTRACT,
}


def state_machine_pass_spec(
    pass_id: str,
    pass_factory,
    requirements,
    safety_policy,
    *,
    analyses: AnalysisContract,
) -> PassSpec:
    """Build a canonical state-machine pass spec with native contract metadata."""
    return PassSpec(
        pass_id,
        pass_factory,
        requirements,
        safety_policy,
        analyses=analyses,
        contract=_CONTRACTS_BY_PASS_ID[pass_id],
    )


def register_state_machine_passes(registry: PassRegistry) -> PassRegistry:
    """Register the canonical state-machine CFF pass factories."""
    registry.register("recover_dispatcher", RecoverDispatcher)
    registry.register("recover_state_transitions", RecoverStateTransitions)
    registry.register("plan_semantic_regions", PlanSemanticRegions)
    registry.register("lower_state_machine", LowerStateMachine)
    registry.register("cleanup_residual_dispatcher", CleanupResidualDispatcher)
    return registry


def state_machine_pass_registry() -> PassRegistry:
    """Return a registry populated with the canonical state-machine pass ids."""
    return register_state_machine_passes(PassRegistry())


def standard_state_machine_passes() -> tuple[PassSpec, ...]:
    """Return the canonical five-pass unflatten state-machine spine, in order."""
    return (
        state_machine_pass_spec(
            "recover_dispatcher",
            RecoverDispatcher,
            live_mba,
            default,
            analyses=DISPATCHER_ANALYSES,
        ),
        state_machine_pass_spec(
            "recover_state_transitions",
            RecoverStateTransitions,
            live_mba,
            default,
            analyses=TRANSITION_ANALYSES,
        ),
        state_machine_pass_spec(
            "plan_semantic_regions",
            PlanSemanticRegions,
            no_caps,
            default,
            analyses=REGION_ANALYSES,
        ),
        state_machine_pass_spec(
            "lower_state_machine",
            LowerStateMachine,
            no_caps,
            default,
            analyses=LOWER_ANALYSES,
        ),
        state_machine_pass_spec(
            "cleanup_residual_dispatcher",
            CleanupResidualDispatcher,
            no_caps,
            default,
            analyses=CLEANUP_ANALYSES,
        ),
    )
