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
    MaturityRange,
    PassContract,
    PassInvalidates,
    PassOutputs,
    PassRequires,
    PassScope,
    PassSpec,
    default,
    golden,
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


def _state_machine_contract(
    *,
    requires_analyses: frozenset[str] = frozenset(),
    requires_evidence: frozenset[str] = frozenset(),
    outputs_facts: frozenset[str] = frozenset(),
    invalidates_analyses: frozenset[str] = frozenset(),
    invalidates_facts: frozenset[str] = frozenset(),
) -> PassContract:
    return PassContract(
        scope=PassScope.FUNCTION,
        # Standard CFF families declare GLOBAL_ANALYZED; indirect-table variants can
        # enter at CALL_MODELED, so the native contract records the full supported range.
        maturity=STATE_MACHINE_MATURITY,
        requires=PassRequires(
            analyses=requires_analyses,
            evidence=requires_evidence,
        ),
        outputs=PassOutputs(facts=outputs_facts),
        invalidates=PassInvalidates(
            analyses=invalidates_analyses,
            facts=invalidates_facts,
        ),
    )


DISPATCHER_CONTRACT = _state_machine_contract(
    outputs_facts=frozenset({"dispatcher_family"}),
)
TRANSITION_CONTRACT = _state_machine_contract(
    requires_analyses=TRANSITION_ANALYSES.required,
    requires_evidence=frozenset({"state_variable_writes"}),
    outputs_facts=frozenset({"state_transition"}),
)
REGION_CONTRACT = _state_machine_contract(
    requires_analyses=REGION_ANALYSES.required,
    outputs_facts=frozenset({"semantic_region"}),
)
LOWER_CONTRACT = _state_machine_contract(
    requires_analyses=LOWER_ANALYSES.required,
    outputs_facts=frozenset({"recovered_cfg_edge"}),
    invalidates_facts=frozenset({"stale_cfg_shape"}),
)
CLEANUP_CONTRACT = _state_machine_contract()


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
            golden,
            analyses=LOWER_ANALYSES,
        ),
        state_machine_pass_spec(
            "cleanup_residual_dispatcher",
            CleanupResidualDispatcher,
            no_caps,
            golden,
            analyses=CLEANUP_ANALYSES,
        ),
    )
