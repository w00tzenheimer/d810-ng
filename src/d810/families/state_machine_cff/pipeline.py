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
    PassSpec,
    default,
    golden,
    live_mba,
    no_caps,
)
from d810.passes.registry import PassRegistry
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
        PassSpec(
            "recover_dispatcher",
            RecoverDispatcher,
            live_mba,
            default,
            analyses=DISPATCHER_ANALYSES,
        ),
        PassSpec(
            "recover_state_transitions",
            RecoverStateTransitions,
            live_mba,
            default,
            analyses=TRANSITION_ANALYSES,
        ),
        PassSpec(
            "plan_semantic_regions",
            PlanSemanticRegions,
            no_caps,
            default,
            analyses=REGION_ANALYSES,
        ),
        PassSpec(
            "lower_state_machine",
            LowerStateMachine,
            no_caps,
            golden,
            analyses=LOWER_ANALYSES,
        ),
        PassSpec(
            "cleanup_residual_dispatcher",
            CleanupResidualDispatcher,
            no_caps,
            golden,
            analyses=CLEANUP_ANALYSES,
        ),
    )
