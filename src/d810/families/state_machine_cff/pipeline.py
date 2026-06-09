"""Portable §1a pass shape: the canonical five-pass state-machine spine.

The five-pass spine is dispatcher-shape neutral: every standard kind (equality-chain, BST,
switch-table) runs the SAME passes, which re-derive their own evidence from ``ctx.graph``.
This module owns the canonical 5-tuple — the DRY source consumed by the family
``pipeline_for`` (``HodurFamily``; ``ApproovFamily`` for the switch-table kind).

Layer: families -> passes/capabilities is downward; this module is NEVER imported by
``analyses``/``passes``.
"""
from __future__ import annotations

from d810.passes.pass_pipeline import PassSpec, default, golden, live_mba, no_caps
from d810.passes.unflatten.state_machine import (
    CleanupResidualDispatcher,
    LowerStateMachine,
    PlanSemanticRegions,
    RecoverDispatcher,
    RecoverStateTransitions,
)

__all__ = ["standard_state_machine_passes"]


def standard_state_machine_passes() -> tuple[PassSpec, ...]:
    """Return the canonical five-pass §1a state-machine spine, in order."""
    return (
        PassSpec("recover_dispatcher", RecoverDispatcher, live_mba, default),
        PassSpec(
            "recover_state_transitions", RecoverStateTransitions, live_mba, default
        ),
        PassSpec("plan_semantic_regions", PlanSemanticRegions, no_caps, default),
        PassSpec("lower_state_machine", LowerStateMachine, no_caps, golden),
        PassSpec(
            "cleanup_residual_dispatcher", CleanupResidualDispatcher, no_caps, golden
        ),
    )
