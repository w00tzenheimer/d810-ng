"""Portable §1a pass shape, selected by resolved dispatcher kind (llr-g3l8 slice 2).

The five-pass state-machine spine is dispatcher-shape neutral: every standard kind
(equality-chain, BST, switch-table) runs the SAME passes, which re-derive their own
evidence from ``ctx.graph``. This module owns the canonical 5-tuple (the DRY source
for ``HodurFamily.pipeline_for`` and ``StateMachineCffSpine``) plus the kind->shape
policy. ``INDIRECT_TABLE`` / ``UNKNOWN`` map to an empty pipeline (unhandled no-op).

Layer: families -> passes/capabilities is downward; this module is NEVER imported by
``analyses``/``passes``.
"""
from __future__ import annotations

from d810.capabilities.dispatcher import RouterKind
from d810.passes.pass_pipeline import PassSpec, default, golden, live_mba, no_caps
from d810.passes.unflatten.state_machine import (
    CleanupResidualDispatcher,
    LowerStateMachine,
    PlanSemanticRegions,
    RecoverDispatcher,
    RecoverStateTransitions,
)

__all__ = ["standard_state_machine_passes", "pipeline_for_kind"]

#: Dispatcher kinds the standard five-pass spine handles. INDIRECT_TABLE / UNKNOWN
#: are deliberately excluded -> empty pipeline (no-op) until a shape detector lands.
_STANDARD_KINDS = frozenset(
    {RouterKind.EQUALITY_CHAIN, RouterKind.BST, RouterKind.SWITCH}
)


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


def pipeline_for_kind(router_kind: RouterKind) -> tuple[PassSpec, ...]:
    """Select the §1a pass shape for a resolved dispatcher ``router_kind``.

    Standard kinds (equality-chain / BST / switch) run the full five-pass spine;
    every other kind (``INDIRECT_TABLE`` / ``UNKNOWN``) returns an empty tuple,
    i.e. an unhandled no-op.
    """
    if router_kind in _STANDARD_KINDS:
        return standard_state_machine_passes()
    return ()
