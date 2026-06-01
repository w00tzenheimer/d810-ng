"""HodurFamily.pipeline_for — the real per-family call graph (§1a north-star, realized).

The family returns a tuple of named ``PassSpec``s and the runtime flows
family -> passes -> transforms -> backend.apply. ``detect`` recognizes the state-variable CFF
(Hodur) shape over a portable ``FlowGraph``; ``pipeline_for`` declares the five passes. No
microcode patching happens here — the family only chooses shape.

This module is importable + unit-tested now (the passes' transforms are skeleton no-ops). It
becomes the live call graph once the work-list extractions land their real bodies and the driver
replaces ``HodurUnflattener``. Additive + behavior-neutral until then (not wired into the
maturity hook).
"""
from __future__ import annotations

from d810.passes.pass_pipeline import PassSpec, default, golden, live_mba, no_caps
from d810.analyses.control_flow.dispatcher_recovery import (
    build_state_dispatcher_map_from_flow_graph,
)
from d810.passes.unflatten.state_machine import (
    CleanupResidualDispatcher,
    LowerStateMachine,
    PlanSemanticRegions,
    RecoverDispatcher,
    RecoverStateTransitions,
)


class HodurFamily:
    """State-variable CFF (Hodur) family: detection + pipeline shape. No microcode patching."""

    name = "hodur"

    def detect(self, graph, capabilities, context=None):
        """Recognize the Hodur state machine over a portable ``FlowGraph``.

        A match is an equality-chain dispatcher with enough state constants — the same portable
        detector pass #1 uses. The match IS the recovered ``StateDispatcherMap`` (truthy), so the
        pipeline only runs where a real dispatcher is present.
        """
        if graph is None or not hasattr(graph, "blocks"):
            return None
        return build_state_dispatcher_map_from_flow_graph(graph)

    def pipeline_for(self, match, context) -> "tuple[PassSpec, ...]":
        return (
            PassSpec("recover_dispatcher", RecoverDispatcher, live_mba, default),
            PassSpec("recover_state_transitions", RecoverStateTransitions, live_mba, default),
            PassSpec("plan_semantic_regions", PlanSemanticRegions, no_caps, default),
            PassSpec("lower_state_machine", LowerStateMachine, no_caps, golden),
            PassSpec("cleanup_residual_dispatcher", CleanupResidualDispatcher, no_caps, golden),
        )
