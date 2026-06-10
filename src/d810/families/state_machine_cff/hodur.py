"""Hodur family: the unflatten ``Family`` profile for equality-chain state-variable CFF.

:class:`HodurFamily` recognizes the equality-chain (Hodur) dispatcher shape over a
portable ``FlowGraph`` and declares the five-pass pipeline on the shared spine. It
auto-registers via :class:`StateMachineCffFamily` / ``Registrant`` so the scanner
discovers it on load. Hexrays-free (the unflatten passes/analyses are portable); no microcode
patching happens here.

(The former ``HodurUnflatteningProfile`` strategy-ordering policy was retired with the
M2 hodur-cluster sever, llr-ibpi — its only consumer was the deleted ``hodur/profile.py``.)
"""
from __future__ import annotations

from d810.ir.flowgraph import FlowGraph
from d810.passes.pass_pipeline import PassSpec
from d810.analyses.control_flow.dispatcher_recovery import build_state_dispatcher_map_from_flow_graph
from d810.families.state_machine_cff.base import StateMachineCffFamily
from d810.families.state_machine_cff.pipeline import standard_state_machine_passes

__all__ = ["HodurFamily"]


class HodurFamily(StateMachineCffFamily):
    """State-variable CFF (Hodur) family: detection + pipeline shape. No microcode patching."""

    name = "hodur"

    def detect(self, graph: FlowGraph, capabilities, context=None):
        """Recognize the equality-chain (``CONDITIONAL_CHAIN``) Hodur state machine.

        Claims ONLY the equality-chain dispatcher shape via
        ``build_state_dispatcher_map_from_flow_graph`` — DISJOINT from ``ApproovFamily``'s
        switch/indirect, so at most one profile claims any graph and ``select_family`` is
        order-independent. The match IS the recovered ``StateDispatcherMap`` (truthy), so
        the pipeline only runs where a real equality-chain dispatcher is present.
        """
        if graph is None or not hasattr(graph, "blocks"):
            return None
        return build_state_dispatcher_map_from_flow_graph(graph)

    def pipeline_for(self, match, context) -> "tuple[PassSpec, ...]":
        # DRY: the canonical five-pass spine lives in ``pipeline``; this family's
        # equality-chain shape runs it unchanged.
        return standard_state_machine_passes()
