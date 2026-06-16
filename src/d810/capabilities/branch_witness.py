"""Capability boundary for exact branch-arm witnesses."""
from __future__ import annotations

from d810.core.typing import Protocol
from d810.ir.flowgraph import FlowGraph

__all__ = ["BranchWitnessCapability"]


class BranchWitnessCapability(Protocol):
    """Backend capability for prove-exact-or-abstain branch-arm witnesses."""

    def exact_branch_witness(
        self,
        flow_graph: FlowGraph,
        compare_block: int,
        state: int,
        state_var_stkoff: int | None,
    ) -> object:
        """Return an exact branch witness or an abstain object.

        Concrete implementations should return
        ``d810.analyses.control_flow.branch_witness.ExactBranchWitness`` or
        ``BranchWitnessAbstain``.  This module deliberately uses ``object`` so
        the lower capability layer does not import upward into analyses for the
        result DTO.
        """
