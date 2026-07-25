"Constant-fixpoint capability Protocol.\n\nDescribes the backend boundary for state-variable constant-propagation\nevidence.  The default Hodur implementation lives at\n``d810.passes.constant_fixpoint_backend``;\nfuture angr / Ghidra backends would implement this Protocol next to\ntheir own data-flow analyses.\n\nThe ``flow_graph`` parameter is annotated ``Any`` because this is a\nProtocol surface; the portable ``FlowGraph`` lives at\n``d810.ir.flowgraph`` (with a ``FlowGraphHandle`` identity at\n``d810.ir.handles``).  Concrete implementations may type\nthemselves against the richer types: Protocol method parameters are\ncontravariant so ``Any`` is the only annotation that lets a concrete\n``compute(self, flow_graph: FlowGraph, ...)`` structurally satisfy\nthis contract.\n\nThe return type is now tightened to\n``d810.ir.results.ConstantFixpointResult`` (slice 9, see\n``docs/plans/preanalysis-and-cfg-restructuring-phase0-inventory.md``).  This\ncloses the slice-3 follow-up that left ``compute()`` returning\n``Any``.  Concrete impls already produce this shape under the legacy\nalias ``SnapshotConstantFixpointResult`` (see\n``d810.analyses.control_flow.state_machine_analysis``).  Return-type covariance\npermits backend impls to declare narrower types as long as they\nreturn an instance of ``ConstantFixpointResult``.\n\nNaming note (slice 6): the canonical name is ``ConstantFixpointCapability``,\nmatching the ``*Capability`` discipline established by slice 5's\n``UseDefSafetyCapability``.  The legacy name ``ConstantFixpointBackend``\n(the only capability shipped without the ``*Capability`` suffix, slice\n3) is preserved as a back-compat alias so the 7 prod consumers + 2\ntest files don't need to update in this slice.\n"

from __future__ import annotations

from d810.core.typing import Any, Protocol
from d810.ir.results import ConstantFixpointResult

__all__ = ["ConstantFixpointBackend", "ConstantFixpointCapability"]


class ConstantFixpointCapability(Protocol):
    """Capability boundary for state-variable constant propagation evidence."""

    def compute(
        self,
        flow_graph: Any,
        state_var_stkoff: int,
    ) -> ConstantFixpointResult:
        """Compute constant propagation facts for a flow graph snapshot.

        Args:
            flow_graph: Portable flow graph snapshot.  Concrete backends
                accept their native graph type (``d810.ir.flowgraph.FlowGraph``
                for Hodur today; angr ``AILGraph`` for a future angr
                backend); the Protocol surface stays ``Any`` so it
                binds to no concrete backend graph type.
            state_var_stkoff: Stack offset of the state variable being
                analyzed.

        Returns:
            A ``ConstantFixpointResult`` carrying the in/out stack and
            register constant maps per block plus the iteration count.
            Concrete backends produce instances of this dataclass
            directly; the legacy ``SnapshotConstantFixpointResult``
            name is an alias preserved at the Hodur lift site.
        """


# Back-compat alias for the slice-3 name.  New code should import
# ``ConstantFixpointCapability``.  This alias preserves the import path
# used by the 7 Hodur strategy consumers, the substrate unit test, and
# the system-runtime re-export test so they do not need to update in
# this slice.
ConstantFixpointBackend = ConstantFixpointCapability
