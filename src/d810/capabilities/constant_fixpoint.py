"""Constant-fixpoint capability Protocol.

Describes the backend boundary for state-variable constant-propagation
evidence.  The default Hodur implementation lives at
``d810.passes.constant_fixpoint_backend``;
future angr / Ghidra backends would implement this Protocol next to
their own data-flow analyses.

The ``flow_graph`` parameter is annotated ``Any`` to keep
``d810.capabilities`` free of an upward edge into ``d810.cfg``
(``FlowGraph`` lives there today; a portable ``FlowGraphHandle``
identity is available at ``d810.ir.handles`` but it does not yet
replace ``d810.cfg.FlowGraph``).  Concrete implementations may type
themselves against the richer types: Protocol method parameters are
contravariant so ``Any`` is the only annotation that lets a concrete
``compute(self, flow_graph: FlowGraph, ...)`` structurally satisfy
this contract.

The return type is now tightened to
``d810.ir.results.ConstantFixpointResult`` (slice 9, see
``docs/plans/recon-and-cfg-restructuring-phase0-inventory.md``).  This
closes the slice-3 follow-up that left ``compute()`` returning
``Any``.  Concrete impls already produce this shape under the legacy
alias ``SnapshotConstantFixpointResult`` (see
``d810.analyses.control_flow.state_machine_analysis``).  Return-type covariance
permits backend impls to declare narrower types as long as they
return an instance of ``ConstantFixpointResult``.

Naming note (slice 6): the canonical name is ``ConstantFixpointCapability``,
matching the ``*Capability`` discipline established by slice 5's
``UseDefSafetyCapability``.  The legacy name ``ConstantFixpointBackend``
(the only capability shipped without the ``*Capability`` suffix, slice
3) is preserved as a back-compat alias so the 7 prod consumers + 2
test files don't need to update in this slice.
"""
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
                accept their native graph type (``d810.cfg.FlowGraph``
                for Hodur today; angr ``AILGraph`` for a future angr
                backend); the Protocol surface stays ``Any`` so the
                capability layer holds no upward edge into ``d810.cfg``.
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
