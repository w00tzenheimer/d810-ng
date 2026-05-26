"""Constant-fixpoint capability Protocol.

Describes the backend boundary for state-variable constant-propagation
evidence.  The default Hodur implementation lives at
``d810.optimizers.microcode.flow.flattening.hodur.constant_fixpoint_backend``;
future angr / Ghidra backends would implement this Protocol next to
their own data-flow analyses.

Parameters and return types are annotated as ``Any`` to keep the
``d810.capabilities`` layer free of upward dependencies on
``d810.cfg`` (which is where ``FlowGraph`` lives today; it would move
to ``d810.ir`` in a later slice).  Concrete implementations may type
themselves against the richer types: Protocol satisfaction is
structural so the widened annotations here do not constrain consumers.

The ``Any`` choice (vs ``object``) is deliberate: Python Protocol
method parameters are contravariant, and a concrete
``compute(self, flow_graph: FlowGraph, ...)`` would NOT satisfy a
Protocol method ``compute(self, flow_graph: object, ...)`` under a
strict type-checker.  ``Any`` is the escape hatch.

Naming note (slice 6): the canonical name is ``ConstantFixpointCapability``,
matching the ``*Capability`` discipline established by slice 5's
``UseDefSafetyCapability``.  The legacy name ``ConstantFixpointBackend``
(the only capability shipped without the ``*Capability`` suffix, slice
3) is preserved as a back-compat alias so the 7 prod consumers + 2
test files don't need to update in this slice.
"""
from __future__ import annotations

from d810.core.typing import Any, Protocol

__all__ = ["ConstantFixpointBackend", "ConstantFixpointCapability"]


class ConstantFixpointCapability(Protocol):
    """Capability boundary for state-variable constant propagation evidence."""

    def compute(
        self,
        flow_graph: Any,
        state_var_stkoff: int,
    ) -> Any:
        """Compute constant propagation facts for a flow graph snapshot.

        Args:
            flow_graph: Portable flow graph snapshot.  Concrete backends
                accept their native graph type (``d810.cfg.FlowGraph``
                for Hodur today; angr ``AILGraph`` for a future angr
                backend); the Protocol surface is widened to ``Any`` so
                the capability layer (and portable consumers above it)
                stays vendor-neutral.
            state_var_stkoff: Stack offset of the state variable being
                analyzed.

        Returns:
            An abstract constant-fixpoint result.  Per the capability
            discipline, this is intended to be a portable, vendor-neutral
            dataclass.  The return annotation is currently widened to
            ``Any`` only because a stable portable home for the result
            type does not yet exist; once a ``ConstantFixpointResult``
            dataclass lands under ``d810.ir`` (or a sibling portable
            location), this annotation tightens and consumers stop
            downcasting.
        """


# Back-compat alias for the slice-3 name.  New code should import
# ``ConstantFixpointCapability``.  This alias preserves the import path
# used by the 7 Hodur strategy consumers, the substrate unit test, and
# the system-runtime re-export test so they do not need to update in
# this slice.
ConstantFixpointBackend = ConstantFixpointCapability
