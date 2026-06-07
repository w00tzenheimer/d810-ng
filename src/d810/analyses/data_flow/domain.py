"""Abstract data-flow domain Protocol."""
from __future__ import annotations

from d810.core.typing import Protocol, TypeVar, runtime_checkable

StateT = TypeVar("StateT")

# Identifier of a node in the analyzed graph.  An opaque integer (the
# block serial in the Hex-Rays backend); analyses never interpret its
# value beyond equality and use it to key the in/out state maps.
NodeId = int


@runtime_checkable
class FlowDomain(Protocol[StateT]):
    """Abstract domain a fixpoint analysis is written against.

    Generalises the engine's separate ``MeetFunction`` / ``TransferFunction``
    callables (in
    ``d810.evaluator.hexrays_microcode.forward_dataflow``) into a single
    domain object, adding the ``bottom`` / ``equals`` / ``widen`` operations
    a terminating lattice analysis needs.  A later slice (Landing Sequence
    step 5) adapts the worklist solver to consume a ``FlowDomain`` directly.
    """

    def bottom(self) -> StateT:
        """Least element -- the initial state carrying no information."""
        ...

    def confluence(self, left: StateT, right: StateT) -> StateT:
        """Combine two states at a control-flow merge point.

        The dataflow "meet-over-all-paths" operator -- for may-analyses it is a
        join (lub).  Named ``confluence`` rather than ``meet`` so this whole-state
        merge is never confused with the lattice-theoretic ``meet`` (glb) carried
        by value-lattice *elements* (e.g. ``KnownBits.meet``).
        """
        ...

    def transfer(self, node: NodeId, in_state: StateT) -> StateT:
        """Propagate ``in_state`` through ``node`` to its output state."""
        ...

    def equals(self, left: StateT, right: StateT) -> bool:
        """Return ``True`` when two states are equal (the fixpoint test)."""
        ...

    def widen(self, previous: StateT, current: StateT) -> StateT:
        """Accelerate convergence over a back-edge (bound ascending chains)."""
        ...
