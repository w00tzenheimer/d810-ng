"""``ConcolicTransitionDomain`` -- a ``FlowDomain[PartitionedState]`` (S2).

Generalises ``StateTransitionDomain`` from a single ``StateValue`` to a
:class:`~d810.analyses.data_flow.concolic.partitioning.PartitionedState` whose
store maps each tracked ``LocationRef`` to a value-lattice element.  The domain is
**parametric over the per-cell value algebra** (:class:`ValueLatticeOps`), so it
reproduces ``StateTransitionDomain`` *exactly* when instantiated with the
``StateValue`` powerset, and later carries ``ConcolicValue`` (concrete + abstract
+ symbolic) cells without changing the fixpoint plumbing.

S2 is **abstract-only transfer**: per cell, strong-update-or-passthrough, mirroring
``StateTransitionDomain.transfer`` (an unreachable cell -- ``vops.is_bottom`` --
stays unreachable, so a dead block never pollutes the value-set).  No concrete
emulation (S3), no symbolic refinement (S5), no multi-partition branch splitting
(S6): there is exactly one partition and the per-block strong-update view is
supplied as plain data, exactly like ``StateTransitionDomain``'s ``state_writes``.

Run via :func:`d810.analyses.data_flow.run_fixpoint`.  Ticket llr-mauq.  Portable:
no IDA, no z3.
"""
from __future__ import annotations

from d810.core.typing import Mapping, Protocol, TypeVar

from d810.analyses.data_flow.concolic.partitioning import PartitionedState
from d810.analyses.data_flow.concolic.refs import LocationRef
from d810.analyses.data_flow.domain import NodeId

__all__ = ["ValueLatticeOps", "ConcolicTransitionDomain"]

V = TypeVar("V")


class ValueLatticeOps(Protocol[V]):
    """The per-cell value algebra the transition domain delegates to.

    Injected (not baked in) so the SAME fixpoint reproduces ``StateTransitionDomain``
    with the ``StateValue`` powerset, or carries ``ConcolicValue`` later.  ``widen``
    receives ``(previous, current)`` -- match the existing domain's policy (for a
    finite-height lattice, ``previous.join(current)``).
    """

    def bottom(self) -> V: ...
    def join(self, a: V, b: V) -> V: ...
    def widen(self, previous: V, current: V) -> V: ...
    def is_bottom(self, value: V) -> bool: ...


class ConcolicTransitionDomain:
    """``FlowDomain[PartitionedState]`` over a ``LocationRef -> V`` store.

    ``writes`` is the per-block strong-update view (``node -> {loc: V}``); a block
    absent from the view, or a cell absent from a block's write, performs no update
    and passes the incoming value through.  ``cells`` is the fixed set of tracked
    locations (so ``bottom`` builds a complete store).  ``vops`` is the per-cell
    :class:`ValueLatticeOps`.
    """

    def __init__(
        self,
        *,
        writes: Mapping[NodeId, Mapping[LocationRef, V]],
        vops: ValueLatticeOps[V],
        cells: "frozenset[LocationRef] | set[LocationRef]",
    ) -> None:
        self._writes: dict[int, dict[LocationRef, V]] = {
            int(node): dict(write) for node, write in writes.items()
        }
        self._vops = vops
        self._cells: frozenset[LocationRef] = frozenset(cells)

    def bottom(self) -> PartitionedState:
        return PartitionedState.single({c: self._vops.bottom() for c in self._cells})

    def confluence(
        self, left: PartitionedState, right: PartitionedState
    ) -> PartitionedState:
        """Single-partition, cell-wise least upper bound (an unset cell is ⊥)."""
        ls, rs = left.store(), right.store()
        bottom = self._vops.bottom
        return PartitionedState.single(
            {
                c: self._vops.join(ls.get(c, bottom()), rs.get(c, bottom()))
                for c in self._cells
            }
        )

    def transfer(self, node: NodeId, in_state: PartitionedState) -> PartitionedState:
        """Per cell: ⊥ stays ⊥; else strong-update to the block's write, else pass through."""
        store = in_state.store()
        write = self._writes.get(int(node), {})
        bottom = self._vops.bottom
        out: dict[LocationRef, V] = {}
        for c in self._cells:
            current = store.get(c, bottom())
            if self._vops.is_bottom(current):
                out[c] = bottom()
            elif c in write:
                out[c] = write[c]
            else:
                out[c] = current
        return PartitionedState.single(out)

    def equals(self, left: PartitionedState, right: PartitionedState) -> bool:
        return left.store() == right.store()

    def widen(
        self, previous: PartitionedState, current: PartitionedState
    ) -> PartitionedState:
        ps, cs = previous.store(), current.store()
        bottom = self._vops.bottom
        return PartitionedState.single(
            {
                c: self._vops.widen(ps.get(c, bottom()), cs.get(c, bottom()))
                for c in self._cells
            }
        )
