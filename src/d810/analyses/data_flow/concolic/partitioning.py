"""Trace partitioning: ``PathPredicate`` + ``PartitionedState`` (S2 single-partition).

Trace partitioning (path-sensitivity) is kept **orthogonal** to value precision
(the reduced product): a :class:`PartitionedState` maps each
:class:`PathPredicate` (a conjunction of assumed branch conditions) to its own
*store* (``LocationRef -> value-lattice element``).  Today's
``StateTransitionDomain`` is the degenerate one-partition, single-cell case the
fixpoint generalises onto.

S1/S2 carry exactly ONE (trivial, empty) partition -- the partition machinery is
present so the ``StateT`` shape is final, but multi-partition splitting + a budget
land in S6 (when ``SolverCapability.refute`` prunes infeasible arms).  The store
value type is left generic (``LocationRef -> V``): S2 instantiates ``V`` with the
``StateValue`` powerset (exact reproduction of ``StateTransitionDomain``); later
slices carry ``ConcolicValue``.  Ticket llr-mauq / epic llr-7ouc.

Portable: no IDA, no z3.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.typing import Mapping

from d810.analyses.data_flow.concolic.refs import LocationRef

__all__ = ["PathPredicate", "PartitionedState", "TRIVIAL_PATH", "Store"]

#: A store: per-location value-lattice element.  ``V`` is ``StateValue`` in S2,
#: ``ConcolicValue`` later -- kept loose (``object``) so the partitioning layer
#: stays value-agnostic (the domain injects the per-cell algebra).
Store = Mapping[LocationRef, object]


@dataclass(frozen=True, slots=True)
class PathPredicate:
    """A conjunction of assumed branch conditions (the partition key).

    ``conjuncts`` holds opaque condition tokens (portable ``ExprRef``s once the
    symbolic layer lands in S5/S6); empty = the unconditioned trivial partition.
    Frozen + hashable so it keys the partition map.
    """

    conjuncts: tuple = ()

    def assume(self, condition: object) -> "PathPredicate":
        """Refine this path by assuming ``condition`` also holds."""
        return PathPredicate((*self.conjuncts, condition))


#: The single partition every S1/S2 state carries (no path-sensitivity yet).
TRIVIAL_PATH = PathPredicate()


@dataclass(frozen=True, slots=True)
class PartitionedState:
    """``PathPredicate -> store`` -- the ``StateT`` the fixpoint carries.

    S1/S2 invariant: exactly one (``TRIVIAL_PATH``) partition.  Use
    :meth:`single` to build it and :meth:`store` to read the sole partition's
    store back.
    """

    partitions: Mapping[PathPredicate, Store] = field(default_factory=dict)

    @staticmethod
    def single(store: Store) -> "PartitionedState":
        """A one-partition state holding ``store`` under the trivial path."""
        return PartitionedState({TRIVIAL_PATH: dict(store)})

    def store(self) -> Store:
        """The single partition's store (S1/S2: there is exactly one)."""
        return self.partitions.get(TRIVIAL_PATH, {})
