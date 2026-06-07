"""Block-ownership forward fixpoint: which handler region(s) own each block.

Portable-core (no IDA).  The companion to the state-value dispatcher discovery
(:mod:`state_transition_domain` / :mod:`dispatcher_discovery_fixpoint`): the
state-value fixpoint says *which state(s)* a block holds; this owner-set
fixpoint says *which handler region(s)* a block belongs to.  Orthogonal, both
needed -- a ``RANGE_BACKED`` handler is one owner (entry ``H``) whose
``in_states[H]`` is multi-const.

The lattice is a forward "may-reach-from-handler-entry" set, finite-height
(bounded by the handler count), so it needs no widening.  Three transfer rules
collapse the BST-corridor / supplemental / anchor heuristic clusters:

* dispatcher region (head + BST compares) -> **KILL** (ownership never flows
  through the dispatcher; this is what keeps the handler->dispatcher->handler
  back-edges from making every block owned by everyone);
* handler entry -> **GEN** (the block starts its own region);
* anything else -> **pass-through** (the union is handled by ``meet`` at
  joins, so a block two handler regions reach converges to ``{H1, H2}`` -- the
  shared epilogue, computed as a lattice join instead of a corridor heuristic).

Read-off (:func:`block_owners`) is over the **OUT-state**, not the IN-state:

* a handler entry's IN arrives empty from the killed dispatcher -- only the
  GEN, in its OUT, makes it own itself;
* the dispatcher head's IN is the back-edge fan-in of *every* handler -- only
  its OUT, post-KILL, reads as infrastructure (``frozenset()``).

``in == out`` for every pass-through block, so body / epilogue ownership is
identical either way; the OUT-state is the one that is correct for *all three*
block classes.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Callable, Collection, Iterable, Mapping

from d810.analyses.data_flow import FixpointResult, run_fixpoint
from d810.analyses.data_flow.domain import NodeId

__all__ = [
    "OwnerSet",
    "BlockOwnershipDomain",
    "analyze_block_ownership",
    "block_owners",
    "owned_blocks",
    "exclusive_blocks",
    "shared_suffix_blocks",
]

# The abstract value: the set of handler-entry serials whose region reaches a
# block.  ``frozenset()`` is bottom -- unreached / dispatcher infrastructure.
OwnerSet = frozenset

_Succ = Callable[[NodeId], Iterable[NodeId]]


@dataclass(frozen=True, slots=True)
class BlockOwnershipDomain:
    """``FlowDomain[frozenset[int]]`` -- a forward may-reach-from-handler set.

    Finite-height (bounded by ``len(handler_entries)``), so ``widen`` is the
    identity (mirrors a reaching-definitions style domain): the ascending chain
    can grow at most to the full handler set, so the worklist always drains
    without needing to accelerate convergence.
    """

    handler_entries: frozenset[int]
    dispatcher_region: frozenset[int]

    def bottom(self) -> frozenset[int]:
        return frozenset()

    def confluence(
        self, left: frozenset[int], right: frozenset[int]
    ) -> frozenset[int]:
        # Confluence is union: a block reachable from either region is owned by
        # both, so the shared epilogue emerges as a lattice join.
        return left | right

    def transfer(self, node: NodeId, in_state: frozenset[int]) -> frozenset[int]:
        node = int(node)
        if node in self.dispatcher_region:
            return frozenset()  # KILL -- ownership never flows through dispatch
        if node in self.handler_entries:
            return in_state | {node}  # GEN -- this block starts its own region
        return in_state  # pass-through

    def equals(self, left: frozenset[int], right: frozenset[int]) -> bool:
        return left == right

    def widen(
        self, previous: frozenset[int], current: frozenset[int]
    ) -> frozenset[int]:
        return current  # finite height -> no widening needed


def analyze_block_ownership(
    *,
    nodes: Iterable[NodeId],
    successors_of: _Succ,
    predecessors_of: _Succ,
    handler_entries: Collection[int],
    dispatcher_region: Collection[int],
) -> FixpointResult[frozenset[int]]:
    """Run the block-ownership fixpoint over a portable graph.

    ``handler_entries`` and ``dispatcher_region`` come straight off the
    :class:`~d810.analyses.control_flow.dispatcher_discovery_fixpoint.DispatcherView`
    read-off (``handler_entry_by_state`` values, and ``dispatcher_entry`` plus
    ``bst_node_blocks``) -- no new structural recognition.  The handler entries
    seed the worklist with an empty boundary; each GENs itself via
    ``transfer``.
    """
    he = frozenset(int(h) for h in handler_entries)
    dr = frozenset(int(d) for d in dispatcher_region)
    domain = BlockOwnershipDomain(handler_entries=he, dispatcher_region=dr)
    return run_fixpoint(
        domain,
        nodes=[int(n) for n in nodes],
        entry_nodes=list(he),
        entry_state=frozenset(),
        successors_of=successors_of,
        predecessors_of=predecessors_of,
        raise_on_nonconvergence=True,
    )


def block_owners(result: FixpointResult[frozenset[int]]) -> Mapping[int, frozenset[int]]:
    """The owner map: block serial -> the handler-entry set that owns it.

    Read off the OUT-state (see the module docstring on the IN-vs-OUT choice).
    A block mapping to ``frozenset()`` is dispatcher / BST infrastructure,
    correctly owned by no handler.
    """
    return {int(b): owners for b, owners in result.out_states.items()}


def owned_blocks(owners: Mapping[int, frozenset[int]], handler: int) -> list[int]:
    """Blocks in handler ``H``'s region (entry + body + any shared suffix)."""
    handler = int(handler)
    return sorted(b for b, o in owners.items() if handler in o)


def exclusive_blocks(owners: Mapping[int, frozenset[int]], handler: int) -> list[int]:
    """Blocks owned *only* by ``H`` -- its private region (no shared suffix)."""
    handler = int(handler)
    return sorted(b for b, o in owners.items() if o == frozenset({handler}))


def shared_suffix_blocks(
    owners: Mapping[int, frozenset[int]], handler: int
) -> list[int]:
    """Blocks ``H`` shares with another handler -- the shared epilogue/corridor.

    ``len(owners[b]) > 1`` is the single predicate that replaces
    ``detect_side_effect_corridors``, the supplemental-alias family, and the
    bespoke ``_resolve_sub7ffd_corridor_dispatcher_anchor_override``.
    """
    handler = int(handler)
    return sorted(b for b, o in owners.items() if handler in o and len(o) > 1)
