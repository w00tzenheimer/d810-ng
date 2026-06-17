"""The explicit two layers over a recovered dispatcher: node kinds + SCC condensation.

The recovered control flow is modelled in two layers (the user's two-layer
framing):

1. :class:`~d810.analyses.control_flow.state_transition_graph.StateTransitionGraph`
   -- a **cyclic** block graph (dispatcher back-edges, handler loops). Its blocks
   play distinct roles, captured by :class:`NodeKind` and assigned by
   :func:`classify_nodes`.
2. :class:`CondensedStateDag` -- the strongly-connected-component quotient of (1),
   which is the *only* genuinely acyclic view (hence reserving "DAG" for it). The
   non-trivial SCCs are exactly the loop bodies the structurer must turn into
   ``while`` / ``do``; the condensed edges give the loop-free skeleton.

Pure / IDA-free.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.core.typing import Iterable, Mapping, Optional

from d810.analyses.control_flow.state_transition_graph import StateTransitionGraph

__all__ = [
    "NodeKind",
    "classify_nodes",
    "CondensedStateDag",
    "condense_sccs",
]


class NodeKind(str, Enum):
    """The role a block plays in the recovered state machine.

    * ``HANDLER`` -- a semantic handler block (the default).
    * ``DISPATCHER_TEST`` -- a condition-chain comparison node (lives in the decision-DAG).
    * ``STATE_WRITE`` -- a block that writes the next state var (re-dispatches),
      including the materialised range/else-routed handlers (e.g. ``blk57``).
    * ``ROUTE_GLUE`` -- a shared routine reached by goto from several handlers
      (e.g. the ``blk35`` ``LABEL_x420E`` shared tail) that itself sets a state.
    * ``ENTRY`` -- the function entry handler.
    """

    HANDLER = "handler"
    DISPATCHER_TEST = "dispatcher_test"
    STATE_WRITE = "state_write"
    ROUTE_GLUE = "route_glue"
    ENTRY = "entry"


def classify_nodes(
    cfg: StateTransitionGraph,
    *,
    comparison_blocks: Iterable[int] = (),
    state_write_blocks: Iterable[int] = (),
    route_glue_blocks: Iterable[int] = (),
    entry: Optional[int] = None,
) -> Mapping[int, NodeKind]:
    """Tag every block of *cfg* with its :class:`NodeKind`.

    Precedence (most specific first): ``ENTRY`` > ``DISPATCHER_TEST`` >
    ``STATE_WRITE`` > ``ROUTE_GLUE`` > ``HANDLER``. The caller supplies the
    role sets from the layers that know them -- *comparison_blocks* from the
    decision-DAG (``DecisionDag.nodes``), *state_write_blocks* from the
    materialise set / ``block_writes_state_var``, *route_glue_blocks* from the
    shared-routine detector. Blocks not otherwise classified are ``HANDLER``.
    """
    tests = {int(b) for b in comparison_blocks}
    writes = {int(b) for b in state_write_blocks}
    glue = {int(b) for b in route_glue_blocks}
    entry_serial = int(entry) if entry is not None else int(cfg.entry_serial)

    kinds: dict[int, NodeKind] = {}
    for serial in cfg.blocks:
        if serial == entry_serial:
            kinds[serial] = NodeKind.ENTRY
        elif serial in tests:
            kinds[serial] = NodeKind.DISPATCHER_TEST
        elif serial in writes:
            kinds[serial] = NodeKind.STATE_WRITE
        elif serial in glue:
            kinds[serial] = NodeKind.ROUTE_GLUE
        else:
            kinds[serial] = NodeKind.HANDLER
    return kinds


@dataclass(frozen=True)
class CondensedStateDag:
    """The SCC quotient of a :class:`StateTransitionGraph` -- acyclic by construction.

    Each component is a ``frozenset`` of block serials (a singleton for an
    acyclic block, a larger set for a loop body). :attr:`succs` maps a component
    index to its successor component indices (no self-loops -- intra-SCC edges
    are contracted), so it is a genuine DAG.
    """

    components: tuple[frozenset[int], ...]
    component_of: Mapping[int, int]
    succs: Mapping[int, frozenset[int]]
    entry_component: int

    def is_loop(self, component_index: int) -> bool:
        """A non-trivial SCC (>1 block) -- a recovered loop body.

        The :class:`StateTransitionGraph` carries no block-level self-edges (the
        builder drops ``src == dst`` dispatcher-spin artifacts), so a multi-block
        SCC is the only loop shape.
        """
        return len(self.components[component_index]) > 1


def condense_sccs(cfg: StateTransitionGraph) -> CondensedStateDag:
    """Contract the strongly-connected components of *cfg* into an acyclic quotient.

    Iterative Tarjan (no recursion-depth risk on deep dispatcher graphs). A
    single block with a self-edge is reported as its own (loop) component via the
    successor-set check; the condensed :attr:`succs` never contains a self-edge.
    """
    succ = {serial: list(block.succs) for serial, block in cfg.blocks.items()}
    index_of: dict[int, int] = {}
    low: dict[int, int] = {}
    on_stack: set[int] = set()
    stack: list[int] = []
    counter = 0
    comp_of: dict[int, int] = {}
    components: list[frozenset[int]] = []

    for root in cfg.blocks:
        if root in index_of:
            continue
        # work-stack of (node, successor-iterator-position)
        work: list[tuple[int, int]] = [(root, 0)]
        while work:
            node, pos = work[-1]
            if pos == 0:
                index_of[node] = low[node] = counter
                counter += 1
                stack.append(node)
                on_stack.add(node)
            succs = succ.get(node, ())
            if pos < len(succs):
                work[-1] = (node, pos + 1)
                nxt = succs[pos]
                if nxt not in index_of:
                    work.append((nxt, 0))
                elif nxt in on_stack:
                    low[node] = min(low[node], index_of[nxt])
            else:
                if low[node] == index_of[node]:
                    members: list[int] = []
                    while True:
                        w = stack.pop()
                        on_stack.discard(w)
                        comp_of[w] = len(components)
                        members.append(w)
                        if w == node:
                            break
                    components.append(frozenset(members))
                work.pop()
                if work:
                    parent = work[-1][0]
                    low[parent] = min(low[parent], low[node])

    quotient: dict[int, set[int]] = {i: set() for i in range(len(components))}
    for src, dsts in succ.items():
        cs = comp_of[src]
        for dst in dsts:
            cd = comp_of[dst]
            if cd != cs:  # contract intra-SCC edges -> acyclic
                quotient[cs].add(cd)

    succs_frozen = {i: frozenset(v) for i, v in quotient.items()}
    entry_component = comp_of[int(cfg.entry_serial)] if cfg.blocks else 0
    return CondensedStateDag(
        components=tuple(components),
        component_of=dict(comp_of),
        succs=succs_frozen,
        entry_component=entry_component,
    )
