"""DEFFAI Context Transition Graph (CTG) -- Algorithm 2 + ``POSSIBLE_SUCCESSORS``.

The CTG maps each context to its **successor contexts** -- the un-flattened
transition graph that becomes the recovered machine's FORKING edges (Baek & Lee,
IEEE TSE 52(3) 2026, Algorithm 2).

Algorithm 2 (reflected here):

    for each context ctx:
        next_states = lub over ctx's back-edge stores of S#[...][state_cell]
                      (a SET -- this is the fork)
        for each concrete next_state s in next_states:
            ctx' = POSSIBLE_SUCCESSORS(ctx, s, k)
            successors[ctx].add(ctx')

    POSSIBLE_SUCCESSORS(ctx, s, k):
        return ctx.extend(s, k)     # if len(ctx.cases) < k: the window GROWS
                                    # else: it SLIDES (drops the oldest)

``POSSIBLE_SUCCESSORS`` is gated on ``len(ctx) < k`` (the ticket's exact
requirement): while the context is not yet full, extending *grows* the window
(more precision); once full it *slides*.  This is the finiteness bound:
``|contexts| <= |states|^k``.

A ``next_states`` member that routes to default / STOP / a miss becomes a
``top`` / return successor (DEFFAI's tail: unresolved -> leave for the concolic
refiner).  A multi-member ``next_states`` is the **fork** -- multiple ``ctx'``.

Portable-core: no IDA imports.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Callable, Mapping, Optional

from d810.ir.flowgraph import FlowGraph
from d810.analyses.control_flow.state_transition_domain import StateValue
from d810.analyses.data_flow.concolic.refs import LocationRef

from d810.analyses.control_flow.deffai.analysis import AnalysisResult
from d810.analyses.control_flow.deffai.ccm import CCM
from d810.analyses.control_flow.deffai.context import KContext

__all__ = ["CTG", "build_ctg", "possible_successors"]

#: A routing function: a concrete next-state const -> the handler block it
#: routes to, or ``None`` (default / STOP / unroutable -> a top/return edge).
RouteFn = Callable[[int], Optional[int]]


@dataclass(frozen=True, slots=True)
class CTG:
    """Context Transition Graph: ``ctx -> {ctx', ...}`` plus the unresolved set.

    ``successors[ctx]`` is the set of successor contexts (the fork edges).
    ``initial_contexts`` is every context reachable from the entry.
    ``unresolved`` is the set of contexts that produced at least one ``top`` /
    unroutable next-state (a back-edge whose next-state set is ``top`` or whose
    member routes nowhere) -- these are the DEFFAI tail left for the concolic
    refiner (P4); P3 marks them, never guesses them.
    """

    successors: Mapping[KContext, frozenset[KContext]]
    initial_contexts: frozenset[KContext]
    unresolved: frozenset[KContext]

    def get(self, ctx: KContext) -> frozenset[KContext]:
        return self.successors.get(ctx, frozenset())


def possible_successors(ctx: KContext, state: int, k: int) -> KContext:
    """``POSSIBLE_SUCCESSORS(ctx, s, k)`` -- the successor context for ``state``.

    Delegates to :meth:`KContext.extend`, which grows the window while
    ``len(ctx) < k`` and slides once full -- the exact DEFFAI gate.
    """
    return ctx.extend(int(state), k)


def _next_state_source_blocks(
    graph: FlowGraph, ccm: CCM, ctx: KContext, dispatcher_entry: int
) -> frozenset[int]:
    """Blocks in ``ctx``'s partial CFG whose successor re-enters the dispatcher.

    These are the back-edge predecessors of ``dispatcher_entry`` -- the handler
    exit blocks that write the next state and loop back.  A terminal (``ret``)
    block is a RETURN, not a transition, so it is NOT a next-state source (it has
    no successor toward the dispatcher).  These blocks' state-cell **out**-values
    form the ``next_states`` set.
    """
    partial = ccm.get(ctx)
    blocks = partial.blocks
    result: set[int] = set()
    for bb in blocks:
        blk = graph.blocks.get(int(bb))
        if blk is None or not blk.succs:
            continue  # terminal: a return, not a next-state transition
        if any(int(s) == int(dispatcher_entry) for s in blk.succs):
            result.add(int(bb))  # back-edge into the dispatcher
    return frozenset(result)


def _next_states_for_context(
    result: AnalysisResult,
    graph: FlowGraph,
    ccm: CCM,
    ctx: KContext,
    state_cell: LocationRef,
    dispatcher_entry: int,
) -> StateValue:
    """The ``next_states`` set for ``ctx``: lub of the state cell over back-edges.

    Joins the state-cell value across every next-state source block's **out**-
    store under ``ctx`` -- the post-fold store, where the handler's next-state
    write lives (the in-store still holds the dispatcher-routed value the handler
    consumes).  A multi-member result is the fork; an empty join is ``bottom`` (no
    resolved next-state -- e.g. a returning context); a ``top`` member is an
    unknown next-state (left for P4).
    """
    acc = StateValue.bottom()
    for bb in _next_state_source_blocks(graph, ccm, ctx, dispatcher_entry):
        store = result.out_store_at(ctx, int(bb))
        acc = acc.join(store.get(state_cell))
    return acc


def build_ctg(
    result: AnalysisResult,
    ccm: CCM,
    *,
    state_cell: LocationRef,
    graph: FlowGraph,
    k: int,
    dispatcher_entry: Optional[int] = None,
    route: Optional[RouteFn] = None,
) -> CTG:
    """DEFFAI Algorithm 2: build the context-successor graph (the FORKING edges).

    For each reachable context, compute ``next_states`` (the lub of the state
    cell over the context's back-edge blocks -- the handler exits that re-enter
    ``dispatcher_entry``).  For each concrete member ``s``:

    * if ``route`` is given and ``route(s)`` is ``None`` (unroutable / default /
      STOP), the context is marked ``unresolved`` (a ``top``/return edge -- left
      for P4) and no successor context is added for ``s``;
    * otherwise add ``ctx' = possible_successors(ctx, s, k)``.

    A ``top`` ``next_states`` (unknown -- data/MBA-obfuscated condvar) marks the
    context ``unresolved`` with no fabricated successors.  A multi-member set is
    the fork (several ``ctx'``).  ``dispatcher_entry`` defaults to the graph
    entry serial.
    """
    if dispatcher_entry is None:
        dispatcher_entry = int(graph.entry_serial)
    successors: dict[KContext, frozenset[KContext]] = {}
    unresolved: set[KContext] = set()

    for ctx in sorted(result.reachable_contexts, key=lambda c: c.cases):
        next_states = _next_states_for_context(
            result, graph, ccm, ctx, state_cell, int(dispatcher_entry)
        )
        if next_states.is_top:
            unresolved.add(ctx)
            successors[ctx] = frozenset()
            continue
        if next_states.is_bottom:
            successors[ctx] = frozenset()
            continue
        succ_ctxs: set[KContext] = set()
        for s in sorted(next_states.constants):
            if route is not None and route(int(s)) is None:
                unresolved.add(ctx)
                continue
            succ_ctxs.add(possible_successors(ctx, int(s), k))
        successors[ctx] = frozenset(succ_ctxs)

    initial = frozenset(
        c for c in result.reachable_contexts if c.depth == 0
    ) or frozenset({KContext.empty()})

    return CTG(
        successors=successors,
        initial_contexts=initial,
        unresolved=frozenset(unresolved),
    )
