"""Portable worklist fixpoint solver driven by a :class:`FlowDomain`.

This is the analyses-layer counterpart to the engine in
``d810.evaluator.hexrays_microcode.forward_dataflow``: the same monotone
worklist algorithm, but written against the abstract
:class:`~d810.analyses.data_flow.domain.FlowDomain` (portable -- no IDA, no
concrete graph object; topology is supplied as callables) with explicit
widening for tall lattices.

The Hex-Rays engine is migrated onto this solver in a later slice; today
this module is the step-5 worked example proving the step-3 vocabulary
carries a real fixpoint computation.
"""
from __future__ import annotations

from d810.core.logging import getLogger
from d810.core.typing import Callable, Collection, Iterable

from d810.analyses.data_flow.analyzed_cfg import FixpointResult
from d810.analyses.data_flow.configuration import Direction, FixpointConfiguration
from d810.analyses.data_flow.domain import FlowDomain, NodeId, StateT
from d810.analyses.data_flow.exceptions import FixpointDidNotConverge
from d810.analyses.data_flow.working_set import WorkingSet

logger = getLogger(__name__)


def run_fixpoint(
    domain: FlowDomain[StateT],
    *,
    nodes: Collection[NodeId],
    entry_nodes: Collection[NodeId],
    successors_of: Callable[[NodeId], Iterable[NodeId]],
    predecessors_of: Callable[[NodeId], Iterable[NodeId]],
    config: FixpointConfiguration = FixpointConfiguration(),
    raise_on_nonconvergence: bool = False,
) -> FixpointResult[StateT]:
    """Run a monotone worklist fixpoint for *domain* over a graph.

    The topology is supplied as callables rather than a concrete graph
    object so the solver stays portable.  ``config.direction`` selects
    forward (meet predecessor outputs, propagate to successors) or backward
    (meet successor outputs, propagate to predecessors) -- backward is the
    forward algorithm on the reversed edge relation.

    The boundary state of every ``entry_nodes`` member is ``domain.bottom()``
    and always participates in that node's meet, so a loop header that is
    also an entry does not lose its initial fact across the back-edge
    (mirrors ``run_forward_fixpoint``'s entry handling).

    Widening (``FlowDomain.widen``) is applied to a node's incoming state
    once it has been re-evaluated more than ``config.widening_threshold``
    times, bounding ascending chains on tall lattices.  Finite-height
    domains (e.g. constant propagation) implement ``widen`` as
    ``return current`` and converge without it.

    Args:
        domain: The abstract domain (bottom/meet/transfer/equals/widen).
        nodes: Every node id in the graph (seeds the state maps).
        entry_nodes: Boundary nodes enqueued first (function entry for a
            forward run, exits for a backward run).
        successors_of: Maps a node to its successor ids.
        predecessors_of: Maps a node to its predecessor ids.
        config: Iteration cap, widening threshold, and direction.
        raise_on_nonconvergence: When ``True`` and the worklist does not
            drain within ``config.max_iterations``, raise
            :class:`FixpointDidNotConverge` instead of returning a
            ``converged=False`` result.

    Returns:
        A :class:`FixpointResult` with the in/out state of every node.

    Note:
        ``config.descending_iterations`` (narrowing) is reserved for a
        later slice; this solver computes only the ascending fixpoint.
    """
    forward = config.direction is Direction.FORWARD
    flow_preds = predecessors_of if forward else successors_of
    flow_succs = successors_of if forward else predecessors_of

    bottom = domain.bottom()
    in_states: dict[NodeId, StateT] = {node: bottom for node in nodes}
    out_states: dict[NodeId, StateT] = {node: bottom for node in nodes}
    visits: dict[NodeId, int] = {}

    entry_set = set(entry_nodes)
    worklist = WorkingSet(entry_nodes)
    iterations = 0
    max_iterations = config.max_iterations

    while worklist and iterations < max_iterations:
        node = worklist.pop()
        iterations += 1
        visits[node] = visits.get(node, 0) + 1

        incoming = [out_states[p] for p in flow_preds(node)]
        if node in entry_set:
            # Boundary condition participates in the meet (see docstring).
            incoming = [bottom, *incoming]

        if incoming:
            in_candidate = incoming[0]
            for state in incoming[1:]:
                in_candidate = domain.meet(in_candidate, state)
        else:
            # Non-entry node with no incoming edges: keep its current state.
            in_candidate = in_states[node]

        if visits[node] > config.widening_threshold:
            in_candidate = domain.widen(in_states[node], in_candidate)

        if not domain.equals(in_candidate, in_states[node]):
            in_states[node] = in_candidate

        out_candidate = domain.transfer(node, in_states[node])
        if not domain.equals(out_candidate, out_states[node]):
            out_states[node] = out_candidate
            for succ in flow_succs(node):
                worklist.add(succ)

    converged = not worklist  # drained -> True; hit the iteration cap -> False
    if not converged and raise_on_nonconvergence:
        raise FixpointDidNotConverge(
            iterations=iterations, max_iterations=max_iterations
        )

    return FixpointResult(
        in_states=in_states,
        out_states=out_states,
        iterations=iterations,
        converged=converged,
    )
