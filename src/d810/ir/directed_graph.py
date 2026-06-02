"""Portable heterogeneous directed (cyclic-capable) graph model.

This is the pure-model base for D810's control-/state-flow graphs. A
control-flow graph (CFG) and the recovered state-transition graph are
**directed graphs that natively support cycles** -- loops are preserved as
real back-edges (``while``/``do-while``/spin-locks self-loop). Calling such a
graph a "DAG" is a category error: a DAG is *acyclic*, which implies a
topological/linear order that does not exist while back-edges are present.

To keep that distinction honest, "DAG/topological order" is modelled here as a
**derived, conditional projection** -- :func:`acyclic_view` returns an
:class:`AcyclicView` (the only place ``topo_order`` is legitimate) **only when
the graph is actually acyclic**, and ``None`` otherwise.

Design (per handoff decision, 2026-06-02): composition over inheritance.
:class:`DirectedGraph` is a structural :class:`~typing.Protocol` -- any object
exposing ``node_ids()`` + ``successors(node)`` *is* a directed graph (e.g.
``d810.ir.flowgraph.FlowGraph``). The graph algorithms are free functions over
that protocol, so they also run on raw adjacency maps via a tiny adapter.

Layering: ``d810.ir`` is the lowest layer, so the Tarjan SCC routine is
implemented here rather than imported from ``d810.analyses.control_flow``
(an upward import). The sibling copies in ``analyses.control_flow.scc`` /
``analyses.control_flow.loops`` exist for the same reason; the eventual
consolidation is for those (in the higher layer) to delegate *down* to this
canonical home.
"""
from __future__ import annotations

from d810.core.typing import Hashable, Iterable, Mapping, Protocol, runtime_checkable

__all__ = [
    "AcyclicView",
    "DirectedGraph",
    "acyclic_view",
    "adjacency",
    "back_edges",
    "has_cycles",
    "sccs",
    "tarjan_scc",
]

# A node is any hashable identifier (block serial, state value, ...). The
# graph is *heterogeneous* in that nodes/edges may carry distinct types and
# attributes in richer subtypes; the topology contract below needs only the
# identifiers and the successor relation.
NodeId = Hashable
Edge = tuple[NodeId, NodeId]


@runtime_checkable
class DirectedGraph(Protocol):
    """Structural contract for a directed (cyclic-capable) graph.

    Any object exposing these two methods *is* a ``DirectedGraph`` -- no base
    class required. ``FlowGraph`` satisfies it natively.
    """

    def node_ids(self) -> Iterable[NodeId]:
        """Yield every node identifier in the graph."""
        ...

    def successors(self, node: NodeId) -> Iterable[NodeId]:
        """Yield the direct successors of ``node`` (empty if none/unknown)."""
        ...


def adjacency(graph: DirectedGraph) -> dict[NodeId, tuple[NodeId, ...]]:
    """Snapshot ``graph`` as a successor map.

    Successors referenced by an edge but not present in ``node_ids()`` are
    added as leaf nodes (no outgoing edges), so algorithms never KeyError on a
    dangling target.
    """
    adj: dict[NodeId, tuple[NodeId, ...]] = {}
    referenced: list[NodeId] = []
    for node in graph.node_ids():
        succs = tuple(graph.successors(node))
        adj[node] = succs
        referenced.extend(succs)
    for tgt in referenced:
        adj.setdefault(tgt, ())
    return adj


def tarjan_scc(adj: Mapping[NodeId, tuple[NodeId, ...]]) -> list[frozenset[NodeId]]:
    """Tarjan strongly-connected components over an adjacency map.

    Pure-Python, generic over hashable nodes. Returns components in Tarjan's
    standard reverse-topological order (leaves first). Mirrors
    ``d810.analyses.control_flow.scc._tarjan_scc`` (which is int-specialised);
    kept here as the canonical lowest-layer copy.

    >>> tarjan_scc({0: (1,), 1: (0,)})
    [frozenset({0, 1})]
    >>> tarjan_scc({0: (1,), 1: (2,), 2: ()})
    [frozenset({2}), frozenset({1}), frozenset({0})]
    """
    if not adj:
        return []

    nodes: list[NodeId] = list(adj.keys())

    index = 0
    stack: list[NodeId] = []
    indices: dict[NodeId, int] = {}
    lowlink: dict[NodeId, int] = {}
    on_stack: set[NodeId] = set()
    out: list[frozenset[NodeId]] = []

    def strongconnect(v: NodeId) -> None:
        nonlocal index
        indices[v] = index
        lowlink[v] = index
        index += 1
        stack.append(v)
        on_stack.add(v)

        for w in adj.get(v, ()):
            if w not in indices:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in on_stack:
                lowlink[v] = min(lowlink[v], indices[w])

        if lowlink[v] == indices[v]:
            component: set[NodeId] = set()
            while stack:
                w = stack.pop()
                on_stack.discard(w)
                component.add(w)
                if w == v:
                    break
            out.append(frozenset(component))

    for n in nodes:
        if n not in indices:
            strongconnect(n)
    return out


def sccs(graph: DirectedGraph) -> tuple[frozenset[NodeId], ...]:
    """Strongly-connected components of ``graph`` (reverse-topological order)."""
    return tuple(tarjan_scc(adjacency(graph)))


def back_edges(graph: DirectedGraph) -> frozenset[Edge]:
    """Edges ``(u, v)`` where ``v`` is an ancestor of ``u`` on the DFS stack.

    These are the loop back-edges (latch -> header, and self-loops); their
    presence is exactly what makes the graph non-acyclic. The DFS visits root
    nodes in ``node_ids()`` order for determinism.
    """
    adj = adjacency(graph)
    found: set[Edge] = set()
    visited: set[NodeId] = set()
    on_stack: set[NodeId] = set()

    def dfs(start: NodeId) -> None:
        # Iterative DFS to avoid recursion limits on large CFGs. Each stack
        # frame is (node, iterator over its successors).
        work: list[tuple[NodeId, Iterable[NodeId]]] = [(start, iter(adj.get(start, ())))]
        visited.add(start)
        on_stack.add(start)
        while work:
            node, it = work[-1]
            advanced = False
            for succ in it:
                if succ in on_stack:
                    found.add((node, succ))
                elif succ not in visited:
                    visited.add(succ)
                    on_stack.add(succ)
                    work.append((succ, iter(adj.get(succ, ()))))
                    advanced = True
                    break
            if not advanced:
                on_stack.discard(node)
                work.pop()

    for n in adj:
        if n not in visited:
            dfs(n)
    return frozenset(found)


def has_cycles(graph: DirectedGraph) -> bool:
    """``True`` iff ``graph`` contains any cycle (incl. a self-loop)."""
    return bool(back_edges(graph))


class AcyclicView:
    """Topo-orderable projection of a graph, valid **only** when acyclic.

    Constructed solely via :func:`acyclic_view` (which returns ``None`` for a
    cyclic graph), so holding one is proof the graph had no back-edges. This is
    the only place a topological ("DAG") order is legitimate.
    """

    __slots__ = ("_nodes", "_adj")

    def __init__(
        self, nodes: Iterable[NodeId], adj: Mapping[NodeId, tuple[NodeId, ...]]
    ) -> None:
        self._nodes: tuple[NodeId, ...] = tuple(nodes)
        self._adj: dict[NodeId, tuple[NodeId, ...]] = dict(adj)

    def node_ids(self) -> tuple[NodeId, ...]:
        return self._nodes

    def successors(self, node: NodeId) -> tuple[NodeId, ...]:
        return self._adj.get(node, ())

    def topo_order(self) -> tuple[NodeId, ...]:
        """Kahn's algorithm; ties broken by ``node_ids()`` order (deterministic)."""
        order_index = {n: i for i, n in enumerate(self._nodes)}
        indeg: dict[NodeId, int] = {n: 0 for n in self._nodes}
        for n in self._nodes:
            for s in self._adj.get(n, ()):
                if s in indeg:
                    indeg[s] += 1
        ready = [n for n in self._nodes if indeg[n] == 0]
        result: list[NodeId] = []
        while ready:
            ready.sort(key=order_index.__getitem__)
            node = ready.pop(0)
            result.append(node)
            for s in self._adj.get(node, ()):
                if s in indeg:
                    indeg[s] -= 1
                    if indeg[s] == 0:
                        ready.append(s)
        return tuple(result)


def acyclic_view(graph: DirectedGraph) -> AcyclicView | None:
    """Return an :class:`AcyclicView` of ``graph``, or ``None`` if it is cyclic.

    There is no "DAG" of a graph with back-edges; ``None`` says so explicitly
    rather than silently producing a bogus linear order.
    """
    if has_cycles(graph):
        return None
    adj = adjacency(graph)
    return AcyclicView(adj.keys(), adj)
