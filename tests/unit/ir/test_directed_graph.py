"""Tests for the portable DirectedGraph protocol + cycle/acyclic-view ops.

The handoff (2026-06-02-dag-to-cfg-rename-flowgraph-base) requires modelling
the recovered state-transition graph as a *heterogeneous directed cyclic
graph* (a CFG), with "DAG" demoted to a derived, conditional projection that
exists **only when the graph is actually acyclic**. These tests pin that
contract:

* ``has_cycles`` / ``back_edges`` / ``sccs`` detect real cycles (incl. self
  loops), never falsely linearizing a graph with back-edges.
* ``acyclic_view`` returns a topo-orderable view **only** for acyclic graphs,
  and ``None`` otherwise -- so ``topo_order`` is unreachable on a cyclic graph.
"""
from __future__ import annotations

from collections.abc import Iterable

from d810.ir.directed_graph import (
    AcyclicView,
    DirectedGraph,
    acyclic_view,
    back_edges,
    has_cycles,
    sccs,
)


class _DictGraph:
    """Minimal DirectedGraph backed by a successor map (for testing)."""

    def __init__(self, adj: dict[int, tuple[int, ...]]) -> None:
        self._adj = adj

    def node_ids(self) -> Iterable[int]:
        return tuple(self._adj.keys())

    def successors(self, node: int) -> Iterable[int]:
        return self._adj.get(node, ())


LINEAR = _DictGraph({0: (1,), 1: (2,), 2: ()})
DIAMOND = _DictGraph({0: (1, 2), 1: (3,), 2: (3,), 3: ()})
SELF_LOOP = _DictGraph({0: (1,), 1: (1, 2), 2: ()})
TWO_CYCLE = _DictGraph({0: (1,), 1: (2,), 2: (1, 3), 3: ()})
GIANT_SCC = _DictGraph({0: (1,), 1: (2,), 2: (3,), 3: (2, 4), 4: (1, 2, 5), 5: ()})
EMPTY = _DictGraph({})


class TestHasCycles:
    def test_empty_graph_is_acyclic(self) -> None:
        assert has_cycles(EMPTY) is False

    def test_linear_chain_is_acyclic(self) -> None:
        assert has_cycles(LINEAR) is False

    def test_diamond_is_acyclic(self) -> None:
        assert has_cycles(DIAMOND) is False

    def test_self_loop_is_cyclic(self) -> None:
        assert has_cycles(SELF_LOOP) is True

    def test_two_block_cycle_is_cyclic(self) -> None:
        assert has_cycles(TWO_CYCLE) is True

    def test_giant_scc_is_cyclic(self) -> None:
        assert has_cycles(GIANT_SCC) is True


class TestBackEdges:
    def test_linear_has_no_back_edges(self) -> None:
        assert back_edges(LINEAR) == frozenset()

    def test_diamond_has_no_back_edges(self) -> None:
        # The re-convergence edge (2->3) is a forward/cross edge, NOT a back
        # edge: it does not point to a DFS ancestor.
        assert back_edges(DIAMOND) == frozenset()

    def test_self_loop_back_edge(self) -> None:
        assert back_edges(SELF_LOOP) == frozenset({(1, 1)})

    def test_two_cycle_back_edge_is_the_latch(self) -> None:
        # Only the latch edge (2->1, target is an ancestor) is a back edge.
        assert back_edges(TWO_CYCLE) == frozenset({(2, 1)})

    def test_giant_scc_back_edges(self) -> None:
        be = back_edges(GIANT_SCC)
        assert (3, 2) in be
        assert (4, 1) in be
        assert (4, 2) in be
        # Forward exit edge is not a back edge.
        assert (4, 5) not in be


class TestSccs:
    def test_linear_all_trivial(self) -> None:
        comps = sccs(LINEAR)
        assert all(len(c) == 1 for c in comps)
        assert {frozenset({0}), frozenset({1}), frozenset({2})} == set(comps)

    def test_two_cycle_groups_loop(self) -> None:
        comps = sccs(TWO_CYCLE)
        assert frozenset({1, 2}) in comps
        assert frozenset({0}) in comps
        assert frozenset({3}) in comps

    def test_giant_scc_one_big_component(self) -> None:
        comps = sccs(GIANT_SCC)
        assert frozenset({1, 2, 3, 4}) in comps
        # 0 and 5 are trivial singletons outside the cycle.
        assert frozenset({0}) in comps
        assert frozenset({5}) in comps


class TestAcyclicView:
    def test_cyclic_graph_has_no_acyclic_view(self) -> None:
        assert acyclic_view(TWO_CYCLE) is None
        assert acyclic_view(SELF_LOOP) is None
        assert acyclic_view(GIANT_SCC) is None

    def test_acyclic_graph_yields_view(self) -> None:
        view = acyclic_view(LINEAR)
        assert view is not None
        assert isinstance(view, AcyclicView)

    def test_empty_graph_yields_view(self) -> None:
        view = acyclic_view(EMPTY)
        assert view is not None
        assert view.topo_order() == ()

    def test_topo_order_respects_linear_edges(self) -> None:
        view = acyclic_view(LINEAR)
        assert view is not None
        assert view.topo_order() == (0, 1, 2)

    def test_topo_order_respects_diamond_precedence(self) -> None:
        view = acyclic_view(DIAMOND)
        assert view is not None
        order = view.topo_order()
        pos = {n: i for i, n in enumerate(order)}
        assert set(order) == {0, 1, 2, 3}
        # Every edge u->v must place u before v.
        for u, succs in {0: (1, 2), 1: (3,), 2: (3,), 3: ()}.items():
            for v in succs:
                assert pos[u] < pos[v]
        assert order[0] == 0
        assert order[-1] == 3

    def test_view_satisfies_directed_graph_protocol(self) -> None:
        view = acyclic_view(DIAMOND)
        assert view is not None
        assert isinstance(view, DirectedGraph)
        assert set(view.node_ids()) == {0, 1, 2, 3}
        assert tuple(view.successors(0)) == (1, 2)


class TestProtocolConformance:
    def test_dict_graph_is_directed_graph(self) -> None:
        assert isinstance(LINEAR, DirectedGraph)

    def test_referenced_but_unlisted_successor_treated_as_leaf(self) -> None:
        # blk 1 -> blk 5 where 5 is not a key: algorithms must not crash and
        # must treat 5 as a reachable leaf node.
        g = _DictGraph({0: (1,), 1: (5,)})
        assert has_cycles(g) is False
        view = acyclic_view(g)
        assert view is not None
        assert 5 in set(view.topo_order())
