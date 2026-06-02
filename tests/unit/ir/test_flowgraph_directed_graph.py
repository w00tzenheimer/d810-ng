"""FlowGraph IS-A DirectedGraph (structurally): cycle/acyclic-view delegation.

Pins the P1 re-base from the DAG->CFG handoff: ``FlowGraph`` exposes the
portable ``DirectedGraph`` surface (``node_ids``/``successors``) and the
cycle/acyclic-view ops, delegating to ``d810.ir.directed_graph``. Purely
additive -- no change to existing FlowGraph behavior.
"""
from __future__ import annotations

from d810.ir.directed_graph import AcyclicView, DirectedGraph
from d810.ir.flowgraph import BlockSnapshot, FlowGraph


def _fg(adj: dict[int, tuple[int, ...]], entry: int = 0) -> FlowGraph:
    """Build a minimal FlowGraph from a successor map (topology only)."""
    preds: dict[int, list[int]] = {s: [] for s in adj}
    for s, succs in adj.items():
        for t in succs:
            preds.setdefault(t, []).append(s)
    blocks = {
        s: BlockSnapshot(
            serial=s,
            block_type=3,
            succs=tuple(succs),
            preds=tuple(preds.get(s, ())),
            flags=0,
            start_ea=0x1000 + s * 0x100,
            insn_snapshots=(),
        )
        for s, succs in adj.items()
    }
    return FlowGraph(blocks=blocks, entry_serial=entry, func_ea=0x1000)


ACYCLIC_FG = _fg({0: (1, 2), 1: (3,), 2: (3,), 3: ()})
CYCLIC_FG = _fg({0: (1,), 1: (2,), 2: (1, 3), 3: ()})


class TestFlowGraphIsDirectedGraph:
    def test_flowgraph_satisfies_protocol(self) -> None:
        assert isinstance(ACYCLIC_FG, DirectedGraph)

    def test_node_ids_are_block_serials(self) -> None:
        assert set(ACYCLIC_FG.node_ids()) == {0, 1, 2, 3}

    def test_successors_match_blocks(self) -> None:
        assert tuple(ACYCLIC_FG.successors(0)) == (1, 2)


class TestFlowGraphCycleOps:
    def test_acyclic_flowgraph_has_no_cycles(self) -> None:
        assert ACYCLIC_FG.has_cycles() is False

    def test_cyclic_flowgraph_has_cycles(self) -> None:
        assert CYCLIC_FG.has_cycles() is True

    def test_back_edges(self) -> None:
        assert ACYCLIC_FG.back_edges() == frozenset()
        assert CYCLIC_FG.back_edges() == frozenset({(2, 1)})

    def test_sccs_group_the_loop(self) -> None:
        assert frozenset({1, 2}) in CYCLIC_FG.sccs()

    def test_acyclic_view_none_when_cyclic(self) -> None:
        assert CYCLIC_FG.acyclic_view() is None

    def test_acyclic_view_present_when_acyclic(self) -> None:
        view = ACYCLIC_FG.acyclic_view()
        assert isinstance(view, AcyclicView)
        order = view.topo_order()
        pos = {n: i for i, n in enumerate(order)}
        assert pos[0] < pos[1] < pos[3]
        assert pos[0] < pos[2] < pos[3]
