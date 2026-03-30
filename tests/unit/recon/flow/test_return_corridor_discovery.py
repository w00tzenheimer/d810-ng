from __future__ import annotations

from types import SimpleNamespace

from d810.recon.flow.linearized_state_dag import SemanticEdgeKind
from d810.recon.flow.return_corridor_discovery import collect_common_return_corridor


class _DummyFlowGraph:
    def __init__(self, blocks: dict[int, tuple[tuple[int, ...], tuple[int, ...]]]):
        self._blocks = {
            serial: SimpleNamespace(
                preds=preds,
                succs=succs,
                nsucc=len(succs),
            )
            for serial, (preds, succs) in blocks.items()
        }

    def get_block(self, serial: int):
        return self._blocks.get(int(serial))

    def predecessors(self, serial: int):
        block = self.get_block(serial)
        return () if block is None else block.preds


def _edge(kind: SemanticEdgeKind, ordered_path: tuple[int, ...]):
    return SimpleNamespace(kind=kind, ordered_path=ordered_path)


class TestReturnCorridorDiscovery:
    def test_intersects_return_paths_and_backtracks_oneway_preds(self) -> None:
        dag = SimpleNamespace(
            edges=(
                _edge(SemanticEdgeKind.CONDITIONAL_RETURN, (20, 30, 40)),
                _edge(SemanticEdgeKind.CONDITIONAL_RETURN, (25, 30, 40)),
            )
        )
        flow_graph = _DummyFlowGraph(
            {
                10: ((), (15,)),
                15: ((10,), (30,)),
                20: ((30,), (30,)),
                25: ((35,), (30,)),
                30: ((15, 20, 25), (40,)),
                35: ((), (25,)),
                40: ((30,), ()),
            }
        )

        corridor = collect_common_return_corridor(
            dag,
            flow_graph,
            bst_node_blocks={2},
            dispatcher_serial=6,
        )

        assert corridor == {25, 30, 35, 40}

    def test_ignores_non_return_edges_and_bst_dispatcher_preds(self) -> None:
        dag = SimpleNamespace(
            edges=(
                _edge(SemanticEdgeKind.TRANSITION, (10, 20)),
                _edge(SemanticEdgeKind.CONDITIONAL_RETURN, (30, 40)),
                _edge(SemanticEdgeKind.CONDITIONAL_RETURN, (35, 40)),
            )
        )
        flow_graph = _DummyFlowGraph(
            {
                2: ((), (30,)),
                6: ((), (30,)),
                30: ((2, 6), (40,)),
                35: ((), (40,)),
                40: ((30, 35), ()),
            }
        )

        corridor = collect_common_return_corridor(
            dag,
            flow_graph,
            bst_node_blocks={2},
            dispatcher_serial=6,
        )

        assert corridor == {35, 40}
