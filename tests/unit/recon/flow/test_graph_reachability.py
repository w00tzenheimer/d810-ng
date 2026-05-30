from __future__ import annotations

from d810.analyses.control_flow.graph_reachability import (
    collect_dispatcher_predecessors,
    collect_residual_dispatcher_predecessors,
    compute_reachable_blocks,
    edge_reachable_frontier,
    graph_reaches_block,
    pick_deepest_rescue_frontier,
)


class _DummyBlock:
    def __init__(self, succs: tuple[int, ...], preds: tuple[int, ...] = ()):
        self.succs = succs
        self.preds = preds


class _DummyFlowGraph:
    def __init__(self, mapping: dict[int, tuple[tuple[int, ...], tuple[int, ...]]]):
        self._mapping = {
            int(k): (
                tuple(int(v) for v in succs),
                tuple(int(v) for v in preds),
            )
            for k, (succs, preds) in mapping.items()
        }

    def get_block(self, serial: int):
        item = self._mapping.get(int(serial))
        if item is None:
            return None
        succs, preds = item
        return _DummyBlock(succs, preds)

    def successors(self, serial: int):
        item = self._mapping.get(int(serial))
        return () if item is None else item[0]


class TestComputeReachableBlocks:
    def test_walks_successors_from_start(self):
        fg = _DummyFlowGraph({
            10: ((11, 12), ()),
            11: ((14,), (10,)),
            12: ((), (10,)),
            14: ((), (11,)),
        })
        assert compute_reachable_blocks(fg, start_serial=10) == {10, 11, 12, 14}

    def test_missing_start_returns_none(self):
        fg = _DummyFlowGraph({})
        assert compute_reachable_blocks(fg, start_serial=10) is None


class TestDispatcherPredecessors:
    def test_collect_dispatcher_predecessors_skips_dispatcher_and_bst(self):
        fg = _DummyFlowGraph({
            6: ((), (6, 8, 9, 12)),
        })
        assert collect_dispatcher_predecessors(
            fg,
            6,
            bst_node_blocks={9},
        ) == (8, 12)

    def test_collect_residual_dispatcher_predecessors_filters_unreachable(self):
        fg = _DummyFlowGraph({
            0: ((8,), ()),
            8: ((6,), (0,)),
            6: ((), (8, 12)),
            12: ((6,), ()),
        })
        assert collect_residual_dispatcher_predecessors(
            fg,
            6,
            bst_node_blocks=set(),
            reachable_from_serial=0,
        ) == (8,)


class TestReachabilityHelpers:
    def test_edge_reachable_frontier_skips_dispatcher_region(self):
        assert edge_reachable_frontier(
            ordered_path=(6, 9, 14, 15),
            source_block=9,
            reachable_blocks={6, 9, 14},
            dispatcher_region={6, 9},
        ) == 14

    def test_graph_reaches_block_detects_reachable_target(self):
        fg = _DummyFlowGraph({
            10: ((11,), ()),
            11: ((12,), (10,)),
            12: ((), (11,)),
        })
        assert graph_reaches_block(fg, source_block=10, target_block=12)
        assert not graph_reaches_block(fg, source_block=12, target_block=10)

    def test_pick_deepest_rescue_frontier_chooses_non_dominated_candidate(self):
        fg = _DummyFlowGraph({
            20: ((30,), ()),
            30: ((40,), (20,)),
            40: ((), (30,)),
        })
        assert pick_deepest_rescue_frontier(fg, (20, 30, 40)) == 40
