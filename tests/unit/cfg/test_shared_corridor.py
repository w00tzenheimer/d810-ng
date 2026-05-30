from __future__ import annotations

from d810.analyses.control_flow.shared_corridor import (
    first_boundary_index,
    first_shared_block_index,
    is_backward_same_corridor_target,
    is_shared_block,
    resolve_old_target,
)


class _DummyBlock:
    def __init__(self, preds: tuple[int, ...], succs: tuple[int, ...]):
        self.preds = preds
        self.succs = succs
        self.npred = len(preds)
        self.nsucc = len(succs)


class _DummyFlowGraph:
    def __init__(self, mapping: dict[int, tuple[tuple[int, ...], tuple[int, ...]]]):
        self._mapping = {
            int(k): _DummyBlock(tuple(int(v) for v in preds), tuple(int(v) for v in succs))
            for k, (preds, succs) in mapping.items()
        }

    def get_block(self, serial: int):
        return self._mapping.get(int(serial))


class TestResolveOldTarget:
    def test_prefers_next_block_on_ordered_path(self):
        flow_graph = _DummyFlowGraph({
            14: ((12,), (6, 16)),
        })
        assert resolve_old_target(flow_graph, 14, (12, 14, 16)) == 16

    def test_falls_back_to_single_successor(self):
        flow_graph = _DummyFlowGraph({
            14: ((12,), (6,)),
        })
        assert resolve_old_target(flow_graph, 14, (12, 20)) == 6


class TestSharedCorridorQueries:
    def test_is_shared_block_checks_suffix_and_indegree(self):
        flow_graph = _DummyFlowGraph({
            14: ((12, 13), (16,)),
            20: ((14,), (22,)),
        })
        assert is_shared_block(flow_graph, 14, shared_suffix_blocks=set())
        assert is_shared_block(flow_graph, 20, shared_suffix_blocks={20})
        assert not is_shared_block(flow_graph, 20, shared_suffix_blocks=set())

    def test_first_shared_block_index_skips_dispatcher_region(self):
        flow_graph = _DummyFlowGraph({
            6: ((1,), (14,)),
            14: ((12, 13), (16,)),
            16: ((14,), (18,)),
        })
        assert (
            first_shared_block_index(
                flow_graph,
                (6, 14, 16),
                start_index=0,
                shared_suffix_blocks=set(),
                dispatcher_region={6},
            )
            == 1
        )

    def test_first_boundary_index_finds_dispatcher_or_shared_frontier(self):
        flow_graph = _DummyFlowGraph({
            14: ((12,), (16,)),
            16: ((14, 15), (18,)),
            18: ((16,), (20,)),
        })
        assert (
            first_boundary_index(
                flow_graph,
                (14, 16, 18),
                start_index=0,
                shared_suffix_blocks=set(),
                dispatcher_region=set(),
            )
            == 1
        )

    def test_backward_same_corridor_target_detects_backward_retarget(self):
        assert is_backward_same_corridor_target(
            (10, 14, 16, 20),
            rewrite_block=16,
            target_entry=14,
        )
        assert not is_backward_same_corridor_target(
            (10, 14, 16, 20),
            rewrite_block=14,
            target_entry=20,
        )
