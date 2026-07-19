from __future__ import annotations

from types import SimpleNamespace

from d810.analyses.control_flow.entry_island_rescue_discovery import (
    EntryIslandRescueSeed,
    LateEntryIslandDiagnostic,
    LateEntryIslandRescueSeed,
    collect_entry_island_rescue_seeds,
    collect_late_entry_island_diagnostics,
    collect_late_entry_island_rescue_seeds,
)


class _Block:
    def __init__(self, preds=(), succs=()):
        self.preds = tuple(preds)
        self.succs = tuple(succs)


class _FlowGraph:
    def __init__(self, blocks):
        self.blocks = blocks

    def get_block(self, serial: int):
        return self.blocks.get(int(serial))


class TestCollectEntryIslandRescueSeeds:
    def test_collects_frontier_and_lifted_entry(self, monkeypatch) -> None:
        dag = SimpleNamespace(
            edges=(
                SimpleNamespace(
                    target_entry_anchor=60,
                    ordered_path=(10, 11, 12),
                    source_anchor=SimpleNamespace(block_serial=10),
                ),
            )
        )

        monkeypatch.setattr(
            "d810.analyses.control_flow.entry_island_rescue_discovery.semantic_entry_anchors",
            lambda dag: {60, 90},
        )
        monkeypatch.setattr(
            "d810.analyses.control_flow.entry_island_rescue_discovery.incoming_edges_by_target_entry",
            lambda dag: {60: ()},
        )
        monkeypatch.setattr(
            "d810.analyses.control_flow.entry_island_rescue_discovery.lift_target_entry_to_island_entry",
            lambda target_entry, **kwargs: 90,
        )
        monkeypatch.setattr(
            "d810.analyses.control_flow.entry_island_rescue_discovery.edge_reachable_frontier",
            lambda **kwargs: 12,
        )

        assert collect_entry_island_rescue_seeds(
            dag,
            reachable_blocks={10},
            dispatcher_region={7},
            claimed_targets=set(),
        ) == (EntryIslandRescueSeed(source_block=12, lifted_entry=90),)

    def test_skips_claimed_or_unreachable_targets(self, monkeypatch) -> None:
        dag = SimpleNamespace(
            edges=(
                SimpleNamespace(
                    target_entry_anchor=60,
                    ordered_path=(10, 11, 12),
                    source_anchor=SimpleNamespace(block_serial=10),
                ),
            )
        )

        monkeypatch.setattr(
            "d810.analyses.control_flow.entry_island_rescue_discovery.semantic_entry_anchors",
            lambda dag: {60},
        )
        monkeypatch.setattr(
            "d810.analyses.control_flow.entry_island_rescue_discovery.incoming_edges_by_target_entry",
            lambda dag: {60: ()},
        )
        monkeypatch.setattr(
            "d810.analyses.control_flow.entry_island_rescue_discovery.lift_target_entry_to_island_entry",
            lambda target_entry, **kwargs: 80,
        )
        monkeypatch.setattr(
            "d810.analyses.control_flow.entry_island_rescue_discovery.edge_reachable_frontier",
            lambda **kwargs: 12,
        )

        assert collect_entry_island_rescue_seeds(
            dag,
            reachable_blocks={80},
            dispatcher_region={7},
            claimed_targets=set(),
        ) == ()
        assert collect_entry_island_rescue_seeds(
            dag,
            reachable_blocks=set(),
            dispatcher_region={7},
            claimed_targets={80},
        ) == ()


class TestCollectLateEntryIslandRescueSeeds:
    def test_collects_unreachable_successors_and_frontier(self, monkeypatch) -> None:
        dag = SimpleNamespace(
            edges=(
                SimpleNamespace(
                    target_entry_anchor=40,
                    ordered_path=(8, 9, 10),
                    source_anchor=SimpleNamespace(block_serial=8),
                ),
            )
        )
        flow_graph = _FlowGraph({40: _Block(succs=(41, 42, 7))})

        monkeypatch.setattr(
            "d810.analyses.control_flow.entry_island_rescue_discovery.edge_reachable_frontier",
            lambda **kwargs: 33,
        )

        assert collect_late_entry_island_rescue_seeds(
            dag,
            projected_flow_graph=flow_graph,
            reachable_blocks={42},
            dispatcher_region={7, 40},
        ) == (
            LateEntryIslandRescueSeed(
                source_block=33,
                lifted_entry=41,
                passthrough_block=40,
                edge_source_block=8,
            ),
        )

    def test_preserves_missing_frontier_for_diagnostics(self, monkeypatch) -> None:
        dag = SimpleNamespace(
            edges=(
                SimpleNamespace(
                    target_entry_anchor=40,
                    ordered_path=(8, 9, 10),
                    source_anchor=SimpleNamespace(block_serial=8),
                ),
            )
        )
        flow_graph = _FlowGraph({40: _Block(succs=(41,))})

        monkeypatch.setattr(
            "d810.analyses.control_flow.entry_island_rescue_discovery.edge_reachable_frontier",
            lambda **kwargs: None,
        )

        assert collect_late_entry_island_rescue_seeds(
            dag,
            projected_flow_graph=flow_graph,
            reachable_blocks=set(),
            dispatcher_region={40},
        ) == (
            LateEntryIslandRescueSeed(
                source_block=None,
                lifted_entry=41,
                passthrough_block=40,
                edge_source_block=8,
            ),
        )


class TestCollectLateEntryIslandDiagnostics:
    def test_collects_condition_chain_only_unreachable_blocks(self) -> None:
        flow_graph = _FlowGraph(
            {
                7: _Block(),
                8: _Block(),
                50: _Block(preds=(7, 8)),
                60: _Block(preds=(9,)),
            }
        )
        dispatcher = SimpleNamespace(
            _rows=(
                SimpleNamespace(lo=0x10, hi=0x1F, target=7),
                SimpleNamespace(lo=0x20, hi=0x2F, target=50),
            )
        )

        assert collect_late_entry_island_diagnostics(
            flow_graph,
            reachable_blocks=set(),
            dispatcher_region={7, 8},
            dispatcher=dispatcher,
        ) == (
            LateEntryIslandDiagnostic(
                block_serial=50,
                condition_chain_preds=(7, 8),
                dispatcher_rows=(
                    "[0x10..0x1F)->blk[7]",
                    "[0x20..0x2F)->blk[50]",
                ),
            ),
        )
