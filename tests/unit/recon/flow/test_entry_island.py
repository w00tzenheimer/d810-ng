from __future__ import annotations

from types import SimpleNamespace

from d810.analyses.control_flow.entry_island import lift_target_entry_to_island_entry


def _edge(source_block: int):
    return SimpleNamespace(source_anchor=SimpleNamespace(block_serial=source_block))


class TestLiftTargetEntryToIslandEntry:
    def test_lifts_through_unique_unreachable_semantic_parent(self):
        assert (
            lift_target_entry_to_island_entry(
                40,
                incoming_by_target_entry={
                    40: (_edge(30),),
                    30: (_edge(20),),
                },
                semantic_entry_anchors={20, 30, 40},
                reachable_blocks={10},
                dispatcher_region={6},
            )
            == 20
        )

    def test_stops_when_parent_is_reachable_or_ambiguous(self):
        assert (
            lift_target_entry_to_island_entry(
                40,
                incoming_by_target_entry={
                    40: (_edge(30), _edge(32)),
                    30: (_edge(20),),
                },
                semantic_entry_anchors={20, 30, 32, 40},
                reachable_blocks={20},
                dispatcher_region={6},
            )
            == 40
        )
