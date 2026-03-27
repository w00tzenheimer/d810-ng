from __future__ import annotations

from d810.cfg.entry_island_rescue import (
    EntryIslandRescueOption,
    build_entry_island_rescue_modification,
    build_entry_island_rescue_options,
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


class _DummyBuilder:
    @staticmethod
    def goto_redirect(*, source_block: int, target_block: int, old_target: int):
        return ("goto", int(source_block), int(target_block), int(old_target))

    @staticmethod
    def edge_redirect(*, source_block: int, target_block: int, old_target: int, via_pred: int):
        return ("edge", int(source_block), int(target_block), int(old_target), int(via_pred))


class TestBuildEntryIslandRescueOptions:
    def test_builds_block_and_pred_options_for_reachable_preds(self):
        flow_graph = _DummyFlowGraph({
            40: ((12, 14, 16), (6,)),
        })

        options = build_entry_island_rescue_options(
            40,
            lifted_entry=90,
            projected_flow_graph=flow_graph,
            reachable_blocks={12, 14},
            dispatcher_region={6},
            claimed_sources={14},
        )

        assert options == (
            EntryIslandRescueOption(source_block=40, lifted_entry=90, old_target=6),
            EntryIslandRescueOption(
                source_block=40,
                lifted_entry=90,
                old_target=6,
                via_pred=12,
            ),
        )

    def test_rejects_missing_or_noop_sources(self):
        flow_graph = _DummyFlowGraph({
            40: ((12,), (90,)),
            41: ((12,), (6, 90)),
        })

        assert build_entry_island_rescue_options(
            99,
            lifted_entry=90,
            projected_flow_graph=flow_graph,
            reachable_blocks={12},
            dispatcher_region={6},
            claimed_sources=set(),
        ) == ()
        assert build_entry_island_rescue_options(
            40,
            lifted_entry=90,
            projected_flow_graph=flow_graph,
            reachable_blocks={12},
            dispatcher_region={6},
            claimed_sources=set(),
        ) == ()
        assert build_entry_island_rescue_options(
            41,
            lifted_entry=90,
            projected_flow_graph=flow_graph,
            reachable_blocks={12},
            dispatcher_region={6},
            claimed_sources=set(),
        ) == ()


class TestBuildEntryIslandRescueModification:
    def test_builds_goto_redirect_for_source_level_option(self):
        builder = _DummyBuilder()
        option = EntryIslandRescueOption(40, 90, 6)

        assert build_entry_island_rescue_modification(option, builder=builder) == (
            "goto",
            40,
            90,
            6,
        )

    def test_builds_edge_redirect_for_pred_scoped_option(self):
        builder = _DummyBuilder()
        option = EntryIslandRescueOption(40, 90, 6, via_pred=12)

        assert build_entry_island_rescue_modification(option, builder=builder) == (
            "edge",
            40,
            90,
            6,
            12,
        )
