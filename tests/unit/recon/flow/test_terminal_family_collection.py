from __future__ import annotations

from d810.analyses.control_flow.terminal_family_collection import (
    TerminalSourceUnreachableDiagnostic,
    collect_terminal_source_unreachable_diagnostic,
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


class TestCollectTerminalSourceUnreachableDiagnostic:
    def test_collects_pred_status_and_island(self) -> None:
        flow_graph = _FlowGraph(
            {
                10: _Block(preds=(7, 8)),
                8: _Block(preds=(12,)),
                12: _Block(preds=()),
            }
        )

        assert collect_terminal_source_unreachable_diagnostic(
            flow_graph,
            source_serial=10,
            reachable_blocks={12},
            dispatcher_region={7},
        ) == TerminalSourceUnreachableDiagnostic(
            source_block=10,
            pred_info=("blk[7]=dispatcher", "blk[8]=unreachable"),
            nearest_reachable=12,
            island_blocks=(8, 12),
        )

    def test_returns_none_when_source_missing(self) -> None:
        flow_graph = _FlowGraph({})

        assert (
            collect_terminal_source_unreachable_diagnostic(
                flow_graph,
                source_serial=10,
                reachable_blocks=set(),
                dispatcher_region=set(),
            )
            is None
        )
