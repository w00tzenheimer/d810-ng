from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

from d810.passes.fake_jump import (
    FAKE_JUMP_FIXES_METADATA_KEY,
    PAYLOAD_FAKE_JUMP_FIXES_METADATA_KEY,
    FakeJumpPredFix,
    FakeJumpStrategy,
    PayloadFakeJumpFix,
    extract_fake_jump_fixes,
    extract_payload_fake_jump_fixes,
)


@dataclass
class _Block:
    serial: int
    succs: tuple[int, ...]
    preds: tuple[int, ...] = ()

    @property
    def nsucc(self) -> int:
        return len(self.succs)


class _FlowGraph:
    def __init__(
        self,
        blocks: dict[int, _Block],
        *,
        metadata: dict[str, object],
        entry_serial: int = 0,
    ) -> None:
        self.blocks = blocks
        self.metadata = metadata
        self.entry_serial = int(entry_serial)

    def get_block(self, serial: int) -> _Block | None:
        return self.blocks.get(int(serial))

    def as_adjacency_dict(self) -> dict[int, list[int]]:
        return {serial: list(block.succs) for serial, block in self.blocks.items()}


def test_extract_fake_jump_rejects_terminal_successor_bypass() -> None:
    graph = _FlowGraph(
        {
            7: _Block(7, (26,)),
            26: _Block(26, (27, 159), (7,)),
            27: _Block(27, (30,), (26,)),
            159: _Block(159, (), (26,)),
        },
        metadata={FAKE_JUMP_FIXES_METADATA_KEY: {26: {7: 27}}},
    )

    assert extract_fake_jump_fixes(graph) == ()


def test_extract_fake_jump_keeps_nonterminal_bypass() -> None:
    graph = _FlowGraph(
        {
            7: _Block(7, (26,)),
            26: _Block(26, (27, 28), (7,)),
            27: _Block(27, (30,), (26,)),
            28: _Block(28, (30,), (26,)),
            30: _Block(30, (), (27, 28)),
        },
        metadata={FAKE_JUMP_FIXES_METADATA_KEY: {26: {7: 27}}},
    )

    assert extract_fake_jump_fixes(graph) == (
        FakeJumpPredFix(fake_block=26, pred_block=7, new_target=27),
    )


def test_extract_payload_fake_jump_rejects_terminal_successor_bypass() -> None:
    graph = _FlowGraph(
        {
            7: _Block(7, (26,)),
            26: _Block(26, (27, 159), (7,)),
            27: _Block(27, (30,), (26,)),
            159: _Block(159, (), (26,)),
        },
        metadata={
            PAYLOAD_FAKE_JUMP_FIXES_METADATA_KEY: (
                {
                    "fake_block": 26,
                    "original_target": 27,
                    "clone_redirects": ((7, 159),),
                },
            ),
        },
    )

    assert extract_payload_fake_jump_fixes(graph) == ()


def test_extract_payload_fake_jump_keeps_nonterminal_bypass() -> None:
    graph = _FlowGraph(
        {
            7: _Block(7, (26,)),
            26: _Block(26, (27, 28), (7,)),
            27: _Block(27, (30,), (26,)),
            28: _Block(28, (30,), (26,)),
            30: _Block(30, (), (27, 28)),
        },
        metadata={
            PAYLOAD_FAKE_JUMP_FIXES_METADATA_KEY: (
                {
                    "fake_block": 26,
                    "original_target": 27,
                    "clone_redirects": ((7, 28),),
                },
            ),
        },
    )

    assert extract_payload_fake_jump_fixes(graph) == (
        PayloadFakeJumpFix(
            fake_block=26,
            original_target=27,
            clone_redirects=((7, 28),),
        ),
    )


def test_fake_jump_plan_records_planner_entry_reachability() -> None:
    graph = _FlowGraph(
        {
            0: _Block(0, (1,)),
            1: _Block(1, (2,)),
            2: _Block(2, (3, 4), (1,)),
            3: _Block(3, (5,), (2,)),
            4: _Block(4, (5,), (2,)),
            5: _Block(5, (), (3, 4)),
        },
        metadata={FAKE_JUMP_FIXES_METADATA_KEY: {2: {1: 3}}},
    )
    snapshot = SimpleNamespace(flow_graph=graph)

    fragment = FakeJumpStrategy().plan(snapshot)

    assert fragment is not None
    assert fragment.metadata["planner_entry_serial"] == 0
    assert fragment.metadata["planner_entry_reachable_count"] == 6
