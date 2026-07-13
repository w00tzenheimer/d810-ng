"""Runtime regressions for detached computed-goto island delivery."""
from __future__ import annotations

from d810.optimizers.microcode.flow.jumps import (
    materialized_computed_goto_island as island,
)


class _Instruction:
    def __init__(self, ea: int) -> None:
        self.ea = ea
        self.next: _Instruction | None = None


class _Block:
    def __init__(self, start: int, instruction_eas: tuple[int, ...]) -> None:
        self.start = start
        instructions = tuple(_Instruction(ea) for ea in instruction_eas)
        for current, following in zip(instructions, instructions[1:]):
            current.next = following
        self.head = instructions[0]
        self.tail = instructions[-1]


class _MBA:
    def __init__(self, block: _Block) -> None:
        self.entry_ea = 0x1000
        self.qty = 1
        self._block = block

    def get_mblock(self, serial: int) -> _Block:
        assert serial == 0
        return self._block


def test_detached_planner_uses_first_surviving_instruction_as_live_target(
    monkeypatch,
) -> None:
    captured: dict[str, frozenset[int]] = {}

    def capture_planner(_transfers, **kwargs):
        captured.update(kwargs)
        return ()

    monkeypatch.setattr(island, "plan_detached_snippet_routes", capture_planner)
    monkeypatch.setattr(
        island,
        "imported_detached_snippet_target_eas",
        lambda _mba: (),
    )

    island._materialize_missing_detached_snippets(
        _MBA(_Block(0x1020, (0x1028, 0x1030))),
        (),
    )

    assert captured["live_eas"] == frozenset({0x1020, 0x1028, 0x1030})
    assert captured["live_target_eas"] == frozenset({0x1020, 0x1028})
