"""Runtime regressions for detached computed-goto island delivery."""
from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

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


def test_terminal_return_carrier_preopt_handler_records_modification(
    monkeypatch,
) -> None:
    mba = object()
    restored: list[tuple[object, int]] = []

    monkeypatch.setattr(
        island,
        "restore_terminal_return_carriers",
        lambda current_mba, function_ea: (
            restored.append((current_mba, function_ea)) or 1
        ),
    )

    decision: dict[str, object] = {"request_redo": False}

    island._restore_preopt_terminal_return_carriers(
        function_ea=0x40A560,
        mba=mba,
        decision=decision,
    )

    assert restored == [(mba, 0x40A560)]
    assert decision == {
        "request_redo": False,
        "microcode_modified": True,
        "details": {"terminal_return_carriers": 1},
    }


def test_live_resolver_cut_counterpart_routes_through_atomic_gateway(
    monkeypatch,
) -> None:
    source_ea = 0x40DACE
    target_ea = 0x40D370

    class _LiveBlock:
        def __init__(self, serial: int, *, tail=None, successors=()) -> None:
            self.serial = int(serial)
            self.tail = tail
            self._successors = tuple(int(value) for value in successors)

        def nsucc(self) -> int:
            return len(self._successors)

    source = _LiveBlock(
        7,
        tail=SimpleNamespace(ea=source_ea, opcode=ida_hexrays.m_ijmp),
    )
    target = _LiveBlock(9)
    mba = SimpleNamespace(entry_ea=0x40D200)
    evidence = SimpleNamespace(
        port=SimpleNamespace(
            delivery_mode="terminal_goto",
            source_instruction_ea=source_ea,
            endpoint_block_ea=0x40DABB,
            target_ea=target_ea,
        )
    )
    monkeypatch.setattr(
        island,
        "imported_detached_snippet_direct_boundary_evidence",
        lambda _mba: (evidence,),
    )
    monkeypatch.setattr(
        island,
        "find_unique_live_block_by_ea",
        lambda _mba, ea: source if int(ea) == source_ea else (
            target if int(ea) == target_ea else None
        ),
    )

    queued: list[tuple[int, int]] = []

    class _Modifier:
        def __init__(self, current_mba) -> None:
            assert current_mba is mba

        def queue_terminal_goto_change(
            self,
            *,
            block_serial: int,
            goto_target: int,
            **_kwargs,
        ) -> None:
            queued.append((int(block_serial), int(goto_target)))

        def apply(self, **kwargs) -> int:
            assert kwargs == {"transactional": True, "staged_atomic": True}
            return 1

    monkeypatch.setattr(island, "DeferredGraphModifier", _Modifier)

    assert island._apply_live_resolver_cut_counterparts(mba) == 1
    assert queued == [(7, 9)]
