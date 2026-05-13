"""Tests for pure MBL_KEEP target selection."""
from __future__ import annotations

from types import SimpleNamespace

from d810.cfg.mbl_keep_selection import select_terminal_byte_keep_targets


def _obs(kind: str, *, payload: dict, fact_id: str = "fact", source_ea=None):
    return SimpleNamespace(
        kind=kind,
        payload=payload,
        fact_id=fact_id,
        source_ea=source_ea,
    )


def test_selects_terminal_tail_memory_and_guard_facts() -> None:
    view = SimpleNamespace(
        active_observations=(
            _obs(
                "TerminalByteEmitterFact",
                fact_id="byte2",
                source_ea="0x180015005",
                payload={
                    "corridor_role": "terminal_tail",
                    "byte_index": "2",
                    "block_serial": "118",
                    "block_ea": "0x180014f07",
                    "emitter_role": "memory_store",
                },
            ),
            _obs(
                "TerminalByteEmitterFact",
                fact_id="guard0",
                payload={
                    "corridor_role": "terminal_tail",
                    "byte_index": 0,
                    "block_serial": 93,
                    "block_ea": 0x180014987,
                    "emitter_role": "guard_only",
                },
            ),
        )
    )

    targets = select_terminal_byte_keep_targets(view)

    assert [(t.fact_id, t.byte_index, t.block_serial) for t in targets] == [
        ("byte2", 2, 118),
        ("guard0", 0, 93),
    ]
    assert targets[0].block_ea == 0x180014F07
    assert targets[0].source_ea == 0x180015005


def test_ignores_non_terminal_and_non_byte_facts() -> None:
    view = SimpleNamespace(
        active_observations=(
            _obs(
                "TerminalByteEmitterFact",
                payload={
                    "corridor_role": "non_terminal_byte_emitter",
                    "byte_index": 2,
                    "block_serial": 66,
                    "block_ea": 0x180014366,
                },
            ),
            _obs(
                "StateWriteAnchorFact",
                payload={"corridor_role": "terminal_tail"},
            ),
        )
    )

    assert select_terminal_byte_keep_targets(view) == ()
