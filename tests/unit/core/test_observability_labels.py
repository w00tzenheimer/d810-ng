"""Tests for neutral diagnostic label helpers."""
from __future__ import annotations

from types import SimpleNamespace

from d810.core.observability_labels import live_block_label, live_block_start_ea


def test_live_block_label_uses_portable_flow_graph_start_ea() -> None:
    source = SimpleNamespace(
        blocks={
            7: SimpleNamespace(start_ea=0x180001B03),
        },
    )

    assert live_block_start_ea(source, 7) == 0x180001B03
    assert live_block_label(source, 7) == "blk[7]@0x180001B03"


def test_live_block_label_uses_hexrays_mba_mblock_start_ea() -> None:
    class _Mba:
        def get_mblock(self, serial: int):
            if serial == 8:
                return SimpleNamespace(start=0x180001B17)
            return None

    source = _Mba()

    assert live_block_start_ea(source, 8) == 0x180001B17
    assert live_block_label(source, 8) == "blk[8]@0x180001B17"
