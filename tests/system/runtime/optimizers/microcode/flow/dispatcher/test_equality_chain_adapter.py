"""Runtime tests for the live equality-chain dispatcher adapter."""
from __future__ import annotations

from types import SimpleNamespace

from d810.backends.hexrays.evidence.dispatcher import equality_chain


class _LiveBlock:
    def __init__(self, serial: int, tail: object, succs: tuple[int, int]) -> None:
        self.serial = serial
        self.type = 4
        self.head = tail
        self.tail = tail
        self._succs = succs

    def nsucc(self) -> int:
        return len(self._succs)

    def succ(self, index: int) -> int:
        return self._succs[int(index)]


class _LiveMba:
    def __init__(self, blocks: dict[int, object]) -> None:
        self.blocks = blocks
        self.qty = max(blocks) + 1
        self.entry_ea = 0x401000
        self.maturity = 5

    def get_mblock(self, serial: int) -> object | None:
        return self.blocks.get(int(serial))


def _block_mop(serial: int) -> object:
    return SimpleNamespace(t=77, b=serial)


def test_live_adapter_normalizes_hexrays_numeric_opcode_and_mop_types(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        equality_chain._hexrays_bst_runtime,
        "build_opcode_map",
        lambda: {444: "m_jz"},
    )
    monkeypatch.setattr(
        equality_chain._hexrays_bst_runtime,
        "build_mop_type_map",
        lambda: {22: "mop_n", 55: "mop_S", 77: "mop_b"},
    )
    tail = SimpleNamespace(
        opcode=444,
        l=SimpleNamespace(t=55, s=SimpleNamespace(off=0x3C), size=4),
        r=SimpleNamespace(t=22, nnn_value=0x55, size=4),
        d=_block_mop(7),
        next=None,
    )
    mba = _LiveMba({2: _LiveBlock(2, tail, (3, 7))})

    dispatch_map = equality_chain.extract_state_dispatcher_map_from_hexrays_mba(
        mba,
        dispatcher_entry_block=2,
    )

    assert dispatch_map is not None
    assert dispatch_map.state_to_handler() == {0x55: 7}
    assert dispatch_map.state_var_stkoff == 0x3C
