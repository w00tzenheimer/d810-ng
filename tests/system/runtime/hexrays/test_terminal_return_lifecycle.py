from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.hexrays.mutation import terminal_return_lifecycle
from d810.hexrays.mutation.deferred_modifier import (
    canonicalize_explicit_return_to_stop_edge,
)


class _Vector(list[int]):
    def push_back(self, value: int) -> None:
        self.append(int(value))


class _Instruction:
    def __init__(self, opcode: int) -> None:
        self.opcode = int(opcode)


class _Block:
    def __init__(
        self,
        serial: int,
        *,
        block_type: int,
        tail: _Instruction | None = None,
        succs: tuple[int, ...] = (),
        preds: tuple[int, ...] = (),
    ) -> None:
        self.serial = int(serial)
        self.type = int(block_type)
        self.tail = tail
        self.succset = _Vector(succs)
        self.predset = _Vector(preds)
        self.dirty = 0
        self.mba = None

    def remove_from_block(self, instruction: _Instruction) -> None:
        assert instruction is self.tail
        self.tail = None

    def mark_lists_dirty(self) -> None:
        self.dirty += 1


class _Mba:
    def __init__(self, blocks: tuple[_Block, ...]) -> None:
        self.blocks = blocks
        self.qty = len(blocks)
        self.chains_dirty = 0
        for block in blocks:
            block.mba = self

    def get_mblock(self, serial: int) -> _Block:
        return self.blocks[int(serial)]

    def mark_chains_dirty(self) -> None:
        self.chains_dirty += 1


def _canonicalize_imported_terminal_returns(
    mba: _Mba,
    return_widths: tuple[int, ...],
) -> int:
    return sum(
        int(canonicalize_explicit_return_to_stop_edge(block, stop))
        for block, stop in terminal_return_lifecycle.imported_terminal_return_edges(
            mba,
            return_widths,
        )
    )


def test_scalar_return_register_uses_active_abi(monkeypatch) -> None:
    location = SimpleNamespace(
        is_reg1=lambda: True,
        reg1=lambda: 7,
        regoff=lambda: 2,
    )
    details = SimpleNamespace(
        rettype=None,
        retloc=location,
        set_cc=lambda _cc: None,
    )
    monkeypatch.setattr(
        terminal_return_lifecycle.ida_typeinf,
        "func_type_data_t",
        lambda: details,
    )
    monkeypatch.setattr(
        terminal_return_lifecycle.ida_typeinf,
        "tinfo_t",
        lambda declaration: int(declaration),
    )
    monkeypatch.setattr(
        terminal_return_lifecycle.ida_typeinf,
        "calc_retloc",
        lambda candidate: candidate is details,
    )
    monkeypatch.setattr(
        terminal_return_lifecycle.ida_ida,
        "inf_get_callcnv",
        lambda: 112,
    )
    monkeypatch.setattr(
        terminal_return_lifecycle.ida_hexrays,
        "reg2mreg",
        lambda register: 100 + int(register),
    )

    return_mreg = terminal_return_lifecycle.scalar_return_mreg(8)

    assert return_mreg == 109


def test_return_register_protection_has_a_bounded_lifetime(monkeypatch) -> None:
    calls: list[tuple[str, int, int]] = []
    mba = SimpleNamespace(
        nodel_memory=SimpleNamespace(
            add=lambda register, width: calls.append(
                ("add", int(register), int(width))
            )
            or True,
            sub=lambda register, width: calls.append(
                ("sub", int(register), int(width))
            )
            or True,
        )
    )
    monkeypatch.setattr(
        terminal_return_lifecycle,
        "scalar_return_mreg",
        lambda width: 24 if int(width) == 8 else None,
    )

    assert terminal_return_lifecycle.protect_scalar_return_register(mba, 8)
    assert terminal_return_lifecycle.release_scalar_return_register(mba, 8)
    assert calls == [("add", 24, 8), ("sub", 24, 8)]


def test_canonicalizes_explicit_return_to_stop_edge(monkeypatch) -> None:
    monkeypatch.setattr(
        terminal_return_lifecycle,
        "scalar_return_mreg",
        lambda width: 24 if int(width) == 8 else None,
    )
    entry = _Block(0, block_type=ida_hexrays.BLT_1WAY, succs=(1,))
    terminal = _Block(
        1,
        block_type=ida_hexrays.BLT_0WAY,
        tail=_Instruction(ida_hexrays.m_ret),
        preds=(0,),
    )
    stop = _Block(2, block_type=ida_hexrays.BLT_STOP)
    mba = _Mba((entry, terminal, stop))

    assert _canonicalize_imported_terminal_returns(
        mba,
        (8,),
    ) == 1
    assert terminal.tail is None
    assert terminal.type == int(ida_hexrays.BLT_1WAY)
    assert tuple(terminal.succset) == (2,)
    assert tuple(stop.predset) == (1,)
    assert terminal.dirty == 1
    assert stop.dirty == 1
    assert mba.chains_dirty == 1


def test_canonicalizes_return_already_routed_to_stop(monkeypatch) -> None:
    monkeypatch.setattr(
        terminal_return_lifecycle,
        "scalar_return_mreg",
        lambda width: 24 if int(width) == 8 else None,
    )
    entry = _Block(0, block_type=ida_hexrays.BLT_1WAY, succs=(1,))
    terminal = _Block(
        1,
        block_type=ida_hexrays.BLT_1WAY,
        tail=_Instruction(ida_hexrays.m_ret),
        succs=(2,),
        preds=(0,),
    )
    stop = _Block(2, block_type=ida_hexrays.BLT_STOP, preds=(1,))
    mba = _Mba((entry, terminal, stop))

    assert _canonicalize_imported_terminal_returns(
        mba,
        (8,),
    ) == 1
    assert terminal.tail is None
    assert tuple(terminal.succset) == (2,)
    assert tuple(stop.predset) == (1,)
    assert terminal.dirty == 1
    assert stop.dirty == 1
    assert mba.chains_dirty == 1


def test_canonicalization_abstains_without_one_supported_width(monkeypatch) -> None:
    monkeypatch.setattr(
        terminal_return_lifecycle,
        "scalar_return_mreg",
        lambda width: 24 if int(width) == 8 else None,
    )
    terminal = _Block(
        0,
        block_type=ida_hexrays.BLT_0WAY,
        tail=_Instruction(ida_hexrays.m_ret),
    )
    stop = _Block(1, block_type=ida_hexrays.BLT_STOP)
    mba = _Mba((terminal, stop))

    assert _canonicalize_imported_terminal_returns(
        mba,
        (),
    ) == 0
    assert terminal.tail is not None
    assert _canonicalize_imported_terminal_returns(
        mba,
        (4, 8),
    ) == 0
    assert terminal.tail is not None
