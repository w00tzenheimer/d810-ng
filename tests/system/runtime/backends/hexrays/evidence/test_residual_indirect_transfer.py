"""Runtime tests for the local residual indirect-transfer snippet recognizer."""
from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.backends.hexrays.evidence import residual_indirect_transfer as residual_module
from d810.backends.hexrays.evidence.residual_indirect_transfer import (
    recognize_residual_indirect_transfer,
)


PTR = 10
LOADED = 11
ESI = 6


@pytest.fixture(autouse=True)
def _deterministic_pointer_cells(monkeypatch) -> None:
    values = {0x2000: 0x2000, 0x3000: 0x3000}
    monkeypatch.setattr(
        residual_module,
        "_read_pointer_cell",
        lambda ea: values.get(int(ea)),
    )


class _Block:
    def __init__(self, instructions, succs, start, end):
        self._succs = tuple(succs)
        self.start = start
        self.end = end
        self.head = instructions[0] if instructions else None
        self.tail = instructions[-1] if instructions else None
        for current, following in zip(instructions, instructions[1:]):
            current.next = following
        if instructions:
            instructions[-1].next = None

    def nsucc(self):
        return len(self._succs)

    def succ(self, index):
        return self._succs[index]


def _reg(number):
    return SimpleNamespace(t=ida_hexrays.mop_r, r=number)


def _stack(offset):
    return SimpleNamespace(t=ida_hexrays.mop_S, s=SimpleNamespace(off=offset))


def _number(value):
    return SimpleNamespace(t=ida_hexrays.mop_n, nnn=SimpleNamespace(value=value))


def _global(ea):
    return SimpleNamespace(t=ida_hexrays.mop_v, g=ea)


def _insn(opcode, ea, *, l=None, r=None, d=None):
    return SimpleNamespace(opcode=opcode, ea=ea, l=l, r=r, d=d, next=None)


def _mba(blocks):
    return SimpleNamespace(
        qty=len(blocks),
        get_mblock=lambda serial: blocks.get(int(serial)),
    )


def _two_arm_snippet(*, fallthrough_global=0x3000, direct_taken_merge=False):
    branch = _insn(
        ida_hexrays.m_jz,
        0x110,
        l=_reg(3) if direct_taken_merge else _stack(0x80),
        r=_number(0),
        d=SimpleNamespace(b=3 if direct_taken_merge else 1),
    )
    return _mba(
        ({
            0: _Block(
                [_insn(ida_hexrays.m_mov, 0x100, l=_global(0x2000), d=_reg(PTR)), branch],
                [2, 3] if direct_taken_merge else [2, 1],
                0x100,
                0x111,
            ),
            2: _Block(
                [_insn(ida_hexrays.m_mov, 0x130, l=_global(fallthrough_global), d=_reg(PTR))],
                [3],
                0x130,
                0x131,
            ),
            3: _Block(
                [
                    _insn(ida_hexrays.m_ldx, 0x140, r=_reg(PTR), d=_reg(LOADED)),
                    _insn(ida_hexrays.m_add, 0x141, l=_reg(LOADED), r=_reg(ESI), d=_reg(LOADED)),
                    _insn(ida_hexrays.m_ijmp, 0x142, l=_reg(LOADED)),
                ],
                [],
                0x140,
                0x145,
            ),
        } if direct_taken_merge else {
            0: _Block(
                [_insn(ida_hexrays.m_mov, 0x100, l=_global(0x2000), d=_reg(PTR)), branch],
                [2, 1],
                0x100,
                0x111,
            ),
            1: _Block([], [3], 0x120, 0x121),
            2: _Block(
                [_insn(ida_hexrays.m_mov, 0x130, l=_global(fallthrough_global), d=_reg(PTR))],
                [3],
                0x130,
                0x131,
            ),
            3: _Block(
                [
                    _insn(ida_hexrays.m_ldx, 0x140, r=_reg(PTR), d=_reg(LOADED)),
                    _insn(ida_hexrays.m_add, 0x141, l=_reg(LOADED), r=_reg(ESI), d=_reg(LOADED)),
                    _insn(ida_hexrays.m_ijmp, 0x142, l=_reg(LOADED)),
                ],
                [],
                0x140,
                0x145,
            ),
        })
    )


def test_recognizes_two_arm_residual_transfer_and_native_patch_range():
    result = recognize_residual_indirect_transfer(
        _two_arm_snippet(),
        {ESI: 0x1000},
        0x1000,
        0x5000,
    )

    assert result is not None
    assert result.proof.true_target_ea == 0x3000
    assert result.proof.false_target_ea == 0x4000
    assert result.conditional_branch_ea == 0x110
    assert result.terminal_indirect_transfer_ea == 0x142
    assert result.terminal_indirect_transfer_end_ea == 0x145


def test_abstains_when_fallthrough_global_is_not_constant():
    result = recognize_residual_indirect_transfer(
        _two_arm_snippet(fallthrough_global=0x2000),
        {ESI: 0x1000},
        0x1000,
        0x5000,
    )

    assert result is None


def test_recognizes_register_selector_when_taken_arm_is_the_merge_block():
    result = recognize_residual_indirect_transfer(
        _two_arm_snippet(direct_taken_merge=True),
        {ESI: 0x1000},
        0x1000,
        0x5000,
    )

    assert result is not None
    assert result.proof.selector_register == 3
    assert result.proof.selector_stack_offset is None
