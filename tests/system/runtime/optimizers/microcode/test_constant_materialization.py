from __future__ import annotations

import importlib
import sys
from types import SimpleNamespace

import pytest


class _Mop:
    def __init__(self) -> None:
        self.t = 0
        self.size = 0
        self.value: int | None = None

    def make_number(self, value: int, size: int) -> None:
        self.t = 1
        self.size = size
        self.value = value

    def erase(self) -> None:
        self.t = 0
        self.size = 0
        self.value = None

    def assign(self, other: "_Mop") -> None:
        self.t = other.t
        self.size = other.size
        self.value = other.value


class _Insn:
    def __init__(self, ea: int) -> None:
        self.ea = ea
        self.opcode = 0
        self.l = _Mop()
        self.r = _Mop()
        self.d = _Mop()


def _load_materializer(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setitem(
        sys.modules,
        "ida_hexrays",
        SimpleNamespace(
            mop_t=_Mop,
            minsn_t=_Insn,
            mop_z=0,
            mop_n=1,
            mop_r=2,
            mop_l=3,
            mop_S=4,
            mop_v=5,
            m_ldc=10,
            m_mov=11,
        ),
    )
    module_name = "d810.optimizers.microcode.constant_materialization"
    monkeypatch.delitem(sys.modules, module_name, raising=False)
    return importlib.import_module(module_name)


def test_operand_materializer_masks_value_to_width(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    materializer = _load_materializer(monkeypatch)
    operand = _Mop()

    materializer.replace_operand_with_immediate(operand, -1, 2)

    assert operand.t == 1
    assert operand.size == 2
    assert operand.value == 0xFFFF


def test_ldc_materializer_preserves_legal_destination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    materializer = _load_materializer(monkeypatch)
    original = _Insn(0x401000)
    original.d.t = 2
    original.d.size = 4

    replacement = materializer.make_ldc_replacement(original, 0x12345678, 4)

    assert replacement.ea == 0x401000
    assert replacement.opcode == 10
    assert replacement.l.value == 0x12345678
    assert replacement.l.size == 4
    assert replacement.r.t == 0
    assert replacement.d.t == 2
    assert replacement.d.size == 4


def test_move_materializer_erases_memory_address_operand(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    materializer = _load_materializer(monkeypatch)
    instruction = _Insn(0x401000)
    instruction.opcode = 99
    instruction.r.t = 5
    instruction.r.size = 8

    materializer.rewrite_load_as_immediate_move(instruction, 0x42, 1)

    assert instruction.opcode == 11
    assert instruction.l.value == 0x42
    assert instruction.l.size == 1
    assert instruction.r.t == 0
