"""Contract tests for GlobalConstantInliner pointer filtering.

These tests simulate the exact regression shape seen in the field:
an inlined 8-byte global value looks like a PE RVA (imagebase-relative
address) and must NOT be folded into a raw immediate.
"""

from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.optimizers.microcode.flow import global_const_inline as gci


class _FakeMop:
    def __init__(self, *, t: int, size: int = 0, g: int = 0):
        self.t = t
        self.size = size
        self.g = g
        self.number_calls: list[tuple[int, int]] = []
        self.erase_calls = 0

    def make_number(self, value: int, size: int) -> None:
        self.number_calls.append((value, size))

    def erase(self) -> None:
        self.erase_calls += 1


class _FakeInsn:
    def __init__(self, *, opcode: int, l: _FakeMop, r: _FakeMop, d: _FakeMop):
        self.opcode = opcode
        self.l = l
        self.r = r
        self.d = d


def test_try_inline_globals_skips_rebased_rva_pointer(monkeypatch):
    """Do not inline constants that resolve to imagebase-relative pointers."""
    rule = gci.GlobalConstantInliner()

    insn = _FakeInsn(
        opcode=ida_hexrays.m_mov,
        l=_FakeMop(t=ida_hexrays.mop_v, size=8, g=0x1805AEB00),
        r=_FakeMop(t=ida_hexrays.mop_z, size=0),
        d=_FakeMop(t=ida_hexrays.mop_z, size=8),
    )

    monkeypatch.setattr(gci.ida_bytes, "get_flags", lambda ea: 0)
    monkeypatch.setattr(gci.ida_bytes, "is_code", lambda flags: False)
    monkeypatch.setattr(gci, "_is_constant_global", lambda ea: True)
    monkeypatch.setattr(gci, "_read_constant_value", lambda ea, size: 0x5AF54E)

    imagebase = 0x180000000

    def _fake_getseg(ea: int):
        # Simulate that only imagebase + value maps to a real segment.
        if ea == imagebase + 0x5AF54E:
            return object()
        return None

    monkeypatch.setattr(gci.ida_segment, "getseg", _fake_getseg)
    monkeypatch.setattr(gci.idaapi, "get_imagebase", lambda: imagebase)

    patched = rule._try_inline_globals(SimpleNamespace(), insn)

    assert patched == 0
    assert insn.opcode == ida_hexrays.m_mov
    assert insn.l.number_calls == []
    assert insn.r.erase_calls == 0


def test_try_inline_globals_inlines_non_pointer_constant(monkeypatch):
    """Inline normal constants that do not look pointer-like."""
    rule = gci.GlobalConstantInliner()

    insn = _FakeInsn(
        opcode=ida_hexrays.m_ldx,
        l=_FakeMop(t=ida_hexrays.mop_n, size=8),
        r=_FakeMop(t=ida_hexrays.mop_v, size=8, g=0x1805AEB08),
        d=_FakeMop(t=ida_hexrays.mop_z, size=8),
    )

    monkeypatch.setattr(gci.ida_bytes, "get_flags", lambda ea: 0)
    monkeypatch.setattr(gci.ida_bytes, "is_code", lambda flags: False)
    monkeypatch.setattr(gci, "_is_constant_global", lambda ea: True)
    monkeypatch.setattr(gci, "_read_constant_value", lambda ea, size: 0x1337)
    monkeypatch.setattr(gci.ida_segment, "getseg", lambda ea: None)
    monkeypatch.setattr(gci.idaapi, "get_imagebase", lambda: 0x180000000)

    patched = rule._try_inline_globals(SimpleNamespace(), insn)

    assert patched == 1
    assert insn.opcode == ida_hexrays.m_mov
    assert insn.l.number_calls == [(0x1337, 8)]
    assert insn.r.erase_calls == 1


def test_try_inline_globals_skips_badaddr_sentinel(monkeypatch):
    """Do not inline all-ones BADADDR sentinels into call/data flows."""
    rule = gci.GlobalConstantInliner()

    insn = _FakeInsn(
        opcode=ida_hexrays.m_mov,
        l=_FakeMop(t=ida_hexrays.mop_v, size=8, g=0x1805AEB10),
        r=_FakeMop(t=ida_hexrays.mop_z, size=0),
        d=_FakeMop(t=ida_hexrays.mop_z, size=8),
    )

    monkeypatch.setattr(gci.ida_bytes, "get_flags", lambda ea: 0)
    monkeypatch.setattr(gci.ida_bytes, "is_code", lambda flags: False)
    monkeypatch.setattr(gci, "_is_constant_global", lambda ea: True)
    monkeypatch.setattr(gci, "_read_constant_value", lambda ea, size: 0xFFFFFFFFFFFFFFFF)
    monkeypatch.setattr(gci.ida_segment, "getseg", lambda ea: None)
    monkeypatch.setattr(gci.idaapi, "get_imagebase", lambda: 0x180000000)
    monkeypatch.setattr(gci.idaapi, "BADADDR", 0xFFFFFFFFFFFFFFFF)

    patched = rule._try_inline_globals(SimpleNamespace(), insn)

    assert patched == 0
    assert insn.opcode == ida_hexrays.m_mov
    assert insn.l.number_calls == []
    assert insn.r.erase_calls == 0
