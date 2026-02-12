from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.hexrays.hexrays_helpers import check_ins_mop_size_are_ok


@dataclass
class _FakeMop:
    size: int
    t: int = ida_hexrays.mop_n
    d: object | None = None


@dataclass
class _FakeInsn:
    opcode: int
    l: _FakeMop
    r: _FakeMop
    d: _FakeMop


def _make_binary_ins(opcode: int, left_size: int, right_size: int, dest_size: int) -> _FakeInsn:
    return _FakeInsn(
        opcode=opcode,
        l=_FakeMop(size=left_size),
        r=_FakeMop(size=right_size),
        d=_FakeMop(size=dest_size),
    )


class TestCheckInsnMopSize:
    def test_cfadd_accepts_flag_dest_size(self):
        """cfadd writes flag-sized output; source sizes may be wider."""
        ins = _make_binary_ins(ida_hexrays.m_cfadd, left_size=4, right_size=4, dest_size=1)
        assert check_ins_mop_size_are_ok(ins) is True

    def test_ofadd_accepts_flag_dest_size(self):
        """ofadd writes flag-sized output; source sizes may be wider."""
        ins = _make_binary_ins(ida_hexrays.m_ofadd, left_size=4, right_size=4, dest_size=1)
        assert check_ins_mop_size_are_ok(ins) is True

    def test_add_still_requires_matching_operand_and_dest_sizes(self):
        """Regular arithmetic instructions still require strict size agreement."""
        ins = _make_binary_ins(ida_hexrays.m_add, left_size=4, right_size=4, dest_size=1)
        assert check_ins_mop_size_are_ok(ins) is False
