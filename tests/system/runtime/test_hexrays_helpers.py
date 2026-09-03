from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays
import idautils
import pytest

from d810.hexrays.utils import hexrays_helpers
from d810.hexrays.utils.hexrays_helpers import (
    check_ins_mop_size_are_ok,
    equal_bnot_mop,
    equal_mops_ignore_size,
)
from tests.system.runtime.conftest import gen_microcode_at_maturity


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


def _make_binary_ins(
    opcode: int, left_size: int, right_size: int, dest_size: int
) -> _FakeInsn:
    return _FakeInsn(
        opcode=opcode,
        l=_FakeMop(size=left_size),
        r=_FakeMop(size=right_size),
        d=_FakeMop(size=dest_size),
    )


class TestCheckInsnMopSize:
    def test_cfadd_accepts_flag_dest_size(self):
        """cfadd writes flag-sized output; source sizes may be wider."""
        ins = _make_binary_ins(
            ida_hexrays.m_cfadd, left_size=4, right_size=4, dest_size=1
        )
        assert check_ins_mop_size_are_ok(ins) is True

    def test_ofadd_accepts_flag_dest_size(self):
        """ofadd writes flag-sized output; source sizes may be wider."""
        ins = _make_binary_ins(
            ida_hexrays.m_ofadd, left_size=4, right_size=4, dest_size=1
        )
        assert check_ins_mop_size_are_ok(ins) is True

    def test_add_still_requires_matching_operand_and_dest_sizes(self):
        """Regular arithmetic instructions still require strict size agreement."""
        ins = _make_binary_ins(
            ida_hexrays.m_add, left_size=4, right_size=4, dest_size=1
        )
        assert check_ins_mop_size_are_ok(ins) is False

    def test_jnz_ignores_branch_target_dest_size(self):
        """Conditional jumps should not enforce arithmetic dest-size matching."""
        ins = _make_binary_ins(
            ida_hexrays.m_jnz, left_size=4, right_size=4, dest_size=0
        )
        assert check_ins_mop_size_are_ok(ins) is True

    def test_jnz_still_validates_nested_operands(self):
        """Jump conditions embedding invalid expressions should still fail."""
        bad_expr = _make_binary_ins(
            ida_hexrays.m_add, left_size=4, right_size=4, dest_size=1
        )
        ins = _FakeInsn(
            opcode=ida_hexrays.m_jnz,
            l=_FakeMop(size=4, t=ida_hexrays.mop_d, d=bad_expr),
            r=_FakeMop(size=4),
            d=_FakeMop(size=0),
        )
        assert check_ins_mop_size_are_ok(ins) is False

    @pytest.mark.parametrize("opcode", (ida_hexrays.m_xds, ida_hexrays.m_xdu))
    def test_extension_requires_a_strictly_wider_destination(self, opcode):
        """verify.cpp INTERR 50837: xds/xdu require l.size < d.size."""
        assert check_ins_mop_size_are_ok(
            _make_binary_ins(opcode, left_size=8, right_size=0, dest_size=8)
        ) is False
        assert check_ins_mop_size_are_ok(
            _make_binary_ins(opcode, left_size=8, right_size=0, dest_size=4)
        ) is False
        assert check_ins_mop_size_are_ok(
            _make_binary_ins(opcode, left_size=4, right_size=0, dest_size=8)
        ) is True


def _number(value: int, size: int = 4) -> ida_hexrays.mop_t:
    mop = ida_hexrays.mop_t()
    mop.make_number(value, size, 0)
    return mop


def _binary_operand(
    opcode: int, left: ida_hexrays.mop_t, right: ida_hexrays.mop_t, size: int = 4
) -> ida_hexrays.mop_t:
    """Wrap ``opcode(left, right)`` into a nested ``mop_d`` operand."""
    insn = ida_hexrays.minsn_t(0)
    insn.opcode = opcode
    insn.l = left
    insn.r = right
    insn.d = ida_hexrays.mop_t()
    insn.d.size = size
    operand = ida_hexrays.mop_t()
    operand.create_from_insn(insn)
    return operand


def _unary_operand(
    opcode: int, operand: ida_hexrays.mop_t, size: int = 4
) -> ida_hexrays.mop_t:
    insn = ida_hexrays.minsn_t(0)
    insn.opcode = opcode
    insn.l = operand
    insn.d = ida_hexrays.mop_t()
    insn.d.size = size
    wrapped = ida_hexrays.mop_t()
    wrapped.create_from_insn(insn)
    return wrapped


@pytest.mark.usefixtures("ida_database")
class TestMopEqualityIsNotMemoizedOnABucketKey:
    """Operand equality must never be answered from a lossy bucket key.

    ``mop_quick_key_ignore_size`` documents itself as a *bucketing* key that
    "may collide across non-equal operands": every ``mop_d`` collapses to
    ``d:<opcode>``.  When that key was also used to memoize the answer, the
    FIRST comparison of any two same-opcode expressions in the process decided
    every later one -- across instructions, functions, projects and tests.

    d81-jvtp: ``affine_opaque_jz_false`` cached ``m_mul == m_mul -> True`` while
    correctly folding ``(0x25C*rcx) - ((0x25C*rcx) - 0x300)``.  The next test in
    the same interpreter then cancelled ``(0xB*~ecx) - (7*(~ecx|0x70))`` to
    zero, destroying the MBA that ``FiniteZeroSetPredicateBlockRule`` recovers.
    """

    binary_name = "libobfuscated.dll"

    @staticmethod
    def _warm_hexrays() -> None:
        """Build microcode once; bare ``mop_t`` allocation needs a live mba."""
        for function_ea in idautils.Functions():
            if (
                gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_GLBOPT1)
                is not None
            ):
                return
        pytest.fail("fixture database produced no microcode")

    def test_equal_pair_does_not_decide_a_different_same_opcode_pair(
        self, monkeypatch
    ):
        self._warm_hexrays()
        # Force the documented lossy fallback key regardless of build flavour.
        monkeypatch.setattr(hexrays_helpers, "cy_hash_mop", None)

        equal_left = _binary_operand(
            ida_hexrays.m_mul, _number(0x25C), _number(3)
        )
        equal_right = _binary_operand(
            ida_hexrays.m_mul, _number(0x25C), _number(3)
        )
        assert equal_mops_ignore_size(equal_left, equal_right)

        different_left = _binary_operand(
            ida_hexrays.m_mul, _number(0xB), _number(7)
        )
        different_right = _binary_operand(
            ida_hexrays.m_mul, _number(0x12), _number(0x70)
        )
        assert not equal_mops_ignore_size(different_left, different_right)

    def test_bnot_pair_does_not_decide_a_different_same_opcode_pair(
        self, monkeypatch
    ):
        self._warm_hexrays()
        monkeypatch.setattr(hexrays_helpers, "cy_hash_mop", None)

        inner = _binary_operand(ida_hexrays.m_mul, _number(1), _number(2))
        assert equal_bnot_mop(_unary_operand(ida_hexrays.m_bnot, inner), inner)

        other = _binary_operand(ida_hexrays.m_mul, _number(3), _number(4))
        unrelated = _binary_operand(ida_hexrays.m_mul, _number(5), _number(6))
        assert not equal_bnot_mop(
            _unary_operand(ida_hexrays.m_bnot, other), unrelated
        )
