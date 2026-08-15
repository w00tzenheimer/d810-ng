"""Native width-preservation regressions for constant-subtree folding."""

from __future__ import annotations

import ida_hexrays
import idautils
import pytest

from d810.hexrays.ir.number_operand import safe_make_number
from d810.hexrays.utils.hexrays_helpers import check_ins_mop_size_are_ok
from d810.optimizers.microcode.instructions.peephole.fold_constant_subtree import (
    ConstantSubtreeFoldRule,
)
from tests.system.runtime.conftest import gen_microcode_at_maturity


def _number(value: int, size: int, ea: int) -> ida_hexrays.mop_t:
    mop = ida_hexrays.mop_t()
    assert safe_make_number(mop, value, size, ea)
    return mop


def _empty() -> ida_hexrays.mop_t:
    mop = ida_hexrays.mop_t()
    mop.erase()
    return mop


def _nested(ins: ida_hexrays.minsn_t, size: int) -> ida_hexrays.mop_t:
    mop = ida_hexrays.mop_t()
    mop.create_from_insn(ins)
    mop.size = size
    return mop


def _copy(mop: ida_hexrays.mop_t) -> ida_hexrays.mop_t:
    copy = ida_hexrays.mop_t()
    copy.assign(mop)
    return copy


def _first_64_bit_register() -> tuple[ida_hexrays.mop_t, int]:
    for function_ea in idautils.Functions():
        mba = gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_GLBOPT1)
        if mba is None:
            continue
        for serial in range(mba.qty):
            block = mba.get_mblock(serial)
            if block is None:
                continue
            instruction = block.head
            while instruction is not None:
                for mop in (instruction.l, instruction.r, instruction.d):
                    if mop is not None and mop.t == ida_hexrays.mop_r and mop.size == 8:
                        return _copy(mop), int(instruction.ea)
                instruction = instruction.next
    pytest.fail("fixture database did not expose a 64-bit register operand")


@pytest.mark.usefixtures("ida_database")
class TestConstantSubtreeFoldWidths:
    binary_name = "libobfuscated.dll"

    def test_partial_fold_preserves_byte_constant_and_xdu_result_width(self) -> None:
        """``(xdu.8(reg.1) << (#A4.1-#3E.1)) ^ reg.8`` stays verifier-shaped.

        This is the live shape: the byte subtraction folds to ``#66.1`` as a
        shift amount, while the enclosing zero-extension remains an eight-byte
        value. Rebuilding either node at the outer XOR width is a semantic and
        verifier error.
        """

        variable, ea = _first_64_bit_register()

        byte_variable = _copy(variable)
        byte_variable.size = 1

        zero_extend = ida_hexrays.minsn_t(ea)
        zero_extend.opcode = ida_hexrays.m_xdu
        zero_extend.l = byte_variable
        zero_extend.r = _empty()
        zero_extend.d = _empty()
        zero_extend.d.size = 8

        byte_sub = ida_hexrays.minsn_t(ea)
        byte_sub.opcode = ida_hexrays.m_sub
        byte_sub.l = _number(0xA4, 1, ea)
        byte_sub.r = _number(0x3E, 1, ea)
        byte_sub.d = _empty()

        shift = ida_hexrays.minsn_t(ea)
        shift.opcode = ida_hexrays.m_shl
        shift.l = _nested(zero_extend, 8)
        shift.r = _nested(byte_sub, 1)
        shift.d = _empty()
        shift.d.size = 8

        original = ida_hexrays.minsn_t(ea)
        original.opcode = ida_hexrays.m_xor
        original.l = _nested(shift, 8)
        original.r = _copy(variable)
        original.d = _copy(variable)

        replacement = ConstantSubtreeFoldRule().check_and_replace(None, original)

        assert replacement is not None
        assert replacement.l.t == ida_hexrays.mop_d
        assert replacement.l.d.opcode == ida_hexrays.m_shl
        assert replacement.l.d.d.size == 8
        assert replacement.l.d.l.t == ida_hexrays.mop_d
        assert replacement.l.d.l.d.opcode == ida_hexrays.m_xdu
        assert replacement.l.d.l.d.d.size == 8
        assert replacement.l.d.r.t == ida_hexrays.mop_n
        assert replacement.l.d.r.size == 1
        assert replacement.l.d.r.nnn.value == 0x66
        assert check_ins_mop_size_are_ok(replacement)
