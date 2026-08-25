"""Use-site metadata regressions for the process-global microcode AST cache."""

from __future__ import annotations

import ida_hexrays
import idautils
import pytest

from d810.core import MOP_TO_AST_CACHE
from d810.hexrays.ir.minsn_utils import minsn_to_ast
from d810.hexrays.ir.number_operand import safe_make_number
from tests.system.runtime.conftest import gen_microcode_at_maturity


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


def _setz(variable: ida_hexrays.mop_t, ea: int) -> ida_hexrays.minsn_t:
    zero = ida_hexrays.mop_t()
    assert safe_make_number(zero, 0, 8, ea)

    instruction = ida_hexrays.minsn_t(ea)
    instruction.opcode = ida_hexrays.m_setz
    instruction.l = _copy(variable)
    instruction.r = zero
    instruction.d = _copy(variable)
    instruction.d.size = 1
    return instruction


@pytest.mark.usefixtures("ida_database")
class TestMinsnToAstCacheEa:
    binary_name = "libobfuscated.dll"

    def test_cached_ast_root_rebinds_to_the_current_instruction_ea(self) -> None:
        """A register-only cache hit must not retain another function's EA.

        Nested decompilation sessions intentionally share the process-global AST
        cache. Register/constant-only expressions carry no MBA owner in their
        cache key, so equal instructions can hit one template across functions.
        """

        variable, first_ea = _first_64_bit_register()
        second_ea = first_ea + 0x100000

        MOP_TO_AST_CACHE.clear(reset_stats=True)
        first = minsn_to_ast(_setz(variable, first_ea))
        second = minsn_to_ast(_setz(variable, second_ea))

        assert first is not None
        assert second is not None
        assert first.ea == first_ea
        assert second.ea == second_ea
        assert MOP_TO_AST_CACHE.stats.hits >= 1
