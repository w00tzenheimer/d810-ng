"""Live Hex-Rays regression for finite-zero-set predicate lowering."""

from __future__ import annotations

import os

import pytest

import ida_hexrays
import idaapi
import idc

from d810.hexrays.utils.hexrays_formatters import format_minsn_t
from tests.system.runtime.conftest import gen_microcode_at_maturity


class TestFiniteZeroSetPredicateNative:
    binary_name = os.getenv("D810_FINITE_ZERO_SET_TEST_BINARY", "libobfuscated.dll")

    def test_masm_fixture_mutates_only_after_typed_and_z3_admission(self, libobfuscated_setup):
        from d810.optimizers.microcode.instructions.peephole.predicate_root_recovery_native import (
            FiniteZeroSetPredicateBlockRule,
        )

        function_ea = idc.get_name_ea_simple("finite_zero_set_predicate32")
        if function_ea == idaapi.BADADDR:
            pytest.skip("MASM fixture is absent from this platform build")
        mba = gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_GLBOPT2)
        assert mba is not None
        rule = FiniteZeroSetPredicateBlockRule()
        observed = []

        for serial in range(mba.qty):
            block = mba.get_mblock(serial)
            if block is None:
                continue
            instruction = block.head
            while instruction is not None:
                observed.append(format_minsn_t(instruction))
                instruction = instruction.next
            if not rule.optimize(block):
                continue
            rendered = []
            instruction = block.head
            while instruction is not None:
                rendered.append(format_minsn_t(instruction))
                instruction = instruction.next
            mba.verify(True)
            assert sum("setnz" in line for line in rendered) >= 2, "\n".join(rendered)
            assert any("#0x124924AF.4" in line for line in rendered), "\n".join(rendered)
            assert any("#0x924924AF.4" in line for line in rendered), "\n".join(rendered)
            return
        pytest.fail(
            "fixture did not expose a Z3-proven finite-zero-set predicate\n"
            + "\n".join(observed)
        )
