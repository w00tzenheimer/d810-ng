"""Live regression for modular-product nonzero helper lowering."""

from __future__ import annotations

import os

import pytest

import ida_hexrays
import idaapi
import idc

from d810.hexrays.utils.hexrays_formatters import format_minsn_t
from tests.system.runtime.conftest import gen_microcode_at_maturity


class TestModularProductNonzeroNative:
    binary_name = os.getenv("D810_MODULAR_PRODUCT_TEST_BINARY", "libobfuscated.dll")

    def test_masm_product_lowers_to_a_ctz_budget_and_verifies(self, libobfuscated_setup):
        from d810.optimizers.microcode.instructions.peephole.modular_product_nonzero_native import (
            ModularProductNonzeroBlockRule,
        )

        function_ea = idc.get_name_ea_simple("modular_product_nonzero32")
        if function_ea == idaapi.BADADDR:
            pytest.skip("MASM fixture is absent from this platform build")
        mba = gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_GLBOPT2)
        assert mba is not None
        rule = ModularProductNonzeroBlockRule()
        for serial in range(mba.qty):
            block = mba.get_mblock(serial)
            if block is None or not rule.optimize(block):
                continue
            rendered = []
            instruction = block.head
            while instruction is not None:
                rendered.append(format_minsn_t(instruction))
                instruction = instruction.next
            mba.verify(True)
            assert sum("call !__ctz" in line for line in rendered) == 5, "\n".join(rendered)
            assert any("setb" in line and "#0x1D.4" in line for line in rendered), "\n".join(rendered)
            return
        pytest.fail("fixture did not expose a proven modular-product predicate")

    def test_profile_renders_the_ctz_budget(self, libobfuscated_setup, d810_state, pseudocode_to_string):
        """Exercise profile routing, native mutation, and ctree rendering together."""

        with d810_state() as state:
            index = next(
                index
                for index, project in enumerate(state.project_manager.projects())
                if project.path.name == "eidolon_v3_const_solve.json"
            )
            state.load_project(index)
            state.current_ins_rules = []
            state.current_blk_rules = [
                rule
                for rule in state.current_blk_rules
                if rule.name == "ModularProductNonzeroBlockRule"
            ]
            assert len(state.current_blk_rules) == 1
            # This test deliberately narrows the live rule collections to the
            # native block rule.  Do the same for the compiled bundle schedule;
            # otherwise manager scope compilation quite correctly rejects the
            # enabled constant stages whose implementations were removed here.
            state.manager.configure_constant_simplification_schedule(None)
            state.start_d810()
            function_ea = idc.get_name_ea_simple("modular_product_nonzero32")
            if function_ea == idaapi.BADADDR:
                pytest.skip("MASM fixture is absent from this platform build")
            cfunc = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert cfunc is not None
            code = pseudocode_to_string(cfunc.get_pseudocode())

            assert code.count("__ctz") == 5, code
            assert "< 0x1D" in code, code
