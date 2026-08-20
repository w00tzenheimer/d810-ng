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

    def test_helper_type_is_fresh_for_the_current_idb_lifetime(
        self, libobfuscated_setup
    ):
        """Do not retain a SWIG tinfo object across database lifetimes."""
        from d810.optimizers.microcode.instructions.peephole import (
            modular_product_nonzero_native as native,
        )

        assert not hasattr(native, "_UINT32")
        first = native._uint32_type()
        second = native._uint32_type()
        assert first is not second
        assert first.get_size() == second.get_size() == 4

    def test_masm_product_lowers_to_a_ctz_budget_and_verifies(self, libobfuscated_setup):
        from d810.optimizers.microcode.instructions.peephole.modular_product_nonzero_native import (
            ModularProductNonzeroBlockRule,
            _predicate_from_instruction,
        )
        from d810.optimizers.microcode.instructions.peephole.modular_product_nonzero import (
            recover_modular_product_nonzero,
        )

        function_ea = idc.get_name_ea_simple("modular_product_nonzero32")
        if function_ea == idaapi.BADADDR:
            pytest.skip("MASM fixture is absent from this platform build")
        mba = gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_GLBOPT2)
        assert mba is not None
        rule = ModularProductNonzeroBlockRule()
        observed = []
        for serial in range(mba.qty):
            block = mba.get_mblock(serial)
            instruction = None if block is None else block.head
            while instruction is not None:
                observed.append(f"blk{serial}: {format_minsn_t(instruction)}")
                if (
                    instruction.opcode == ida_hexrays.m_xdu
                    and instruction.l.t == ida_hexrays.mop_d
                    and instruction.l.d is not None
                ):
                    predicate = _predicate_from_instruction(instruction.l.d)
                    observed.append(f"  predicate={predicate!r}")
                    observed.append(
                        f"  recovered={recover_modular_product_nonzero(predicate)!r}"
                    )
                instruction = instruction.next
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
        pytest.fail(
            "fixture did not expose a proven modular-product predicate:\n"
            + "\n".join(observed)
        )

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
