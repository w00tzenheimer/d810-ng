"""Live Hex-Rays regression for finite-zero-set predicate lowering."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import ida_hexrays
import idaapi
import idc

from d810.hexrays.utils.hexrays_formatters import format_minsn_t
from tests.system.runtime.conftest import gen_microcode_at_maturity


class TestFiniteZeroSetPredicateNative:
    binary_name = os.getenv("D810_FINITE_ZERO_SET_TEST_BINARY", "libobfuscated.dll")

    def test_configured_decompile_rewrites_authoritative_fixture(
        self, libobfuscated_setup, d810_state
    ):
        from d810.core.config import ProjectConfiguration

        with d810_state() as state:
            project_path = (
                Path(__file__).resolve().parents[5]
                / "src/d810/conf/eidolon_v3_const_solve.json"
            )
            project = ProjectConfiguration.from_file(project_path)
            index = state.project_manager.index(project.path.name)
            state.project_manager.update(project.path.name, project)
            state.load_project(index)
            state.start_d810()
            function_ea = idc.get_name_ea_simple("finite_zero_set_predicate32")
            decompiled = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert decompiled is not None
            rendered = "\n".join(
                idaapi.tag_remove(line.line) for line in decompiled.get_pseudocode()
            )
            assert "0x124924AF" in rendered
            assert "0x924924AF" in rendered
            assert "0xFFFFFF8F" not in rendered

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

    @pytest.mark.parametrize(
        "maturity",
        (ida_hexrays.MMAT_CALLS, ida_hexrays.MMAT_GLBOPT1),
        ids=("calls", "glbopt1"),
    )
    def test_masm_fixture_is_available_before_glbopt2(
        self, libobfuscated_setup, maturity
    ):
        from d810.optimizers.microcode.instructions.peephole.predicate_root_recovery_native import (
            FiniteZeroSetPredicateBlockRule,
        )

        function_ea = idc.get_name_ea_simple("finite_zero_set_predicate32")
        assert function_ea != idaapi.BADADDR
        mba = gen_microcode_at_maturity(function_ea, maturity)
        assert mba is not None
        rule = FiniteZeroSetPredicateBlockRule()

        assert any(
            rule.optimize(mba.get_mblock(serial))
            for serial in range(mba.qty)
            if mba.get_mblock(serial) is not None
        )
