"""Live regression for modular-product nonzero helper lowering."""

from __future__ import annotations

import os

import pytest

import ida_hexrays
import idaapi
import idc

from d810.hexrays.mutation import deferred_modifier as deferred_modifier_module
from d810.hexrays.mutation.block_instruction_commit import (
    HexRaysBlockInstructionCommitter,
)
from d810.hexrays.mutation.instruction_commit import NativeEpoch
from d810.hexrays.utils.hexrays_formatters import format_minsn_t
from tests.system.runtime.conftest import gen_microcode_at_maturity
from tests.system.runtime.mutation_gateway import make_mutation_gateway


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
        )

        function_ea = idc.get_name_ea_simple("modular_product_nonzero32")
        if function_ea == idaapi.BADADDR:
            pytest.skip("MASM fixture is absent from this platform build")
        mba = gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_GLBOPT2)
        assert mba is not None
        rule = ModularProductNonzeroBlockRule()
        proposals = []
        for serial in range(mba.qty):
            block = mba.get_mblock(serial)
            if block is None:
                continue
            before = tuple(format_minsn_t(ins) for ins in _instructions(block))
            candidate = rule.propose_instruction_batch(
                block,
                epoch=NativeEpoch.from_mba(mba),
            )
            if candidate is None:
                continue
            proposals.append((block, candidate, before))
        assert len(proposals) == 1, "one callback must admit one batch only"
        block, candidate, before = proposals[0]
        assert len(candidate.edits) == 1
        assert candidate.pass_id == "mba-simplify"
        assert candidate.stage_id == "modular-product-nonzero"
        assert tuple(format_minsn_t(ins) for ins in _instructions(block)) == before
        modifier = deferred_modifier_module.DeferredGraphModifier(
            mba,
            mutation_gateway=make_mutation_gateway(mba),
        )
        receipt = HexRaysBlockInstructionCommitter(
            epoch_provider=lambda _block, epoch=candidate.epoch_before: epoch,
        ).commit(block=block, candidate=candidate, modifier=modifier)
        assert receipt.committed, f"{receipt.reason}: {receipt}"
        assert receipt.applied_edit_count == 1
        rendered = []
        instruction = block.head
        while instruction is not None:
            rendered.append(format_minsn_t(instruction))
            instruction = instruction.next
        mba.verify(True)
        assert sum("call !__ctz" in line for line in rendered) == 5, "\n".join(rendered)
        assert any("setb" in line and "#0x1D.4" in line for line in rendered), "\n".join(rendered)

    def test_profile_renders_the_ctz_budget(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
    ):
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
            state.manager.configure_external_implementation_bindings({})
            # This test deliberately narrows the live rule collections to the
            # native block rule.  Do the same for the compiled bundle schedule;
            # otherwise manager scope compilation quite correctly rejects the
            # enabled constant stages whose implementations were removed here.
            state.manager.configure_constant_simplification_schedule(None)
            state.stop_d810()
            state.start_d810()
            function_ea = idc.get_name_ea_simple("modular_product_nonzero32")
            if function_ea == idaapi.BADADDR:
                pytest.skip("MASM fixture is absent from this platform build")
            cfunc = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert cfunc is not None
            code = pseudocode_to_string(cfunc.get_pseudocode())

            assert code.count("__ctz") == 5, code
            assert "< 0x1D" in code, code

    def test_failed_z3_proof_abstains_before_materialization(
        self,
        libobfuscated_setup,
        monkeypatch,
    ):
        from d810.optimizers.microcode.instructions.peephole import (
            modular_product_nonzero_native as native,
        )
        from d810.optimizers.microcode.instructions.peephole.modular_product_nonzero_native import (
            ModularProductNonzeroBlockRule,
        )

        function_ea = idc.get_name_ea_simple("modular_product_nonzero32")
        if function_ea == idaapi.BADADDR:
            pytest.skip("MASM fixture is absent from this platform build")
        mba = gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_GLBOPT2)
        assert mba is not None
        monkeypatch.setattr(
            native,
            "z3_proves_modular_product_nonzero",
            lambda *_args, **_kwargs: False,
        )
        monkeypatch.setattr(
            native,
            "_fresh_kreg",
            lambda *_args, **_kwargs: pytest.fail(
                "failed proof must not reach materialization"
            ),
        )
        rule = ModularProductNonzeroBlockRule()
        for serial in range(mba.qty):
            block = mba.get_mblock(serial)
            if block is None:
                continue
            before = tuple(format_minsn_t(ins) for ins in _instructions(block))
            assert (
                rule.propose_instruction_batch(
                    block,
                    epoch=NativeEpoch.from_mba(mba),
                )
                is None
            )
            assert tuple(format_minsn_t(ins) for ins in _instructions(block)) == before


def _instructions(block):
    instruction = block.head
    seen = set()
    while instruction is not None and id(instruction) not in seen:
        seen.add(id(instruction))
        yield instruction
        if instruction is block.tail:
            break
        instruction = instruction.next
