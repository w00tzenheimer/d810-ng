"""Native Hex-Rays construction checks for rotate-idiom recovery.

The structural matcher is deliberately tested without IDA.  This test covers
the boundary that cannot be faked: Hex-Rays must accept the value-producing
``__ROL8__`` helper form returned by ``mba_t.create_helper_call``.
"""

from __future__ import annotations

import pytest

import ida_hexrays
import idautils
import idaapi
import idc

from d810.hexrays.utils.hexrays_helpers import dup_mop
from d810.hexrays.utils.hexrays_formatters import format_minsn_t
from tests.system.runtime.conftest import gen_microcode_at_maturity


def _find_64_bit_value_and_destination(mba):
    for block_serial in range(mba.qty):
        block = mba.get_mblock(block_serial)
        if block is None:
            continue
        instruction = block.head
        while instruction is not None:
            if (
                instruction.l is not None
                and instruction.d is not None
                and instruction.l.size == 8
                and instruction.d.size == 8
                and instruction.d.t != ida_hexrays.mop_z
            ):
                return block, instruction, dup_mop(instruction.l), dup_mop(instruction.d)
            instruction = instruction.next
    pytest.fail("the fixture database did not expose a usable 64-bit microcode value")


def _find_fixture_mba_with_64_bit_value():
    for function_ea in idautils.Functions():
        mba = gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_GLBOPT2)
        if mba is None:
            continue
        try:
            return mba, _find_64_bit_value_and_destination(mba)
        except pytest.fail.Exception:
            continue
    pytest.fail("fixture database has no usable 64-bit microcode value")


class TestRotateIdiomRecoveryNative:
    binary_name = "libobfuscated.dll"

    def test_make_rol8_helper_call_uses_native_value_producing_form(self, libobfuscated_setup):
        from d810.optimizers.microcode.instructions.peephole.rotate_idiom_recovery_native import (
            make_rol8_helper_call,
        )

        mba, (block, instruction, base, output) = _find_fixture_mba_with_64_bit_value()

        replacement = make_rol8_helper_call(
            block,
            ea=instruction.ea,
            base=base,
            rotation=31,
            output=output,
        )

        assert replacement is not None
        assert replacement.opcode == ida_hexrays.m_mov
        assert replacement.d.size == 8
        assert replacement.l.t == ida_hexrays.mop_d
        call = replacement.l.d
        assert call.opcode == ida_hexrays.m_call
        assert call.l.t == ida_hexrays.mop_h
        assert call.l.helper == "__ROL8__"
        rendered = format_minsn_t(replacement)
        assert "call !__ROL8__" in rendered
        assert "#0x1F.1" in rendered
        instruction.swap(replacement)
        block.mark_lists_dirty()
        mba.verify(True)

    def test_native_rule_matches_both_masm_murmur_shapes(self, libobfuscated_setup):
        from d810.optimizers.microcode.instructions.peephole.rotate_idiom_recovery_native import (
            RotateIdiomRecoveryBlockRule,
            _expression_from_mop,
        )
        from d810.optimizers.microcode.instructions.peephole.rotate_idiom_recovery import (
            match_rol64_idiom,
        )

        function_ea = idc.get_name_ea_simple("Eidolon_ComputeTwoQwordBufferHash")
        assert function_ea != idaapi.BADADDR
        mba = gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_GLBOPT2)
        assert mba is not None
        rule = RotateIdiomRecoveryBlockRule()
        candidates = []
        or_expressions = []

        def collect_or_expressions(mop):
            if mop is None or mop.t != ida_hexrays.mop_d or mop.d is None:
                return
            if mop.d.opcode == ida_hexrays.m_or:
                or_expressions.append(_expression_from_mop(mop))
            collect_or_expressions(mop.d.l)
            collect_or_expressions(mop.d.r)

        for block_serial in range(mba.qty):
            block = mba.get_mblock(block_serial)
            if block is None:
                continue
            instruction = block.head
            while instruction is not None:
                candidates.append(format_minsn_t(instruction))
                collect_or_expressions(instruction.l)
                collect_or_expressions(instruction.r)
                instruction = instruction.next

        assert len(or_expressions) == 2, "\n".join(candidates)
        assert all(match_rol64_idiom(expression) is not None for expression in or_expressions), or_expressions
        # Formatting is not enough: mutate and verify the live MBA. This is
        # the exact helper-lowering boundary used by the optblock callback.
        for block_serial in range(mba.qty):
            block = mba.get_mblock(block_serial)
            if block is None:
                continue
            if rule.optimize(block):
                rendered = []
                instruction = block.head
                while instruction is not None:
                    rendered.append(format_minsn_t(instruction))
                    instruction = instruction.next
                try:
                    mba.verify(True)
                except RuntimeError as error:
                    pytest.fail(f"MBA verification failed: {error}\n" + "\n".join(rendered))
                assert sum("call !__ROL8__" in line for line in rendered) == 2
                # GLBOPT2 may revisit a block after a reported mutation. A
                # value lift is terminal for this MBA/site; revisiting it must
                # never emit another helper call or keep the decompiler busy.
                assert rule.optimize(block) == 0
                return
        pytest.fail("the native Murmur fixture did not expose a replaceable instruction")

    def test_nonmatching_nested_values_do_not_allocate_kregs(
        self,
        libobfuscated_setup,
        monkeypatch,
    ):
        """A recursive scan must not perturb the MBA unless it will rewrite."""

        from d810.optimizers.microcode.instructions.peephole import (
            rotate_idiom_recovery_native as native,
        )

        function_ea = idc.get_name_ea_simple("Eidolon_ComputeTwoQwordBufferHash")
        mba = gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_GLBOPT2)
        assert mba is not None
        block, instruction, _, _ = _find_64_bit_value_and_destination(mba)

        left = ida_hexrays.mop_t()
        left.make_number(0x1234, 8, instruction.ea)
        right = ida_hexrays.mop_t()
        right.make_number(0x5678, 8, instruction.ea)
        nested = ida_hexrays.minsn_t(instruction.ea)
        nested.opcode = ida_hexrays.m_add
        nested.l = left
        nested.r = right
        nonmatching_value = ida_hexrays.mop_t()
        nonmatching_value.create_from_insn(nested)

        def unexpected_allocation(*_args, **_kwargs):
            pytest.fail("nonmatching value tree allocated a kreg")

        monkeypatch.setattr(native, "_fresh_kreg_output", unexpected_allocation)
        _, helpers = native._recover_nested_value_mop(
            block,
            ea=instruction.ea,
            mop=nonmatching_value,
        )
        assert helpers == ()

    def test_eidolon_profile_installs_rotate_rule(self, libobfuscated_setup, d810_state):
        with d810_state() as state:
            index = next(
                index
                for index, project in enumerate(state.project_manager.projects())
                if project.path.name == "eidolon_v3_const_solve.json"
            )
            state.load_project(index)
            assert "RotateIdiomRecoveryBlockRule" in {
                rule.name for rule in state.current_blk_rules
            }
            state.start_d810()
            function_ea = idc.get_name_ea_simple("Eidolon_ComputeTwoQwordBufferHash")
            report = state.manager.get_effective_execution_report(function_ea)
            assert any(
                decision.stage_id == "rotate-idiom-recovery" and decision.active
                for decision in report.decisions
            ), report

    def test_masm_fixture_renders_two_nested_rol8_calls(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
    ):
        """Prove the real hook, helper lowering, and ctree renderer together.

        The production Eidolon profile intentionally retains its much broader
        solver portfolio.  This fixture isolates the new value-only rule so a
        failure is attributable to rotate lowering rather than an unrelated
        solver rewrite in a synthetic MASM body.
        """

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
                if rule.name == "RotateIdiomRecoveryBlockRule"
            ]
            assert len(state.current_blk_rules) == 1
            state.start_d810()

            function_ea = idc.get_name_ea_simple("Eidolon_ComputeTwoQwordBufferHash")
            assert function_ea != idaapi.BADADDR
            cfunc = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert cfunc is not None
            code = pseudocode_to_string(cfunc.get_pseudocode())

            assert code.count("__ROL8__") == 2, code
            assert len(
                state.manager.stats.cfg_rule_usages["RotateIdiomRecoveryBlockRule"]
            ) >= 1
