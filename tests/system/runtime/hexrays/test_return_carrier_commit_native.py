"""Exercise the carrier evidence and committer with native Hex-Rays objects."""

import ida_hexrays
import pytest
from dataclasses import replace

from d810.hexrays.hooks.glbopt_diagnostics import apply_return_const_corruption_cleanup
from d810.hexrays.mutation.return_carrier_corruption import (
    find_droppable_return_const_corruptions,
    snapshot_return_reg_consumption,
)
from tests.system.runtime.conftest import gen_microcode_at_maturity, get_func_ea


class TestReturnCarrierNativeCommit:
    binary_name = "libobfuscated.dll"

    @pytest.mark.ida_required
    def test_native_evidence_rechecks_and_commits_a_severed_definition(
        self, libobfuscated_setup
    ):
        mba = gen_microcode_at_maturity(
            get_func_ea("test_cst_simplification"), ida_hexrays.MMAT_GLBOPT1
        )
        assert mba is not None
        mba.build_graph()
        entry = mba.get_mblock(0)
        target_block = mba.get_mblock(1)
        assert 1 in set(entry.succset)
        rax = ida_hexrays.reg2mreg(0)
        # Synthetic instructions live only in this disposable native MBA.
        # They model the before/after severance; no input file or IDB is edited.
        carrier = ida_hexrays.minsn_t(int(mba.entry_ea) + 0x100000)
        carrier.opcode = ida_hexrays.m_mov
        carrier.l.make_stkvar(mba, 0)
        carrier.l.size = 8
        carrier.d.make_reg(rax, 8)
        entry.insert_into_block(carrier, entry.tail)

        target_ea = int(mba.entry_ea) + 0x100010
        target = ida_hexrays.minsn_t(target_ea)
        target.opcode = ida_hexrays.m_mov
        target.l.make_number(0xB5, 1)
        target.d.make_reg(rax, 1)
        target.d.valnum = 151
        target_block.insert_into_block(target, None)

        consumer = ida_hexrays.minsn_t(target_ea + 1)
        consumer.opcode = ida_hexrays.m_mov
        consumer.l.make_reg(rax, 1)
        consumer.l.valnum = 151
        consumer.d.make_reg(rax + 8, 1)
        target_block.insert_into_block(consumer, target)
        prefold = snapshot_return_reg_consumption(mba)
        assert target_ea in [
            definition.ea for definition in prefold.consumed_definitions
        ]
        target_block.remove_from_block(consumer)

        assert (
            find_droppable_return_const_corruptions(
                mba, prefold_snapshot=frozenset({target_ea})
            )
            == []
        ), "a bare EA set must not authenticate pre-fold consumption"

        assert (
            find_droppable_return_const_corruptions(
                mba,
                prefold_snapshot=replace(prefold, function_ea=int(mba.entry_ea) + 1),
            )
            == []
        )
        other_mba = gen_microcode_at_maturity(
            get_func_ea("test_cst_simplification"), ida_hexrays.MMAT_GLBOPT1
        )
        assert (
            find_droppable_return_const_corruptions(other_mba, prefold_snapshot=prefold)
            == []
        )

        sites = find_droppable_return_const_corruptions(mba, prefold_snapshot=prefold)
        assert len([site for site in sites if site.insn_ea == target_ea]) == 1
        assert apply_return_const_corruption_cleanup(mba, prefold_snapshot=prefold) == 1
        assert target.opcode == ida_hexrays.m_nop
        assert apply_return_const_corruption_cleanup(mba, prefold_snapshot=prefold) == 0
