import logging
import typing
import unittest

# Added necessary imports
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_range
import ida_typeinf

from d810.optimizers.microcode.instructions.peephole.fold_const import (
    FoldPureConstantRule,
)

logging.basicConfig(level=logging.DEBUG)
LOG = logging.getLogger(__name__)


class SyntheticRotateChainFoldTests(unittest.TestCase):
    """Fold the exact micro-instruction that was shown in the decompiler output."""

    def setUp(self):
        if not ida_hexrays.init_hexrays_plugin():
            self.skipTest("Hex-Rays SDK not available")

    # -------------------------------------------------------------------------
    # Helper: build a minimal micro-block with the instruction we care about.
    # -------------------------------------------------------------------------
    def _build_micro_insn(self):
        """
        Build a single-block micro-function that contains the microcode for:

            var_B90 = add(
                (call !__ROL4__(
                    call !__ROL4__(var_B94, 4), 3) ^ 0x770BB7B8),
                0x33AC85C6)

        Return the mbl_array_t.
        """
        # Find an existing function to host the microcode for robust initialization.
        self.assertGreater(
            ida_funcs.get_func_qty(), 0, "No functions found in database to host test"
        )
        pfn = ida_funcs.get_func(ida_funcs.getn_func(0).start_ea)
        self.assertIsNotNone(pfn, "Could not get a function pointer (pfn)")

        fl = ida_hexrays.hexrays_failure_t()
        mba = ida_hexrays.create_empty_mba(pfn, fl)
        self.assertIsNotNone(mba, f"Failed to create empty mba: {fl}")

        blk = mba.get_mblock(0)
        blk.make_empty()

        tinfo_int32 = ida_typeinf.tinfo_t(ida_typeinf.BT_INT32)

        # FIX 1: Use `ida_local_types.lvar_t` to define local variables.
        lvar_b94_info = ida_local_types.lvar_t()
        lvar_b94_info.name = "var_B94_input"
        lvar_b94_info.type = tinfo_int32
        lvar_b94_info.set_user_name()

        lvar_b90_info = ida_local_types.lvar_t()
        lvar_b90_info.name = "var_B90_output"
        lvar_b90_info.type = tinfo_int32
        lvar_b90_info.set_user_name()

        # FIX 2: Correctly add variables via `mba.lvars.push_back()`.
        # The index of the new variable is its position in the list before adding it.
        var_b94_idx = mba.lvars.size()
        mba.lvars.push_back(lvar_b94_info)

        var_b90_idx = mba.lvars.size()
        mba.lvars.push_back(lvar_b90_info)

        # Create variable operands (`mop_v`) using a robust helper.
        var_b94 = ida_hexrays.mop_t()
        var_b94.make_lvar(var_b94_idx)
        var_b90 = ida_hexrays.mop_t()
        var_b90.make_lvar(var_b90_idx)

        # Constants.
        c4 = ida_hexrays.mop_t()
        c4.make_number(4, 1)
        c3 = ida_hexrays.mop_t()
        c3.make_number(3, 1)
        c77 = ida_hexrays.mop_t()
        c77.make_number(0x770BB7B8, 4)
        c33 = ida_hexrays.mop_t()
        c33.make_number(0x33AC85C6, 4)

        def make_rol_call(
            dst: ida_hexrays.mop_t,
            arg: ida_hexrays.mop_t,
            rot: ida_hexrays.mop_t,
        ) -> ida_hexrays.minsn_t:
            """Correctly constructs a `m_call` minsn_t for a helper function."""
            call_info = ida_hexrays.mcallinfo_t()
            call_info.callee = ida_idaapi.BADADDR
            call_info.cc = ida_typeinf.CM_CC_FASTCALL
            call_info.flags = ida_hexrays.FCI_HELPER
            call_info.return_type = tinfo_int32
            call_info.args.push_back(arg)
            call_info.args.push_back(rot)

            # FIX 3: Use `.start_ea` to get a valid address for the instruction.
            call_insn = ida_hexrays.minsn_t(blk.start_ea)
            call_insn.opcode = ida_hexrays.m_call

            call_insn.l.make_helper("__ROL4__")
            call_insn.r.t = ida_hexrays.mop_f
            call_insn.r.f = call_info
            call_insn.d = dst
            return call_insn

        # Use unique destinations for each intermediate result (SSA form).
        inner_call_dst = ida_hexrays.mop_t(ida_hexrays.mop_d, 0, 4)
        inner_call = make_rol_call(inner_call_dst, var_b94, c4)

        outer_call_dst = ida_hexrays.mop_t(ida_hexrays.mop_d, 1, 4)
        outer_call = make_rol_call(outer_call_dst, inner_call.d, c3)

        xor_insn = ida_hexrays.minsn_t(blk.start_ea)
        xor_insn.opcode = ida_hexrays.m_xor
        xor_insn.l = outer_call.d
        xor_insn.r = c77
        xor_insn.d = ida_hexrays.mop_t(ida_hexrays.mop_d, 2, 4)

        add_insn = ida_hexrays.minsn_t(blk.start_ea)
        add_insn.opcode = ida_hexrays.m_add
        add_insn.l = xor_insn.d
        add_insn.r = c33
        add_insn.d = var_b90

        # Chain the instructions by appending them to the block.
        blk.insert_into_block(inner_call, blk.tail)
        blk.insert_into_block(outer_call, blk.tail)
        blk.insert_into_block(xor_insn, blk.tail)
        blk.insert_into_block(add_insn, blk.tail)

        mba.mark_chains_dirty()
        mba.build_graph()
        return mba

    # -------------------------------------------------------------------------
    # Test
    # -------------------------------------------------------------------------
    def test_rotate_chain_folds(self):
        mba = self._build_micro_insn()
        LOG.debug("Initial microcode for block 0:\n%s", mba.get_mblock(0).dump())

        # Run the rule.
        rule = FoldPureConstantRule()
        changed = False
        for blk in mba.blocks:
            ins = blk.head
            while ins:
                if rule.check_and_replace(blk, ins):
                    changed = True
                ins = ins.next

        self.assertTrue(changed, "Rule did not make any changes.")

        mba.verify(True)

        # Ensure __ROL4__ calls are gone.
        for blk in mba.blocks:
            for ins in blk:
                self.assertNotEqual(
                    ins.opcode,
                    ida_hexrays.m_call,
                    f"Found unfolded __ROL4__ call after folding: {ins.dstr()}",
                )

        # Optional: dump the final block to stdout for manual inspection.
        LOG.debug("Final block after folding:\n%s", mba.get_mblock(0).dump())
