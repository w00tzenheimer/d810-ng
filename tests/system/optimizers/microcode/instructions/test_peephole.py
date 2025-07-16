import logging
import unittest

from d810.optimizers.microcode.instructions.peephole.fold_const import (
    FoldPureConstantRule,
)

import ida_hexrays
import ida_idaapi
import ida_range
import ida_typeinf

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
        Build a single-block micro-function that contains only the instruction:

            add(
                (call !__ROL4__(
                    call !__ROL4__(var_B94, 4), 3) ^ 0x770BB7B8),
                0x33AC85C6,
                var_B90)

        Return the mbl_array_t.
        """
        # Create a dummy mbl_array_t (1 block).
        mbrgs = ida_hexrays.mba_ranges_t()
        rg = ida_range.range_t(0x180008FF4, 0x180009010)
        mbrgs.ranges.push_back(rg)
        fl = ida_hexrays.hexrays_failure_t()
        mba = ida_hexrays.create_empty_mba(mbrgs, fl)
        self.assertIsNotNone(mba, f"Failed to create empty mba: {fl}")
        blk = mba.insert_block((mba.qty - 1) or 0)

        # Dummy variables.
        var_b94 = ida_hexrays.mop_t(ida_hexrays.mop_r, 0xB94, 4)
        var_b90 = ida_hexrays.mop_t(ida_hexrays.mop_r, 0xB90, 4)

        # Constants.
        c4 = ida_hexrays.mop_t(ida_hexrays.mop_n, 4)
        c3 = ida_hexrays.mop_t(ida_hexrays.mop_n, 3)
        c77 = ida_hexrays.mop_t(ida_hexrays.mop_n, 0x770BB7B8)
        c33 = ida_hexrays.mop_t(ida_hexrays.mop_n, 0x33AC85C6)

        # Helper: build a __ROL4__ instruction.
        def make_rol_call(
            arg: ida_hexrays.mop_t, rot: ida_hexrays.mop_t
        ) -> ida_hexrays.minsn_t:
            call_info = ida_hexrays.mcallinfo_t()
            call_info.cc = ida_typeinf.CM_CC_FASTCALL
            call_info.callee = ida_idaapi.BADADDR
            call_info.solid_args = 2
            call_info.role = ida_hexrays.ROLE_UNK
            call_info.flags = (
                ida_hexrays.FCI_SPLOK | ida_hexrays.FCI_FINAL | ida_hexrays.FCI_PROP
            )
            call_info.return_type = ida_typeinf.tinfo_t()

            call_insn = ida_hexrays.minsn_t(ida_hexrays.m_call)
            call_insn.l.make_helper("__ROL4__")
            call_insn.l.d.f = call_info
            call_insn.l.d.size = 4
            call_insn.l.a[0] = arg
            call_insn.l.a[1] = rot
            call_insn.d = ida_hexrays.mop_t(ida_hexrays.mop_d, 0, 4)
            return call_insn

        # Build the call chain.
        inner_call = make_rol_call(var_b94, c4)
        outer_call = make_rol_call(inner_call.d, c3)

        # xor with 0x770BB7B8
        xor_insn = ida_hexrays.minsn_t(ida_hexrays.m_xor)
        xor_insn.l = outer_call.d
        xor_insn.r = c77
        xor_insn.d = ida_hexrays.mop_t(ida_hexrays.mop_d, 2, 4)

        # final add
        add_insn = ida_hexrays.minsn_t(ida_hexrays.m_add)
        add_insn.l = xor_insn.d
        add_insn.r = c33
        add_insn.d = var_b90

        # Chain the instructions.
        blk.insert_into_block(inner_call, None)
        blk.insert_into_block(outer_call, None)
        blk.insert_into_block(xor_insn, None)
        blk.insert_into_block(add_insn, None)

        mba.mark_chains_dirty()
        mba.build_graph()
        return mba

    # -------------------------------------------------------------------------
    # Test
    # -------------------------------------------------------------------------
    def test_rotate_chain_folds(self):
        mba = self._build_micro_insn()

        # Run the rule.
        rule = FoldPureConstantRule()
        for blk in mba.blocks:
            ins = blk.head
            while ins:
                rule.check_and_replace(blk, ins)
                ins = ins.next

        mba.verify(True)

        # Ensure __ROL4__ calls are gone.
        for blk in mba.blocks:
            for ins in blk:
                self.assertNotEqual(
                    ins.opcode,
                    ida_hexrays.m_call,
                    "Found unfolded __ROL4__ call after folding.",
                )

        # Optional: dump the final block to stdout for manual inspection.
        LOG.debug("Final block after folding:\n%s", mba.get_mblock(0).dump())
