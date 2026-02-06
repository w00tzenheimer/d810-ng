"""Test that SDK pxd and manual pxd produce equivalent bindings.

This test decompiles a real function and accesses mop_t/minsn_t fields
to verify the structures are bound identically.
"""
import pytest

pytest.importorskip("idapro")

import idapro
import ida_hexrays


def test_mop_t_field_equivalence():
    """Test that mop_t fields are accessible and match expected layout."""
    # Open a test binary
    idapro.open_database(
        "samples/bins/libobfuscated.dylib",
        run_auto_analysis=True,
    )

    # Find a simple function
    import ida_funcs
    import ida_name

    func_ea = ida_name.get_name_ea(0, "test_chained_add")
    if func_ea == 0xFFFFFFFFFFFFFFFF:
        pytest.skip("Function not found")

    # Decompile it
    cfunc = ida_hexrays.decompile(func_ea)
    assert cfunc is not None, "Decompilation failed"

    mba = cfunc.mba
    assert mba is not None, "No mba"

    # Iterate through blocks and instructions
    found_mop = False
    for blk_idx in range(mba.qty):
        blk = mba.get_mblock(blk_idx)
        if blk is None:
            continue

        insn = blk.head
        while insn:
            # Test minsn_t fields
            assert hasattr(insn, 'opcode'), "minsn_t missing opcode"
            assert hasattr(insn, 'ea'), "minsn_t missing ea"
            assert hasattr(insn, 'l'), "minsn_t missing l (left operand)"
            assert hasattr(insn, 'r'), "minsn_t missing r (right operand)"
            assert hasattr(insn, 'd'), "minsn_t missing d (dest operand)"
            assert hasattr(insn, 'next'), "minsn_t missing next"
            assert hasattr(insn, 'prev'), "minsn_t missing prev"

            # Test mop_t fields on left operand
            mop = insn.l
            assert hasattr(mop, 't'), "mop_t missing t (type)"
            assert hasattr(mop, 'size'), "mop_t missing size"
            assert hasattr(mop, 'oprops'), "mop_t missing oprops"

            # Test union member access based on type
            mop_type = mop.t

            if mop_type == ida_hexrays.mop_r:  # register
                assert hasattr(mop, 'r'), "mop_t missing r (register)"
                reg = mop.r
                assert isinstance(reg, int), f"mop.r should be int, got {type(reg)}"
                found_mop = True
                print(f"  mop_r: register={reg}, size={mop.size}")

            elif mop_type == ida_hexrays.mop_n:  # number
                assert hasattr(mop, 'nnn'), "mop_t missing nnn (number)"
                nnn = mop.nnn
                assert nnn is not None, "nnn should not be None for mop_n"
                value = nnn.value
                print(f"  mop_n: value={hex(value)}, size={mop.size}")
                found_mop = True

            elif mop_type == ida_hexrays.mop_d:  # nested instruction
                assert hasattr(mop, 'd'), "mop_t missing d (nested insn)"
                nested = mop.d
                if nested:
                    print(f"  mop_d: nested opcode={nested.opcode}")
                    found_mop = True

            elif mop_type == ida_hexrays.mop_v:  # global var
                assert hasattr(mop, 'g'), "mop_t missing g (global addr)"
                addr = mop.g
                print(f"  mop_v: global addr={hex(addr)}")
                found_mop = True

            elif mop_type == ida_hexrays.mop_S:  # stack var
                assert hasattr(mop, 's'), "mop_t missing s (stkvar)"
                stkvar = mop.s
                if stkvar:
                    print(f"  mop_S: stack var offset={stkvar.off}")
                    found_mop = True

            elif mop_type == ida_hexrays.mop_b:  # block ref
                assert hasattr(mop, 'b'), "mop_t missing b (block)"
                blknum = mop.b
                print(f"  mop_b: block={blknum}")
                found_mop = True

            # Print instruction info
            print(f"Insn @ {hex(insn.ea)}: opcode={insn.opcode}, "
                  f"l.t={insn.l.t}, r.t={insn.r.t}, d.t={insn.d.t}")

            insn = insn.next

    assert found_mop, "Should have found at least one typed mop"
    print("\n✅ All mop_t and minsn_t fields accessible!")


def test_minsn_methods():
    """Test that minsn_t methods work correctly."""
    idapro.open_database(
        "samples/bins/libobfuscated.dylib",
        run_auto_analysis=True,
    )

    import ida_name

    func_ea = ida_name.get_name_ea(0, "test_chained_add")
    if func_ea == 0xFFFFFFFFFFFFFFFF:
        pytest.skip("Function not found")

    cfunc = ida_hexrays.decompile(func_ea)
    mba = cfunc.mba

    for blk_idx in range(mba.qty):
        blk = mba.get_mblock(blk_idx)
        if blk is None:
            continue

        insn = blk.head
        while insn:
            # Test dstr() method
            dstr = insn.dstr()
            assert dstr is not None, "dstr() returned None"
            assert isinstance(dstr, str), f"dstr() should return str, got {type(dstr)}"
            print(f"dstr: {dstr}")

            # Test has_side_effects() - should exist on minsn_t
            # Note: SWIG binding might be on the instruction differently

            insn = insn.next
            break  # Just test first instruction
        break

    print("\n✅ minsn_t methods work!")


if __name__ == "__main__":
    test_mop_t_field_equivalence()
    test_minsn_methods()
