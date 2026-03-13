#!/usr/bin/env python3
"""
Simple test script to verify def-use integration is working.

This script can be run manually in IDA to test the enhanced def-use resolution.
"""

import ida_hexrays
import idaapi
import idc

from d810.evaluator.hexrays_microcode.emulator import (
    MicroCodeEnvironment,
    MicroCodeInterpreter,
)


def find_test_functions():
    """Find available test functions."""
    test_functions = []
    prefixes = ["abc_f6_", "approov_", "constant_", "arithmetic_", "control_"]
    
    # Get all functions
    for i in range(idaapi.get_func_qty()):
        func = idaapi.getn_func(i)
        if func is not None:
            name = idaapi.get_name(func.start_ea)
            if name and any(name.startswith(prefix) for prefix in prefixes):
                test_functions.append((func.start_ea, name))
    
    return test_functions


def test_def_use_resolution():
    """Test def-use resolution on available functions."""
    print("Testing def-use integration...")
    
    # Find test functions
    test_functions = find_test_functions()
    if not test_functions:
        print("No test functions found!")
        return
    
    print(f"Found {len(test_functions)} test functions:")
    for ea, name in test_functions:
        print(f"  - {name} (0x{ea:x})")
    
    # Test the first function
    func_ea, func_name = test_functions[0]
    print(f"\nTesting function: {func_name}")
    
    # Generate microcode
    func = idaapi.get_func(func_ea)
    if func is None:
        print("Failed to get function")
        return
        
    mbr = ida_hexrays.mba_ranges_t(func)
    hf = ida_hexrays.hexrays_failure_t()
    mba = ida_hexrays.gen_microcode(
        mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT, ida_hexrays.MMAT_GLBOPT1
    )
    
    if mba is None:
        print("Failed to generate microcode")
        return
        
    print(f"Generated microcode with {mba.qty} blocks")
    
    # Create interpreter
    interp = MicroCodeInterpreter()
    env = MicroCodeEnvironment()
    
    # Find some operands to test
    test_mops = []
    for i in range(min(5, mba.qty)):
        blk = mba.get_mblock(i)
        if blk is None:
            continue
        ins = blk.head
        while ins and len(test_mops) < 10:
            # Check left operand
            if ins.l is not None and ins.l.t in [ida_hexrays.mop_r, ida_hexrays.mop_S]:
                test_mops.append(ins.l)
            # Check right operand
            if ins.r is not None and ins.r.t in [ida_hexrays.mop_r, ida_hexrays.mop_S]:
                test_mops.append(ins.r)
            # Check destination operand
            if ins.d is not None and ins.d.t in [ida_hexrays.mop_r, ida_hexrays.mop_S]:
                test_mops.append(ins.d)
            ins = ins.next
    
    print(f"Found {len(test_mops)} operands to test")
    
    # Test resolution
    resolved_count = 0
    for i, mop in enumerate(test_mops[:5]):  # Test first 5
        try:
            result = interp.eval(mop, env)
            if result is not None:
                resolved_count += 1
                print(f"  Operand {i}: Resolved to 0x{result:x}")
            else:
                print(f"  Operand {i}: Not resolved")
        except Exception as e:
            print(f"  Operand {i}: Error - {e}")
    
    print(f"\nResolved {resolved_count}/{min(5, len(test_mops))} operands via def-use chains")
    print("Def-use integration test completed!")


if __name__ == "__main__":
    if not idaapi.init_hexrays_plugin():
        print("Hex-Rays decompiler not available")
    else:
        test_def_use_resolution()