"""Pytest configuration for runtime tests.

Runtime tests require IDA Pro and validate invariants, API behavior,
and stability checks. They do NOT compare full pipeline output.

Failure means: "Our interaction with IDA/Hex-Rays is wrong or unstable."
"""
from __future__ import annotations

import os
import platform

import pytest


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Mark all tests in this subtree as runtime tests."""
    for item in items:
        if "tests/system/runtime" in str(item.fspath):
            item.add_marker(pytest.mark.runtime)
            item.add_marker(pytest.mark.hexrays)
            item.add_marker(pytest.mark.ida_required)


# =========================================================================
# Shared helper functions for microcode/AST generation
# =========================================================================


def get_func_ea(name: str) -> int:
    """Get function address by name, handling macOS underscore prefix."""
    import idaapi
    import idc

    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    return ea


def gen_microcode_at_maturity(func_ea: int, maturity: int):
    """Generate microcode at a specific maturity level.

    Returns an mba_t object or None if generation fails.
    """
    import ida_hexrays
    import idaapi

    func = idaapi.get_func(func_ea)
    if func is None:
        return None

    mbr = ida_hexrays.mba_ranges_t(func)
    hf = ida_hexrays.hexrays_failure_t()
    mba = ida_hexrays.gen_microcode(
        mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT, maturity
    )
    return mba


def collect_real_asts_from_mba(mba) -> list:
    """Walk all blocks in an mba_t and convert each minsn_t to an AST.

    Returns a list of (ast, minsn) tuples for instructions that
    successfully convert to AST trees.
    """
    from d810.expr.p_ast import minsn_to_ast

    results = []
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk is None:
            continue
        ins = blk.head
        while ins is not None:
            try:
                ast = minsn_to_ast(ins)
                if ast is not None:
                    results.append((ast, ins))
            except Exception:
                pass
            ins = ins.next
    return results


# =========================================================================
# Shared fixtures for pattern matching tests with real microcode
# =========================================================================


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    """Class-scoped setup fixture for libobfuscated tests.

    This fixture is shared across all runtime tests that need the libobfuscated binary.
    """
    import idaapi

    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


@pytest.fixture(scope="class")
def real_asts(libobfuscated_setup):
    """Class-scoped fixture providing real AST trees from microcode.

    Generates microcode from a known function in the test binary and
    converts all instructions to AST trees via minsn_to_ast().
    Returns a list of (ast, minsn) tuples.
    """
    import ida_hexrays
    import idaapi

    test_functions = [
        "test_cst_simplification",
        "test_xor",
        "test_mba_guessing",
        "test_chained_add",
        "test_opaque_predicate",
    ]

    def _collect_from_function_ea(func_ea: int):
        for maturity in [
            ida_hexrays.MMAT_PREOPTIMIZED,
            ida_hexrays.MMAT_LOCOPT,
        ]:
            mba = gen_microcode_at_maturity(func_ea, maturity)
            if mba is None:
                continue

            asts = collect_real_asts_from_mba(mba)
            if len(asts) >= 3:
                print(
                    f"\n  Collected {len(asts)} ASTs "
                    f"@ maturity {maturity}"
                )
                return asts
        return None

    for func_name in test_functions:
        func_ea = get_func_ea(func_name)
        if func_ea == idaapi.BADADDR:
            continue

        asts = _collect_from_function_ea(func_ea)
        if asts is not None:
            print(f"  Source function: {func_name}")
            return asts

    # Fallback: scan arbitrary functions in the current binary for AST-rich blocks.
    import idautils

    for idx, func_ea in enumerate(idautils.Functions()):
        if idx >= 128:
            break
        asts = _collect_from_function_ea(func_ea)
        if asts is not None:
            print(f"  Source function EA: {hex(func_ea)}")
            return asts

    pytest.skip("Could not collect enough ASTs from any test function")


@pytest.fixture(scope="class")
def populated_storages(real_asts):
    """Create OpcodeIndexedStorage with patterns from real ASTs.

    Returns a dict with:
        "new": OpcodeIndexedStorage with 20 unique patterns
        "patterns": List of unique pattern ASTs
    """
    from d810.optimizers.microcode.instructions.pattern_matching.engine import (
        OpcodeIndexedStorage,
    )

    unique_patterns = []
    seen_sigs = set()

    for ast, _ in real_asts:
        if ast.is_node():
            sig = ast.get_pattern()
            if sig not in seen_sigs:
                seen_sigs.add(sig)
                unique_patterns.append(ast)
                if len(unique_patterns) >= 20:
                    break

    if len(unique_patterns) < 3:
        pytest.skip("Not enough unique patterns found in real ASTs")

    new_storage = OpcodeIndexedStorage()

    rules = []
    for i, pattern in enumerate(unique_patterns):
        class MockRule:
            pass

        rule = MockRule()
        rule.name = f"test_rule_{i}"
        rules.append(rule)

        new_storage.add_pattern(pattern, rule)

    print(f"\n  Registered {len(unique_patterns)} patterns in storage")

    return {
        "new": new_storage,
        "patterns": unique_patterns,
    }
