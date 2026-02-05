#!/usr/bin/env python3
"""Run overlapping tests from both suites and capture before/after pseudocode.

This script runs the 13 overlapping test functions from both test suites
and captures the deobfuscation results to SQLite for comparison.

Usage:
    python tests/system/run_comparison.py

Results are stored in tests/system/.test_results.db
"""

import os
import sys
import pathlib

# Add src to path
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent / "src"))

# The 13 overlapping functions between both test suites
OVERLAPPING_FUNCTIONS = [
    "test_chained_add",
    "test_cst_simplification",
    "test_opaque_predicate",
    "test_xor",
    "test_or",
    "test_and",
    "test_neg",
    "tigress_minmaxarray",
    "unwrap_loops",
    "unwrap_loops_2",
    "unwrap_loops_3",
    "while_switch_flattened",
    "test_function_ollvm_fla_bcf_sub",
]

# Mapping from function name to test method name in test_libdeobfuscated.py
FUNCTION_TO_TEST_METHOD = {
    "test_chained_add": "test_simplify_chained_add",
    "test_cst_simplification": "test_cst_simplification",
    "test_opaque_predicate": "test_deobfuscate_opaque_predicate",
    "test_xor": "test_simplify_xor",
    "test_or": "test_simplify_or",
    "test_and": "test_simplify_and",
    "test_neg": "test_simplify_neg",
    "tigress_minmaxarray": "test_tigress_minmaxarray",
    "unwrap_loops": "test_unwrap_loops",
    "unwrap_loops_2": "test_unwrap_loops_2",
    "unwrap_loops_3": "test_unwrap_loops_3",
    "while_switch_flattened": "test_while_switch_flattened",
    "test_function_ollvm_fla_bcf_sub": "test_ollvm_fla_bcf_sub",
}


def run_comparison_tests():
    """Run pytest with --capture-to-db for both test suites."""
    import subprocess

    test_dir = pathlib.Path(__file__).parent

    # Build test selection for test_libdeobfuscated.py
    libdeob_tests = [
        f"tests/system/test_libdeobfuscated.py::TestLibDeobfuscated::{method}"
        for method in FUNCTION_TO_TEST_METHOD.values()
    ]

    # Build test selection for test_libdeobfuscated_dsl.py (parametrized)
    # These use test IDs like test_core_deobfuscation[test_xor]
    dsl_tests = []
    for func in OVERLAPPING_FUNCTIONS:
        # The DSL tests are parametrized, so we match by function name in test ID
        dsl_tests.append(f"-k {func}")

    print("=" * 60)
    print("Running test_libdeobfuscated.py tests with --capture-to-db")
    print("=" * 60)

    cmd1 = [
        sys.executable, "-m", "pytest",
        "--capture-to-db",
        "-v",
        "--tb=short",
    ] + libdeob_tests

    print(f"Command: {' '.join(cmd1)}")
    result1 = subprocess.run(cmd1, cwd=test_dir.parent.parent)

    print("\n" + "=" * 60)
    print("Running test_libdeobfuscated_dsl.py tests with --capture-to-db")
    print("=" * 60)

    # For DSL tests, we need to filter by function names
    func_filter = " or ".join(OVERLAPPING_FUNCTIONS)
    cmd2 = [
        sys.executable, "-m", "pytest",
        "tests/system/test_libdeobfuscated_dsl.py",
        "--capture-to-db",
        "-v",
        "--tb=short",
        "-k", func_filter,
    ]

    print(f"Command: {' '.join(cmd2)}")
    result2 = subprocess.run(cmd2, cwd=test_dir.parent.parent)

    print("\n" + "=" * 60)
    print("Test runs complete. Query results with:")
    print("  python -m tests.system.test_capture compare-suites test_libdeobfuscated test_libdeobfuscated_dsl")
    print("=" * 60)

    return result1.returncode == 0 and result2.returncode == 0


def capture_single_function(func_name: str, binary_path: str):
    """Capture before/after pseudocode for a single function.

    This runs inside IDA context.
    """
    import idapro
    import idaapi
    import idc

    from d810.manager import D810Manager
    from tests.system.test_capture import TestResultCapture

    # Open database
    idapro.open_database(binary_path, run_auto_analysis=True)

    if not idaapi.init_hexrays_plugin():
        print(f"ERROR: Hex-Rays not available")
        return None

    # Find function
    ea = idc.get_name_ea_simple(func_name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + func_name)  # macOS prefix
    if ea == idaapi.BADADDR:
        print(f"ERROR: Function '{func_name}' not found")
        return None

    # Decompile without d810
    cfunc_before = idaapi.decompile(ea, flags=idaapi.DECOMP_NO_CACHE)
    if cfunc_before is None:
        print(f"ERROR: Decompilation failed for '{func_name}'")
        return None

    code_before = str(cfunc_before)

    # Enable d810 and decompile again
    manager = D810Manager()
    manager.start()

    cfunc_after = idaapi.decompile(ea, flags=idaapi.DECOMP_NO_CACHE)
    code_after = str(cfunc_after) if cfunc_after else code_before

    # Get stats
    stats_dict = manager.stats.to_dict() if hasattr(manager, 'stats') else {}
    rules_fired = manager.stats.get_fired_rule_names() if hasattr(manager, 'stats') else []

    manager.stop()

    result = {
        "function_name": func_name,
        "function_address": hex(ea),
        "code_before": code_before,
        "code_after": code_after,
        "code_changed": code_before != code_after,
        "rules_fired": rules_fired,
        "stats_dict": stats_dict,
    }

    idapro.close_database()

    return result


def display_results():
    """Display comparison results from the database."""
    from tests.system.test_capture import TestResultQuery, DB_PATH

    if not DB_PATH.exists():
        print("ERROR: No test results database found.")
        print("Run the tests first with --capture-to-db flag.")
        return

    query = TestResultQuery(DB_PATH)

    print("\n" + "=" * 80)
    print("COMPARISON: test_libdeobfuscated.py vs test_libdeobfuscated_dsl.py")
    print("=" * 80)

    for func_name in OVERLAPPING_FUNCTIONS:
        print(f"\n{'=' * 80}")
        print(f"FUNCTION: {func_name}")
        print("=" * 80)

        results = query.get_function_results(func_name)

        if not results:
            print("  No results captured yet.")
            continue

        # Group by suite
        by_suite = {}
        for r in results:
            suite = r["test_suite"]
            if suite not in by_suite:
                by_suite[suite] = r

        for suite, r in sorted(by_suite.items()):
            print(f"\n--- Suite: {suite} ---")
            print(f"Test: {r['test_name']}")
            print(f"Passed: {r['passed']}")
            print(f"Code Changed: {r['code_changed']}")

            if r.get('rules_fired'):
                import json
                rules = json.loads(r['rules_fired']) if isinstance(r['rules_fired'], str) else r['rules_fired']
                print(f"Rules Fired: {', '.join(rules[:5])}{'...' if len(rules) > 5 else ''}")

            print(f"\nBEFORE (first 500 chars):")
            print("-" * 40)
            code_before = r.get('code_before', 'N/A')
            print(code_before[:500] if code_before else 'N/A')

            print(f"\nAFTER (first 500 chars):")
            print("-" * 40)
            code_after = r.get('code_after', 'N/A')
            print(code_after[:500] if code_after else 'N/A')


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run comparison tests or display results")
    parser.add_argument("--run", action="store_true", help="Run the tests")
    parser.add_argument("--display", action="store_true", help="Display captured results")
    parser.add_argument("--function", type=str, help="Capture single function (requires --binary)")
    parser.add_argument("--binary", type=str, help="Path to binary for single function capture")

    args = parser.parse_args()

    if args.function and args.binary:
        result = capture_single_function(args.function, args.binary)
        if result:
            import json
            print(json.dumps(result, indent=2, default=str))
    elif args.run:
        run_comparison_tests()
    elif args.display:
        display_results()
    else:
        parser.print_help()
        print("\nTo run tests and capture results:")
        print("  python tests/system/run_comparison.py --run")
        print("\nTo display captured results:")
        print("  python tests/system/run_comparison.py --display")
