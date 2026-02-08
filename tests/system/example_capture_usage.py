"""Example demonstrating test capture system usage.

This script shows how to use the test capture system both manually
and via the pytest plugin.
"""

import os
import platform
from pathlib import Path
import tempfile

# Manual usage example
from tests.system.test_capture import TestResultCapture, TestResultQuery


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


def example_manual_capture():
    """Example of manually capturing test results."""
    print("=== Manual Capture Example ===\n")

    # Use a temporary database for this example
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)

    try:
        # Capture some results
        with TestResultCapture(db_path) as capture:
            print("Capturing test results...")

            # Simulate test result 1
            capture.capture_result(
                test_suite="test_example.py",
                test_name="test_xor_simplification",
                function_name="test_xor",
                code_before="return (a + b) - 2 * (a & b);",
                code_after="return a ^ b;",
                stats_dict={
                    "instruction_rule_matches": {
                        "Rule_XorToOr": 1,
                        "Rule_AddSub": 2,
                    },
                    "optimizer_matches": {"PatternOptimizer": 3},
                    "cfg_rule_usages": {},
                },
                passed=True,
                binary_name=_get_default_binary(),
            )

            # Simulate test result 2
            capture.capture_result(
                test_suite="test_example.py",
                test_name="test_constant_folding",
                function_name="test_cst_fold",
                code_before="return (x << 3) + (x << 1);",
                code_after="return x * 10;",
                stats_dict={
                    "instruction_rule_matches": {
                        "Rule_ConstFold": 1,
                        "Rule_ShiftToMul": 2,
                    },
                    "optimizer_matches": {"ConstantOptimizer": 1},
                    "cfg_rule_usages": {},
                },
                passed=True,
                binary_name=_get_default_binary(),
            )

            print("Captured 2 test results\n")

        # Query the results
        with TestResultQuery(db_path) as query:
            print("Querying captured results...\n")

            # List all functions
            functions = query.list_functions()
            print(f"Functions tested: {len(functions)}")
            for func in functions:
                print(f"  - {func['function_name']}: {func['total_runs']} runs")

            print()

            # Get results for specific function
            results = query.get_function_results("test_xor")
            print(f"Results for 'test_xor': {len(results)}")
            for result in results:
                print(f"  Test: {result['test_name']}")
                print(f"  Passed: {result['passed']}")
                print(f"  Rules fired: {result['rules_fired']}")
                print(f"  Code after:\n    {result['code_after']}")

            print()

            # Get stats
            stats = query.get_stats_summary()
            print("Database statistics:")
            print(f"  Total tests: {stats['total_tests']}")
            print(f"  Functions: {stats['total_functions']}")
            print(f"  Passed: {stats['passed_count']}")

    finally:
        # Cleanup
        if db_path.exists():
            db_path.unlink()
            print(f"\n✓ Cleaned up temporary database")


def example_pytest_usage():
    """Example showing pytest integration."""
    print("\n\n=== Pytest Integration Example ===\n")

    print("To use with pytest, run tests with --capture-to-db flag:\n")
    print("  pytest tests/system/test_libdeobfuscated.py --capture-to-db -v\n")

    print("Then query results using the CLI:\n")
    print("  # List all functions tested")
    print("  python -m tests.system.test_capture list-functions\n")

    print("  # Get results for specific function")
    print("  python -m tests.system.test_capture get-function test_chained_add\n")

    print("  # Compare two test suites")
    print("  python -m tests.system.test_capture compare-suites \\")
    print("      test_libdeobfuscated.py \\")
    print("      test_libdeobfuscated_dsl.py\n")

    print("  # Show recent test runs")
    print("  python -m tests.system.test_capture recent --limit 10\n")


def example_test_integration():
    """Example showing integration in test code."""
    print("\n\n=== Test Code Integration Example ===\n")

    example_code = '''
def test_my_deobfuscation(self, d810_state, db_capture, pseudocode_to_string):
    """Example test with automatic capture."""
    func_ea = get_func_ea("my_function")

    with d810_state() as state:
        # Decompile before optimization
        state.stop_d810()
        decompiled_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
        code_before = pseudocode_to_string(decompiled_before.get_pseudocode())

        # Decompile after optimization
        state.start_d810()
        decompiled_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
        code_after = pseudocode_to_string(decompiled_after.get_pseudocode())

        # Assert code improved
        assert code_before != code_after

        # Manually capture result (when test passes)
        db_capture.record(
            function_name="my_function",
            code_before=code_before,
            code_after=code_after,
            stats=state.stats,
            passed=True,
            function_address=hex(func_ea),
        )
'''

    print("Add db_capture fixture to your test:")
    print(example_code)

    print("\nOr use with DSL tests (automatic capture):")

    example_dsl_code = '''
@pytest.mark.parametrize("case", TEST_CASES, ids=lambda c: c.test_id)
def test_deobfuscation(
    self,
    case,
    d810_state,
    pseudocode_to_string,
    code_comparator,
    db_capture,  # Add this
):
    """Test with automatic capture."""
    run_deobfuscation_test(
        case=case,
        d810_state=d810_state,
        pseudocode_to_string=pseudocode_to_string,
        code_comparator=code_comparator,
        db_capture=db_capture,  # Pass to runner
    )
'''

    print(example_dsl_code)


def example_use_cases():
    """Example showing common use cases."""
    print("\n\n=== Common Use Cases ===\n")

    print("1. Track Regression")
    print("   - Capture baseline: pytest tests/system/test_*.py --capture-to-db")
    print("   - Make code changes...")
    print("   - Run again: pytest tests/system/test_*.py --capture-to-db")
    print("   - Compare: python -m tests.system.test_capture get-function <name> --limit 5")
    print()

    print("2. Compare Test Suites")
    print("   - Find functions only in one suite:")
    print("     python -m tests.system.test_capture compare-suites suite1.py suite2.py")
    print()

    print("3. Analyze Rule Usage")
    print("   - See which rules fired for a function:")
    print("     python -m tests.system.test_capture get-function test_xor")
    print()

    print("4. Find Failures")
    print("   - Query database directly:")
    print("     sqlite3 tests/system/.test_results.db")
    print("     SELECT function_name, error_message FROM test_results WHERE passed=0;")
    print()

    print("5. Export Results")
    print("   - To CSV:")
    print("     sqlite3 -header -csv tests/system/.test_results.db \\")
    print('       "SELECT * FROM test_results" > results.csv')
    print()


if __name__ == "__main__":
    example_manual_capture()
    example_pytest_usage()
    example_test_integration()
    example_use_cases()
