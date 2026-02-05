#!/usr/bin/env python3
"""Show before/after pseudocode diffs grouped by test origin.

Usage:
    python tests/system/show_diffs.py              # Show all diffs
    python tests/system/show_diffs.py test_xor    # Show specific function
    python tests/system/show_diffs.py --compact   # Compact view (no full code)
"""

import difflib
import json
import pathlib
import re
import sqlite3
import sys

DB_PATH = pathlib.Path(__file__).parent / ".pseudocode_capture.db"

# Mapping from function name to test method in test_libdeobfuscated.py
FUNCTION_TO_LIBDEOB_TEST = {
    "test_chained_add": "TestLibDeobfuscated::test_simplify_chained_add",
    "test_cst_simplification": "TestLibDeobfuscated::test_cst_simplification",
    "test_opaque_predicate": "TestLibDeobfuscated::test_deobfuscate_opaque_predicate",
    "test_xor": "TestLibDeobfuscated::test_simplify_xor",
    "test_or": "TestLibDeobfuscated::test_simplify_or",
    "test_and": "TestLibDeobfuscated::test_simplify_and",
    "test_neg": "TestLibDeobfuscated::test_simplify_neg",
    "tigress_minmaxarray": "TestLibDeobfuscated::test_tigress_minmaxarray",
    "unwrap_loops": "TestLibDeobfuscated::test_unwrap_loops",
    "unwrap_loops_2": "TestLibDeobfuscated::test_unwrap_loops_2",
    "unwrap_loops_3": "TestLibDeobfuscated::test_unwrap_loops_3",
    "while_switch_flattened": "TestLibDeobfuscated::test_while_switch_flattened",
    "test_function_ollvm_fla_bcf_sub": "TestLibDeobfuscated::test_ollvm_fla_bcf_sub",
}

# Mapping from function name to DSL test classes
FUNCTION_TO_DSL_TESTS = {
    "test_chained_add": ["TestCoreDeobfuscation", "TestMBASimplification", "TestSmoke", "TestAllCases"],
    "test_cst_simplification": ["TestCoreDeobfuscation", "TestMBASimplification", "TestAllCases"],
    "test_opaque_predicate": ["TestCoreDeobfuscation", "TestMBASimplification", "TestAllCases"],
    "test_xor": ["TestCoreDeobfuscation", "TestMBASimplification", "TestSmoke", "TestAllCases"],
    "test_or": ["TestCoreDeobfuscation", "TestMBASimplification", "TestSmoke", "TestAllCases"],
    "test_and": ["TestCoreDeobfuscation", "TestMBASimplification", "TestAllCases"],
    "test_neg": ["TestCoreDeobfuscation", "TestMBASimplification", "TestAllCases"],
    "tigress_minmaxarray": ["TestCoreDeobfuscation", "TestTigressPatterns", "TestAllCases"],
    "unwrap_loops": ["TestLoopPatterns", "TestAllCases"],
    "unwrap_loops_2": ["TestLoopPatterns", "TestAllCases"],
    "unwrap_loops_3": ["TestLoopPatterns", "TestAllCases"],
    "while_switch_flattened": ["TestCoreDeobfuscation", "TestLoopPatterns", "TestAllCases"],
    "test_function_ollvm_fla_bcf_sub": ["TestCoreDeobfuscation", "TestOLLVMPatterns", "TestAllCases"],
}


def strip_colors(text: str) -> str:
    """Remove IDA color tags from pseudocode."""
    if not text:
        return ""
    text = re.sub(r'\x01.', '', text)
    text = re.sub(r'\x02.', '', text)
    return text


def unified_diff(before: str, after: str, func_name: str) -> str:
    """Generate unified diff between before and after."""
    before_lines = strip_colors(before).splitlines(keepends=True)
    after_lines = strip_colors(after).splitlines(keepends=True)

    diff = difflib.unified_diff(
        before_lines,
        after_lines,
        fromfile=f"{func_name} (OBFUSCATED)",
        tofile=f"{func_name} (DEOBFUSCATED)",
        lineterm=""
    )
    return "".join(diff)


def side_by_side_diff(before: str, after: str, width: int = 60) -> str:
    """Generate side-by-side diff."""
    before_lines = strip_colors(before).splitlines()
    after_lines = strip_colors(after).splitlines()

    result = []
    result.append(f"{'BEFORE (Obfuscated)':<{width}} | {'AFTER (Deobfuscated)':<{width}}")
    result.append("-" * (width * 2 + 3))

    max_lines = max(len(before_lines), len(after_lines))
    for i in range(max_lines):
        left = before_lines[i] if i < len(before_lines) else ""
        right = after_lines[i] if i < len(after_lines) else ""

        # Truncate if needed
        if len(left) > width:
            left = left[:width-3] + "..."
        if len(right) > width:
            right = right[:width-3] + "..."

        # Mark changed lines
        marker = " " if left.strip() == right.strip() else "*"
        result.append(f"{left:<{width}} {marker} {right:<{width}}")

    return "\n".join(result)


def show_function_diff(func_name: str, compact: bool = False):
    """Show diff for a specific function."""
    if not DB_PATH.exists():
        print("ERROR: No capture database found. Run capture test first:")
        print("  pytest tests/system/test_capture_pseudocode.py -v")
        return

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    cursor = conn.execute("""
        SELECT * FROM pseudocode_capture WHERE function_name = ?
    """, (func_name,))

    row = cursor.fetchone()
    if not row:
        print(f"No results found for function '{func_name}'")
        conn.close()
        return

    # Header
    print("\n" + "=" * 100)
    print(f"FUNCTION: {row['function_name']} @ {row['function_address']}")
    print("=" * 100)

    # Test origins
    libdeob_test = FUNCTION_TO_LIBDEOB_TEST.get(func_name, "N/A")
    dsl_tests = FUNCTION_TO_DSL_TESTS.get(func_name, [])

    print(f"\nTested by test_libdeobfuscated.py:")
    print(f"  → {libdeob_test}")

    print(f"\nTested by test_libdeobfuscated_dsl.py:")
    for test_class in dsl_tests:
        print(f"  → {test_class}::test_*[{func_name}]")

    # Stats
    print(f"\nCode Changed: {bool(row['code_changed'])}")
    rules = json.loads(row['rules_fired']) if row['rules_fired'] else []
    if rules:
        print(f"Rules Fired ({len(rules)}):")
        for rule in rules:
            print(f"  • {rule}")

    if compact:
        # Just show stats, no full code
        before_lines = len(strip_colors(row['code_before']).splitlines()) if row['code_before'] else 0
        after_lines = len(strip_colors(row['code_after']).splitlines()) if row['code_after'] else 0
        print(f"\nCode size: {before_lines} lines → {after_lines} lines")
        conn.close()
        return

    # Show diff
    print("\n" + "-" * 100)
    print("UNIFIED DIFF")
    print("-" * 100)

    diff = unified_diff(
        row['code_before'] or "",
        row['code_after'] or "",
        func_name
    )

    if diff:
        print(diff)
    else:
        print("(no changes)")

    conn.close()


def show_all_diffs(compact: bool = False):
    """Show diffs for all captured functions."""
    if not DB_PATH.exists():
        print("ERROR: No capture database found. Run capture test first:")
        print("  pytest tests/system/test_capture_pseudocode.py -v")
        return

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    cursor = conn.execute("""
        SELECT function_name FROM pseudocode_capture ORDER BY function_name
    """)

    functions = [row['function_name'] for row in cursor]
    conn.close()

    for func_name in functions:
        show_function_diff(func_name, compact=compact)
        print("\n")


def show_summary_table():
    """Show summary table with test origins."""
    if not DB_PATH.exists():
        print("ERROR: No capture database found.")
        return

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    cursor = conn.execute("""
        SELECT function_name, code_changed, function_address, rules_fired,
               LENGTH(code_before) as before_len, LENGTH(code_after) as after_len
        FROM pseudocode_capture ORDER BY function_name
    """)

    print("\n" + "=" * 120)
    print("DEOBFUSCATION RESULTS BY TEST ORIGIN")
    print("=" * 120)

    print(f"\n{'Function':<35} {'Changed':<8} {'Lines':<12} {'Original Test':<45}")
    print("-" * 120)

    for row in cursor:
        func = row['function_name']
        changed = "✓" if row['code_changed'] else "✗"

        # Estimate line counts from byte lengths (rough approximation)
        before_len = row['before_len'] or 0
        after_len = row['after_len'] or 0
        before_lines = before_len // 40 if before_len else 0
        after_lines = after_len // 40 if after_len else 0
        lines = f"{before_lines}→{after_lines}"

        libdeob = FUNCTION_TO_LIBDEOB_TEST.get(func, "N/A")

        print(f"{func:<35} {changed:<8} {lines:<12} {libdeob:<45}")

    print("-" * 120)

    print("\n\nDSL Test Classes that test these functions:")
    print("-" * 60)

    # Group by DSL test class
    test_class_funcs = {}
    for func, classes in FUNCTION_TO_DSL_TESTS.items():
        for cls in classes:
            if cls not in test_class_funcs:
                test_class_funcs[cls] = []
            test_class_funcs[cls].append(func)

    for cls in sorted(test_class_funcs.keys()):
        funcs = test_class_funcs[cls]
        print(f"\n{cls}:")
        for f in sorted(funcs):
            print(f"  • {f}")

    conn.close()


if __name__ == "__main__":
    compact = "--compact" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("--")]

    if "--summary" in sys.argv:
        show_summary_table()
    elif "--help" in sys.argv:
        print(__doc__)
    elif args:
        show_function_diff(args[0], compact=compact)
    else:
        show_all_diffs(compact=compact)
