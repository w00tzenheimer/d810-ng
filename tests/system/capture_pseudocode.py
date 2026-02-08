#!/usr/bin/env python3
"""Capture before/after pseudocode for overlapping test functions.

This script directly captures the decompiled pseudocode for each function
and stores it in an SQLite database for comparison.

Usage:
    python tests/system/capture_pseudocode.py

Results are stored in tests/system/.test_results.db
"""

import json
import pathlib
import platform
import sqlite3
import sys

# Add src to path
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent / "src"))

# Database path
DB_PATH = pathlib.Path(__file__).parent / ".test_results.db"

# The overlapping functions between both test suites
OVERLAPPING_FUNCTIONS = [
    ("test_chained_add", "example_libobfuscated.json"),
    ("test_cst_simplification", "example_libobfuscated.json"),
    ("test_opaque_predicate", "example_libobfuscated.json"),
    ("test_xor", "example_libobfuscated.json"),
    ("test_or", "example_libobfuscated.json"),
    ("test_and", "example_libobfuscated.json"),
    ("test_neg", None),  # No project config needed
    ("tigress_minmaxarray", "example_libobfuscated.json"),
    ("unwrap_loops", "example_libobfuscated.json"),
    ("unwrap_loops_2", "example_libobfuscated.json"),
    ("unwrap_loops_3", "example_libobfuscated.json"),
    ("while_switch_flattened", "example_libobfuscated.json"),
    ("test_function_ollvm_fla_bcf_sub", "example_libobfuscated.json"),
]


def init_db():
    """Initialize the database."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS pseudocode_capture (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            function_name TEXT NOT NULL,
            function_address TEXT,
            code_before TEXT,
            code_after TEXT,
            code_changed BOOLEAN,
            rules_fired TEXT,
            project_config TEXT,
            binary_name TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_func_name ON pseudocode_capture(function_name)")
    conn.commit()
    return conn


def pseudocode_to_string(pseudocode):
    """Convert pseudocode to string."""
    lines = []
    for i in range(pseudocode.size()):
        line = pseudocode[i]
        lines.append(line.line)
    return "\n".join(lines)


def get_func_ea(name: str) -> int:
    """Get function address by name."""
    import idaapi
    import idc

    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)  # macOS prefix
    return ea


def capture_function(func_name: str, project_config: str | None, conn: sqlite3.Connection, state):
    """Capture before/after pseudocode for a single function."""
    import idaapi

    func_ea = get_func_ea(func_name)
    if func_ea == idaapi.BADADDR:
        print(f"  SKIP: Function '{func_name}' not found")
        return None

    print(f"  Capturing {func_name} @ {hex(func_ea)}...")

    # Decompile WITHOUT d810
    state.stop_d810()
    cfunc_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
    if cfunc_before is None:
        print(f"  ERROR: Decompilation failed for '{func_name}'")
        return None

    code_before = pseudocode_to_string(cfunc_before.get_pseudocode())

    # Load project config if specified
    if project_config:
        state.load_project(project_config)

    # Reset stats before decompilation
    state.stats.reset()

    # Start D810
    state.start_d810()

    # Decompile WITH d810
    cfunc_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
    code_after = pseudocode_to_string(cfunc_after.get_pseudocode()) if cfunc_after else code_before

    # Get stats
    rules_fired = state.stats.get_fired_rule_names()

    state.stop_d810()

    # Store in database
    binary_name = "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"

    conn.execute("""
        INSERT INTO pseudocode_capture
        (function_name, function_address, code_before, code_after, code_changed, rules_fired, project_config, binary_name)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        func_name,
        hex(func_ea),
        code_before,
        code_after,
        code_before != code_after,
        json.dumps(rules_fired),
        project_config,
        binary_name,
    ))
    conn.commit()

    return {
        "function_name": func_name,
        "function_address": hex(func_ea),
        "code_before": code_before,
        "code_after": code_after,
        "code_changed": code_before != code_after,
        "rules_fired": rules_fired,
    }


def capture_all():
    """Capture pseudocode for all overlapping functions."""
    import idapro
    import idaapi

    from d810.manager import D810State

    # Determine binary path
    binary_name = "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    binary_path = pathlib.Path(__file__).parent.parent.parent / "samples" / "bins" / binary_name

    print(f"Opening database: {binary_path}")
    idapro.open_database(str(binary_path), run_auto_analysis=True)

    if not idaapi.init_hexrays_plugin():
        print("ERROR: Hex-Rays decompiler not available")
        idapro.close_database()
        return

    # Initialize result database
    conn = init_db()

    # Clear previous captures
    conn.execute("DELETE FROM pseudocode_capture")
    conn.commit()

    # Initialize D810State
    print("Initializing D810State...")
    state = D810State()
    state.load(gui=False)

    print(f"\nCapturing {len(OVERLAPPING_FUNCTIONS)} functions...")

    results = []
    for func_name, project_config in OVERLAPPING_FUNCTIONS:
        result = capture_function(func_name, project_config, conn, state)
        if result:
            results.append(result)

    conn.close()
    idapro.close_database()

    print(f"\nCaptured {len(results)} functions to {DB_PATH}")
    return results


def display_results():
    """Display captured pseudocode results."""
    if not DB_PATH.exists():
        print("ERROR: No capture database found. Run capture first.")
        return

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    cursor = conn.execute("""
        SELECT * FROM pseudocode_capture ORDER BY function_name
    """)

    for row in cursor:
        print("\n" + "=" * 80)
        print(f"FUNCTION: {row['function_name']} @ {row['function_address']}")
        print(f"Binary: {row['binary_name']}")
        print(f"Project Config: {row['project_config'] or 'None'}")
        print(f"Code Changed: {bool(row['code_changed'])}")

        rules = json.loads(row['rules_fired']) if row['rules_fired'] else []
        if rules:
            print(f"Rules Fired ({len(rules)}): {', '.join(rules[:10])}{'...' if len(rules) > 10 else ''}")

        print("\n--- BEFORE DEOBFUSCATION ---")
        print("-" * 40)
        print(row['code_before'][:2000] if row['code_before'] else 'N/A')
        if row['code_before'] and len(row['code_before']) > 2000:
            print(f"\n... ({len(row['code_before'])} chars total)")

        print("\n--- AFTER DEOBFUSCATION ---")
        print("-" * 40)
        print(row['code_after'][:2000] if row['code_after'] else 'N/A')
        if row['code_after'] and len(row['code_after']) > 2000:
            print(f"\n... ({len(row['code_after'])} chars total)")

    conn.close()


def display_function(func_name: str):
    """Display results for a specific function."""
    if not DB_PATH.exists():
        print("ERROR: No capture database found. Run capture first.")
        return

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    cursor = conn.execute("""
        SELECT * FROM pseudocode_capture WHERE function_name = ?
    """, (func_name,))

    row = cursor.fetchone()
    if not row:
        print(f"No results found for function '{func_name}'")
        return

    print("=" * 80)
    print(f"FUNCTION: {row['function_name']} @ {row['function_address']}")
    print(f"Binary: {row['binary_name']}")
    print(f"Project Config: {row['project_config'] or 'None'}")
    print(f"Code Changed: {bool(row['code_changed'])}")

    rules = json.loads(row['rules_fired']) if row['rules_fired'] else []
    if rules:
        print(f"\nRules Fired ({len(rules)}):")
        for rule in rules:
            print(f"  - {rule}")

    print("\n" + "=" * 80)
    print("BEFORE DEOBFUSCATION")
    print("=" * 80)
    print(row['code_before'] or 'N/A')

    print("\n" + "=" * 80)
    print("AFTER DEOBFUSCATION")
    print("=" * 80)
    print(row['code_after'] or 'N/A')

    conn.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Capture deobfuscation pseudocode")
    parser.add_argument("--capture", action="store_true", help="Capture pseudocode from IDA")
    parser.add_argument("--display", action="store_true", help="Display all captured results")
    parser.add_argument("--function", type=str, help="Display results for specific function")
    parser.add_argument("--list", action="store_true", help="List captured functions")

    args = parser.parse_args()

    if args.capture:
        capture_all()
    elif args.function:
        display_function(args.function)
    elif args.list:
        if not DB_PATH.exists():
            print("No capture database found.")
        else:
            conn = sqlite3.connect(str(DB_PATH))
            cursor = conn.execute("SELECT function_name, code_changed, function_address FROM pseudocode_capture ORDER BY function_name")
            print(f"{'Function':<40} {'Changed':<10} {'Address'}")
            print("-" * 70)
            for row in cursor:
                print(f"{row[0]:<40} {bool(row[1]):<10} {row[2]}")
            conn.close()
    elif args.display:
        display_results()
    else:
        parser.print_help()
        print("\nExamples:")
        print("  python tests/system/capture_pseudocode.py --capture   # Capture from IDA")
        print("  python tests/system/capture_pseudocode.py --list      # List functions")
        print("  python tests/system/capture_pseudocode.py --display   # Show all results")
        print("  python tests/system/capture_pseudocode.py --function test_xor  # Show specific function")
