#!/usr/bin/env python3
"""Display captured before/after pseudocode from the database.

Usage:
    python tests/system/show_pseudocode.py              # Show all
    python tests/system/show_pseudocode.py --list       # List functions
    python tests/system/show_pseudocode.py test_xor     # Show specific function
"""

import json
import pathlib
import sqlite3
import sys

DB_PATH = pathlib.Path(__file__).parent / ".pseudocode_capture.db"


def strip_colors(text: str) -> str:
    """Remove IDA color tags from pseudocode."""
    import re
    # IDA uses \x01 and \x02 for color tags
    text = re.sub(r'\x01.', '', text)
    text = re.sub(r'\x02.', '', text)
    return text


def display_function(func_name: str):
    """Display results for a specific function."""
    if not DB_PATH.exists():
        print("ERROR: No capture database found. Run capture test first.")
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
    print(strip_colors(row['code_before']) if row['code_before'] else 'N/A')

    print("\n" + "=" * 80)
    print("AFTER DEOBFUSCATION")
    print("=" * 80)
    print(strip_colors(row['code_after']) if row['code_after'] else 'N/A')

    conn.close()


def display_all():
    """Display all captured results."""
    if not DB_PATH.exists():
        print("ERROR: No capture database found. Run capture test first.")
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
        code_before = strip_colors(row['code_before']) if row['code_before'] else 'N/A'
        print(code_before)

        print("\n--- AFTER DEOBFUSCATION ---")
        print("-" * 40)
        code_after = strip_colors(row['code_after']) if row['code_after'] else 'N/A'
        print(code_after)

    conn.close()


def list_functions():
    """List all captured functions."""
    if not DB_PATH.exists():
        print("No capture database found.")
        return

    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.execute("""
        SELECT function_name, code_changed, function_address, rules_fired
        FROM pseudocode_capture ORDER BY function_name
    """)

    print(f"{'Function':<40} {'Changed':<10} {'Address':<15} {'Rules'}")
    print("-" * 90)
    for row in cursor:
        rules = json.loads(row[3]) if row[3] else []
        rules_str = ', '.join(rules[:3]) + ('...' if len(rules) > 3 else '')
        print(f"{row[0]:<40} {bool(row[1]):<10} {row[2]:<15} {rules_str}")
    conn.close()


def summary():
    """Show summary of all functions."""
    if not DB_PATH.exists():
        print("No capture database found.")
        return

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    cursor = conn.execute("""
        SELECT function_name, code_changed, function_address, rules_fired,
               LENGTH(code_before) as before_len, LENGTH(code_after) as after_len
        FROM pseudocode_capture ORDER BY function_name
    """)

    print("\n" + "=" * 100)
    print("DEOBFUSCATION SUMMARY")
    print("=" * 100)
    print(f"\n{'Function':<40} {'Changed':<10} {'Before':<10} {'After':<10} {'Rules'}")
    print("-" * 100)

    total_changed = 0
    total_funcs = 0
    for row in cursor:
        rules = json.loads(row['rules_fired']) if row['rules_fired'] else []
        rules_count = len(rules)
        changed = bool(row['code_changed'])
        if changed:
            total_changed += 1
        total_funcs += 1

        print(f"{row['function_name']:<40} {str(changed):<10} {row['before_len']:<10} {row['after_len']:<10} {rules_count} rules")

    print("-" * 100)
    print(f"\nTotal: {total_funcs} functions, {total_changed} changed ({total_changed/total_funcs*100:.0f}%)")
    conn.close()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg == "--list":
            list_functions()
        elif arg == "--summary":
            summary()
        elif arg == "--help":
            print(__doc__)
        else:
            display_function(arg)
    else:
        display_all()
