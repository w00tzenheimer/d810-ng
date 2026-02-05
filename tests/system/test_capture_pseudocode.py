"""Test that captures before/after pseudocode for comparison.

Run with:
    pytest tests/system/test_capture_pseudocode.py -v -s
"""

import json
import pathlib
import platform
import sqlite3

import pytest
import idaapi
import idc

# Database path
DB_PATH = pathlib.Path(__file__).parent / ".pseudocode_capture.db"

# The overlapping functions between both test suites
OVERLAPPING_FUNCTIONS = [
    ("test_chained_add", "example_libobfuscated.json"),
    ("test_cst_simplification", "example_libobfuscated.json"),
    ("test_opaque_predicate", "example_libobfuscated.json"),
    ("test_xor", "example_libobfuscated.json"),
    ("test_or", "example_libobfuscated.json"),
    ("test_and", "example_libobfuscated.json"),
    ("test_neg", None),
    ("tigress_minmaxarray", "example_libobfuscated.json"),
    ("unwrap_loops", "example_libobfuscated.json"),
    ("unwrap_loops_2", "example_libobfuscated.json"),
    ("unwrap_loops_3", "example_libobfuscated.json"),
    ("while_switch_flattened", "example_libobfuscated.json"),
    ("test_function_ollvm_fla_bcf_sub", "example_libobfuscated.json"),
]


def get_func_ea(name: str) -> int:
    """Get function address by name."""
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    return ea


def pseudocode_to_string(pseudocode):
    """Convert pseudocode to string."""
    lines = []
    for i in range(pseudocode.size()):
        line = pseudocode[i]
        lines.append(line.line)
    return "\n".join(lines)


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
    # Clear previous captures
    conn.execute("DELETE FROM pseudocode_capture")
    conn.commit()
    return conn


def _get_default_binary() -> str:
    """Get default binary name based on platform."""
    import os
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


@pytest.fixture(scope="module")
def capture_db():
    """Fixture to provide database connection."""
    conn = init_db()
    yield conn
    conn.close()


class TestCapturePseudocode:
    """Capture before/after pseudocode for overlapping functions."""

    binary_name = _get_default_binary()

    @pytest.fixture(scope="class")
    def libobfuscated_setup(self, ida_database, configure_hexrays, setup_libobfuscated_funcs):
        """Setup fixture for libobfuscated tests."""
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler not available")
        return ida_database

    @pytest.mark.parametrize("func_name,project_config", OVERLAPPING_FUNCTIONS)
    def test_capture_function(
        self,
        func_name,
        project_config,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        capture_db,
    ):
        """Capture before/after pseudocode for a function."""
        func_ea = get_func_ea(func_name)
        if func_ea == idaapi.BADADDR:
            pytest.skip(f"Function '{func_name}' not found")

        with d810_state() as state:
            # Load project config if specified
            if project_config:
                with state.for_project(project_config):
                    self._capture_and_store(func_name, func_ea, project_config, state, pseudocode_to_string, capture_db)
            else:
                self._capture_and_store(func_name, func_ea, project_config, state, pseudocode_to_string, capture_db)

    def _capture_and_store(self, func_name, func_ea, project_config, state, pseudocode_to_string, capture_db):
        """Capture pseudocode and store in database."""
        # Decompile WITHOUT d810
        state.stop_d810()
        cfunc_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
        assert cfunc_before is not None, f"Decompilation failed for '{func_name}'"
        code_before = pseudocode_to_string(cfunc_before.get_pseudocode())

        # Reset stats
        state.stats.reset()

        # Decompile WITH d810
        state.start_d810()
        cfunc_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
        assert cfunc_after is not None, f"D810 decompilation failed for '{func_name}'"
        code_after = pseudocode_to_string(cfunc_after.get_pseudocode())

        # Get stats
        rules_fired = state.stats.get_fired_rule_names()

        # Store in database
        binary_name = _get_default_binary()
        capture_db.execute("""
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
        capture_db.commit()

        # Print summary
        print(f"\n{'=' * 60}")
        print(f"FUNCTION: {func_name} @ {hex(func_ea)}")
        print(f"Code Changed: {code_before != code_after}")
        print(f"Rules Fired: {len(rules_fired)}")
        if rules_fired:
            print(f"  {', '.join(rules_fired[:5])}{'...' if len(rules_fired) > 5 else ''}")

        # Assert deobfuscation happened for most functions
        if func_name not in ["test_neg", "unwrap_loops_3"]:  # These might not change
            assert code_before != code_after, f"Deobfuscation should change code for {func_name}"


def display_captured_results():
    """Display captured results from database."""
    if not DB_PATH.exists():
        print("No capture database found. Run tests first.")
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
        print(row['code_before'] or 'N/A')

        print("\n--- AFTER DEOBFUSCATION ---")
        print("-" * 40)
        print(row['code_after'] or 'N/A')

    conn.close()


if __name__ == "__main__":
    display_captured_results()
