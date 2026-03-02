"""Test that captures before/after pseudocode for comparison.

Run with:
    pytest tests/system/e2e/test_capture_pseudocode.py -v -s
"""

import json
import pathlib
import sqlite3

import pytest
import idaapi

from d810.testing.capture_db import (
    OVERLAPPING_FUNCTIONS,
    capture_one_function,
    get_default_binary_name,
    get_func_ea,
    init_capture_db,
    resolve_capture_db_path,
)
from d810.testing.skip_controls import should_skip_reason
from tests.system.cases.known_issues import SEGFAULT_FUNCTIONS

# Shared capture DB path (CLI + tests)
DB_PATH = resolve_capture_db_path(None)


def init_db() -> sqlite3.Connection:
    """Initialize and clear the shared capture database for this test module."""
    conn = init_capture_db(DB_PATH)
    conn.execute("DELETE FROM pseudocode_capture")
    conn.commit()
    return conn


@pytest.fixture(scope="module")
def capture_db():
    """Fixture to provide database connection."""
    conn = init_db()
    yield conn
    conn.close()


class TestCapturePseudocode:
    """Capture before/after pseudocode for overlapping functions."""

    binary_name = get_default_binary_name()

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
        if func_name in SEGFAULT_FUNCTIONS:
            reason = f"Known segfault in decompile_func for '{func_name}'"
            if should_skip_reason(reason):
                pytest.skip(reason)

        func_ea = get_func_ea(func_name)
        if func_ea == idaapi.BADADDR:
            pytest.skip(f"Function '{func_name}' not found")

        with d810_state() as state:
            if project_config:
                with state.for_project(project_config):
                    summary = capture_one_function(
                        state=state,
                        func_name=func_name,
                        func_ea=func_ea,
                        project_config=project_config,
                        conn=capture_db,
                        binary_name=self.binary_name,
                        pseudo_to_str=pseudocode_to_string,
                    )
            else:
                summary = capture_one_function(
                    state=state,
                    func_name=func_name,
                    func_ea=func_ea,
                    project_config=project_config,
                    conn=capture_db,
                    binary_name=self.binary_name,
                    pseudo_to_str=pseudocode_to_string,
                )

        code_changed = summary["code_changed"]
        rules_fired = summary["rules_fired"]

        print(f"\n{'=' * 60}")
        print(f"FUNCTION: {func_name} @ {summary['function_address']}")
        print(f"Code Changed: {code_changed}")
        print(f"Rules Fired: {len(rules_fired)}")
        if rules_fired:
            print(
                f"  {', '.join(rules_fired[:5])}"
                f"{'...' if len(rules_fired) > 5 else ''}"
            )

        # Assert deobfuscation happened for most functions
        if func_name not in [
            "test_neg",
            "unwrap_loops_3",
        ]:  # These might not change
            assert (
                code_changed
            ), f"Deobfuscation should change code for {func_name}"

