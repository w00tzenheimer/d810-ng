"""Regression baselines for Hodur unflattening pseudocode metrics.

These tests lock in the expected AFTER-deobfuscation pseudocode metrics
(lines, returns, whiles, gotos) for Hodur-unflattened functions. Any change
to the metrics indicates a regression or improvement that must be reviewed.

Run with:
    pytest tests/system/e2e/test_hodur_baselines.py -v -s

Requires IDA Pro with Hex-Rays (auto-marked by e2e conftest).
"""

from __future__ import annotations

import os
import platform
import re
import sqlite3

import pytest

import idaapi
import idc


def _get_func_ea(name: str) -> int:
    """Get function address by name or hex address string.

    Handles named symbols, macOS underscore prefix, and hex addresses.
    """
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    if ea == idaapi.BADADDR and name.startswith("0x"):
        try:
            ea = int(name, 16)
            if not idaapi.get_func(ea):
                ea = idaapi.BADADDR
        except ValueError:
            pass
    return ea


def _extract_pseudocode_stats(text: str) -> dict:
    """Extract simple metrics from a pseudocode string.

    Counts are approximate -- based on pattern matching, not AST parsing.
    """
    lines = [ln for ln in text.splitlines() if ln.strip()]
    returns = len(re.findall(r'\breturn\b', text))
    whiles = len(re.findall(r'\bwhile\s*\(', text))
    gotos = len(re.findall(r'\bgoto\b', text))
    return {
        'lines': len(lines),
        'returns': returns,
        'whiles': whiles,
        'gotos': gotos,
    }


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


# Baseline expectations: (function_name_or_hex, project_json, expected_stats)
# expected_stats keys: lines, returns, whiles, gotos
HODUR_BASELINES = [
    pytest.param(
        "hodur_func",
        "example_libobfuscated.json",
        {"lines": 113, "returns": 3, "whiles": 0, "gotos": 1},
        id="hodur_func",
    ),
    pytest.param(
        "sub_7FFD3338C040",
        "hodur_flag2.json",
        {"lines": 304, "returns": 4, "whiles": 5, "gotos": 8},
        id="sub_7FFD3338C040",
    ),
]


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    """Setup fixture for libobfuscated Hodur tests."""
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestHodurBaselines:
    """Regression baselines for Hodur-unflattened function metrics.

    Each parametrized case decompiles a function with its Hodur project
    configuration and asserts that the AFTER pseudocode metrics match
    the locked-in baseline values.
    """

    binary_name = _get_default_binary()

    @pytest.mark.parametrize(
        "func_name,project_config,expected_stats",
        HODUR_BASELINES,
    )
    def test_hodur_baseline(
        self,
        func_name: str,
        project_config: str,
        expected_stats: dict,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
    ):
        """Assert AFTER pseudocode metrics match the locked-in baseline."""
        func_ea = _get_func_ea(func_name)
        if func_ea == idaapi.BADADDR:
            pytest.skip(f"Function '{func_name}' not found in binary")

        with d810_state() as state:
            with state.for_project(project_config):
                # Decompile with d810 active
                state.stats.reset()
                state.start_d810()
                cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                assert cfunc is not None, (
                    f"Decompilation of '{func_name}' with d810 failed"
                )
                code_after = pseudocode_to_string(cfunc.get_pseudocode())

        actual = _extract_pseudocode_stats(code_after)

        # Print diagnostics before asserting
        print(f"\n=== HODUR BASELINE: {func_name} ===")
        print(f"  Project:  {project_config}")
        print(f"  Expected: {expected_stats}")
        print(f"  Actual:   {actual}")

        for metric, expected_val in expected_stats.items():
            actual_val = actual[metric]
            assert actual_val == expected_val, (
                f"{func_name}: {metric} regression: "
                f"expected={expected_val}, actual={actual_val}"
            )


# Key semantic markers that must appear in the rendered program.
# These are handler-body fragments that prove semantic recovery.
SUB_7FFD_SEMANTIC_MARKERS = [
    "sub_1800164E0",      # API call: C2 communication
    "0xFFFFFFFFFFFFFF02",  # MBA-resolved constant in conditional
    "unk_180018E95",       # Data reference in handler
]


class TestSemanticReferenceRegression:
    """Regression: semantic_reference_like program must exist at GLBOPT1/post_d810.

    This prevents silent regression of Hodur's semantic recovery quality.
    The rendered linearized state program is the primary semantic artifact —
    if it loses handler bodies or API calls, the unflattening regressed.
    """

    binary_name = _get_default_binary()

    def test_sub_7FFD_semantic_reference_exists(
        self,
        libobfuscated_setup,
        d810_state,
        monkeypatch,
    ):
        """sub_7FFD must produce a semantic_reference_like program with key markers."""
        func_ea = _get_func_ea("sub_7FFD3338C040")
        if func_ea == idaapi.BADADDR:
            pytest.skip("sub_7FFD3338C040 not found")

        # Enable diagnostic snapshots for this decompilation
        monkeypatch.setenv("D810_DIAG_SNAPSHOT", "1")

        with d810_state() as state:
            with state.for_project("hodur_flag2.json"):
                state.stats.reset()
                state.start_d810()
                cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                if cfunc is None:
                    pytest.fail("sub_7FFD3338C040 decompile returned None")

        # Find the diag DB created during decompilation
        from d810.core.diag import get_diag_db
        from d810.core.diag.query import rendered_program_text

        diag_conn = get_diag_db(func_ea)
        if diag_conn is None:
            pytest.skip("Diagnostic DB not available (D810_DIAG_SNAPSHOT not active)")

        # Find GLBOPT1/post_d810 snapshot
        snap_id = None
        for row in diag_conn.execute("SELECT id, label FROM snapshots"):
            if "GLBOPT1" in row[1] and "post_d810" in row[1]:
                snap_id = row[0]
                break

        assert snap_id is not None, (
            "No MMAT_GLBOPT1/post_d810 snapshot found in diag DB"
        )

        program = rendered_program_text(diag_conn, snap_id, "semantic_reference_like")
        assert program is not None and len(program) > 100, (
            f"semantic_reference_like program missing or too short "
            f"(snap_id={snap_id}, len={len(program) if program else 0})"
        )

        # Check key semantic markers
        for marker in SUB_7FFD_SEMANTIC_MARKERS:
            assert marker in program, (
                f"Semantic marker '{marker}' missing from rendered program — "
                f"handler body may have been lost during unflattening"
            )

        diag_conn.close()
