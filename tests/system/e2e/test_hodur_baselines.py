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
        "example_hodur.json",
        {"lines": 114, "returns": 3, "whiles": 0, "gotos": 1},
        id="hodur_func",
    ),
    pytest.param(
        "sub_7FFD3338C040",
        "hodur_flag2.json",
        {"lines": 325, "returns": 8, "whiles": 3, "gotos": 7},
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
