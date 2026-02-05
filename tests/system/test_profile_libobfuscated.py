"""Profile d810 deobfuscation performance on libobfuscated binary.

Run with:
    pytest tests/system/test_profile_libobfuscated.py -v -s

This generates an HTML profile report in the test output.

Supports both:
- libobfuscated.dll (Windows PE)
- libobfuscated.dylib (macOS x86_64)
"""

from __future__ import annotations

import platform

import pytest

import idaapi
import idc

try:
    import pyinstrument
    PYINSTRUMENT_AVAILABLE = True
except ImportError:
    PYINSTRUMENT_AVAILABLE = False


def get_func_ea(name: str) -> int:
    """Get function address by name, handling macOS underscore prefix."""
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)  # macOS prefix
    return ea


# Functions to profile from libobfuscated binary
FUNCTIONS_TO_PROFILE = [
    "test_chained_add",
    "test_cst_simplification",
    "test_opaque_predicate",
    "test_xor",
    "test_mba_guessing",
]


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    """Setup fixture for libobfuscated tests."""
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


@pytest.mark.skipif(not PYINSTRUMENT_AVAILABLE, reason="pyinstrument not installed")
class TestProfileLibObfuscated:
    """Profile d810 deobfuscation performance."""

    # Use platform-appropriate binary
    binary_name = "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"

    def test_profile_all_functions(self, libobfuscated_setup, d810_state):
        """Profile deobfuscation of all test functions."""
        profiler = pyinstrument.Profiler()

        # Collect function addresses
        func_addresses = []
        for func_name in FUNCTIONS_TO_PROFILE:
            func_ea = get_func_ea(func_name)
            if func_ea != idaapi.BADADDR:
                func_addresses.append((func_name, func_ea))
            else:
                print(f"Warning: Function '{func_name}' not found")

        if not func_addresses:
            pytest.skip("No test functions found in database")

        iterations = 3  # Multiple iterations for better profiling data

        with d810_state() as state:
            state.start_d810()

            # Profile decompilation
            profiler.start()

            for _ in range(iterations):
                for func_name, func_ea in func_addresses:
                    try:
                        result = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                        if result is None:
                            print(f"Warning: Decompilation failed for {func_name}")
                    except Exception as e:
                        print(f"Error decompiling {func_name}: {e}")

            profiler.stop()

        # Print profile results
        print("\n" + "=" * 80)
        print("PYINSTRUMENT PROFILE RESULTS")
        print("=" * 80)
        print(profiler.output_text(unicode=True, color=True))

        # Save HTML report
        html_output = profiler.output_html()
        report_path = "/tmp/d810_profile_libobfuscated.html"
        with open(report_path, "w") as f:
            f.write(html_output)
        print(f"\nHTML report saved to: {report_path}")

    def test_profile_mba_guessing(self, libobfuscated_setup, d810_state):
        """Profile MBA guessing function specifically (heaviest workload)."""
        func_ea = get_func_ea("test_mba_guessing")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'test_mba_guessing' not found")

        profiler = pyinstrument.Profiler()
        iterations = 10

        with d810_state() as state:
            state.start_d810()

            profiler.start()
            for _ in range(iterations):
                idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            profiler.stop()

        print("\n" + "=" * 80)
        print(f"PROFILE: test_mba_guessing ({iterations} iterations)")
        print("=" * 80)
        print(profiler.output_text(unicode=True, color=True))

        # Save HTML report
        html_output = profiler.output_html()
        report_path = "/tmp/d810_profile_mba_guessing.html"
        with open(report_path, "w") as f:
            f.write(html_output)
        print(f"\nHTML report saved to: {report_path}")

    def test_profile_xor(self, libobfuscated_setup, d810_state):
        """Profile XOR simplification specifically."""
        func_ea = get_func_ea("test_xor")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'test_xor' not found")

        profiler = pyinstrument.Profiler()
        iterations = 10

        with d810_state() as state:
            with state.for_project("example_libobfuscated.json"):
                state.start_d810()

                profiler.start()
                for _ in range(iterations):
                    idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                profiler.stop()

        print("\n" + "=" * 80)
        print(f"PROFILE: test_xor ({iterations} iterations)")
        print("=" * 80)
        print(profiler.output_text(unicode=True, color=True))

        # Save HTML report
        html_output = profiler.output_html()
        report_path = "/tmp/d810_profile_xor.html"
        with open(report_path, "w") as f:
            f.write(html_output)
        print(f"\nHTML report saved to: {report_path}")
