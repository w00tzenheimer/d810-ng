"""Manual utility test to dump before/after pseudocode for specific functions.

Usage:
    pytest -s tests/system/e2e/test_dump_function_pseudocode.py \
      --dump-function-pseudocode mixed_dispatcher_pattern \
      --dump-project example_libobfuscated.json

Multiple functions:
    pytest -s tests/system/e2e/test_dump_function_pseudocode.py \
      --dump-function-pseudocode "func_a,func_b,func_c"

Use default platform binary, or override with:
    D810_TEST_BINARY=libobfuscated.dll
"""

from __future__ import annotations

import os
import platform

import idaapi
import idc
import pytest

from d810.testing.runner import _resolve_test_project_index


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


def _get_func_ea(name: str) -> int:
    """Get function address by name, handling macOS underscore prefix."""
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    return ea


@pytest.mark.pseudocode_dump
class TestDumpFunctionPseudocode:
    """Ad-hoc pseudocode dump harness for local debugging."""

    binary_name = _get_default_binary()

    @pytest.fixture(scope="class")
    def _dump_target(self, request) -> str:
        raw = request.config.getoption("--dump-function-pseudocode")
        if not raw:
            pytest.skip("No --dump-function-pseudocode value provided")
        return raw

    @pytest.fixture(scope="class")
    def libobfuscated_setup(
        self,
        _dump_target,
        ida_database,
        configure_hexrays,
        setup_libobfuscated_funcs,
    ):
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")
        # Dump utility prefers fully expanded locals for copy/paste-compilable output.
        idaapi.change_hexrays_config("COLLAPSE_LVARS = NO")
        return ida_database

    def test_dump_function_pseudocode(
        self,
        request,
        _dump_target,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
    ):
        raw = _dump_target
        function_names = [name.strip() for name in raw.split(",") if name.strip()]
        if not function_names:
            raise AssertionError("No valid function names provided to --dump-function-pseudocode")

        use_project = not request.config.getoption("--dump-no-project")
        project_name = request.config.getoption("--dump-project")

        with d810_state() as state:
            if use_project:
                project_index = _resolve_test_project_index(state, project_name)
                state.load_project(project_index)

            for function_name in function_names:
                func_ea = _get_func_ea(function_name)
                if func_ea == idaapi.BADADDR:
                    raise AssertionError(f"Function '{function_name}' not found")

                state.stop_d810()
                before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                if before is None:
                    raise AssertionError(
                        f"Failed to decompile '{function_name}' without d810"
                    )
                code_before = pseudocode_to_string(before.get_pseudocode())

                state.stats.reset()
                state.start_d810()
                after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                if after is None:
                    raise AssertionError(
                        f"Failed to decompile '{function_name}' with d810"
                    )
                code_after = pseudocode_to_string(after.get_pseudocode())
                rules_fired = state.stats.get_fired_rule_names()

                print("\n" + "=" * 88)
                print(f"FUNCTION: {function_name} @ {hex(func_ea)}")
                print(f"BINARY: {self.binary_name}")
                print(f"PROJECT: {project_name if use_project else '<none>'}")
                print(f"CODE_CHANGED: {code_before != code_after}")
                print(
                    "RULES_FIRED: "
                    + (", ".join(rules_fired) if rules_fired else "<none>")
                )
                print("\n--- BEFORE ---")
                print(code_before)
                print("\n--- AFTER ---")
                print(code_after)
                print("=" * 88)
