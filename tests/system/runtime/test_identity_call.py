"""System tests for IdentityCallResolver.

These tests run against real libobfuscated binaries in IDA runtime and validate
identity-wrapper call handling end-to-end.
"""
from __future__ import annotations

import os
import platform

import pytest

from d810.testing.cases import DeobfuscationCase
from d810.testing.runner import run_deobfuscation_test


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


IDENTITY_CALL_SIMPLE = DeobfuscationCase(
    function="identity_call_simple",
    description=(
        "Identity wrapper around branch-selected function pointer. "
        "Currently used as a stability/coverage case for resolver detection."
    ),
    project="identity_call.json",
    must_change=False,
    check_stats=True,
)

IDENTITY_CALL_TRAMPOLINE_CHAIN = DeobfuscationCase(
    function="identity_call_trampoline_chain",
    description=(
        "Identity wrapper + trampoline global should rewrite indirect call "
        "to a direct call target."
    ),
    project="identity_call.json",
    must_change=True,
    check_stats=True,
    required_rules=["IdentityCallResolver"],
    deobfuscated_not_contains=["identity_func("],
    acceptable_patterns=["trampoline_wrapper(", "sub_"],
)

IDENTITY_CALL_DUAL_ENTRY_TABLE = DeobfuscationCase(
    function="identity_call_dual_entry_table",
    description=(
        "Dual-entry table with identical targets should collapse to a direct call."
    ),
    project="identity_call.json",
    must_change=True,
    check_stats=True,
    required_rules=["IdentityCallResolver"],
    deobfuscated_not_contains=["identity_func("],
    acceptable_patterns=["identity_helper_xor(", "sub_"],
)

IDENTITY_CALL_SELF_REFERENCE = DeobfuscationCase(
    function="identity_call_self_reference",
    description=(
        "Self-referencing target should be detected and left untouched to avoid "
        "introducing recursive direct-call rewrites."
    ),
    project="identity_call.json",
    must_change=False,
    check_stats=True,
    acceptable_patterns=["identity_func(", "sub_18000BF40("],
)


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    """Setup fixture for libobfuscated tests -- runs once per class."""
    import idaapi

    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestIdentityCallResolver:
    """System tests for IdentityCallResolver using real IDA decompilation."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_identity_call_simple(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        run_deobfuscation_test(
            case=IDENTITY_CALL_SIMPLE,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )

    @pytest.mark.ida_required
    def test_identity_call_trampoline_chain(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        run_deobfuscation_test(
            case=IDENTITY_CALL_TRAMPOLINE_CHAIN,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )

    @pytest.mark.ida_required
    def test_identity_call_dual_entry_table(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        run_deobfuscation_test(
            case=IDENTITY_CALL_DUAL_ENTRY_TABLE,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )

    @pytest.mark.ida_required
    def test_identity_call_annotations(
        self,
        libobfuscated_setup,
        d810_state,
    ):
        """Verify resolver leaves trace comments at rewritten callsites."""
        import idaapi
        import idautils
        import idc

        from d810.testing.runner import _resolve_test_project_index

        func_name = "identity_call_dual_entry_table"
        func_ea = idc.get_name_ea_simple(func_name)
        if func_ea == idaapi.BADADDR:
            func_ea = idc.get_name_ea_simple("_" + func_name)
        assert func_ea != idaapi.BADADDR

        with d810_state() as state:
            project_index = _resolve_test_project_index(state, "identity_call.json")
            state.load_project(project_index)

            state.start_d810()
            cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert cfunc is not None

            comments = []
            for ea in idautils.FuncItems(func_ea):
                cmt = idaapi.get_cmt(ea, False)
                if cmt:
                    comments.append(cmt)

            assert any("Resolved indirect call ->" in c for c in comments), comments

    @pytest.mark.ida_required
    def test_identity_call_self_reference_skip(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        run_deobfuscation_test(
            case=IDENTITY_CALL_SELF_REFERENCE,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )
