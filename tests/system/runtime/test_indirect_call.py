"""System tests for IndirectCallResolver (copycat Phase 6).

Tests that IndirectCallResolver correctly detects indirect call
instructions (m_icall / m_call with register targets), locates the
associated function pointer table, traces the index and sub-offset,
and replaces the indirect call with a direct m_call in real IDA Pro
microcode.

These tests require IDA Pro with Hex-Rays decompiler and exercise the
optimizer against real binaries -- no mocks.

Sample requirements:
    A binary containing functions with indirect calls through function
    pointer tables (e.g., Hikari-style vtable obfuscation with
    sub-offset encoding).  The libobfuscated sample does not currently
    contain such patterns.  These tests are structured and ready to run
    once an appropriate sample is added.
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


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------
# IndirectCallResolver handles m_icall and m_call-with-register-target
# instructions by locating the associated function pointer table,
# tracing the index computation (via register/stack variable tracking),
# extracting any sub-offset encoding, computing the target EA, and
# replacing the indirect call with a direct m_call.
#
# This pattern appears in Hikari-obfuscated binaries with vtable
# obfuscation.  The libobfuscated sample does not contain these
# patterns, so tests are marked as needing a dedicated sample.
# ---------------------------------------------------------------------------

INDIRECT_CALL_CASES = [
    DeobfuscationCase(
        function="indirect_call_vtable_sub",
        description=(
            "Function with indirect call through a function pointer table "
            "using sub-offset encoding.  IndirectCallResolver should trace "
            "the index, extract the sub-offset, compute the target, and "
            "convert m_icall to m_call."
        ),
        project="default.json",
        must_change=True,
        check_stats=True,
        required_rules=["IndirectCallResolver"],
        skip="Needs test binary with sub-offset encoded function pointer table",
    ),
    DeobfuscationCase(
        function="indirect_call_register_target",
        description=(
            "Function with m_call using a register target (computed from "
            "table lookup).  IndirectCallResolver should resolve the "
            "register value and replace with a direct call."
        ),
        project="default.json",
        must_change=True,
        check_stats=True,
        required_rules=["IndirectCallResolver"],
        skip="Needs test binary with register-target indirect calls",
    ),
    DeobfuscationCase(
        function="indirect_call_hikari_mov_sub",
        description=(
            "Hikari-style indirect call pattern: mov+ldx+sub+icall.  "
            "IndirectCallResolver should detect the full pattern chain "
            "and resolve the target function."
        ),
        project="default.json",
        must_change=True,
        check_stats=True,
        required_rules=["IndirectCallResolver"],
        skip="Needs test binary with Hikari mov+sub indirect call pattern",
    ),
]


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    """Setup fixture for libobfuscated tests -- runs once per class."""
    import idaapi
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestIndirectCallResolver:
    """System tests for IndirectCallResolver using real IDA Pro decompilation.

    IndirectCallResolver detects indirect calls (m_icall or m_call
    with register/computed targets), locates the function pointer
    table, traces index computation through register and stack variable
    assignments, extracts sub-offset encoding, and replaces the
    indirect call with a direct m_call to the resolved target.
    """

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    @pytest.mark.parametrize(
        "case", INDIRECT_CALL_CASES, ids=lambda c: c.test_id
    )
    def test_indirect_call_resolver(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """Verify IndirectCallResolver resolves indirect calls."""
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )


# ---------------------------------------------------------------------------
# Attribute and constant verification tests
# ---------------------------------------------------------------------------

class TestIndirectCallResolverAttributes:
    """Verify IndirectCallResolver class attributes with real IDA constants."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_name(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.indirect_call import (
            IndirectCallResolver,
        )
        assert IndirectCallResolver.NAME == "IndirectCallResolver"

    @pytest.mark.ida_required
    def test_description_mentions_indirect_call(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.indirect_call import (
            IndirectCallResolver,
        )
        assert "indirect call" in IndirectCallResolver.DESCRIPTION.lower()

    @pytest.mark.ida_required
    def test_uses_deferred_cfg_is_true(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.indirect_call import (
            IndirectCallResolver,
        )
        assert IndirectCallResolver.USES_DEFERRED_CFG is True

    @pytest.mark.ida_required
    def test_max_table_entries(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.indirect_call import (
            IndirectCallResolver,
        )
        assert IndirectCallResolver.MAX_TABLE_ENTRIES == 512

    @pytest.mark.ida_required
    def test_default_entry_size(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.indirect_call import (
            IndirectCallResolver,
        )
        assert IndirectCallResolver.DEFAULT_ENTRY_SIZE == 8

    @pytest.mark.ida_required
    def test_min_sub_offset(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.indirect_call import (
            IndirectCallResolver,
        )
        assert IndirectCallResolver.MIN_SUB_OFFSET == 0x10000

    @pytest.mark.ida_required
    def test_max_sub_offset(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.indirect_call import (
            IndirectCallResolver,
        )
        assert IndirectCallResolver.MAX_SUB_OFFSET == 0x1000000

    @pytest.mark.ida_required
    def test_safe_maturities_uses_real_constants(self, libobfuscated_setup):
        """SAFE_MATURITIES should contain real IDA maturity values."""
        from d810.optimizers.microcode.flow.indirect_call import (
            IndirectCallResolver,
        )
        assert isinstance(IndirectCallResolver.SAFE_MATURITIES, list)
        for mat in IndirectCallResolver.SAFE_MATURITIES:
            assert isinstance(mat, int)


# ---------------------------------------------------------------------------
# Module-level constant tests
# ---------------------------------------------------------------------------

class TestModuleConstants:
    """Verify module-level constants with real IDA imports."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_max_table_entries_module_level(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.indirect_call import MAX_TABLE_ENTRIES
        assert MAX_TABLE_ENTRIES == 512

    @pytest.mark.ida_required
    def test_default_entry_size_module_level(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.indirect_call import DEFAULT_ENTRY_SIZE
        assert DEFAULT_ENTRY_SIZE == 8

    @pytest.mark.ida_required
    def test_min_sub_offset_module_level(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.indirect_call import MIN_SUB_OFFSET
        assert MIN_SUB_OFFSET == 0x10000

    @pytest.mark.ida_required
    def test_max_sub_offset_module_level(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.indirect_call import MAX_SUB_OFFSET
        assert MAX_SUB_OFFSET == 0x1000000
