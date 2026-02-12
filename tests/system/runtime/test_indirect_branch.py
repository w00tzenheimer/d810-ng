"""System tests for IndirectBranchResolver (Chernobog Phase 5).

Tests that IndirectBranchResolver correctly detects m_ijmp instructions,
locates jump tables (via switch_info or known symbol names), decodes
table entries, and converts indirect jumps to direct gotos in real IDA
Pro microcode.

These tests require IDA Pro with Hex-Rays decompiler and exercise the
optimizer against real binaries -- no mocks.

Sample requirements:
    A binary containing functions with indirect jumps through encrypted
    or offset-based jump tables.  The libobfuscated sample does not
    currently contain such patterns (it uses switch-based flattening,
    not raw indirect jumps through encrypted tables).  These tests are
    structured and ready to run once an appropriate sample is added.
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
# IndirectBranchResolver handles m_ijmp (indirect jump) instructions
# by locating the associated jump table, decoding its entries (which
# may be XOR-encrypted or offset-encoded), and converting the ijmp
# to a direct m_goto.
#
# This pattern appears in Hikari-obfuscated binaries and some custom
# protections.  The libobfuscated sample primarily uses switch-based
# flattening (which is handled by the unflattener), so we mark these
# tests as needing a dedicated sample binary.
# ---------------------------------------------------------------------------

INDIRECT_BRANCH_CASES = [
    DeobfuscationCase(
        function="indirect_jump_table_xor",
        description=(
            "Function with XOR-encrypted indirect jump table.  "
            "IndirectBranchResolver should decode the table entries "
            "and convert m_ijmp to m_goto."
        ),
        project="default.json",
        must_change=True,
        check_stats=True,
        required_rules=["IndirectBranchResolver"],
        skip="Needs test binary with XOR-encrypted indirect jump table",
    ),
    DeobfuscationCase(
        function="indirect_jump_table_offset",
        description=(
            "Function with offset-encoded indirect jump table.  "
            "IndirectBranchResolver should decode base+offset entries "
            "and convert m_ijmp to m_goto."
        ),
        project="default.json",
        must_change=True,
        check_stats=True,
        required_rules=["IndirectBranchResolver"],
        skip="Needs test binary with offset-encoded indirect jump table",
    ),
    DeobfuscationCase(
        function="indirect_jump_switch_info",
        description=(
            "Function with switch_info metadata.  IndirectBranchResolver "
            "should use IDA's switch_info_t to locate the jump table "
            "and resolve the indirect jump."
        ),
        project="default.json",
        must_change=True,
        check_stats=True,
        required_rules=["IndirectBranchResolver"],
        skip="Needs test binary with IDA-recognized switch/indirect jump",
    ),
]


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    """Setup fixture for libobfuscated tests -- runs once per class."""
    import idaapi
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestIndirectBranchResolver:
    """System tests for IndirectBranchResolver using real IDA Pro decompilation.

    IndirectBranchResolver detects m_ijmp instructions, locates the
    associated jump table (via switch_info or known Hikari symbol
    names), decodes potentially encrypted/offset entries, and converts
    the indirect jump to a direct goto.
    """

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    @pytest.mark.parametrize(
        "case", INDIRECT_BRANCH_CASES, ids=lambda c: c.test_id
    )
    def test_indirect_branch_resolver(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """Verify IndirectBranchResolver resolves indirect jumps."""
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

class TestIndirectBranchResolverAttributes:
    """Verify IndirectBranchResolver class attributes with real IDA constants."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_name(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.indirect_branch import (
            IndirectBranchResolver,
        )
        assert IndirectBranchResolver.NAME == "indirect_branch_resolver"

    @pytest.mark.ida_required
    def test_description_mentions_indirect(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.indirect_branch import (
            IndirectBranchResolver,
        )
        desc = IndirectBranchResolver.DESCRIPTION.lower()
        assert "indirect" in desc

    @pytest.mark.ida_required
    def test_safe_maturities_uses_real_constants(self, libobfuscated_setup):
        import ida_hexrays
        from d810.optimizers.microcode.flow.indirect_branch import (
            IndirectBranchResolver,
        )
        # SAFE_MATURITIES should contain real IDA maturity constants
        for mat in IndirectBranchResolver.SAFE_MATURITIES:
            assert isinstance(mat, int)

    @pytest.mark.ida_required
    def test_max_table_entries(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.indirect_branch import (
            MAX_TABLE_ENTRIES,
        )
        assert MAX_TABLE_ENTRIES == 512

    @pytest.mark.ida_required
    def test_max_consecutive_invalid(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.indirect_branch import (
            MAX_CONSECUTIVE_INVALID,
        )
        assert MAX_CONSECUTIVE_INVALID == 5

    @pytest.mark.ida_required
    def test_default_entry_size(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.indirect_branch import (
            DEFAULT_TABLE_ENTRY_SIZE,
        )
        assert DEFAULT_TABLE_ENTRY_SIZE == 8


# ---------------------------------------------------------------------------
# Table utility tests -- pure logic, but using real IDA module imports
# ---------------------------------------------------------------------------

class TestTableUtils:
    """Test table decoding utilities with real IDA modules loaded."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_decode_direct(self, libobfuscated_setup):
        from d810.hexrays.table_utils import TableEncoding, decode_table_entry
        assert decode_table_entry(0xDEAD, TableEncoding.DIRECT) == 0xDEAD

    @pytest.mark.ida_required
    def test_decode_offset(self, libobfuscated_setup):
        from d810.hexrays.table_utils import TableEncoding, decode_table_entry
        assert decode_table_entry(0x100, TableEncoding.OFFSET, base=0x4000) == 0x4100

    @pytest.mark.ida_required
    def test_decode_xor(self, libobfuscated_setup):
        from d810.hexrays.table_utils import TableEncoding, decode_table_entry
        assert decode_table_entry(0xFF00, TableEncoding.XOR, key=0x00FF) == 0xFFFF

    @pytest.mark.ida_required
    def test_decode_offset_xor(self, libobfuscated_setup):
        from d810.hexrays.table_utils import TableEncoding, decode_table_entry
        result = decode_table_entry(
            0xFF00, TableEncoding.OFFSET_XOR, key=0x00FF, base=0x1000
        )
        assert result == 0x10FFF

    @pytest.mark.ida_required
    def test_roundtrip_xor(self, libobfuscated_setup):
        """Encoding + decoding with XOR should produce the original address."""
        from d810.hexrays.table_utils import TableEncoding, decode_table_entry
        original = 0x401000
        key = 0xCAFEBABE
        encoded = original ^ key
        decoded = decode_table_entry(encoded, TableEncoding.XOR, key=key)
        assert decoded == original

    @pytest.mark.ida_required
    def test_roundtrip_offset(self, libobfuscated_setup):
        from d810.hexrays.table_utils import TableEncoding, decode_table_entry
        original = 0x401000
        base = 0x400000
        encoded = original - base
        decoded = decode_table_entry(encoded, TableEncoding.OFFSET, base=base)
        assert decoded == original

    @pytest.mark.ida_required
    def test_table_encoding_enum_values(self, libobfuscated_setup):
        from d810.hexrays.table_utils import TableEncoding
        assert TableEncoding.DIRECT == 0
        assert TableEncoding.OFFSET == 1
        assert TableEncoding.XOR == 2
        assert TableEncoding.OFFSET_XOR == 3
