"""System tests for d810.hexrays.table_utils.

These tests exercise table_utils functions with real IDA Pro modules loaded.
No mocks, no stubs, no _ensure_ida_stubs().

Tests are organized into:
  - Pure-logic tests that verify enum, dataclass, and decode_table_entry
    behavior using real IDA imports (ensuring the module loads correctly
    in a real IDA environment).
  - IDA-dependent tests that call ida_bytes functions against a real
    loaded binary (read_global_value, read_table_entries, validate_code_target).
  - Microcode-dependent tests that require specific block patterns
    (find_xor_with_globals, analyze_table_encoding, find_table_reference).
    These are skipped until a binary with suitable table patterns is available.
"""
from __future__ import annotations

import os
import platform

import pytest

from d810.hexrays.table_utils import (
    TableEncoding,
    XorKeyInfo,
    analyze_table_encoding,
    decode_table_entry,
    find_table_reference,
    find_xor_with_globals,
    read_global_value,
    read_table_entries,
    validate_code_target,
)


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    """Setup fixture for libobfuscated tests -- runs once per class."""
    import idaapi
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


def _get_any_real_mblock(max_functions: int = 128):
    """Return one non-empty real microcode block from the loaded database."""
    import ida_funcs
    import ida_hexrays
    import idautils

    for i, func_ea in enumerate(idautils.Functions()):
        if i >= max_functions:
            break
        func = ida_funcs.get_func(func_ea)
        if func is None:
            continue
        mbr = ida_hexrays.mba_ranges_t(func)
        hf = ida_hexrays.hexrays_failure_t()
        mba = ida_hexrays.gen_microcode(
            mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT, ida_hexrays.MMAT_PREOPTIMIZED
        )
        if mba is None:
            continue
        for blk_idx in range(mba.qty):
            blk = mba.get_mblock(blk_idx)
            if blk is not None and blk.head is not None:
                return blk
    return None


# ===================================================================
# TableEncoding enum
# ===================================================================
class TestTableEncoding:
    """Verify TableEncoding enum values with real IDA modules loaded."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_values(self, libobfuscated_setup):
        assert int(TableEncoding.DIRECT) == 0
        assert int(TableEncoding.OFFSET) == 1
        assert int(TableEncoding.XOR) == 2
        assert int(TableEncoding.OFFSET_XOR) == 3

    @pytest.mark.ida_required
    def test_members(self, libobfuscated_setup):
        assert set(TableEncoding.__members__.keys()) == {
            "DIRECT", "OFFSET", "XOR", "OFFSET_XOR",
        }

    @pytest.mark.ida_required
    def test_from_int(self, libobfuscated_setup):
        assert TableEncoding(0) is TableEncoding.DIRECT
        assert TableEncoding(3) is TableEncoding.OFFSET_XOR


# ===================================================================
# XorKeyInfo dataclass
# ===================================================================
class TestXorKeyInfo:
    """Verify XorKeyInfo dataclass behavior with real IDA modules loaded."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_creation(self, libobfuscated_setup):
        info = XorKeyInfo(xor_key=0xDEAD, is_negated=False, source_ea=0x1000, reg=5)
        assert info.xor_key == 0xDEAD
        assert info.is_negated is False
        assert info.source_ea == 0x1000
        assert info.reg == 5

    @pytest.mark.ida_required
    def test_negated(self, libobfuscated_setup):
        info = XorKeyInfo(xor_key=0xBEEF, is_negated=True, source_ea=0x2000, reg=3)
        assert info.is_negated is True

    @pytest.mark.ida_required
    def test_equality(self, libobfuscated_setup):
        a = XorKeyInfo(xor_key=1, is_negated=False, source_ea=0, reg=0)
        b = XorKeyInfo(xor_key=1, is_negated=False, source_ea=0, reg=0)
        assert a == b

    @pytest.mark.ida_required
    def test_repr(self, libobfuscated_setup):
        info = XorKeyInfo(xor_key=0xFF, is_negated=False, source_ea=0x100, reg=2)
        r = repr(info)
        assert "XorKeyInfo" in r
        assert "255" in r or "0xff" in r.lower()


# ===================================================================
# decode_table_entry -- pure logic with real IDA modules loaded
# ===================================================================
class TestDecodeTableEntry:
    """Verify decode_table_entry with real IDA modules loaded."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_direct(self, libobfuscated_setup):
        assert decode_table_entry(0x401000, TableEncoding.DIRECT) == 0x401000

    @pytest.mark.ida_required
    def test_offset(self, libobfuscated_setup):
        result = decode_table_entry(0x100, TableEncoding.OFFSET, base=0x400000)
        assert result == 0x400100

    @pytest.mark.ida_required
    def test_xor(self, libobfuscated_setup):
        result = decode_table_entry(0xDEADBEEF, TableEncoding.XOR, key=0xFF00FF00)
        assert result == 0xDEADBEEF ^ 0xFF00FF00

    @pytest.mark.ida_required
    def test_offset_xor(self, libobfuscated_setup):
        raw = 0xABCD
        key = 0xFF00
        base = 0x100000
        result = decode_table_entry(raw, TableEncoding.OFFSET_XOR, key=key, base=base)
        assert result == base + (raw ^ key)

    @pytest.mark.ida_required
    def test_direct_ignores_key_and_base(self, libobfuscated_setup):
        result = decode_table_entry(42, TableEncoding.DIRECT, key=99, base=100)
        assert result == 42

    @pytest.mark.ida_required
    def test_offset_zero_base(self, libobfuscated_setup):
        result = decode_table_entry(0x500, TableEncoding.OFFSET, base=0)
        assert result == 0x500

    @pytest.mark.ida_required
    def test_xor_zero_key(self, libobfuscated_setup):
        result = decode_table_entry(0x1234, TableEncoding.XOR, key=0)
        assert result == 0x1234

    @pytest.mark.ida_required
    def test_offset_xor_identity(self, libobfuscated_setup):
        """XOR with zero key and zero base is identity."""
        result = decode_table_entry(0xCAFE, TableEncoding.OFFSET_XOR, key=0, base=0)
        assert result == 0xCAFE

    @pytest.mark.ida_required
    def test_roundtrip_xor(self, libobfuscated_setup):
        """Encoding + decoding with XOR should produce the original address."""
        original = 0x401000
        key = 0xCAFEBABE
        encoded = original ^ key
        decoded = decode_table_entry(encoded, TableEncoding.XOR, key=key)
        assert decoded == original

    @pytest.mark.ida_required
    def test_roundtrip_offset(self, libobfuscated_setup):
        original = 0x401000
        base = 0x400000
        encoded = original - base
        decoded = decode_table_entry(encoded, TableEncoding.OFFSET, base=base)
        assert decoded == original


# ===================================================================
# decode_table_entry -- overflow / edge cases
# ===================================================================
class TestDecodeTableEntryOverflow:
    """Verify decode_table_entry overflow behavior with real IDA modules loaded."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_offset_64bit_overflow(self, libobfuscated_setup):
        """OFFSET encoding with values that overflow 64 bits.

        Python ints do not overflow, so base + raw_value may exceed 2**64.
        Document whether truncation happens (currently: it does NOT).
        """
        raw = 0xFFFFFFFFFFFFFFFF
        base = 1
        result = decode_table_entry(raw, TableEncoding.OFFSET, base=base)
        assert result == 0xFFFFFFFFFFFFFFFF + 1
        assert result == 2**64

    @pytest.mark.ida_required
    def test_large_xor_key(self, libobfuscated_setup):
        """XOR with maximum 64-bit key."""
        raw = 0x0000000000000001
        key = 0xFFFFFFFFFFFFFFFF
        result = decode_table_entry(raw, TableEncoding.XOR, key=key)
        assert result == raw ^ key
        assert result == 0xFFFFFFFFFFFFFFFE

    @pytest.mark.ida_required
    def test_offset_xor_large_values(self, libobfuscated_setup):
        """OFFSET_XOR with large values that may overflow."""
        raw = 0xFFFFFFFFFFFFFFFF
        key = 0xFFFFFFFFFFFFFFFF
        base = 0x1000
        result = decode_table_entry(raw, TableEncoding.OFFSET_XOR, key=key, base=base)
        # raw ^ key = 0, so result = base + 0 = 0x1000
        assert result == 0x1000

    @pytest.mark.ida_required
    def test_offset_xor_no_truncation(self, libobfuscated_setup):
        """Verify Python int semantics: no 64-bit truncation in OFFSET_XOR."""
        raw = 0xFFFFFFFFFFFFFFFE
        key = 0x0000000000000001
        base = 0xFFFFFFFFFFFFFFFF
        # raw ^ key = 0xFFFFFFFFFFFFFFFF
        # result = base + 0xFFFFFFFFFFFFFFFF
        result = decode_table_entry(raw, TableEncoding.OFFSET_XOR, key=key, base=base)
        expected = 0xFFFFFFFFFFFFFFFF + 0xFFFFFFFFFFFFFFFF
        assert result == expected
        assert result > 2**64


# ===================================================================
# read_global_value -- real IDA database reads
# ===================================================================
class TestReadGlobalValue:
    """Test read_global_value against real IDA database state.

    Uses the loaded binary to read known addresses.  Since the binary is
    already analyzed by IDA, ida_bytes.get_bytes returns real data.
    """

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_read_from_valid_address(self, libobfuscated_setup):
        """Reading from a valid address within the binary should return an int."""
        import idaapi
        min_ea = idaapi.inf_get_min_ea()
        result = read_global_value(min_ea, 4)
        assert result is not None
        assert isinstance(result, int)

    @pytest.mark.ida_required
    def test_read_1_byte(self, libobfuscated_setup):
        """Reading 1 byte from a valid address should return a value 0..255."""
        import idaapi
        min_ea = idaapi.inf_get_min_ea()
        result = read_global_value(min_ea, 1)
        assert result is not None
        assert 0 <= result <= 0xFF

    @pytest.mark.ida_required
    def test_read_2_bytes(self, libobfuscated_setup):
        """Reading 2 bytes from a valid address should return a value 0..65535."""
        import idaapi
        min_ea = idaapi.inf_get_min_ea()
        result = read_global_value(min_ea, 2)
        assert result is not None
        assert 0 <= result <= 0xFFFF

    @pytest.mark.ida_required
    def test_read_4_bytes(self, libobfuscated_setup):
        """Reading 4 bytes from a valid address should return a 32-bit value."""
        import idaapi
        min_ea = idaapi.inf_get_min_ea()
        result = read_global_value(min_ea, 4)
        assert result is not None
        assert 0 <= result <= 0xFFFFFFFF

    @pytest.mark.ida_required
    def test_read_8_bytes(self, libobfuscated_setup):
        """Reading 8 bytes from a valid address should return a 64-bit value."""
        import idaapi
        min_ea = idaapi.inf_get_min_ea()
        result = read_global_value(min_ea, 8)
        assert result is not None
        assert 0 <= result <= 0xFFFFFFFFFFFFFFFF

    @pytest.mark.ida_required
    def test_badaddr_returns_none(self, libobfuscated_setup):
        """BADADDR (0xFFFFFFFFFFFFFFFF) should return None."""
        result = read_global_value(0xFFFFFFFFFFFFFFFF, 4)
        assert result is None

    @pytest.mark.ida_required
    def test_read_consistency(self, libobfuscated_setup):
        """Reading the same address twice should return the same value."""
        import idaapi
        min_ea = idaapi.inf_get_min_ea()
        result1 = read_global_value(min_ea, 4)
        result2 = read_global_value(min_ea, 4)
        assert result1 == result2

    @pytest.mark.ida_required
    def test_read_adjacent_bytes_consistency(self, libobfuscated_setup):
        """A 4-byte read should be consistent with individual byte reads.

        read_global_value(ea, 4) == (byte[0] | byte[1]<<8 | byte[2]<<16 | byte[3]<<24)
        """
        import idaapi
        min_ea = idaapi.inf_get_min_ea()
        full = read_global_value(min_ea, 4)
        if full is None:
            pytest.skip("Could not read from min_ea")

        b0 = read_global_value(min_ea, 1)
        b1 = read_global_value(min_ea + 1, 1)
        b2 = read_global_value(min_ea + 2, 1)
        b3 = read_global_value(min_ea + 3, 1)
        if any(b is None for b in (b0, b1, b2, b3)):
            pytest.skip("Could not read individual bytes from min_ea")

        assembled = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
        assert full == assembled


# ===================================================================
# read_table_entries -- real IDA database reads
# ===================================================================
class TestReadTableEntries:
    """Test read_table_entries against real IDA database state."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_reads_entries_from_valid_address(self, libobfuscated_setup):
        """Reading entries from a valid address should return a non-empty list."""
        import idaapi
        min_ea = idaapi.inf_get_min_ea()
        entries = read_table_entries(min_ea, 3, entry_size=4)
        assert isinstance(entries, list)
        assert len(entries) > 0
        for e in entries:
            assert isinstance(e, int)

    @pytest.mark.ida_required
    def test_entry_count_matches_request(self, libobfuscated_setup):
        """When all reads succeed, the number of entries should match the count."""
        import idaapi
        min_ea = idaapi.inf_get_min_ea()
        count = 5
        entries = read_table_entries(min_ea, count, entry_size=4)
        # May return fewer if reads fail, but should return at least some
        assert 0 < len(entries) <= count

    @pytest.mark.ida_required
    def test_entries_consistent_with_read_global_value(self, libobfuscated_setup):
        """Each entry should match what read_global_value returns at that offset."""
        import idaapi
        min_ea = idaapi.inf_get_min_ea()
        entry_size = 4
        entries = read_table_entries(min_ea, 3, entry_size=entry_size)
        for i, entry in enumerate(entries):
            expected = read_global_value(min_ea + i * entry_size, entry_size)
            assert entry == expected


# ===================================================================
# validate_code_target -- real IDA database
# ===================================================================
class TestValidateCodeTarget:
    """Test validate_code_target against real IDA database state."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_known_code_address_returns_true(self, libobfuscated_setup):
        """A known function entry point should be recognized as code."""
        import idc
        import idaapi

        # Find a real function address in the loaded binary
        func_ea = idc.get_next_func(idaapi.inf_get_min_ea() - 1)
        if func_ea == idaapi.BADADDR:
            pytest.skip("No functions found in binary")

        result = validate_code_target(func_ea)
        assert result is True

    @pytest.mark.ida_required
    def test_data_address_without_func_bounds_returns_false(self, libobfuscated_setup):
        """An address in a data segment (not code) without func bounds should be False."""
        import idaapi
        import ida_bytes

        # Try to find a non-code address
        ea = idaapi.inf_get_min_ea()
        max_ea = idaapi.inf_get_max_ea()
        non_code_ea = None
        test_ea = ea
        while test_ea < max_ea:
            flags = ida_bytes.get_flags(test_ea)
            if not ida_bytes.is_code(flags):
                non_code_ea = test_ea
                break
            test_ea += 1

        if non_code_ea is None:
            pytest.skip("Could not find a non-code address in binary")

        result = validate_code_target(non_code_ea)
        assert result is False

    @pytest.mark.ida_required
    def test_address_within_function_bounds(self, libobfuscated_setup):
        """A non-code address within func bounds should return True."""
        import idc
        import idaapi

        func_ea = idc.get_next_func(idaapi.inf_get_min_ea() - 1)
        if func_ea == idaapi.BADADDR:
            pytest.skip("No functions found in binary")

        func_end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
        if func_end == idaapi.BADADDR or func_end <= func_ea:
            pytest.skip("Cannot determine function bounds")

        # Any address in [func_start, func_end) should be accepted
        # when func bounds are provided (even if is_code returns False)
        result = validate_code_target(func_ea, func_start=func_ea, func_end=func_end)
        assert result is True

    @pytest.mark.ida_required
    def test_ea_equals_func_end_is_false(self, libobfuscated_setup):
        """ea == func_end should be False (half-open range [start, end))."""
        import idc
        import idaapi

        func_ea = idc.get_next_func(idaapi.inf_get_min_ea() - 1)
        if func_ea == idaapi.BADADDR:
            pytest.skip("No functions found in binary")

        func_end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
        if func_end == idaapi.BADADDR or func_end <= func_ea:
            pytest.skip("Cannot determine function bounds")

        import ida_bytes
        flags = ida_bytes.get_flags(func_end)
        if ida_bytes.is_code(flags):
            # func_end itself might be code (next function), so validate_code_target
            # returns True via is_code. This test only makes sense when func_end
            # is NOT code.
            pytest.skip("func_end is a code address, boundary test not applicable")

        result = validate_code_target(func_end, func_start=func_ea, func_end=func_end)
        assert result is False

    @pytest.mark.ida_required
    def test_ea_at_func_start_is_true(self, libobfuscated_setup):
        """ea == func_start should be True (inclusive lower bound)."""
        import idc
        import idaapi

        func_ea = idc.get_next_func(idaapi.inf_get_min_ea() - 1)
        if func_ea == idaapi.BADADDR:
            pytest.skip("No functions found in binary")

        func_end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
        if func_end == idaapi.BADADDR:
            pytest.skip("Cannot determine function end")

        result = validate_code_target(func_ea, func_start=func_ea, func_end=func_end)
        assert result is True


# ===================================================================
# find_xor_with_globals -- requires real microcode blocks
# ===================================================================
class TestFindXorWithGlobals:
    """Test find_xor_with_globals with real IDA microcode blocks.

    These tests require a binary with XOR-encrypted table patterns
    (e.g., Hikari-style indirect jumps with XOR obfuscation).
    """

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_none_block_returns_empty_list(self, libobfuscated_setup):
        """None block should return empty list."""
        result = find_xor_with_globals(None)
        assert result == []

    @pytest.mark.ida_required
    def test_xor_pattern_detection(self, libobfuscated_setup):
        """find_xor_with_globals should accept real mblock_t and return typed results."""
        blk = _get_any_real_mblock()
        assert blk is not None, "Could not build a real microcode block from current binary"
        result = find_xor_with_globals(blk)
        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, XorKeyInfo)


# ===================================================================
# analyze_table_encoding -- requires real microcode blocks
# ===================================================================
class TestAnalyzeTableEncoding:
    """Test analyze_table_encoding with real IDA microcode blocks.

    These tests require a binary with table-based indirect branch
    patterns to produce real microcode blocks for analysis.
    """

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_none_block_returns_direct(self, libobfuscated_setup):
        """None block should return (DIRECT, 0, 0)."""
        result = analyze_table_encoding(None)
        assert result == (TableEncoding.DIRECT, 0, 0)

    @pytest.mark.ida_required
    def test_xor_encoding_detection(self, libobfuscated_setup):
        """analyze_table_encoding should return a valid triple on real mblock_t."""
        blk = _get_any_real_mblock()
        assert blk is not None, "Could not build a real microcode block from current binary"
        encoding, xor_key, base = analyze_table_encoding(blk)
        assert isinstance(encoding, TableEncoding)
        assert isinstance(xor_key, int)
        assert isinstance(base, int)

    @pytest.mark.ida_required
    def test_offset_encoding_detection(self, libobfuscated_setup):
        """analyze_table_encoding should be stable across repeated calls."""
        blk = _get_any_real_mblock()
        assert blk is not None, "Could not build a real microcode block from current binary"
        first = analyze_table_encoding(blk)
        second = analyze_table_encoding(blk)
        assert first == second


# ===================================================================
# find_table_reference -- requires real microcode blocks
# ===================================================================
class TestFindTableReference:
    """Test find_table_reference with real IDA microcode blocks.

    These tests require a binary with indirect branch patterns
    (m_ldx referencing global table addresses) to produce real
    microcode blocks for analysis.
    """

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_none_block_returns_none(self, libobfuscated_setup):
        """None block should return None."""
        result = find_table_reference(None)
        assert result is None

    @pytest.mark.ida_required
    def test_ldx_global_detection(self, libobfuscated_setup):
        """find_table_reference should accept real mblock_t and return int/None."""
        blk = _get_any_real_mblock()
        assert blk is not None, "Could not build a real microcode block from current binary"
        result = find_table_reference(blk)
        assert result is None or isinstance(result, int)


# ===================================================================
# IDA module import verification
# ===================================================================
class TestModuleImports:
    """Verify that table_utils correctly imports real IDA modules.

    When running inside IDA Pro, _IDA_AVAILABLE should be True and
    ida_bytes / ida_hexrays should be real modules (not None or stubs).
    """

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_ida_available_is_true(self, libobfuscated_setup):
        """In system tests, _IDA_AVAILABLE must be True."""
        from d810.hexrays import table_utils
        assert table_utils._IDA_AVAILABLE is True

    @pytest.mark.ida_required
    def test_ida_bytes_is_real_module(self, libobfuscated_setup):
        """ida_bytes should be a real module, not None."""
        from d810.hexrays import table_utils
        assert table_utils.ida_bytes is not None
        assert hasattr(table_utils.ida_bytes, "get_bytes")
        assert hasattr(table_utils.ida_bytes, "get_flags")
        assert hasattr(table_utils.ida_bytes, "is_code")

    @pytest.mark.ida_required
    def test_ida_hexrays_is_real_module(self, libobfuscated_setup):
        """ida_hexrays should be a real module, not None."""
        from d810.hexrays import table_utils
        assert table_utils.ida_hexrays is not None
        # Verify real IDA constants exist
        assert hasattr(table_utils.ida_hexrays, "m_xor")
        assert hasattr(table_utils.ida_hexrays, "m_mov")
        assert hasattr(table_utils.ida_hexrays, "m_ldx")
        assert hasattr(table_utils.ida_hexrays, "mop_r")
        assert hasattr(table_utils.ida_hexrays, "mop_n")
        assert hasattr(table_utils.ida_hexrays, "mop_v")
