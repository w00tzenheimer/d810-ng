"""System tests for fetch_idb_value in d810.expr.emulator.

fetch_idb_value reads a value from the IDA database at a given address.
It supports sizes 1, 2, 4, and 8 bytes. All other sizes (including 0,
negative, and unsupported positive values) must return None.

These tests use real IDA APIs with libobfuscated.dll loaded.
"""

import pytest
import idaapi
import idc

from d810.expr.emulator import fetch_idb_value


@pytest.mark.ida_required
class TestFetchIdbValueSupportedSizes:
    """fetch_idb_value should delegate to the correct idaapi reader."""

    binary_name = "libobfuscated.dll"

    def test_size_1_calls_get_byte(self, ida_database):
        """Test reading a single byte from .rdata section.

        At address 0x180012000 in .rdata, we have the byte sequence:
        40 14 01 80 01 00 00 00 ...
        """
        # Use a known address in .rdata section
        test_addr = 0x180012000

        # Read using fetch_idb_value
        result = fetch_idb_value(test_addr, 1)

        # Verify it matches direct idaapi call
        expected = idaapi.get_byte(test_addr)
        assert result == expected
        assert result == 0x40

    def test_size_2_calls_get_word(self, ida_database):
        """Test reading a 2-byte word from .rdata section.

        At address 0x180012000 in .rdata, we have:
        40 14 (little-endian) = 0x1440
        """
        test_addr = 0x180012000

        result = fetch_idb_value(test_addr, 2)

        expected = idaapi.get_word(test_addr)
        assert result == expected
        assert result == 0x1440  # little-endian: 40 14

    def test_size_4_calls_get_dword(self, ida_database):
        """Test reading a 4-byte dword from .rdata section.

        At address 0x180012000 in .rdata, we have:
        40 14 01 80 (little-endian) = 0x80011440
        """
        test_addr = 0x180012000

        result = fetch_idb_value(test_addr, 4)

        expected = idaapi.get_dword(test_addr)
        assert result == expected
        assert result == 0x80011440  # little-endian: 40 14 01 80

    def test_size_8_calls_get_qword(self, ida_database):
        """Test reading an 8-byte qword from .rdata section.

        At address 0x180012000 in .rdata, we have:
        40 14 01 80 01 00 00 00 (little-endian) = 0x0000000180011440
        """
        test_addr = 0x180012000

        result = fetch_idb_value(test_addr, 8)

        expected = idaapi.get_qword(test_addr)
        assert result == expected
        assert result == 0x0000000180011440  # little-endian: 40 14 01 80 01 00 00 00


@pytest.mark.ida_required
class TestFetchIdbValueUnsupportedSizes:
    """fetch_idb_value must return None for unsupported sizes."""

    binary_name = "libobfuscated.dll"

    @pytest.mark.parametrize("bad_size", [0, 3, 5, 6, 7, 9, 16, 32, 64])
    def test_unsupported_positive_sizes_return_none(self, ida_database, bad_size):
        test_addr = 0x180012000
        assert fetch_idb_value(test_addr, bad_size) is None

    @pytest.mark.parametrize("bad_size", [-1, -2, -8])
    def test_negative_sizes_return_none(self, ida_database, bad_size):
        test_addr = 0x180012000
        assert fetch_idb_value(test_addr, bad_size) is None


@pytest.mark.ida_required
class TestFetchIdbValueEdgeCases:
    """Edge cases: different addresses and valid reads."""

    binary_name = "libobfuscated.dll"

    def test_different_rdata_offset(self, ida_database):
        """Test reading from a different offset in .rdata section.

        At address 0x180012010 in .rdata, we have:
        90 18 01 80 (little-endian) = 0x80011890
        """
        test_addr = 0x180012010

        result = fetch_idb_value(test_addr, 4)
        expected = idaapi.get_dword(test_addr)

        assert result == expected
        assert result == 0x80011890

    def test_text_section_read(self, ida_database):
        """Test reading from .text section (first bytes of code)."""
        # .text section starts at 0x180001000
        test_addr = 0x180001000

        # Just verify we can read and it matches direct idaapi call
        result = fetch_idb_value(test_addr, 1)
        expected = idaapi.get_byte(test_addr)

        assert result == expected
        assert result is not None

    def test_consistency_across_sizes(self, ida_database):
        """Verify that reading overlapping sizes yields consistent values.

        Reading a dword should equal combining two words, etc.
        """
        test_addr = 0x180012000

        # Read as individual bytes
        b0 = fetch_idb_value(test_addr, 1)
        b1 = fetch_idb_value(test_addr + 1, 1)
        b2 = fetch_idb_value(test_addr + 2, 1)
        b3 = fetch_idb_value(test_addr + 3, 1)

        # Read as dword
        dword = fetch_idb_value(test_addr, 4)

        # Reconstruct dword from bytes (little-endian)
        reconstructed = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)

        assert dword == reconstructed
