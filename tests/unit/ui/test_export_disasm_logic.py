"""Unit tests for export disassembly logic layer.

These tests verify the pure Python logic without requiring IDA Pro.
"""
from __future__ import annotations

import pytest

from d810.ui.actions.export_disasm_logic import (
    DISASM_FORMATS,
    DisasmExportSettings,
    suggest_disasm_filename,
    to_ida_flags,
    to_ida_format_int,
)


class TestDisasmExportSettings:
    """Test DisasmExportSettings dataclass."""

    def test_default_values(self):
        """Test default values are correct."""
        settings = DisasmExportSettings()
        assert settings.format == "LST"
        assert settings.include_headers is True
        assert settings.include_segments is True
        assert settings.output_path == ""

    def test_custom_values(self):
        """Test custom values can be set."""
        settings = DisasmExportSettings(
            format="ASM",
            include_headers=False,
            include_segments=False,
            output_path="/tmp/output.asm",
        )
        assert settings.format == "ASM"
        assert settings.include_headers is False
        assert settings.include_segments is False
        assert settings.output_path == "/tmp/output.asm"


class TestDisasmFormats:
    """Test DISASM_FORMATS constant."""

    def test_has_all_formats(self):
        """Test all 4 formats are defined."""
        assert len(DISASM_FORMATS) == 4

    def test_format_structure(self):
        """Test each format is a (id, description) tuple."""
        for fmt in DISASM_FORMATS:
            assert isinstance(fmt, tuple)
            assert len(fmt) == 2
            assert isinstance(fmt[0], str)
            assert isinstance(fmt[1], str)

    def test_format_ids(self):
        """Test expected format IDs are present."""
        format_ids = [fmt[0] for fmt in DISASM_FORMATS]
        assert "ASM" in format_ids
        assert "LST" in format_ids
        assert "MAP" in format_ids
        assert "IDC" in format_ids


class TestToIdaFormatInt:
    """Test format string to integer mapping."""

    def test_asm_format(self):
        """Test ASM maps to 4 (ida_loader.OFILE_ASM)."""
        assert to_ida_format_int("ASM") == 4

    def test_lst_format(self):
        """Test LST maps to 3 (ida_loader.OFILE_LST)."""
        assert to_ida_format_int("LST") == 3

    def test_map_format(self):
        """Test MAP maps to 0 (ida_loader.OFILE_MAP)."""
        assert to_ida_format_int("MAP") == 0

    def test_idc_format(self):
        """Test IDC maps to 2 (ida_loader.OFILE_IDC)."""
        assert to_ida_format_int("IDC") == 2

    def test_invalid_format_raises(self):
        """Test invalid format raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            to_ida_format_int("INVALID")
        assert "Unknown format" in str(exc_info.value)
        assert "INVALID" in str(exc_info.value)

    def test_case_sensitive(self):
        """Test format matching is case-sensitive."""
        with pytest.raises(ValueError):
            to_ida_format_int("asm")  # lowercase should fail


class TestToIdaFlags:
    """Test flag bitmask generation."""

    def test_no_options(self):
        """Test no options produces zero flags."""
        settings = DisasmExportSettings(
            format="ASM", include_headers=False, include_segments=False
        )
        assert to_ida_flags(settings) == 0

    def test_headers_only(self):
        """Test include_headers sets GENFLG_ASMTYPE (0x0002)."""
        settings = DisasmExportSettings(
            format="ASM", include_headers=True, include_segments=False
        )
        assert to_ida_flags(settings) == 0x0002

    def test_segments_only(self):
        """Test include_segments sets MAP flags (0x007C)."""
        settings = DisasmExportSettings(
            format="MAP", include_headers=False, include_segments=True
        )
        assert to_ida_flags(settings) == 0x007C

    def test_both_options(self):
        """Test both options sets combined flags (0x007E)."""
        settings = DisasmExportSettings(
            format="LST", include_headers=True, include_segments=True
        )
        # 0x0002 | 0x007C = 0x007E = 126
        assert to_ida_flags(settings) == 126

    def test_format_independent(self):
        """Test flags are independent of format choice."""
        settings_asm = DisasmExportSettings(
            format="ASM", include_headers=True, include_segments=True
        )
        settings_lst = DisasmExportSettings(
            format="LST", include_headers=True, include_segments=True
        )
        assert to_ida_flags(settings_asm) == to_ida_flags(settings_lst)


class TestSuggestDisasmFilename:
    """Test filename suggestion."""

    def test_basic_name_asm(self):
        """Test basic function name with ASM format."""
        assert suggest_disasm_filename("my_function", "ASM") == "my_function.asm"

    def test_basic_name_lst(self):
        """Test basic function name with LST format."""
        assert suggest_disasm_filename("my_function", "LST") == "my_function.lst"

    def test_basic_name_map(self):
        """Test basic function name with MAP format."""
        assert suggest_disasm_filename("my_function", "MAP") == "my_function.map"

    def test_basic_name_idc(self):
        """Test basic function name with IDC format."""
        assert suggest_disasm_filename("my_function", "IDC") == "my_function.idc"

    def test_sanitizes_invalid_chars(self):
        """Test invalid filename characters are replaced."""
        assert suggest_disasm_filename("my::func", "ASM") == "my__func.asm"
        assert suggest_disasm_filename("operator<<", "LST") == "operator__.lst"
        assert suggest_disasm_filename("my/bad\\path", "MAP") == "my_bad_path.map"

    def test_sanitizes_angle_brackets(self):
        """Test angle brackets are replaced."""
        assert suggest_disasm_filename("func<int>", "ASM") == "func_int_.asm"

    def test_sanitizes_spaces(self):
        """Test spaces are replaced with underscores."""
        assert suggest_disasm_filename("my function", "LST") == "my_function.lst"

    def test_limits_length(self):
        """Test long names are truncated."""
        long_name = "a" * 150
        result = suggest_disasm_filename(long_name, "ASM")
        # Should be 100 chars + ".asm" = 104 total
        assert len(result) == 104
        assert result == ("a" * 100) + ".asm"

    def test_unknown_format_uses_txt(self):
        """Test unknown format defaults to .txt extension."""
        result = suggest_disasm_filename("func", "UNKNOWN")
        assert result == "func.txt"

    def test_preserves_valid_chars(self):
        """Test valid characters are preserved."""
        assert suggest_disasm_filename("my_func_123", "ASM") == "my_func_123.asm"
        assert suggest_disasm_filename("FuncABC", "LST") == "FuncABC.lst"
