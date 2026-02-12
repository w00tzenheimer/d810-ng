"""System tests for export disassembly actions.

These tests verify that our constant mappings match the actual IDA API.
They require IDA Pro to be available and will be skipped in CI.
"""
from __future__ import annotations

import pytest

try:
    import ida_loader

    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False


@pytest.mark.skipif(not IDA_AVAILABLE, reason="Requires IDA Pro")
class TestIdaLoaderConstants:
    """Verify our constant mappings match actual IDA API."""

    def test_ofile_constants_exist(self):
        """Test that all OFILE_* constants we use actually exist in ida_loader."""
        assert hasattr(ida_loader, "OFILE_ASM"), "Missing OFILE_ASM constant"
        assert hasattr(ida_loader, "OFILE_LST"), "Missing OFILE_LST constant"
        assert hasattr(ida_loader, "OFILE_MAP"), "Missing OFILE_MAP constant"
        assert hasattr(ida_loader, "OFILE_IDC"), "Missing OFILE_IDC constant"
        assert hasattr(ida_loader, "OFILE_EXE"), "Missing OFILE_EXE constant"
        assert hasattr(ida_loader, "OFILE_DIF"), "Missing OFILE_DIF constant"

    def test_ofile_constant_values(self):
        """Test OFILE constants are usable integer enums."""
        ofiles = [
            ida_loader.OFILE_MAP,
            ida_loader.OFILE_EXE,
            ida_loader.OFILE_IDC,
            ida_loader.OFILE_LST,
            ida_loader.OFILE_ASM,
            ida_loader.OFILE_DIF,
        ]
        assert all(isinstance(v, int) for v in ofiles)
        assert len(set(ofiles)) == len(ofiles)

    def test_format_mapping_matches_ida(self):
        """Test that our format mapping matches actual IDA constants."""
        from d810.ui.actions.export_disasm_logic import to_ida_format_int_with_loader

        assert to_ida_format_int_with_loader("ASM", loader=ida_loader) == ida_loader.OFILE_ASM
        assert to_ida_format_int_with_loader("LST", loader=ida_loader) == ida_loader.OFILE_LST
        assert to_ida_format_int_with_loader("MAP", loader=ida_loader) == ida_loader.OFILE_MAP
        assert to_ida_format_int_with_loader("IDC", loader=ida_loader) == ida_loader.OFILE_IDC

    def test_genflg_constants_exist(self):
        """Test that all GENFLG_* constants we use actually exist."""
        # These are the flags we actually use in our code
        assert hasattr(ida_loader, "GENFLG_ASMTYPE"), "Missing GENFLG_ASMTYPE constant"
        assert hasattr(ida_loader, "GENFLG_MAPSEG"), "Missing GENFLG_MAPSEG constant"
        assert hasattr(ida_loader, "GENFLG_MAPNAME"), "Missing GENFLG_MAPNAME constant"
        assert hasattr(ida_loader, "GENFLG_MAPDMNG"), "Missing GENFLG_MAPDMNG constant"
        assert hasattr(ida_loader, "GENFLG_MAPLOC"), "Missing GENFLG_MAPLOC constant"

    def test_genflg_xrf_does_not_exist(self):
        """Test that GENFLG_GENXRF does NOT exist (was the bug)."""
        assert not hasattr(
            ida_loader, "GENFLG_GENXRF"
        ), "GENFLG_GENXRF should not exist in ida_loader"

    def test_genflg_constant_values(self):
        """Test GENFLG constants are stable integer bitmasks."""
        flags = [
            ida_loader.GENFLG_GENHTML,
            ida_loader.GENFLG_ASMTYPE,
            ida_loader.GENFLG_MAPDMNG,
            ida_loader.GENFLG_MAPNAME,
            ida_loader.GENFLG_MAPLOC,
            ida_loader.GENFLG_MAPSEG,
        ]
        assert all(isinstance(v, int) and v > 0 for v in flags)

    def test_gen_file_function_exists(self):
        """Test that ida_loader.gen_file function exists and is callable."""
        assert hasattr(ida_loader, "gen_file"), "Missing gen_file function"
        assert callable(ida_loader.gen_file), "gen_file should be callable"


@pytest.mark.skipif(not IDA_AVAILABLE, reason="Requires IDA Pro")
class TestExportActionIntegration:
    """Integration tests for export action with real IDA API."""

    def test_can_import_export_action(self):
        """Test that export action module can be imported when IDA is available."""
        from d810.ui.actions import export_disasm

        assert export_disasm is not None

    def test_export_action_handler_exists(self):
        """Test that ExportDisassembly action handler class exists."""
        from d810.ui.actions.export_disasm import ExportDisassembly

        assert ExportDisassembly.ACTION_ID == "d810ng:export_disasm"
        assert ExportDisassembly.ACTION_TEXT == "Export disassembly..."

    def test_flag_mapping_produces_valid_flags(self):
        """Test that our flag mapping produces valid IDA loader flags."""
        from d810.ui.actions.export_disasm_logic import (
            DisasmExportSettings,
            to_ida_flags_with_loader,
        )

        # Test various combinations
        settings_none = DisasmExportSettings(
            format="ASM", include_headers=False, include_segments=False
        )
        flags_none = to_ida_flags_with_loader(settings_none, loader=ida_loader)
        assert isinstance(flags_none, int)
        assert flags_none == 0

        settings_headers = DisasmExportSettings(
            format="ASM", include_headers=True, include_segments=False
        )
        flags_headers = to_ida_flags_with_loader(settings_headers, loader=ida_loader)
        assert flags_headers == ida_loader.GENFLG_ASMTYPE

        settings_both = DisasmExportSettings(
            format="LST", include_headers=True, include_segments=True
        )
        flags_both = to_ida_flags_with_loader(settings_both, loader=ida_loader)
        assert flags_both & ida_loader.GENFLG_ASMTYPE != 0
        settings_segments = DisasmExportSettings(
            format="LST", include_headers=False, include_segments=True
        )
        flags_segments = to_ida_flags_with_loader(settings_segments, loader=ida_loader)
        assert flags_both == (ida_loader.GENFLG_ASMTYPE | flags_segments)
