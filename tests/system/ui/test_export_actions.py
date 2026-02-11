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
        """Test that OFILE_* constants have the expected values."""
        assert ida_loader.OFILE_MAP == 0, "OFILE_MAP should be 0"
        assert ida_loader.OFILE_EXE == 1, "OFILE_EXE should be 1"
        assert ida_loader.OFILE_IDC == 2, "OFILE_IDC should be 2"
        assert ida_loader.OFILE_LST == 3, "OFILE_LST should be 3"
        assert ida_loader.OFILE_ASM == 4, "OFILE_ASM should be 4"
        assert ida_loader.OFILE_DIF == 5, "OFILE_DIF should be 5"

    def test_format_mapping_matches_ida(self):
        """Test that our format mapping matches actual IDA constants."""
        from d810.ui.actions.export_disasm_logic import to_ida_format_int

        assert to_ida_format_int("ASM") == ida_loader.OFILE_ASM
        assert to_ida_format_int("LST") == ida_loader.OFILE_LST
        assert to_ida_format_int("MAP") == ida_loader.OFILE_MAP
        assert to_ida_format_int("IDC") == ida_loader.OFILE_IDC

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
        """Test GENFLG_* constants have expected bitmask values."""
        # These are standard flag values from IDA SDK
        assert ida_loader.GENFLG_GENHTML == 0x0001, "GENFLG_GENHTML should be 0x0001"
        assert ida_loader.GENFLG_ASMTYPE == 0x0002, "GENFLG_ASMTYPE should be 0x0002"
        assert ida_loader.GENFLG_MAPDMNG == 0x0004, "GENFLG_MAPDMNG should be 0x0004"
        assert ida_loader.GENFLG_MAPNAME == 0x0008, "GENFLG_MAPNAME should be 0x0008"

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

        assert export_disasm.IDA_AVAILABLE is True
        assert export_disasm.ida_loader is not None

    def test_export_action_handler_exists(self):
        """Test that ExportDisassembly action handler class exists."""
        from d810.ui.actions.export_disasm import ExportDisassembly

        assert ExportDisassembly.ACTION_ID == "d810ng:export_disasm"
        assert ExportDisassembly.ACTION_TEXT == "Export disassembly..."

    def test_flag_mapping_produces_valid_flags(self):
        """Test that our flag mapping produces valid IDA loader flags."""
        from d810.ui.actions.export_disasm_logic import DisasmExportSettings, to_ida_flags

        # Test various combinations
        settings_none = DisasmExportSettings(
            format="ASM", include_headers=False, include_segments=False
        )
        flags_none = to_ida_flags(settings_none)
        assert isinstance(flags_none, int)
        assert flags_none == 0

        settings_headers = DisasmExportSettings(
            format="ASM", include_headers=True, include_segments=False
        )
        flags_headers = to_ida_flags(settings_headers)
        assert flags_headers == ida_loader.GENFLG_ASMTYPE

        settings_both = DisasmExportSettings(
            format="LST", include_headers=True, include_segments=True
        )
        flags_both = to_ida_flags(settings_both)
        assert flags_both & ida_loader.GENFLG_ASMTYPE != 0
        assert flags_both == 0x007E  # GENFLG_ASMTYPE | MAP flags
