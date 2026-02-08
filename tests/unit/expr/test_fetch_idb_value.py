"""Unit tests for fetch_idb_value in d810.expr.emulator.

fetch_idb_value reads a value from the IDA database at a given address.
It supports sizes 1, 2, 4, and 8 bytes. All other sizes (including 0,
negative, and unsupported positive values) must return None.

These tests mock the idaapi module to avoid requiring a live IDA instance.
"""

import sys
import types
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def mock_ida_modules():
    """Inject mock IDA modules so d810.expr.emulator can be imported."""
    mock_idaapi = MagicMock()
    mock_hexrays = MagicMock()

    # Configure idaapi read helpers to return deterministic values
    mock_idaapi.get_byte.return_value = 0xAB
    mock_idaapi.get_word.return_value = 0xABCD
    mock_idaapi.get_dword.return_value = 0xDEADBEEF
    mock_idaapi.get_qword.return_value = 0xCAFEBABEDEADBEEF

    # mop_t must be a real class (not MagicMock) to avoid singledispatch issues
    class mop_t:
        def __init__(self):
            self.t = 0
            self.size = 4

    mock_hexrays.mop_t = mop_t

    # Provide MMAT_ constants needed by transitive imports
    mock_hexrays.MMAT_GENERATED = 0
    mock_hexrays.MMAT_PREOPTIMIZED = 1
    mock_hexrays.MMAT_LOCOPT = 2
    mock_hexrays.MMAT_CALLS = 3
    mock_hexrays.MMAT_GLBOPT1 = 4
    mock_hexrays.MMAT_GLBOPT2 = 5
    mock_hexrays.MMAT_GLBOPT3 = 6
    mock_hexrays.MMAT_LVARS = 7

    # mop type constants
    mock_hexrays.mop_z = 0
    mock_hexrays.mop_r = 1
    mock_hexrays.mop_n = 2
    mock_hexrays.mop_d = 4
    mock_hexrays.mop_S = 5
    mock_hexrays.mop_v = 6
    mock_hexrays.mop_b = 7
    mock_hexrays.mop_a = 10
    mock_hexrays.mop_h = 11

    # Opcode constants used by the emulator module
    mock_hexrays.m_mov = 0x04
    mock_hexrays.m_ldx = 0x02
    mock_hexrays.m_stx = 0x01
    mock_hexrays.m_call = 0x38
    mock_hexrays.m_icall = 0x39
    mock_hexrays.m_goto = 0x37
    mock_hexrays.m_jcnd = 0x2A
    mock_hexrays.m_jnz = 0x2B
    mock_hexrays.m_jz = 0x2C
    mock_hexrays.m_jae = 0x2D
    mock_hexrays.m_jb = 0x2E
    mock_hexrays.m_ja = 0x2F
    mock_hexrays.m_jbe = 0x30
    mock_hexrays.m_jg = 0x31
    mock_hexrays.m_jge = 0x32
    mock_hexrays.m_jl = 0x33
    mock_hexrays.m_jle = 0x34
    mock_hexrays.m_jtbl = 0x35
    mock_hexrays.m_ijmp = 0x36
    mock_hexrays.m_ret = 0x3A
    mock_hexrays.m_neg = 0x05
    mock_hexrays.m_lnot = 0x06
    mock_hexrays.m_bnot = 0x07
    mock_hexrays.m_xds = 0x08
    mock_hexrays.m_xdu = 0x09
    mock_hexrays.m_low = 0x0A
    mock_hexrays.m_high = 0x0B
    mock_hexrays.m_add = 0x0C
    mock_hexrays.m_sub = 0x0D
    mock_hexrays.m_mul = 0x0E
    mock_hexrays.m_udiv = 0x0F
    mock_hexrays.m_sdiv = 0x10
    mock_hexrays.m_umod = 0x11
    mock_hexrays.m_smod = 0x12
    mock_hexrays.m_or = 0x13
    mock_hexrays.m_and = 0x14
    mock_hexrays.m_xor = 0x15
    mock_hexrays.m_shl = 0x16
    mock_hexrays.m_shr = 0x17
    mock_hexrays.m_sar = 0x18
    mock_hexrays.m_cfadd = 0x19
    mock_hexrays.m_ofadd = 0x1A
    mock_hexrays.m_sets = 0x1D
    mock_hexrays.m_seto = 0x1E
    mock_hexrays.m_setp = 0x1F
    mock_hexrays.m_setnz = 0x20
    mock_hexrays.m_setz = 0x21
    mock_hexrays.m_setae = 0x22
    mock_hexrays.m_setb = 0x23
    mock_hexrays.m_seta = 0x24
    mock_hexrays.m_setbe = 0x25
    mock_hexrays.m_setg = 0x26
    mock_hexrays.m_setge = 0x27
    mock_hexrays.m_setl = 0x28
    mock_hexrays.m_setle = 0x29

    # Make dir(mock_hexrays) return the attribute names we set so that
    # MicrocodeHelper's list comprehensions (filtering MMAT_, mop_, m_) work.
    _explicit_attrs = [
        a for a in dir(type(mock_hexrays))
        if not a.startswith("_")
    ]
    # Collect our manually-set constant names
    _our_attrs = [
        a for a in mock_hexrays.__dict__
        if not a.startswith("_")
    ]
    _all_attrs = sorted(set(_explicit_attrs + _our_attrs))
    type(mock_hexrays).__dir__ = lambda self: _all_attrs

    # SEGPERM constants
    mock_idaapi.SEGPERM_READ = 4
    mock_idaapi.SEGPERM_WRITE = 2

    # xref constants
    mock_idaapi.XREF_DATA = 2
    mock_idaapi.dr_W = 2

    mock_idc = MagicMock()
    mock_ida_ida = MagicMock()
    mock_ida_idp = MagicMock()
    mock_ida_bytes = MagicMock()

    modules_to_mock = {
        "ida_hexrays": mock_hexrays,
        "idaapi": mock_idaapi,
        "idc": mock_idc,
        "ida_ida": mock_ida_ida,
        "ida_idp": mock_ida_idp,
        "ida_bytes": mock_ida_bytes,
    }

    # Purge any previously-cached d810 modules so they reimport with our mocks
    cached_d810 = [k for k in sys.modules if k.startswith("d810")]
    saved = {k: sys.modules.pop(k) for k in cached_d810}

    with patch.dict("sys.modules", modules_to_mock):
        yield mock_idaapi

    # Restore previously-cached modules
    for k, v in saved.items():
        sys.modules[k] = v


# ---------------------------------------------------------------------------
# Tests for fetch_idb_value
# ---------------------------------------------------------------------------


class TestFetchIdbValueSupportedSizes:
    """fetch_idb_value should delegate to the correct idaapi reader."""

    def test_size_1_calls_get_byte(self, mock_ida_modules):
        from d810.expr.emulator import fetch_idb_value

        result = fetch_idb_value(0x401000, 1)
        mock_ida_modules.get_byte.assert_called_once_with(0x401000)
        assert result == 0xAB

    def test_size_2_calls_get_word(self, mock_ida_modules):
        from d810.expr.emulator import fetch_idb_value

        result = fetch_idb_value(0x401000, 2)
        mock_ida_modules.get_word.assert_called_once_with(0x401000)
        assert result == 0xABCD

    def test_size_4_calls_get_dword(self, mock_ida_modules):
        from d810.expr.emulator import fetch_idb_value

        result = fetch_idb_value(0x401000, 4)
        mock_ida_modules.get_dword.assert_called_once_with(0x401000)
        assert result == 0xDEADBEEF

    def test_size_8_calls_get_qword(self, mock_ida_modules):
        from d810.expr.emulator import fetch_idb_value

        result = fetch_idb_value(0x401000, 8)
        mock_ida_modules.get_qword.assert_called_once_with(0x401000)
        assert result == 0xCAFEBABEDEADBEEF


class TestFetchIdbValueUnsupportedSizes:
    """fetch_idb_value must return None for unsupported sizes."""

    @pytest.mark.parametrize("bad_size", [0, 3, 5, 6, 7, 9, 16, 32, 64])
    def test_unsupported_positive_sizes_return_none(self, mock_ida_modules, bad_size):
        from d810.expr.emulator import fetch_idb_value

        assert fetch_idb_value(0x401000, bad_size) is None

    @pytest.mark.parametrize("bad_size", [-1, -2, -8])
    def test_negative_sizes_return_none(self, mock_ida_modules, bad_size):
        from d810.expr.emulator import fetch_idb_value

        assert fetch_idb_value(0x401000, bad_size) is None

    def test_no_idaapi_call_for_unsupported_size(self, mock_ida_modules):
        """Ensure no idaapi read function is called for unsupported sizes."""
        from d810.expr.emulator import fetch_idb_value

        fetch_idb_value(0x401000, 3)
        mock_ida_modules.get_byte.assert_not_called()
        mock_ida_modules.get_word.assert_not_called()
        mock_ida_modules.get_dword.assert_not_called()
        mock_ida_modules.get_qword.assert_not_called()


class TestFetchIdbValueEdgeCases:
    """Edge cases: address 0, large addresses."""

    def test_address_zero(self, mock_ida_modules):
        from d810.expr.emulator import fetch_idb_value

        result = fetch_idb_value(0x0, 4)
        mock_ida_modules.get_dword.assert_called_once_with(0x0)
        assert result == 0xDEADBEEF

    def test_large_address(self, mock_ida_modules):
        from d810.expr.emulator import fetch_idb_value

        result = fetch_idb_value(0x7FFC1EB47830, 8)
        mock_ida_modules.get_qword.assert_called_once_with(0x7FFC1EB47830)
        assert result == 0xCAFEBABEDEADBEEF
