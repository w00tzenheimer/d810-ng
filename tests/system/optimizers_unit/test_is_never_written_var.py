"""Unit tests for is_never_written_var in d810.hexrays.ida_utils.

is_never_written_var checks whether a variable at a given address is never
written to by any code. It returns True only when:
  - is_loaded(address) is False  (not an imported/loaded symbol)
  - No data xref of type dr_W points to the address

These tests mock the idaapi module (is_loaded, xrefblk_t, XREF_DATA, dr_W)
to avoid requiring a live IDA instance.
"""

import sys
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Mock xrefblk_t factory
# ---------------------------------------------------------------------------

def _make_xrefblk_class(xrefs):
    """Create a mock xrefblk_t class that iterates over a list of xref types.

    Args:
        xrefs: List of xref type integers. An empty list means no xrefs exist.

    Returns:
        A class whose instances behave like idaapi.xrefblk_t:
          - first_to(...) returns True if xrefs exist, sets .type to xrefs[0]
          - next_to() advances through the list, returns False when exhausted
    """

    class MockXrefblk:
        def __init__(self):
            self.type = 0
            self._xrefs = list(xrefs)
            self._index = -1

        def first_to(self, address, flags):
            if not self._xrefs:
                return False
            self._index = 0
            self.type = self._xrefs[0]
            return True

        def next_to(self):
            self._index += 1
            if self._index >= len(self._xrefs):
                return False
            self.type = self._xrefs[self._index]
            return True

    return MockXrefblk


@pytest.fixture(autouse=True)
def mock_ida_modules():
    """Inject mock IDA modules so d810 mem_read module can be imported."""
    mock_idaapi = MagicMock()
    mock_hexrays = MagicMock()

    # Provide real class for mop_t (singledispatch needs it)
    class mop_t:
        def __init__(self):
            self.t = 0
            self.size = 4

    mock_hexrays.mop_t = mop_t

    # MMAT_ constants
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

    # Opcode constants (needed by transitive imports from EarlyRule hierarchy)
    mock_hexrays.m_mov = 0x04
    mock_hexrays.m_ldx = 0x02
    mock_hexrays.m_stx = 0x01
    mock_hexrays.m_call = 0x38

    # Make dir(mock_hexrays) return the attribute names we set so that
    # MicrocodeHelper's list comprehensions (filtering MMAT_, mop_, m_) work.
    _our_attrs = [
        a for a in mock_hexrays.__dict__
        if not a.startswith("_")
    ]
    _explicit_attrs = [
        a for a in dir(type(mock_hexrays))
        if not a.startswith("_")
    ]
    _all_attrs = sorted(set(_explicit_attrs + _our_attrs))
    type(mock_hexrays).__dir__ = lambda self: _all_attrs

    # SEGPERM constants used in the module
    mock_idaapi.SEGPERM_READ = 4
    mock_idaapi.SEGPERM_WRITE = 2

    # xref constants -- these are the real values from IDA
    DR_W = 2  # data write xref
    XREF_DATA = 2
    DR_R = 1  # data read xref (not a write)
    DR_O = 0  # data offset xref (not a write)

    mock_idaapi.XREF_DATA = XREF_DATA
    mock_idaapi.dr_W = DR_W

    # Default: is_loaded returns False (not an imported symbol)
    mock_idaapi.is_loaded.return_value = False

    # Default: xrefblk_t with no xrefs (first_to returns False)
    mock_idaapi.xrefblk_t = _make_xrefblk_class([])

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

    # Purge cached d810 modules so they reimport with our mocks
    cached_d810 = [k for k in sys.modules if k.startswith("d810")]
    saved = {k: sys.modules.pop(k) for k in cached_d810}

    with patch.dict("sys.modules", modules_to_mock):
        yield mock_idaapi

    # Restore previously-cached modules
    for k, v in saved.items():
        sys.modules[k] = v


# ---------------------------------------------------------------------------
# Tests for is_never_written_var
# ---------------------------------------------------------------------------


class TestIsNeverWrittenVarNoXrefs:
    """When no data xrefs exist, the variable is never written."""

    def test_no_xrefs_returns_true(self, mock_ida_modules):
        """A variable with zero xrefs should be considered never-written."""
        mock_ida_modules.is_loaded.return_value = False
        mock_ida_modules.xrefblk_t = _make_xrefblk_class([])

        from d810.hexrays.ida_utils import is_never_written_var

        assert is_never_written_var(0x401000) is True


class TestIsNeverWrittenVarWithWriteXref:
    """When a dr_W xref exists, the variable IS written."""

    def test_single_write_xref_returns_false(self, mock_ida_modules):
        DR_W = 2
        mock_ida_modules.is_loaded.return_value = False
        mock_ida_modules.xrefblk_t = _make_xrefblk_class([DR_W])

        from d810.hexrays.ida_utils import is_never_written_var

        assert is_never_written_var(0x401000) is False

    def test_write_among_reads_returns_false(self, mock_ida_modules):
        """Even if there are read xrefs, a single write makes it writable."""
        DR_R = 1
        DR_W = 2
        mock_ida_modules.is_loaded.return_value = False
        mock_ida_modules.xrefblk_t = _make_xrefblk_class([DR_R, DR_R, DR_W, DR_R])

        from d810.hexrays.ida_utils import is_never_written_var

        assert is_never_written_var(0x401000) is False


class TestIsNeverWrittenVarReadOnly:
    """When only read xrefs exist, the variable is never written."""

    def test_only_read_xrefs_returns_true(self, mock_ida_modules):
        DR_R = 1
        DR_O = 0
        mock_ida_modules.is_loaded.return_value = False
        mock_ida_modules.xrefblk_t = _make_xrefblk_class([DR_R, DR_O, DR_R])

        from d810.hexrays.ida_utils import is_never_written_var

        assert is_never_written_var(0x401000) is True


class TestIsNeverWrittenVarIsLoaded:
    """If is_loaded returns True, the function should return False immediately."""

    def test_is_loaded_returns_false(self, mock_ida_modules):
        mock_ida_modules.is_loaded.return_value = True
        # Even with no write xrefs, is_loaded makes it return False
        mock_ida_modules.xrefblk_t = _make_xrefblk_class([])

        from d810.hexrays.ida_utils import is_never_written_var

        assert is_never_written_var(0x401000) is False

    def test_is_loaded_skips_xref_check(self, mock_ida_modules):
        """When is_loaded is True, xrefblk_t should never be instantiated."""
        mock_ida_modules.is_loaded.return_value = True

        # Use a sentinel class that would fail if instantiated
        class FailXrefblk:
            def __init__(self):
                raise AssertionError("xrefblk_t should not be created when is_loaded is True")

        mock_ida_modules.xrefblk_t = FailXrefblk

        from d810.hexrays.ida_utils import is_never_written_var

        assert is_never_written_var(0x401000) is False
