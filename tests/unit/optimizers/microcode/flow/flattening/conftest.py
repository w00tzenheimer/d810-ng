"""Pytest conftest for flattening unit tests.

Provides IDA mocking infrastructure for tests that need to import
d810 modules without having IDA Pro installed.

IMPORTANT: This conftest patches sys.modules BEFORE any test collection
happens, which is required because the d810 modules import ida_hexrays
at module level.
"""

import sys
from unittest.mock import MagicMock


def _setup_ida_mocks():
    """Set up all IDA module mocks before any imports happen."""
    if "ida_hexrays" in sys.modules:
        return  # Already mocked or real IDA present

    # Create comprehensive ida_hexrays mock
    mock_ida_hexrays = MagicMock()

    # Opcode constants
    mock_ida_hexrays.m_jz = 0x31
    mock_ida_hexrays.m_jnz = 0x30
    mock_ida_hexrays.m_goto = 0x40
    mock_ida_hexrays.m_mov = 0x01
    mock_ida_hexrays.m_call = 0x50
    mock_ida_hexrays.m_ijmp = 0x51
    mock_ida_hexrays.m_jtbl = 0x52
    mock_ida_hexrays.m_nop = 0x00

    # mop_t types
    mock_ida_hexrays.mop_n = 2
    mock_ida_hexrays.mop_r = 1
    mock_ida_hexrays.mop_d = 4
    mock_ida_hexrays.mop_h = 5
    mock_ida_hexrays.mop_S = 6

    # Maturity levels
    mock_ida_hexrays.MMAT_ZERO = 0
    mock_ida_hexrays.MMAT_GENERATED = 10
    mock_ida_hexrays.MMAT_PREOPTIMIZED = 15
    mock_ida_hexrays.MMAT_LOCOPT = 20
    mock_ida_hexrays.MMAT_CALLS = 25
    mock_ida_hexrays.MMAT_GLBOPT1 = 30
    mock_ida_hexrays.MMAT_GLBOPT2 = 35
    mock_ida_hexrays.MMAT_GLBOPT3 = 40
    mock_ida_hexrays.MMAT_LVARS = 45

    # Block types
    mock_ida_hexrays.BLT_0WAY = 0
    mock_ida_hexrays.BLT_1WAY = 1
    mock_ida_hexrays.BLT_2WAY = 2
    mock_ida_hexrays.BLT_NWAY = 3
    mock_ida_hexrays.BLT_STOP = 4

    # Create proper class mocks (not functions)
    class MockMopT:
        """Mock mop_t class."""
        def __init__(self, arg=None):
            self.t = 0
            self.nnn = MagicMock(value=0)
            self.r = 0
            self.s = MagicMock()
            self.helper = ""
            if arg is not None:
                self.t = getattr(arg, "t", 0)
                self.nnn = getattr(arg, "nnn", MagicMock(value=0))

        def assign(self, src):
            pass

    class MockMinsnT:
        """Mock minsn_t class."""
        def __init__(self):
            self.opcode = 0
            self.l = MockMopT()
            self.r = MockMopT()
            self.d = MockMopT()
            self.next = None
            self.prev = None

    class MockMblockT:
        """Mock mblock_t class."""
        def __init__(self):
            self.serial = 0
            self.head = None
            self.tail = None
            self.type = 0
            self.npred = MagicMock(return_value=0)
            self.nsucc = MagicMock(return_value=0)

    class MockMbaT:
        """Mock mbl_array_t class."""
        def __init__(self):
            self.qty = 0
            self.maturity = 0

    mock_ida_hexrays.mop_t = MockMopT
    mock_ida_hexrays.minsn_t = MockMinsnT
    mock_ida_hexrays.mblock_t = MockMblockT
    mock_ida_hexrays.mbl_array_t = MockMbaT

    # Other IDA modules
    mock_idaapi = MagicMock()
    mock_ida_kernwin = MagicMock()
    mock_idc = MagicMock()
    mock_ida_funcs = MagicMock()
    mock_ida_bytes = MagicMock()
    mock_ida_name = MagicMock()

    # Patch sys.modules
    sys.modules["ida_hexrays"] = mock_ida_hexrays
    sys.modules["idaapi"] = mock_idaapi
    sys.modules["ida_kernwin"] = mock_ida_kernwin
    sys.modules["idc"] = mock_idc
    sys.modules["ida_funcs"] = mock_ida_funcs
    sys.modules["ida_bytes"] = mock_ida_bytes
    sys.modules["ida_name"] = mock_ida_name


# Call immediately when conftest is loaded (before test collection)
_setup_ida_mocks()
