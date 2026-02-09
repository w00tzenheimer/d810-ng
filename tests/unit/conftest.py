"""Pytest configuration for unit tests.

Unit tests verify rule correctness using Z3 and do not require IDA Pro.
"""
import sys
from unittest.mock import MagicMock
import pytest


class MockIDAHexrays:
    """Mock ida_hexrays module with controlled __dir__ output."""

    def __init__(self):
        self._attrs = {}

    def __dir__(self):
        # Return only explicitly set non-private attributes
        # This prevents auto-generated MagicMock from being included in filter operations
        return [k for k in self._attrs.keys() if not k.startswith('_')]

    def __getattr__(self, name):
        # Return existing attribute or auto-create MagicMock
        if name == '_attrs':
            raise AttributeError(name)
        if name in self._attrs:
            return self._attrs[name]
        # Auto-create MagicMock for attributes accessed but not set
        # This allows code like ida_hexrays.m_stx to work without errors
        # BUT we don't add them to _attrs dict so they won't show up in dir()
        return MagicMock()

    def __setattr__(self, name, value):
        if name == '_attrs':
            super().__setattr__(name, value)
        else:
            if not hasattr(self, '_attrs'):
                super().__setattr__('_attrs', {})
            self._attrs[name] = value


# Mock IDA modules at module import time (before pytest collection)
# This prevents import errors when pytest collects tests
if 'ida_hexrays' not in sys.modules:
    # Create custom mock with controlled dir()
    mock_ida_hex = MockIDAHexrays()
    mock_idaapi = MagicMock()

    # Set common constants (BLT_*, m_*, mop_*, MMAT_*)
    # These are accessed during module import
    mock_ida_hex.BLT_NONE = 0
    mock_ida_hex.BLT_STOP = 1
    mock_ida_hex.BLT_0WAY = 2
    mock_ida_hex.BLT_1WAY = 3
    mock_ida_hex.BLT_2WAY = 4
    mock_ida_hex.BLT_NWAY = 5
    mock_ida_hex.BLT_XTRN = 6

    # Set all MMAT_* constants to integers (for sorted() in MicrocodeHelper.MMAT)
    mock_ida_hex.MMAT_ZERO = -1
    mock_ida_hex.MMAT_GENERATED = 0
    mock_ida_hex.MMAT_PREOPTIMIZED = 1
    mock_ida_hex.MMAT_LOCOPT = 2
    mock_ida_hex.MMAT_CALLS = 3
    mock_ida_hex.MMAT_GLBOPT1 = 4
    mock_ida_hex.MMAT_GLBOPT2 = 5
    mock_ida_hex.MMAT_GLBOPT3 = 6
    mock_ida_hex.MMAT_LVARS = 7

    # Set m_* opcodes to integers (for opcode comparisons in conditional_exit tests)
    mock_ida_hex.m_mov = 15
    mock_ida_hex.m_add = 16

    # Set mop_* types to integers
    mock_ida_hex.mop_r = 4
    mock_ida_hex.mop_n = 2

    # Set helper functions
    mock_ida_hex.is_mcode_jcond = MagicMock(return_value=True)

    # Install in sys.modules
    sys.modules['ida_hexrays'] = mock_ida_hex
    sys.modules['idaapi'] = mock_idaapi
