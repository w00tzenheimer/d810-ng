"""Pytest configuration for unit tests.

Unit tests verify rule correctness using Z3 and do not require IDA Pro.

RULE: No IDA mocking in unit tests.
IDA-dependent tests belong in tests/system/.
"""
import sys
import pytest

# IDA modules that must NOT be mocked in unit tests
_IDA_MODULES = frozenset({
    "idaapi", "idc", "idautils",
    "ida_hexrays", "ida_bytes", "ida_funcs", "ida_gdl",
    "ida_ida", "ida_kernwin", "ida_lines", "ida_nalt",
    "ida_name", "ida_pro", "ida_range", "ida_segment",
    "ida_typeinf", "ida_ua", "ida_xref",
})


@pytest.fixture(autouse=True)
def _enforce_no_ida_mocks():
    """Fail any unit test that injects mock IDA modules into sys.modules."""
    from unittest.mock import MagicMock, Mock
    for mod_name in _IDA_MODULES:
        mod = sys.modules.get(mod_name)
        if mod is not None and isinstance(mod, (MagicMock, Mock)):
            pytest.fail(
                f"Unit test injected mock for '{mod_name}' into sys.modules. "
                f"IDA-dependent tests belong in tests/system/, not tests/unit/."
            )
    yield
    # Also check after test runs (catches mocks injected during test)
    for mod_name in _IDA_MODULES:
        mod = sys.modules.get(mod_name)
        if mod is not None and isinstance(mod, (MagicMock, Mock)):
            pytest.fail(
                f"Unit test left mock '{mod_name}' in sys.modules. "
                f"IDA-dependent tests belong in tests/system/, not tests/unit/."
            )
            # Clean it up to prevent cascade
            del sys.modules[mod_name]
