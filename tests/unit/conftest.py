"""Pytest configuration for unit tests.

RULE: No IDA mocking in unit tests.
IDA-dependent tests belong in tests/system/runtime/ or tests/system/e2e/.
"""

import sys
from unittest.mock import MagicMock, Mock

import pytest

# IDA modules that must NOT be mocked in unit tests
_IDA_MODULES = frozenset(
    {
        "idaapi",
        "idc",
        "idautils",
        "ida_hexrays",
        "ida_bytes",
        "ida_funcs",
        "ida_gdl",
        "ida_ida",
        "ida_kernwin",
        "ida_lines",
        "ida_nalt",
        "ida_name",
        "ida_pro",
        "ida_range",
        "ida_segment",
        "ida_typeinf",
        "ida_ua",
        "ida_xref",
    }
)


@pytest.fixture(autouse=True)
def _release_diag_test_binds():
    """Disconnect the per-test bound diag DB singleton at teardown.

    Production never relies on a process-global Model bind; unit tests that call
    ORM readers directly bind explicitly via ``make_bound_diag_db``
    (``tests.unit.core.diag._orm_bind``). This restores the prior bind and
    disconnects that singleton after each test so it never leaks. No-op for
    tests that never bound anything.
    """
    yield
    from tests.unit.core.diag._orm_bind import release_diag_test_binds

    release_diag_test_binds()


@pytest.fixture(autouse=True)
def _enforce_no_ida_mocks():
    """Fail any unit test that injects mock IDA modules into sys.modules."""

    for mod_name in _IDA_MODULES:
        mod = sys.modules.get(mod_name)
        if mod is not None and isinstance(mod, (MagicMock, Mock)):
            pytest.fail(
                f"Unit test injected mock for '{mod_name}' into sys.modules. "
                f"IDA-dependent tests belong in tests/system/runtime/ or tests/system/, not tests/unit/."
            )
    yield
    # Also check after test runs (catches mocks injected during test)
    for mod_name in _IDA_MODULES:
        mod = sys.modules.get(mod_name)
        if mod is not None and isinstance(mod, (MagicMock, Mock)):
            pytest.fail(
                f"Unit test left mock '{mod_name}' in sys.modules. "
                f"IDA-dependent tests belong in tests/system/runtime/ or tests/system/, not tests/unit/."
            )
            # Clean it up to prevent cascade
            del sys.modules[mod_name]
