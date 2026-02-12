"""Pytest configuration for stateless IDA-runtime tests.

Reuses the system-test fixture implementations while avoiding duplicate pytest
hook registration when both test trees are collected together.
"""

from __future__ import annotations

import pytest

from tests.system import conftest as _system

# Re-export fixture functions from tests/system/conftest.py
clear_all_caches = _system.clear_all_caches
ida_available = _system.ida_available
skip_if_no_ida = _system.skip_if_no_ida
ida_database = _system.ida_database
pseudocode_to_string = _system.pseudocode_to_string
configure_hexrays = _system.configure_hexrays
setup_libobfuscated_funcs = _system.setup_libobfuscated_funcs
setup_libobfuscated_test_funcs = _system.setup_libobfuscated_test_funcs
d810_state = _system.d810_state
d810_state_all_rules = _system.d810_state_all_rules
clang_index = _system.clang_index
code_comparator = _system.code_comparator
require_clang = _system.require_clang
assert_code_equivalent = _system.assert_code_equivalent
assert_code_contains = _system.assert_code_contains
assert_code_not_contains = _system.assert_code_not_contains
capture_stats = _system.capture_stats
load_expected_stats = _system.load_expected_stats
db_capture = _system.db_capture


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Mark all tests in this subtree as stateless IDA-runtime tests."""
    for item in items:
        item.add_marker(pytest.mark.ida_stateless)
        item.add_marker(pytest.mark.ida_required)
