"""Pytest configuration for end-to-end tests.

E2E tests run the full deobfuscation pipeline and compare results
against golden output (pseudocode snapshots, statistics, DeobfuscationCase).

Failure means: "The deobfuscation pipeline is wrong."
"""
from __future__ import annotations

import pytest


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Mark all tests in this subtree as e2e tests."""
    for item in items:
        if "tests/system/e2e" in str(item.fspath):
            item.add_marker(pytest.mark.e2e)
            item.add_marker(pytest.mark.hexrays)
            item.add_marker(pytest.mark.ida_required)
