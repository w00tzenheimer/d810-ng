"""Pytest configuration for runtime tests.

Runtime tests require IDA Pro and validate invariants, API behavior,
and stability checks. They do NOT compare full pipeline output.

Failure means: "Our interaction with IDA/Hex-Rays is wrong or unstable."
"""
from __future__ import annotations

import pytest


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Mark all tests in this subtree as runtime tests."""
    for item in items:
        if "tests/system/runtime" in str(item.fspath):
            item.add_marker(pytest.mark.runtime)
            item.add_marker(pytest.mark.hexrays)
            item.add_marker(pytest.mark.ida_required)
