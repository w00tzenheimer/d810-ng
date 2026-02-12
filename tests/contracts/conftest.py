"""Pytest configuration for contract tests.

Contract tests validate behavior around IDA-bound modules using stubs/mocks,
without requiring a live IDA database/runtime session.
"""

from __future__ import annotations

import pytest


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        item.add_marker(pytest.mark.contracts)
        item.add_marker(pytest.mark.pure_python)
