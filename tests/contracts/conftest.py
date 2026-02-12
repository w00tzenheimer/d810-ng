"""Pytest configuration for contract tests.

Contract tests validate behavior around IDA-bound modules using stubs/mocks,
without requiring a live IDA database/runtime session.
"""

from __future__ import annotations

import pathlib
import sys

import pytest


def _is_ida() -> bool:
    exec_name = pathlib.Path(sys.executable).name.lower()
    return exec_name.startswith("ida") or exec_name.startswith("idat")


if not _is_ida():
    try:
        import idapro  # noqa: F401
    except ImportError:
        pytest.skip(
            "Contracts tests require IDA Pro or idalib runtime.",
            allow_module_level=True,
        )


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        item.add_marker(pytest.mark.contracts)
        item.add_marker(pytest.mark.ida_required)
