"""Repository-wide pytest policy shared by local and IDA test runtimes."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.speedup_parity import speedup_parity_modules


SPEEDUP_PARITY_MODULES = speedup_parity_modules(Path(__file__).resolve().parent)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Mark every test owned by the explicit Python/Cython parity manifest."""
    for item in items:
        module_path = item.nodeid.split("::", 1)[0]
        if module_path in SPEEDUP_PARITY_MODULES:
            item.add_marker(pytest.mark.speedup_parity)
