"""Pytest configuration for end-to-end tests.

E2E tests run the full deobfuscation pipeline and compare results
against golden output (pseudocode snapshots, statistics, DeobfuscationCase).

Failure means: "The deobfuscation pipeline is wrong."
"""

from __future__ import annotations

import pytest

# ``copy_of_idb`` (Task 6 of the profile-guided native-mutation implementer
# plan) is otherwise registered only in ``tests/system/runtime/conftest.py``,
# scoped to writing tests under that subtree. Task 6's own file list places
# one writing test -- the explicit user-policy/certificate boundary proof --
# at ``tests/system/e2e/test_native_normalization.py`` instead, so this
# subtree needs the same registration. Imported, not redefined: the fixture
# and its safety guarantees (refuses an already-open database, asserts zero
# pre-existing patched bytes, closes with ``close_database(False)``, asserts
# the canonical fixture's SHA-256 is unchanged) live in exactly one place.
from tests.system.runtime.support.disposable_idb import (  # noqa: F401,E402
    copy_of_idb,
)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Mark all tests in this subtree as e2e tests."""
    for item in items:
        if "tests/system/e2e" in str(item.fspath):
            item.add_marker(pytest.mark.e2e)
            item.add_marker(pytest.mark.hexrays)
            item.add_marker(pytest.mark.ida_required)
