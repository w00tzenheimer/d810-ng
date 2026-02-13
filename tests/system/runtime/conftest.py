"""Pytest configuration for runtime tests.

Runtime tests require IDA Pro and validate invariants, API behavior,
and stability checks. They do NOT compare full pipeline output.

Failure means: "Our interaction with IDA/Hex-Rays is wrong or unstable."
"""
from __future__ import annotations

import os
import platform

import pytest


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Mark all tests in this subtree as runtime tests."""
    for item in items:
        if "tests/system/runtime" in str(item.fspath):
            item.add_marker(pytest.mark.runtime)
            item.add_marker(pytest.mark.hexrays)
            item.add_marker(pytest.mark.ida_required)


# =========================================================================
# Shared fixtures for pattern matching tests with real microcode
# =========================================================================


@pytest.fixture(scope="session")
def populated_storages(real_asts):
    """Create OpcodeIndexedStorage with patterns from real ASTs.

    Returns a dict with:
        "new": OpcodeIndexedStorage with 20 unique patterns
        "patterns": List of unique pattern ASTs
    """
    from d810.optimizers.microcode.instructions.pattern_matching.engine import (
        OpcodeIndexedStorage,
    )

    unique_patterns = []
    seen_sigs = set()

    for ast, _ in real_asts:
        if ast.is_node():
            sig = ast.get_pattern()
            if sig not in seen_sigs:
                seen_sigs.add(sig)
                unique_patterns.append(ast)
                if len(unique_patterns) >= 20:
                    break

    if len(unique_patterns) < 5:
        pytest.skip("Not enough unique patterns found in real ASTs")

    new_storage = OpcodeIndexedStorage()

    rules = []
    for i, pattern in enumerate(unique_patterns):
        class MockRule:
            pass

        rule = MockRule()
        rule.name = f"test_rule_{i}"
        rules.append(rule)

        new_storage.add_pattern(pattern, rule)

    print(f"\n  Registered {len(unique_patterns)} patterns in storage")

    return {
        "new": new_storage,
        "patterns": unique_patterns,
    }
