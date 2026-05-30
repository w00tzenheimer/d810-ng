"""System/runtime regression for P2: the Hex-Rays live SourceLifter survives a
registry reset via the explicit, idempotent ``ensure_hexrays_lifter_registered``.

A bare ``import d810.backends.facts.ida`` only registers once (module import is
cached in ``sys.modules``), so a prior ``reset_live_lifters_for_tests`` would
leave the registry empty.  ``Manager.start`` calls the ensure() helper instead.

IDA-bound: ``backends.facts.ida`` imports ``ida_hexrays`` via
``d810.hexrays.fact_target``, so this only collects under real IDA.
"""
from __future__ import annotations

import ida_hexrays  # noqa: F401  # gate: collected only under real IDA

import pytest

from d810.backends.facts.ida import (
    HexRaysMicrocodeLifter,
    ensure_hexrays_lifter_registered,
)
from d810.capabilities.source_lifter import (
    register_live_lifter,
    registered_lifters,
    reset_live_lifters_for_tests,
)


@pytest.fixture(autouse=True)
def _restore_registry():
    saved = registered_lifters()
    yield
    reset_live_lifters_for_tests()
    for lifter in saved:
        register_live_lifter(lifter)


def _hexrays_lifter_count() -> int:
    return sum(
        1 for lifter in registered_lifters()
        if isinstance(lifter, HexRaysMicrocodeLifter)
    )


def test_ensure_reregisters_after_reset_and_is_idempotent() -> None:
    ensure_hexrays_lifter_registered()
    assert _hexrays_lifter_count() == 1

    # Simulate a test-isolation / reload reset that clears the registry.
    reset_live_lifters_for_tests()
    assert _hexrays_lifter_count() == 0

    # The explicit ensure() restores it (a cached bare re-import would not)...
    ensure_hexrays_lifter_registered()
    # ...and repeated ensures never append a duplicate (singleton identity).
    ensure_hexrays_lifter_registered()
    assert _hexrays_lifter_count() == 1
