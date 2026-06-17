"""Provider registration for recon-flow unit tests.

The recon condition-chain transition analyses read their Hex-Rays walker seams from
``d810.capabilities.providers`` -- they no longer import the vendor backend
directly (ticket d81-1w16).  Several of these unit tests exercise the *real*
portable constant-folding evaluation, so register the backend-supplied provider
before each test (production wires the identical bundle in
``D810State.start_d810`` via ``build_condition_chain_walker_provider``).

Importing ``d810.backends.hexrays.evidence.condition_chain_analysis`` here is contract-legal
for unit tests (the ``unit-tests-no-hexrays`` contract forbids only
``d810.hexrays``); the module defers all ``idaapi`` access, so it imports without
a live IDA.  Tests that want a stub still monkeypatch the module-level seam name
in place, which overrides the registry for that call.
"""
from __future__ import annotations

import pytest

from d810.backends.hexrays.evidence.condition_chain_analysis import build_condition_chain_walker_provider
from d810.capabilities.providers import (
    register_condition_chain_walkers,
    reset_providers_for_tests,
)


@pytest.fixture(autouse=True)
def _register_condition_chain_walkers():
    register_condition_chain_walkers(build_condition_chain_walker_provider())
    yield
    reset_providers_for_tests()
