"""Provider registration for recon-flow unit tests.

The recon BST-transition analyses read their Hex-Rays walker seams from
``d810.capabilities.providers`` -- they no longer import the vendor backend
directly (ticket d81-1w16).  Several of these unit tests exercise the *real*
portable constant-folding evaluation, so register the backend-supplied provider
before each test (production wires the identical bundle in
``D810State.start_d810`` via ``build_bst_walker_provider``).

Importing ``d810.backends.hexrays.evidence.bst_analysis`` here is contract-legal
for unit tests (the ``unit-tests-no-hexrays`` contract forbids only
``d810.hexrays``); the module defers all ``idaapi`` access, so it imports without
a live IDA.  Tests that want a stub still monkeypatch the module-level seam name
in place, which overrides the registry for that call.
"""
from __future__ import annotations

import pytest

from d810.backends.hexrays.evidence.bst_analysis import build_bst_walker_provider
from d810.capabilities.providers import (
    register_bst_walkers,
    reset_providers_for_tests,
)


@pytest.fixture(autouse=True)
def _register_bst_walkers():
    register_bst_walkers(build_bst_walker_provider())
    yield
    reset_providers_for_tests()
