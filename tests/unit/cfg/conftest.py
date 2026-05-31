"""Provider registration for cfg unit tests.

Some transforms-layer guards (``loop_bound_writer_guard``) route their block
lookups through the ``BstWalkerProvider`` seam rather than calling the live-MBA
method API directly (ticket llr-zeyu).  Those tests drive the guards with a fake
``mba`` exposing ``get_mblock``; register the backend-supplied provider so the
seam dispatches to it -- exactly as production wires it in
``D810State.start_d810`` via ``build_bst_walker_provider``.

Importing ``d810.backends.hexrays.evidence.bst_analysis`` here is contract-legal
for unit tests (the ``unit-tests-no-hexrays`` contract forbids only
``d810.hexrays``); the module defers all ``idaapi`` access, so it imports
without a live IDA.  Mirrors ``tests/unit/recon/flow/conftest.py``.
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
