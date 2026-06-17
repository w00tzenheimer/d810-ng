"""Provider registration for cfg unit tests.

Some transforms-layer guards (``loop_bound_writer_guard``) route their block
lookups through the ``ConditionChainWalkerProvider`` seam rather than calling the live-MBA
method API directly (ticket llr-zeyu).  Those tests drive the guards with a fake
``mba`` exposing ``get_mblock``; register the backend-supplied provider so the
seam dispatches to it -- exactly as production wires it in
``D810State.start_d810`` via ``build_condition_chain_walker_provider``.

Importing ``d810.backends.hexrays.evidence.condition_chain_analysis`` here is contract-legal
for unit tests (the ``unit-tests-no-hexrays`` contract forbids only
``d810.hexrays``); the module defers all ``idaapi`` access, so it imports
without a live IDA.  Mirrors ``tests/unit/recon/flow/conftest.py``.
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
