"Provider registration for cfg unit tests.\n\nSome transforms-layer guards (``loop_bound_writer_guard``) route their block\nlookups through the ``ConditionChainWalkerProvider`` seam rather than calling the live-MBA\nmethod API directly (ticket llr-zeyu).  Those tests drive the guards with a fake\n``mba`` exposing ``get_mblock``; register the backend-supplied provider so the\nseam dispatches to it -- exactly as production wires it in\n``D810State.start_d810`` via ``build_condition_chain_walker_provider``.\n\nImporting ``d810.backends.hexrays.evidence.condition_chain_analysis`` here is contract-legal\nfor unit tests (the ``unit-tests-no-hexrays`` contract forbids only\n``d810.hexrays``); the module defers all ``idaapi`` access, so it imports\nwithout a live IDA.  Mirrors ``tests/unit/preanalysis/flow/conftest.py``.\n"
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
