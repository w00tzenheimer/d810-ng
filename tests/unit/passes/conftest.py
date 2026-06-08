"""Provider registration for passes unit tests.

After the S4 C3 flip (ticket llr-1szn) ``emit_minimal_unflatten`` sources its
back-edge next-states from the region-partitioned constant fixpoint
(``run_snapshot_constant_fixpoint`` -> ``_transfer_snapshot_constant_block`` ->
``_forward_eval_insn``), which routes through the ``BstWalkerProvider`` seam --
a fail-loud recon dependency the composition root (``D810State.start_d810``)
wires via ``build_bst_walker_provider``.  The previous per-region walk
(``_resolve_back_edge_states``) short-circuited on a synthetic graph with no
dispatcher regions, so the pass-chain unit tests never reached the seam; the
global fixpoint walks every block and does.

Register the backend-supplied provider so the seam dispatches -- exactly as
production does.  Importing ``d810.backends.hexrays.evidence.bst_analysis`` is
contract-legal for unit tests (``unit-tests-no-hexrays`` forbids only
``d810.hexrays``; this module defers all ``idaapi`` access, so it imports without
a live IDA).  Mirrors ``tests/unit/cfg/conftest.py`` and
``tests/unit/recon/flow/conftest.py``.
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
