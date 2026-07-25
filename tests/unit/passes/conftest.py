"Provider registration for passes unit tests.\n\nAfter the S4 C3 flip (ticket llr-1szn) ``emit_minimal_unflatten`` sources its\nback-edge next-states from the region-partitioned constant fixpoint\n(``run_snapshot_constant_fixpoint`` -> ``_transfer_snapshot_constant_block`` ->\n``_forward_eval_insn``), which routes through the ``ConditionChainWalkerProvider`` seam --\na fail-loud preanalysis dependency the composition root (``D810State.start_d810``)\nwires via ``build_condition_chain_walker_provider``.  The previous per-region walk\n(``_resolve_back_edge_states``) short-circuited on a synthetic graph with no\ndispatcher regions, so the pass-chain unit tests never reached the seam; the\nglobal fixpoint walks every block and does.\n\nRegister the backend-supplied provider so the seam dispatches -- exactly as\nproduction does.  Importing ``d810.backends.hexrays.evidence.condition_chain_analysis`` is\ncontract-legal for unit tests (``unit-tests-no-hexrays`` forbids only\n``d810.hexrays``; this module defers all ``idaapi`` access, so it imports without\na live IDA).  Mirrors ``tests/unit/cfg/conftest.py`` and\n``tests/unit/preanalysis/flow/conftest.py``.\n"

from __future__ import annotations

import pytest

from d810.backends.hexrays.evidence.condition_chain_analysis import (
    build_condition_chain_walker_provider,
)
from d810.capabilities.providers import (
    register_condition_chain_walkers,
    reset_providers_for_tests,
)


@pytest.fixture(autouse=True)
def _register_condition_chain_walkers():
    register_condition_chain_walkers(build_condition_chain_walker_provider())
    yield
    reset_providers_for_tests()
