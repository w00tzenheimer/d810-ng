"""Pure contracts for the canonical native-preanalysis fact aggregate."""

from __future__ import annotations

import pytest

from d810.analyses.control_flow.detached_handler_island import (
    DetachedSnippetBoundaryPorts,
)
from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisFacts,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
)
from d810.analyses.control_flow.native_semantic_closure import NativeBlock, NativeCfg
from d810.core.native_preanalysis_key import NativePreanalysisKeyMismatch
from tests.native_preanalysis import make_native_key


def _facts(*, key=None, blocks=()) -> NativePreanalysisFacts:
    native_key = key or make_native_key()
    return NativePreanalysisFacts(
        key=native_key,
        native_cfg=NativeCfg({block.start_ea: block for block in blocks}),
        semantic_closure=None,
        transfers=(),
        boundary_ports=DetachedSnippetBoundaryPorts((), ()),
    )


def test_native_preanalysis_facts_require_one_matching_portable_key() -> None:
    key = make_native_key()
    facts = _facts(key=key)

    assert facts.key is key
    assert facts.native_cfg.blocks_by_ea == {}
    assert facts.transfers == ()
    assert facts.boundary_ports == DetachedSnippetBoundaryPorts((), ())


def test_native_preanalysis_facts_reject_evidence_from_another_key() -> None:
    key = make_native_key()
    other = make_native_key(profile_fingerprint="sha256:test-profile-b")

    with pytest.raises(NativePreanalysisKeyMismatch):
        _facts(key=other).require_key(key)


def test_native_preanalysis_facts_have_value_semantics_for_changed_cfg() -> None:
    key = make_native_key()
    empty = _facts(key=key)
    same = _facts(key=key)
    changed = _facts(key=key, blocks=(NativeBlock(0x401000, 0x401010),))

    assert empty == same
    assert empty != changed


def test_native_preanalysis_facts_normalize_transfer_order_and_duplicates() -> None:
    key = make_native_key()
    earlier = MaterializedIndirectTransfer(
        source_jmp_ea=0x401000,
        source_block_ea=0x401000,
        materialized_anchor_eas=(0x401000,),
        target_eas=(0x402000,),
    )
    later = MaterializedIndirectTransfer(
        source_jmp_ea=0x401100,
        source_block_ea=0x401100,
        materialized_anchor_eas=(0x401100,),
        target_eas=(0x402100,),
    )

    facts = NativePreanalysisFacts(
        key=key,
        native_cfg=NativeCfg({}),
        semantic_closure=None,
        transfers=(later, earlier, later),
        boundary_ports=DetachedSnippetBoundaryPorts((), ()),
    )

    assert facts.transfers == (earlier, later)
