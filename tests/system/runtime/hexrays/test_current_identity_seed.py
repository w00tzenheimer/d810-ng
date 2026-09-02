"""Runtime boundary tests for the current-CFG identity seed adapter.

The adapter is deliberately Hex-Rays-owned because it manipulates the live
``MbaBlockIdentityIndex`` freshness domain.  These tests therefore live under
the IDA runtime suite rather than the portable unit suite.
"""

from __future__ import annotations

import pytest

from d810.hexrays.ir import current_identity_seed as cff
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.transforms.cfg_transaction import LogicalBlockRef
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key()


def _block(serial: int, ea: int) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=0,
        succs=(),
        preds=(),
        flags=0,
        start_ea=ea,
        insn_snapshots=(InsnSnapshot(opcode=0, ea=ea, operands=()),),
    )


def _graph(*blocks: BlockSnapshot) -> FlowGraph:
    return FlowGraph(
        {block.serial: block for block in blocks},
        entry_serial=blocks[0].serial,
        func_ea=0x401000,
    )


def _seed(index: MbaBlockIdentityIndex | None, graph: FlowGraph) -> MbaBlockIdentityIndex:
    return cff.select_current_identity_index_for_flow_graph(
        index,
        graph,
        native_key=NATIVE_KEY,
        generation=7,
        evidence_generation=11,
        maturity=13,
        session_id="cff-current-source",
        imported_native_eas_by_serial={},
    )


def test_cff_seed_retains_a_complete_matching_index_and_logical_exit() -> None:
    native = _block(1, 0x401020)
    logical_exit = BlockSnapshot(
        serial=2,
        block_type=0,
        succs=(),
        preds=(),
        flags=0,
        start_ea=0xFFFFFFFFFFFFFFFF,
        insn_snapshots=(),
    )
    graph = _graph(native, logical_exit)
    index = MbaBlockIdentityIndex.from_flow_graph(
        generation=7, native_key=NATIVE_KEY, flow_graph=graph,
        session_id="cff-current-source", evidence_generation=11, maturity=13,
    )

    assert cff.resolver_identity_index_matches_flow_graph(
        index, graph, native_key=NATIVE_KEY,
    )
    assert _seed(index, graph) is index
    assert isinstance(index.plan_refs_by_serial()[2], LogicalBlockRef)


def test_cff_seed_rebuilds_for_extra_or_missing_serials() -> None:
    graph = _graph(_block(1, 0x401020), _block(2, 0x401040))
    extra_graph = _graph(_block(1, 0x401020), _block(2, 0x401040), _block(3, 0x401060))
    extra = MbaBlockIdentityIndex.from_flow_graph(
        generation=7, native_key=NATIVE_KEY, flow_graph=extra_graph,
        session_id="stale-extra", evidence_generation=11,
    )
    missing = MbaBlockIdentityIndex.from_flow_graph(
        generation=7, native_key=NATIVE_KEY, flow_graph=_graph(_block(1, 0x401020)),
        session_id="stale-missing", evidence_generation=11,
    )

    assert not cff.resolver_identity_index_matches_flow_graph(extra, graph, native_key=NATIVE_KEY)
    assert not cff.resolver_identity_index_matches_flow_graph(missing, graph, native_key=NATIVE_KEY)
    for stale in (extra, missing):
        rebuilt = _seed(stale, graph)
        assert set(rebuilt.plan_refs_by_serial()) == {1, 2}
        assert rebuilt.native_key == NATIVE_KEY
        assert rebuilt.generation == 7
        assert rebuilt.evidence_generation == 11
        # The source catalogue must preserve the live gateway's provider stage
        # independently of its transaction generation.
        assert rebuilt.maturity == 13


def test_cff_seed_rebuild_preserves_the_live_gateway_binding_domain() -> None:
    """A fresh source catalogue cannot mint a new transaction identity."""
    source = _graph(_block(1, 0x401020), _block(2, 0x401040))
    stale = MbaBlockIdentityIndex.from_flow_graph(
        generation=0,
        native_key=NATIVE_KEY,
        flow_graph=_graph(_block(1, 0x401020)),
        session_id="resolver-session:0x401000:1",
        evidence_generation=17,
        maturity=5,
    )

    rebuilt = cff.select_current_identity_index_for_flow_graph(
        stale,
        source,
        native_key=NATIVE_KEY,
        generation=0,
        evidence_generation=17,
        maturity=5,
        session_id="resolver-session:0x401000:1",
        imported_native_eas_by_serial={},
    )

    assert rebuilt is not stale
    assert set(rebuilt.plan_refs_by_serial()) == {1, 2}
    assert (
        rebuilt.generation,
        rebuilt.evidence_generation,
        rebuilt.maturity,
        rebuilt.session_id,
    ) == (0, 17, 5, "resolver-session:0x401000:1")


def test_cff_seed_refreshes_provider_maturity_without_minting_transaction_generation() -> None:
    """A new MBA stage needs a new catalogue in the same transaction domain."""
    source = _graph(_block(1, 0x401020), _block(2, 0x401040))
    prior = MbaBlockIdentityIndex.from_flow_graph(
        generation=0,
        native_key=NATIVE_KEY,
        flow_graph=source,
        session_id="resolver-session:0x401000:1",
        evidence_generation=17,
        maturity=5,
    )

    current = cff.refresh_current_identity_index_for_mba(
        prior,
        source,
        native_key=NATIVE_KEY,
        evidence_generation=17,
        current_maturity=6,
        imported_native_eas_by_serial={},
    )

    assert current is not prior
    assert (
        current.generation,
        current.evidence_generation,
        current.maturity,
        current.session_id,
    ) == (0, 17, 6, "resolver-session:0x401000:1")


def test_cff_seed_rebuilds_when_same_serial_has_different_native_origins() -> None:
    graph = _graph(_block(1, 0x401020))
    stale = MbaBlockIdentityIndex.from_flow_graph(
        generation=7, native_key=NATIVE_KEY,
        flow_graph=_graph(_block(1, 0x401090)),
        session_id="stale-origin", evidence_generation=11,
    )

    assert not cff.resolver_identity_index_matches_flow_graph(
        stale, graph, native_key=NATIVE_KEY,
    )
    rebuilt = _seed(stale, graph)
    ref = rebuilt.plan_refs_by_serial()[1]
    assert 0x401020 in ref.identity.exact_instruction_eas


@pytest.mark.parametrize(
    ("stale_generation", "stale_evidence_generation", "stale_session_id"),
    (
        (6, 11, "cff-current-source"),
        (7, 10, "cff-current-source"),
        (7, 11, "other-cff-session"),
    ),
)
def test_cff_seed_rebuilds_same_shape_index_from_another_freshness_domain(
    stale_generation: int,
    stale_evidence_generation: int,
    stale_session_id: str,
) -> None:
    graph = _graph(_block(1, 0x401020))
    stale = MbaBlockIdentityIndex.from_flow_graph(
        generation=stale_generation,
        native_key=NATIVE_KEY,
        flow_graph=graph,
        session_id=stale_session_id,
        evidence_generation=stale_evidence_generation,
    )

    rebuilt = _seed(stale, graph)

    assert rebuilt is not stale
    assert rebuilt.generation == 7
    assert rebuilt.evidence_generation == 11
    assert rebuilt.session_id == "cff-current-source"


def test_cff_seed_rejects_a_missing_lifecycle_binding() -> None:
    graph = _graph(_block(1, 0x401020), _block(2, 0x401040))
    with pytest.raises(TypeError, match="live resolver binding"):
        _seed(None, graph)


def test_materialized_lowering_defers_after_lifecycle_binding_is_invalidated() -> None:
    """Materialized lowering has no serial/EA fallback between MBA bindings."""
    graph = _graph(_block(1, 0x401020))
    index = MbaBlockIdentityIndex.from_flow_graph(
        generation=7,
        native_key=NATIVE_KEY,
        flow_graph=graph,
        session_id="cff-current-source",
        evidence_generation=11,
        maturity=13,
    )

    assert cff.current_materialized_lowering_identity(index) is index
    # ResolverSessionState.invalidate_current_mba_binding() clears this field.
    assert cff.current_materialized_lowering_identity(None) is None
