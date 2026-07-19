"""Current-MBA stable block identity index contract."""
from __future__ import annotations

import importlib.util

from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.ir.block_identity import (
    MbaBlockHandle,
    NativeEaInterval,
    RebindStatus,
    StableBlockIdentity,
)
from d810.ir.flowgraph import BlockSnapshot, FlowGraph

def test_live_mba_identity_index_has_a_dedicated_module() -> None:
    assert importlib.util.find_spec("d810.hexrays.ir.mba_identity_index") is not None


def test_rebinds_only_unique_current_native_identity() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),)
    )
    ambiguous = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),)
    )
    index = MbaBlockIdentityIndex.from_bindings(
        generation=4,
        bindings=((source, 17), (ambiguous, 18), (ambiguous, 19)),
    )

    rebound = index.rebind_identity(source)
    assert rebound.status is RebindStatus.BOUND
    assert rebound.block is not None
    assert rebound.block.serial == 17
    assert rebound.block.generation == 4
    assert rebound.block.handle.identity == source
    assert index.rebind_identity(ambiguous).status is RebindStatus.AMBIGUOUS
    assert index.rebind(
        MbaBlockHandle.native(
            source,
            session_id="prior-mba",
            token="old-source",
        )
    ).status is RebindStatus.STALE_GENERATION


def test_builds_live_generation_bindings_from_portable_mba_snapshot() -> None:
    """The adapter may bind a current MBA, but durable state retains no serial."""
    source_block = BlockSnapshot(
        serial=17,
        block_type=0,
        succs=(),
        preds=(),
        flags=0,
        start_ea=0x40D348,
        insn_snapshots=(),
    )
    handler_block = BlockSnapshot(
        serial=42,
        block_type=0,
        succs=(),
        preds=(),
        flags=0,
        start_ea=0x40EAA7,
        insn_snapshots=(),
    )
    synthetic_block = BlockSnapshot(
        serial=99,
        block_type=0,
        succs=(),
        preds=(),
        flags=0,
        start_ea=0xFFFFFFFFFFFFFFFF,
        insn_snapshots=(),
    )
    index = MbaBlockIdentityIndex.from_flow_graph(
        generation=1,
        flow_graph=FlowGraph(
            blocks={17: source_block, 42: handler_block, 99: synthetic_block},
            entry_serial=17,
            func_ea=0x40D200,
        ),
    )

    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),)
    )
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),)
    )
    assert index.rebind_identity(source).block is not None
    assert index.rebind_identity(source).block.serial == 17
    assert index.rebind_identity(handler).block is not None
    assert index.rebind_identity(handler).block.serial == 42
    assert len(index.serials_by_identity) == 2


def test_index_keeps_evidence_and_mutation_generations_independent() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),)
    )
    index = MbaBlockIdentityIndex.from_bindings(
        generation=0,
        evidence_generation=4,
        bindings=((source, 17),),
    )

    index.advance_generation()

    assert index.evidence_generation == 4
    assert index.rebind_identity(source).block.generation == 1
