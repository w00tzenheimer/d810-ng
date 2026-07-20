"""Current-MBA stable block identity index contract."""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass

from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.ir.block_identity import (
    BlockHandleProvenance,
    MbaBlockHandle,
    NativeEaInterval,
    RebindStatus,
    StableBlockIdentity,
)
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from tests.native_preanalysis import make_native_key

NATIVE_KEY = make_native_key()


def test_live_mba_identity_index_has_a_dedicated_module() -> None:
    assert importlib.util.find_spec("d810.hexrays.ir.mba_identity_index") is not None


def test_rebinds_only_unique_current_native_identity() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),), native_key=NATIVE_KEY
    )
    ambiguous = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        generation=4,
        bindings=((source, 17), (ambiguous, 18), (ambiguous, 19)),
        native_key=NATIVE_KEY,
    )

    rebound = index.rebind_identity(source)
    assert rebound.status is RebindStatus.BOUND
    assert rebound.block is not None
    assert rebound.block.serial == 17
    assert rebound.block.generation == 4
    assert rebound.block.handle.stable_identity == source
    assert index.rebind_identity(ambiguous).status is RebindStatus.AMBIGUOUS
    assert (
        index.rebind(
            MbaBlockHandle.native(
                source,
                session_id="prior-mba",
                token="old-source",
            )
        ).status
        is RebindStatus.STALE_GENERATION
    )


def test_imported_native_rebind_disambiguates_a_live_translation_clone() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),), native_key=NATIVE_KEY
    )
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        generation=0, bindings=((source, 7), (handler, 9)), native_key=NATIVE_KEY
    )
    index.begin_transaction(10)
    imported = index.create_imported_native_handle(handler)
    index.record_insert(
        insertion_serial=10,
        created=imported,
        returned_serial=10,
    )

    assert index.rebind_identity(handler).status is RebindStatus.AMBIGUOUS
    rebound = index.rebind_imported_identity(handler)
    assert rebound.status is RebindStatus.BOUND
    assert rebound.block is not None
    assert rebound.block.serial == 10
    assert rebound.block.handle is imported


def test_builds_live_generation_bindings_from_portable_mba_snapshot() -> None:
    """The adapter may bind a current MBA, but durable state retains no serial."""
    source_block = BlockSnapshot(
        serial=17,
        block_type=0,
        succs=(),
        preds=(),
        flags=0,
        start_ea=0x40D348,
        insn_snapshots=(InsnSnapshot(opcode=0, ea=0x40D348, operands=()),),
    )
    handler_block = BlockSnapshot(
        serial=42,
        block_type=0,
        succs=(),
        preds=(),
        flags=0,
        start_ea=0x40EAA7,
        insn_snapshots=(InsnSnapshot(opcode=0, ea=0x40EAA7, operands=()),),
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
        native_key=NATIVE_KEY,
    )

    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),), native_key=NATIVE_KEY
    )
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),), native_key=NATIVE_KEY
    )
    assert index.rebind_identity(source).block is not None
    assert index.rebind_identity(source).block.serial == 17
    assert index.rebind_identity(handler).block is not None
    assert index.rebind_identity(handler).block.serial == 42
    assert len(index.serials_by_identity) == 2


def test_builds_from_live_mba_without_retaining_it_and_abstains_on_cloned_eas() -> None:
    @dataclass
    class Insn:
        ea: int
        next: object | None = None

    @dataclass
    class Block:
        serial: int
        start: int
        head: object | None

    first_tail = Insn(0x401005)
    first = Block(0, 0x401000, Insn(0x401000, first_tail))
    clone = Block(1, 0x401000, Insn(0x401000, Insn(0x401005)))
    unique = Block(2, 0x402000, Insn(0x402003))
    synthetic = Block(3, 0xFFFFFFFFFFFFFFFF, None)
    blocks = {block.serial: block for block in (first, clone, unique, synthetic)}

    class Mba:
        qty = 4

        @staticmethod
        def get_mblock(serial):
            return blocks.get(int(serial))

    mba = Mba()
    index = MbaBlockIdentityIndex.from_mba(
        mba, generation=7, session_id="live-test", native_key=NATIVE_KEY
    )

    cloned_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401005, 0x401006),), native_key=NATIVE_KEY
    )
    unique_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x402003, 0x402004),), native_key=NATIVE_KEY
    )
    assert index.rebind_identity(cloned_identity).status is RebindStatus.AMBIGUOUS
    assert index.rebind_identity(unique_identity).block.serial == 2
    assert index.identity_for_serial(3) is None
    assert not hasattr(index, "mba")


def test_imported_native_origins_replace_synthetic_snapshot_identity() -> None:
    synthetic_block = BlockSnapshot(
        serial=40,
        block_type=0,
        succs=(),
        preds=(),
        flags=0,
        start_ea=0xFFFFFFFFFFFFFFFF,
        insn_snapshots=(),
    )
    index = MbaBlockIdentityIndex.from_flow_graph(
        generation=3,
        flow_graph=FlowGraph(
            blocks={40: synthetic_block},
            entry_serial=40,
            func_ea=0x40D200,
        ),
        imported_native_eas_by_serial={40: (0x40E245, 0x40E260)},
        native_key=NATIVE_KEY,
    )

    identity = index.identity_for_serial(40)
    assert identity == StableBlockIdentity.from_intervals(
        (
            NativeEaInterval(0x40E245, 0x40E246),
            NativeEaInterval(0x40E260, 0x40E261),
        ),
        native_key=NATIVE_KEY,
    )
    assert (
        index.handle_for_serial(40).provenance is BlockHandleProvenance.IMPORTED_NATIVE
    )
    assert index.rebind_imported_identity(identity).block.serial == 40


def test_imported_region_rebinds_to_earliest_surviving_native_anchor() -> None:
    blocks = {
        serial: BlockSnapshot(
            serial=serial,
            block_type=0,
            succs=(),
            preds=(),
            flags=0,
            start_ea=0xFFFFFFFFFFFFFFFF,
            insn_snapshots=(),
        )
        for serial in (40, 41)
    }
    index = MbaBlockIdentityIndex.from_flow_graph(
        generation=3,
        flow_graph=FlowGraph(
            blocks=blocks,
            entry_serial=40,
            func_ea=0x40D200,
        ),
        imported_native_eas_by_serial={
            40: (0x40E245, 0x40E260),
            41: (0x40F12D,),
        },
        native_key=NATIVE_KEY,
    )
    handler_region = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40E242, 0x40E280),), native_key=NATIVE_KEY
    )

    rebound = index.rebind_imported_region_entry(handler_region)

    assert rebound.status is RebindStatus.BOUND
    assert rebound.block is not None
    assert rebound.block.serial == 40
    assert rebound.block.anchor_ea == 0x40E245


def test_imported_region_rebind_abstains_on_duplicate_earliest_anchor() -> None:
    blocks = {
        serial: BlockSnapshot(
            serial=serial,
            block_type=0,
            succs=(),
            preds=(),
            flags=0,
            start_ea=0xFFFFFFFFFFFFFFFF,
            insn_snapshots=(),
        )
        for serial in (40, 41)
    }
    index = MbaBlockIdentityIndex.from_flow_graph(
        generation=3,
        flow_graph=FlowGraph(
            blocks=blocks,
            entry_serial=40,
            func_ea=0x40D200,
        ),
        imported_native_eas_by_serial={40: (0x40E245,), 41: (0x40E245,)},
        native_key=NATIVE_KEY,
    )


def test_imported_region_exit_rebinds_to_latest_surviving_native_anchor() -> None:
    blocks = {
        serial: BlockSnapshot(
            serial=serial,
            block_type=0,
            succs=(),
            preds=(),
            flags=0,
            start_ea=0xFFFFFFFFFFFFFFFF,
            insn_snapshots=(),
        )
        for serial in (40, 41)
    }
    index = MbaBlockIdentityIndex.from_flow_graph(
        generation=3,
        flow_graph=FlowGraph(
            blocks=blocks,
            entry_serial=40,
            func_ea=0x40D200,
        ),
        imported_native_eas_by_serial={
            40: (0x40E245,),
            41: (0x40E260, 0x40E27A),
        },
        native_key=NATIVE_KEY,
    )
    handler_region = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40E242, 0x40E280),), native_key=NATIVE_KEY
    )

    rebound = index.rebind_imported_region_exit(handler_region)

    assert rebound.status is RebindStatus.BOUND
    assert rebound.block is not None
    assert rebound.block.serial == 41


def test_imported_region_exit_abstains_on_duplicate_latest_anchor() -> None:
    blocks = {
        serial: BlockSnapshot(
            serial=serial,
            block_type=0,
            succs=(),
            preds=(),
            flags=0,
            start_ea=0xFFFFFFFFFFFFFFFF,
            insn_snapshots=(),
        )
        for serial in (40, 41)
    }
    index = MbaBlockIdentityIndex.from_flow_graph(
        generation=3,
        flow_graph=FlowGraph(
            blocks=blocks,
            entry_serial=40,
            func_ea=0x40D200,
        ),
        imported_native_eas_by_serial={40: (0x40E27A,), 41: (0x40E27A,)},
        native_key=NATIVE_KEY,
    )
    handler_region = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40E242, 0x40E280),), native_key=NATIVE_KEY
    )

    assert (
        index.rebind_imported_region_exit(handler_region).status
        is RebindStatus.AMBIGUOUS
    )
    handler_region = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40E242, 0x40E280),), native_key=NATIVE_KEY
    )

    assert (
        index.rebind_imported_region_entry(handler_region).status
        is RebindStatus.AMBIGUOUS
    )


def test_index_keeps_evidence_and_mutation_generations_independent() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        generation=0,
        evidence_generation=4,
        bindings=((source, 17),),
        native_key=NATIVE_KEY,
    )

    index.advance_generation()

    assert index.evidence_generation == 4
    assert index.rebind_identity(source).block.generation == 1
