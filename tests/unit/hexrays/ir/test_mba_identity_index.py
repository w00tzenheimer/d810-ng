"""Current-MBA stable block identity index contract."""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass
from dataclasses import fields

import pytest

from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.ir.block_identity import (
    BlockHandleProvenance,
    CurrentMbaBlockIdentityBinding,
    CurrentMbaIdentityBindingSnapshot,
    MbaBlockHandle,
    NativeEaInterval,
    RebindStatus,
    StableBlockIdentity,
)
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.transforms.cfg_transaction import PlanBlockRef, TransactionAttemptId
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
    index.begin_transaction("import-translation", 10)
    imported = index.create_imported_native_handle(handler)
    index.record_insert(
        transaction_id="import-translation",
        insertion_serial=10,
        created=imported,
        returned_serial=10,
    )
    index.commit_proxy_transaction("import-translation")
    index.advance_generation()

    assert index.rebind_identity(handler).status is RebindStatus.AMBIGUOUS
    native_rebound = index.rebind_native_identity(handler)
    assert native_rebound.status is RebindStatus.BOUND
    assert native_rebound.block is not None
    assert native_rebound.block.serial == 9
    assert native_rebound.block.handle.provenance is BlockHandleProvenance.NATIVE
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

        @staticmethod
        def map_fict_ea(ea):
            return int(ea)

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
    unique_start_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x402000, 0x402001),), native_key=NATIVE_KEY
    )
    assert index.rebind_identity(cloned_identity).status is RebindStatus.AMBIGUOUS
    assert index.rebind_identity(unique_identity).block.serial == 2
    assert index.rebind_identity(unique_start_identity).block.serial == 2
    assert index.identity_for_serial(2).exact_instruction_eas == frozenset({0x402003})
    assert index.identity_for_serial(3) is None
    assert not hasattr(index, "mba")


def test_live_mba_identity_scan_maps_fictitious_eas_to_native_origins() -> None:
    live_predicate_ea = 0xF1C00018

    class Insn:
        ea = live_predicate_ea
        next = None

    block = type(
        "Block",
        (),
        {
            "serial": 0,
            "start": 0x401000,
            "head": Insn(),
        },
    )()
    mba = type(
        "Mba",
        (),
        {
            "qty": 1,
            "get_mblock": lambda self, _serial: block,
            "map_fict_ea": lambda self, ea: (
                0x401020 if int(ea) == live_predicate_ea else int(ea)
            ),
        },
    )()

    index = MbaBlockIdentityIndex.from_mba(
        mba,
        generation=3,
        native_key=NATIVE_KEY,
    )

    identity = index.identity_for_serial(0)
    assert identity is not None
    assert identity.native_ranges.contains(0x401000)
    assert identity.native_ranges.contains(0x401020)
    assert not identity.native_ranges.contains(live_predicate_ea)
    assert identity.exact_instruction_eas == frozenset({0x401020})


def test_live_mba_identity_scan_does_not_use_recycled_proxy_ids_as_cycles(
    monkeypatch,
) -> None:
    import d810.hexrays.ir.mba_identity_index as identity_index_module

    @dataclass
    class Insn:
        ea: int
        proxy_id: int
        next: object | None = None

    tail = Insn(0x401020, 1)
    head = Insn(0x401000, 1, Insn(0x401010, 2, tail))
    block = type(
        "Block",
        (),
        {"serial": 0, "start": 0x401000, "head": head},
    )()
    mba = type(
        "Mba",
        (),
        {
            "qty": 1,
            "get_mblock": lambda self, serial: block,
            "map_fict_ea": lambda self, ea: int(ea),
        },
    )()
    monkeypatch.setattr(
        identity_index_module,
        "id",
        lambda instruction: int(instruction.proxy_id),
        raising=False,
    )

    index = MbaBlockIdentityIndex.from_mba(
        mba,
        generation=3,
        native_key=NATIVE_KEY,
    )

    tail_identity = StableBlockIdentity.from_instruction_eas(
        (0x401020,),
        native_key=NATIVE_KEY,
    )
    assert index.rebind_identity(tail_identity).block is not None


def test_live_mba_identity_scan_uses_imported_eas_without_reading_operands() -> None:
    class Insn:
        def __init__(self, ea: int, next_insn=None) -> None:
            self.ea = ea
            self.next = next_insn

        @property
        def l(self):
            raise AssertionError("identity indexing must not inspect operands")

        r = l
        d = l

    block = type(
        "Block",
        (),
        {
            "serial": 0,
            "head": Insn(0xFFFFFFFFFFFFFF01, Insn(0x401005)),
        },
    )()
    mba = type(
        "Mba",
        (),
        {
            "qty": 1,
            "get_mblock": lambda self, serial: block,
            "map_fict_ea": lambda self, ea: int(ea),
        },
    )()

    index = MbaBlockIdentityIndex.from_mba(
        mba,
        generation=3,
        native_key=NATIVE_KEY,
        imported_instruction_origins={0xFFFFFFFFFFFFFF01: 0x40E245},
    )

    identity = index.identity_for_serial(0)
    assert identity == StableBlockIdentity.from_instruction_eas(
        (0x40E245,),
        native_key=NATIVE_KEY,
    )
    assert (
        index.handle_for_serial(0).provenance is BlockHandleProvenance.IMPORTED_NATIVE
    )


def test_live_mba_identity_scan_restores_receipted_imported_block_range() -> None:
    live_ea = 0xFFFFFFFFFFFFFF01

    class Insn:
        ea = live_ea
        next = None

    block = type(
        "Block",
        (),
        {
            "serial": 0,
            "start": 0xFFFFFFFFFFFFFFFF,
            "head": Insn(),
        },
    )()
    mba = type(
        "Mba",
        (),
        {"qty": 1, "get_mblock": lambda self, _serial: block},
    )()
    imported_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40C623, 0x40C696),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x40C630, 0x40C64B),
    )
    snapshot = CurrentMbaIdentityBindingSnapshot(
        instruction_origins=((live_ea, 0x40C64B),),
        block_bindings=(
            CurrentMbaBlockIdentityBinding(
                stable_identity=imported_identity,
                live_instruction_eas=frozenset({live_ea}),
            ),
        ),
    )

    index = MbaBlockIdentityIndex.from_mba(
        mba,
        generation=3,
        native_key=NATIVE_KEY,
        current_mba_identity_binding=snapshot,
    )
    handler_region = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40C62F, 0x40C64B),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(),
    )

    rebound = index.rebind_region_entry(handler_region)

    assert rebound.status is RebindStatus.BOUND
    assert rebound.block is not None
    assert rebound.block.serial == 0
    assert rebound.block.handle.stable_identity == StableBlockIdentity.from_intervals(
        imported_identity.native_ranges.intervals,
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x40C64B,),
    )
    assert rebound.block.handle.provenance is BlockHandleProvenance.IMPORTED_NATIVE


def test_region_rebind_keeps_overlapping_receipted_ranges_ambiguous() -> None:
    first_live_ea = 0xFFFFFFFFFFFFFF01
    second_live_ea = 0xFFFFFFFFFFFFFF02

    class Insn:
        def __init__(self, ea: int) -> None:
            self.ea = ea
            self.next = None

    blocks = (
        type(
            "Block",
            (),
            {
                "serial": 0,
                "start": 0xFFFFFFFFFFFFFFFF,
                "head": Insn(first_live_ea),
            },
        )(),
        type(
            "Block",
            (),
            {
                "serial": 1,
                "start": 0xFFFFFFFFFFFFFFFF,
                "head": Insn(second_live_ea),
            },
        )(),
    )
    mba = type(
        "Mba",
        (),
        {
            "qty": len(blocks),
            "get_mblock": lambda self, serial: blocks[serial],
        },
    )()
    first_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40C623, 0x40C696),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x40C64B,),
    )
    second_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40C620, 0x40C690),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x40C680,),
    )
    snapshot = CurrentMbaIdentityBindingSnapshot(
        instruction_origins=(
            (first_live_ea, 0x40C64B),
            (second_live_ea, 0x40C680),
        ),
        block_bindings=(
            CurrentMbaBlockIdentityBinding(
                stable_identity=first_identity,
                live_instruction_eas=frozenset({first_live_ea}),
            ),
            CurrentMbaBlockIdentityBinding(
                stable_identity=second_identity,
                live_instruction_eas=frozenset({second_live_ea}),
            ),
        ),
    )
    index = MbaBlockIdentityIndex.from_mba(
        mba,
        generation=3,
        native_key=NATIVE_KEY,
        current_mba_identity_binding=snapshot,
    )
    handler_region = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40C62F, 0x40C64B),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(),
    )

    assert index.rebind_region_entry(handler_region).status is RebindStatus.AMBIGUOUS


def test_refresh_from_live_mba_accepts_newly_published_imported_origins() -> None:
    class Insn:
        def __init__(self, ea: int) -> None:
            self.ea = ea
            self.next = None

    block = type(
        "Block",
        (),
        {
            "serial": 0,
            "start": 0xFFFFFFFFFFFFFFFF,
            "head": Insn(0xFFFFFFFFFFFFFF01),
        },
    )()
    mba = type(
        "Mba",
        (),
        {
            "qty": 1,
            "get_mblock": lambda self, serial: block,
            "map_fict_ea": lambda self, ea: int(ea),
        },
    )()
    index = MbaBlockIdentityIndex.from_mba(
        mba,
        generation=3,
        native_key=NATIVE_KEY,
    )
    native_identity = StableBlockIdentity.from_instruction_eas(
        (0x40C498,),
        native_key=NATIVE_KEY,
    )

    assert (
        index.rebind_imported_identity(native_identity).status is RebindStatus.MISSING
    )

    index.refresh_from_mba(
        mba,
        imported_instruction_origins={0xFFFFFFFFFFFFFF01: 0x40C498},
    )

    rebound = index.rebind_imported_identity(native_identity)
    assert rebound.status is RebindStatus.BOUND
    assert rebound.block is not None
    assert rebound.block.serial == 0


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


def test_region_rebinds_to_earliest_surviving_imported_native_anchor() -> None:
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

    rebound = index.rebind_region_entry(handler_region)

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


def test_region_exit_rebinds_to_latest_surviving_imported_native_anchor() -> None:
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

    rebound = index.rebind_region_exit(handler_region)

    assert rebound.status is RebindStatus.BOUND
    assert rebound.block is not None
    assert rebound.block.serial == 41


def test_region_exit_abstains_on_duplicate_latest_anchor() -> None:
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

    assert index.rebind_region_exit(handler_region).status is RebindStatus.AMBIGUOUS
    handler_region = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40E242, 0x40E280),), native_key=NATIVE_KEY
    )

    assert index.rebind_region_entry(handler_region).status is RebindStatus.AMBIGUOUS


def test_region_entry_rebinds_to_earliest_surviving_native_anchor() -> None:
    early = StableBlockIdentity.from_instruction_eas(
        (0x40A910, 0x40A915),
        native_key=NATIVE_KEY,
    )
    late = StableBlockIdentity.from_instruction_eas(
        (0x40A92F,),
        native_key=NATIVE_KEY,
    )
    region = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40A903, 0x40A93C),),
        native_key=NATIVE_KEY,
    )
    observed = []
    index = MbaBlockIdentityIndex.from_bindings(
        generation=3,
        native_key=NATIVE_KEY,
        bindings=((early, 34), (late, 35)),
        decision_observer=observed.append,
    )

    rebound = index.rebind_region_entry(region)

    assert rebound.status is RebindStatus.BOUND
    assert rebound.block is not None
    assert rebound.block.serial == 34
    assert len(observed) == 1
    assert observed[0].decision_kind == "rebind_region_entry"
    assert observed[0].identity == region
    assert observed[0].result == rebound


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


def test_rebuild_repairs_a_missing_primary_serial_before_preserving_handle() -> None:
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        generation=0,
        bindings=((identity, 5),),
        native_key=NATIVE_KEY,
    )
    original_handle = index.handle_for_serial(5)
    rebuilt = MbaBlockIdentityIndex.from_bindings(
        generation=0,
        bindings=((identity, 5),),
        native_key=NATIVE_KEY,
    )
    rebuilt._token_by_serial.pop(5)

    index._replace_with_rebuilt(rebuilt)

    rebound = index.rebind_identity(identity)
    assert rebound.block is not None
    assert rebound.block.serial == 5
    assert rebound.block.handle is original_handle


def test_rebind_observer_receives_portable_identity_and_generations() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),), native_key=NATIVE_KEY
    )
    observed = []
    index = MbaBlockIdentityIndex.from_bindings(
        generation=5,
        evidence_generation=3,
        bindings=((source, 17),),
        native_key=NATIVE_KEY,
        decision_observer=observed.append,
    )

    assert index.rebind_identity(source).status is RebindStatus.BOUND
    assert len(observed) == 1
    row = observed[0]
    assert row.identity == source
    assert row.result.block.serial == 17
    assert row.mba_generation == 5
    assert row.evidence_generation == 3


def test_ambiguous_rebind_observer_receives_every_current_candidate() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x40D348,),
    )
    observed = []
    index = MbaBlockIdentityIndex.from_bindings(
        generation=5,
        evidence_generation=3,
        bindings=((source, 17), (source, 18)),
        native_key=NATIVE_KEY,
        decision_observer=observed.append,
    )

    assert index.rebind_identity(source).status is RebindStatus.AMBIGUOUS
    assert len(observed) == 1
    assert tuple(
        (
            candidate.serial,
            candidate.anchor_ea,
            candidate.handle.stable_identity,
        )
        for candidate in observed[0].candidates
    ) == (
        (17, 0x40D348, source),
        (18, 0x40D348, source),
    )


def test_ea_rebind_prefers_unique_exact_instruction_owner_over_shared_range() -> None:
    exact_owner = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x401004,),
    )
    range_owner = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x401008,),
    )
    index = MbaBlockIdentityIndex.from_bindings(
        generation=0,
        bindings=((exact_owner, 4), (range_owner, 5)),
        native_key=NATIVE_KEY,
    )

    exact = index.rebind_native_ea(0x401004)
    ambiguous = index.rebind_native_ea(0x401006)

    assert exact.status is RebindStatus.BOUND
    assert exact.block is not None
    assert exact.block.serial == 4
    assert ambiguous.status is RebindStatus.AMBIGUOUS


def test_ea_rebind_accepts_explicit_owner_only_when_it_owns_the_ea() -> None:
    first = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x401004,),
    )
    second = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x401008,),
    )
    index = MbaBlockIdentityIndex.from_bindings(
        generation=0,
        bindings=((first, 4), (second, 5)),
        native_key=NATIVE_KEY,
    )
    second_owner = index.handle_for_serial(5)
    assert second_owner is not None

    rebound = index.rebind_native_ea(0x401006, owner=second_owner)

    assert rebound.status is RebindStatus.BOUND
    assert rebound.block is not None
    assert rebound.block.serial == 5
    assert (
        index.rebind_native_ea(0x402000, owner=second_owner).status
        is RebindStatus.MISSING
    )


def test_every_initial_binding_has_one_logical_proxy() -> None:
    first = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),), native_key=NATIVE_KEY
    )
    second = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x402000, 0x402010),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        generation=2,
        bindings=((first, 4), (second, 5)),
        native_key=NATIVE_KEY,
    )

    assert index.logical_proxy_count == 2
    assert index.logical_proxy_for_handle(index.handle_for_serial(4)) is not None
    assert index.logical_proxy_for_handle(index.handle_for_serial(5)) is not None


def test_proxy_commit_preflights_every_future_binding_before_promotion() -> None:
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),),
        native_key=NATIVE_KEY,
    )
    index = MbaBlockIdentityIndex.from_bindings(
        generation=2,
        bindings=((identity, 4),),
        native_key=NATIVE_KEY,
    )
    original = index.handle_for_serial(4)
    assert original is not None
    proxy = index.logical_proxy_for_handle(original)
    assert proxy is not None
    replacement = index.create_native_handle(identity)
    index.begin_transaction("missing-binding", 5)
    staged = index.stage_replacement(
        transaction_id="missing-binding",
        original=original,
        replacement=replacement,
        returned_serial=4,
    )
    index._serials_by_transaction["missing-binding"].pop(replacement.token)

    with pytest.raises(ValueError, match="future published logical block"):
        index.commit_proxy_transaction("missing-binding")

    assert proxy.resolve().handle is original
    assert proxy.resolve(transaction_id="missing-binding") is staged
    assert index.resolve(original).serial == 4
    index.abort_proxy_transaction("missing-binding")


def test_inserted_replacement_stages_one_proxy_and_shifts_transaction_view() -> None:
    original_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),),
        native_key=NATIVE_KEY,
    )
    later_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x402000, 0x402010),),
        native_key=NATIVE_KEY,
    )
    index = MbaBlockIdentityIndex.from_bindings(
        generation=2,
        bindings=((original_identity, 2), (later_identity, 5)),
        native_key=NATIVE_KEY,
    )
    original = index.handle_for_serial(2)
    later = index.handle_for_serial(5)
    assert original is not None
    assert later is not None
    original_proxy = index.logical_proxy_for_handle(original)
    assert original_proxy is not None
    replacement = index.create_native_handle(original_identity)
    index.begin_transaction("inserted-replacement", 6)
    proxy_count_before_stage = index.logical_proxy_count

    staged = index.stage_inserted_replacement(
        transaction_id="inserted-replacement",
        original=original,
        replacement=replacement,
        insertion_serial=5,
        returned_serial=5,
    )

    assert index.logical_proxy_count == proxy_count_before_stage
    assert index.logical_proxy_for_handle(replacement) is original_proxy
    assert index.resolve(original).serial == 2
    assert index.resolve(later).serial == 5
    assert (
        index.resolve(
            original,
            transaction_id="inserted-replacement",
        ).serial
        == 5
    )
    assert (
        index.resolve(
            later,
            transaction_id="inserted-replacement",
        ).serial
        == 6
    )
    assert (
        index.resolve_logical_version(
            original_proxy.resolve(),
            transaction_id="inserted-replacement",
        ).serial
        == 2
    )
    assert staged.predecessor_version_id == original_proxy.resolve().version_id

    transitions = index.commit_proxy_transaction("inserted-replacement")

    assert index.resolve(original).handle is replacement
    assert index.resolve(original).serial == 5
    assert index.resolve(later).serial == 6
    assert len(transitions) == 1


def test_reserved_synthetic_proxy_binds_only_when_insertion_is_realized() -> None:
    first_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),),
        native_key=NATIVE_KEY,
    )
    later_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x402000, 0x402010),),
        native_key=NATIVE_KEY,
    )
    index = MbaBlockIdentityIndex.from_bindings(
        generation=2,
        bindings=((first_identity, 0), (later_identity, 1)),
        native_key=NATIVE_KEY,
    )
    later = index.handle_for_serial(1)
    assert later is not None
    proxy_count = index.logical_proxy_count
    attempt = TransactionAttemptId(
        plan_id="plan-a",
        session_id=index.session_id,
        generation=index.generation,
        attempt_id="reserved-synthetic",
    )
    plan_ref = PlanBlockRef("plan-a", "helper")
    index.begin_transaction(attempt, 2)
    reservation = index.reserve_plan_block(attempt, plan_ref)
    helper = reservation.logical_version.handle
    staged = reservation.logical_version

    proxy = index.logical_proxy_for_handle(helper)
    assert proxy is not None
    assert proxy.resolve() is None
    assert proxy.resolve(transaction_id=attempt.attempt_id) is staged
    assert (
        index.resolve_logical_version(staged, transaction_id=attempt.attempt_id) is None
    )
    assert index.logical_proxy_count == proxy_count + 1

    receipt = index.bind_reserved_plan_block(
        attempt,
        plan_ref,
        insertion_serial=1,
        returned_serial=1,
    )

    bound = index.resolve_logical_version(
        staged,
        transaction_id=attempt.attempt_id,
    )
    assert bound is not None and bound.serial == 1
    assert receipt.plan_ref == plan_ref
    assert receipt.attempt_id == attempt
    assert receipt.logical_version is staged
    assert receipt.insertion_serial == 1
    assert receipt.returned_serial == 1
    assert receipt.block == bound
    shifted = index.resolve(later, transaction_id=attempt.attempt_id)
    assert shifted is not None and shifted.serial == 2

    discarded = index.abort_proxy_transaction(attempt.attempt_id)

    assert discarded == (staged,)
    assert index.logical_proxy_for_handle(helper) is None
    assert index.logical_proxy_count == proxy_count
    assert index.resolve(later).serial == 1


def test_inserted_replacement_abort_preserves_published_coordinates() -> None:
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),),
        native_key=NATIVE_KEY,
    )
    index = MbaBlockIdentityIndex.from_bindings(
        generation=2,
        bindings=((identity, 2),),
        native_key=NATIVE_KEY,
    )
    original = index.handle_for_serial(2)
    assert original is not None
    replacement = index.create_native_handle(identity)
    index.begin_transaction("abort-inserted-replacement", 3)
    staged = index.stage_inserted_replacement(
        transaction_id="abort-inserted-replacement",
        original=original,
        replacement=replacement,
        insertion_serial=2,
        returned_serial=2,
    )
    original_proxy = index.logical_proxy_for_handle(original)
    assert original_proxy is not None
    assert (
        index.resolve_logical_version(
            original_proxy.resolve(),
            transaction_id="abort-inserted-replacement",
        ).serial
        == 3
    )

    discarded = index.abort_proxy_transaction("abort-inserted-replacement")

    assert discarded == (staged,)
    assert index.resolve(original).handle is original
    assert index.resolve(original).serial == 2
    assert index.resolve(replacement) is None


def test_plan_block_receipt_preserves_requested_and_returned_coordinates() -> None:
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="session-a",
        generation=4,
        bindings=((identity, 4),),
        native_key=NATIVE_KEY,
    )
    original = index.handle_for_serial(4)
    assert original is not None
    attempt = TransactionAttemptId(
        plan_id="plan-a",
        session_id=index.session_id,
        generation=index.generation,
        attempt_id="attempt-divergent-coordinate",
    )
    plan_ref = PlanBlockRef("plan-a", "created")
    index.begin_transaction(attempt, 5)
    index.reserve_plan_block(attempt, plan_ref)

    receipt = index.bind_reserved_plan_block(
        attempt,
        plan_ref,
        insertion_serial=2,
        returned_serial=3,
    )

    assert receipt.insertion_serial == 2
    assert receipt.returned_serial == 3
    assert receipt.block.serial == 3
    assert index.resolve(original, transaction_id=attempt.attempt_id).serial == 5


def test_plan_replacement_reserves_native_identity_before_sdk_binding() -> None:
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="session-a",
        generation=4,
        bindings=((identity, 2),),
        native_key=NATIVE_KEY,
    )
    original = index.handle_for_serial(2)
    assert original is not None
    replacement = index.create_native_handle(identity)
    attempt = TransactionAttemptId(
        plan_id="plan-a",
        session_id=index.session_id,
        generation=index.generation,
        attempt_id="attempt-native-replacement",
    )
    plan_ref = PlanBlockRef("plan-a", "replacement")
    index.begin_transaction(attempt, 3)

    reservation = index.reserve_plan_block(
        attempt,
        plan_ref,
        handle=replacement,
        replaces=original,
    )

    assert reservation.logical_version.handle is replacement
    assert index.resolve(replacement, transaction_id=attempt.attempt_id) is None

    receipt = index.bind_reserved_plan_block(
        attempt,
        plan_ref,
        insertion_serial=2,
        returned_serial=2,
    )

    assert receipt.logical_version is reservation.logical_version
    assert receipt.block.serial == 2
    assert index.resolve(original, transaction_id=attempt.attempt_id) == receipt.block


def test_generic_insert_cannot_consume_a_typed_plan_reservation() -> None:
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="session-a",
        generation=3,
        bindings=((identity, 2),),
        native_key=NATIVE_KEY,
    )
    original = index.handle_for_serial(2)
    assert original is not None
    attempt = TransactionAttemptId(
        plan_id="plan-a",
        session_id=index.session_id,
        generation=index.generation,
        attempt_id="typed-only",
    )
    plan_ref = PlanBlockRef("plan-a", "created")
    index.begin_transaction(attempt, 3)
    reservation = index.reserve_plan_block(attempt, plan_ref)

    with pytest.raises(ValueError, match="bind_reserved_plan_block"):
        index.record_insert(
            transaction_id=attempt.attempt_id,
            insertion_serial=1,
            created=reservation.logical_version.handle,
            returned_serial=1,
        )

    assert index.resolve(original, transaction_id=attempt.attempt_id).serial == 2
    assert index.plan_creation_receipts == ()

    receipt = index.bind_reserved_plan_block(
        attempt,
        plan_ref,
        insertion_serial=1,
        returned_serial=1,
    )
    assert receipt.block.serial == 1
    assert index.resolve(original, transaction_id=attempt.attempt_id).serial == 3
    assert index.plan_creation_receipts == (receipt,)


def test_plan_block_replay_allocates_new_attempt_local_realization() -> None:
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="session-a",
        generation=2,
        bindings=(),
        native_key=NATIVE_KEY,
    )
    plan_ref = PlanBlockRef("plan-a", "same-plan-block")
    first_attempt = TransactionAttemptId(
        plan_id="plan-a",
        session_id=index.session_id,
        generation=index.generation,
        attempt_id="attempt-abort",
    )
    index.begin_transaction(first_attempt, 0)
    first = index.reserve_plan_block(first_attempt, plan_ref)
    index.abort_proxy_transaction(first_attempt.attempt_id)

    assert index.resolve(first.logical_version.handle) is None

    second_attempt = TransactionAttemptId(
        plan_id="plan-a",
        session_id=index.session_id,
        generation=index.generation,
        attempt_id="attempt-replay",
    )
    index.begin_transaction(second_attempt, 0)
    second = index.reserve_plan_block(second_attempt, plan_ref)

    assert second.logical_version.handle is not first.logical_version.handle
    assert second.logical_version.version_id != first.logical_version.version_id


def test_serial_space_imports_are_observed_not_created() -> None:
    index = MbaBlockIdentityIndex.from_bindings(
        generation=3,
        bindings=(),
        native_key=NATIVE_KEY,
    )
    index.ensure_serial_space(1)

    observed = index.handle_for_serial(0)
    assert observed is not None
    assert observed.provenance is BlockHandleProvenance.OBSERVED_EPHEMERAL
    assert not hasattr(BlockHandleProvenance, "SYNTHETIC")
    assert not hasattr(MbaBlockHandle, "synthetic")
    assert not hasattr(index, "create_synthetic_handle")


def test_identity_index_has_no_parallel_stale_token_authority() -> None:
    assert "_stale_tokens" not in {
        field.name for field in fields(MbaBlockIdentityIndex)
    }
