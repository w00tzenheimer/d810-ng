"""Structural mutation receipt gateway contract."""
from __future__ import annotations

import importlib.util

from d810.core.events import EventEmitter
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.mutation.mba_mutation_events import (
    MbaMutationCommitted,
    MbaMutationGateway,
    StructuralMutationKind,
)
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity

def test_mutation_receipts_have_a_dedicated_module() -> None:
    assert importlib.util.find_spec("d810.hexrays.mutation.mba_mutation_events") is not None


def test_structural_receipts_advance_one_generation_and_deduplicate_identities() -> None:
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),)
    )
    gateway = MbaMutationGateway(generation=7)

    receipt = gateway.record(
        StructuralMutationKind.EDGE_REDIRECT,
        affected_identities=(identity, identity),
        description="restore bootstrap edge",
    )

    assert receipt.pre_generation == 7
    assert receipt.post_generation == 8
    assert receipt.affected_identities == (identity,)
    assert gateway.generation == 8
    assert gateway.receipts == (receipt,)


def test_gateway_shifts_live_bindings_before_emitting_its_commit_receipt() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),)
    )
    target = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),)
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="mutation-session",
        generation=7,
        bindings=((source, 5), (target, 9)),
    )
    events: list[MbaMutationCommitted] = []
    emitter = EventEmitter()
    emitter.on(MbaMutationCommitted, events.append)
    gateway = MbaMutationGateway(
        generation=7,
        session_id="mutation-session",
        function_ea=0x40D200,
        maturity=4,
        identity_index=index,
        event_emitter=emitter,
    )

    gateway.begin_batch(StructuralMutationKind.BLOCK_INSERT, serial_quantity=10)
    created = gateway.record_insert(insertion_serial=4, returned_serial=4)

    assert index.rebind_identity(source).block.serial == 6
    assert index.rebind_identity(target).block.serial == 10
    assert index.resolve(created).serial == 4
    receipt = gateway.commit()

    assert receipt.operation_count == 1
    assert index.generation == 8
    assert events == [
        MbaMutationCommitted(
            session_id="mutation-session",
            function_ea=0x40D200,
            maturity=4,
            mba_generation_before=7,
            mba_generation_after=8,
            receipt=receipt,
        )
    ]


def test_gateway_creates_independent_transactions_over_the_same_live_index() -> None:
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),)
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="mutation-session",
        generation=2,
        bindings=((identity, 5),),
    )
    gateway = MbaMutationGateway(
        generation=2,
        session_id="mutation-session",
        function_ea=0x40D200,
        maturity=4,
        identity_index=index,
    )

    transaction = gateway.new_transaction()
    transaction.begin_batch(StructuralMutationKind.BLOCK_INSERT, serial_quantity=6)
    transaction.record_insert(insertion_serial=3, returned_serial=3)
    transaction.commit()

    assert transaction is not gateway
    assert transaction.identity_index is gateway.identity_index
    assert gateway.identity_index.rebind_identity(identity).block.serial == 6
    assert gateway.identity_index.generation == 3


def test_index_keeps_clone_and_split_handles_transaction_local() -> None:
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),)
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="mutation-session",
        generation=3,
        bindings=((identity, 8),),
    )
    original = index.handle_for_serial(8)
    assert original is not None
    retained = index.create_native_handle(identity)
    split_tail = index.create_synthetic_handle()

    index.record_split(
        original=original,
        retained=retained,
        created_tail=split_tail,
        returned_tail_serial=9,
    )
    assert index.resolve(original) is None
    assert index.resolve(retained).serial == 8
    assert index.resolve(split_tail).serial == 9

    clone = index.create_native_handle(identity)
    index.record_clone(source=retained, created=clone, returned_serial=10)

    assert index.resolve(clone).serial == 10
    assert index.rebind_identity(identity).status.name == "AMBIGUOUS"
