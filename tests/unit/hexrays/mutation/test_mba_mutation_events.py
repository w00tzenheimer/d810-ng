"""Structural mutation receipt gateway contract."""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass

import pytest

from d810.core.events import EventEmitter
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.mutation.mba_mutation_events import (
    MbaMutationAborted,
    MbaMutationCommitted,
    MbaMutationGateway,
    MbaMutationPlanned,
    StructuralMutationKind,
)
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from tests.native_preanalysis import make_native_key

NATIVE_KEY = make_native_key()


def test_mutation_receipts_have_a_dedicated_module() -> None:
    assert (
        importlib.util.find_spec("d810.hexrays.mutation.mba_mutation_events")
        is not None
    )


def test_structural_receipts_advance_one_generation_and_deduplicate_identities() -> (
    None
):
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="mutation-gateway",
        generation=7,
        bindings=(),
        native_key=NATIVE_KEY,
    )
    gateway = MbaMutationGateway(
        generation=7,
        native_key=NATIVE_KEY,
        identity_index=index,
    )

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
        (NativeEaInterval(0x40D348, 0x40D349),), native_key=NATIVE_KEY
    )
    target = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="mutation-session",
        generation=7,
        bindings=((source, 5), (target, 9)),
        native_key=NATIVE_KEY,
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
        native_key=NATIVE_KEY,
    )

    gateway.begin_batch(StructuralMutationKind.BLOCK_INSERT, serial_quantity=10)
    created = gateway.record_insert(insertion_serial=4, returned_serial=4)

    assert index.rebind_identity(source).block.serial == 5
    assert index.rebind_identity(target).block.serial == 9
    assert index.resolve(created) is None
    assert gateway.resolve_block(index.handle_for_serial(5)).serial == 6
    assert gateway.resolve_block(index.handle_for_serial(9)).serial == 10
    assert gateway.resolve_block(created).serial == 4
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
            evidence_generation=7,
            receipt=receipt,
        )
    ]


def test_gateway_correlates_plan_commit_and_abort_with_batch_ids() -> None:
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="mutation-session",
        generation=2,
        bindings=(),
        native_key=NATIVE_KEY,
    )
    emitter = EventEmitter()
    planned = []
    committed = []
    aborted = []
    emitter.on(MbaMutationPlanned, planned.append)
    emitter.on(MbaMutationCommitted, committed.append)
    emitter.on(MbaMutationAborted, aborted.append)
    gateway = MbaMutationGateway(
        generation=2,
        session_id="mutation-session",
        function_ea=0x40D200,
        maturity=4,
        identity_index=index,
        event_emitter=emitter,
        native_key=NATIVE_KEY,
    )

    gateway.begin_batch(
        StructuralMutationKind.EDGE_REDIRECT,
        planned_operation_count=1,
    )
    first_batch = planned[-1].mutation_batch_id
    gateway.record_edge_redirect()
    receipt = gateway.commit()

    assert receipt.mutation_batch_id == first_batch
    assert receipt.planned_operation_count == 1
    assert committed[-1].receipt == receipt

    gateway.begin_batch(
        StructuralMutationKind.BLOCK_REPLACE,
        planned_operation_count=2,
    )
    second_batch = planned[-1].mutation_batch_id
    gateway.abort(reason="preflight rejected")

    assert second_batch != first_batch
    assert aborted[-1].mutation_batch_id == second_batch
    assert aborted[-1].reason == "preflight rejected"
    assert index.generation == 3


def test_gateway_observer_failure_cannot_change_transaction_authority() -> None:
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="mutation-session",
        generation=2,
        bindings=(),
        native_key=NATIVE_KEY,
    )
    emitter = EventEmitter()

    def _raise(_event) -> None:
        raise RuntimeError("diagnostic sink unavailable")

    emitter.on(MbaMutationPlanned, _raise)
    emitter.on(MbaMutationCommitted, _raise)
    emitter.on(MbaMutationAborted, _raise)
    gateway = MbaMutationGateway(
        generation=2,
        session_id="mutation-session",
        identity_index=index,
        event_emitter=emitter,
        native_key=NATIVE_KEY,
    )

    gateway.begin_batch(StructuralMutationKind.EDGE_REDIRECT)
    gateway.record_edge_redirect()
    receipt = gateway.commit()

    assert receipt.post_generation == 3
    assert gateway.active is False
    assert index.generation == 3
    assert [failure.phase for failure in gateway.observation_failures] == [
        "planned",
        "committed",
    ]

    gateway.begin_batch(StructuralMutationKind.BLOCK_REPLACE)
    gateway.abort(reason="expected rejection")

    assert gateway.active is False
    assert [failure.phase for failure in gateway.observation_failures] == [
        "planned",
        "committed",
        "planned",
        "aborted",
    ]


def test_invalid_batch_preflight_leaves_no_active_identity_transaction() -> None:
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="mutation-session",
        generation=2,
        bindings=(),
        native_key=NATIVE_KEY,
    )
    gateway = MbaMutationGateway(
        generation=2,
        session_id="mutation-session",
        identity_index=index,
        native_key=NATIVE_KEY,
    )

    with pytest.raises(ValueError, match="planned operation count"):
        gateway.begin_batch(
            StructuralMutationKind.EDGE_REDIRECT,
            planned_operation_count=-1,
        )

    assert gateway.active is False
    gateway.begin_batch(StructuralMutationKind.EDGE_REDIRECT)
    gateway.abort(reason="test cleanup")


def test_gateway_creates_independent_transactions_over_the_same_live_index() -> None:
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="mutation-session",
        generation=2,
        bindings=((identity, 5),),
        native_key=NATIVE_KEY,
    )
    gateway = MbaMutationGateway(
        generation=2,
        session_id="mutation-session",
        function_ea=0x40D200,
        maturity=4,
        identity_index=index,
        native_key=NATIVE_KEY,
    )

    transaction = gateway.new_transaction()
    transaction.begin_batch(StructuralMutationKind.BLOCK_INSERT, serial_quantity=6)
    transaction.record_insert(insertion_serial=3, returned_serial=3)
    transaction.commit()

    assert transaction is not gateway
    assert transaction.identity_index is gateway.identity_index
    assert gateway.identity_index.rebind_identity(identity).block.serial == 6
    assert gateway.identity_index.generation == 3


def test_new_transaction_rebases_planned_coordinates_to_current_serials() -> None:
    first = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),), native_key=NATIVE_KEY
    )
    second = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="mutation-session",
        generation=0,
        bindings=((first, 4), (second, 5)),
        native_key=NATIVE_KEY,
    )
    gateway = MbaMutationGateway(
        session_id="mutation-session", identity_index=index, native_key=NATIVE_KEY
    )

    gateway.begin_batch(StructuralMutationKind.BLOCK_INSERT, serial_quantity=6)
    gateway.record_insert(insertion_serial=3, returned_serial=3)
    gateway.commit()

    transaction = gateway.new_transaction()
    transaction.begin_batch(
        StructuralMutationKind.EDGE_REDIRECT,
        serial_quantity=7,
    )

    assert index.rebind_identity(first).block.serial == 5
    assert index.rebind_identity(second).block.serial == 6
    assert transaction.resolve_serial(5) == 5
    assert transaction.resolve_serial(6) == 6


def test_inactive_transaction_treats_serials_as_current_live_coordinates() -> None:
    first = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),), native_key=NATIVE_KEY
    )
    second = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="mutation-session",
        generation=0,
        bindings=((first, 4), (second, 5)),
        native_key=NATIVE_KEY,
    )
    gateway = MbaMutationGateway(
        session_id="mutation-session", identity_index=index, native_key=NATIVE_KEY
    )

    gateway.begin_batch(StructuralMutationKind.BLOCK_INSERT, serial_quantity=6)
    gateway.record_insert(insertion_serial=3, returned_serial=3)
    gateway.commit()

    transaction = gateway.new_transaction()

    assert not transaction.active
    assert transaction.resolve_serial(5) == 5
    assert transaction.resolve_serial(6) == 6


def test_index_keeps_clone_and_split_handles_transaction_local() -> None:
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="mutation-session",
        generation=3,
        bindings=((identity, 8),),
        native_key=NATIVE_KEY,
    )
    original = index.handle_for_serial(8)
    assert original is not None
    retained = index.create_native_handle(identity)
    split_tail = index.create_synthetic_handle()

    index.begin_transaction("split-clone", 9)
    index.record_split(
        transaction_id="split-clone",
        original=original,
        retained=retained,
        created_tail=split_tail,
        returned_tail_serial=9,
    )
    assert index.resolve(original).serial == 8
    assert index.resolve(retained) is not None
    assert index.resolve(
        original,
        transaction_id="split-clone",
    ).handle is retained
    assert index.resolve(
        split_tail,
        transaction_id="split-clone",
    ).serial == 9

    clone = index.create_native_handle(identity)
    index.record_clone(
        transaction_id="split-clone",
        source=retained,
        created=clone,
        returned_serial=10,
    )
    index.commit_proxy_transaction("split-clone")
    index.advance_generation()

    assert index.resolve(original).handle is retained
    assert index.resolve(clone).serial == 10
    assert index.rebind_identity(identity).status.name == "AMBIGUOUS"


def test_gateway_delete_stales_removed_handle_and_shifts_later_bindings() -> None:
    removed_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401001),), native_key=NATIVE_KEY
    )
    later_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x402000, 0x402001),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="mutation-session",
        generation=4,
        bindings=((removed_identity, 3), (later_identity, 7)),
        native_key=NATIVE_KEY,
    )
    removed = index.handle_for_serial(3)
    assert removed is not None
    gateway = MbaMutationGateway(
        generation=4,
        session_id="mutation-session",
        identity_index=index,
        native_key=NATIVE_KEY,
    )

    gateway.begin_batch(StructuralMutationKind.BLOCK_REMOVE)
    gateway.record_remove(removed)
    receipt = gateway.commit()

    assert index.resolve(removed) is None
    assert index.rebind_identity(removed_identity).status.name == "MISSING"
    assert index.rebind_identity(later_identity).block.serial == 6
    assert receipt.operation_count == 1


def test_gateway_is_the_receipted_path_for_split_and_clone_bindings() -> None:
    original_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),), native_key=NATIVE_KEY
    )
    retained_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401008),), native_key=NATIVE_KEY
    )
    tail_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401008, 0x401010),), native_key=NATIVE_KEY
    )
    later_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x402000, 0x402010),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="mutation-session",
        generation=0,
        bindings=((original_identity, 2), (later_identity, 5)),
        native_key=NATIVE_KEY,
    )
    original = index.handle_for_serial(2)
    assert original is not None
    retained = index.create_native_handle(retained_identity)
    tail = index.create_native_handle(tail_identity)
    gateway = MbaMutationGateway(
        session_id="mutation-session", identity_index=index, native_key=NATIVE_KEY
    )

    gateway.begin_batch(StructuralMutationKind.BLOCK_REPLACE)
    gateway.record_split(
        original=original,
        retained=retained,
        created_tail=tail,
        returned_tail_serial=3,
    )
    gateway.record_clone(source=tail, returned_serial=4)
    receipt = gateway.commit()

    assert index.resolve(original) is None
    assert index.resolve(retained).serial == 2
    assert index.resolve(tail).serial == 3
    assert index.rebind_identity(later_identity).block.serial == 6
    assert index.rebind_identity(tail_identity).status.name == "AMBIGUOUS"
    assert receipt.operation_count == 2
    assert set(receipt.affected_identities) == {
        original_identity,
        retained_identity,
        tail_identity,
    }


def test_unknown_sdk_effect_refreshes_before_commit_and_stales_synthetic_handles() -> (
    None
):
    @dataclass
    class Insn:
        ea: int
        next: object | None = None

    @dataclass
    class Block:
        serial: int
        start: int
        head: object | None

    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401001),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="mutation-session",
        generation=8,
        bindings=((identity, 5),),
        native_key=NATIVE_KEY,
    )
    original = index.handle_for_serial(5)
    assert original is not None
    index.begin_transaction("uncommitted-insert", 6)
    synthetic = index.create_synthetic_handle()
    index.record_insert(
        transaction_id="uncommitted-insert",
        insertion_serial=6,
        created=synthetic,
        returned_serial=6,
    )
    index.abort_proxy_transaction("uncommitted-insert")

    blocks = {
        1: Block(1, 0x401000, Insn(0x401000)),
        2: Block(2, 0x402000, Insn(0x402000)),
    }

    class Mba:
        qty = 3

        @staticmethod
        def get_mblock(serial):
            return blocks.get(int(serial))

    observed_serials: list[int] = []
    emitter = EventEmitter()
    emitter.on(
        MbaMutationCommitted,
        lambda _event: observed_serials.append(
            index.rebind_identity(identity).block.serial
        ),
    )
    gateway = MbaMutationGateway(
        generation=8,
        session_id="mutation-session",
        identity_index=index,
        event_emitter=emitter,
        native_key=NATIVE_KEY,
    )

    gateway.begin_batch(StructuralMutationKind.BLOCK_REPLACE)
    gateway.record_unknown_sdk_operation(Mba())
    gateway.commit()

    assert index.resolve(original).serial == 1
    assert index.resolve(synthetic) is None
    assert observed_serials == [1]


def test_gateway_replacement_is_transaction_local_until_commit() -> None:
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="mutation-session",
        generation=3,
        bindings=((identity, 5),),
        native_key=NATIVE_KEY,
    )
    original = index.handle_for_serial(5)
    assert original is not None
    replacement = index.create_native_handle(identity)
    gateway = MbaMutationGateway(
        generation=3,
        session_id="mutation-session",
        identity_index=index,
        native_key=NATIVE_KEY,
    )

    gateway.begin_batch(
        StructuralMutationKind.BLOCK_REPLACE,
        serial_quantity=6,
    )
    staged = gateway.stage_replacement(
        original=original,
        replacement=replacement,
        returned_serial=5,
    )

    assert index.resolve(original).handle is original
    assert gateway.resolve_block(original).handle is replacement
    assert staged.handle is replacement

    receipt = gateway.commit()

    assert index.resolve(original).handle is replacement
    assert index.resolve(original).generation == 4
    assert len(receipt.version_transitions) == 1
    transition = receipt.version_transitions[0]
    assert transition.retired_version_id is not None
    assert transition.promoted_version_id == staged.version_id


def test_gateway_stages_inserted_replacement_as_one_logical_operation() -> None:
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="mutation-session",
        generation=3,
        bindings=((identity, 2),),
        native_key=NATIVE_KEY,
    )
    original = index.handle_for_serial(2)
    assert original is not None
    replacement = index.create_native_handle(identity)
    gateway = MbaMutationGateway(
        generation=3,
        session_id="mutation-session",
        identity_index=index,
        native_key=NATIVE_KEY,
    )
    gateway.begin_batch(
        StructuralMutationKind.BLOCK_REPLACE,
        serial_quantity=4,
        planned_operation_count=1,
    )

    staged = gateway.stage_inserted_replacement(
        original=original,
        replacement=replacement,
        insertion_serial=3,
        returned_serial=3,
    )

    assert staged.handle is replacement
    assert gateway.resolve_block(original).serial == 3
    assert index.resolve(original).serial == 2
    assert gateway._operation_count == 1
    gateway.abort(reason="unit test does not attach fragment validation")


def test_gateway_abort_discards_staged_version_and_preserves_published_authority() -> (
    None
):
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="mutation-session",
        generation=3,
        bindings=((identity, 5),),
        native_key=NATIVE_KEY,
    )
    original = index.handle_for_serial(5)
    assert original is not None
    replacement = index.create_native_handle(identity)
    emitter = EventEmitter()
    aborted: list[MbaMutationAborted] = []
    emitter.on(MbaMutationAborted, aborted.append)
    gateway = MbaMutationGateway(
        generation=3,
        session_id="mutation-session",
        identity_index=index,
        event_emitter=emitter,
        native_key=NATIVE_KEY,
    )

    gateway.begin_batch(
        StructuralMutationKind.BLOCK_REPLACE,
        serial_quantity=6,
    )
    staged = gateway.stage_replacement(
        original=original,
        replacement=replacement,
        returned_serial=5,
    )
    gateway.abort(reason="projected graph rejected")

    assert index.resolve(original).handle is original
    assert index.resolve(original).generation == 3
    assert index.generation == 3
    assert aborted[-1].discarded_version_ids == (staged.version_id,)


def test_gateway_insert_is_transaction_local_and_abort_restores_bindings() -> None:
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="mutation-session",
        generation=3,
        bindings=((identity, 4),),
        native_key=NATIVE_KEY,
    )
    original = index.handle_for_serial(4)
    assert original is not None
    gateway = MbaMutationGateway(
        generation=3,
        session_id="mutation-session",
        identity_index=index,
        native_key=NATIVE_KEY,
    )

    gateway.begin_batch(
        StructuralMutationKind.BLOCK_INSERT,
        serial_quantity=5,
    )
    created = gateway.record_insert(insertion_serial=3, returned_serial=3)

    assert index.resolve(original).serial == 4
    assert gateway.resolve_block(original).serial == 5
    assert index.resolve(created) is None
    assert gateway.resolve_block(created).serial == 3

    gateway.abort(reason="publisher rejected fragment")

    assert index.resolve(original).serial == 4
    assert index.resolve(created) is None
    assert index.generation == 3


def test_gateway_insert_commit_publishes_new_proxy_and_shifted_bindings() -> None:
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="mutation-session",
        generation=3,
        bindings=((identity, 4),),
        native_key=NATIVE_KEY,
    )
    original = index.handle_for_serial(4)
    assert original is not None
    gateway = MbaMutationGateway(
        generation=3,
        session_id="mutation-session",
        identity_index=index,
        native_key=NATIVE_KEY,
    )
    gateway.begin_batch(
        StructuralMutationKind.BLOCK_INSERT,
        serial_quantity=5,
    )
    created = gateway.record_insert(insertion_serial=3, returned_serial=3)

    receipt = gateway.commit()

    assert index.resolve(original).serial == 5
    assert index.resolve(created).serial == 3
    assert any(
        transition.retired_version_id is None
        and transition.promoted_version_id is not None
        for transition in receipt.version_transitions
    )


def test_gateway_remove_is_transaction_local_and_abort_preserves_block() -> None:
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="mutation-session",
        generation=3,
        bindings=((identity, 4),),
        native_key=NATIVE_KEY,
    )
    original = index.handle_for_serial(4)
    assert original is not None
    gateway = MbaMutationGateway(
        generation=3,
        session_id="mutation-session",
        identity_index=index,
        native_key=NATIVE_KEY,
    )
    gateway.begin_batch(StructuralMutationKind.BLOCK_REMOVE, serial_quantity=5)
    gateway.record_remove(original)

    assert index.resolve(original).serial == 4
    assert gateway.resolve_block(original) is None

    gateway.abort(reason="postcondition failed")

    assert index.resolve(original).serial == 4


def test_gateway_remove_commit_retires_proxy_without_promoting_version() -> None:
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="mutation-session",
        generation=3,
        bindings=((identity, 4),),
        native_key=NATIVE_KEY,
    )
    original = index.handle_for_serial(4)
    assert original is not None
    gateway = MbaMutationGateway(
        generation=3,
        session_id="mutation-session",
        identity_index=index,
        native_key=NATIVE_KEY,
    )
    gateway.begin_batch(StructuralMutationKind.BLOCK_REMOVE, serial_quantity=5)
    gateway.record_remove(original)

    receipt = gateway.commit()

    assert index.resolve(original) is None
    assert any(
        transition.retired_version_id is not None
        and transition.promoted_version_id is None
        for transition in receipt.version_transitions
    )
