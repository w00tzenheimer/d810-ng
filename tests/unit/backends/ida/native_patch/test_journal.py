"""Write-ahead state-machine tests for the SQLite-backed native patch journal.

Section 14.4 / 15 of ``_gitless/REVERSIBLE-NATIVE-PATCHES.md`` plus review
finding P1 "journal state conflates byte persistence with analysis
certification" (design requirement 2) and design requirements 3
("PREPARED must be durably committed before a transaction is exposed for
application") and 4 (the netnode mirror is a separate receipt that can never
retroactively change SQLite transaction state).
"""

from __future__ import annotations

import dataclasses
import sqlite3
import threading

import pytest

from d810.backends.ida.native_patch.journal import (
    NativePatchFunctionScopeConflictError,
    NativePatchLegacyIdentityError,
    NativePatchMetadataScopeConflictError,
    NativePatchTransactionConflictError,
    SQLiteNativePatchJournal,
)
from d810.capabilities.native_patch import (
    IllegalNativeJournalTransition,
    NativeByteEventPhase,
    NativeJournalState,
    NativeMirrorOutcome,
    NativePatchTransactionId,
)
from d810.transforms.native_patch_plan import (
    NativeAddressRange,
    NativeFunctionTypeInfo,
    NativeMetadataAction,
    NativeMetadataActionKind,
)

from . import _plan_fixtures as fixtures

pytestmark = pytest.mark.pure_python


@pytest.fixture
def store(tmp_path):
    journal = SQLiteNativePatchJournal(tmp_path / "journal.db")
    yield journal
    journal.close()


# ---------------------------------------------------------------------------
# prepare()
# ---------------------------------------------------------------------------


class TestPrepare:
    def test_prepare_durably_commits_prepared_before_returning(self, store) -> None:
        record = store.prepare(fixtures.plan())
        assert record.state is NativeJournalState.PREPARED

        # A fresh handle against the same file must see it -- proves this is a
        # durable commit, not an in-process cache.
        reopened = SQLiteNativePatchJournal(store.db_path)
        try:
            reread = reopened.get(record.transaction_id)
        finally:
            reopened.close()
        assert reread is not None
        assert reread.state is NativeJournalState.PREPARED

    def test_prepare_records_plan_hash_and_authorizing_attempt(self, store) -> None:
        p = fixtures.plan()
        record = store.prepare(p)
        assert record.plan_hash == p.plan_hash
        assert record.authorizing_attempt_id == p.authorizing_attempt_id
        assert record.database_identity == p.database_identity.idb_uuid

    def test_prepare_without_metadata_actions(self, store) -> None:
        record = store.prepare(fixtures.plan())
        assert record.has_metadata_actions is False

    def test_prepare_detects_metadata_ownership(self, store) -> None:
        op = fixtures.operation(
            operation_id="op-md",
            metadata_actions=(
                NativeMetadataAction(
                    kind=NativeMetadataActionKind.RECREATE_ITEM,
                    ea=0x1000,
                    expected_before="code:2",
                    expected_after="code:2",
                ),
            ),
        )
        record = store.prepare(fixtures.plan(operations=(op,)))
        assert record.has_metadata_actions is True

    def test_prepare_rejects_overlap_with_an_active_transaction(self, store) -> None:
        store.prepare(
            fixtures.plan(
                operations=(
                    fixtures.operation(
                        operation_id="a", start_ea=0x1000, end_ea=0x1002
                    ),
                )
            )
        )
        with pytest.raises(NativePatchTransactionConflictError):
            store.prepare(
                fixtures.plan(
                    operations=(
                        fixtures.operation(
                            operation_id="b", start_ea=0x1001, end_ea=0x1003
                        ),
                    )
                )
            )

    def test_prepare_allows_adjacent_non_overlapping_active_ranges(self, store) -> None:
        store.prepare(
            fixtures.plan(
                operations=(
                    fixtures.operation(
                        operation_id="a", start_ea=0x1000, end_ea=0x1002
                    ),
                )
            )
        )
        second_operation = fixtures.operation(
            operation_id="b", start_ea=0x1002, end_ea=0x1004
        )
        second_ownership = dataclasses.replace(
            second_operation.expected_function_ownership,
            owning_function_entry_ea=0x2000,
            chunk_ranges=(NativeAddressRange(0x1000, 0x3000),),
        )
        second_operation = dataclasses.replace(
            second_operation,
            expected_function_ownership=second_ownership,
            restore_snapshot=dataclasses.replace(
                second_operation.restore_snapshot,
                function_ownership=second_ownership,
            ),
        )
        second = store.prepare(
            fixtures.plan(
                operations=(second_operation,),
                function_identity=dataclasses.replace(
                    fixtures.plan().function_identity,
                    entry_ea=0x2000,
                    chunk_ranges=(NativeAddressRange(0x1000, 0x3000),),
                ),
            )
        )
        assert second.state is NativeJournalState.PREPARED

    def test_prepare_scopes_same_byte_ranges_to_their_database_identity(
        self, store
    ) -> None:
        first = fixtures.plan()
        foreign = dataclasses.replace(
            first,
            database_identity=dataclasses.replace(
                first.database_identity, idb_uuid="idb-foreign"
            ),
        )

        store.prepare(first)

        assert store.prepare(foreign).state is NativeJournalState.PREPARED

    @pytest.mark.parametrize("ownership_field", ("expected", "restore"))
    def test_prepare_rejects_operation_ownership_outside_plan_function(
        self, store, ownership_field
    ) -> None:
        operation = fixtures.operation()
        foreign_ownership = dataclasses.replace(
            operation.expected_function_ownership,
            owning_function_entry_ea=0x2000,
        )
        if ownership_field == "expected":
            operation = dataclasses.replace(
                operation, expected_function_ownership=foreign_ownership
            )
        else:
            operation = dataclasses.replace(
                operation,
                restore_snapshot=dataclasses.replace(
                    operation.restore_snapshot,
                    function_ownership=foreign_ownership,
                ),
            )

        with pytest.raises(ValueError, match="function identity"):
            store.prepare(fixtures.plan(operations=(operation,)))

    def test_empty_chunk_ownership_still_acquires_the_function_slot(
        self, store
    ) -> None:
        operation = fixtures.operation()
        ownership = dataclasses.replace(
            operation.expected_function_ownership,
            owning_function_entry_ea=0x1000,
            chunk_ranges=(),
        )
        operation = dataclasses.replace(
            operation,
            expected_function_ownership=ownership,
            restore_snapshot=dataclasses.replace(
                operation.restore_snapshot,
                function_ownership=ownership,
            ),
        )
        first = fixtures.plan(operations=(operation,))
        second_operation = dataclasses.replace(
            operation,
            operation_id="op-2",
            range=dataclasses.replace(operation.range, start_ea=0x2000, end_ea=0x2002),
            expected_before_shape=fixtures.shape(0x2000, 2, "jcc"),
            expected_after_shape=fixtures.shape(0x2000, 2, "jmp"),
            expected_item_shape=dataclasses.replace(
                operation.expected_item_shape,
                heads=(
                    dataclasses.replace(
                        operation.expected_item_shape.heads[0], ea=0x2000
                    ),
                ),
            ),
            encoding_evidence=dataclasses.replace(
                operation.encoding_evidence, final_ea=0x2000
            ),
        )
        second = fixtures.plan(operations=(second_operation,), plan_id="plan-2")

        store.prepare(first)

        with pytest.raises(NativePatchFunctionScopeConflictError):
            store.prepare(second)

    def test_concurrent_prepares_acquire_one_function_slot(self, tmp_path) -> None:
        """The lease must be serialized by SQLite, not a pre-transaction read."""
        barrier = threading.Barrier(2)
        results: list[object] = []
        results_lock = threading.Lock()

        operation = fixtures.operation()
        ownership = dataclasses.replace(
            operation.expected_function_ownership,
            owning_function_entry_ea=0x1000,
        )
        operation = dataclasses.replace(
            operation,
            expected_function_ownership=ownership,
            restore_snapshot=dataclasses.replace(
                operation.restore_snapshot,
                function_ownership=ownership,
            ),
        )
        plan_a = fixtures.plan(operations=(operation,), plan_id="plan-a")
        operation_b = dataclasses.replace(
            operation,
            operation_id="op-2",
            range=dataclasses.replace(operation.range, start_ea=0x2000, end_ea=0x2002),
            expected_before_shape=fixtures.shape(0x2000, 2, "jcc"),
            expected_after_shape=fixtures.shape(0x2000, 2, "jmp"),
            expected_item_shape=dataclasses.replace(
                operation.expected_item_shape,
                heads=(
                    dataclasses.replace(
                        operation.expected_item_shape.heads[0], ea=0x2000
                    ),
                ),
            ),
            encoding_evidence=dataclasses.replace(
                operation.encoding_evidence, final_ea=0x2000
            ),
        )
        plan_b = fixtures.plan(operations=(operation_b,), plan_id="plan-b")
        path = tmp_path / "concurrent.db"

        def _prepare(plan) -> None:
            journal = SQLiteNativePatchJournal(path)
            try:
                barrier.wait(timeout=5)
                result = journal.prepare(plan)
            except Exception as error:  # expected for exactly one contender
                result = error
            finally:
                journal.close()
            with results_lock:
                results.append(result)

        first = threading.Thread(target=_prepare, args=(plan_a,))
        second = threading.Thread(target=_prepare, args=(plan_b,))
        first.start()
        second.start()
        first.join(timeout=10)
        second.join(timeout=10)

        assert len(results) == 2
        assert (
            sum(
                isinstance(result, NativePatchFunctionScopeConflictError)
                for result in results
            )
            == 1
        )

    def test_active_legacy_row_fails_closed_after_schema_migration(
        self, tmp_path
    ) -> None:
        path = tmp_path / "legacy.db"
        connection = sqlite3.connect(path)
        try:
            connection.execute(
                """
                CREATE TABLE native_patch_transactions (
                    transaction_id TEXT PRIMARY KEY,
                    plan_id TEXT NOT NULL,
                    plan_hash TEXT NOT NULL,
                    attempt_session TEXT NOT NULL,
                    attempt_sequence INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    has_metadata_actions INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            connection.execute(
                """
                INSERT INTO native_patch_transactions VALUES
                    ('legacy', 'plan', 'hash', 'session', 1, 'prepared', 0, 0, 0)
                """
            )
            connection.commit()
        finally:
            connection.close()

        journal = SQLiteNativePatchJournal(path)
        try:
            assert journal.recoverable_transaction_ids(database_identity="idb-1") == ()
            with pytest.raises(NativePatchLegacyIdentityError):
                journal.prepare(fixtures.plan())
        finally:
            journal.close()

    def test_prepare_rejects_same_xref_source_under_distinct_byte_anchors(
        self, store
    ) -> None:
        """Byte-range ownership cannot serialize an xref source mutation."""
        first = fixtures.operation(
            operation_id="first",
            start_ea=0x1000,
            end_ea=0x1002,
            metadata_actions=(
                NativeMetadataAction(
                    kind=NativeMetadataActionKind.UPDATE_XREF,
                    ea=0x5000,
                    expected_before="cref3:",
                    expected_after="cref3:0x6000@0x11@u",
                ),
            ),
        )
        second = fixtures.operation(
            operation_id="second",
            start_ea=0x2000,
            end_ea=0x2002,
            metadata_actions=(
                NativeMetadataAction(
                    kind=NativeMetadataActionKind.UPDATE_XREF,
                    ea=0x5000,
                    expected_before="cref3:0x6000@0x11@u",
                    expected_after="cref3:0x6000@0x11@u,0x7000@0x11@u",
                ),
            ),
        )
        store.prepare(fixtures.plan(operations=(first,)))

        with pytest.raises(NativePatchMetadataScopeConflictError):
            store.prepare(fixtures.plan(operations=(second,)))

    def test_metadata_scope_is_released_only_after_verified_restore(
        self, store
    ) -> None:
        operation = fixtures.operation(
            operation_id="xref-owner",
            metadata_actions=(
                NativeMetadataAction(
                    kind=NativeMetadataActionKind.UPDATE_XREF,
                    ea=0x5000,
                    expected_before="cref3:",
                    expected_after="cref3:0x6000@0x11@u",
                ),
            ),
        )
        first = store.prepare(fixtures.plan(operations=(operation,)))
        store.transition(first.transaction_id, NativeJournalState.ROLLING_BACK)
        store.transition(first.transaction_id, NativeJournalState.RESTORED)

        second = store.prepare(
            fixtures.plan(
                operations=(
                    dataclasses.replace(operation, operation_id="xref-new-owner"),
                )
            )
        )

        assert second.state is NativeJournalState.PREPARED

    def test_prepare_allows_overlap_after_the_prior_transaction_is_restored(
        self, store
    ) -> None:
        first = store.prepare(
            fixtures.plan(operations=(fixtures.operation(operation_id="a"),))
        )
        tx = first.transaction_id
        for target in (
            NativeJournalState.BYTES_APPLIED,
            NativeJournalState.ANALYSIS_PENDING,
            NativeJournalState.ANALYSIS_VALIDATED,
            NativeJournalState.CACHE_INVALIDATED,
            NativeJournalState.CERTIFICATE_PENDING,
            NativeJournalState.CERTIFIED,
            NativeJournalState.RESTORING,
            NativeJournalState.RESTORE_BYTES_RESTORED,
            NativeJournalState.RESTORED,
        ):
            store.transition(tx, target)

        second = store.prepare(
            fixtures.plan(operations=(fixtures.operation(operation_id="a"),))
        )
        assert second.state is NativeJournalState.PREPARED


# ---------------------------------------------------------------------------
# Legal transitions
# ---------------------------------------------------------------------------


class TestLegalTransitions:
    def test_full_apply_and_certify_sequence(self, store) -> None:
        record = store.prepare(fixtures.plan())
        tx = record.transaction_id
        for target in (
            NativeJournalState.BYTES_APPLIED,
            NativeJournalState.ANALYSIS_PENDING,
            NativeJournalState.ANALYSIS_VALIDATED,
            NativeJournalState.CACHE_INVALIDATED,
            NativeJournalState.CERTIFICATE_PENDING,
            NativeJournalState.CERTIFIED,
        ):
            record = store.transition(tx, target)
            assert record.state is target

    def test_stage_c_postcondition_remains_recoverable_until_certified(
        self, store
    ) -> None:
        record = store.prepare(fixtures.plan())
        tx = record.transaction_id
        for target in (
            NativeJournalState.BYTES_APPLIED,
            NativeJournalState.ANALYSIS_PENDING,
            NativeJournalState.ANALYSIS_VALIDATED,
            NativeJournalState.CACHE_INVALIDATED,
            NativeJournalState.CERTIFICATE_PENDING,
            NativeJournalState.POSTCONDITION_PENDING,
        ):
            record = store.transition(tx, target)
            assert record.state is target

        assert store.recoverable_transaction_ids(database_identity="idb-1") == (tx,)
        record = store.transition(tx, NativeJournalState.CERTIFIED)
        assert record.state is NativeJournalState.CERTIFIED
        assert store.recoverable_transaction_ids(database_identity="idb-1") == ()

    def test_stage_c_pending_postcondition_can_enter_restore_lane(self, store) -> None:
        record = store.prepare(fixtures.plan())
        tx = record.transaction_id
        for target in (
            NativeJournalState.BYTES_APPLIED,
            NativeJournalState.ANALYSIS_PENDING,
            NativeJournalState.ANALYSIS_VALIDATED,
            NativeJournalState.CACHE_INVALIDATED,
            NativeJournalState.CERTIFICATE_PENDING,
            NativeJournalState.POSTCONDITION_PENDING,
            NativeJournalState.RESTORING,
        ):
            record = store.transition(tx, target)
        assert record.state is NativeJournalState.RESTORING

    def test_metadata_owning_plan_must_pass_through_metadata_applied(
        self, store
    ) -> None:
        op = fixtures.operation(
            metadata_actions=(
                NativeMetadataAction(
                    kind=NativeMetadataActionKind.RECREATE_ITEM,
                    ea=0x1000,
                    expected_before="a",
                    expected_after="b",
                ),
            )
        )
        record = store.prepare(fixtures.plan(operations=(op,)))
        tx = record.transaction_id
        store.transition(tx, NativeJournalState.BYTES_APPLIED)
        record = store.transition(tx, NativeJournalState.METADATA_APPLIED)
        assert record.state is NativeJournalState.METADATA_APPLIED
        record = store.transition(tx, NativeJournalState.ANALYSIS_PENDING)
        assert record.state is NativeJournalState.ANALYSIS_PENDING

    def test_certified_transaction_can_be_explicitly_restored(self, store) -> None:
        record = store.prepare(fixtures.plan())
        tx = record.transaction_id
        for target in (
            NativeJournalState.BYTES_APPLIED,
            NativeJournalState.ANALYSIS_PENDING,
            NativeJournalState.ANALYSIS_VALIDATED,
            NativeJournalState.CACHE_INVALIDATED,
            NativeJournalState.CERTIFICATE_PENDING,
            NativeJournalState.CERTIFIED,
        ):
            store.transition(tx, target)
        record = store.transition(tx, NativeJournalState.RESTORING)
        assert record.state is NativeJournalState.RESTORING
        record = store.transition(tx, NativeJournalState.RESTORED)
        assert record.state is NativeJournalState.RESTORED

    def test_apply_failure_rolls_back(self, store) -> None:
        record = store.prepare(fixtures.plan())
        tx = record.transaction_id
        store.transition(tx, NativeJournalState.BYTES_APPLIED)
        record = store.transition(tx, NativeJournalState.ROLLING_BACK)
        assert record.state is NativeJournalState.ROLLING_BACK
        record = store.transition(tx, NativeJournalState.RESTORED)
        assert record.state is NativeJournalState.RESTORED

    def test_recovery_required_can_resume_into_restoring(self, store) -> None:
        record = store.prepare(fixtures.plan())
        tx = record.transaction_id
        store.transition(tx, NativeJournalState.BYTES_APPLIED)
        store.transition(tx, NativeJournalState.RECOVERY_REQUIRED)
        record = store.transition(tx, NativeJournalState.RESTORING)
        assert record.state is NativeJournalState.RESTORING


# ---------------------------------------------------------------------------
# Illegal transitions
# ---------------------------------------------------------------------------


class TestIllegalTransitions:
    def test_bytes_applied_requires_a_durable_prepared_record(self, store) -> None:
        tx = NativePatchTransactionId.new()
        with pytest.raises(IllegalNativeJournalTransition):
            store.transition(tx, NativeJournalState.BYTES_APPLIED)

    def test_cannot_skip_prepared_straight_to_certified(self, store) -> None:
        record = store.prepare(fixtures.plan())
        with pytest.raises(IllegalNativeJournalTransition):
            store.transition(record.transaction_id, NativeJournalState.CERTIFIED)

    def test_cannot_re_enter_prepared(self, store) -> None:
        record = store.prepare(fixtures.plan())
        with pytest.raises(IllegalNativeJournalTransition):
            store.transition(record.transaction_id, NativeJournalState.PREPARED)

    def test_restored_is_terminal(self, store) -> None:
        record = store.prepare(fixtures.plan())
        tx = record.transaction_id
        store.transition(tx, NativeJournalState.BYTES_APPLIED)
        store.transition(tx, NativeJournalState.ROLLING_BACK)
        store.transition(tx, NativeJournalState.RESTORED)
        with pytest.raises(IllegalNativeJournalTransition):
            store.transition(tx, NativeJournalState.BYTES_APPLIED)

    def test_cannot_restore_before_certification(self, store) -> None:
        record = store.prepare(fixtures.plan())
        tx = record.transaction_id
        store.transition(tx, NativeJournalState.BYTES_APPLIED)
        with pytest.raises(IllegalNativeJournalTransition):
            store.transition(tx, NativeJournalState.RESTORING)

    def test_metadata_applied_illegal_without_owned_metadata(self, store) -> None:
        record = store.prepare(fixtures.plan())  # no metadata actions
        tx = record.transaction_id
        store.transition(tx, NativeJournalState.BYTES_APPLIED)
        with pytest.raises(IllegalNativeJournalTransition):
            store.transition(tx, NativeJournalState.METADATA_APPLIED)

    def test_metadata_owning_plan_cannot_skip_metadata_applied(self, store) -> None:
        op = fixtures.operation(
            metadata_actions=(
                NativeMetadataAction(
                    kind=NativeMetadataActionKind.RECREATE_ITEM,
                    ea=0x1000,
                    expected_before="a",
                    expected_after="b",
                ),
            )
        )
        record = store.prepare(fixtures.plan(operations=(op,)))
        tx = record.transaction_id
        store.transition(tx, NativeJournalState.BYTES_APPLIED)
        with pytest.raises(IllegalNativeJournalTransition):
            store.transition(tx, NativeJournalState.ANALYSIS_PENDING)

    def test_transition_on_unknown_transaction_raises(self, store) -> None:
        with pytest.raises(IllegalNativeJournalTransition):
            store.transition(
                NativePatchTransactionId.new(), NativeJournalState.BYTES_APPLIED
            )


# ---------------------------------------------------------------------------
# Byte-granular write-ahead log
# ---------------------------------------------------------------------------


class TestByteEvents:
    def test_record_byte_event_requires_a_governed_ea(self, store) -> None:
        record = store.prepare(fixtures.plan())
        with pytest.raises(ValueError):
            store.record_byte_event(
                record.transaction_id,
                "op-1",
                0xDEAD,
                NativeByteEventPhase.WRITE_STARTED,
                expected_current=0x75,
                expected_original=0x75,
                replacement=0xEB,
            )

    def test_record_byte_event_requires_matching_expected_values(self, store) -> None:
        record = store.prepare(fixtures.plan())
        with pytest.raises(ValueError):
            store.record_byte_event(
                record.transaction_id,
                "op-1",
                0x1000,
                NativeByteEventPhase.WRITE_STARTED,
                expected_current=0x00,
                expected_original=0x75,
                replacement=0xEB,
            )

    def test_record_byte_event_accepts_a_governed_ea(self, store) -> None:
        record = store.prepare(fixtures.plan())
        store.record_byte_event(
            record.transaction_id,
            "op-1",
            0x1000,
            NativeByteEventPhase.WRITE_STARTED,
            expected_current=0x75,
            expected_original=0x75,
            replacement=0xEB,
        )
        store.record_byte_event(
            record.transaction_id,
            "op-1",
            0x1000,
            NativeByteEventPhase.WRITE_APPLIED,
            expected_current=0x75,
            expected_original=0x75,
            replacement=0xEB,
        )

    def test_duplicate_phase_for_the_same_byte_is_rejected(self, store) -> None:
        record = store.prepare(fixtures.plan())
        store.record_byte_event(
            record.transaction_id,
            "op-1",
            0x1000,
            NativeByteEventPhase.WRITE_STARTED,
            expected_current=0x75,
            expected_original=0x75,
            replacement=0xEB,
        )
        with pytest.raises(sqlite3.IntegrityError):
            store.record_byte_event(
                record.transaction_id,
                "op-1",
                0x1000,
                NativeByteEventPhase.WRITE_STARTED,
                expected_current=0x75,
                expected_original=0x75,
                replacement=0xEB,
            )


# ---------------------------------------------------------------------------
# Netnode mirror receipts (design requirement 4)
# ---------------------------------------------------------------------------


class TestMirrorReceipts:
    def test_mirror_receipt_records_outcome_and_current_state(self, store) -> None:
        record = store.prepare(fixtures.plan())
        store.transition(record.transaction_id, NativeJournalState.BYTES_APPLIED)
        receipt = store.record_mirror_receipt(
            record.transaction_id, NativeMirrorOutcome.MIRROR_WRITTEN
        )
        assert receipt.outcome is NativeMirrorOutcome.MIRROR_WRITTEN
        assert receipt.at_state is NativeJournalState.BYTES_APPLIED

    def test_mirror_failure_never_changes_transaction_state(self, store) -> None:
        record = store.prepare(fixtures.plan())
        store.record_mirror_receipt(
            record.transaction_id,
            NativeMirrorOutcome.MIRROR_FAILED,
            reason="netnode write failed",
        )
        reread = store.get(record.transaction_id)
        assert reread is not None
        assert reread.state is NativeJournalState.PREPARED

    def test_mirror_receipts_are_queryable_in_order(self, store) -> None:
        record = store.prepare(fixtures.plan())
        store.record_mirror_receipt(
            record.transaction_id, NativeMirrorOutcome.MIRROR_FAILED, reason="first"
        )
        store.transition(record.transaction_id, NativeJournalState.BYTES_APPLIED)
        store.record_mirror_receipt(
            record.transaction_id, NativeMirrorOutcome.MIRROR_WRITTEN
        )

        receipts = store.mirror_receipts(record.transaction_id)
        assert [r.outcome for r in receipts] == [
            NativeMirrorOutcome.MIRROR_FAILED,
            NativeMirrorOutcome.MIRROR_WRITTEN,
        ]

    def test_mirror_receipt_on_unknown_transaction_raises(self, store) -> None:
        with pytest.raises(ValueError):
            store.record_mirror_receipt(
                NativePatchTransactionId.new(), NativeMirrorOutcome.MIRROR_WRITTEN
            )


class TestPrePatchFunctionOwnershipIsPersisted:
    """The journal must persist the *pre-patch* function extent.

    Restoring bytes is not restoring state. Erasing a branch orphans its
    target block, IDA's reanalysis shrinks the owning function, and a restore
    that re-derives ownership from the live database reads the already-shrunken
    extent -- so the function never comes back. Measured on
    ``fake_jump_opaque_predicate``: [0x1800099d0,0x180009a1e) -> apply ->
    [...,0x180009a00) -> restore -> [...,0x1800099fe).

    ``NativeRestoreSnapshot`` already carries the ownership; it just was not
    durable. These tests pin that it is written at prepare time, when the
    database still holds the truth, and is readable afterwards.
    """

    def test_prepare_persists_the_owning_entry_and_chunks(self, store) -> None:
        record = store.prepare(fixtures.plan())

        ownership = store.operation_ownership(record.transaction_id)

        assert ownership, "prepare must persist function ownership per operation"
        for entry_ea, chunks in ownership.values():
            assert isinstance(entry_ea, int)
            assert chunks and all(len(c) == 2 for c in chunks)

    def test_persisted_ownership_matches_the_restore_snapshot(self, store) -> None:
        plan = fixtures.plan()
        record = store.prepare(plan)

        ownership = store.operation_ownership(record.transaction_id)

        for op in plan.operations:
            expected = op.restore_snapshot.function_ownership
            entry_ea, chunks = ownership[op.operation_id]
            assert entry_ea == expected.owning_function_entry_ea
            assert chunks == tuple(
                (r.start_ea, r.end_ea) for r in expected.chunk_ranges
            )

    def test_prepare_persists_exact_internal_flow_refs(self, store) -> None:
        plan = fixtures.plan()
        record = store.prepare(plan)

        refs = store.operation_flow_refs(record.transaction_id)

        for op in plan.operations:
            assert refs[op.operation_id] == tuple(
                (ref.source_ea, ref.target_ea, ref.xref_type, ref.user)
                for ref in op.restore_snapshot.function_ownership.flow_refs
            )

    def test_prepare_persists_exact_function_flags_type_and_tail_chunks(
        self, store
    ) -> None:
        op = fixtures.operation()
        ownership = dataclasses.replace(
            op.restore_snapshot.function_ownership,
            chunk_ranges=(
                NativeAddressRange(0x1000, 0x1800),
                NativeAddressRange(0x2000, 0x2010),
            ),
            function_flags=0x4,
            type_info=NativeFunctionTypeInfo(
                type_bytes=b"\x0cp\x07\x02\x05",
                field_bytes=b"\x06value",
                field_comment_bytes=None,
            ),
        )
        op = dataclasses.replace(
            op,
            expected_function_ownership=ownership,
            restore_snapshot=dataclasses.replace(
                op.restore_snapshot,
                function_ownership=ownership,
            ),
        )
        record = store.prepare(fixtures.plan(operations=(op,)))

        read_metadata = getattr(store, "operation_function_metadata", None)
        assert callable(read_metadata), "journal does not expose function metadata"
        assert read_metadata(record.transaction_id) == {
            op.operation_id: (
                0x4,
                (b"\x0cp\x07\x02\x05", b"\x06value", None),
            )
        }
        assert store.operation_ownership(record.transaction_id)[op.operation_id][1] == (
            (0x1000, 0x1800),
            (0x2000, 0x2010),
        )

    def test_ownership_survives_reopening_the_journal(self, tmp_path) -> None:
        """Durability, not just in-memory bookkeeping -- a crash between apply
        and restore is exactly when this record is needed."""
        from d810.backends.ida.native_patch.journal import SQLiteNativePatchJournal

        path = tmp_path / "durable.db"
        first = SQLiteNativePatchJournal(path)
        record = first.prepare(fixtures.plan())
        expected = first.operation_ownership(record.transaction_id)
        first.close()

        second = SQLiteNativePatchJournal(path)
        try:
            assert second.operation_ownership(record.transaction_id) == expected
        finally:
            second.close()

    def test_unknown_transaction_has_no_ownership(self, store) -> None:
        assert store.operation_ownership(NativePatchTransactionId.new()) == {}


class TestMetadataActionsAreJournaled:
    """Metadata actions must be reversible from a recorded before-state.

    The extent P0 established the rule: state that is not derived from the
    bytes is not restored by restoring the bytes. Metadata actions are
    entirely made of such state, so the *actual* pre-action state has to be
    written down at apply time -- re-deriving it at restore time reads the
    already-mutated database, which is exactly what has to be undone.
    """

    def test_recorded_actions_round_trip(self, store) -> None:
        record = store.prepare(fixtures.plan())
        store.record_metadata_action(
            record.transaction_id,
            operation_id="op-0",
            kind="recreate_item",
            ea=0x1000,
            recorded_before="data:1",
            expected_after="code:2",
        )

        actions = store.metadata_actions(record.transaction_id)

        assert len(actions) == 1
        assert actions[0].kind == "recreate_item"
        assert actions[0].ea == 0x1000
        assert actions[0].recorded_before == "data:1"
        assert actions[0].expected_after == "code:2"

    def test_actions_are_returned_in_application_order(self, store) -> None:
        record = store.prepare(fixtures.plan())
        for ea in (0x1002, 0x1000, 0x1001):
            store.record_metadata_action(
                record.transaction_id,
                operation_id="op-0",
                kind="update_xref",
                ea=ea,
                recorded_before=f"before:{ea:#x}",
                expected_after=f"after:{ea:#x}",
            )

        actions = store.metadata_actions(record.transaction_id)

        # Insertion order, not ea order: reversal walks this backwards, and
        # sorting by address would reverse dependent actions out of sequence.
        assert [a.ea for a in actions] == [0x1002, 0x1000, 0x1001]

    def test_actions_survive_reopening_the_journal(self, tmp_path) -> None:
        from d810.backends.ida.native_patch.journal import SQLiteNativePatchJournal

        path = tmp_path / "meta.db"
        first = SQLiteNativePatchJournal(path)
        record = first.prepare(fixtures.plan())
        first.record_metadata_action(
            record.transaction_id,
            operation_id="op-0",
            kind="set_function_tail",
            ea=0x2000,
            recorded_before="none",
            expected_after="tail:0x2000-0x2010",
        )
        first.close()

        second = SQLiteNativePatchJournal(path)
        try:
            actions = second.metadata_actions(record.transaction_id)
            assert [a.recorded_before for a in actions] == ["none"]
        finally:
            second.close()

    def test_unknown_transaction_has_no_actions(self, store) -> None:
        assert store.metadata_actions(NativePatchTransactionId.new()) == ()
