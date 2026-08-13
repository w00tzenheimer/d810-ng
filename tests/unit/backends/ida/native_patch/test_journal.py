"""Write-ahead state-machine tests for the SQLite-backed native patch journal.

Section 14.4 / 15 of ``_gitless/REVERSIBLE-NATIVE-PATCHES.md`` plus review
finding P1 "journal state conflates byte persistence with analysis
certification" (design requirement 2) and design requirements 3
("PREPARED must be durably committed before a transaction is exposed for
application") and 4 (the netnode mirror is a separate receipt that can never
retroactively change SQLite transaction state).
"""

from __future__ import annotations

import sqlite3

import pytest

from d810.backends.ida.native_patch.journal import (
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
        second = store.prepare(
            fixtures.plan(
                operations=(
                    fixtures.operation(
                        operation_id="b", start_ea=0x1002, end_ea=0x1004
                    ),
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
            NativeJournalState.CERTIFIED,
            NativeJournalState.RESTORING,
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
            NativeJournalState.CERTIFIED,
        ):
            record = store.transition(tx, target)
            assert record.state is target

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
