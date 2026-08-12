"""Byte-granular recovery classification tests (review finding P0 #2).

``ida_bytes.patch_bytes`` returns no status and documents no atomicity
guarantee, so a crash mid-write can leave a *mixed* range: part before-image,
part after-image. Classifying an entire operation against its whole
before/after image would misclassify D810's own interrupted write as external
interference and refuse the rollback that is actually safe. These tests pin
the per-byte classifier (:class:`NativeByteRecoveryVerdict`) and the
operation/transaction-level reconstruction built from it
(:class:`NativeOperationRecoveryVerdict`, the recommended
:class:`NativeJournalState`).

They also pin design requirement 2 -- byte persistence and analysis
certification are different failure domains, so a crash after ``BYTES_APPLIED``
must not roll back bytes that are still fully present and correct.
"""

from __future__ import annotations

import pytest

from d810.backends.ida.native_patch.journal import SQLiteNativePatchJournal
from d810.capabilities.native_patch import (
    NativeByteEventPhase,
    NativeJournalState,
    NativeOperationRecoveryVerdict,
    NativePatchTransactionId,
)

from . import _plan_fixtures as fixtures

pytestmark = pytest.mark.pure_python


@pytest.fixture
def store(tmp_path):
    journal = SQLiteNativePatchJournal(tmp_path / "journal.db")
    yield journal
    journal.close()


def _reader(mapping: dict[int, int | None]):
    def _read(ea: int) -> int | None:
        return mapping.get(ea)

    return _read


class TestByteGranularClassification:
    def test_untouched_bytes_classify_as_not_applied(self, store) -> None:
        record = store.prepare(fixtures.plan())  # before=75 01, after=eb 01
        report = store.classify_recovery(
            record.transaction_id, _reader({0x1000: 0x75, 0x1001: 0x01})
        )
        assert (
            report.operation_reports[0].verdict
            is NativeOperationRecoveryVerdict.NOT_APPLIED
        )
        assert report.recommended_state is NativeJournalState.PREPARED

    def test_fully_written_and_corroborated_bytes_classify_as_applied(
        self, store
    ) -> None:
        record = store.prepare(fixtures.plan())
        tx = record.transaction_id
        for ea, current, replacement in ((0x1000, 0x75, 0xEB), (0x1001, 0x01, 0x01)):
            store.record_byte_event(
                tx,
                "op-1",
                ea,
                NativeByteEventPhase.WRITE_STARTED,
                expected_current=current,
                expected_original=current,
                replacement=replacement,
            )
            store.record_byte_event(
                tx,
                "op-1",
                ea,
                NativeByteEventPhase.WRITE_APPLIED,
                expected_current=current,
                expected_original=current,
                replacement=replacement,
            )

        report = store.classify_recovery(tx, _reader({0x1000: 0xEB, 0x1001: 0x01}))
        op_report = report.operation_reports[0]
        assert op_report.verdict is NativeOperationRecoveryVerdict.APPLIED
        assert op_report.corroborated_by_write_applied_receipt is True
        assert report.recommended_state is NativeJournalState.BYTES_APPLIED

    def test_applied_bytes_without_a_write_receipt_are_unexplained_interference(
        self, store
    ) -> None:
        # Bytes read as fully "after", but the store never recorded writing
        # them -- section 15.1.1 point 4: an unexplained delta invalidates
        # rather than being trusted as our own certified write.
        record = store.prepare(fixtures.plan())
        report = store.classify_recovery(
            record.transaction_id, _reader({0x1000: 0xEB, 0x1001: 0x01})
        )
        op_report = report.operation_reports[0]
        assert op_report.verdict is NativeOperationRecoveryVerdict.APPLIED
        assert op_report.corroborated_by_write_applied_receipt is False
        assert report.recommended_state is NativeJournalState.INTERFERENCE_DETECTED

    def test_a_partially_written_operation_is_partially_applied_not_interference(
        self, store
    ) -> None:
        # The exact P0 scenario: patch_byte(s) crashed after the first byte.
        # Both bytes actually differ before/after so the classification is
        # unambiguous (unlike the default fixture's second byte, whose
        # before/after values happen to coincide).
        op = fixtures.operation(
            expected_current_bytes=b"\x75\x01", replacement_bytes=b"\xeb\x02"
        )
        record = store.prepare(fixtures.plan(operations=(op,)))
        report = store.classify_recovery(
            record.transaction_id, _reader({0x1000: 0xEB, 0x1001: 0x01})
        )
        op_report = report.operation_reports[0]
        assert op_report.verdict is NativeOperationRecoveryVerdict.PARTIALLY_APPLIED
        assert report.recommended_state is NativeJournalState.ROLLING_BACK

    def test_a_byte_matching_neither_image_is_interference(self, store) -> None:
        op = fixtures.operation(
            expected_current_bytes=b"\x75\x01", replacement_bytes=b"\xeb\x02"
        )
        record = store.prepare(fixtures.plan(operations=(op,)))
        report = store.classify_recovery(
            record.transaction_id, _reader({0x1000: 0x90, 0x1001: 0x01})
        )
        op_report = report.operation_reports[0]
        assert op_report.verdict is NativeOperationRecoveryVerdict.INTERFERENCE
        assert report.recommended_state is NativeJournalState.INTERFERENCE_DETECTED

    def test_an_unreadable_byte_is_treated_as_interference(self, store) -> None:
        op = fixtures.operation(
            expected_current_bytes=b"\x75\x01", replacement_bytes=b"\xeb\x02"
        )
        record = store.prepare(fixtures.plan(operations=(op,)))
        report = store.classify_recovery(
            record.transaction_id, _reader({0x1000: None, 0x1001: 0x01})
        )
        assert (
            report.operation_reports[0].verdict
            is NativeOperationRecoveryVerdict.INTERFERENCE
        )

    def test_analysis_domain_failure_does_not_roll_back_applied_bytes(
        self, store
    ) -> None:
        # Design requirement 2: byte persistence and analysis certification
        # are different failure domains. A crash after BYTES_APPLIED but
        # before CERTIFIED must not imply the bytes should roll back.
        record = store.prepare(fixtures.plan())
        tx = record.transaction_id
        for ea, current, replacement in ((0x1000, 0x75, 0xEB), (0x1001, 0x01, 0x01)):
            store.record_byte_event(
                tx,
                "op-1",
                ea,
                NativeByteEventPhase.WRITE_STARTED,
                expected_current=current,
                expected_original=current,
                replacement=replacement,
            )
            store.record_byte_event(
                tx,
                "op-1",
                ea,
                NativeByteEventPhase.WRITE_APPLIED,
                expected_current=current,
                expected_original=current,
                replacement=replacement,
            )
        store.transition(tx, NativeJournalState.BYTES_APPLIED)
        store.transition(tx, NativeJournalState.ANALYSIS_PENDING)
        # Crash lands here -- process restarts; bytes are still fully applied.

        report = store.classify_recovery(tx, _reader({0x1000: 0xEB, 0x1001: 0x01}))
        assert (
            report.operation_reports[0].verdict
            is NativeOperationRecoveryVerdict.APPLIED
        )
        # Unchanged, NOT rolled back: the recorded analysis-domain progress
        # is preserved because the bytes are exactly where they should be.
        assert report.recommended_state is NativeJournalState.ANALYSIS_PENDING

    def test_reverted_bytes_after_recorded_progress_are_interference(
        self, store
    ) -> None:
        record = store.prepare(fixtures.plan())
        tx = record.transaction_id
        store.transition(tx, NativeJournalState.BYTES_APPLIED)
        # Someone reverted our patch back to the original bytes underneath us.
        report = store.classify_recovery(tx, _reader({0x1000: 0x75, 0x1001: 0x01}))
        assert report.recommended_state is NativeJournalState.INTERFERENCE_DETECTED

    def test_multi_operation_mixed_progress_with_no_interference_rolls_back(
        self, store
    ) -> None:
        a = fixtures.operation(
            operation_id="a",
            start_ea=0x1000,
            end_ea=0x1002,
            expected_current_bytes=b"\x75\x01",
            replacement_bytes=b"\xeb\x02",
        )
        b = fixtures.operation(
            operation_id="b",
            start_ea=0x2000,
            end_ea=0x2002,
            expected_current_bytes=b"\x75\x03",
            replacement_bytes=b"\xeb\x04",
        )
        record = store.prepare(fixtures.plan(operations=(a, b)))
        # "a" is fully applied, "b" is untouched: an operation-granularity
        # partial, still fully disambiguated (no NEITHER anywhere).
        reader = _reader({0x1000: 0xEB, 0x1001: 0x02, 0x2000: 0x75, 0x2001: 0x03})
        report = store.classify_recovery(record.transaction_id, reader)

        verdicts = {r.operation_id: r.verdict for r in report.operation_reports}
        assert verdicts["a"] is NativeOperationRecoveryVerdict.APPLIED
        assert verdicts["b"] is NativeOperationRecoveryVerdict.NOT_APPLIED
        assert report.recommended_state is NativeJournalState.ROLLING_BACK

    def test_classify_recovery_on_unknown_transaction_raises(self, store) -> None:
        with pytest.raises(ValueError):
            store.classify_recovery(NativePatchTransactionId.new(), _reader({}))
