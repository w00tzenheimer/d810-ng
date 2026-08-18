from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

import pytest

from d810.backends.ida.idb_preparation.journal import (
    PreparationLeaseConflict,
    PreparationLegacyIdentityError,
    SQLitePreparationJournal,
)
from d810.capabilities.idb_preparation import (
    IllegalPreparationTransition,
    PreparationByteDelta,
    PreparationDeclaredByteBaseline,
    PreparationPatchRow,
    PreparationRunRequest,
    PreparationScriptDescriptor,
    PreparationState,
    PreparationTypeDelta,
    SerializedTypeSnapshot,
)
from d810.core.execution_journal import DecompilationSessionId, ExecutionAttemptId

pytestmark = pytest.mark.pure_python


def _request(
    database_identity: str,
    script_id: str,
    *,
    function_ea: int = 0x401000,
) -> PreparationRunRequest:
    return PreparationRunRequest(
        database_identity=database_identity,
        anchor_function_ea=function_ea,
        script=PreparationScriptDescriptor(
            script_id=script_id,
            display_name=script_id,
            path=f"scripts/{script_id}.py",
            source_sha256="a" * 64,
            enabled=True,
            portable=True,
        ),
        authorizing_attempt_id=ExecutionAttemptId.new(
            session=DecompilationSessionId.new(), sequence=1
        ),
    )


def _baseline() -> tuple[PreparationPatchRow, ...]:
    return (PreparationPatchRow(0x1000, 4, 0x75, 0x74),)


def _create_running(
    journal: SQLitePreparationJournal,
    *,
    database_identity: str,
    script_id: str,
):
    record = journal.prepare(_request(database_identity, script_id), _baseline())
    return journal.transition(record.transaction_id, PreparationState.SCRIPT_RUNNING)


def test_prepare_persists_baseline_and_identity_across_reopen(tmp_path: Path) -> None:
    path = tmp_path / "journal.sqlite3"
    with SQLitePreparationJournal(path) as journal:
        created = journal.prepare(_request("idb-a", "script-a"), _baseline())

    with SQLitePreparationJournal(path) as reopened:
        assert reopened.get(created.transaction_id) == created
        assert reopened.baseline_rows(created.transaction_id) == _baseline()


def test_prepare_atomically_excludes_second_running_script(tmp_path: Path) -> None:
    path = tmp_path / "journal.sqlite3"
    with (
        SQLitePreparationJournal(path) as first,
        SQLitePreparationJournal(path) as second,
    ):
        transaction = _create_running(
            first, database_identity="idb-a", script_id="script-a"
        )

        with pytest.raises(PreparationLeaseConflict, match="idb-a"):
            second.prepare(_request("idb-a", "script-b"), ())

        assert first.get(transaction.transaction_id) == transaction


def test_prepare_allows_independent_databases(tmp_path: Path) -> None:
    path = tmp_path / "journal.sqlite3"
    with (
        SQLitePreparationJournal(path) as first,
        SQLitePreparationJournal(path) as second,
    ):
        _create_running(first, database_identity="idb-a", script_id="script-a")
        other = second.prepare(_request("idb-b", "script-b"), ())

        assert other.database_identity == "idb-b"


def test_recoverable_transactions_are_database_scoped(tmp_path: Path) -> None:
    with SQLitePreparationJournal(tmp_path / "journal.sqlite3") as journal:
        transaction_a = _create_running(
            journal, database_identity="idb-a", script_id="script-a"
        )
        _create_running(journal, database_identity="idb-b", script_id="script-b")

        assert journal.recoverable("idb-a") == (transaction_a,)


def test_running_transaction_remains_recoverable_after_reopen(tmp_path: Path) -> None:
    path = tmp_path / "journal.sqlite3"
    with SQLitePreparationJournal(path) as journal:
        running = _create_running(
            journal, database_identity="idb-a", script_id="script-a"
        )

    with SQLitePreparationJournal(path) as reopened:
        assert reopened.recoverable("idb-a") == (running,)


def test_legacy_null_identity_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "journal.sqlite3"
    with SQLitePreparationJournal(path):
        pass
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            INSERT INTO preparation_transactions (
                transaction_id, database_identity, anchor_function_ea,
                script_id, script_path, script_source_sha256,
                attempt_session, attempt_sequence, state, created_at, updated_at
            ) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "legacy",
                0x401000,
                "legacy-script",
                "legacy.py",
                "b" * 64,
                "legacy-session",
                1,
                PreparationState.SCRIPT_RUNNING.value,
                1.0,
                1.0,
            ),
        )

    with SQLitePreparationJournal(path) as journal:
        assert journal.recoverable("idb-a") == ()
        with pytest.raises(PreparationLegacyIdentityError):
            journal.prepare(_request("idb-a", "script-a"), ())


def test_concurrent_prepare_has_exactly_one_winner(tmp_path: Path) -> None:
    path = tmp_path / "journal.sqlite3"
    with SQLitePreparationJournal(path):
        pass
    barrier = threading.Barrier(2)
    outcomes: list[str] = []
    outcome_lock = threading.Lock()

    def _prepare(script_id: str) -> None:
        with SQLitePreparationJournal(path) as journal:
            barrier.wait()
            try:
                journal.prepare(_request("idb-a", script_id), ())
                outcome = "prepared"
            except PreparationLeaseConflict:
                outcome = "conflict"
            with outcome_lock:
                outcomes.append(outcome)

    threads = [
        threading.Thread(target=_prepare, args=("script-a",)),
        threading.Thread(target=_prepare, args=("script-b",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert all(not thread.is_alive() for thread in threads)
    assert sorted(outcomes) == ["conflict", "prepared"]


def test_capture_data_and_ownership_round_trip(tmp_path: Path) -> None:
    with SQLitePreparationJournal(tmp_path / "journal.sqlite3") as journal:
        transaction = _create_running(
            journal, database_identity="idb-a", script_id="script-a"
        )
        declared_baseline = PreparationDeclaredByteBaseline(
            ea=0x1000,
            ida_original=0x75,
            before_is_patched=False,
            before_value=0x66,
        )
        journal.record_declared_byte_baselines(
            transaction.transaction_id, (declared_baseline,)
        )
        transaction = journal.transition(
            transaction.transaction_id, PreparationState.CAPTURE_PENDING
        )
        byte_delta = PreparationByteDelta(0x1000, 0x75, True, 0x74, True, 0xEB)
        type_delta = PreparationTypeDelta(
            item_ea=0x2000,
            before=SerializedTypeSnapshot.absent(),
            after=SerializedTypeSnapshot.from_parts(b"type", b"fields", b"comments"),
        )
        journal.record_byte_deltas(transaction.transaction_id, (byte_delta,))
        journal.record_type_deltas(transaction.transaction_id, (type_delta,))
        journal.record_affected_functions(transaction.transaction_id, (0x401000,))

        assert journal.byte_deltas(transaction.transaction_id) == (byte_delta,)
        assert journal.declared_byte_baselines(transaction.transaction_id) == (
            declared_baseline,
        )
        assert journal.type_deltas(transaction.transaction_id) == (type_delta,)
        assert journal.affected_functions(transaction.transaction_id) == (0x401000,)
        assert journal.active_byte_ranges("idb-a") == ((0x1000, 0x1001),)
        assert journal.active_type_items("idb-a") == (0x2000,)


def test_idb_prepared_releases_execution_lease_but_retains_ownership(
    tmp_path: Path,
) -> None:
    with SQLitePreparationJournal(tmp_path / "journal.sqlite3") as journal:
        transaction = _create_running(
            journal, database_identity="idb-a", script_id="script-a"
        )
        transaction = journal.transition(
            transaction.transaction_id, PreparationState.CAPTURE_PENDING
        )
        journal.record_byte_deltas(
            transaction.transaction_id,
            (PreparationByteDelta(0x1000, 0x75, False, 0x75, True, 0xEB),),
        )
        for state in (
            PreparationState.CAPTURED,
            PreparationState.ANALYSIS_PENDING,
            PreparationState.IDB_PREPARED,
        ):
            transaction = journal.transition(transaction.transaction_id, state)

        assert journal.recoverable("idb-a") == ()
        assert journal.prepared("idb-a") == (transaction,)
        assert journal.transactions("idb-a") == (transaction,)
        assert journal.prepared("idb-b") == ()
        assert journal.transactions("idb-b") == ()
        assert journal.active_byte_ranges("idb-a") == ((0x1000, 0x1001),)
        next_transaction = journal.prepare(_request("idb-a", "script-b"), ())
        assert next_transaction.state is PreparationState.PREPARED


def test_restore_reacquires_database_execution_lease(tmp_path: Path) -> None:
    with SQLitePreparationJournal(tmp_path / "journal.sqlite3") as journal:
        transaction = _create_running(
            journal, database_identity="idb-a", script_id="script-a"
        )
        for state in (
            PreparationState.CAPTURE_PENDING,
            PreparationState.CAPTURED,
            PreparationState.ANALYSIS_PENDING,
            PreparationState.IDB_PREPARED,
            PreparationState.RESTORING,
        ):
            transaction = journal.transition(transaction.transaction_id, state)

        with pytest.raises(PreparationLeaseConflict):
            journal.prepare(_request("idb-a", "script-b"), ())


def test_illegal_transition_does_not_change_durable_state(tmp_path: Path) -> None:
    with SQLitePreparationJournal(tmp_path / "journal.sqlite3") as journal:
        transaction = journal.prepare(_request("idb-a", "script-a"), ())

        with pytest.raises(IllegalPreparationTransition):
            journal.transition(
                transaction.transaction_id, PreparationState.IDB_PREPARED
            )

        assert journal.get(transaction.transaction_id) == transaction
