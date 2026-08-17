"""SQLite write-ahead journal for reversible IDB preparation."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from d810.capabilities.idb_preparation import (
    IllegalPreparationTransition,
    PreparationByteDelta,
    PreparationPatchRow,
    PreparationRunRequest,
    PreparationState,
    PreparationTransactionId,
    PreparationTransactionRecord,
    PreparationTypeDelta,
    SerializedTypeSnapshot,
    allowed_preparation_transition,
)
from d810.core.execution_journal import DecompilationSessionId, ExecutionAttemptId

__all__ = [
    "PreparationLeaseConflict",
    "PreparationLegacyIdentityError",
    "SQLitePreparationJournal",
]


class PreparationLeaseConflict(ValueError):
    """Another transaction owns the database-wide preparation lane."""

    def __init__(self, database_identity: str, owner_transaction_id: str) -> None:
        self.database_identity = database_identity
        self.owner_transaction_id = owner_transaction_id
        super().__init__(
            f"database {database_identity!r} preparation lease is owned by "
            f"transaction {owner_transaction_id}"
        )


class PreparationLegacyIdentityError(ValueError):
    """An active legacy row cannot safely be attributed to any open IDB."""

    def __init__(self) -> None:
        super().__init__(
            "an active preparation journal row lacks durable database identity; "
            "manual recovery is required"
        )


_TERMINAL_STATES = frozenset(
    {
        PreparationState.RESTORED,
        PreparationState.REJECTED,
        PreparationState.FAILED,
    }
)
_RECOVERABLE_STATES = frozenset(
    {
        PreparationState.PREPARED,
        PreparationState.SCRIPT_RUNNING,
        PreparationState.CAPTURE_PENDING,
        PreparationState.CAPTURED,
        PreparationState.ANALYSIS_PENDING,
        PreparationState.RESTORING,
        PreparationState.ROLLING_BACK,
        PreparationState.RESTORE_FAILED,
        PreparationState.RECOVERY_REQUIRED,
    }
)
_LEASE_RELEASE_STATES = frozenset(
    {
        PreparationState.IDB_PREPARED,
        PreparationState.RESTORED,
        PreparationState.REJECTED,
        PreparationState.FAILED,
    }
)


class SQLitePreparationJournal:
    """Database-scoped durable implementation of the preparation store."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self._conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._init_schema()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> SQLitePreparationJournal:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS preparation_transactions (
                    transaction_id TEXT PRIMARY KEY,
                    database_identity TEXT,
                    anchor_function_ea INTEGER NOT NULL,
                    script_id TEXT NOT NULL,
                    script_path TEXT NOT NULL,
                    script_source_sha256 TEXT NOT NULL,
                    attempt_session TEXT NOT NULL,
                    attempt_sequence INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS preparation_database_leases (
                    database_identity TEXT PRIMARY KEY,
                    transaction_id TEXT NOT NULL UNIQUE,
                    FOREIGN KEY (transaction_id)
                        REFERENCES preparation_transactions(transaction_id)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS preparation_baseline_patches (
                    transaction_id TEXT NOT NULL,
                    ea INTEGER NOT NULL,
                    file_position INTEGER NOT NULL,
                    ida_original INTEGER NOT NULL,
                    current_value INTEGER NOT NULL,
                    PRIMARY KEY (transaction_id, ea),
                    FOREIGN KEY (transaction_id)
                        REFERENCES preparation_transactions(transaction_id)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS preparation_byte_deltas (
                    transaction_id TEXT NOT NULL,
                    ea INTEGER NOT NULL,
                    ida_original INTEGER NOT NULL,
                    before_is_patched INTEGER NOT NULL,
                    before_value INTEGER NOT NULL,
                    after_is_patched INTEGER NOT NULL,
                    after_value INTEGER NOT NULL,
                    PRIMARY KEY (transaction_id, ea),
                    FOREIGN KEY (transaction_id)
                        REFERENCES preparation_transactions(transaction_id)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS preparation_type_deltas (
                    transaction_id TEXT NOT NULL,
                    item_ea INTEGER NOT NULL,
                    before_present INTEGER NOT NULL,
                    before_type BLOB,
                    before_fields BLOB,
                    before_field_comments BLOB,
                    after_present INTEGER NOT NULL,
                    after_type BLOB,
                    after_fields BLOB,
                    after_field_comments BLOB,
                    PRIMARY KEY (transaction_id, item_ea),
                    FOREIGN KEY (transaction_id)
                        REFERENCES preparation_transactions(transaction_id)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS preparation_affected_functions (
                    transaction_id TEXT NOT NULL,
                    function_ea INTEGER NOT NULL,
                    PRIMARY KEY (transaction_id, function_ea),
                    FOREIGN KEY (transaction_id)
                        REFERENCES preparation_transactions(transaction_id)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS preparation_transitions (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    transaction_id TEXT NOT NULL,
                    from_state TEXT,
                    to_state TEXT NOT NULL,
                    note TEXT,
                    recorded_at REAL NOT NULL,
                    FOREIGN KEY (transaction_id)
                        REFERENCES preparation_transactions(transaction_id)
                )
                """
            )

    def _assert_no_active_legacy_rows(self) -> None:
        placeholders = ", ".join("?" for _ in _TERMINAL_STATES)
        row = self._conn.execute(
            """
            SELECT transaction_id
            FROM preparation_transactions
            WHERE (database_identity IS NULL OR TRIM(database_identity) = '')
              AND state NOT IN ("""
            + placeholders
            + ") LIMIT 1",
            tuple(state.value for state in _TERMINAL_STATES),
        ).fetchone()
        if row is not None:
            raise PreparationLegacyIdentityError()

    @staticmethod
    def _record_from_row(row: sqlite3.Row) -> PreparationTransactionRecord:
        return PreparationTransactionRecord(
            transaction_id=PreparationTransactionId(str(row["transaction_id"])),
            database_identity=str(row["database_identity"]),
            anchor_function_ea=int(row["anchor_function_ea"]),
            script_id=str(row["script_id"]),
            script_path=str(row["script_path"]),
            script_source_sha256=str(row["script_source_sha256"]),
            authorizing_attempt_id=ExecutionAttemptId(
                session=DecompilationSessionId(str(row["attempt_session"])),
                sequence=int(row["attempt_sequence"]),
            ),
            state=PreparationState(str(row["state"])),
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
        )

    def _require_record(
        self, transaction_id: PreparationTransactionId
    ) -> PreparationTransactionRecord:
        record = self.get(transaction_id)
        if record is None:
            raise KeyError(f"unknown preparation transaction {transaction_id.value}")
        return record

    def _acquire_lease(
        self, database_identity: str, transaction_id: PreparationTransactionId
    ) -> None:
        try:
            self._conn.execute(
                """
                INSERT INTO preparation_database_leases (
                    database_identity, transaction_id
                ) VALUES (?, ?)
                """,
                (database_identity, transaction_id.value),
            )
        except sqlite3.IntegrityError as error:
            owner = self._conn.execute(
                """
                SELECT transaction_id FROM preparation_database_leases
                WHERE database_identity = ?
                """,
                (database_identity,),
            ).fetchone()
            owner_id = "unknown" if owner is None else str(owner["transaction_id"])
            raise PreparationLeaseConflict(database_identity, owner_id) from error

    def prepare(
        self,
        request: PreparationRunRequest,
        baseline_rows: tuple[PreparationPatchRow, ...],
    ) -> PreparationTransactionRecord:
        if not isinstance(request, PreparationRunRequest):
            raise TypeError("request must be a PreparationRunRequest")
        ordered_baseline = tuple(sorted(baseline_rows, key=lambda row: row.ea))
        for previous, current in zip(
            ordered_baseline, ordered_baseline[1:], strict=False
        ):
            if previous.ea == current.ea:
                raise ValueError(f"duplicate baseline patch EA {current.ea:#x}")

        transaction_id = PreparationTransactionId.new()
        now = time.time()
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            self._assert_no_active_legacy_rows()
            self._conn.execute(
                """
                INSERT INTO preparation_transactions (
                    transaction_id, database_identity, anchor_function_ea,
                    script_id, script_path, script_source_sha256,
                    attempt_session, attempt_sequence, state, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    transaction_id.value,
                    request.database_identity,
                    request.anchor_function_ea,
                    request.script.script_id,
                    request.script.path,
                    request.script.source_sha256,
                    request.authorizing_attempt_id.session.value,
                    request.authorizing_attempt_id.sequence,
                    PreparationState.PREPARED.value,
                    now,
                    now,
                ),
            )
            self._acquire_lease(request.database_identity, transaction_id)
            self._conn.executemany(
                """
                INSERT INTO preparation_baseline_patches (
                    transaction_id, ea, file_position, ida_original, current_value
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    (
                        transaction_id.value,
                        row.ea,
                        row.file_position,
                        row.ida_original,
                        row.current_value,
                    )
                    for row in ordered_baseline
                ),
            )
            self._conn.execute(
                """
                INSERT INTO preparation_transitions (
                    transaction_id, from_state, to_state, note, recorded_at
                ) VALUES (?, NULL, ?, ?, ?)
                """,
                (
                    transaction_id.value,
                    PreparationState.PREPARED.value,
                    "prepared with durable patch baseline",
                    now,
                ),
            )
            self._conn.commit()
        except BaseException:
            self._conn.rollback()
            raise
        return self._require_record(transaction_id)

    def transition(
        self,
        transaction_id: PreparationTransactionId,
        target: PreparationState,
        *,
        note: str | None = None,
    ) -> PreparationTransactionRecord:
        if not isinstance(transaction_id, PreparationTransactionId):
            raise TypeError("transaction_id must be a PreparationTransactionId")
        if not isinstance(target, PreparationState):
            raise TypeError("target must be a PreparationState")
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            current = self._require_record(transaction_id)
            if not allowed_preparation_transition(current.state, target):
                raise IllegalPreparationTransition(current.state, target)
            if target is PreparationState.RESTORING:
                existing = self._conn.execute(
                    """
                    SELECT transaction_id FROM preparation_database_leases
                    WHERE database_identity = ?
                    """,
                    (current.database_identity,),
                ).fetchone()
                if existing is None:
                    self._acquire_lease(current.database_identity, transaction_id)
                elif str(existing["transaction_id"]) != transaction_id.value:
                    raise PreparationLeaseConflict(
                        current.database_identity, str(existing["transaction_id"])
                    )
            now = time.time()
            self._conn.execute(
                """
                UPDATE preparation_transactions
                SET state = ?, updated_at = ?
                WHERE transaction_id = ?
                """,
                (target.value, now, transaction_id.value),
            )
            self._conn.execute(
                """
                INSERT INTO preparation_transitions (
                    transaction_id, from_state, to_state, note, recorded_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (transaction_id.value, current.state.value, target.value, note, now),
            )
            if target in _LEASE_RELEASE_STATES:
                self._conn.execute(
                    """
                    DELETE FROM preparation_database_leases
                    WHERE database_identity = ? AND transaction_id = ?
                    """,
                    (current.database_identity, transaction_id.value),
                )
            self._conn.commit()
        except BaseException:
            self._conn.rollback()
            raise
        return self._require_record(transaction_id)

    def get(
        self, transaction_id: PreparationTransactionId
    ) -> PreparationTransactionRecord | None:
        row = self._conn.execute(
            """
            SELECT * FROM preparation_transactions WHERE transaction_id = ?
            """,
            (transaction_id.value,),
        ).fetchone()
        return None if row is None else self._record_from_row(row)

    def baseline_rows(
        self, transaction_id: PreparationTransactionId
    ) -> tuple[PreparationPatchRow, ...]:
        self._require_record(transaction_id)
        rows = self._conn.execute(
            """
            SELECT ea, file_position, ida_original, current_value
            FROM preparation_baseline_patches
            WHERE transaction_id = ? ORDER BY ea
            """,
            (transaction_id.value,),
        ).fetchall()
        return tuple(
            PreparationPatchRow(
                ea=int(row["ea"]),
                file_position=int(row["file_position"]),
                ida_original=int(row["ida_original"]),
                current_value=int(row["current_value"]),
            )
            for row in rows
        )

    def record_byte_deltas(
        self,
        transaction_id: PreparationTransactionId,
        deltas: tuple[PreparationByteDelta, ...],
    ) -> None:
        record = self._require_record(transaction_id)
        if record.state is not PreparationState.CAPTURE_PENDING:
            raise ValueError("byte deltas may only be recorded in capture_pending")
        ordered = tuple(sorted(deltas, key=lambda delta: delta.ea))
        with self._conn:
            self._conn.executemany(
                """
                INSERT INTO preparation_byte_deltas (
                    transaction_id, ea, ida_original, before_is_patched,
                    before_value, after_is_patched, after_value
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    (
                        transaction_id.value,
                        delta.ea,
                        delta.ida_original,
                        int(delta.before_is_patched),
                        delta.before_value,
                        int(delta.after_is_patched),
                        delta.after_value,
                    )
                    for delta in ordered
                ),
            )

    def byte_deltas(
        self, transaction_id: PreparationTransactionId
    ) -> tuple[PreparationByteDelta, ...]:
        self._require_record(transaction_id)
        rows = self._conn.execute(
            """
            SELECT * FROM preparation_byte_deltas
            WHERE transaction_id = ? ORDER BY ea
            """,
            (transaction_id.value,),
        ).fetchall()
        return tuple(
            PreparationByteDelta(
                ea=int(row["ea"]),
                ida_original=int(row["ida_original"]),
                before_is_patched=bool(row["before_is_patched"]),
                before_value=int(row["before_value"]),
                after_is_patched=bool(row["after_is_patched"]),
                after_value=int(row["after_value"]),
            )
            for row in rows
        )

    @staticmethod
    def _snapshot_from_row(row: sqlite3.Row, prefix: str) -> SerializedTypeSnapshot:
        if not bool(row[f"{prefix}_present"]):
            return SerializedTypeSnapshot.absent()
        return SerializedTypeSnapshot.from_parts(
            bytes(row[f"{prefix}_type"]),
            None if row[f"{prefix}_fields"] is None else bytes(row[f"{prefix}_fields"]),
            None
            if row[f"{prefix}_field_comments"] is None
            else bytes(row[f"{prefix}_field_comments"]),
        )

    def record_type_deltas(
        self,
        transaction_id: PreparationTransactionId,
        deltas: tuple[PreparationTypeDelta, ...],
    ) -> None:
        record = self._require_record(transaction_id)
        if record.state is not PreparationState.CAPTURE_PENDING:
            raise ValueError("type deltas may only be recorded in capture_pending")
        ordered = tuple(sorted(deltas, key=lambda delta: delta.item_ea))
        with self._conn:
            self._conn.executemany(
                """
                INSERT INTO preparation_type_deltas (
                    transaction_id, item_ea,
                    before_present, before_type, before_fields,
                    before_field_comments, after_present, after_type,
                    after_fields, after_field_comments
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    (
                        transaction_id.value,
                        delta.item_ea,
                        int(delta.before.present),
                        delta.before.type_bytes,
                        delta.before.field_bytes,
                        delta.before.field_comment_bytes,
                        int(delta.after.present),
                        delta.after.type_bytes,
                        delta.after.field_bytes,
                        delta.after.field_comment_bytes,
                    )
                    for delta in ordered
                ),
            )

    def type_deltas(
        self, transaction_id: PreparationTransactionId
    ) -> tuple[PreparationTypeDelta, ...]:
        self._require_record(transaction_id)
        rows = self._conn.execute(
            """
            SELECT * FROM preparation_type_deltas
            WHERE transaction_id = ? ORDER BY item_ea
            """,
            (transaction_id.value,),
        ).fetchall()
        return tuple(
            PreparationTypeDelta(
                item_ea=int(row["item_ea"]),
                before=self._snapshot_from_row(row, "before"),
                after=self._snapshot_from_row(row, "after"),
            )
            for row in rows
        )

    def record_affected_functions(
        self,
        transaction_id: PreparationTransactionId,
        function_eas: tuple[int, ...],
    ) -> None:
        self._require_record(transaction_id)
        ordered = tuple(sorted(set(function_eas)))
        if any(
            isinstance(ea, bool) or not isinstance(ea, int) or ea < 0 for ea in ordered
        ):
            raise ValueError("affected function EAs must be non-negative integers")
        with self._conn:
            self._conn.executemany(
                """
                INSERT INTO preparation_affected_functions (
                    transaction_id, function_ea
                ) VALUES (?, ?)
                """,
                ((transaction_id.value, ea) for ea in ordered),
            )

    def affected_functions(
        self, transaction_id: PreparationTransactionId
    ) -> tuple[int, ...]:
        self._require_record(transaction_id)
        rows = self._conn.execute(
            """
            SELECT function_ea FROM preparation_affected_functions
            WHERE transaction_id = ? ORDER BY function_ea
            """,
            (transaction_id.value,),
        ).fetchall()
        return tuple(int(row["function_ea"]) for row in rows)

    def recoverable(
        self, database_identity: str
    ) -> tuple[PreparationTransactionRecord, ...]:
        if not isinstance(database_identity, str) or not database_identity.strip():
            raise ValueError("database_identity must be a non-empty string")
        placeholders = ", ".join("?" for _ in _RECOVERABLE_STATES)
        rows = self._conn.execute(
            """
            SELECT * FROM preparation_transactions
            WHERE database_identity = ? AND state IN ("""
            + placeholders
            + ") ORDER BY created_at, transaction_id",
            (database_identity,) + tuple(state.value for state in _RECOVERABLE_STATES),
        ).fetchall()
        return tuple(self._record_from_row(row) for row in rows)

    def active_byte_ranges(self, database_identity: str) -> tuple[tuple[int, int], ...]:
        terminal_placeholders = ", ".join("?" for _ in _TERMINAL_STATES)
        rows = self._conn.execute(
            """
            SELECT d.ea
            FROM preparation_byte_deltas d
            JOIN preparation_transactions t
              ON t.transaction_id = d.transaction_id
            WHERE t.database_identity = ? AND t.state NOT IN ("""
            + terminal_placeholders
            + ") ORDER BY d.ea",
            (database_identity,) + tuple(state.value for state in _TERMINAL_STATES),
        ).fetchall()
        eas = sorted({int(row["ea"]) for row in rows})
        if not eas:
            return ()
        ranges: list[tuple[int, int]] = []
        start = previous = eas[0]
        for ea in eas[1:]:
            if ea != previous + 1:
                ranges.append((start, previous + 1))
                start = ea
            previous = ea
        ranges.append((start, previous + 1))
        return tuple(ranges)

    def active_type_items(self, database_identity: str) -> tuple[int, ...]:
        terminal_placeholders = ", ".join("?" for _ in _TERMINAL_STATES)
        rows = self._conn.execute(
            """
            SELECT DISTINCT d.item_ea
            FROM preparation_type_deltas d
            JOIN preparation_transactions t
              ON t.transaction_id = d.transaction_id
            WHERE t.database_identity = ? AND t.state NOT IN ("""
            + terminal_placeholders
            + ") ORDER BY d.item_ea",
            (database_identity,) + tuple(state.value for state in _TERMINAL_STATES),
        ).fetchall()
        return tuple(int(row["item_ea"]) for row in rows)
