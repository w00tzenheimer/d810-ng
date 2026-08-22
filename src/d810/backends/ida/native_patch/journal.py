"""SQLite-backed write-ahead native-patch journal and recovery classifier.

Implements ``NativePatchJournalStore`` (``d810.capabilities.native_patch``)
for Task 2 of ``_gitless/profile-guided-native-mutation-implementer-plan.md``.
This module owns:

* durable transaction persistence (``prepare``/``transition``/``get``);
* the byte-granular write-ahead log (``record_byte_event``) and its
  reconstruction into a recovery verdict (``classify_recovery`` -- review
  finding P0 #2, see ``d810.capabilities.native_patch``'s module docstring
  for the design);
* the netnode-mirror receipt lane (``record_mirror_receipt`` /
  ``mirror_receipts``), kept strictly separate from transaction state
  (design requirement 4).

This module writes no IDB bytes and makes no live IDA call. It sits in
``d810.backends.ida.native_patch`` (rank 6, may import IDA) because it is the
IDA-specific recovery journal and will eventually be handed a real
``ida_bytes``-backed byte reader by Task 6's gateway -- but Task 2 itself only
needs an injected ``Callable[[int], int | None]``, so no ``ida_*`` import
appears here yet. Fakes are used in the unit tests per this repository's
"no IDA mocking in unit tests" rule (``tests/unit/conftest.py``): the reader
is a plain Python callable, not a mocked IDA module.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path

from d810.capabilities.native_patch import (
    IllegalNativeJournalTransition,
    NativeByteEventPhase,
    NativeByteRecoveryEntry,
    NativeByteRecoveryVerdict,
    NativeJournalState,
    NativeMirrorOutcome,
    AppliedMetadataAction,
    NativeMirrorReceipt,
    NativeOperationRecoveryReport,
    NativeOperationRecoveryVerdict,
    NativePatchPlanEnvelope,
    NativePatchTransactionId,
    NativePatchTransactionRecord,
    NativeTransactionRecoveryReport,
    OperationByteRecord,
    is_legal_native_journal_transition,
)
from d810.backends.ida.native_patch.phase_schema import (
    parse_analysis_phase_attestation,
    parse_analysis_phase_witness,
)
from d810.core.execution_journal import DecompilationSessionId, ExecutionAttemptId

__all__ = [
    "NativeCurrentByteReader",
    "NativePatchMetadataScopeConflictError",
    "NativePatchFunctionScopeConflictError",
    "NativePatchTransactionConflictError",
    "SQLiteNativePatchJournal",
]

# A byte reader returns the current byte value at `ea`, or None when it
# cannot be read (undefined/unmapped/inaccessible). `None` is treated as
# NEITHER (interference) rather than silently skipped -- an unreadable byte
# can confirm neither the before- nor the after-image.
NativeCurrentByteReader = Callable[[int], "int | None"]


class NativePatchTransactionConflictError(ValueError):
    """A new plan's operation range overlaps an already-active transaction.

    Invariant 6: "No active plan owns an overlapping range." A transaction
    is "active" (blocks a new overlapping prepare) unless it is ``RESTORED``
    -- the only state that verifiably frees its range for reuse.
    ``RESTORE_FAILED`` deliberately still blocks: the range is in an unknown,
    broken state that requires manual resolution, not reuse by a new plan.
    """

    def __init__(self, operation_id: str, start_ea: int, end_ea: int) -> None:
        self.operation_id = operation_id
        self.start_ea = start_ea
        self.end_ea = end_ea
        super().__init__(
            f"operation {operation_id!r} range "
            f"[0x{start_ea:x}, 0x{end_ea:x}) overlaps an active transaction"
        )


class NativePatchMetadataScopeConflictError(ValueError):
    """A metadata surface is owned by an active transaction.

    Byte-anchor ranges identify the evidence used to authorize an operation,
    not every mutable IDB surface it owns.  In particular, two disjoint
    anchors can both target one xref source or switch record.  Those plans
    must serialize just as overlapping byte writes do.
    """

    def __init__(self, operation_id: str, scope_kind: str, scope_ea: int) -> None:
        self.operation_id = operation_id
        self.scope_kind = scope_kind
        self.scope_ea = scope_ea
        super().__init__(
            f"operation {operation_id!r} metadata scope "
            f"{scope_kind}@{scope_ea:#x} overlaps an active transaction"
        )


class NativePatchFunctionScopeConflictError(ValueError):
    """An active transaction already owns a function's certificate slot.

    Certificates are keyed by database identity plus function entry, so
    disjoint byte anchors inside one function still cannot coexist.  Without
    this journal-level exclusion, a direct gateway caller could replace the
    first transaction's certificate before it is explicitly restored.
    """

    def __init__(self, operation_id: str, function_ea: int) -> None:
        self.operation_id = operation_id
        self.function_ea = function_ea
        super().__init__(
            f"operation {operation_id!r} function certificate slot "
            f"0x{function_ea:x} is owned by an active transaction"
        )


class NativePatchLegacyIdentityError(ValueError):
    """A legacy active row cannot be attributed to the current IDB safely."""

    def __init__(self) -> None:
        super().__init__(
            "an active native-patch journal row lacks durable database identity; "
            "manual recovery is required before preparing another patch"
        )


_POST_BYTES_STATES = frozenset(
    {
        NativeJournalState.BYTES_APPLIED,
        NativeJournalState.METADATA_APPLIED,
        NativeJournalState.ANALYSIS_PENDING,
        NativeJournalState.ANALYSIS_VALIDATED,
        NativeJournalState.CACHE_INVALIDATED,
        NativeJournalState.CERTIFICATE_PENDING,
        NativeJournalState.POSTCONDITION_PENDING,
        NativeJournalState.CERTIFIED,
    }
)

# These are the states where an interrupted apply has a reversible, durable
# before-image and the gateway's emergency lane can still transition to its
# rollback/recovery outcome. ``CERTIFICATE_PENDING`` and
# ``POSTCONDITION_PENDING`` are deliberately included: a certificate is not
# complete until its external blob/link writes finish, and a Stage C
# certificate is not authoritative until its independent live observation is
# durably linked to the terminal transition.
# Restore-lane states have their own resumable reconciliation path.
_STARTUP_RECOVERABLE_STATES = frozenset(
    {
        NativeJournalState.PREPARED,
        NativeJournalState.BYTES_APPLIED,
        NativeJournalState.METADATA_APPLIED,
        NativeJournalState.ANALYSIS_PENDING,
        NativeJournalState.ANALYSIS_VALIDATED,
        NativeJournalState.CACHE_INVALIDATED,
        NativeJournalState.CERTIFICATE_PENDING,
        NativeJournalState.POSTCONDITION_PENDING,
        NativeJournalState.RESTORING,
        NativeJournalState.RESTORE_BYTES_RESTORED,
        NativeJournalState.ANALYSIS_RECONCILED,
        NativeJournalState.RESTORE_FAILED,
    }
)


def _recommend_state(
    recorded_state: NativeJournalState,
    operation_reports: tuple[NativeOperationRecoveryReport, ...],
) -> NativeJournalState:
    """Reconcile the last durably recorded state against observed bytes.

    Byte persistence and analysis certification are different failure
    domains (design requirement 2): a recorded state past ``BYTES_APPLIED``
    is never downgraded just because recovery is being classified -- bytes
    that read back as fully applied leave that downstream state untouched.
    """
    verdicts = [report.verdict for report in operation_reports]

    if any(v is NativeOperationRecoveryVerdict.INTERFERENCE for v in verdicts):
        return NativeJournalState.INTERFERENCE_DETECTED

    if all(v is NativeOperationRecoveryVerdict.NOT_APPLIED for v in verdicts):
        if recorded_state in _POST_BYTES_STATES:
            # The record says bytes should be there; they are not. Something
            # reverted our applied bytes underneath us.
            return NativeJournalState.INTERFERENCE_DETECTED
        return NativeJournalState.PREPARED

    if all(v is NativeOperationRecoveryVerdict.APPLIED for v in verdicts):
        if recorded_state in _POST_BYTES_STATES:
            return recorded_state
        if recorded_state is NativeJournalState.PREPARED:
            corroborated = all(
                report.corroborated_by_write_applied_receipt
                for report in operation_reports
            )
            return (
                NativeJournalState.BYTES_APPLIED
                if corroborated
                else NativeJournalState.INTERFERENCE_DETECTED
            )
        # A restore/rollback-lane state (RESTORED, RESTORE_FAILED, ...) but
        # bytes read back fully applied: inconsistent with the recorded
        # outcome.
        return NativeJournalState.INTERFERENCE_DETECTED

    # A disambiguated mix (some NOT_APPLIED, some APPLIED, or a single
    # PARTIALLY_APPLIED operation) with zero NEITHER verdicts anywhere: every
    # byte is unambiguously identifiable, so automatic rollback is safe.
    return NativeJournalState.ROLLING_BACK


class SQLiteNativePatchJournal:
    """The write-ahead journal's SQLite-backed concrete implementation."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._init_schema()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> SQLiteNativePatchJournal:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS native_patch_transactions (
                    transaction_id TEXT PRIMARY KEY,
                    plan_id TEXT NOT NULL,
                    plan_hash TEXT NOT NULL,
                    attempt_session TEXT NOT NULL,
                    attempt_sequence INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    has_metadata_actions INTEGER NOT NULL,
                    idb_uuid TEXT,
                    function_entry_ea INTEGER,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            columns = {
                str(row["name"])
                for row in self._conn.execute(
                    "PRAGMA table_info(native_patch_transactions)"
                ).fetchall()
            }
            # Existing global journals predate database-scoped rows. Keep the
            # migration non-destructive, but leave their identity NULL so all
            # subsequent code fails closed rather than guessing an IDB.
            if "idb_uuid" not in columns:
                self._conn.execute(
                    "ALTER TABLE native_patch_transactions ADD COLUMN idb_uuid TEXT"
                )
            if "function_entry_ea" not in columns:
                self._conn.execute(
                    "ALTER TABLE native_patch_transactions "
                    "ADD COLUMN function_entry_ea INTEGER"
                )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS native_patch_certificate_slots (
                    idb_uuid TEXT NOT NULL,
                    function_entry_ea INTEGER NOT NULL,
                    transaction_id TEXT NOT NULL UNIQUE,
                    PRIMARY KEY (idb_uuid, function_entry_ea),
                    FOREIGN KEY (transaction_id)
                        REFERENCES native_patch_transactions(transaction_id)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS native_patch_operations (
                    transaction_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    start_ea INTEGER NOT NULL,
                    end_ea INTEGER NOT NULL,
                    PRIMARY KEY (transaction_id, operation_id)
                )
                """
            )
            # Metadata actions actually applied, with the state each one
            # replaced. Written at apply time, not plan time: the plan says
            # what the before-state is *expected* to be, this records what it
            # actually was, and reversal replays that recorded value.
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS native_patch_metadata_actions (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    transaction_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    ea INTEGER NOT NULL,
                    recorded_before TEXT NOT NULL,
                    expected_after TEXT NOT NULL
                )
                """
            )
            # Scoped metadata ownership is recorded at PREPARED time, before
            # an IDA mutation can begin.  It prevents distinct byte anchors
            # from concurrently modifying one item head, xref source, switch
            # record, or function extent.
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS native_patch_metadata_scopes (
                    transaction_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    action_index INTEGER NOT NULL,
                    scope_kind TEXT NOT NULL,
                    scope_ea INTEGER NOT NULL,
                    PRIMARY KEY (transaction_id, operation_id, action_index)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS native_patch_analysis_phases (
                    transaction_id TEXT PRIMARY KEY,
                    witness TEXT NOT NULL,
                    FOREIGN KEY (transaction_id)
                        REFERENCES native_patch_transactions(transaction_id)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS native_patch_analysis_attestations (
                    transaction_id TEXT PRIMARY KEY,
                    attestation TEXT NOT NULL,
                    FOREIGN KEY (transaction_id)
                        REFERENCES native_patch_transactions(transaction_id)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS native_patch_certificate_links (
                    transaction_id TEXT PRIMARY KEY,
                    certificate_id TEXT NOT NULL,
                    plan_hash TEXT NOT NULL,
                    database_key TEXT NOT NULL,
                    function_key TEXT NOT NULL,
                    FOREIGN KEY (transaction_id)
                        REFERENCES native_patch_transactions(transaction_id)
                )
                """
            )
            # The reverse schedule is durable independently of the
            # certificate.  ``status`` and the two exact state snapshots make
            # a crash between a carrier intent and its natural inverse
            # distinguishable from a completed step.
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS native_patch_analysis_reverse_steps (
                    transaction_id TEXT NOT NULL,
                    step_index INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    head_ea INTEGER,
                    action_index INTEGER,
                    action_kind TEXT,
                    ea INTEGER,
                    before_state TEXT,
                    after_state TEXT,
                    expected_after TEXT,
                    global_before TEXT,
                    global_after TEXT,
                    cleared_state TEXT,
                    status TEXT NOT NULL,
                    intent TEXT,
                    completion TEXT,
                    PRIMARY KEY (transaction_id, step_index),
                    FOREIGN KEY (transaction_id)
                        REFERENCES native_patch_transactions(transaction_id)
                )
                """
            )
            reverse_columns = {
                str(row["name"])
                for row in self._conn.execute(
                    "PRAGMA table_info(native_patch_analysis_reverse_steps)"
                ).fetchall()
            }
            for column in (
                "before_state", "after_state", "global_before", "global_after",
                "cleared_state",
            ):
                if column not in reverse_columns:
                    self._conn.execute(
                        f"ALTER TABLE native_patch_analysis_reverse_steps "
                        f"ADD COLUMN {column} TEXT"
                    )
            # Pre-patch function extent, captured while the database still
            # holds the truth. A separate table rather than columns on
            # native_patch_operations so an existing journal file picks it up
            # under CREATE TABLE IF NOT EXISTS instead of needing an ALTER.
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS native_patch_operation_ownership (
                    transaction_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    chunk_index INTEGER NOT NULL,
                    owning_function_entry_ea INTEGER NOT NULL,
                    chunk_start_ea INTEGER NOT NULL,
                    chunk_end_ea INTEGER NOT NULL,
                    PRIMARY KEY (transaction_id, operation_id, chunk_index)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS native_patch_operation_flow_refs (
                    transaction_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    ref_index INTEGER NOT NULL,
                    source_ea INTEGER NOT NULL,
                    target_ea INTEGER NOT NULL,
                    xref_type INTEGER NOT NULL,
                    is_user INTEGER NOT NULL,
                    PRIMARY KEY (transaction_id, operation_id, ref_index)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS native_patch_operation_function_metadata (
                    transaction_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    owning_function_entry_ea INTEGER NOT NULL,
                    function_flags INTEGER NOT NULL,
                    has_type_info INTEGER NOT NULL,
                    type_bytes BLOB,
                    field_bytes BLOB,
                    field_comment_bytes BLOB,
                    PRIMARY KEY (transaction_id, operation_id)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS native_patch_operation_bytes (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    transaction_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    ea INTEGER NOT NULL,
                    expected_current INTEGER NOT NULL,
                    expected_original INTEGER NOT NULL,
                    replacement INTEGER NOT NULL,
                    UNIQUE (transaction_id, operation_id, ea)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS native_patch_byte_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    transaction_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    ea INTEGER NOT NULL,
                    phase TEXT NOT NULL,
                    expected_current INTEGER NOT NULL,
                    expected_original INTEGER NOT NULL,
                    replacement INTEGER NOT NULL,
                    recorded_at REAL NOT NULL,
                    UNIQUE (transaction_id, operation_id, ea, phase)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS native_patch_transitions (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    transaction_id TEXT NOT NULL,
                    from_state TEXT,
                    to_state TEXT NOT NULL,
                    note TEXT,
                    recorded_at REAL NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS native_patch_mirror_receipts (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    transaction_id TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    at_state TEXT NOT NULL,
                    reason TEXT,
                    recorded_at REAL NOT NULL
                )
                """
            )

    # -- transaction lifecycle -------------------------------------------------

    def _assert_no_legacy_active_transactions(self) -> None:
        row = self._conn.execute(
            """
            SELECT transaction_id
            FROM native_patch_transactions
            WHERE state != ? AND (idb_uuid IS NULL OR TRIM(idb_uuid) = '')
            LIMIT 1
            """,
            (NativeJournalState.RESTORED.value,),
        ).fetchone()
        if row is not None:
            raise NativePatchLegacyIdentityError()

    def _active_operation_ranges(self, database_identity: str) -> list[tuple[int, int]]:
        rows = self._conn.execute(
            """
            SELECT o.start_ea, o.end_ea
            FROM native_patch_operations o
            JOIN native_patch_transactions t ON t.transaction_id = o.transaction_id
            WHERE t.state != ? AND t.idb_uuid = ?
            """,
            (NativeJournalState.RESTORED.value, database_identity),
        ).fetchall()
        return [(row["start_ea"], row["end_ea"]) for row in rows]

    def active_operation_ranges(
        self, *, database_identity: str
    ) -> tuple[tuple[int, int], ...]:
        """Expose current byte ownership to peer mutation gateways."""

        if not isinstance(database_identity, str) or not database_identity.strip():
            raise ValueError("database_identity must be a non-empty string")
        return tuple(self._active_operation_ranges(database_identity))

    def _active_metadata_scopes(self, database_identity: str) -> set[tuple[str, int]]:
        rows = self._conn.execute(
            """
            SELECT s.scope_kind, s.scope_ea
            FROM native_patch_metadata_scopes s
            JOIN native_patch_transactions t ON t.transaction_id = s.transaction_id
            WHERE t.state != ? AND t.idb_uuid = ?
            """,
            (NativeJournalState.RESTORED.value, database_identity),
        ).fetchall()
        return {(str(row["scope_kind"]), int(row["scope_ea"])) for row in rows}

    def _active_function_certificate_slots(self, database_identity: str) -> set[int]:
        rows = self._conn.execute(
            """
            SELECT function_entry_ea
            FROM native_patch_certificate_slots
            WHERE idb_uuid = ?
            """,
            (database_identity,),
        ).fetchall()
        return {int(row["function_entry_ea"]) for row in rows}

    def recoverable_transaction_ids(
        self, *, database_identity: str
    ) -> tuple[NativePatchTransactionId, ...]:
        """Return startup-reconcilable apply/restore transactions in order."""
        if not isinstance(database_identity, str) or not database_identity.strip():
            raise ValueError("database_identity must be a non-empty string")
        placeholders = ", ".join("?" for _ in _STARTUP_RECOVERABLE_STATES)
        rows = self._conn.execute(
            """
            SELECT transaction_id
            FROM native_patch_transactions
            WHERE idb_uuid = ? AND state IN ("""
            + placeholders
            + ") ORDER BY created_at, transaction_id",
            (database_identity,)
            + tuple(state.value for state in _STARTUP_RECOVERABLE_STATES),
        ).fetchall()
        return tuple(
            NativePatchTransactionId(value=str(row["transaction_id"])) for row in rows
        )

    @staticmethod
    def _metadata_scopes_for_operation(operation) -> tuple[tuple[str, int], ...]:
        scopes: list[tuple[str, int]] = []
        function_ea = (
            operation.restore_snapshot.function_ownership.owning_function_entry_ea
        )
        for action in operation.metadata_actions:
            if action.kind.value == "recreate_item":
                scopes.extend((("item_graph", 0), ("xref_graph", 0)))
            elif action.kind.value == "update_xref":
                scopes.append(("xref_source", int(action.ea)))
            elif action.kind.value == "set_switch_info":
                scopes.append(("switch", int(action.ea)))
            elif action.kind.value in {"set_function_tail", "function_tail_chunk"}:
                scopes.append(("function_chunks", int(function_ea)))
            else:
                # Unsupported metadata actions must never become silently
                # shareable.  Their own executor rejects them, and this
                # durable scope also serializes any future implementation.
                scopes.append((f"metadata:{action.kind.value}", int(action.ea)))
        return tuple(scopes)

    @staticmethod
    def _metadata_scopes_overlap(
        left: tuple[str, int], right: tuple[str, int]
    ) -> bool:
        left_kind, left_ea = left
        right_kind, right_ea = right
        if left_kind == "item_graph" or right_kind == "item_graph":
            return left_kind in {"item_graph", "item"} or right_kind in {
                "item_graph",
                "item",
            }
        if left_kind == "xref_graph" or right_kind == "xref_graph":
            return left_kind in {"xref_graph", "xref_source"} and right_kind in {
                "xref_graph",
                "xref_source",
            }
        return left_kind == right_kind and left_ea == right_ea

    def prepare(self, plan: NativePatchPlanEnvelope) -> NativePatchTransactionRecord:
        database_identity = str(plan.database_identity.idb_uuid)
        function_ea = int(plan.function_identity.entry_ea)
        if not database_identity.strip():
            raise ValueError("plan database identity must be non-empty")
        for operation in plan.operations:
            for ownership in (
                operation.expected_function_ownership,
                operation.restore_snapshot.function_ownership,
            ):
                if ownership.owning_function_entry_ea != function_ea:
                    raise ValueError(
                        "operation ownership must belong to the plan function identity"
                    )

        transaction_id = NativePatchTransactionId.new()
        now = time.time()
        has_metadata_actions = any(
            len(op.metadata_actions) > 0 for op in plan.operations
        )

        # Everything below commits atomically (or not at all): the
        # transaction row, every operation row, and every governed byte's
        # planned before/after image must all land durably together before
        # `prepare()` returns -- design requirement 3.
        # SQLite's BEGIN IMMEDIATE grants the slot contender an exclusive
        # writer reservation *before* any active-slot query.  Every prepared
        # row therefore either owns the canonical certificate slot or was
        # rejected while that slot was still held; a pre-transaction check
        # would admit two contenders through a TOCTOU window.
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._assert_no_legacy_active_transactions()
            active_ranges = self._active_operation_ranges(database_identity)
            for op in plan.operations:
                op_start, op_end = op.range.start_ea, op.range.end_ea
                for active_start, active_end in active_ranges:
                    if op_start < active_end and active_start < op_end:
                        raise NativePatchTransactionConflictError(
                            op.operation_id, op_start, op_end
                        )

            active_metadata_scopes = self._active_metadata_scopes(database_identity)
            for operation in plan.operations:
                for scope_kind, scope_ea in self._metadata_scopes_for_operation(
                    operation
                ):
                    if any(
                        self._metadata_scopes_overlap(
                            (scope_kind, scope_ea), active_scope
                        )
                        for active_scope in active_metadata_scopes
                    ):
                        raise NativePatchMetadataScopeConflictError(
                            operation.operation_id, scope_kind, scope_ea
                        )

            if function_ea in self._active_function_certificate_slots(
                database_identity
            ):
                raise NativePatchFunctionScopeConflictError(
                    plan.operations[0].operation_id, function_ea
                )
            self._conn.execute(
                """
                INSERT INTO native_patch_transactions
                    (transaction_id, plan_id, plan_hash, attempt_session,
                     attempt_sequence, state, has_metadata_actions, idb_uuid,
                     function_entry_ea,
                     created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    transaction_id.value,
                    plan.plan_id,
                    plan.plan_hash,
                    plan.authorizing_attempt_id.session.value,
                    plan.authorizing_attempt_id.sequence,
                    NativeJournalState.PREPARED.value,
                    int(has_metadata_actions),
                    database_identity,
                    function_ea,
                    now,
                    now,
                ),
            )
            try:
                self._conn.execute(
                    """
                    INSERT INTO native_patch_certificate_slots
                        (idb_uuid, function_entry_ea, transaction_id)
                    VALUES (?, ?, ?)
                    """,
                    (database_identity, function_ea, transaction_id.value),
                )
            except sqlite3.IntegrityError as error:
                raise NativePatchFunctionScopeConflictError(
                    plan.operations[0].operation_id, function_ea
                ) from error
            for op in plan.operations:
                self._conn.execute(
                    """
                    INSERT INTO native_patch_operations
                        (transaction_id, operation_id, start_ea, end_ea)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        transaction_id.value,
                        op.operation_id,
                        op.range.start_ea,
                        op.range.end_ea,
                    ),
                )
                ownership = op.restore_snapshot.function_ownership
                for action_index, (scope_kind, scope_ea) in enumerate(
                    self._metadata_scopes_for_operation(op)
                ):
                    self._conn.execute(
                        """
                        INSERT INTO native_patch_metadata_scopes
                            (transaction_id, operation_id, action_index,
                             scope_kind, scope_ea)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            transaction_id.value,
                            op.operation_id,
                            action_index,
                            scope_kind,
                            scope_ea,
                        ),
                    )
                for chunk_index, chunk in enumerate(ownership.chunk_ranges):
                    self._conn.execute(
                        """
                        INSERT INTO native_patch_operation_ownership
                            (transaction_id, operation_id, chunk_index,
                             owning_function_entry_ea, chunk_start_ea,
                             chunk_end_ea)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            transaction_id.value,
                            op.operation_id,
                            chunk_index,
                            ownership.owning_function_entry_ea,
                            chunk.start_ea,
                            chunk.end_ea,
                        ),
                    )
                for ref_index, ref in enumerate(ownership.flow_refs):
                    self._conn.execute(
                        """
                        INSERT INTO native_patch_operation_flow_refs
                            (transaction_id, operation_id, ref_index,
                             source_ea, target_ea, xref_type, is_user)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            transaction_id.value,
                            op.operation_id,
                            ref_index,
                            ref.source_ea,
                            ref.target_ea,
                            ref.xref_type,
                            int(ref.user),
                        ),
                    )
                type_info = ownership.type_info
                self._conn.execute(
                    """
                    INSERT INTO native_patch_operation_function_metadata
                        (transaction_id, operation_id,
                         owning_function_entry_ea, function_flags,
                         has_type_info, type_bytes, field_bytes,
                         field_comment_bytes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        transaction_id.value,
                        op.operation_id,
                        ownership.owning_function_entry_ea,
                        ownership.function_flags,
                        int(type_info is not None),
                        type_info.type_bytes if type_info is not None else None,
                        type_info.field_bytes if type_info is not None else None,
                        (
                            type_info.field_comment_bytes
                            if type_info is not None
                            else None
                        ),
                    ),
                )
                for offset, ea in enumerate(range(op.range.start_ea, op.range.end_ea)):
                    self._conn.execute(
                        """
                        INSERT INTO native_patch_operation_bytes
                            (transaction_id, operation_id, ea,
                             expected_current, expected_original, replacement)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            transaction_id.value,
                            op.operation_id,
                            ea,
                            op.expected_current_bytes[offset],
                            op.expected_original_bytes[offset],
                            op.replacement_bytes[offset],
                        ),
                    )
            if plan.analysis_phase_witness is not None:
                phase = parse_analysis_phase_witness(plan.analysis_phase_witness)
                self._conn.execute(
                    """
                    INSERT INTO native_patch_analysis_phases
                        (transaction_id, witness)
                    VALUES (?, ?)
                    """,
                    (transaction_id.value, plan.analysis_phase_witness),
                )
                for step_index, step in enumerate(phase.reverse_schedule):
                    self._conn.execute(
                        """
                        INSERT INTO native_patch_analysis_reverse_steps
                            (transaction_id, step_index, kind, head_ea,
                            action_index, action_kind, ea, before_state,
                            after_state, expected_after, global_before, global_after,
                            cleared_state,
                             status, intent, completion)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL, NULL)
                        """,
                        (
                            transaction_id.value,
                            step_index,
                            step.kind,
                            step.head_ea,
                            step.index,
                            step.action_kind,
                            step.ea,
                            step.before_state,
                            step.after_state,
                            step.expected_after,
                            (
                                None if step.global_before is None
                                else json.dumps(step.global_before.as_payload(), sort_keys=True, separators=(",", ":"))
                            ),
                            (
                                None if step.global_after is None
                                else json.dumps(step.global_after.as_payload(), sort_keys=True, separators=(",", ":"))
                            ),
                            (
                                None if step.cleared_state is None
                                else json.dumps(step.cleared_state.as_payload(), sort_keys=True, separators=(",", ":"))
                            ),
                        ),
                    )
            self._conn.execute(
                """
                INSERT INTO native_patch_transitions
                    (transaction_id, from_state, to_state, note, recorded_at)
                VALUES (?, NULL, ?, ?, ?)
                """,
                (
                    transaction_id.value,
                    NativeJournalState.PREPARED.value,
                    "prepare",
                    now,
                ),
            )
        except Exception:
            self._conn.rollback()
            raise
        else:
            self._conn.commit()

        record = self.get(transaction_id)
        assert record is not None  # just committed; must be readable
        return record

    def _record_from_row(self, row: sqlite3.Row) -> NativePatchTransactionRecord:
        return NativePatchTransactionRecord(
            transaction_id=NativePatchTransactionId(value=row["transaction_id"]),
            plan_id=row["plan_id"],
            plan_hash=row["plan_hash"],
            authorizing_attempt_id=ExecutionAttemptId(
                session=DecompilationSessionId(value=row["attempt_session"]),
                sequence=row["attempt_sequence"],
            ),
            state=NativeJournalState(row["state"]),
            has_metadata_actions=bool(row["has_metadata_actions"]),
            database_identity=(
                str(row["idb_uuid"])
                if row["idb_uuid"] is not None and str(row["idb_uuid"]).strip()
                else None
            ),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def get(
        self, transaction_id: NativePatchTransactionId
    ) -> NativePatchTransactionRecord | None:
        row = self._conn.execute(
            "SELECT * FROM native_patch_transactions WHERE transaction_id = ?",
            (transaction_id.value,),
        ).fetchone()
        if row is None:
            return None
        return self._record_from_row(row)

    def transition(
        self,
        transaction_id: NativePatchTransactionId,
        target_state: NativeJournalState,
        *,
        note: str | None = None,
    ) -> NativePatchTransactionRecord:
        row = self._conn.execute(
            "SELECT state, has_metadata_actions FROM native_patch_transactions "
            "WHERE transaction_id = ?",
            (transaction_id.value,),
        ).fetchone()
        if row is None:
            # No durable PREPARED row exists. `prepare()` is the only legal
            # way to create one.
            raise IllegalNativeJournalTransition(
                None, target_state, detail="no durable record for this transaction"
            )

        current = NativeJournalState(row["state"])
        if not is_legal_native_journal_transition(current, target_state):
            raise IllegalNativeJournalTransition(current, target_state)

        has_metadata_actions = bool(row["has_metadata_actions"])
        if (
            target_state is NativeJournalState.METADATA_APPLIED
            and not has_metadata_actions
        ):
            raise IllegalNativeJournalTransition(
                current,
                target_state,
                detail="plan owns no metadata actions",
            )
        if (
            current is NativeJournalState.BYTES_APPLIED
            and target_state is NativeJournalState.ANALYSIS_PENDING
            and has_metadata_actions
        ):
            raise IllegalNativeJournalTransition(
                current,
                target_state,
                detail="plan owns metadata actions; must pass through METADATA_APPLIED",
            )

        now = time.time()
        with self._conn:
            self._conn.execute(
                "UPDATE native_patch_transactions SET state = ?, updated_at = ? "
                "WHERE transaction_id = ?",
                (target_state.value, now, transaction_id.value),
            )
            self._conn.execute(
                """
                INSERT INTO native_patch_transitions
                    (transaction_id, from_state, to_state, note, recorded_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (transaction_id.value, current.value, target_state.value, note, now),
            )
            if target_state is NativeJournalState.RESTORED:
                self._conn.execute(
                    "DELETE FROM native_patch_certificate_slots WHERE transaction_id = ?",
                    (transaction_id.value,),
                )

        record = self.get(transaction_id)
        assert record is not None
        return record

    # -- byte-granular write-ahead log ------------------------------------------

    def record_byte_event(
        self,
        transaction_id: NativePatchTransactionId,
        operation_id: str,
        ea: int,
        phase: NativeByteEventPhase,
        *,
        expected_current: int,
        expected_original: int,
        replacement: int,
    ) -> None:
        row = self._conn.execute(
            """
            SELECT expected_current, expected_original, replacement
            FROM native_patch_operation_bytes
            WHERE transaction_id = ? AND operation_id = ? AND ea = ?
            """,
            (transaction_id.value, operation_id, ea),
        ).fetchone()
        if row is None:
            raise ValueError(
                f"ea 0x{ea:x} is not governed by operation {operation_id!r} "
                f"in transaction {transaction_id.value}"
            )
        planned = (
            row["expected_current"],
            row["expected_original"],
            row["replacement"],
        )
        given = (expected_current, expected_original, replacement)
        if planned != given:
            raise ValueError(
                f"byte event for ea 0x{ea:x} does not match the durably planned "
                f"expected-before/original/after values {planned}, got {given}"
            )

        with self._conn:
            self._conn.execute(
                """
                INSERT INTO native_patch_byte_events
                    (transaction_id, operation_id, ea, phase,
                     expected_current, expected_original, replacement, recorded_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    transaction_id.value,
                    operation_id,
                    ea,
                    phase.value,
                    expected_current,
                    expected_original,
                    replacement,
                    time.time(),
                ),
            )

    # -- netnode mirror receipts (separate lane; never a state authority) ------

    def record_mirror_receipt(
        self,
        transaction_id: NativePatchTransactionId,
        outcome: NativeMirrorOutcome,
        *,
        reason: str | None = None,
    ) -> NativeMirrorReceipt:
        row = self._conn.execute(
            "SELECT state FROM native_patch_transactions WHERE transaction_id = ?",
            (transaction_id.value,),
        ).fetchone()
        if row is None:
            raise ValueError(f"unknown transaction {transaction_id.value}")
        at_state = NativeJournalState(row["state"])
        now = time.time()

        with self._conn:
            self._conn.execute(
                """
                INSERT INTO native_patch_mirror_receipts
                    (transaction_id, outcome, at_state, reason, recorded_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (transaction_id.value, outcome.value, at_state.value, reason, now),
            )
        # Deliberately no write to native_patch_transactions here: a mirror
        # receipt -- written or failed -- never touches transaction state.
        return NativeMirrorReceipt(
            transaction_id=transaction_id,
            outcome=outcome,
            at_state=at_state,
            reason=reason,
            recorded_at=now,
        )

    def mirror_receipts(
        self, transaction_id: NativePatchTransactionId
    ) -> tuple[NativeMirrorReceipt, ...]:
        rows = self._conn.execute(
            """
            SELECT outcome, at_state, reason, recorded_at
            FROM native_patch_mirror_receipts
            WHERE transaction_id = ?
            ORDER BY seq
            """,
            (transaction_id.value,),
        ).fetchall()
        return tuple(
            NativeMirrorReceipt(
                transaction_id=transaction_id,
                outcome=NativeMirrorOutcome(row["outcome"]),
                at_state=NativeJournalState(row["at_state"]),
                reason=row["reason"],
                recorded_at=row["recorded_at"],
            )
            for row in rows
        )

    def record_metadata_action(
        self,
        transaction_id: NativePatchTransactionId,
        *,
        operation_id: str,
        kind: str,
        ea: int,
        recorded_before: str,
        expected_after: str,
    ) -> None:
        """Record one applied metadata action and the state it replaced."""
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO native_patch_metadata_actions
                    (transaction_id, operation_id, kind, ea,
                     recorded_before, expected_after)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    transaction_id.value,
                    operation_id,
                    kind,
                    int(ea),
                    recorded_before,
                    expected_after,
                ),
            )

    def metadata_actions(
        self, transaction_id: NativePatchTransactionId
    ) -> tuple[AppliedMetadataAction, ...]:
        """Applied metadata actions in application order.

        Reversal walks this backwards. Ordering is by insertion, never by
        address: actions can depend on each other (an item must exist before a
        cref to it does), and address order would undo them out of sequence.
        """
        rows = self._conn.execute(
            """
            SELECT operation_id, kind, ea, recorded_before, expected_after
            FROM native_patch_metadata_actions
            WHERE transaction_id = ?
            ORDER BY seq
            """,
            (transaction_id.value,),
        ).fetchall()
        return tuple(
            AppliedMetadataAction(
                operation_id=row["operation_id"],
                kind=row["kind"],
                ea=int(row["ea"]),
                recorded_before=row["recorded_before"],
                expected_after=row["expected_after"],
            )
            for row in rows
        )

    def analysis_phase_witness(
        self, transaction_id: NativePatchTransactionId
    ) -> str | None:
        row = self._conn.execute(
            """
            SELECT witness FROM native_patch_analysis_phases
            WHERE transaction_id = ?
            """,
            (transaction_id.value,),
        ).fetchone()
        return None if row is None else str(row["witness"])

    def analysis_phase_attestation(
        self, transaction_id: NativePatchTransactionId
    ) -> str | None:
        row = self._conn.execute(
            """
            SELECT attestation FROM native_patch_analysis_attestations
            WHERE transaction_id = ?
            """,
            (transaction_id.value,),
        ).fetchone()
        return None if row is None else str(row["attestation"])

    def record_certificate_link(
        self,
        transaction_id: NativePatchTransactionId,
        certificate_id: str,
        plan_hash: str,
        database_key: str,
        function_key: str,
    ) -> None:
        values = (certificate_id, plan_hash, database_key, function_key)
        if any(not isinstance(value, str) or not value for value in values):
            raise ValueError("certificate link fields must be non-empty strings")
        with self._conn:
            existing = self._conn.execute(
                "SELECT certificate_id, plan_hash, database_key, function_key "
                "FROM native_patch_certificate_links WHERE transaction_id = ?",
                (transaction_id.value,),
            ).fetchone()
            if existing is not None and tuple(existing) != values:
                raise ValueError("certificate link is immutable")
            self._conn.execute(
                """
                INSERT OR IGNORE INTO native_patch_certificate_links
                    (transaction_id, certificate_id, plan_hash, database_key, function_key)
                VALUES (?, ?, ?, ?, ?)
                """,
                (transaction_id.value, *values),
            )

    def certificate_link(
        self, transaction_id: NativePatchTransactionId
    ) -> dict[str, str] | None:
        row = self._conn.execute(
            "SELECT certificate_id, plan_hash, database_key, function_key "
            "FROM native_patch_certificate_links WHERE transaction_id = ?",
            (transaction_id.value,),
        ).fetchone()
        return None if row is None else {key: str(row[key]) for key in row.keys()}

    def install_analysis_phase_attestation(
        self, transaction_id: NativePatchTransactionId, attestation: str
    ) -> None:
        """Atomically install attestation and its observed reverse states."""
        # Lock before all transaction/authorization/cursor reads.  The
        # installer and reverse cursor are independent SQLite handles, so an
        # implicit transaction here would leave a race before the first write.
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            parsed = parse_analysis_phase_attestation(attestation)
            transaction = self._conn.execute(
                "SELECT transaction_id FROM native_patch_transactions WHERE transaction_id = ?",
                (transaction_id.value,),
            ).fetchone()
            if transaction is None:
                raise ValueError("analysis attestation transaction does not exist")
            authorized = self.analysis_phase_witness(transaction_id)
            if authorized is None:
                raise ValueError("analysis attestation transaction is not phase-bearing")
            if parsed.transaction_id != transaction_id.value:
                raise ValueError("analysis attestation transaction id mismatch")
            if parsed.phase_witness.token != authorized:
                raise ValueError("analysis attestation is unrelated to transaction authorization")
            # parse_analysis_phase_attestation already materializes and
            # validates the observed-P schedule. Consume that exact authority;
            # do not derive a second schedule in the journal layer.
            schedule = parsed.reverse_schedule
            rows = self.analysis_reverse_steps(transaction_id)
            if len(rows) != len(schedule) or not rows:
                raise ValueError("analysis reverse schedule is incomplete")
            if self.analysis_phase_attestation(transaction_id) is not None:
                raise ValueError("analysis phase attestation is already installed")
            for index, (row, step) in enumerate(zip(rows, schedule)):
                if row["status"] != "pending":
                    raise ValueError("analysis reverse schedule is already in progress")
                for column, expected in (
                    ("kind", step.kind),
                    ("head_ea", step.head_ea),
                    ("action_index", step.index),
                    ("action_kind", step.action_kind),
                    ("ea", step.ea),
                    ("before_state", step.before_state),
                    ("after_state", step.after_state),
                    ("expected_after", step.expected_after),
                ):
                    if row[column] != expected:
                        raise ValueError(
                            f"analysis reverse identity mismatch at step {index}: {column}"
                        )
            cursor = self._conn.execute(
                """
                INSERT INTO native_patch_analysis_attestations
                    (transaction_id, attestation)
                VALUES (?, ?)
                """,
                (transaction_id.value, attestation),
            )
            if cursor.rowcount != 1:
                raise ValueError("analysis attestation insert affected unexpected rows")
            for index, step in enumerate(schedule):
                cursor = self._conn.execute(
                    """
                    UPDATE native_patch_analysis_reverse_steps
                    SET before_state = ?, after_state = ?,
                        global_before = ?, global_after = ?, cleared_state = ?
                    WHERE transaction_id = ? AND step_index = ?
                      AND status = 'pending'
                      AND kind IS ? AND head_ea IS ? AND action_index IS ?
                      AND action_kind IS ? AND ea IS ? AND expected_after IS ?
                    """,
                    (
                        step.before_state,
                        step.after_state,
                        None if step.global_before is None else json.dumps(
                            step.global_before.as_payload(), sort_keys=True,
                            separators=(",", ":"),
                        ),
                        None if step.global_after is None else json.dumps(
                            step.global_after.as_payload(), sort_keys=True,
                            separators=(",", ":"),
                        ),
                        None if step.cleared_state is None else json.dumps(
                            step.cleared_state.as_payload(), sort_keys=True,
                            separators=(",", ":"),
                        ),
                        transaction_id.value,
                        index,
                        step.kind,
                        step.head_ea,
                        step.index,
                        step.action_kind,
                        step.ea,
                        step.expected_after,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ValueError(
                        f"analysis reverse state update affected unexpected rows at {index}"
                    )
            self._conn.commit()
        except BaseException:
            self._conn.rollback()
            raise

    def analysis_reverse_steps(
        self, transaction_id: NativePatchTransactionId
    ) -> tuple[dict[str, object], ...]:
        """Return the immutable global reverse schedule and its cursor state."""
        rows = self._conn.execute(
            """
            SELECT step_index, kind, head_ea, action_index, action_kind, ea,
                   before_state, after_state, expected_after, global_before,
                   global_after, cleared_state, status, intent,
                   completion
            FROM native_patch_analysis_reverse_steps
            WHERE transaction_id = ?
            ORDER BY step_index
            """,
            (transaction_id.value,),
        ).fetchall()
        return tuple(dict(row) for row in rows)

    def record_analysis_reverse_intent(
        self,
        transaction_id: NativePatchTransactionId,
        step_index: int,
        intent: str,
    ) -> None:
        """Durably record a reverse-step pre-mutation intent."""
        if not isinstance(step_index, int) or isinstance(step_index, bool) or step_index < 0:
            raise ValueError("step_index must be a non-negative integer")
        if not isinstance(intent, str) or not intent:
            raise ValueError("reverse-step intent must be a non-empty string")
        row = self._conn.execute(
            """
            SELECT status, intent FROM native_patch_analysis_reverse_steps
            WHERE transaction_id = ? AND step_index = ?
            """,
            (transaction_id.value, step_index),
        ).fetchone()
        if row is None:
            raise ValueError("unknown analysis reverse step")
        if row["status"] == "complete":
            if row["intent"] != intent:
                raise ValueError("completed reverse step intent mismatch")
            return
        if row["status"] == "intent" and row["intent"] != intent:
            raise ValueError("reverse step already has a different intent")
        cursor = self._conn.execute(
            """
            SELECT step_index, status FROM native_patch_analysis_reverse_steps
            WHERE transaction_id = ? ORDER BY step_index
            """,
            (transaction_id.value,),
        ).fetchall()
        statuses = [str(item["status"]) for item in cursor]
        if any(status not in {"pending", "intent", "complete"} for status in statuses):
            raise ValueError("malformed reverse cursor")
        completed = [index for index, status in enumerate(statuses) if status == "complete"]
        intents = [index for index, status in enumerate(statuses) if status == "intent"]
        if completed != list(range(len(completed))):
            raise ValueError("reverse cursor completed prefix is not contiguous")
        if intents and (len(intents) != 1 or intents[0] != len(completed)):
            raise ValueError("reverse cursor has more than one or misplaced intent")
        if int(step_index) != len(completed):
            raise ValueError("reverse cursor intent is not the next pending step")
        if any(status != "pending" for status in statuses[int(step_index) + 1 :]):
            raise ValueError("reverse cursor has a non-pending suffix")
        with self._conn:
            self._conn.execute(
                """
                UPDATE native_patch_analysis_reverse_steps
                SET status = 'intent', intent = ?
                WHERE transaction_id = ? AND step_index = ?
                """,
                (intent, transaction_id.value, step_index),
            )

    def record_analysis_reverse_completion(
        self,
        transaction_id: NativePatchTransactionId,
        step_index: int,
        completion: str,
    ) -> None:
        """Durably record the exact post-mutation reverse-step witness."""
        if not isinstance(completion, str) or not completion:
            raise ValueError("reverse-step completion must be a non-empty string")
        row = self._conn.execute(
            """
            SELECT status, completion FROM native_patch_analysis_reverse_steps
            WHERE transaction_id = ? AND step_index = ?
            """,
            (transaction_id.value, step_index),
        ).fetchone()
        if row is None or row["status"] not in {"intent", "complete"}:
            raise ValueError("reverse step completion without durable intent")
        if row["status"] == "complete":
            if row["completion"] != completion:
                raise ValueError("completed reverse step witness mismatch")
            return
        with self._conn:
            self._conn.execute(
                """
                UPDATE native_patch_analysis_reverse_steps
                SET status = 'complete', completion = ?
                WHERE transaction_id = ? AND step_index = ?
                """,
                (completion, transaction_id.value, step_index),
            )

    def operation_ownership(
        self, transaction_id: NativePatchTransactionId
    ) -> dict[str, tuple[int, tuple[tuple[int, int], ...]]]:
        """Pre-patch function extent per operation.

        Returns ``{operation_id: (owning_function_entry_ea, ((start, end),
        ...))}``. Read from the journal rather than the live database on
        purpose: by restore time the database has already been reanalyzed and
        its ownership reflects the *patched* shape, which is precisely the
        state a restore must undo.
        """
        rows = self._conn.execute(
            """
            SELECT operation_id, owning_function_entry_ea,
                   chunk_start_ea, chunk_end_ea
            FROM native_patch_operation_ownership
            WHERE transaction_id = ?
            ORDER BY operation_id, chunk_index
            """,
            (transaction_id.value,),
        ).fetchall()
        result: dict[str, tuple[int, tuple[tuple[int, int], ...]]] = {}
        for row in rows:
            operation_id = row["operation_id"]
            entry_ea, chunks = result.get(
                operation_id, (int(row["owning_function_entry_ea"]), ())
            )
            result[operation_id] = (
                entry_ea,
                chunks + ((int(row["chunk_start_ea"]), int(row["chunk_end_ea"])),),
            )
        return result

    def operation_flow_refs(
        self, transaction_id: NativePatchTransactionId
    ) -> dict[str, tuple[tuple[int, int, int, bool], ...]]:
        """Exact pre-patch internal code refs per operation."""
        rows = self._conn.execute(
            """
            SELECT operation_id, source_ea, target_ea, xref_type, is_user
            FROM native_patch_operation_flow_refs
            WHERE transaction_id = ?
            ORDER BY operation_id, ref_index
            """,
            (transaction_id.value,),
        ).fetchall()
        result: dict[str, tuple[tuple[int, int, int, bool], ...]] = {}
        for row in rows:
            operation_id = str(row["operation_id"])
            result[operation_id] = result.get(operation_id, ()) + (
                (
                    int(row["source_ea"]),
                    int(row["target_ea"]),
                    int(row["xref_type"]),
                    bool(row["is_user"]),
                ),
            )
        return result

    def operation_function_metadata(
        self, transaction_id: NativePatchTransactionId
    ) -> dict[str, tuple[int, tuple[bytes, bytes | None, bytes | None] | None]]:
        """Exact inherited flags and SDK-serialized tinfo per operation."""
        rows = self._conn.execute(
            """
            SELECT operation_id, function_flags, has_type_info, type_bytes,
                   field_bytes, field_comment_bytes
            FROM native_patch_operation_function_metadata
            WHERE transaction_id = ?
            ORDER BY operation_id
            """,
            (transaction_id.value,),
        ).fetchall()
        result: dict[
            str, tuple[int, tuple[bytes, bytes | None, bytes | None] | None]
        ] = {}
        for row in rows:
            serialized = None
            if bool(row["has_type_info"]):
                type_bytes = row["type_bytes"]
                if type_bytes is None:
                    continue
                serialized = (
                    bytes(type_bytes),
                    bytes(row["field_bytes"])
                    if row["field_bytes"] is not None
                    else None,
                    bytes(row["field_comment_bytes"])
                    if row["field_comment_bytes"] is not None
                    else None,
                )
            result[str(row["operation_id"])] = (
                int(row["function_flags"]),
                serialized,
            )
        return result

    # -- read back the durably-planned bytes (Task 6 restore; see
    # OperationByteRecord's docstring for why this -- not the in-memory plan
    # -- is what the gateway restores from) --------------------------------

    def operation_bytes(
        self, transaction_id: NativePatchTransactionId
    ) -> tuple[OperationByteRecord, ...]:
        rows = self._conn.execute(
            """
            SELECT operation_id, ea, expected_current, expected_original, replacement
            FROM native_patch_operation_bytes
            WHERE transaction_id = ?
            ORDER BY operation_id, ea
            """,
            (transaction_id.value,),
        ).fetchall()
        return tuple(
            OperationByteRecord(
                operation_id=row["operation_id"],
                ea=row["ea"],
                expected_current=row["expected_current"],
                expected_original=row["expected_original"],
                replacement=row["replacement"],
            )
            for row in rows
        )

    # -- byte-granular recovery classification ----------------------------------

    def classify_recovery(
        self,
        transaction_id: NativePatchTransactionId,
        read_current_bytes: NativeCurrentByteReader,
    ) -> NativeTransactionRecoveryReport:
        record = self.get(transaction_id)
        if record is None:
            raise ValueError(f"unknown transaction {transaction_id.value}")

        operation_ids = [
            row["operation_id"]
            for row in self._conn.execute(
                """
                SELECT DISTINCT operation_id FROM native_patch_operations
                WHERE transaction_id = ?
                ORDER BY operation_id
                """,
                (transaction_id.value,),
            ).fetchall()
        ]

        applied_receipt_eas = {
            row["ea"]
            for row in self._conn.execute(
                """
                SELECT ea FROM native_patch_byte_events
                WHERE transaction_id = ? AND phase = ?
                """,
                (transaction_id.value, NativeByteEventPhase.WRITE_APPLIED.value),
            ).fetchall()
        }

        operation_reports = []
        for operation_id in operation_ids:
            byte_rows = self._conn.execute(
                """
                SELECT ea, expected_current, replacement
                FROM native_patch_operation_bytes
                WHERE transaction_id = ? AND operation_id = ?
                ORDER BY ea
                """,
                (transaction_id.value, operation_id),
            ).fetchall()

            entries = []
            for byte_row in byte_rows:
                ea = byte_row["ea"]
                expected_current = byte_row["expected_current"]
                replacement = byte_row["replacement"]
                current = read_current_bytes(ea)
                if current is None:
                    verdict = NativeByteRecoveryVerdict.NEITHER
                elif current == expected_current and current == replacement:
                    verdict = NativeByteRecoveryVerdict.BOTH
                elif current == expected_current:
                    verdict = NativeByteRecoveryVerdict.BEFORE
                elif current == replacement:
                    verdict = NativeByteRecoveryVerdict.AFTER
                else:
                    verdict = NativeByteRecoveryVerdict.NEITHER
                entries.append(
                    NativeByteRecoveryEntry(
                        ea=ea, verdict=verdict, current_value=current
                    )
                )

            verdict_set = {entry.verdict for entry in entries}
            if NativeByteRecoveryVerdict.NEITHER in verdict_set:
                op_verdict = NativeOperationRecoveryVerdict.INTERFERENCE
            elif verdict_set <= {
                NativeByteRecoveryVerdict.BEFORE,
                NativeByteRecoveryVerdict.BOTH,
            }:
                op_verdict = NativeOperationRecoveryVerdict.NOT_APPLIED
            elif verdict_set <= {
                NativeByteRecoveryVerdict.AFTER,
                NativeByteRecoveryVerdict.BOTH,
            }:
                op_verdict = NativeOperationRecoveryVerdict.APPLIED
            else:
                op_verdict = NativeOperationRecoveryVerdict.PARTIALLY_APPLIED

            corroborated = op_verdict is NativeOperationRecoveryVerdict.APPLIED and all(
                entry.ea in applied_receipt_eas
                for entry in entries
                if entry.verdict is not NativeByteRecoveryVerdict.BOTH
            )

            operation_reports.append(
                NativeOperationRecoveryReport(
                    operation_id=operation_id,
                    verdict=op_verdict,
                    byte_entries=tuple(entries),
                    corroborated_by_write_applied_receipt=corroborated,
                )
            )

        recommended_state = _recommend_state(record.state, tuple(operation_reports))
        return NativeTransactionRecoveryReport(
            transaction_id=transaction_id,
            recorded_state=record.state,
            operation_reports=tuple(operation_reports),
            recommended_state=recommended_state,
        )
