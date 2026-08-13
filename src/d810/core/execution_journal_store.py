"""Append-only SQLite storage for :mod:`d810.core.execution_journal` records.

This is the durable half of the generic execution-provenance journal: it
persists :class:`~d810.core.execution_journal.ExecutionAttempt` rows so a
D810 run answers "what did this decompilation session consider, run, abstain
from, or fail, and why?" after the fact, not just while a live process is
running.

Layering
--------

``d810.core`` is the bottom of the layered-architecture import-linter
contract (see ``.importlinter``), so this module imports nothing from
``d810.capabilities``, ``d810.transforms``, ``d810.backends``,
``d810.hexrays``, ``d810.passes``, or ``d810.manager`` -- and never a live
IDA package. SQLite (stdlib) is the only storage dependency, matching the
existing ``d810.passes.store.PreanalysisStore`` / ``d810.core.persistence``
pattern, so this store is fully usable from ``d810.backends`` (and any lower
layer) without ever importing ``d810.passes`` -- see the plan's global
constraint "D810 backends must not import d810.passes to create journal
records; depend on the core correlation protocol instead."

Append-only design
-------------------

Nothing here ever runs ``UPDATE`` or ``DELETE``. An attempt's identity (its
``(session_id, sequence)`` pair, parentage, stage, and domain) is written
exactly once, in :meth:`ExecutionJournalStore.begin_attempt`, to the
``execution_attempt_identities`` table -- whose primary key is
``(session_id, sequence)``, so a duplicate identity is a hard SQLite
``IntegrityError`` that this module turns into a clear
:class:`DuplicateExecutionAttemptError` rather than silently overwriting or
corrupting an existing row (see :class:`~d810.core.execution_journal.
ExecutionAttemptId`'s docstring obligation: "assigned by the session's
monotonic attempt counter", enforced here for the first time). Every status
observed for an attempt -- its initial ``STARTED`` and, later, at most one
terminal status (``ExecutionAttemptStatus.can_transition_to`` only ever
allows leaving ``STARTED`` once) -- is a new row ``INSERT``ed into
``execution_attempt_events``. "Current state" is derived by reading the
latest event for an identity, never by mutating a row in place.

Monotonic per-session sequence allocation
------------------------------------------

:meth:`ExecutionJournalStore.next_sequence` is the monotonic per-session
attempt counter ``ExecutionAttemptId``'s docstring promises but that, before
this module, did not actually exist anywhere. It uses a single atomic
``INSERT ... ON CONFLICT DO UPDATE ... RETURNING`` statement (SQLite >= 3.35)
against a dedicated ``execution_attempt_sequence_counters`` table, so two
threads racing to allocate the next sequence for the same session can never
observe or persist the same value -- see
``test_next_sequence_never_duplicates_under_concurrent_allocation`` and
``test_begin_attempt_rejects_a_duplicate_session_sequence_pair``.
:meth:`ExecutionJournalStore.begin_attempt` is the intended caller-facing
entry point: it allocates the next sequence *and* durably records the
attempt's ``STARTED`` identity+event in one call, so callers never construct
a raw ``ExecutionAttemptId`` with a sequence number they picked themselves.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from d810.core import logging
from d810.core.execution_journal import (
    DecompilationSessionId,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptStatus,
    ExecutionDomain,
    ExecutionEffectRef,
    advance_attempt,
)

logger = logging.getLogger(__name__)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS execution_attempt_identities (
    session_id        TEXT    NOT NULL,
    sequence          INTEGER NOT NULL,
    parent_session_id TEXT,
    parent_sequence   INTEGER,
    stage_id          TEXT    NOT NULL,
    domain            TEXT    NOT NULL,
    created_at        REAL    NOT NULL,
    PRIMARY KEY (session_id, sequence)
);

CREATE TABLE IF NOT EXISTS execution_attempt_events (
    event_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT    NOT NULL,
    sequence      INTEGER NOT NULL,
    status        TEXT    NOT NULL,
    reason_code   TEXT,
    effect_refs_json TEXT NOT NULL,
    created_at    REAL    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_execution_attempt_events_identity
    ON execution_attempt_events(session_id, sequence, event_id);

CREATE TABLE IF NOT EXISTS execution_attempt_sequence_counters (
    session_id    TEXT PRIMARY KEY,
    next_sequence INTEGER NOT NULL
);
"""


class DuplicateExecutionAttemptError(ValueError):
    """Raised when a ``(session_id, sequence)`` identity is recorded twice.

    ``ExecutionAttemptId`` promises this pair is globally unique (see its
    docstring); this is the schema-level enforcement of that promise, so a
    duplicate is a loud, immediate error instead of a silently corrupted or
    overwritten provenance row.
    """

    def __init__(self, attempt_id: ExecutionAttemptId) -> None:
        self.attempt_id = attempt_id
        super().__init__(
            "duplicate execution attempt identity: "
            f"session={attempt_id.session.value} sequence={attempt_id.sequence}"
        )


class UnknownExecutionAttemptError(KeyError):
    """Raised when an operation targets an attempt identity never recorded."""

    def __init__(self, attempt_id: ExecutionAttemptId) -> None:
        self.attempt_id = attempt_id
        super().__init__(
            "unknown execution attempt identity: "
            f"session={attempt_id.session.value} sequence={attempt_id.sequence}"
        )


class AmbiguousExecutionAttemptLookupError(ValueError):
    """Raised when a lookup expecting exactly one attempt finds zero or many."""


def _effect_refs_to_json(effect_refs: tuple[ExecutionEffectRef, ...]) -> str:
    return json.dumps([{"kind": ref.kind, "ref_id": ref.ref_id} for ref in effect_refs])


def _effect_refs_from_json(payload: str) -> tuple[ExecutionEffectRef, ...]:
    return tuple(
        ExecutionEffectRef(kind=str(row["kind"]), ref_id=str(row["ref_id"]))
        for row in json.loads(payload or "[]")
    )


@dataclass(frozen=True, slots=True)
class _IdentityRow:
    """Portable row shape for one recorded attempt identity."""

    session_id: DecompilationSessionId
    sequence: int
    parent_attempt_id: ExecutionAttemptId | None
    stage_id: str
    domain: ExecutionDomain

    @property
    def attempt_id(self) -> ExecutionAttemptId:
        return ExecutionAttemptId(session=self.session_id, sequence=self.sequence)


class ExecutionJournalStore:
    """Append-only SQLite-backed store for :class:`ExecutionAttempt` provenance.

    Usable from any layer at or above ``core`` (including ``d810.backends``)
    without importing ``d810.passes`` -- see the module docstring. Not
    thread-affine: a single instance may be shared by multiple threads, all
    write paths serialize through an internal lock so concurrent, repeated
    :meth:`next_sequence`/:meth:`begin_attempt` calls for the same session
    never allocate or persist the same sequence twice.

    Example:
        >>> store = ExecutionJournalStore("/tmp/execution_journal.db")
        >>> session = DecompilationSessionId.new()
        >>> attempt = store.begin_attempt(
        ...     session, stage_id="mba_simplify", domain=ExecutionDomain.PASS
        ... )
        >>> store.advance(attempt, status=ExecutionAttemptStatus.COMPLETED)
        >>> store.close()
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection = sqlite3.connect(
            str(self.db_path), check_same_thread=False
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Monotonic per-session sequence allocation
    # ------------------------------------------------------------------

    def next_sequence(self, session_id: DecompilationSessionId) -> int:
        """Atomically allocate and return the next sequence for ``session_id``.

        Never returns the same value twice for the same session, including
        under concurrent calls from multiple threads sharing this store
        instance (serialized by an internal lock plus one atomic SQLite
        upsert -- see the module docstring).
        """
        if not isinstance(session_id, DecompilationSessionId):
            raise TypeError("session_id must be a DecompilationSessionId")
        with self._lock:
            sequence = self._allocate_sequence_locked(session_id)
            self._conn.commit()
            return sequence

    # ------------------------------------------------------------------
    # Attempt creation (append-only identity + initial STARTED event)
    # ------------------------------------------------------------------

    def begin_attempt(
        self,
        session_id: DecompilationSessionId,
        *,
        parent_attempt_id: ExecutionAttemptId | None = None,
        stage_id: str,
        domain: ExecutionDomain,
    ) -> ExecutionAttempt:
        """Allocate the next sequence and durably record a ``STARTED`` attempt.

        This is the intended entry point for every caller: it is the
        "monotonic per-session allocation so callers stop passing raw
        integers" the plan requires -- nobody outside this module ever picks
        an ``ExecutionAttemptId.sequence`` value by hand.
        """
        if not isinstance(session_id, DecompilationSessionId):
            raise TypeError("session_id must be a DecompilationSessionId")
        with self._lock:
            sequence = self._allocate_sequence_locked(session_id)
            attempt_id = ExecutionAttemptId(session=session_id, sequence=sequence)
            attempt = ExecutionAttempt(
                attempt_id=attempt_id,
                parent_attempt_id=parent_attempt_id,
                stage_id=stage_id,
                domain=domain,
                status=ExecutionAttemptStatus.STARTED,
                reason_code=None,
                effect_refs=(),
            )
            self._insert_identity_locked(attempt)
            self._insert_event_locked(attempt)
            self._conn.commit()
            return attempt

    def _allocate_sequence_locked(self, session_id: DecompilationSessionId) -> int:
        """``next_sequence``'s body, callable while ``self._lock`` is already held."""
        cursor = self._conn.execute(
            """
            INSERT INTO execution_attempt_sequence_counters
                (session_id, next_sequence)
            VALUES (?, 2)
            ON CONFLICT(session_id) DO UPDATE
                SET next_sequence = next_sequence + 1
            RETURNING next_sequence - 1
            """,
            (session_id.value,),
        )
        return int(cursor.fetchone()[0])

    def record_attempt(self, attempt: ExecutionAttempt) -> None:
        """Append a caller-constructed attempt's identity and current event.

        Low-level counterpart to :meth:`begin_attempt` for callers that
        already hold a fully-formed :class:`ExecutionAttempt` (for example a
        test constructing ``ExecutionAttemptId`` values directly to prove
        the schema rejects a duplicate ``(session_id, sequence)`` pair
        regardless of how the identity was obtained). Raises
        :class:`DuplicateExecutionAttemptError` if this identity was already
        recorded.
        """
        if not isinstance(attempt, ExecutionAttempt):
            raise TypeError("attempt must be an ExecutionAttempt")
        with self._lock:
            self._insert_identity_locked(attempt)
            self._insert_event_locked(attempt)
            self._conn.commit()

    def _insert_identity_locked(self, attempt: ExecutionAttempt) -> None:
        parent = attempt.parent_attempt_id
        try:
            self._conn.execute(
                """
                INSERT INTO execution_attempt_identities
                    (session_id, sequence, parent_session_id, parent_sequence,
                     stage_id, domain, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attempt.attempt_id.session.value,
                    attempt.attempt_id.sequence,
                    None if parent is None else parent.session.value,
                    None if parent is None else parent.sequence,
                    attempt.stage_id,
                    attempt.domain.value,
                    time.time(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            self._conn.rollback()
            logger.warning(
                "execution journal: rejected duplicate attempt identity "
                "session=%s sequence=%d",
                attempt.attempt_id.session.value,
                attempt.attempt_id.sequence,
            )
            raise DuplicateExecutionAttemptError(attempt.attempt_id) from exc

    def _insert_event_locked(self, attempt: ExecutionAttempt) -> None:
        self._conn.execute(
            """
            INSERT INTO execution_attempt_events
                (session_id, sequence, status, reason_code, effect_refs_json,
                 created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                attempt.attempt_id.session.value,
                attempt.attempt_id.sequence,
                attempt.status.value,
                attempt.reason_code,
                _effect_refs_to_json(attempt.effect_refs),
                time.time(),
            ),
        )

    # ------------------------------------------------------------------
    # Status transitions (append-only event log)
    # ------------------------------------------------------------------

    def advance(
        self,
        attempt: ExecutionAttempt,
        *,
        status: ExecutionAttemptStatus,
        reason_code: str | None = None,
        effect_refs: tuple[ExecutionEffectRef, ...] | None = None,
    ) -> ExecutionAttempt:
        """Validate and durably append one attempt status transition.

        Delegates legality of the transition to
        :func:`d810.core.execution_journal.advance_attempt`, so an illegal
        transition (leaving a terminal status, or "transitioning" into
        ``STARTED``) raises :class:`IllegalExecutionAttemptTransition` and
        writes nothing -- this store never persists a state
        ``advance_attempt`` itself would refuse to construct.
        """
        advanced = advance_attempt(
            attempt,
            status=status,
            reason_code=reason_code,
            effect_refs=effect_refs,
        )
        with self._lock:
            row = self._conn.execute(
                """
                SELECT 1 FROM execution_attempt_identities
                WHERE session_id = ? AND sequence = ?
                """,
                (attempt.attempt_id.session.value, attempt.attempt_id.sequence),
            ).fetchone()
            if row is None:
                raise UnknownExecutionAttemptError(attempt.attempt_id)
            self._insert_event_locked(advanced)
            self._conn.commit()
        return advanced

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_attempt(self, attempt_id: ExecutionAttemptId) -> ExecutionAttempt | None:
        """Return the current (latest-event) state of one attempt, or ``None``."""
        identity_row = self._conn.execute(
            """
            SELECT parent_session_id, parent_sequence, stage_id, domain
            FROM execution_attempt_identities
            WHERE session_id = ? AND sequence = ?
            """,
            (attempt_id.session.value, attempt_id.sequence),
        ).fetchone()
        if identity_row is None:
            return None
        event_row = self._conn.execute(
            """
            SELECT status, reason_code, effect_refs_json
            FROM execution_attempt_events
            WHERE session_id = ? AND sequence = ?
            ORDER BY event_id DESC
            LIMIT 1
            """,
            (attempt_id.session.value, attempt_id.sequence),
        ).fetchone()
        parent_attempt_id = None
        if identity_row["parent_session_id"] is not None:
            parent_attempt_id = ExecutionAttemptId(
                session=DecompilationSessionId(identity_row["parent_session_id"]),
                sequence=int(identity_row["parent_sequence"]),
            )
        return ExecutionAttempt(
            attempt_id=attempt_id,
            parent_attempt_id=parent_attempt_id,
            stage_id=str(identity_row["stage_id"]),
            domain=ExecutionDomain(identity_row["domain"]),
            status=ExecutionAttemptStatus(event_row["status"]),
            reason_code=event_row["reason_code"],
            effect_refs=_effect_refs_from_json(event_row["effect_refs_json"]),
        )

    def history(self, attempt_id: ExecutionAttemptId) -> tuple[ExecutionAttempt, ...]:
        """Return every recorded status for ``attempt_id``, oldest first.

        Direct evidence of the append-only design: this is never more than
        two rows (``STARTED`` plus at most one terminal status), and neither
        row is ever mutated once written.
        """
        identity_row = self._conn.execute(
            """
            SELECT parent_session_id, parent_sequence, stage_id, domain
            FROM execution_attempt_identities
            WHERE session_id = ? AND sequence = ?
            """,
            (attempt_id.session.value, attempt_id.sequence),
        ).fetchone()
        if identity_row is None:
            return ()
        parent_attempt_id = None
        if identity_row["parent_session_id"] is not None:
            parent_attempt_id = ExecutionAttemptId(
                session=DecompilationSessionId(identity_row["parent_session_id"]),
                sequence=int(identity_row["parent_sequence"]),
            )
        rows = self._conn.execute(
            """
            SELECT status, reason_code, effect_refs_json
            FROM execution_attempt_events
            WHERE session_id = ? AND sequence = ?
            ORDER BY event_id ASC
            """,
            (attempt_id.session.value, attempt_id.sequence),
        ).fetchall()
        return tuple(
            ExecutionAttempt(
                attempt_id=attempt_id,
                parent_attempt_id=parent_attempt_id,
                stage_id=str(identity_row["stage_id"]),
                domain=ExecutionDomain(identity_row["domain"]),
                status=ExecutionAttemptStatus(row["status"]),
                reason_code=row["reason_code"],
                effect_refs=_effect_refs_from_json(row["effect_refs_json"]),
            )
            for row in rows
        )

    def attempts_for_session(
        self, session_id: DecompilationSessionId
    ) -> tuple[ExecutionAttempt, ...]:
        """Return every attempt recorded for ``session_id``, ordered by sequence."""
        rows = self._conn.execute(
            """
            SELECT sequence FROM execution_attempt_identities
            WHERE session_id = ?
            ORDER BY sequence ASC
            """,
            (session_id.value,),
        ).fetchall()
        attempts = (
            self.get_attempt(
                ExecutionAttemptId(session=session_id, sequence=int(row["sequence"]))
            )
            for row in rows
        )
        return tuple(attempt for attempt in attempts if attempt is not None)

    def attempts_for_stage(
        self, session_id: DecompilationSessionId, *, stage_id: str
    ) -> tuple[ExecutionAttempt, ...]:
        """Return every attempt for ``session_id`` whose ``stage_id`` matches."""
        return tuple(
            attempt
            for attempt in self.attempts_for_session(session_id)
            if attempt.stage_id == stage_id
        )

    def only_attempt(
        self, session_id: DecompilationSessionId, *, stage_id: str
    ) -> ExecutionAttempt:
        """Return the single attempt for ``stage_id``, or raise if not exactly one."""
        matches = self.attempts_for_stage(session_id, stage_id=stage_id)
        if len(matches) != 1:
            raise AmbiguousExecutionAttemptLookupError(
                f"expected exactly one attempt for stage_id={stage_id!r}, "
                f"found {len(matches)}"
            )
        return matches[0]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()

    def __enter__(self) -> "ExecutionJournalStore":
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()


__all__ = [
    "AmbiguousExecutionAttemptLookupError",
    "DuplicateExecutionAttemptError",
    "ExecutionJournalStore",
    "UnknownExecutionAttemptError",
]
