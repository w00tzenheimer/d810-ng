"""Append-only persistence tests for :mod:`d810.core.execution_journal_store`.

Covers the two obligations Task 1 left unfinished on
:class:`~d810.core.execution_journal.ExecutionAttemptId`: schema-level
uniqueness of ``(session_id, sequence)`` and monotonic per-session sequence
allocation (see ``ExecutionAttemptId``'s docstring, "assigned by the
session's monotonic attempt counter"). No IDA imports; SQLite only.
"""

from __future__ import annotations

import sqlite3
import tempfile
import threading
from pathlib import Path

import pytest

from d810.core.execution_journal import (
    DecompilationSessionId,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptStatus,
    ExecutionDomain,
    ExecutionEffectRef,
    IllegalExecutionAttemptTransition,
)
from d810.core.execution_journal_store import (
    AmbiguousExecutionAttemptLookupError,
    DuplicateExecutionAttemptError,
    ExecutionJournalStore,
    TerminalExecutionAttempt,
    UnknownExecutionAttemptError,
)
from d810.core.native_preanalysis_key import NativePreanalysisKey


def _tmp_db_path() -> Path:
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    return Path(tmp.name)


@pytest.fixture
def store():
    journal_store = ExecutionJournalStore(_tmp_db_path())
    try:
        yield journal_store
    finally:
        journal_store.close()


def _native_key(*, function_fingerprint: str = "a" * 64) -> NativePreanalysisKey:
    return NativePreanalysisKey(
        input_identity="b" * 64,
        processor="metapc",
        bitness=64,
        function_rva=0x1000,
        function_fingerprint=function_fingerprint,
        profile_fingerprint="c" * 64,
        sdk_fingerprint="ida-9.4+d810-test",
    )


def test_summary_mode_collapses_repeated_callback_abstentions(tmp_path: Path) -> None:
    session = DecompilationSessionId.new()
    with ExecutionJournalStore(
        tmp_path / "execution.sqlite", callback_detail="summary"
    ) as journal:
        parent = journal.begin_attempt(
            session,
            stage_id="hexrays_preanalysis",
            domain=ExecutionDomain.PASS,
        )
        for _ in range(1_000):
            journal.summarize_callback_abstention(
                session,
                parent_attempt_id=parent.attempt_id,
                callback_kind="optinsn",
                stage_id="instruction_optimizer",
                maturity="GLBOPT1",
                reason_code="no_instruction_change",
            )

        assert [a.stage_id for a in journal.attempts_for_session(session)] == [
            "hexrays_preanalysis"
        ]

        summary = journal.flush_callback_summaries(
            session, parent_attempt_id=parent.attempt_id
        )

        assert summary is not None
        assert summary.stage_id == "callback_summary"
        assert summary.status is ExecutionAttemptStatus.COMPLETED
        assert summary.details["total_abstentions"] == 1_000
        assert summary.details["groups"] == (
            {
                "callback_kind": "optinsn",
                "count": 1_000,
                "maturity": "GLBOPT1",
                "reason_code": "no_instruction_change",
                "stage_id": "instruction_optimizer",
            },
        )
        assert (
            journal.flush_callback_summaries(
                session, parent_attempt_id=parent.attempt_id
            )
            is None
        )


def test_full_mode_does_not_accept_summary_only_abstentions(tmp_path: Path) -> None:
    session = DecompilationSessionId.new()
    with ExecutionJournalStore(
        tmp_path / "execution.sqlite", callback_detail="full"
    ) as journal:
        assert journal.callback_detail_is_full is True
        with pytest.raises(RuntimeError, match="full callback detail"):
            journal.summarize_callback_abstention(
                session,
                parent_attempt_id=None,
                callback_kind="optinsn",
                stage_id="instruction_optimizer",
                maturity="GLBOPT1",
                reason_code="no_instruction_change",
            )


def test_callback_detail_can_be_reconfigured_between_sessions(tmp_path: Path) -> None:
    with ExecutionJournalStore(tmp_path / "execution.sqlite") as journal:
        journal.configure_callback_detail("full")
        assert journal.callback_detail_is_full is True

        journal.configure_callback_detail("summary")
        assert journal.callback_detail_is_full is False


def test_callback_detail_reconfiguration_refuses_to_drop_pending_summary(
    tmp_path: Path,
) -> None:
    session = DecompilationSessionId.new()
    with ExecutionJournalStore(tmp_path / "execution.sqlite") as journal:
        journal.summarize_callback_abstention(
            session,
            parent_attempt_id=None,
            callback_kind="optinsn",
            stage_id="instruction_optimizer",
            maturity="GLBOPT1",
            reason_code="no_instruction_change",
        )

        with pytest.raises(RuntimeError, match="pending callback summaries"):
            journal.configure_callback_detail("full")

        assert journal.callback_detail_is_full is False


def test_terminal_attempt_batch_persists_callback_and_mutation_atomically(
    tmp_path: Path,
) -> None:
    session = DecompilationSessionId.new()
    with ExecutionJournalStore(tmp_path / "execution.sqlite") as journal:
        parent = journal.begin_attempt(
            session,
            stage_id="hexrays_preanalysis",
            domain=ExecutionDomain.PASS,
        )

        callback, mutation = journal.record_terminal_attempts(
            session,
            parent_attempt_id=parent.attempt_id,
            records=(
                TerminalExecutionAttempt(
                    stage_id="optinsn_callback:maturity=4:insn=0x401000",
                    domain=ExecutionDomain.HOOK,
                    status=ExecutionAttemptStatus.COMPLETED,
                    details={"instruction_ea": 0x401000},
                ),
                TerminalExecutionAttempt(
                    stage_id="mba_mutation:optinsn:maturity=4:insn=0x401000",
                    domain=ExecutionDomain.MUTATION,
                    status=ExecutionAttemptStatus.COMPLETED,
                    parent_record_index=0,
                    effect_refs=(
                        ExecutionEffectRef(
                            kind="mba_instruction_edit",
                            ref_id="maturity=4:insn=0x401000",
                        ),
                    ),
                ),
            ),
        )

        assert callback.parent_attempt_id == parent.attempt_id
        assert mutation.parent_attempt_id == callback.attempt_id
        assert callback.status is ExecutionAttemptStatus.COMPLETED
        assert mutation.status is ExecutionAttemptStatus.COMPLETED
        assert [
            attempt.stage_id for attempt in journal.attempts_for_session(session)
        ] == [
            "hexrays_preanalysis",
            "optinsn_callback:maturity=4:insn=0x401000",
            "mba_mutation:optinsn:maturity=4:insn=0x401000",
        ]


def test_terminal_attempt_batch_rolls_back_every_record_on_late_validation_failure(
    tmp_path: Path,
) -> None:
    session = DecompilationSessionId.new()
    with ExecutionJournalStore(tmp_path / "execution.sqlite") as journal:
        parent = journal.begin_attempt(
            session,
            stage_id="hexrays_preanalysis",
            domain=ExecutionDomain.PASS,
        )

        with pytest.raises(ValueError, match="earlier record"):
            journal.record_terminal_attempts(
                session,
                parent_attempt_id=parent.attempt_id,
                records=(
                    TerminalExecutionAttempt(
                        stage_id="callback",
                        domain=ExecutionDomain.HOOK,
                        status=ExecutionAttemptStatus.COMPLETED,
                    ),
                    TerminalExecutionAttempt(
                        stage_id="invalid-child",
                        domain=ExecutionDomain.MUTATION,
                        status=ExecutionAttemptStatus.COMPLETED,
                        parent_record_index=1,
                    ),
                ),
            )

        assert journal.attempts_for_session(session) == (parent,)
        next_attempt = journal.begin_attempt(
            session,
            stage_id="after-rollback",
            domain=ExecutionDomain.PASS,
        )
        assert next_attempt.attempt_id.sequence == 2


# ---------------------------------------------------------------------------
# Durable function/session binding
# ---------------------------------------------------------------------------


def test_latest_session_for_function_survives_reopen_and_ignores_other_functions(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "execution.sqlite"
    first = DecompilationSessionId.new()
    other = DecompilationSessionId.new()
    latest = DecompilationSessionId.new()

    with ExecutionJournalStore(db_path) as journal:
        journal.bind_session(first, function_ea=0x401000)
        journal.bind_session(other, function_ea=0x402000)
        journal.bind_session(latest, function_ea=0x401000)
        assert journal.latest_session_for_function(0x401000) == latest

    with ExecutionJournalStore(db_path) as reopened:
        assert reopened.latest_session_for_function(0x401000) == latest
        assert reopened.latest_session_for_function(0x402000) == other
        assert reopened.latest_session_for_function(0x403000) is None


def test_profile_attempt_query_requires_an_exact_attested_native_key(store) -> None:
    exact_session = DecompilationSessionId.new()
    foreign_session = DecompilationSessionId.new()
    legacy_session = DecompilationSessionId.new()
    exact_key = _native_key()
    foreign_key = _native_key(function_fingerprint="d" * 64)
    store.bind_session(exact_session, function_ea=0x401000, native_key=exact_key)
    store.bind_session(foreign_session, function_ea=0x401000, native_key=foreign_key)
    store.bind_session(legacy_session, function_ea=0x401000)
    exact = store.begin_attempt(
        exact_session, stage_id="exact", domain=ExecutionDomain.PASS
    )
    store.advance(exact, status=ExecutionAttemptStatus.COMPLETED)
    foreign = store.begin_attempt(
        foreign_session, stage_id="foreign", domain=ExecutionDomain.PASS
    )
    store.advance(foreign, status=ExecutionAttemptStatus.COMPLETED)
    legacy = store.begin_attempt(
        legacy_session, stage_id="legacy", domain=ExecutionDomain.PASS
    )
    store.advance(legacy, status=ExecutionAttemptStatus.COMPLETED)

    attempts = store.attempts_for_native_key(exact_key)

    assert [attempt.stage_id for attempt in attempts] == ["exact"]
    assert store.latest_native_key_for_function(0x401000) == foreign_key


def test_function_attempt_query_follows_all_durable_session_bindings(store) -> None:
    first = DecompilationSessionId.new()
    other = DecompilationSessionId.new()
    latest = DecompilationSessionId.new()
    store.bind_session(first, function_ea=0x401000, native_key=_native_key())
    store.bind_session(other, function_ea=0x402000, native_key=_native_key())
    store.bind_session(latest, function_ea=0x401000)
    for session, stage_id in (
        (first, "first"),
        (other, "other"),
        (latest, "latest"),
    ):
        attempt = store.begin_attempt(
            session,
            stage_id=stage_id,
            domain=ExecutionDomain.PASS,
        )
        store.advance(attempt, status=ExecutionAttemptStatus.COMPLETED)

    attempts = store.attempts_for_function(0x401000)

    assert [attempt.stage_id for attempt in attempts] == ["first", "latest"]


# ---------------------------------------------------------------------------
# Monotonic per-session sequence allocation
# ---------------------------------------------------------------------------


class TestNextSequence:
    def test_first_allocation_in_a_session_is_one(self, store) -> None:
        session = DecompilationSessionId.new()
        assert store.next_sequence(session) == 1

    def test_repeated_allocation_is_monotonic_within_a_session(self, store) -> None:
        session = DecompilationSessionId.new()
        allocated = [store.next_sequence(session) for _ in range(5)]
        assert allocated == [1, 2, 3, 4, 5]

    def test_sessions_allocate_independently(self, store) -> None:
        first_session = DecompilationSessionId.new()
        second_session = DecompilationSessionId.new()
        assert store.next_sequence(first_session) == 1
        assert store.next_sequence(second_session) == 1
        assert store.next_sequence(first_session) == 2

    def test_rejects_a_non_session_argument(self, store) -> None:
        with pytest.raises(TypeError):
            store.next_sequence("not-a-session-id")  # type: ignore[arg-type]

    def test_concurrent_repeated_allocation_never_yields_a_duplicate(
        self, store
    ) -> None:
        """Many threads racing to allocate for one session get disjoint sequences."""
        session = DecompilationSessionId.new()
        thread_count = 32
        allocated: list[int] = []
        lock = threading.Lock()
        barrier = threading.Barrier(thread_count)

        def _allocate() -> None:
            barrier.wait()
            sequence = store.next_sequence(session)
            with lock:
                allocated.append(sequence)

        threads = [threading.Thread(target=_allocate) for _ in range(thread_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(allocated) == thread_count
        assert len(set(allocated)) == thread_count, "a sequence was allocated twice"
        assert sorted(allocated) == list(range(1, thread_count + 1))


# ---------------------------------------------------------------------------
# begin_attempt / record_attempt: identity uniqueness
# ---------------------------------------------------------------------------


class TestBeginAttempt:
    def test_begin_attempt_allocates_and_persists_a_started_attempt(
        self, store
    ) -> None:
        session = DecompilationSessionId.new()

        attempt = store.begin_attempt(
            session, stage_id="mba_simplify", domain=ExecutionDomain.PASS
        )

        assert attempt.attempt_id.session == session
        assert attempt.attempt_id.sequence == 1
        assert attempt.status is ExecutionAttemptStatus.STARTED
        assert attempt.parent_attempt_id is None
        assert attempt.effect_refs == ()
        assert store.get_attempt(attempt.attempt_id) == attempt

    def test_begin_attempt_sequence_is_monotonic_across_calls(self, store) -> None:
        session = DecompilationSessionId.new()

        first = store.begin_attempt(session, stage_id="a", domain=ExecutionDomain.PASS)
        second = store.begin_attempt(session, stage_id="b", domain=ExecutionDomain.PASS)

        assert first.attempt_id.sequence == 1
        assert second.attempt_id.sequence == 2

    def test_begin_attempt_records_a_child_parent_link(self, store) -> None:
        session = DecompilationSessionId.new()
        parent = store.begin_attempt(
            session, stage_id="outer", domain=ExecutionDomain.PASS
        )

        child = store.begin_attempt(
            session,
            parent_attempt_id=parent.attempt_id,
            stage_id="inner",
            domain=ExecutionDomain.HOOK,
        )

        reloaded = store.get_attempt(child.attempt_id)
        assert reloaded is not None
        assert reloaded.parent_attempt_id == parent.attempt_id

    def test_begin_attempt_rejects_a_non_session_argument(self, store) -> None:
        with pytest.raises(TypeError):
            store.begin_attempt(
                "not-a-session-id",  # type: ignore[arg-type]
                stage_id="a",
                domain=ExecutionDomain.PASS,
            )


class TestDuplicateAttemptRejection:
    """The obligation Task 1 handed off: (session, sequence) must be unique."""

    def test_record_attempt_rejects_a_duplicate_session_sequence_pair(
        self, store
    ) -> None:
        session = DecompilationSessionId.new()
        attempt_id = ExecutionAttemptId.new(session=session, sequence=1)
        first = ExecutionAttempt(
            attempt_id=attempt_id,
            parent_attempt_id=None,
            stage_id="first",
            domain=ExecutionDomain.PASS,
            status=ExecutionAttemptStatus.STARTED,
            reason_code=None,
            effect_refs=(),
        )
        # A second, distinct attempt record that happens to reuse the exact
        # same (session, sequence) identity -- the scenario the docstring
        # obligation exists to prevent from silently corrupting provenance.
        second = ExecutionAttempt(
            attempt_id=attempt_id,
            parent_attempt_id=None,
            stage_id="second-different-stage",
            domain=ExecutionDomain.HOOK,
            status=ExecutionAttemptStatus.STARTED,
            reason_code=None,
            effect_refs=(),
        )

        store.record_attempt(first)
        with pytest.raises(DuplicateExecutionAttemptError):
            store.record_attempt(second)

        # The rejected duplicate must not have clobbered the original row.
        reloaded = store.get_attempt(attempt_id)
        assert reloaded is not None
        assert reloaded.stage_id == "first"

    def test_begin_attempt_after_a_raw_duplicate_insert_still_raises(
        self, store
    ) -> None:
        """Even if a caller bypasses the allocator, uniqueness still holds."""
        session = DecompilationSessionId.new()
        manual = ExecutionAttempt(
            attempt_id=ExecutionAttemptId.new(session=session, sequence=1),
            parent_attempt_id=None,
            stage_id="manual",
            domain=ExecutionDomain.PASS,
            status=ExecutionAttemptStatus.STARTED,
            reason_code=None,
            effect_refs=(),
        )
        store.record_attempt(manual)

        # The allocator has never been asked for a sequence in this session,
        # so it would also hand out 1 -- collide with the manual insert.
        duplicate = ExecutionAttempt(
            attempt_id=ExecutionAttemptId.new(session=session, sequence=1),
            parent_attempt_id=None,
            stage_id="collides",
            domain=ExecutionDomain.PASS,
            status=ExecutionAttemptStatus.STARTED,
            reason_code=None,
            effect_refs=(),
        )
        with pytest.raises(DuplicateExecutionAttemptError):
            store.record_attempt(duplicate)


# ---------------------------------------------------------------------------
# advance(): append-only status transitions
# ---------------------------------------------------------------------------


class TestAdvance:
    def test_advance_persists_the_terminal_status(self, store) -> None:
        session = DecompilationSessionId.new()
        attempt = store.begin_attempt(
            session, stage_id="a", domain=ExecutionDomain.PASS
        )

        advanced = store.advance(attempt, status=ExecutionAttemptStatus.COMPLETED)

        assert advanced.status is ExecutionAttemptStatus.COMPLETED
        reloaded = store.get_attempt(attempt.attempt_id)
        assert reloaded == advanced

    def test_advance_persists_a_reason_code_and_effect_refs(self, store) -> None:
        session = DecompilationSessionId.new()
        attempt = store.begin_attempt(
            session, stage_id="a", domain=ExecutionDomain.PASS
        )
        effect_refs = (ExecutionEffectRef(kind="mutation", ref_id="rewrite-1"),)

        store.advance(
            attempt,
            status=ExecutionAttemptStatus.FAILED,
            reason_code="pass_exception:RuntimeError",
            effect_refs=effect_refs,
        )

        reloaded = store.get_attempt(attempt.attempt_id)
        assert reloaded is not None
        assert reloaded.status is ExecutionAttemptStatus.FAILED
        assert reloaded.reason_code == "pass_exception:RuntimeError"
        assert reloaded.effect_refs == effect_refs

    def test_advance_persists_elapsed_time_and_structured_terminal_detail(
        self, store
    ) -> None:
        session = DecompilationSessionId.new()
        attempt = store.begin_attempt(
            session, stage_id="rewrite-dispatcher", domain=ExecutionDomain.MUTATION
        )

        advanced = store.advance(
            attempt,
            status=ExecutionAttemptStatus.COMPLETED,
            details={
                "plan_id": "plan:dispatcher-rewrite",
                "operation_count": 3,
                "receipt": {"status": "committed"},
            },
        )

        assert advanced.elapsed_ms is not None
        assert advanced.elapsed_ms >= 0.0
        assert advanced.details == {
            "plan_id": "plan:dispatcher-rewrite",
            "operation_count": 3,
            "receipt": {"status": "committed"},
        }
        assert store.get_attempt(attempt.attempt_id) == advanced

    def test_advance_rejects_an_illegal_transition_and_writes_nothing(
        self, store
    ) -> None:
        session = DecompilationSessionId.new()
        attempt = store.begin_attempt(
            session, stage_id="a", domain=ExecutionDomain.PASS
        )
        store.advance(attempt, status=ExecutionAttemptStatus.COMPLETED)
        completed = store.get_attempt(attempt.attempt_id)
        assert completed is not None

        with pytest.raises(IllegalExecutionAttemptTransition):
            store.advance(completed, status=ExecutionAttemptStatus.FAILED)

        # Still COMPLETED -- the illegal attempt did not overwrite history.
        unchanged = store.get_attempt(attempt.attempt_id)
        assert unchanged == completed

    def test_advance_of_an_unrecorded_identity_raises(self, store) -> None:
        session = DecompilationSessionId.new()
        never_begun = ExecutionAttempt(
            attempt_id=ExecutionAttemptId.new(session=session, sequence=1),
            parent_attempt_id=None,
            stage_id="ghost",
            domain=ExecutionDomain.PASS,
            status=ExecutionAttemptStatus.STARTED,
            reason_code=None,
            effect_refs=(),
        )

        with pytest.raises(UnknownExecutionAttemptError):
            store.advance(never_begun, status=ExecutionAttemptStatus.COMPLETED)

    def test_history_is_append_only_and_never_more_than_two_rows(self, store) -> None:
        session = DecompilationSessionId.new()
        attempt = store.begin_attempt(
            session, stage_id="a", domain=ExecutionDomain.PASS
        )
        assert [record.status for record in store.history(attempt.attempt_id)] == [
            ExecutionAttemptStatus.STARTED
        ]

        store.advance(attempt, status=ExecutionAttemptStatus.ABSTAINED)

        history = store.history(attempt.attempt_id)
        assert [record.status for record in history] == [
            ExecutionAttemptStatus.STARTED,
            ExecutionAttemptStatus.ABSTAINED,
        ]


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


class TestQueries:
    def test_get_attempt_returns_none_for_an_unrecorded_identity(self, store) -> None:
        session = DecompilationSessionId.new()
        unknown = ExecutionAttemptId.new(session=session, sequence=1)
        assert store.get_attempt(unknown) is None

    def test_attempts_for_session_is_ordered_by_sequence(self, store) -> None:
        session = DecompilationSessionId.new()
        other_session = DecompilationSessionId.new()
        first = store.begin_attempt(session, stage_id="a", domain=ExecutionDomain.PASS)
        second = store.begin_attempt(session, stage_id="b", domain=ExecutionDomain.PASS)
        store.begin_attempt(other_session, stage_id="c", domain=ExecutionDomain.PASS)

        attempts = store.attempts_for_session(session)

        assert [a.attempt_id for a in attempts] == [
            first.attempt_id,
            second.attempt_id,
        ]

    def test_only_attempt_finds_the_unique_match(self, store) -> None:
        session = DecompilationSessionId.new()
        store.begin_attempt(session, stage_id="no_effect", domain=ExecutionDomain.PASS)

        attempt = store.only_attempt(session, stage_id="no_effect")

        assert attempt.stage_id == "no_effect"

    def test_only_attempt_raises_when_no_match(self, store) -> None:
        session = DecompilationSessionId.new()
        with pytest.raises(AmbiguousExecutionAttemptLookupError):
            store.only_attempt(session, stage_id="missing")

    def test_only_attempt_raises_when_multiple_match(self, store) -> None:
        session = DecompilationSessionId.new()
        store.begin_attempt(session, stage_id="dup", domain=ExecutionDomain.PASS)
        store.begin_attempt(session, stage_id="dup", domain=ExecutionDomain.PASS)

        with pytest.raises(AmbiguousExecutionAttemptLookupError):
            store.only_attempt(session, stage_id="dup")


# ---------------------------------------------------------------------------
# Durability
# ---------------------------------------------------------------------------


def test_attempts_survive_a_store_close_and_reopen() -> None:
    db_path = _tmp_db_path()
    session = DecompilationSessionId.new()

    store = ExecutionJournalStore(db_path)
    try:
        attempt = store.begin_attempt(
            session, stage_id="durable", domain=ExecutionDomain.PASS
        )
        store.advance(attempt, status=ExecutionAttemptStatus.COMPLETED)
    finally:
        store.close()

    reopened = ExecutionJournalStore(db_path)
    try:
        reloaded = reopened.get_attempt(attempt.attempt_id)
        assert reloaded is not None
        assert reloaded.status is ExecutionAttemptStatus.COMPLETED
        # The counter survives too: the next allocation continues from 2.
        assert reopened.next_sequence(session) == 2
    finally:
        reopened.close()


def test_opening_a_pre_detail_journal_adds_the_new_event_columns() -> None:
    db_path = _tmp_db_path()
    connection = sqlite3.connect(db_path)
    try:
        connection.executescript(
            """
            CREATE TABLE execution_attempt_identities (
                session_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                parent_session_id TEXT,
                parent_sequence INTEGER,
                stage_id TEXT NOT NULL,
                domain TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (session_id, sequence)
            );
            CREATE TABLE execution_attempt_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                status TEXT NOT NULL,
                reason_code TEXT,
                effect_refs_json TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE TABLE execution_attempt_sequence_counters (
                session_id TEXT PRIMARY KEY,
                next_sequence INTEGER NOT NULL
            );
            """
        )
        connection.commit()
    finally:
        connection.close()

    store = ExecutionJournalStore(db_path)
    try:
        attempt = store.begin_attempt(
            DecompilationSessionId.new(),
            stage_id="migrated",
            domain=ExecutionDomain.PASS,
        )
        completed = store.advance(
            attempt,
            status=ExecutionAttemptStatus.COMPLETED,
            details={"operation_count": 1},
        )

        assert completed.details == {"operation_count": 1}
        assert completed.elapsed_ms is not None
    finally:
        store.close()
