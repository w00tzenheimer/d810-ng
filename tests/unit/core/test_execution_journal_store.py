"""Append-only persistence tests for :mod:`d810.core.execution_journal_store`.

Covers the two obligations Task 1 left unfinished on
:class:`~d810.core.execution_journal.ExecutionAttemptId`: schema-level
uniqueness of ``(session_id, sequence)`` and monotonic per-session sequence
allocation (see ``ExecutionAttemptId``'s docstring, "assigned by the
session's monotonic attempt counter"). No IDA imports; SQLite only.
"""

from __future__ import annotations

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
    UnknownExecutionAttemptError,
)


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
