"""Pure identity, ordering, and contract-negative tests for the execution journal.

This module is the bottom-layer correlation contract: :class:`DecompilationSessionId`,
:class:`ExecutionAttemptId`, :class:`ExecutionAttemptStatus`, :class:`ExecutionEffectRef`,
:class:`ExecutionAttempt`, :class:`ExecutionDomain`, and :class:`NativeTransactionLink`.
Every higher layer must pass these typed records instead of raw UUID strings, so the
constructors are the only place that can enforce the session/ordering/transition/
attribution invariants relied on everywhere else. These tests pin both the happy path
and the rejections that make those invariants load-bearing rather than aspirational.
"""

from __future__ import annotations

import pytest

from d810.core.execution_journal import (
    DecompilationSessionId,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptStatus,
    ExecutionDomain,
    ExecutionEffectRef,
    IllegalExecutionAttemptTransition,
    NativeTransactionLink,
    advance_attempt,
)


def _attempt(
    *,
    session: DecompilationSessionId | None = None,
    sequence: int = 1,
    parent_attempt_id: ExecutionAttemptId | None = None,
    stage_id: str = "mba-simplify",
    domain: ExecutionDomain = ExecutionDomain.PASS,
    status: ExecutionAttemptStatus = ExecutionAttemptStatus.STARTED,
    reason_code: str | None = None,
    effect_refs: tuple[ExecutionEffectRef, ...] = (),
) -> ExecutionAttempt:
    session = session or DecompilationSessionId.new()
    return ExecutionAttempt(
        attempt_id=ExecutionAttemptId.new(session=session, sequence=sequence),
        parent_attempt_id=parent_attempt_id,
        stage_id=stage_id,
        domain=domain,
        status=status,
        reason_code=reason_code,
        effect_refs=effect_refs,
    )


def test_attempts_are_ordered_within_one_session() -> None:
    session = DecompilationSessionId.new()
    first = ExecutionAttemptId.new(session=session, sequence=1)
    second = ExecutionAttemptId.new(session=session, sequence=2)
    assert first.session == second.session == session
    assert first.sequence < second.sequence


class TestDecompilationSessionId:
    def test_new_sessions_are_distinct(self) -> None:
        assert DecompilationSessionId.new() != DecompilationSessionId.new()

    def test_rejects_a_blank_value(self) -> None:
        with pytest.raises(ValueError):
            DecompilationSessionId(value="   ")

    def test_rejects_a_non_string_value(self) -> None:
        with pytest.raises(TypeError):
            DecompilationSessionId(value=123)  # type: ignore[arg-type]

    def test_is_immutable(self) -> None:
        session = DecompilationSessionId.new()
        with pytest.raises((AttributeError, TypeError)):
            session.value = "other"  # type: ignore[misc]


class TestExecutionAttemptId:
    def test_rejects_a_non_positive_sequence(self) -> None:
        session = DecompilationSessionId.new()
        for sequence in (0, -1):
            with pytest.raises(ValueError):
                ExecutionAttemptId.new(session=session, sequence=sequence)

    def test_rejects_a_non_positive_sequence_via_direct_construction(self) -> None:
        session = DecompilationSessionId.new()
        with pytest.raises(ValueError):
            ExecutionAttemptId(session=session, sequence=0)

    def test_rejects_a_bool_sequence(self) -> None:
        """``bool`` is an ``int`` subclass; a stray ``True`` must not slip through."""
        session = DecompilationSessionId.new()
        with pytest.raises(TypeError):
            ExecutionAttemptId(session=session, sequence=True)  # type: ignore[arg-type]

    def test_rejects_a_non_session_session(self) -> None:
        with pytest.raises(TypeError):
            ExecutionAttemptId(session="not-a-session-id", sequence=1)  # type: ignore[arg-type]


class TestExecutionAttempt:
    def test_accepts_a_child_attempt_from_the_same_session(self) -> None:
        session = DecompilationSessionId.new()
        parent = ExecutionAttemptId.new(session=session, sequence=1)
        child = _attempt(session=session, sequence=2, parent_attempt_id=parent)
        assert child.parent_attempt_id == parent

    def test_rejects_a_parent_attempt_from_a_different_session(self) -> None:
        other_session = DecompilationSessionId.new()
        parent_in_other_session = ExecutionAttemptId.new(
            session=other_session, sequence=1
        )
        with pytest.raises(ValueError):
            _attempt(parent_attempt_id=parent_in_other_session)

    def test_rejects_a_non_execution_attempt_id_parent(self) -> None:
        with pytest.raises(TypeError):
            _attempt(parent_attempt_id="not-an-attempt-id")  # type: ignore[arg-type]

    def test_rejects_a_blank_stage_id(self) -> None:
        with pytest.raises(ValueError):
            _attempt(stage_id="")

    def test_rejects_an_untyped_domain(self) -> None:
        with pytest.raises(TypeError):
            _attempt(domain="pass")  # type: ignore[arg-type]

    def test_rejects_an_untyped_status(self) -> None:
        with pytest.raises(TypeError):
            _attempt(status="started")  # type: ignore[arg-type]

    def test_rejects_effect_refs_that_are_not_a_tuple(self) -> None:
        with pytest.raises(TypeError):
            _attempt(effect_refs=[])  # type: ignore[arg-type]

    def test_rejects_an_effect_refs_element_of_the_wrong_type(self) -> None:
        with pytest.raises(TypeError):
            _attempt(effect_refs=("not-a-ref",))  # type: ignore[arg-type]

    def test_is_immutable(self) -> None:
        attempt = _attempt()
        with pytest.raises((AttributeError, TypeError)):
            attempt.status = ExecutionAttemptStatus.COMPLETED  # type: ignore[misc]


class TestExecutionEffectRef:
    def test_rejects_a_blank_kind(self) -> None:
        with pytest.raises(ValueError):
            ExecutionEffectRef(kind="", ref_id="fact-1")

    def test_rejects_a_blank_ref_id(self) -> None:
        with pytest.raises(ValueError):
            ExecutionEffectRef(kind="fact", ref_id="")

    def test_retains_immutable_json_safe_operation_detail(self) -> None:
        detail = {
            "plan_id": "plan:dispatcher-rewrite",
            "operation_count": 3,
            "receipt": {"status": "committed"},
        }

        effect = ExecutionEffectRef(
            kind="mba_mutation_receipt",
            ref_id="receipt:42",
            detail=detail,
        )
        detail["operation_count"] = 999

        assert effect.detail == {
            "plan_id": "plan:dispatcher-rewrite",
            "operation_count": 3,
            "receipt": {"status": "committed"},
        }
        with pytest.raises(TypeError):
            effect.detail["plan_id"] = "mutated"  # type: ignore[index]


class TestExecutionAttemptStatusTransitions:
    def test_started_can_transition_to_every_terminal_status(self) -> None:
        for target in ExecutionAttemptStatus:
            if target is ExecutionAttemptStatus.STARTED:
                continue
            assert ExecutionAttemptStatus.STARTED.can_transition_to(target)

    def test_started_cannot_transition_to_itself(self) -> None:
        assert not ExecutionAttemptStatus.STARTED.can_transition_to(
            ExecutionAttemptStatus.STARTED
        )

    @pytest.mark.parametrize(
        "terminal",
        [
            ExecutionAttemptStatus.ABSTAINED,
            ExecutionAttemptStatus.COMPLETED,
            ExecutionAttemptStatus.FAILED,
            ExecutionAttemptStatus.REJECTED,
            ExecutionAttemptStatus.POISONED_RESTART_REQUIRED,
        ],
    )
    def test_a_terminal_status_can_never_transition_again(
        self, terminal: ExecutionAttemptStatus
    ) -> None:
        for target in ExecutionAttemptStatus:
            assert not terminal.can_transition_to(target)

    def test_advance_attempt_moves_started_to_completed(self) -> None:
        attempt = _attempt(status=ExecutionAttemptStatus.STARTED)

        advanced = advance_attempt(attempt, status=ExecutionAttemptStatus.COMPLETED)

        assert advanced.status is ExecutionAttemptStatus.COMPLETED
        # The original record is untouched -- advancing builds a new one.
        assert attempt.status is ExecutionAttemptStatus.STARTED

    def test_advance_attempt_rejects_an_invalid_status_transition(self) -> None:
        completed = _attempt(status=ExecutionAttemptStatus.COMPLETED)

        with pytest.raises(IllegalExecutionAttemptTransition):
            advance_attempt(completed, status=ExecutionAttemptStatus.FAILED)

    def test_advance_attempt_rejects_re_entering_started(self) -> None:
        attempt = _attempt(status=ExecutionAttemptStatus.STARTED)

        with pytest.raises(IllegalExecutionAttemptTransition):
            advance_attempt(attempt, status=ExecutionAttemptStatus.STARTED)


class TestNativeTransactionLink:
    def test_links_an_attempt_to_a_transaction(self) -> None:
        attempt_id = ExecutionAttemptId.new(
            session=DecompilationSessionId.new(), sequence=1
        )
        link = NativeTransactionLink(attempt_id=attempt_id, transaction_id="tx-1")
        assert link.attempt_id == attempt_id
        assert link.transaction_id == "tx-1"

    def test_rejects_a_missing_attempt_id(self) -> None:
        with pytest.raises(TypeError):
            NativeTransactionLink(attempt_id=None, transaction_id="tx-1")  # type: ignore[arg-type]

    def test_rejects_a_blank_transaction_id(self) -> None:
        attempt_id = ExecutionAttemptId.new(
            session=DecompilationSessionId.new(), sequence=1
        )
        with pytest.raises(ValueError):
            NativeTransactionLink(attempt_id=attempt_id, transaction_id="")
