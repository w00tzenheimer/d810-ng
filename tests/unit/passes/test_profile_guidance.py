"""Deterministic, read-only profile guidance policy."""

from d810.core.execution_journal import (
    DecompilationSessionId,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptStatus,
    ExecutionDomain,
    ExecutionEffectRef,
)
from d810.core.execution_journal_store import ExecutionJournalStore
from d810.core.execution_profile import (
    ExecutionProfileKey,
    build_execution_profile_preview,
)
from d810.passes.profile_guidance import (
    ProfileCandidate,
    ProfileDecisionKind,
    ProfileGuidancePlanner,
    record_profile_guidance_preview,
)


def _key(*, function: str = "function") -> ExecutionProfileKey:
    return ExecutionProfileKey(
        database_identity="database",
        function_fingerprint=function,
        config_fingerprint="config",
        toolchain_fingerprint="toolchain",
        maturity="MMAT_GLBOPT2",
        structural_shape="state-machine:two-way",
    )


def _attempt(
    sequence: int,
    stage_id: str,
    *,
    status: ExecutionAttemptStatus = ExecutionAttemptStatus.COMPLETED,
    elapsed_ms: float = 5.0,
    effective: bool = True,
    maturity: str = "MMAT_GLBOPT2",
    structural_shape: str = "state-machine:two-way",
) -> ExecutionAttempt:
    return ExecutionAttempt(
        attempt_id=ExecutionAttemptId(
            DecompilationSessionId("historical-session"), sequence
        ),
        parent_attempt_id=None,
        stage_id=stage_id,
        domain=ExecutionDomain.PASS,
        status=status,
        reason_code=None,
        effect_refs=(
            (ExecutionEffectRef("rewrite_plan", f"plan-{sequence}"),)
            if effective
            else ()
        ),
        elapsed_ms=elapsed_ms,
        details={
            "maturity": maturity,
            "structural_shape": structural_shape,
        },
    )


def _history():
    return build_execution_profile_preview(
        _key(),
        (
            _attempt(1, "effective", elapsed_ms=4.0),
            _attempt(2, "expensive", elapsed_ms=40.0),
            _attempt(
                3,
                "rejected",
                status=ExecutionAttemptStatus.REJECTED,
                elapsed_ms=2.0,
                effective=False,
            ),
        ),
    )


def test_disabled_guidance_is_baseline_order_equivalent() -> None:
    candidates = (
        ProfileCandidate("b", "expensive", ExecutionDomain.PASS, 40.0),
        ProfileCandidate("a", "effective", ExecutionDomain.PASS, 4.0),
    )

    preview = ProfileGuidancePlanner(enabled=False, budget_ms=1.0).preview(
        key=_key(), candidates=candidates, history=_history()
    )

    assert [decision.candidate.candidate_id for decision in preview.decisions] == [
        "b",
        "a",
    ]
    assert all(
        decision.kind is ProfileDecisionKind.BASELINE for decision in preview.decisions
    )
    assert preview.has_execution_authority is False


def test_profile_budget_ranks_effective_work_and_explores_one_unknown() -> None:
    candidates = (
        ProfileCandidate("rejected", "rejected", ExecutionDomain.PASS, 2.0),
        ProfileCandidate("unknown-a", "unknown-a", ExecutionDomain.SOLVER, 3.0),
        ProfileCandidate("effective", "effective", ExecutionDomain.PASS, 4.0),
        ProfileCandidate("unknown-b", "unknown-b", ExecutionDomain.SOLVER, 3.0),
        ProfileCandidate("expensive", "expensive", ExecutionDomain.PASS, 40.0),
    )

    preview = ProfileGuidancePlanner(
        enabled=True, budget_ms=8.0, exploration_slots=1
    ).preview(key=_key(), candidates=candidates, history=_history())
    kinds = {
        decision.candidate.candidate_id: decision.kind for decision in preview.decisions
    }

    assert kinds == {
        "effective": ProfileDecisionKind.PROFILE_SELECTED,
        "expensive": ProfileDecisionKind.PROFILE_BUDGET_EXHAUSTED,
        "rejected": ProfileDecisionKind.PROFILE_DEPRIORITIZED,
        "unknown-a": ProfileDecisionKind.PROFILE_UNKNOWN_EXPLORE,
        "unknown-b": ProfileDecisionKind.PROFILE_DEPRIORITIZED,
    }
    assert preview.allocated_budget_ms == 7.0


def test_explicit_user_choice_is_authoritative_but_does_not_spend_profile_budget() -> (
    None
):
    explicit = ProfileCandidate(
        "explicit",
        "rejected",
        ExecutionDomain.PASS,
        1000.0,
        explicit_user_selected=True,
    )

    preview = ProfileGuidancePlanner(enabled=True, budget_ms=0.0).preview(
        key=_key(), candidates=(explicit,), history=_history()
    )

    assert preview.decisions[0].kind is ProfileDecisionKind.EXPLICIT_USER
    assert preview.decisions[0].recommended is True
    assert preview.allocated_budget_ms == 0.0


def test_native_candidate_is_preview_only_even_with_history_and_user_policy() -> None:
    native = ProfileCandidate(
        "native",
        "effective",
        ExecutionDomain.NATIVE_NORMALIZATION,
        1.0,
        explicit_user_selected=True,
        native_candidate=True,
    )

    preview = ProfileGuidancePlanner(enabled=True, budget_ms=100.0).preview(
        key=_key(), candidates=(native,), history=_history()
    )

    decision = preview.decisions[0]
    assert decision.kind is ProfileDecisionKind.PREVIEW_ONLY
    assert decision.recommended is False
    assert decision.requires_live_preflight is True
    assert preview.has_execution_authority is False
    assert not any(
        name in dir(preview) for name in ("apply", "authorize", "execute", "schedule")
    )


def test_mismatched_profile_identity_is_rejected_instead_of_reused() -> None:
    planner = ProfileGuidancePlanner(enabled=True, budget_ms=10.0)

    try:
        planner.preview(
            key=_key(function="changed"),
            candidates=(
                ProfileCandidate("candidate", "effective", ExecutionDomain.PASS, 1.0),
            ),
            history=_history(),
        )
    except ValueError as exc:
        assert "identity" in str(exc)
    else:
        raise AssertionError("mismatched profile history was accepted")


def test_history_excludes_other_maturities_and_structural_shapes() -> None:
    # Simulate a legacy row explicitly: it must fail closed instead of being
    # labelled as evidence for the live maturity and shape.
    attempts = (
        _attempt(1, "matching"),
        _attempt(2, "wrong-maturity", maturity="MMAT_CALLS"),
        _attempt(3, "wrong-shape", structural_shape="state-machine:indirect"),
        ExecutionAttempt(
            attempt_id=ExecutionAttemptId(
                DecompilationSessionId("historical-session"), 4
            ),
            parent_attempt_id=None,
            stage_id="legacy-without-dimensions",
            domain=ExecutionDomain.PASS,
            status=ExecutionAttemptStatus.COMPLETED,
            reason_code=None,
            effect_refs=(ExecutionEffectRef("rewrite_plan", "legacy-plan"),),
            elapsed_ms=1.0,
        ),
    )
    history = build_execution_profile_preview(_key(), attempts)

    assert [candidate.stage_id for candidate in history.candidates] == ["matching"]
    assert history.ignored_identity_mismatch_count == 3


def test_guidance_decisions_are_append_only_attempts_not_effect_receipts(
    tmp_path,
) -> None:
    session = DecompilationSessionId("live-session")
    with ExecutionJournalStore(tmp_path / "journal.db") as journal:
        preview = ProfileGuidancePlanner(enabled=True, budget_ms=4.0).preview(
            key=_key(),
            candidates=(
                ProfileCandidate("effective", "effective", ExecutionDomain.PASS, 4.0),
                ProfileCandidate(
                    "native",
                    "effective",
                    ExecutionDomain.NATIVE_NORMALIZATION,
                    1.0,
                    native_candidate=True,
                ),
            ),
            history=_history(),
        )

        record_profile_guidance_preview(journal, session, preview)
        attempts = journal.attempts_for_session(session)

    assert [attempt.domain for attempt in attempts] == [
        ExecutionDomain.PROFILE_GUIDANCE,
        ExecutionDomain.PROFILE_GUIDANCE,
    ]
    assert [attempt.reason_code for attempt in attempts] == [
        "profile_selected",
        "profile_native_preview_only",
    ]
    assert all(not attempt.effect_refs for attempt in attempts)
    assert all(
        attempt.details["has_execution_authority"] is False for attempt in attempts
    )
