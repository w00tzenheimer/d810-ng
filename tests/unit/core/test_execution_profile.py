"""Read-only profile summaries derived from execution-journal attempts."""

from __future__ import annotations

import pytest

from d810.core.execution_journal import (
    DecompilationSessionId,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptStatus,
    ExecutionDomain,
    ExecutionEffectRef,
)
from d810.core.execution_profile import (
    ExecutionProfileKey,
    build_execution_profile_preview,
)


def _attempt(
    *,
    sequence: int,
    stage_id: str,
    status: ExecutionAttemptStatus,
    elapsed_ms: float,
    effects: tuple[ExecutionEffectRef, ...] = (),
    reason_code: str | None = None,
    details: dict[str, object] | None = None,
    domain: ExecutionDomain = ExecutionDomain.PASS,
) -> ExecutionAttempt:
    session = DecompilationSessionId("profile-session")
    return ExecutionAttempt(
        attempt_id=ExecutionAttemptId(session, sequence),
        parent_attempt_id=None,
        stage_id=stage_id,
        domain=domain,
        status=status,
        reason_code=reason_code,
        effect_refs=effects,
        elapsed_ms=elapsed_ms,
        details={
            "maturity": "MMAT_GLBOPT2",
            "structural_shape": "state-machine:two-way",
            **({} if details is None else details),
        },
    )


def _key() -> ExecutionProfileKey:
    return ExecutionProfileKey(
        database_identity="database-attestation",
        function_fingerprint="function-fingerprint",
        config_fingerprint="config-fingerprint",
        toolchain_fingerprint="d810+hexrays-fingerprint",
        maturity="MMAT_GLBOPT2",
        structural_shape="state-machine:two-way",
    )


def test_profile_preview_ranks_terminal_effective_work_without_replaying_it() -> None:
    preview = build_execution_profile_preview(
        _key(),
        (
            _attempt(
                sequence=1,
                stage_id="slow-no-effect",
                status=ExecutionAttemptStatus.COMPLETED,
                elapsed_ms=20.0,
            ),
            _attempt(
                sequence=2,
                stage_id="fast-effective",
                status=ExecutionAttemptStatus.COMPLETED,
                elapsed_ms=2.0,
                effects=(ExecutionEffectRef("rewrite_plan", "plan-1"),),
            ),
            _attempt(
                sequence=3,
                stage_id="fast-effective",
                status=ExecutionAttemptStatus.ABSTAINED,
                elapsed_ms=1.0,
            ),
            _attempt(
                sequence=4,
                stage_id="failed-stage",
                status=ExecutionAttemptStatus.FAILED,
                elapsed_ms=1.0,
            ),
            _attempt(
                sequence=5,
                stage_id="in-progress",
                status=ExecutionAttemptStatus.STARTED,
                elapsed_ms=0.0,
            ),
        ),
    )

    assert [candidate.stage_id for candidate in preview.candidates] == [
        "fast-effective",
        "slow-no-effect",
        "failed-stage",
    ]
    fast = preview.candidates[0]
    assert fast.attempt_count == 2
    assert fast.proven_effect_count == 1
    assert fast.abstained_count == 1
    assert fast.mean_elapsed_ms == pytest.approx(1.5)
    assert fast.attempt_to_effect_rate == pytest.approx(0.5)
    assert preview.ignored_in_progress_count == 1
    assert preview.is_read_only is True


def test_profile_preview_reports_reasons_proof_failures_and_reduction_metrics() -> None:
    preview = build_execution_profile_preview(
        _key(),
        (
            _attempt(
                sequence=1,
                stage_id="stage",
                status=ExecutionAttemptStatus.COMPLETED,
                elapsed_ms=2.0,
                details={"reduction_before": 10, "reduction_after": 4},
            ),
            _attempt(
                sequence=2,
                stage_id="stage",
                status=ExecutionAttemptStatus.REJECTED,
                elapsed_ms=1.0,
                reason_code="proof_precondition_failed",
            ),
            _attempt(
                sequence=3,
                stage_id="profile_guidance:stage",
                status=ExecutionAttemptStatus.COMPLETED,
                elapsed_ms=0.1,
                reason_code="profile_selected",
                domain=ExecutionDomain.PROFILE_GUIDANCE,
            ),
        ),
    )

    assert len(preview.candidates) == 1
    candidate = preview.candidates[0]
    assert candidate.reason_counts == (("proof_precondition_failed", 1),)
    assert candidate.proof_failure_count == 1
    assert candidate.mean_reduction == pytest.approx(6.0)


def test_profile_preview_rejects_an_unattested_key_and_exposes_no_write_api() -> None:
    with pytest.raises(ValueError, match="database_identity"):
        ExecutionProfileKey(
            database_identity="",
            function_fingerprint="function",
            config_fingerprint="config",
            toolchain_fingerprint="tools",
            maturity="MMAT_GLBOPT2",
            structural_shape="shape",
        )

    preview = build_execution_profile_preview(_key(), ())
    assert not any(
        name in dir(preview)
        for name in (
            "apply",
            "authorize",
            "execute",
            "schedule",
            "create_native_request",
        )
    )
