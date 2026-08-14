"""Read-only, deterministic summaries of execution-journal history.

This module is intentionally a *consumer* of immutable execution attempts.
It neither imports a pass scheduler, a mutation backend, nor any native-patch
policy.  A profile preview can tell a caller which optional work historically
looked useful for an identity-compatible function shape; it cannot select,
authorize, replay, or apply that work.  Every live pass still needs its own
current-function evidence, proof, policy, preflight, and post-observation
validation.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from statistics import fmean

from d810.core.execution_journal import (
    ExecutionAttempt,
    ExecutionAttemptStatus,
    ExecutionDomain,
)


def _require_non_blank(value: object, label: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if not value.strip():
        raise ValueError(f"{label} must not be blank")


@dataclass(frozen=True, slots=True)
class ExecutionProfileKey:
    """The identity boundary for reusable, *advisory* execution history.

    A raw function EA is deliberately absent.  The supplied database identity
    is the attested D810/IDA database identity; function/config/toolchain and
    structural fingerprints prevent one environment's history from being
    presented as evidence for an unrelated live decompilation.
    """

    database_identity: str
    function_fingerprint: str
    config_fingerprint: str
    toolchain_fingerprint: str
    maturity: str
    structural_shape: str

    def __post_init__(self) -> None:
        for label in (
            "database_identity",
            "function_fingerprint",
            "config_fingerprint",
            "toolchain_fingerprint",
            "maturity",
            "structural_shape",
        ):
            _require_non_blank(getattr(self, label), label)

    def to_dict(self) -> dict[str, str]:
        """Return the exact JSON-safe identity used by guidance receipts."""
        return {
            "database_identity": self.database_identity,
            "function_fingerprint": self.function_fingerprint,
            "config_fingerprint": self.config_fingerprint,
            "toolchain_fingerprint": self.toolchain_fingerprint,
            "maturity": self.maturity,
            "structural_shape": self.structural_shape,
        }


@dataclass(frozen=True, slots=True)
class ExecutionProfileCandidate:
    """One explainable, historical candidate rank.

    ``priority_score`` is descriptive: callers can show it in a preview or
    feed it into an explicit, bounded planning policy later.  It is not a
    proof score and cannot be passed to any mutation API from this module.
    """

    stage_id: str
    domain: ExecutionDomain
    attempt_count: int
    proven_effect_count: int
    completed_without_effect_count: int
    abstained_count: int
    rejected_count: int
    failed_count: int
    poisoned_count: int
    mean_elapsed_ms: float | None
    p95_elapsed_ms: float | None
    attempt_to_effect_rate: float
    reason_counts: tuple[tuple[str, int], ...]
    proof_failure_count: int
    mean_reduction: float | None
    priority_score: float


@dataclass(frozen=True, slots=True)
class ExecutionProfilePreview:
    """A display/planning preview built from terminal journal attempts only."""

    key: ExecutionProfileKey
    candidates: tuple[ExecutionProfileCandidate, ...]
    ignored_in_progress_count: int
    ignored_identity_mismatch_count: int = 0
    #: Deliberate machine-readable guard against treating this object as
    #: authorization or replay authority.
    is_read_only: bool = True


def _p95(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    # Nearest-rank percentile, deterministic and dependency-free.
    index = max(0, ((95 * len(ordered) + 99) // 100) - 1)
    return ordered[index]


def _candidate(
    stage_id: str,
    domain: ExecutionDomain,
    attempts: list[ExecutionAttempt],
) -> ExecutionProfileCandidate:
    proven_effect_count = sum(
        attempt.status is ExecutionAttemptStatus.COMPLETED and bool(attempt.effect_refs)
        for attempt in attempts
    )
    completed_without_effect_count = sum(
        attempt.status is ExecutionAttemptStatus.COMPLETED and not attempt.effect_refs
        for attempt in attempts
    )
    abstained_count = sum(
        attempt.status is ExecutionAttemptStatus.ABSTAINED for attempt in attempts
    )
    rejected_count = sum(
        attempt.status is ExecutionAttemptStatus.REJECTED for attempt in attempts
    )
    failed_count = sum(
        attempt.status is ExecutionAttemptStatus.FAILED for attempt in attempts
    )
    poisoned_count = sum(
        attempt.status is ExecutionAttemptStatus.POISONED_RESTART_REQUIRED
        for attempt in attempts
    )
    elapsed = [
        float(attempt.elapsed_ms)
        for attempt in attempts
        if attempt.elapsed_ms is not None
    ]
    reason_counter: dict[str, int] = defaultdict(int)
    reductions: list[float] = []
    proof_failure_count = 0
    for attempt in attempts:
        if attempt.reason_code:
            reason_counter[attempt.reason_code] += 1
            normalized_reason = attempt.reason_code.lower()
            if attempt.status in {
                ExecutionAttemptStatus.REJECTED,
                ExecutionAttemptStatus.FAILED,
                ExecutionAttemptStatus.POISONED_RESTART_REQUIRED,
            } and any(
                marker in normalized_reason
                for marker in ("proof", "preflight", "post_observation")
            ):
                proof_failure_count += 1
        before = attempt.details.get("reduction_before")
        after = attempt.details.get("reduction_after")
        if (
            not isinstance(before, bool)
            and isinstance(before, (int, float))
            and not isinstance(after, bool)
            and isinstance(after, (int, float))
        ):
            reductions.append(float(before) - float(after))
    # This ranking has deliberately simple, inspectable semantics. A proven
    # effect is stronger than a no-effect completion; safety-negative outcomes
    # lower a candidate's priority; elapsed values remain explicit rather than
    # becoming a hidden optimization policy.
    priority_score = (
        4 * proven_effect_count
        + completed_without_effect_count
        - abstained_count
        - 3 * (rejected_count + failed_count + poisoned_count)
    ) / len(attempts)
    return ExecutionProfileCandidate(
        stage_id=stage_id,
        domain=domain,
        attempt_count=len(attempts),
        proven_effect_count=proven_effect_count,
        completed_without_effect_count=completed_without_effect_count,
        abstained_count=abstained_count,
        rejected_count=rejected_count,
        failed_count=failed_count,
        poisoned_count=poisoned_count,
        mean_elapsed_ms=None if not elapsed else fmean(elapsed),
        p95_elapsed_ms=_p95(elapsed),
        attempt_to_effect_rate=proven_effect_count / len(attempts),
        reason_counts=tuple(sorted(reason_counter.items())),
        proof_failure_count=proof_failure_count,
        mean_reduction=None if not reductions else fmean(reductions),
        priority_score=priority_score,
    )


def build_execution_profile_preview(
    key: ExecutionProfileKey,
    attempts: tuple[ExecutionAttempt, ...] | list[ExecutionAttempt],
) -> ExecutionProfilePreview:
    """Summarize terminal attempts into an immutable, read-only preview.

    In-progress rows are deliberately ignored: they have no final outcome and
    may still be compensated or poisoned.  The caller supplies an already
    identity-scoped history; this pure function never reads a DB and cannot
    issue a pass request, alter a scheduler budget, or contact native APIs.
    """
    if not isinstance(key, ExecutionProfileKey):
        raise TypeError("key must be an ExecutionProfileKey")
    grouped: dict[tuple[str, ExecutionDomain], list[ExecutionAttempt]] = defaultdict(
        list
    )
    ignored_in_progress_count = 0
    ignored_identity_mismatch_count = 0
    for attempt in attempts:
        if not isinstance(attempt, ExecutionAttempt):
            raise TypeError("attempts must contain only ExecutionAttempt values")
        if not attempt.status.is_terminal:
            ignored_in_progress_count += 1
            continue
        if attempt.domain is ExecutionDomain.PROFILE_GUIDANCE:
            continue
        if (
            attempt.details.get("maturity") != key.maturity
            or attempt.details.get("structural_shape") != key.structural_shape
        ):
            ignored_identity_mismatch_count += 1
            continue
        grouped[(attempt.stage_id, attempt.domain)].append(attempt)
    candidates = tuple(
        sorted(
            (
                _candidate(stage_id, domain, grouped_attempts)
                for (stage_id, domain), grouped_attempts in grouped.items()
            ),
            key=lambda candidate: (
                -candidate.priority_score,
                -candidate.proven_effect_count,
                candidate.mean_elapsed_ms is None,
                candidate.mean_elapsed_ms
                if candidate.mean_elapsed_ms is not None
                else float("inf"),
                candidate.stage_id,
                candidate.domain.value,
            ),
        )
    )
    return ExecutionProfilePreview(
        key=key,
        candidates=candidates,
        ignored_in_progress_count=ignored_in_progress_count,
        ignored_identity_mismatch_count=ignored_identity_mismatch_count,
    )


__all__ = [
    "ExecutionProfileCandidate",
    "ExecutionProfileKey",
    "ExecutionProfilePreview",
    "build_execution_profile_preview",
]
