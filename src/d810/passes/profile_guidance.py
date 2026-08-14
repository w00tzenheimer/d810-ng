"""Deterministic read-only policy previews derived from execution history.

The planner in this module never receives a pass object, patch plan, mutation
backend, or native gateway.  It ranks caller-supplied identifiers and records
why an optional candidate looks worth *considering*.  A recommendation is not
an execution request.  Native candidates are always ``PREVIEW_ONLY`` even when
the user has independently enabled native normalization; that separate policy
still has to cross issuer, live-proof, preflight, transaction, and certificate
boundaries without help from a profile record.
"""

from __future__ import annotations

import enum
import math
from dataclasses import dataclass

from d810.core.execution_journal import (
    DecompilationSessionId,
    ExecutionAttemptId,
    ExecutionAttemptStatus,
    ExecutionDomain,
)
from d810.core.execution_journal_store import ExecutionJournalStore
from d810.core.execution_profile import (
    ExecutionProfileCandidate,
    ExecutionProfileKey,
    ExecutionProfilePreview,
)


class ProfileDecisionKind(str, enum.Enum):
    """Inspectible reason for one profile-policy preview decision."""

    BASELINE = "baseline"
    EXPLICIT_USER = "explicit_user"
    PROFILE_SELECTED = "profile_selected"
    PROFILE_DEPRIORITIZED = "profile_deprioritized"
    PROFILE_BUDGET_EXHAUSTED = "profile_budget_exhausted"
    PROFILE_UNKNOWN_EXPLORE = "profile_unknown_explore"
    PREVIEW_ONLY = "profile_native_preview_only"


@dataclass(frozen=True, slots=True)
class ProfileCandidate:
    """One optional stage identifier the caller wants ranked for display."""

    candidate_id: str
    stage_id: str
    domain: ExecutionDomain
    estimated_cost_ms: float
    explicit_user_selected: bool = False
    native_candidate: bool = False

    def __post_init__(self) -> None:
        for label in ("candidate_id", "stage_id"):
            value = getattr(self, label)
            if not isinstance(value, str):
                raise TypeError(f"{label} must be a string")
            if not value.strip():
                raise ValueError(f"{label} must not be blank")
        if not isinstance(self.domain, ExecutionDomain):
            raise TypeError("domain must be an ExecutionDomain")
        if isinstance(self.estimated_cost_ms, bool) or not isinstance(
            self.estimated_cost_ms, (int, float)
        ):
            raise TypeError("estimated_cost_ms must be a number")
        cost = float(self.estimated_cost_ms)
        if not math.isfinite(cost) or cost < 0.0:
            raise ValueError("estimated_cost_ms must be finite and non-negative")
        object.__setattr__(self, "estimated_cost_ms", cost)
        if (
            self.native_candidate
            and self.domain is not ExecutionDomain.NATIVE_NORMALIZATION
        ):
            raise ValueError(
                "native candidates must use the native-normalization domain"
            )


@dataclass(frozen=True, slots=True)
class ProfileGuidanceDecision:
    candidate: ProfileCandidate
    kind: ProfileDecisionKind
    recommended: bool
    allocated_budget_ms: float
    historical: ExecutionProfileCandidate | None
    requires_live_preflight: bool


@dataclass(frozen=True, slots=True)
class ProfileGuidancePreview:
    key: ExecutionProfileKey
    decisions: tuple[ProfileGuidanceDecision, ...]
    budget_ms: float
    allocated_budget_ms: float
    profile_enabled: bool
    has_execution_authority: bool = False


class ProfileGuidancePlanner:
    """Rank and budget optional identifiers without scheduling any work."""

    def __init__(
        self,
        *,
        enabled: bool,
        budget_ms: float,
        exploration_slots: int = 1,
    ) -> None:
        if not isinstance(enabled, bool):
            raise TypeError("enabled must be a bool")
        if isinstance(budget_ms, bool) or not isinstance(budget_ms, (int, float)):
            raise TypeError("budget_ms must be a number")
        budget = float(budget_ms)
        if not math.isfinite(budget) or budget < 0.0:
            raise ValueError("budget_ms must be finite and non-negative")
        if isinstance(exploration_slots, bool) or not isinstance(
            exploration_slots, int
        ):
            raise TypeError("exploration_slots must be an integer")
        if exploration_slots < 0:
            raise ValueError("exploration_slots must not be negative")
        self._enabled = enabled
        self._budget_ms = budget
        self._exploration_slots = exploration_slots

    def preview(
        self,
        *,
        key: ExecutionProfileKey,
        candidates: tuple[ProfileCandidate, ...],
        history: ExecutionProfilePreview,
    ) -> ProfileGuidancePreview:
        """Return an immutable ranking/budget preview for one exact identity."""
        if not isinstance(key, ExecutionProfileKey):
            raise TypeError("key must be an ExecutionProfileKey")
        if not isinstance(history, ExecutionProfilePreview):
            raise TypeError("history must be an ExecutionProfilePreview")
        if history.key != key:
            raise ValueError("profile history identity does not match the live key")
        if not isinstance(candidates, tuple) or any(
            not isinstance(candidate, ProfileCandidate) for candidate in candidates
        ):
            raise TypeError("candidates must be a tuple of ProfileCandidate values")
        ids = tuple(candidate.candidate_id for candidate in candidates)
        if len(set(ids)) != len(ids):
            raise ValueError("candidate_id values must be unique")

        historical = {
            (candidate.stage_id, candidate.domain): candidate
            for candidate in history.candidates
        }
        if not self._enabled:
            decisions = tuple(
                ProfileGuidanceDecision(
                    candidate=candidate,
                    kind=ProfileDecisionKind.BASELINE,
                    recommended=not candidate.native_candidate,
                    allocated_budget_ms=0.0,
                    historical=historical.get((candidate.stage_id, candidate.domain)),
                    requires_live_preflight=candidate.native_candidate,
                )
                for candidate in candidates
            )
            return ProfileGuidancePreview(
                key=key,
                decisions=decisions,
                budget_ms=self._budget_ms,
                allocated_budget_ms=0.0,
                profile_enabled=False,
            )

        def rank(candidate: ProfileCandidate):
            prior = historical.get((candidate.stage_id, candidate.domain))
            if candidate.explicit_user_selected and not candidate.native_candidate:
                return (0, 0.0, candidate.candidate_id)
            if prior is not None and prior.priority_score > 0.0:
                return (1, -prior.priority_score, candidate.candidate_id)
            if prior is None and not candidate.native_candidate:
                return (2, 0.0, candidate.candidate_id)
            if prior is not None:
                return (3, -prior.priority_score, candidate.candidate_id)
            return (4, 0.0, candidate.candidate_id)

        allocated = 0.0
        explored = 0
        decisions: list[ProfileGuidanceDecision] = []
        for candidate in sorted(candidates, key=rank):
            prior = historical.get((candidate.stage_id, candidate.domain))
            cost = candidate.estimated_cost_ms
            if candidate.native_candidate:
                kind = ProfileDecisionKind.PREVIEW_ONLY
                recommended = False
                granted = 0.0
            elif candidate.explicit_user_selected:
                kind = ProfileDecisionKind.EXPLICIT_USER
                recommended = True
                granted = 0.0
            elif prior is not None and prior.priority_score <= 0.0:
                kind = ProfileDecisionKind.PROFILE_DEPRIORITIZED
                recommended = False
                granted = 0.0
            elif prior is None and explored >= self._exploration_slots:
                kind = ProfileDecisionKind.PROFILE_DEPRIORITIZED
                recommended = False
                granted = 0.0
            elif allocated + cost > self._budget_ms:
                kind = ProfileDecisionKind.PROFILE_BUDGET_EXHAUSTED
                recommended = False
                granted = 0.0
            elif prior is None:
                kind = ProfileDecisionKind.PROFILE_UNKNOWN_EXPLORE
                recommended = True
                granted = cost
                allocated += cost
                explored += 1
            else:
                kind = ProfileDecisionKind.PROFILE_SELECTED
                recommended = True
                granted = cost
                allocated += cost
            decisions.append(
                ProfileGuidanceDecision(
                    candidate=candidate,
                    kind=kind,
                    recommended=recommended,
                    allocated_budget_ms=granted,
                    historical=prior,
                    requires_live_preflight=candidate.native_candidate,
                )
            )
        return ProfileGuidancePreview(
            key=key,
            decisions=tuple(decisions),
            budget_ms=self._budget_ms,
            allocated_budget_ms=allocated,
            profile_enabled=True,
        )


def record_profile_guidance_preview(
    journal: ExecutionJournalStore,
    session_id: DecompilationSessionId,
    preview: ProfileGuidancePreview,
    *,
    parent_attempt_id: ExecutionAttemptId | None = None,
) -> tuple[ExecutionAttemptId, ...]:
    """Append decision receipts; never append plan or mutation effect refs."""
    if not isinstance(journal, ExecutionJournalStore):
        raise TypeError("journal must be an ExecutionJournalStore")
    if not isinstance(session_id, DecompilationSessionId):
        raise TypeError("session_id must be a DecompilationSessionId")
    if not isinstance(preview, ProfileGuidancePreview):
        raise TypeError("preview must be a ProfileGuidancePreview")
    recorded: list[ExecutionAttemptId] = []
    positive = {
        ProfileDecisionKind.BASELINE,
        ProfileDecisionKind.EXPLICIT_USER,
        ProfileDecisionKind.PROFILE_SELECTED,
        ProfileDecisionKind.PROFILE_UNKNOWN_EXPLORE,
    }
    for decision in preview.decisions:
        attempt = journal.begin_attempt(
            session_id,
            parent_attempt_id=parent_attempt_id,
            stage_id=f"profile_guidance:{decision.candidate.candidate_id}",
            domain=ExecutionDomain.PROFILE_GUIDANCE,
        )
        journal.advance(
            attempt,
            status=(
                ExecutionAttemptStatus.COMPLETED
                if decision.kind in positive
                else ExecutionAttemptStatus.ABSTAINED
            ),
            reason_code=decision.kind.value,
            details={
                "profile_key": preview.key.to_dict(),
                "candidate_stage_id": decision.candidate.stage_id,
                "candidate_domain": decision.candidate.domain.value,
                "recommended": decision.recommended,
                "allocated_budget_ms": decision.allocated_budget_ms,
                "requires_live_preflight": decision.requires_live_preflight,
                "has_execution_authority": False,
            },
        )
        recorded.append(attempt.attempt_id)
    return tuple(recorded)


__all__ = [
    "ProfileCandidate",
    "ProfileDecisionKind",
    "ProfileGuidanceDecision",
    "ProfileGuidancePlanner",
    "ProfileGuidancePreview",
    "record_profile_guidance_preview",
]
