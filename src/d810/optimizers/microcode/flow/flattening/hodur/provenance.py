"""Structured decision provenance for Hodur planner pipeline.

Every considered PlanFragment gets a DecisionRecord tracking its
lifecycle phase, reason code, benefit/risk scores, and input context.
This vocabulary is shared across K1 (provenance), K2 (hint inputs),
K4 (gate accounting), and K5 (planner ownership).
"""
from __future__ import annotations

import enum
from collections import Counter
from dataclasses import dataclass, field, replace

from d810.core import logging

_logger = logging.getLogger(__name__)


class DecisionPhase(str, enum.Enum):
    """Lifecycle phase where the decision was made."""

    INAPPLICABLE = "inapplicable"
    CRASHED = "crashed"
    PLANNED = "planned"
    SELECTED = "selected"  # planner accepted into pipeline (pre-execution)
    POLICY_FILTERED = "policy_filtered"
    CONFLICT_DROPPED = "conflict_dropped"
    PREFLIGHT_REJECTED = "preflight_rejected"
    GATE_FAILED = "gate_failed"
    APPLIED = "applied"
    BYPASSED = "bypassed"


class DecisionReasonCode(str, enum.Enum):
    """Machine-readable reason code for the decision."""

    ACCEPTED = "accepted"
    REJECTED_EMPTY = "rejected_empty"
    REJECTED_RISK = "rejected_risk"
    REJECTED_POLICY = "rejected_policy"
    REJECTED_CONFLICT = "rejected_conflict"
    REJECTED_INAPPLICABLE = "rejected_inapplicable"
    REJECTED_CRASHED = "rejected_crashed"
    REJECTED_PREFLIGHT = "rejected_preflight"
    REJECTED_GATE = "rejected_gate"
    REJECTED_TRANSACTION = "rejected_transaction"
    BYPASSED = "bypassed"
    BYPASSED_SAFEGUARD = "bypassed_safeguard"
    BYPASSED_STRICT_MODE_DISABLED = "bypassed_strict_mode_disabled"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class DecisionInputSummary:
    """Summary of recon artifacts available at decision time."""

    handler_transitions_available: bool = False
    return_frontier_available: bool = False
    terminal_return_audit_available: bool = False
    terminal_return_audit_summary: str = ""
    policy_overrides: dict = field(default_factory=dict)


@dataclass(frozen=True)
class DecisionRecord:
    """One row in the planner's decision ledger."""

    strategy_name: str
    family: str  # FAMILY_DIRECT, FAMILY_FALLBACK, or FAMILY_CLEANUP (from strategy.py)
    phase: DecisionPhase
    reason_code: DecisionReasonCode
    reason: str
    composite_score: float = 0.0
    risk_score: float = 0.0
    handler_count: int = 0
    transition_count: int = 0
    ownership_blocks: frozenset[int] = field(default_factory=frozenset)
    prerequisites: frozenset[str] = field(default_factory=frozenset)
    input_summary: DecisionInputSummary | None = None
    terminal_return_summary: str = ""
    notes: str = ""

    @property
    def is_accepted(self) -> bool:
        """Return True if this record represents an accepted decision."""
        return self.reason_code == DecisionReasonCode.ACCEPTED


@dataclass(frozen=True)
class PipelineProvenance:
    """Complete decision ledger for one compose_pipeline call."""

    rows: tuple[DecisionRecord, ...] = ()
    input_summary: DecisionInputSummary | None = None

    @property
    def accepted_count(self) -> int:
        """Count of accepted decisions."""
        return sum(1 for r in self.rows if r.is_accepted)

    @property
    def rejected_count(self) -> int:
        """Count of rejected decisions."""
        return sum(1 for r in self.rows if not r.is_accepted)

    def by_phase(self) -> dict[DecisionPhase, list[DecisionRecord]]:
        """Group decision records by their lifecycle phase."""
        result: dict[DecisionPhase, list[DecisionRecord]] = {}
        for r in self.rows:
            result.setdefault(r.phase, []).append(r)
        return result

    def summary(self) -> str:
        """Human-readable one-line summary."""
        return (
            f"{self.accepted_count} accepted, {self.rejected_count} rejected "
            f"({len(self.rows)} total)"
        )

    def update_phase(
        self,
        fragment_id: str,
        new_phase: DecisionPhase,
        reason_code: DecisionReasonCode | None = None,
        reason_detail: str | None = None,
    ) -> PipelineProvenance:
        """Return a new PipelineProvenance with the named record's phase updated.

        Since DecisionRecord is frozen, this creates a replacement row via
        ``dataclasses.replace``.  If *fragment_id* is not found among
        ``self.rows``, a warning is logged and the original instance is
        returned unchanged.

        Args:
            fragment_id: The ``strategy_name`` of the record to update.
            new_phase: New lifecycle phase to set.
            reason_code: Optional new reason code (kept unchanged if None).
            reason_detail: Optional new reason string (kept unchanged if None).

        Returns:
            A new ``PipelineProvenance`` with the updated row.
        """
        found = False
        new_rows: list[DecisionRecord] = []
        for row in self.rows:
            if row.strategy_name == fragment_id and not found:
                kwargs: dict = {"phase": new_phase}
                if reason_code is not None:
                    kwargs["reason_code"] = reason_code
                if reason_detail is not None:
                    kwargs["reason"] = reason_detail
                new_rows.append(replace(row, **kwargs))
                found = True
            else:
                new_rows.append(row)
        if not found:
            _logger.warning(
                "update_phase: fragment_id %r not found in provenance rows",
                fragment_id,
            )
            return self
        return PipelineProvenance(
            rows=tuple(new_rows),
            input_summary=self.input_summary,
        )

    def phase_summary(self) -> str:
        """One-line summary grouped by phase, e.g. '3 APPLIED, 1 GATE_FAILED'."""
        counts = Counter(r.phase for r in self.rows)
        parts = [
            f"{count} {phase.value.upper()}"
            for phase, count in sorted(counts.items(), key=lambda x: x[0].value)
        ]
        return ", ".join(parts) if parts else "(empty)"

    def to_dicts(self) -> list[dict]:
        """Serialize rows to list of dicts for on-disk reporting."""
        return [
            {
                "strategy_name": r.strategy_name,
                "family": r.family,
                "phase": r.phase.value,
                "reason_code": r.reason_code.value,
                "reason": r.reason,
                "composite_score": r.composite_score,
                "risk_score": r.risk_score,
                "handler_count": r.handler_count,
                "transition_count": r.transition_count,
                "notes": r.notes,
            }
            for r in self.rows
        ]
