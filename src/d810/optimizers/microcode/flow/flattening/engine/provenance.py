"""Structured decision provenance for the shared unflattening engine.

This module contains the outcome layer for planner participation in the
shared recon-analysis-consumer lifecycle. Every considered ``PlanFragment``
gets a ``DecisionRecord`` tracking its lifecycle phase, reason code,
benefit/risk scores, and input context. The aggregate ``PipelineProvenance``
records what the planner decided and why.
"""
from __future__ import annotations

import enum
from collections import Counter
from dataclasses import dataclass, field, replace

from d810.core import logging

_logger = logging.getLogger(__name__)

__all__ = [
    "DecisionInputSummary",
    "DecisionPhase",
    "DecisionReasonCode",
    "DecisionRecord",
    "GateAccounting",
    "GateDecision",
    "GateVerdict",
    "PipelineProvenance",
    "PlannerInputs",
]


class DecisionPhase(str, enum.Enum):
    """Lifecycle phase where the decision was made."""

    INAPPLICABLE = "inapplicable"
    CRASHED = "crashed"
    SELECTED = "selected"
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
    REJECTED_GATE_SAFEGUARD = "rejected_gate_safeguard"
    REJECTED_GATE_SEMANTIC = "rejected_gate_semantic"
    REJECTED_TRANSACTION = "rejected_transaction"
    BYPASSED = "bypassed"
    BYPASSED_SAFEGUARD = "bypassed_safeguard"
    BYPASSED_STRICT_MODE_DISABLED = "bypassed_strict_mode_disabled"
    BYPASSED_PIPELINE_ABORT = "bypassed_pipeline_abort"
    BLOCKED = "blocked"


class GateVerdict(str, enum.Enum):
    """Outcome of a single gate check."""

    PASSED = "passed"
    FAILED = "failed"
    BYPASSED = "bypassed"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class GateDecision:
    """Record of a single gate checkpoint evaluation."""

    gate_name: str
    verdict: GateVerdict
    reason: str
    strict_mode: bool = True
    elapsed_ms: float | None = None


@dataclass(frozen=True)
class GateAccounting:
    """Aggregated gate decisions for one stage execution."""

    decisions: tuple[GateDecision, ...] = ()
    cycle_filter_removed: int = 0
    backend_filter_removed: int = 0

    def add(self, decision: GateDecision) -> GateAccounting:
        """Return a new GateAccounting with the decision appended."""
        return replace(self, decisions=self.decisions + (decision,))

    def with_cycle_filter(self, removed: int) -> GateAccounting:
        """Return a new GateAccounting with cycle filter count set."""
        return replace(self, cycle_filter_removed=removed)

    def with_backend_filter(self, removed: int) -> GateAccounting:
        """Return a new GateAccounting with backend filter count set."""
        return replace(self, backend_filter_removed=removed)

    @property
    def passed_count(self) -> int:
        """Count of PASSED verdicts."""
        return sum(1 for decision in self.decisions if decision.verdict == GateVerdict.PASSED)

    @property
    def failed_count(self) -> int:
        """Count of FAILED verdicts."""
        return sum(1 for decision in self.decisions if decision.verdict == GateVerdict.FAILED)

    @property
    def bypassed_count(self) -> int:
        """Count of BYPASSED verdicts."""
        return sum(1 for decision in self.decisions if decision.verdict == GateVerdict.BYPASSED)

    @property
    def all_passed(self) -> bool:
        """True when every decision passed."""
        return all(decision.verdict == GateVerdict.PASSED for decision in self.decisions)

    def any_failed(self) -> bool:
        """Return True if any gate decision has FAILED verdict."""
        return any(decision.verdict == GateVerdict.FAILED for decision in self.decisions)

    def summary(self) -> str:
        """One-line summary like '2 passed, 1 failed, 0 bypassed'."""
        parts = [
            f"{self.passed_count} passed",
            f"{self.failed_count} failed",
            f"{self.bypassed_count} bypassed",
        ]
        if self.cycle_filter_removed:
            parts.append(f"cycle_filter_removed={self.cycle_filter_removed}")
        if self.backend_filter_removed:
            parts.append(f"backend_filter_removed={self.backend_filter_removed}")
        return ", ".join(parts)


@dataclass(frozen=True)
class DecisionInputSummary:
    """Summary of recon artifacts available at decision time."""

    handler_transitions_available: bool = False
    return_frontier_available: bool = False
    terminal_return_audit_available: bool = False
    terminal_return_audit_summary: str = ""
    policy_overrides: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to a plain dict for JSON reporting."""
        return {
            "handler_transitions_available": self.handler_transitions_available,
            "return_frontier_available": self.return_frontier_available,
            "terminal_return_audit_available": self.terminal_return_audit_available,
            "terminal_return_audit_summary": self.terminal_return_audit_summary,
            "policy_overrides": dict(self.policy_overrides),
        }


@dataclass(frozen=True)
class PlannerInputs:
    """Consumer-specific summary envelope for the current planner boundary."""

    total_handlers: int = 0
    handler_transitions: object | None = None
    return_frontier: object | None = None
    terminal_return_audit: object | None = None
    policy_overrides: dict = field(default_factory=dict)

    @property
    def has_handler_transitions(self) -> bool:
        """True if handler transition data was available at plan time."""
        return self.handler_transitions is not None

    @property
    def has_return_frontier(self) -> bool:
        """True if return frontier data was available at plan time."""
        return self.return_frontier is not None

    def to_input_summary(self) -> DecisionInputSummary:
        """Convert to a DecisionInputSummary for provenance records."""
        audit_summary = ""
        if self.terminal_return_audit is not None:
            summary_fn = getattr(self.terminal_return_audit, "summary", None)
            if callable(summary_fn):
                audit_summary = summary_fn()
        return DecisionInputSummary(
            handler_transitions_available=self.has_handler_transitions,
            return_frontier_available=self.has_return_frontier,
            terminal_return_audit_available=self.terminal_return_audit is not None,
            terminal_return_audit_summary=audit_summary,
            policy_overrides=dict(self.policy_overrides),
        )


@dataclass(frozen=True)
class DecisionRecord:
    """One row in the planner's decision ledger."""

    strategy_name: str
    family: str
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
    gate_accounting: GateAccounting | None = None
    base_score: float = 0.0
    hint_score_delta: float = 0.0
    effective_score: float = 0.0
    hint_reasons: tuple[str, ...] = ()

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
        return sum(1 for row in self.rows if row.is_accepted)

    @property
    def rejected_count(self) -> int:
        """Count of rejected decisions."""
        return sum(1 for row in self.rows if not row.is_accepted)

    def by_phase(self) -> dict[DecisionPhase, list[DecisionRecord]]:
        """Group decision records by their lifecycle phase."""
        result: dict[DecisionPhase, list[DecisionRecord]] = {}
        for row in self.rows:
            result.setdefault(row.phase, []).append(row)
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
        gate_accounting: GateAccounting | None = None,
    ) -> PipelineProvenance:
        """Return a new PipelineProvenance with the named record's phase updated."""
        found = False
        new_rows: list[DecisionRecord] = []
        for row in self.rows:
            if row.strategy_name == fragment_id and not found:
                kwargs: dict = {"phase": new_phase}
                if reason_code is not None:
                    kwargs["reason_code"] = reason_code
                if reason_detail is not None:
                    kwargs["reason"] = reason_detail
                if gate_accounting is not None:
                    kwargs["gate_accounting"] = gate_accounting
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
        counts = Counter(row.phase for row in self.rows)
        parts = [
            f"{count} {phase.value.upper()}"
            for phase, count in sorted(counts.items(), key=lambda item: item[0].value)
        ]
        return ", ".join(parts) if parts else "(empty)"

    def to_dict(self) -> dict:
        """Full provenance serialization including input_summary and phase_summary."""
        return {
            "input_summary": self.input_summary.to_dict() if self.input_summary else None,
            "rows": self._rows_to_dicts(),
            "phase_summary": self.phase_summary(),
        }

    def _rows_to_dicts(self) -> list[dict]:
        """Serialize rows to list of dicts."""
        result: list[dict] = []
        for row in self.rows:
            serialized: dict = {
                "strategy_name": row.strategy_name,
                "family": row.family,
                "phase": row.phase.value,
                "reason_code": row.reason_code.value,
                "reason": row.reason,
                "composite_score": row.composite_score,
                "risk_score": row.risk_score,
                "handler_count": row.handler_count,
                "transition_count": row.transition_count,
                "notes": row.notes,
                "ownership_blocks": sorted(row.ownership_blocks),
                "prerequisites": sorted(row.prerequisites),
            }
            if (
                row.base_score
                or row.hint_score_delta
                or row.effective_score
                or row.hint_reasons
            ):
                serialized["base_score"] = row.base_score
                serialized["hint_score_delta"] = row.hint_score_delta
                serialized["effective_score"] = row.effective_score
                serialized["hint_reasons"] = list(row.hint_reasons)
            if row.input_summary is not None:
                serialized["input_summary"] = row.input_summary.to_dict()
            if row.gate_accounting is not None:
                serialized["gate_accounting"] = [
                    {
                        "gate_name": decision.gate_name,
                        "verdict": decision.verdict.value,
                        "reason": decision.reason,
                        "strict_mode": decision.strict_mode,
                    }
                    for decision in row.gate_accounting.decisions
                ]
            if row.terminal_return_summary:
                serialized["terminal_return_summary"] = row.terminal_return_summary
            result.append(serialized)
        return result
