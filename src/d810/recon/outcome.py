"""Shared outcome vocabulary across all lifecycle consumers.

Each consumer subsystem (rule-scope, flow-context, Hodur planner)
produces its own detailed outcome type.  This module defines a
:class:`ConsumerOutcomeReport` Protocol for cross-consumer comparison
without forcing subsystem-specific provenance into one lossy format.

Concrete adapters wrap existing outcome types to expose the shared view.

:class:`ReconOutcomeLog` accumulates reports per-function for summary
and diagnostic purposes.
"""
from __future__ import annotations

from d810.core.typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.context import FlowGateDecision
    from d810.optimizers.microcode.flow.flattening.hodur.provenance import (
        PipelineProvenance,
    )
    from d810.recon.runtime import ReconOutcome


@runtime_checkable
class ConsumerOutcomeReport(Protocol):
    """Minimal shared outcome vocabulary across all lifecycle consumers.

    Each consumer subsystem (rule-scope, flow-context, Hodur planner)
    produces its own detailed outcome type. This protocol defines the
    common vocabulary for cross-consumer comparison without forcing
    subsystem-specific provenance into one lossy format.
    """

    @property
    def consumer_name(self) -> str:
        """Identifier of the consumer subsystem that produced this outcome."""
        ...

    @property
    def source_artifacts_available(self) -> bool:
        """Whether recon source artifacts were available at decision time."""
        ...

    @property
    def summary_available(self) -> bool:
        """Whether a consumer-specific summary was produced."""
        ...

    @property
    def consumer_verdict_applied(self) -> bool:
        """Whether the consumer's verdict was actually applied."""
        ...

    @property
    def func_ea(self) -> int:
        """Function effective address this outcome pertains to."""
        ...

    @property
    def detail(self) -> str:
        """Optional subsystem-specific detail string."""
        ...

    @property
    def provenance_dict(self) -> dict | None:
        """Optional rich provenance as a serialisable dict, or ``None``."""
        ...


class RuleScopeOutcomeAdapter:
    """Adapter exposing :class:`ReconOutcome` as a :class:`ConsumerOutcomeReport`.

    Wraps the rule-scope consumer's outcome without modifying it.
    """

    def __init__(self, outcome: ReconOutcome) -> None:
        self._outcome = outcome

    @property
    def consumer_name(self) -> str:
        return "rule_scope"

    @property
    def source_artifacts_available(self) -> bool:
        return self._outcome.source != "unavailable"

    @property
    def summary_available(self) -> bool:
        return self._outcome.hints is not None

    @property
    def consumer_verdict_applied(self) -> bool:
        return self._outcome.apply_result is not None

    @property
    def func_ea(self) -> int:
        return self._outcome.func_ea

    @property
    def detail(self) -> str:
        return f"source={self._outcome.source}"

    @property
    def provenance_dict(self) -> dict | None:
        return None


class PlannerOutcomeAdapter:
    """Adapter exposing :class:`PipelineProvenance` as a :class:`ConsumerOutcomeReport`.

    Wraps the Hodur planner's provenance ledger without modifying it.
    """

    def __init__(self, provenance: PipelineProvenance, func_ea: int) -> None:
        self._provenance = provenance
        self._func_ea = func_ea

    @property
    def consumer_name(self) -> str:
        return "hodur_planner"

    @property
    def source_artifacts_available(self) -> bool:
        return self._provenance.input_summary is not None

    @property
    def summary_available(self) -> bool:
        return len(self._provenance.rows) > 0

    @property
    def consumer_verdict_applied(self) -> bool:
        return self._provenance.accepted_count > 0

    @property
    def func_ea(self) -> int:
        return self._func_ea

    @property
    def detail(self) -> str:
        if hasattr(self._provenance, "summary"):
            return str(self._provenance.summary())
        return ""

    @property
    def provenance_dict(self) -> dict | None:
        if hasattr(self._provenance, "to_dict"):
            return self._provenance.to_dict()
        return None


class FlowGateOutcomeAdapter:
    """Adapter exposing :class:`FlowGateDecision` as a :class:`ConsumerOutcomeReport`.

    Wraps the flow-context gate decision without modifying it.
    """

    def __init__(self, decision: FlowGateDecision, func_ea: int, gate_name: str = "flow_gate") -> None:
        self._decision = decision
        self._func_ea = func_ea
        self._gate_name = gate_name

    @property
    def consumer_name(self) -> str:
        return self._gate_name

    @property
    def source_artifacts_available(self) -> bool:
        # Flow gate always runs against live dispatcher analysis; if a
        # decision object exists, the analysis was available.
        return True

    @property
    def summary_available(self) -> bool:
        return True

    @property
    def consumer_verdict_applied(self) -> bool:
        return self._decision.allowed

    @property
    def func_ea(self) -> int:
        return self._func_ea

    @property
    def detail(self) -> str:
        if hasattr(self._decision, "reason"):
            return str(self._decision.reason)
        return ""

    @property
    def provenance_dict(self) -> dict | None:
        return None


class ReconOutcomeLog:
    """Accumulates consumer outcome reports for one decompilation pass.

    Provides a per-function summary of what each consumer decided.
    Reset at the start of each decompilation via :meth:`reset_for_func`.
    """

    def __init__(self) -> None:
        self._entries: dict[int, list[ConsumerOutcomeReport]] = {}

    def record(self, report: ConsumerOutcomeReport) -> None:
        """Record a consumer outcome report.

        If a report with the same ``consumer_name`` already exists for the
        function, the new report replaces it (last-write-wins).
        """
        entries = self._entries.setdefault(report.func_ea, [])
        # Replace existing entry for same consumer (last-write-wins)
        for i, existing in enumerate(entries):
            if existing.consumer_name == report.consumer_name:
                entries[i] = report
                return
        entries.append(report)

    def reset_for_func(self, func_ea: int) -> None:
        """Clear accumulated reports for a function."""
        self._entries.pop(func_ea, None)

    def get_func_reports(self, func_ea: int) -> list[ConsumerOutcomeReport]:
        """Get all reports for a function."""
        return list(self._entries.get(func_ea, []))

    def summary(self, func_ea: int) -> dict:
        """One-line summary per consumer for a function."""
        reports = self._entries.get(func_ea, [])
        return {
            "func_ea": func_ea,
            "consumers": [
                {
                    "name": r.consumer_name,
                    "artifacts_available": r.source_artifacts_available,
                    "summary_available": r.summary_available,
                    "verdict_applied": r.consumer_verdict_applied,
                    "detail": r.detail,
                }
                for r in reports
            ],
        }
