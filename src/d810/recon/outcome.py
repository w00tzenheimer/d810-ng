"""Shared outcome vocabulary across all lifecycle consumers.

Each consumer subsystem (rule-scope, flow-context, Hodur planner)
produces its own detailed outcome type.  This module defines a
:class:`ConsumerOutcomeReport` Protocol for cross-consumer comparison
without forcing subsystem-specific provenance into one lossy format.

Concrete adapters wrap existing outcome types to expose the shared view.
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


class FlowGateOutcomeAdapter:
    """Adapter exposing :class:`FlowGateDecision` as a :class:`ConsumerOutcomeReport`.

    Wraps the flow-context gate decision without modifying it.
    """

    def __init__(self, decision: FlowGateDecision, func_ea: int) -> None:
        self._decision = decision
        self._func_ea = func_ea

    @property
    def consumer_name(self) -> str:
        return "flow_gate"

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
