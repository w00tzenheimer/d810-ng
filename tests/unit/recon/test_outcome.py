"""Tests for shared outcome vocabulary and adapters."""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from d810.recon.outcome import (
    ConsumerOutcomeReport,
    FlowGateOutcomeAdapter,
    PlannerOutcomeAdapter,
    RuleScopeOutcomeAdapter,
)


# ---------------------------------------------------------------------------
# Lightweight stubs for the wrapped types (no IDA imports)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _StubApplyHintsResult:
    func_ea: int = 0x401000
    recipes_applied: tuple[str, ...] = ()
    recipes_not_found: tuple[str, ...] = ()
    rules_suppressed: tuple[str, ...] = ()
    cache_invalidated: bool = False
    generation_before: int = 0
    generation_after: int = 1


@dataclass(frozen=True)
class _StubReconOutcome:
    func_ea: int = 0x401000
    hints: object | None = None
    apply_result: object | None = None
    source: str = "unavailable"


@dataclass(frozen=True)
class _StubDecisionInputSummary:
    handler_transitions_available: bool = False
    return_frontier_available: bool = False


@dataclass(frozen=True)
class _StubDecisionRecord:
    strategy_name: str = "G1"
    family: str = "direct"
    reason_code: str = "accepted"
    is_accepted: bool = True


@dataclass(frozen=True)
class _StubPipelineProvenance:
    rows: tuple[_StubDecisionRecord, ...] = ()
    input_summary: _StubDecisionInputSummary | None = None
    accepted_count: int = 0
    rejected_count: int = 0


@dataclass(frozen=True)
class _StubFlowGateDecision:
    allowed: bool = True
    reason: str = "switch-table dispatcher"


# ---------------------------------------------------------------------------
# Protocol structural conformance
# ---------------------------------------------------------------------------


class TestProtocolConformance:
    """Each adapter must satisfy the ConsumerOutcomeReport protocol."""

    def test_rule_scope_adapter_is_protocol_instance(self) -> None:
        outcome = _StubReconOutcome()
        adapter = RuleScopeOutcomeAdapter(outcome)
        assert isinstance(adapter, ConsumerOutcomeReport)

    def test_planner_adapter_is_protocol_instance(self) -> None:
        prov = _StubPipelineProvenance()
        adapter = PlannerOutcomeAdapter(prov, func_ea=0x401000)
        assert isinstance(adapter, ConsumerOutcomeReport)

    def test_flow_gate_adapter_is_protocol_instance(self) -> None:
        decision = _StubFlowGateDecision()
        adapter = FlowGateOutcomeAdapter(decision, func_ea=0x401000)
        assert isinstance(adapter, ConsumerOutcomeReport)


# ---------------------------------------------------------------------------
# RuleScopeOutcomeAdapter field mapping
# ---------------------------------------------------------------------------


class TestRuleScopeOutcomeAdapter:
    def test_consumer_name(self) -> None:
        adapter = RuleScopeOutcomeAdapter(_StubReconOutcome())
        assert adapter.consumer_name == "rule_scope"

    def test_source_unavailable(self) -> None:
        adapter = RuleScopeOutcomeAdapter(_StubReconOutcome(source="unavailable"))
        assert adapter.source_artifacts_available is False

    def test_source_cached(self) -> None:
        adapter = RuleScopeOutcomeAdapter(_StubReconOutcome(source="cached"))
        assert adapter.source_artifacts_available is True

    def test_source_analyzed(self) -> None:
        adapter = RuleScopeOutcomeAdapter(_StubReconOutcome(source="analyzed"))
        assert adapter.source_artifacts_available is True

    def test_summary_available_when_hints_present(self) -> None:
        adapter = RuleScopeOutcomeAdapter(
            _StubReconOutcome(hints=object()),
        )
        assert adapter.summary_available is True

    def test_summary_unavailable_when_hints_none(self) -> None:
        adapter = RuleScopeOutcomeAdapter(_StubReconOutcome(hints=None))
        assert adapter.summary_available is False

    def test_verdict_applied_when_result_present(self) -> None:
        adapter = RuleScopeOutcomeAdapter(
            _StubReconOutcome(apply_result=_StubApplyHintsResult()),
        )
        assert adapter.consumer_verdict_applied is True

    def test_verdict_not_applied_when_result_none(self) -> None:
        adapter = RuleScopeOutcomeAdapter(_StubReconOutcome(apply_result=None))
        assert adapter.consumer_verdict_applied is False

    def test_func_ea(self) -> None:
        adapter = RuleScopeOutcomeAdapter(_StubReconOutcome(func_ea=0xDEAD))
        assert adapter.func_ea == 0xDEAD


# ---------------------------------------------------------------------------
# PlannerOutcomeAdapter field mapping
# ---------------------------------------------------------------------------


class TestPlannerOutcomeAdapter:
    def test_consumer_name(self) -> None:
        adapter = PlannerOutcomeAdapter(_StubPipelineProvenance(), func_ea=0x1000)
        assert adapter.consumer_name == "hodur_planner"

    def test_source_artifacts_available_with_input_summary(self) -> None:
        prov = _StubPipelineProvenance(
            input_summary=_StubDecisionInputSummary(),
        )
        adapter = PlannerOutcomeAdapter(prov, func_ea=0x1000)
        assert adapter.source_artifacts_available is True

    def test_source_artifacts_unavailable_without_input_summary(self) -> None:
        prov = _StubPipelineProvenance(input_summary=None)
        adapter = PlannerOutcomeAdapter(prov, func_ea=0x1000)
        assert adapter.source_artifacts_available is False

    def test_summary_available_with_rows(self) -> None:
        prov = _StubPipelineProvenance(rows=(_StubDecisionRecord(),))
        adapter = PlannerOutcomeAdapter(prov, func_ea=0x1000)
        assert adapter.summary_available is True

    def test_summary_unavailable_without_rows(self) -> None:
        prov = _StubPipelineProvenance(rows=())
        adapter = PlannerOutcomeAdapter(prov, func_ea=0x1000)
        assert adapter.summary_available is False

    def test_verdict_applied_when_accepted(self) -> None:
        prov = _StubPipelineProvenance(accepted_count=2)
        adapter = PlannerOutcomeAdapter(prov, func_ea=0x1000)
        assert adapter.consumer_verdict_applied is True

    def test_verdict_not_applied_when_zero_accepted(self) -> None:
        prov = _StubPipelineProvenance(accepted_count=0)
        adapter = PlannerOutcomeAdapter(prov, func_ea=0x1000)
        assert adapter.consumer_verdict_applied is False

    def test_func_ea(self) -> None:
        adapter = PlannerOutcomeAdapter(_StubPipelineProvenance(), func_ea=0xBEEF)
        assert adapter.func_ea == 0xBEEF


# ---------------------------------------------------------------------------
# FlowGateOutcomeAdapter field mapping
# ---------------------------------------------------------------------------


class TestFlowGateOutcomeAdapter:
    def test_consumer_name(self) -> None:
        adapter = FlowGateOutcomeAdapter(_StubFlowGateDecision(), func_ea=0x2000)
        assert adapter.consumer_name == "flow_gate"

    def test_source_artifacts_always_available(self) -> None:
        adapter = FlowGateOutcomeAdapter(_StubFlowGateDecision(), func_ea=0x2000)
        assert adapter.source_artifacts_available is True

    def test_summary_always_available(self) -> None:
        adapter = FlowGateOutcomeAdapter(_StubFlowGateDecision(), func_ea=0x2000)
        assert adapter.summary_available is True

    def test_verdict_applied_when_allowed(self) -> None:
        adapter = FlowGateOutcomeAdapter(
            _StubFlowGateDecision(allowed=True), func_ea=0x2000,
        )
        assert adapter.consumer_verdict_applied is True

    def test_verdict_not_applied_when_denied(self) -> None:
        adapter = FlowGateOutcomeAdapter(
            _StubFlowGateDecision(allowed=False), func_ea=0x2000,
        )
        assert adapter.consumer_verdict_applied is False

    def test_func_ea(self) -> None:
        adapter = FlowGateOutcomeAdapter(
            _StubFlowGateDecision(), func_ea=0xCAFE,
        )
        assert adapter.func_ea == 0xCAFE
