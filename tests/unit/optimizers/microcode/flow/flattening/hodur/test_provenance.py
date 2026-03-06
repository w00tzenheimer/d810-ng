"""Tests for Hodur decision provenance types (K1.1)."""
from __future__ import annotations

import json

from d810.optimizers.microcode.flow.flattening.hodur.provenance import (
    DecisionInputSummary,
    DecisionPhase,
    DecisionReasonCode,
    DecisionRecord,
    PipelineProvenance,
)


def test_decision_record_creation():
    """Create an APPLIED record and verify is_accepted."""
    row = DecisionRecord(
        strategy_name="DirectHandlerLinearization",
        family="primary",
        phase=DecisionPhase.APPLIED,
        reason_code=DecisionReasonCode.ACCEPTED,
        reason="composite_score=12.5, no conflicts",
        composite_score=12.5,
        risk_score=0.3,
        handler_count=5,
        transition_count=12,
    )
    assert row.phase == DecisionPhase.APPLIED
    assert row.is_accepted


def test_decision_record_rejected():
    """Create a POLICY_FILTERED record and verify not accepted."""
    row = DecisionRecord(
        strategy_name="FallbackX",
        family="fallback",
        phase=DecisionPhase.POLICY_FILTERED,
        reason_code=DecisionReasonCode.REJECTED_POLICY,
        reason="primary coverage 90% >= 80% threshold",
    )
    assert not row.is_accepted
    assert row.phase == DecisionPhase.POLICY_FILTERED


def test_pipeline_provenance_counts():
    """Three rows (1 accepted, 2 rejected) -- verify counts."""
    rows = (
        DecisionRecord(
            "A",
            "primary",
            DecisionPhase.APPLIED,
            DecisionReasonCode.ACCEPTED,
            "ok",
            composite_score=10.0,
            risk_score=0.1,
            handler_count=5,
            transition_count=12,
        ),
        DecisionRecord(
            "B",
            "fallback",
            DecisionPhase.POLICY_FILTERED,
            DecisionReasonCode.REJECTED_POLICY,
            "coverage>=80%",
            composite_score=5.0,
            risk_score=0.2,
        ),
        DecisionRecord(
            "C",
            "fallback",
            DecisionPhase.PLANNED,
            DecisionReasonCode.REJECTED_RISK,
            "risk=0.8>0.7",
            composite_score=3.0,
            risk_score=0.8,
        ),
    )
    prov = PipelineProvenance(rows=rows)
    assert prov.accepted_count == 1
    assert prov.rejected_count == 2


def test_pipeline_provenance_by_phase():
    """Verify by_phase() groups records correctly."""
    rows = (
        DecisionRecord(
            "A",
            "primary",
            DecisionPhase.APPLIED,
            DecisionReasonCode.ACCEPTED,
            "ok",
        ),
        DecisionRecord(
            "B",
            "primary",
            DecisionPhase.GATE_FAILED,
            DecisionReasonCode.REJECTED_GATE,
            "reachability<0.7",
        ),
        DecisionRecord(
            "C",
            "primary",
            DecisionPhase.INAPPLICABLE,
            DecisionReasonCode.REJECTED_INAPPLICABLE,
            "no dispatcher",
        ),
    )
    prov = PipelineProvenance(rows=rows)
    by_phase = prov.by_phase()
    assert DecisionPhase.APPLIED in by_phase
    assert DecisionPhase.GATE_FAILED in by_phase
    assert len(by_phase[DecisionPhase.INAPPLICABLE]) == 1


def test_decision_input_summary():
    """Create DecisionInputSummary and verify flags."""
    s = DecisionInputSummary(
        handler_transitions_available=True,
        return_frontier_available=False,
        terminal_return_audit_available=True,
        terminal_return_audit_summary="4/46 terminal: 4 shared, 0 direct",
    )
    assert s.handler_transitions_available is True
    assert s.return_frontier_available is False
    assert s.terminal_return_audit_available is True
    assert s.terminal_return_audit_summary == "4/46 terminal: 4 shared, 0 direct"


def test_provenance_to_dicts_serializable():
    """Verify to_dicts() output is JSON-serializable."""
    rows = (
        DecisionRecord(
            "A",
            "primary",
            DecisionPhase.APPLIED,
            DecisionReasonCode.ACCEPTED,
            "ok",
            handler_count=5,
            transition_count=12,
        ),
    )
    prov = PipelineProvenance(rows=rows)
    dicts = prov.to_dicts()
    serialized = json.dumps(dicts)
    assert '"phase": "applied"' in serialized
    assert '"handler_count": 5' in serialized


def test_selected_phase_exists():
    row = DecisionRecord(
        strategy_name="A",
        family="direct",
        phase=DecisionPhase.SELECTED,
        reason_code=DecisionReasonCode.ACCEPTED,
        reason="selected by planner",
    )
    assert row.is_accepted
    assert row.phase == DecisionPhase.SELECTED


def test_bypassed_reason_codes():
    row = DecisionRecord(
        strategy_name="A",
        family="direct",
        phase=DecisionPhase.BYPASSED,
        reason_code=DecisionReasonCode.BYPASSED_SAFEGUARD,
        reason="safeguard disabled",
    )
    assert not row.is_accepted


def test_provenance_summary_format():
    """Verify summary string contains 'accepted' and 'rejected'."""
    rows = (
        DecisionRecord(
            "A",
            "primary",
            DecisionPhase.APPLIED,
            DecisionReasonCode.ACCEPTED,
            "ok",
        ),
        DecisionRecord(
            "B",
            "fallback",
            DecisionPhase.POLICY_FILTERED,
            DecisionReasonCode.REJECTED_POLICY,
            "coverage>=80%",
        ),
    )
    prov = PipelineProvenance(rows=rows)
    summary = prov.summary()
    assert "1 accepted" in summary
    assert "1 rejected" in summary
    assert "2 total" in summary
