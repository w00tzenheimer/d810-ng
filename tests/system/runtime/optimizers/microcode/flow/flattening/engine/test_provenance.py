"""Unit tests for shared engine provenance types."""
from __future__ import annotations

from d810.optimizers.microcode.flow.flattening import engine
from d810.optimizers.microcode.flow.flattening.engine.provenance import (
    DecisionInputSummary,
    DecisionPhase,
    DecisionReasonCode,
    DecisionRecord,
    GateAccounting,
    GateDecision,
    GateVerdict,
    PipelineProvenance,
    PlannerInputs,
)
from d810.optimizers.microcode.flow.flattening.hodur import provenance as hodur_provenance


class _Audit:
    def summary(self) -> str:
        return "2 terminal cases"


def test_engine_package_re_exports_provenance_types() -> None:
    assert engine.PipelineProvenance is PipelineProvenance
    assert engine.PlannerInputs is PlannerInputs


def test_hodur_provenance_shim_points_to_engine_types() -> None:
    assert hodur_provenance.PipelineProvenance is PipelineProvenance
    assert hodur_provenance.DecisionRecord is DecisionRecord


def test_planner_inputs_builds_input_summary() -> None:
    inputs = PlannerInputs(
        total_handlers=3,
        handler_transitions=object(),
        terminal_return_audit=_Audit(),
        policy_overrides={"strict": True},
    )

    summary = inputs.to_input_summary()

    assert summary == DecisionInputSummary(
        handler_transitions_available=True,
        return_frontier_available=False,
        terminal_return_audit_available=True,
        terminal_return_audit_summary="2 terminal cases",
        policy_overrides={"strict": True},
    )


def test_gate_accounting_summary_and_counts() -> None:
    accounting = GateAccounting().add(
        GateDecision("semantic_gate", GateVerdict.PASSED, "ok")
    ).add(
        GateDecision("safeguard", GateVerdict.FAILED, "too risky")
    )

    assert accounting.passed_count == 1
    assert accounting.failed_count == 1
    assert accounting.bypassed_count == 0
    assert accounting.any_failed() is True
    assert accounting.summary() == "1 passed, 1 failed, 0 bypassed"


def test_pipeline_provenance_update_phase_and_to_dict() -> None:
    provenance = PipelineProvenance(
        rows=(
            DecisionRecord(
                strategy_name="direct",
                family="direct",
                phase=DecisionPhase.SELECTED,
                reason_code=DecisionReasonCode.ACCEPTED,
                reason="selected",
            ),
        ),
    )
    updated = provenance.update_phase(
        "direct",
        DecisionPhase.GATE_FAILED,
        reason_code=DecisionReasonCode.REJECTED_GATE,
        reason_detail="semantic gate rejected",
    )

    assert updated.rows[0].phase == DecisionPhase.GATE_FAILED
    assert updated.rows[0].reason_code == DecisionReasonCode.REJECTED_GATE
    assert updated.phase_summary() == "1 GATE_FAILED"
    assert updated.to_dict()["rows"][0]["reason"] == "semantic gate rejected"
