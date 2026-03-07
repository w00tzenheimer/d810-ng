"""Tests for Hodur decision provenance types (K1.1), planner instrumentation (K1.2),
and gate/bypass accounting (K4)."""
from __future__ import annotations

import json

from d810.cfg.graph_modification import RedirectGoto
from d810.optimizers.microcode.flow.flattening.hodur.planner import (
    PipelinePolicy,
    UnflatteningPlanner,
)
from d810.optimizers.microcode.flow.flattening.hodur.provenance import (
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
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    BenefitMetrics,
    FAMILY_DIRECT,
    FAMILY_FALLBACK,
    OwnershipScope,
    PlanFragment,
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
            DecisionPhase.POLICY_FILTERED,
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


def test_provenance_to_dict_serializable():
    """Verify to_dict() output is JSON-serializable."""
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
    d = prov.to_dict()
    serialized = json.dumps(d)
    assert '"phase": "applied"' in serialized
    assert '"handler_count": 5' in serialized
    assert "rows" in d
    assert "phase_summary" in d


def test_decision_input_summary_to_dict():
    """DecisionInputSummary.to_dict() returns all fields."""
    s = DecisionInputSummary(
        handler_transitions_available=True,
        return_frontier_available=False,
        terminal_return_audit_available=True,
        terminal_return_audit_summary="4/46 terminal",
        policy_overrides={"force": True},
    )
    d = s.to_dict()
    assert d["handler_transitions_available"] is True
    assert d["return_frontier_available"] is False
    assert d["terminal_return_audit_available"] is True
    assert d["terminal_return_audit_summary"] == "4/46 terminal"
    assert d["policy_overrides"] == {"force": True}
    serialized = json.dumps(d)
    assert '"handler_transitions_available": true' in serialized


def test_provenance_to_dict_includes_input_summary():
    """to_dict() includes input_summary, rows, and phase_summary."""
    summary = DecisionInputSummary(
        handler_transitions_available=True,
        return_frontier_available=False,
    )
    rows = (
        DecisionRecord(
            "A",
            "primary",
            DecisionPhase.APPLIED,
            DecisionReasonCode.ACCEPTED,
            "ok",
            handler_count=5,
        ),
    )
    prov = PipelineProvenance(rows=rows, input_summary=summary)
    d = prov.to_dict()
    assert d["input_summary"] is not None
    assert d["input_summary"]["handler_transitions_available"] is True
    assert d["input_summary"]["return_frontier_available"] is False
    assert len(d["rows"]) == 1
    assert d["rows"][0]["phase"] == "applied"
    assert "phase_summary" in d
    assert "1 APPLIED" in d["phase_summary"]
    # JSON-serializable
    serialized = json.dumps(d)
    assert '"input_summary"' in serialized


def test_provenance_to_dict_none_input_summary():
    """to_dict() with no input_summary sets it to None."""
    rows = (
        DecisionRecord(
            "A",
            "primary",
            DecisionPhase.APPLIED,
            DecisionReasonCode.ACCEPTED,
            "ok",
        ),
    )
    prov = PipelineProvenance(rows=rows)
    d = prov.to_dict()
    assert d["input_summary"] is None
    # Still JSON-serializable
    serialized = json.dumps(d)
    assert '"input_summary": null' in serialized


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


# ---------------------------------------------------------------------------
# K1.2: compose_pipeline provenance tests
# ---------------------------------------------------------------------------

_DUMMY_MOD = RedirectGoto(from_serial=0, old_target=1, new_target=2)


def _fragment(
    name: str,
    family: str = FAMILY_DIRECT,
    risk: float = 0.3,
    handlers: int = 5,
    transitions: int = 0,
    blocks_freed: int = 0,
    ownership: OwnershipScope | None = None,
    empty: bool = False,
) -> PlanFragment:
    """Build a minimal PlanFragment for planner tests."""
    return PlanFragment(
        strategy_name=name,
        family=family,
        ownership=ownership or OwnershipScope(
            blocks=frozenset(), edges=frozenset(), transitions=frozenset(),
        ),
        prerequisites=[],
        expected_benefit=BenefitMetrics(
            handlers_resolved=handlers,
            transitions_resolved=transitions,
            blocks_freed=blocks_freed,
            conflict_density=0.0,
        ),
        risk_score=risk,
        metadata={},
        modifications=[] if empty else [_DUMMY_MOD],
    )


class TestComposePipelineProvenance:
    """K1.2: compose_pipeline returns (pipeline, PipelineProvenance)."""

    def test_returns_provenance(self) -> None:
        planner = UnflatteningPlanner()
        frags = [_fragment("A"), _fragment("B", risk=0.9)]
        pipeline, provenance = planner.compose_pipeline(frags, inputs=PlannerInputs(total_handlers=10))
        assert isinstance(provenance, PipelineProvenance)
        assert provenance.accepted_count >= 1
        verdicts = {r.strategy_name: r.reason_code for r in provenance.rows}
        assert verdicts["B"] == DecisionReasonCode.REJECTED_RISK

    def test_empty_filter_provenance(self) -> None:
        """Fragments with no modifications get INAPPLICABLE / REJECTED_EMPTY."""
        planner = UnflatteningPlanner()
        frags = [_fragment("empty_one", empty=True), _fragment("real_one")]
        pipeline, provenance = planner.compose_pipeline(frags, inputs=PlannerInputs(total_handlers=10))
        assert len(pipeline) == 1
        assert pipeline[0].strategy_name == "real_one"
        verdicts = {r.strategy_name: r for r in provenance.rows}
        assert verdicts["empty_one"].phase == DecisionPhase.INAPPLICABLE
        assert verdicts["empty_one"].reason_code == DecisionReasonCode.REJECTED_EMPTY

    def test_risk_filter_provenance(self) -> None:
        """Fragments exceeding risk threshold get POLICY_FILTERED / REJECTED_RISK."""
        planner = UnflatteningPlanner(PipelinePolicy(max_risk_score=0.5))
        frags = [_fragment("safe", risk=0.3), _fragment("risky", risk=0.8)]
        pipeline, provenance = planner.compose_pipeline(frags, inputs=PlannerInputs(total_handlers=10))
        assert len(pipeline) == 1
        verdicts = {r.strategy_name: r for r in provenance.rows}
        assert verdicts["risky"].phase == DecisionPhase.POLICY_FILTERED
        assert verdicts["risky"].reason_code == DecisionReasonCode.REJECTED_RISK
        assert verdicts["risky"].risk_score == 0.8

    def test_policy_gate_provenance(self) -> None:
        """Fallbacks dropped when direct coverage >= threshold."""
        planner = UnflatteningPlanner()
        frags = [
            _fragment("primary1", family=FAMILY_DIRECT, handlers=9),
            _fragment("fallback1", family=FAMILY_FALLBACK, handlers=2),
        ]
        # 9/10 = 90% >= 80% threshold => fallback dropped
        pipeline, provenance = planner.compose_pipeline(frags, inputs=PlannerInputs(total_handlers=10))
        phases = {r.strategy_name: r.phase for r in provenance.rows}
        assert phases["fallback1"] == DecisionPhase.POLICY_FILTERED
        reason_codes = {r.strategy_name: r.reason_code for r in provenance.rows}
        assert reason_codes["fallback1"] == DecisionReasonCode.REJECTED_POLICY

    def test_conflict_resolution_provenance(self) -> None:
        """Lower-scoring fragment dropped by conflict gets CONFLICT_DROPPED."""
        shared = frozenset({1, 2, 3})
        frags = [
            _fragment(
                "A",
                handlers=8,
                ownership=OwnershipScope(
                    blocks=shared, edges=frozenset(), transitions=frozenset(),
                ),
            ),
            _fragment(
                "B",
                handlers=3,
                ownership=OwnershipScope(
                    blocks=shared, edges=frozenset(), transitions=frozenset(),
                ),
            ),
        ]
        planner = UnflatteningPlanner()
        pipeline, provenance = planner.compose_pipeline(frags, inputs=PlannerInputs(total_handlers=10))
        phases = {r.strategy_name: r.phase for r in provenance.rows}
        assert phases["B"] == DecisionPhase.CONFLICT_DROPPED
        reason_codes = {r.strategy_name: r.reason_code for r in provenance.rows}
        assert reason_codes["B"] == DecisionReasonCode.REJECTED_CONFLICT
        # A should be SELECTED
        assert phases["A"] == DecisionPhase.SELECTED

    def test_selected_fragments_are_accepted(self) -> None:
        """Surviving fragments get SELECTED / ACCEPTED."""
        planner = UnflatteningPlanner()
        frags = [_fragment("A"), _fragment("B")]
        pipeline, provenance = planner.compose_pipeline(frags, inputs=PlannerInputs(total_handlers=10))
        assert len(pipeline) == 2
        for row in provenance.rows:
            if row.phase == DecisionPhase.SELECTED:
                assert row.reason_code == DecisionReasonCode.ACCEPTED

    def test_provenance_handler_and_transition_counts(self) -> None:
        """DecisionRecord carries handler_count and transition_count from benefit."""
        planner = UnflatteningPlanner()
        frags = [_fragment("A", handlers=7, transitions=12)]
        pipeline, provenance = planner.compose_pipeline(frags, inputs=PlannerInputs(total_handlers=10))
        selected = [r for r in provenance.rows if r.phase == DecisionPhase.SELECTED]
        assert len(selected) == 1
        assert selected[0].handler_count == 7
        assert selected[0].transition_count == 12

    def test_provenance_covers_all_input_fragments(self) -> None:
        """Every input fragment appears exactly once in provenance rows."""
        planner = UnflatteningPlanner()
        frags = [
            _fragment("A"),
            _fragment("B", risk=0.9),
            _fragment("C", empty=True),
        ]
        _pipeline, provenance = planner.compose_pipeline(frags, inputs=PlannerInputs(total_handlers=10))
        names = [r.strategy_name for r in provenance.rows]
        assert sorted(names) == ["A", "B", "C"]

    def test_policy_disallow_fallback_provenance(self) -> None:
        """When allow_fallback_families=False, fallbacks get POLICY_FILTERED."""
        policy = PipelinePolicy(allow_fallback_families=False)
        planner = UnflatteningPlanner(policy)
        frags = [
            _fragment("direct1", family=FAMILY_DIRECT),
            _fragment("fb1", family=FAMILY_FALLBACK),
        ]
        pipeline, provenance = planner.compose_pipeline(frags, inputs=PlannerInputs(total_handlers=10))
        assert len(pipeline) == 1
        verdicts = {r.strategy_name: r for r in provenance.rows}
        assert verdicts["fb1"].phase == DecisionPhase.POLICY_FILTERED
        assert verdicts["fb1"].reason_code == DecisionReasonCode.REJECTED_POLICY

    def test_no_fragments_returns_empty_provenance(self) -> None:
        """Empty input produces empty pipeline and provenance."""
        planner = UnflatteningPlanner()
        pipeline, provenance = planner.compose_pipeline([], inputs=PlannerInputs(total_handlers=10))
        assert pipeline == []
        assert provenance.accepted_count == 0
        assert provenance.rejected_count == 0


# ---------------------------------------------------------------------------
# K1.3: Strategy polling provenance (INAPPLICABLE / CRASHED)
# ---------------------------------------------------------------------------


def test_inapplicable_strategy_record():
    """Strategies that return is_applicable=False get INAPPLICABLE record."""
    row = DecisionRecord(
        strategy_name="SomeStrategy",
        family=FAMILY_DIRECT,
        phase=DecisionPhase.INAPPLICABLE,
        reason_code=DecisionReasonCode.REJECTED_INAPPLICABLE,
        reason="is_applicable returned False",
    )
    assert row.phase == DecisionPhase.INAPPLICABLE
    assert not row.is_accepted


def test_crashed_strategy_record():
    """Strategies that crash during plan() get CRASHED record."""
    row = DecisionRecord(
        strategy_name="BrokenStrategy",
        family=FAMILY_FALLBACK,
        phase=DecisionPhase.CRASHED,
        reason_code=DecisionReasonCode.REJECTED_CRASHED,
        reason="plan() raised: KeyError('missing')",
        notes="KeyError('missing')",
    )
    assert row.phase == DecisionPhase.CRASHED
    assert not row.is_accepted
    assert "KeyError" in row.notes


def test_pre_planner_records_prepended_to_provenance():
    """Pre-planner INAPPLICABLE/CRASHED records appear before planner rows."""
    pre = DecisionRecord(
        strategy_name="Skipped",
        family=FAMILY_DIRECT,
        phase=DecisionPhase.INAPPLICABLE,
        reason_code=DecisionReasonCode.REJECTED_INAPPLICABLE,
        reason="is_applicable returned False",
    )
    planner_row = DecisionRecord(
        strategy_name="Selected",
        family=FAMILY_DIRECT,
        phase=DecisionPhase.SELECTED,
        reason_code=DecisionReasonCode.ACCEPTED,
        reason="selected",
    )
    # Simulate merging as the unflattener does
    planner_prov = PipelineProvenance(rows=(planner_row,))
    merged = PipelineProvenance(
        rows=(pre,) + planner_prov.rows,
        input_summary=planner_prov.input_summary,
    )
    assert merged.rows[0].phase == DecisionPhase.INAPPLICABLE
    assert merged.rows[1].phase == DecisionPhase.SELECTED
    assert len(merged.rows) == 2


# ---------------------------------------------------------------------------
# K1.4: Canonical provenance storage + phase updates
# ---------------------------------------------------------------------------


class TestUpdatePhase:
    """PipelineProvenance.update_phase returns a new frozen instance."""

    def test_updates_existing_record(self) -> None:
        rows = (
            DecisionRecord(
                "A", FAMILY_DIRECT, DecisionPhase.SELECTED,
                DecisionReasonCode.ACCEPTED, "selected into pipeline",
            ),
            DecisionRecord(
                "B", FAMILY_DIRECT, DecisionPhase.SELECTED,
                DecisionReasonCode.ACCEPTED, "selected into pipeline",
            ),
        )
        prov = PipelineProvenance(rows=rows)
        updated = prov.update_phase("A", DecisionPhase.APPLIED)
        # Original unchanged (frozen)
        assert prov.rows[0].phase == DecisionPhase.SELECTED
        # Updated instance has new phase
        assert updated.rows[0].phase == DecisionPhase.APPLIED
        # B untouched
        assert updated.rows[1].phase == DecisionPhase.SELECTED

    def test_updates_reason_code_and_detail(self) -> None:
        rows = (
            DecisionRecord(
                "A", FAMILY_DIRECT, DecisionPhase.SELECTED,
                DecisionReasonCode.ACCEPTED, "selected",
            ),
        )
        prov = PipelineProvenance(rows=rows)
        updated = prov.update_phase(
            "A",
            DecisionPhase.GATE_FAILED,
            reason_code=DecisionReasonCode.REJECTED_GATE,
            reason_detail="semantic gate failed",
        )
        assert updated.rows[0].phase == DecisionPhase.GATE_FAILED
        assert updated.rows[0].reason_code == DecisionReasonCode.REJECTED_GATE
        assert updated.rows[0].reason == "semantic gate failed"

    def test_unknown_fragment_id_returns_unchanged(self) -> None:
        rows = (
            DecisionRecord(
                "A", FAMILY_DIRECT, DecisionPhase.SELECTED,
                DecisionReasonCode.ACCEPTED, "selected",
            ),
        )
        prov = PipelineProvenance(rows=rows)
        result = prov.update_phase("NONEXISTENT", DecisionPhase.APPLIED)
        # Should return the same instance unchanged, no crash
        assert result is prov
        assert result.rows[0].phase == DecisionPhase.SELECTED

    def test_preserves_input_summary(self) -> None:
        summary = DecisionInputSummary(handler_transitions_available=True)
        rows = (
            DecisionRecord(
                "A", FAMILY_DIRECT, DecisionPhase.SELECTED,
                DecisionReasonCode.ACCEPTED, "selected",
            ),
        )
        prov = PipelineProvenance(rows=rows, input_summary=summary)
        updated = prov.update_phase("A", DecisionPhase.APPLIED)
        assert updated.input_summary is summary


class TestPhaseSummary:
    """PipelineProvenance.phase_summary one-liner."""

    def test_mixed_phases(self) -> None:
        rows = (
            DecisionRecord(
                "A", FAMILY_DIRECT, DecisionPhase.APPLIED,
                DecisionReasonCode.ACCEPTED, "ok",
            ),
            DecisionRecord(
                "B", FAMILY_DIRECT, DecisionPhase.APPLIED,
                DecisionReasonCode.ACCEPTED, "ok",
            ),
            DecisionRecord(
                "C", FAMILY_DIRECT, DecisionPhase.GATE_FAILED,
                DecisionReasonCode.REJECTED_GATE, "failed",
            ),
            DecisionRecord(
                "D", FAMILY_DIRECT, DecisionPhase.INAPPLICABLE,
                DecisionReasonCode.REJECTED_INAPPLICABLE, "n/a",
            ),
        )
        prov = PipelineProvenance(rows=rows)
        summary = prov.phase_summary()
        assert "2 APPLIED" in summary
        assert "1 GATE_FAILED" in summary
        assert "1 INAPPLICABLE" in summary

    def test_empty_provenance(self) -> None:
        prov = PipelineProvenance()
        assert prov.phase_summary() == "(empty)"

    def test_single_phase(self) -> None:
        rows = (
            DecisionRecord(
                "A", FAMILY_DIRECT, DecisionPhase.APPLIED,
                DecisionReasonCode.ACCEPTED, "ok",
            ),
        )
        prov = PipelineProvenance(rows=rows)
        assert "1 APPLIED" in prov.phase_summary()


# ---------------------------------------------------------------------------
# K4: Gate/Bypass Accounting
# ---------------------------------------------------------------------------


class TestGateVerdict:
    """K4.1: GateVerdict enum values."""

    def test_verdict_values(self) -> None:
        assert GateVerdict.PASSED.value == "passed"
        assert GateVerdict.FAILED.value == "failed"
        assert GateVerdict.BYPASSED.value == "bypassed"
        assert GateVerdict.SKIPPED.value == "skipped"


class TestGateDecision:
    """K4.1: GateDecision dataclass."""

    def test_creation(self) -> None:
        d = GateDecision(
            gate_name="semantic_gate",
            verdict=GateVerdict.PASSED,
            reason="all checks ok",
        )
        assert d.verdict == GateVerdict.PASSED
        assert d.gate_name == "semantic_gate"
        assert d.strict_mode is True  # default
        assert d.elapsed_ms is None  # default

    def test_with_strict_mode_disabled(self) -> None:
        d = GateDecision(
            gate_name="safeguard",
            verdict=GateVerdict.BYPASSED,
            reason="strict mode disabled",
            strict_mode=False,
        )
        assert d.strict_mode is False
        assert d.verdict == GateVerdict.BYPASSED

    def test_with_elapsed(self) -> None:
        d = GateDecision(
            gate_name="transaction_engine",
            verdict=GateVerdict.PASSED,
            reason="ok",
            elapsed_ms=12.5,
        )
        assert d.elapsed_ms == 12.5


class TestGateAccounting:
    """K4.1: GateAccounting aggregation."""

    def test_empty_accounting(self) -> None:
        acct = GateAccounting()
        assert acct.passed_count == 0
        assert acct.failed_count == 0
        assert acct.bypassed_count == 0
        assert acct.all_passed is True  # vacuously true
        assert not acct.any_failed()

    def test_add_returns_new_instance(self) -> None:
        acct = GateAccounting()
        d = GateDecision("safeguard", GateVerdict.PASSED, "ok")
        acct2 = acct.add(d)
        assert len(acct.decisions) == 0  # original unchanged
        assert len(acct2.decisions) == 1

    def test_mixed_verdicts(self) -> None:
        decisions = (
            GateDecision("safeguard", GateVerdict.PASSED, "ok"),
            GateDecision("semantic_gate", GateVerdict.FAILED, "reachability=0.5<0.7"),
            GateDecision("contract", GateVerdict.BYPASSED, "projected check skipped"),
        )
        acct = GateAccounting(decisions=decisions)
        assert acct.passed_count == 1
        assert acct.failed_count == 1
        assert acct.bypassed_count == 1
        assert not acct.all_passed
        assert acct.any_failed()

    def test_all_passed(self) -> None:
        decisions = (
            GateDecision("safeguard", GateVerdict.PASSED, "ok"),
            GateDecision("semantic_gate", GateVerdict.PASSED, "ok"),
        )
        acct = GateAccounting(decisions=decisions)
        assert acct.all_passed
        assert not acct.any_failed()

    def test_any_failed_with_no_failures(self) -> None:
        decisions = (
            GateDecision("safeguard", GateVerdict.PASSED, "ok"),
            GateDecision("contract", GateVerdict.BYPASSED, "skipped"),
        )
        acct = GateAccounting(decisions=decisions)
        assert not acct.any_failed()

    def test_summary_format(self) -> None:
        decisions = (
            GateDecision("safeguard", GateVerdict.PASSED, "ok"),
            GateDecision("semantic_gate", GateVerdict.FAILED, "bad"),
            GateDecision("contract", GateVerdict.BYPASSED, "skipped"),
        )
        acct = GateAccounting(decisions=decisions)
        summary = acct.summary()
        assert "1 passed" in summary
        assert "1 failed" in summary
        assert "1 bypassed" in summary

    def test_serializable(self) -> None:
        acct = GateAccounting(decisions=(
            GateDecision("safeguard", GateVerdict.PASSED, "ok"),
        ))
        data = [
            {
                "gate": d.gate_name,
                "verdict": d.verdict.value,
                "reason": d.reason,
            }
            for d in acct.decisions
        ]
        serialized = json.dumps(data)
        assert '"verdict": "passed"' in serialized


class TestDecisionRecordWithGateAccounting:
    """K4.3: DecisionRecord carries gate_accounting."""

    def test_default_none(self) -> None:
        row = DecisionRecord(
            "A", FAMILY_DIRECT, DecisionPhase.APPLIED,
            DecisionReasonCode.ACCEPTED, "ok",
        )
        assert row.gate_accounting is None

    def test_with_accounting(self) -> None:
        acct = GateAccounting(decisions=(
            GateDecision("safeguard", GateVerdict.PASSED, "ok"),
            GateDecision("semantic_gate", GateVerdict.PASSED, "ok"),
        ))
        row = DecisionRecord(
            "A", FAMILY_DIRECT, DecisionPhase.APPLIED,
            DecisionReasonCode.ACCEPTED, "ok",
            gate_accounting=acct,
        )
        assert row.gate_accounting is not None
        assert row.gate_accounting.all_passed

    def test_update_phase_with_gate_accounting(self) -> None:
        """update_phase passes gate_accounting through to the new record."""
        rows = (
            DecisionRecord(
                "A", FAMILY_DIRECT, DecisionPhase.SELECTED,
                DecisionReasonCode.ACCEPTED, "selected",
            ),
        )
        prov = PipelineProvenance(rows=rows)
        acct = GateAccounting(decisions=(
            GateDecision("safeguard", GateVerdict.PASSED, "ok"),
            GateDecision("semantic_gate", GateVerdict.FAILED, "reachability low"),
        ))
        updated = prov.update_phase(
            "A",
            DecisionPhase.GATE_FAILED,
            reason_code=DecisionReasonCode.REJECTED_GATE,
            reason_detail="semantic gate failed",
            gate_accounting=acct,
        )
        assert updated.rows[0].gate_accounting is acct
        assert updated.rows[0].gate_accounting.any_failed()
        # Original unchanged
        assert prov.rows[0].gate_accounting is None


# ---------------------------------------------------------------------------
# K2: Hint-to-Decision Integration (PlannerInputs)
# ---------------------------------------------------------------------------


class TestPlannerInputs:
    """K2.1: PlannerInputs envelope creation and properties."""

    def test_creation_with_defaults(self) -> None:
        inputs = PlannerInputs(total_handlers=10)
        assert inputs.total_handlers == 10
        assert inputs.handler_transitions is None
        assert inputs.return_frontier is None
        assert inputs.terminal_return_audit is None
        assert inputs.has_handler_transitions is False
        assert inputs.has_return_frontier is False

    def test_creation_with_recon_data(self) -> None:
        transitions = object()  # stand-in for real recon type
        frontier = object()
        inputs = PlannerInputs(
            total_handlers=10,
            handler_transitions=transitions,
            return_frontier=frontier,
            terminal_return_audit=None,
            policy_overrides={"force_fallback": True},
        )
        assert inputs.has_handler_transitions is True
        assert inputs.has_return_frontier is True
        assert inputs.terminal_return_audit is None
        assert inputs.policy_overrides == {"force_fallback": True}

    def test_to_input_summary_no_data(self) -> None:
        inputs = PlannerInputs(total_handlers=10)
        summary = inputs.to_input_summary()
        assert isinstance(summary, DecisionInputSummary)
        assert summary.handler_transitions_available is False
        assert summary.return_frontier_available is False
        assert summary.terminal_return_audit_available is False
        assert summary.terminal_return_audit_summary == ""

    def test_to_input_summary_with_data(self) -> None:
        inputs = PlannerInputs(
            total_handlers=10,
            handler_transitions=object(),
        )
        summary = inputs.to_input_summary()
        assert summary.handler_transitions_available is True
        assert summary.return_frontier_available is False

    def test_to_input_summary_with_audit(self) -> None:
        class MockAudit:
            def summary(self) -> str:
                return "4/46 terminal: 4 shared, 0 direct"

        inputs = PlannerInputs(
            total_handlers=10,
            terminal_return_audit=MockAudit(),
        )
        summary = inputs.to_input_summary()
        assert summary.terminal_return_audit_available is True
        assert summary.terminal_return_audit_summary == "4/46 terminal: 4 shared, 0 direct"

    def test_to_input_summary_audit_without_summary_method(self) -> None:
        """Audit object without summary() method should produce empty string."""
        inputs = PlannerInputs(
            total_handlers=10,
            terminal_return_audit=object(),  # no summary() method
        )
        summary = inputs.to_input_summary()
        assert summary.terminal_return_audit_available is True
        assert summary.terminal_return_audit_summary == ""


class TestComposePipelineWithPlannerInputs:
    """K2.2: compose_pipeline accepts PlannerInputs."""

    def test_accepts_planner_inputs(self) -> None:
        planner = UnflatteningPlanner()
        inputs = PlannerInputs(total_handlers=10)
        frags = [_fragment("A")]
        pipeline, provenance = planner.compose_pipeline(frags, inputs=inputs)
        assert isinstance(provenance, PipelineProvenance)
        assert provenance.input_summary is not None
        assert provenance.input_summary.handler_transitions_available is False

    def test_input_summary_populated_from_planner_inputs(self) -> None:
        planner = UnflatteningPlanner()
        inputs = PlannerInputs(
            total_handlers=10,
            handler_transitions=object(),
        )
        frags = [_fragment("A")]
        pipeline, provenance = planner.compose_pipeline(frags, inputs=inputs)
        assert provenance.input_summary is not None
        assert provenance.input_summary.handler_transitions_available is True
        assert provenance.input_summary.return_frontier_available is False

    def test_no_inputs_defaults_to_zero_handlers(self) -> None:
        """Without inputs, effective_total_handlers defaults to 0."""
        planner = UnflatteningPlanner()
        frags = [_fragment("A")]
        pipeline, provenance = planner.compose_pipeline(frags)
        assert isinstance(provenance, PipelineProvenance)
        # No input_summary when inputs is None
        assert provenance.input_summary is None

    def test_planner_inputs_total_handlers_used_for_policy(self) -> None:
        """PlannerInputs.total_handlers drives the policy gate."""
        planner = UnflatteningPlanner()
        inputs = PlannerInputs(total_handlers=10)
        frags = [
            _fragment("primary1", family=FAMILY_DIRECT, handlers=9),
            _fragment("fallback1", family=FAMILY_FALLBACK, handlers=2),
        ]
        # 9/10 = 90% >= 80% threshold => fallback dropped
        pipeline, provenance = planner.compose_pipeline(frags, inputs=inputs)
        phases = {r.strategy_name: r.phase for r in provenance.rows}
        assert phases["fallback1"] == DecisionPhase.POLICY_FILTERED


# ---------------------------------------------------------------------------
# K5: Planner Ownership Inversion
# ---------------------------------------------------------------------------


class _MockStrategy:
    """Minimal strategy implementing UnflatteningStrategy protocol for tests."""

    def __init__(
        self,
        name: str,
        family: str = FAMILY_DIRECT,
        applicable: bool = True,
        fragment: PlanFragment | None = None,
        crash: Exception | None = None,
    ) -> None:
        self._name = name
        self._family = family
        self._applicable = applicable
        self._fragment = fragment
        self._crash = crash

    @property
    def name(self) -> str:
        return self._name

    @property
    def family(self) -> str:
        return self._family

    def is_applicable(self, snapshot: object) -> bool:
        return self._applicable

    def plan(self, snapshot: object) -> PlanFragment | None:
        if self._crash is not None:
            raise self._crash
        return self._fragment


class _FakeSnapshot:
    """Minimal stand-in for AnalysisSnapshot (no optimizer imports needed)."""

    def __init__(self, handler_count: int = 10) -> None:
        self._handler_count = handler_count

    @property
    def handler_count(self) -> int:
        return self._handler_count


def _make_snapshot(handler_count: int = 10) -> object:
    """Build a minimal stand-in for AnalysisSnapshot (no IDA dependency)."""
    return _FakeSnapshot(handler_count=handler_count)


class TestPlannerPlan:
    """K5.1: planner.plan() owns strategy polling + compose_pipeline."""

    def test_plan_calls_strategies_and_composes(self) -> None:
        """plan() polls strategies and returns pipeline + provenance."""
        planner = UnflatteningPlanner()
        frag_a = _fragment("A", handlers=5)
        strategies = [
            _MockStrategy("A", fragment=frag_a),
        ]
        snapshot = _make_snapshot(handler_count=10)
        inputs = PlannerInputs(total_handlers=10)
        pipeline, provenance = planner.plan(snapshot, strategies, inputs=inputs)
        assert len(pipeline) == 1
        assert pipeline[0].strategy_name == "A"
        assert isinstance(provenance, PipelineProvenance)
        assert provenance.accepted_count >= 1

    def test_inapplicable_recorded_in_provenance(self) -> None:
        """Strategies returning is_applicable=False appear as INAPPLICABLE."""
        planner = UnflatteningPlanner()
        strategies = [
            _MockStrategy("Skipped", applicable=False),
            _MockStrategy("Active", fragment=_fragment("Active", handlers=5)),
        ]
        snapshot = _make_snapshot(handler_count=10)
        pipeline, provenance = planner.plan(snapshot, strategies)
        phases = {r.strategy_name: r.phase for r in provenance.rows}
        assert phases["Skipped"] == DecisionPhase.INAPPLICABLE
        reason_codes = {r.strategy_name: r.reason_code for r in provenance.rows}
        assert reason_codes["Skipped"] == DecisionReasonCode.REJECTED_INAPPLICABLE

    def test_crashed_recorded_in_provenance(self) -> None:
        """Strategies that raise during plan() appear as CRASHED."""
        planner = UnflatteningPlanner()
        strategies = [
            _MockStrategy("Broken", crash=ValueError("test crash")),
            _MockStrategy("OK", fragment=_fragment("OK", handlers=5)),
        ]
        snapshot = _make_snapshot(handler_count=10)
        pipeline, provenance = planner.plan(snapshot, strategies)
        phases = {r.strategy_name: r.phase for r in provenance.rows}
        assert phases["Broken"] == DecisionPhase.CRASHED
        reason_codes = {r.strategy_name: r.reason_code for r in provenance.rows}
        assert reason_codes["Broken"] == DecisionReasonCode.REJECTED_CRASHED
        # Notes should contain the exception message
        notes = {r.strategy_name: r.notes for r in provenance.rows}
        assert "test crash" in notes["Broken"]

    def test_pre_planner_records_prepended(self) -> None:
        """INAPPLICABLE/CRASHED records appear before planner composition rows."""
        planner = UnflatteningPlanner()
        strategies = [
            _MockStrategy("Skip1", applicable=False),
            _MockStrategy("Active", fragment=_fragment("Active", handlers=5)),
        ]
        snapshot = _make_snapshot(handler_count=10)
        pipeline, provenance = planner.plan(snapshot, strategies)
        # INAPPLICABLE should come first in rows
        assert provenance.rows[0].phase == DecisionPhase.INAPPLICABLE
        assert provenance.rows[0].strategy_name == "Skip1"

    def test_empty_strategies_returns_empty_pipeline(self) -> None:
        """No applicable strategies => empty pipeline, only INAPPLICABLE rows."""
        planner = UnflatteningPlanner()
        strategies = [
            _MockStrategy("S1", applicable=False),
            _MockStrategy("S2", applicable=False),
        ]
        snapshot = _make_snapshot(handler_count=10)
        pipeline, provenance = planner.plan(snapshot, strategies)
        assert pipeline == []
        assert provenance.accepted_count == 0
        inapplicable = [r for r in provenance.rows if r.phase == DecisionPhase.INAPPLICABLE]
        assert len(inapplicable) == 2

    def test_compose_pipeline_still_accessible(self) -> None:
        """compose_pipeline remains callable as an internal method."""
        planner = UnflatteningPlanner()
        frags = [_fragment("X", handlers=5)]
        pipeline, provenance = planner.compose_pipeline(frags, inputs=PlannerInputs(total_handlers=10))
        assert len(pipeline) == 1
        assert isinstance(provenance, PipelineProvenance)

    def test_plan_with_planner_inputs(self) -> None:
        """plan() passes PlannerInputs through to compose_pipeline."""
        planner = UnflatteningPlanner()
        strategies = [
            _MockStrategy("A", fragment=_fragment("A", handlers=5)),
        ]
        snapshot = _make_snapshot(handler_count=10)
        inputs = PlannerInputs(
            total_handlers=10,
            handler_transitions=object(),
        )
        pipeline, provenance = planner.plan(snapshot, strategies, inputs=inputs)
        assert provenance.input_summary is not None
        assert provenance.input_summary.handler_transitions_available is True

    def test_plan_without_inputs(self) -> None:
        """plan() works without PlannerInputs (defaults to None)."""
        planner = UnflatteningPlanner()
        strategies = [
            _MockStrategy("A", fragment=_fragment("A", handlers=5)),
        ]
        snapshot = _make_snapshot(handler_count=10)
        pipeline, provenance = planner.plan(snapshot, strategies)
        assert len(pipeline) == 1
        assert provenance.input_summary is None

    def test_plan_filters_none_fragments(self) -> None:
        """Strategies returning None from plan() are silently skipped."""
        planner = UnflatteningPlanner()
        strategies = [
            _MockStrategy("Returns_None", applicable=True, fragment=None),
            _MockStrategy("Real", fragment=_fragment("Real", handlers=5)),
        ]
        snapshot = _make_snapshot(handler_count=10)
        pipeline, provenance = planner.plan(snapshot, strategies)
        assert len(pipeline) == 1
        assert pipeline[0].strategy_name == "Real"
