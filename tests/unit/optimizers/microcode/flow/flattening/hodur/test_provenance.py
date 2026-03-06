"""Tests for Hodur decision provenance types (K1.1) and planner instrumentation (K1.2)."""
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
    PipelineProvenance,
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
        pipeline, provenance = planner.compose_pipeline(frags, total_handlers=10)
        assert isinstance(provenance, PipelineProvenance)
        assert provenance.accepted_count >= 1
        verdicts = {r.strategy_name: r.reason_code for r in provenance.rows}
        assert verdicts["B"] == DecisionReasonCode.REJECTED_RISK

    def test_empty_filter_provenance(self) -> None:
        """Fragments with no modifications get INAPPLICABLE / REJECTED_EMPTY."""
        planner = UnflatteningPlanner()
        frags = [_fragment("empty_one", empty=True), _fragment("real_one")]
        pipeline, provenance = planner.compose_pipeline(frags, total_handlers=10)
        assert len(pipeline) == 1
        assert pipeline[0].strategy_name == "real_one"
        verdicts = {r.strategy_name: r for r in provenance.rows}
        assert verdicts["empty_one"].phase == DecisionPhase.INAPPLICABLE
        assert verdicts["empty_one"].reason_code == DecisionReasonCode.REJECTED_EMPTY

    def test_risk_filter_provenance(self) -> None:
        """Fragments exceeding risk threshold get POLICY_FILTERED / REJECTED_RISK."""
        planner = UnflatteningPlanner(PipelinePolicy(max_risk_score=0.5))
        frags = [_fragment("safe", risk=0.3), _fragment("risky", risk=0.8)]
        pipeline, provenance = planner.compose_pipeline(frags, total_handlers=10)
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
        pipeline, provenance = planner.compose_pipeline(frags, total_handlers=10)
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
        pipeline, provenance = planner.compose_pipeline(frags, total_handlers=10)
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
        pipeline, provenance = planner.compose_pipeline(frags, total_handlers=10)
        assert len(pipeline) == 2
        for row in provenance.rows:
            if row.phase == DecisionPhase.SELECTED:
                assert row.reason_code == DecisionReasonCode.ACCEPTED

    def test_provenance_handler_and_transition_counts(self) -> None:
        """DecisionRecord carries handler_count and transition_count from benefit."""
        planner = UnflatteningPlanner()
        frags = [_fragment("A", handlers=7, transitions=12)]
        pipeline, provenance = planner.compose_pipeline(frags, total_handlers=10)
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
        _pipeline, provenance = planner.compose_pipeline(frags, total_handlers=10)
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
        pipeline, provenance = planner.compose_pipeline(frags, total_handlers=10)
        assert len(pipeline) == 1
        verdicts = {r.strategy_name: r for r in provenance.rows}
        assert verdicts["fb1"].phase == DecisionPhase.POLICY_FILTERED
        assert verdicts["fb1"].reason_code == DecisionReasonCode.REJECTED_POLICY

    def test_no_fragments_returns_empty_provenance(self) -> None:
        """Empty input produces empty pipeline and provenance."""
        planner = UnflatteningPlanner()
        pipeline, provenance = planner.compose_pipeline([], total_handlers=10)
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
