"""Tests for K6: Planner hint signals (recon-driven scoring)."""
from __future__ import annotations

from types import SimpleNamespace

from d810.cfg.flow.terminal_return import (
    TerminalReturnAuditReport,
    TerminalReturnSiteAudit,
    TerminalReturnSourceKind,
)
from d810.cfg.graph_modification import RedirectGoto
from d810.optimizers.microcode.flow.flattening.hodur.planner import (
    HintAdjustment,
    PipelinePolicy,
    PlannerHintSignals,
    UnflatteningPlanner,
    compute_hint_adjustment,
    derive_hint_signals,
)
from d810.optimizers.microcode.flow.flattening.hodur.provenance import (
    DecisionPhase,
    PipelineProvenance,
    PlannerInputs,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    BenefitMetrics,
    FAMILY_CLEANUP,
    FAMILY_DIRECT,
    FAMILY_FALLBACK,
    OwnershipScope,
    PlanFragment,
)

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


def _transition_report(
    *,
    handlers_total: int,
    known_count: int,
    conditional_count: int = 0,
    exit_count: int = 0,
    unknown_count: int = 0,
) -> object:
    """Build a minimal transition report stub with summary fields."""
    return SimpleNamespace(
        summary=SimpleNamespace(
            handlers_total=handlers_total,
            known_count=known_count,
            conditional_count=conditional_count,
            exit_count=exit_count,
            unknown_count=unknown_count,
        )
    )


def _return_frontier_audit(*, total_sites: int, broken_count: int) -> object:
    """Build a minimal return-frontier audit stub with report()."""
    return SimpleNamespace(
        report=lambda: {
            "total_sites": total_sites,
            "broken_count": broken_count,
        }
    )


def _terminal_return_audit(*sites: TerminalReturnSiteAudit) -> TerminalReturnAuditReport:
    """Build a minimal terminal return audit report."""
    return TerminalReturnAuditReport(
        function_ea=0x180000000,
        total_handlers=10,
        terminal_handlers=len(sites),
        sites=sites,
    )


# ---------------------------------------------------------------------------
# derive_hint_signals
# ---------------------------------------------------------------------------


class TestDeriveHintSignals:
    """Tests for derive_hint_signals()."""

    def test_no_inputs_means_zero_signals(self) -> None:
        """derive_hint_signals(None) returns all-zero signals."""
        signals = derive_hint_signals(None)
        assert signals.transition_confidence == 0.0
        assert signals.return_frontier_risk == 0.0
        assert signals.terminal_return_risk == 0.0

    def test_with_transitions(self) -> None:
        inputs = PlannerInputs(
            total_handlers=10,
            handler_transitions=_transition_report(
                handlers_total=10,
                known_count=8,
            ),
        )
        signals = derive_hint_signals(inputs)
        assert signals.transition_confidence == 0.8

    def test_with_return_frontier(self) -> None:
        inputs = PlannerInputs(
            total_handlers=10,
            return_frontier=_return_frontier_audit(total_sites=4, broken_count=2),
        )
        signals = derive_hint_signals(inputs)
        assert signals.return_frontier_risk == 0.5

    def test_with_terminal_return_audit(self) -> None:
        inputs = PlannerInputs(
            total_handlers=10,
            terminal_return_audit=_terminal_return_audit(
                TerminalReturnSiteAudit(
                    handler_serial=26,
                    exit_serial=219,
                    source_kind=TerminalReturnSourceKind.SHARED_EPILOGUE,
                    has_rax_write=False,
                ),
                TerminalReturnSiteAudit(
                    handler_serial=93,
                    exit_serial=219,
                    source_kind=TerminalReturnSourceKind.EPILOGUE_CORRIDOR,
                    has_rax_write=True,
                ),
            ),
        )
        signals = derive_hint_signals(inputs)
        assert signals.terminal_return_risk == 0.75

    def test_empty_inputs_means_zero_signals(self) -> None:
        """PlannerInputs with no recon data gives all-zero signals."""
        inputs = PlannerInputs(total_handlers=10)
        signals = derive_hint_signals(inputs)
        assert signals.transition_confidence == 0.0
        assert signals.return_frontier_risk == 0.0
        assert signals.terminal_return_risk == 0.0


# ---------------------------------------------------------------------------
# compute_hint_adjustment
# ---------------------------------------------------------------------------


class TestComputeHintAdjustment:
    """Tests for compute_hint_adjustment()."""

    def test_no_inputs_means_zero_adjustment(self) -> None:
        """Zero signals produce zero adjustment for any fragment."""
        frag = _fragment("A", family=FAMILY_DIRECT)
        signals = PlannerHintSignals()
        adj = compute_hint_adjustment(frag, signals)
        assert adj.score_delta == 0.0
        assert adj.reasons == ()

    def test_transition_confidence_boosts_direct(self) -> None:
        """Direct-family fragment gets +bonus with transitions available."""
        frag = _fragment("A", family=FAMILY_DIRECT)
        signals = PlannerHintSignals(transition_confidence=0.8)
        adj = compute_hint_adjustment(frag, signals)
        expected_bonus = 2.0 * 0.8
        assert adj.score_delta == expected_bonus
        assert "transition_report_boost" in adj.reasons

    def test_transition_confidence_no_boost_for_fallback(self) -> None:
        """Fallback-family fragment does NOT get transition boost."""
        frag = _fragment("A", family=FAMILY_FALLBACK)
        signals = PlannerHintSignals(transition_confidence=0.8)
        adj = compute_hint_adjustment(frag, signals)
        assert adj.score_delta == 0.0
        assert "transition_report_boost" not in adj.reasons

    def test_return_frontier_risk_penalizes(self) -> None:
        """All fragments get -penalty when return_frontier risk > 0.3."""
        frag = _fragment("A", family=FAMILY_DIRECT)
        signals = PlannerHintSignals(return_frontier_risk=0.5)
        adj = compute_hint_adjustment(frag, signals)
        expected_penalty = -1.5 * 0.5
        assert adj.score_delta == expected_penalty
        assert "return_frontier_penalty" in adj.reasons

    def test_return_frontier_risk_no_penalty_below_threshold(self) -> None:
        """No penalty when return_frontier_risk <= 0.3."""
        frag = _fragment("A", family=FAMILY_DIRECT)
        signals = PlannerHintSignals(return_frontier_risk=0.2)
        adj = compute_hint_adjustment(frag, signals)
        assert adj.score_delta == 0.0
        assert "return_frontier_penalty" not in adj.reasons

    def test_terminal_return_risk_penalizes_cleanup(self) -> None:
        """Cleanup-family fragment gets -penalty when terminal_return_risk > 0.3."""
        frag = _fragment("A", family=FAMILY_CLEANUP)
        signals = PlannerHintSignals(terminal_return_risk=0.5)
        adj = compute_hint_adjustment(frag, signals)
        expected_penalty = -1.0 * 0.5
        assert adj.score_delta == expected_penalty
        assert "terminal_return_penalty" in adj.reasons

    def test_terminal_return_risk_no_penalty_for_direct(self) -> None:
        """Direct-family fragment does NOT get terminal_return penalty."""
        frag = _fragment("A", family=FAMILY_DIRECT)
        signals = PlannerHintSignals(terminal_return_risk=0.5)
        adj = compute_hint_adjustment(frag, signals)
        assert adj.score_delta == 0.0
        assert "terminal_return_penalty" not in adj.reasons

    def test_multiple_adjustments_combine(self) -> None:
        """When multiple signals fire, deltas and reasons accumulate."""
        frag = _fragment("A", family=FAMILY_DIRECT)
        signals = PlannerHintSignals(
            transition_confidence=0.8,
            return_frontier_risk=0.5,
        )
        adj = compute_hint_adjustment(frag, signals)
        expected = (2.0 * 0.8) + (-1.5 * 0.5)
        assert abs(adj.score_delta - expected) < 1e-9
        assert "transition_report_boost" in adj.reasons
        assert "return_frontier_penalty" in adj.reasons


# ---------------------------------------------------------------------------
# Integration: hint signals change conflict winner
# ---------------------------------------------------------------------------


class TestHintChangesConflictWinner:
    """K6: Verify hint signals can alter conflict resolution outcomes."""

    def test_hint_changes_conflict_winner(self) -> None:
        """Fragment A has higher base score, but B gets transition boost and wins."""
        shared = frozenset({1, 2, 3})
        ownership = OwnershipScope(
            blocks=shared, edges=frozenset(), transitions=frozenset(),
        )
        # A: direct, handlers=4 => composite = 4*3 = 12.0
        frag_a = _fragment("A", family=FAMILY_DIRECT, handlers=4, ownership=ownership)
        # B: direct, handlers=3 => composite = 3*3 = 9.0
        frag_b = _fragment("B", family=FAMILY_DIRECT, handlers=3, ownership=ownership)

        # Without hints, A wins (12.0 > 9.0)
        planner = UnflatteningPlanner()
        pipeline_no_hints, _ = planner.compose_pipeline(
            [frag_a, frag_b], inputs=PlannerInputs(total_handlers=10),
        )
        assert len(pipeline_no_hints) == 1
        assert pipeline_no_hints[0].strategy_name == "A"

        # With hints (transition boost: +2.0*0.8 = +1.6):
        # A effective = 12.0 + 1.6 = 13.6
        # B effective = 9.0 + 1.6 = 10.6
        # A still wins with same boost — need asymmetric setup.
        # Make B have higher handlers so boost tips it over:
        # A: handlers=3 => composite=9.0, B: handlers=2, transitions=3 => composite=6+6=12
        # Actually let's use a cleaner setup:
        # A: fallback (no boost), handlers=4 => 12.0
        # B: direct (gets boost), handlers=3 => 9.0 + 1.6 = 10.6
        # A still > B. Need bigger gap.
        # A: fallback, handlers=4 => 12.0
        # B: direct, handlers=3, transitions=1 => 9+2=11.0 + 1.6 = 12.6
        frag_a2 = _fragment(
            "A", family=FAMILY_FALLBACK, handlers=4, ownership=ownership,
        )
        frag_b2 = _fragment(
            "B", family=FAMILY_DIRECT, handlers=3, transitions=1,
            ownership=ownership,
        )

        # Without hints: A=12.0, B=11.0 => A wins
        pipeline_no, _ = planner.compose_pipeline(
            [frag_a2, frag_b2], inputs=PlannerInputs(total_handlers=10),
        )
        assert len(pipeline_no) == 1
        assert pipeline_no[0].strategy_name == "A"

        # With hints (transition boost on B only): B=11.0+1.6=12.6, A=12.0 => B wins
        inputs = PlannerInputs(
            total_handlers=10,
            handler_transitions=_transition_report(
                handlers_total=10,
                known_count=8,
            ),
        )
        pipeline_hints, _ = planner.compose_pipeline(
            [frag_a2, frag_b2], inputs=inputs,
        )
        assert len(pipeline_hints) == 1
        assert pipeline_hints[0].strategy_name == "B"


class TestHintChangesOrdering:
    """K6: Verify hint signals can alter fragment ordering."""

    def test_hint_changes_ordering(self) -> None:
        """Without hints A ordered first; with hints B ordered first."""
        # Non-overlapping ownership so both survive conflict resolution
        frag_a = _fragment(
            "A", family=FAMILY_FALLBACK, handlers=4,
            ownership=OwnershipScope(
                blocks=frozenset({1}), edges=frozenset(), transitions=frozenset(),
            ),
        )  # composite = 12.0
        frag_b = _fragment(
            "B", family=FAMILY_DIRECT, handlers=3, transitions=1,
            ownership=OwnershipScope(
                blocks=frozenset({2}), edges=frozenset(), transitions=frozenset(),
            ),
        )  # composite = 11.0

        planner = UnflatteningPlanner()

        # Without hints: A(12.0) > B(11.0)
        pipeline_no, _ = planner.compose_pipeline(
            [frag_a, frag_b], inputs=PlannerInputs(total_handlers=10),
        )
        assert pipeline_no[0].strategy_name == "A"
        assert pipeline_no[1].strategy_name == "B"

        # With hints: B gets +1.6 => 12.6 > A=12.0
        inputs = PlannerInputs(
            total_handlers=10,
            handler_transitions=_transition_report(
                handlers_total=10,
                known_count=8,
            ),
        )
        pipeline_hints, _ = planner.compose_pipeline(
            [frag_a, frag_b], inputs=inputs,
        )
        assert pipeline_hints[0].strategy_name == "B"
        assert pipeline_hints[1].strategy_name == "A"


# ---------------------------------------------------------------------------
# Provenance: hint fields recorded
# ---------------------------------------------------------------------------


class TestProvenanceRecordsHintFields:
    """K6: Verify provenance carries hint scoring data."""

    def test_provenance_records_hint_fields(self) -> None:
        """base_score, hint_delta, effective_score, hint_reasons all populated."""
        planner = UnflatteningPlanner()
        frag = _fragment("A", family=FAMILY_DIRECT, handlers=5)
        # composite = 5*3 = 15.0
        inputs = PlannerInputs(
            total_handlers=10,
            handler_transitions=_transition_report(
                handlers_total=10,
                known_count=8,
            ),
        )
        pipeline, provenance = planner.compose_pipeline([frag], inputs=inputs)
        assert len(pipeline) == 1

        selected = [r for r in provenance.rows if r.phase == DecisionPhase.SELECTED]
        assert len(selected) == 1
        row = selected[0]
        assert row.base_score == 15.0
        assert row.hint_score_delta == 2.0 * 0.8  # transition_confidence=0.8
        assert row.effective_score == 15.0 + 2.0 * 0.8
        assert "transition_report_boost" in row.hint_reasons

    def test_provenance_no_hints_zero_delta(self) -> None:
        """Without inputs, hint_score_delta is 0 and effective equals base."""
        planner = UnflatteningPlanner()
        frag = _fragment("A", family=FAMILY_DIRECT, handlers=5)
        # composite = 5*3 = 15.0
        pipeline, provenance = planner.compose_pipeline([frag], inputs=PlannerInputs(total_handlers=10))
        selected = [r for r in provenance.rows if r.phase == DecisionPhase.SELECTED]
        assert len(selected) == 1
        row = selected[0]
        assert row.base_score == 15.0
        assert row.hint_score_delta == 0.0
        assert row.effective_score == 15.0
        assert row.hint_reasons == ()

    def test_provenance_serialization_includes_hints(self) -> None:
        """to_dict() includes hint fields when non-zero."""
        planner = UnflatteningPlanner()
        frag = _fragment("A", family=FAMILY_DIRECT, handlers=5)
        inputs = PlannerInputs(
            total_handlers=10,
            handler_transitions=_transition_report(
                handlers_total=10,
                known_count=8,
            ),
        )
        _, provenance = planner.compose_pipeline([frag], inputs=inputs)
        d = provenance.to_dict()
        row_dict = d["rows"][0]
        assert "base_score" in row_dict
        assert "hint_score_delta" in row_dict
        assert "effective_score" in row_dict
        assert "hint_reasons" in row_dict
        assert row_dict["hint_reasons"] == ["transition_report_boost"]
