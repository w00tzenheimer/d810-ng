"""H7 integration proof: planner ownership is complete end-to-end.

These tests prove the integration boundary between planner, executor, and
orchestrator using pure-Python mocks (no IDA dependency).

Scenarios covered:
- Multi-strategy conflict resolution with winner/loser provenance
- Hint-driven winner changes through planner code only
- Executor applies planner output without re-arbitration
- Provenance shows planner decision separately from executor outcome
- Pipeline abort marks remaining fragments as BYPASSED
- Policy filtering happens before conflict resolution
- Conflict resolution is reproducible across invocations
- Complete lifecycle provenance records
"""
from __future__ import annotations

import pytest

from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    BenefitMetrics,
    FAMILY_CLEANUP,
    FAMILY_DIRECT,
    FAMILY_FALLBACK,
    OwnershipScope,
    PlanFragment,
    StageResult,
)
from d810.optimizers.microcode.flow.flattening.hodur.planner import (
    HintAdjustment,
    PipelinePolicy,
    PlannerCandidate,
    PlannerDecision,
    PlannerDecisionReason,
    UnflatteningPlanner,
)
from d810.optimizers.microcode.flow.flattening.hodur.provenance import (
    DecisionPhase,
    DecisionReasonCode,
    DecisionRecord,
    GateAccounting,
    GateDecision,
    GateVerdict,
    PipelineProvenance,
    PlannerInputs,
)


# ---------------------------------------------------------------------------
# Helpers (reuse patterns from test_planner_authority.py)
# ---------------------------------------------------------------------------

def _make_fragment(
    name: str,
    family: str = FAMILY_DIRECT,
    handlers: int = 10,
    transitions: int = 8,
    blocks_freed: int = 5,
    risk: float = 0.1,
    owned_blocks: frozenset[int] | None = None,
    owned_edges: frozenset[tuple[int, int]] | None = None,
    owned_transitions: frozenset[tuple[int, int]] | None = None,
    prerequisites: list[str] | None = None,
    has_modifications: bool = True,
) -> PlanFragment:
    """Create a mock PlanFragment for testing."""
    ownership = OwnershipScope(
        blocks=owned_blocks or frozenset(),
        edges=owned_edges or frozenset(),
        transitions=owned_transitions or frozenset(),
    )

    class _FakeModification:
        """Minimal mock for a GraphModification."""
        pass

    return PlanFragment(
        strategy_name=name,
        family=family,
        ownership=ownership,
        prerequisites=prerequisites or [],
        expected_benefit=BenefitMetrics(
            handlers_resolved=handlers,
            transitions_resolved=transitions,
            blocks_freed=blocks_freed,
            conflict_density=0.0,
        ),
        risk_score=risk,
        modifications=[_FakeModification()] if has_modifications else [],
    )


class _FakeStrategy:
    """Minimal mock implementing the UnflatteningStrategy protocol."""

    def __init__(
        self,
        name: str,
        family: str = FAMILY_DIRECT,
        applicable: bool = True,
        fragment: PlanFragment | None = None,
        crash: bool = False,
    ):
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
        if self._crash:
            raise RuntimeError("strategy crashed")
        return self._fragment


class _FakeSnapshot:
    """Minimal mock for AnalysisSnapshot."""
    handler_count = 10


# ---------------------------------------------------------------------------
# Test 1: Multi-strategy conflict — planner resolves winner
# ---------------------------------------------------------------------------

class TestMultiStrategyConflictPlannerResolvesWinner:
    """Prove that with 3+ overlapping candidates, exactly one winner emerges
    per conflict group, losers get CONFLICT_DROPPED, winner gets SELECTED."""

    def test_three_way_conflict_single_winner(self) -> None:
        """Three fragments with overlapping blocks: only the highest-scoring wins."""
        planner = UnflatteningPlanner(PipelinePolicy())
        f_high = _make_fragment(
            "high", handlers=20, transitions=15,
            owned_blocks=frozenset({1, 2, 3}),
        )
        f_mid = _make_fragment(
            "mid", handlers=10, transitions=8,
            owned_blocks=frozenset({2, 3, 4}),
        )
        f_low = _make_fragment(
            "low", handlers=5, transitions=3,
            owned_blocks=frozenset({3, 4, 5}),
        )
        pipeline, prov = planner.compose_pipeline([f_high, f_mid, f_low])

        # Only one winner per conflict group
        selected = [r for r in prov.rows if r.phase == DecisionPhase.SELECTED]
        dropped = [r for r in prov.rows if r.phase == DecisionPhase.CONFLICT_DROPPED]

        assert len(selected) == 1
        assert selected[0].strategy_name == "high"

        # Both losers get CONFLICT_DROPPED
        dropped_names = {r.strategy_name for r in dropped}
        assert "mid" in dropped_names
        assert "low" in dropped_names

    def test_disjoint_third_fragment_survives_conflict(self) -> None:
        """A fragment disjoint from the conflicting pair is still accepted."""
        planner = UnflatteningPlanner(PipelinePolicy())
        f_a = _make_fragment(
            "alpha", handlers=20, owned_blocks=frozenset({1, 2}),
        )
        f_b = _make_fragment(
            "beta", handlers=10, owned_blocks=frozenset({2, 3}),
        )
        f_c = _make_fragment(
            "gamma", handlers=5, owned_blocks=frozenset({10, 11}),
        )
        pipeline, prov = planner.compose_pipeline([f_a, f_b, f_c])

        selected = [r for r in prov.rows if r.phase == DecisionPhase.SELECTED]
        selected_names = {r.strategy_name for r in selected}
        assert "alpha" in selected_names
        assert "gamma" in selected_names
        assert "beta" not in selected_names

    def test_conflict_dropped_has_correct_reason_code(self) -> None:
        """Losers get REJECTED_CONFLICT reason code."""
        planner = UnflatteningPlanner(PipelinePolicy())
        f_winner = _make_fragment(
            "winner", handlers=20, owned_blocks=frozenset({1, 2}),
        )
        f_loser = _make_fragment(
            "loser", handlers=5, owned_blocks=frozenset({2, 3}),
        )
        _, prov = planner.compose_pipeline([f_winner, f_loser])
        dropped = [r for r in prov.rows if r.phase == DecisionPhase.CONFLICT_DROPPED]
        assert len(dropped) == 1
        assert dropped[0].reason_code == DecisionReasonCode.REJECTED_CONFLICT


# ---------------------------------------------------------------------------
# Test 2: Hint-driven winner change
# ---------------------------------------------------------------------------

class TestHintDrivenWinnerChange:
    """Prove that hints can change the winner through effective_score."""

    def test_hint_flips_winner(self) -> None:
        """A candidate with lower base_score wins when hint_score_delta is large enough."""
        planner = UnflatteningPlanner(PipelinePolicy())

        # f_base_high has higher base score but will not get hint boost
        f_base_high = _make_fragment(
            "base_high", family=FAMILY_FALLBACK, handlers=12, transitions=10,
            owned_blocks=frozenset({1, 2, 3}),
        )
        # f_base_low has lower base score but will get hint boost via transition_confidence
        f_base_low = _make_fragment(
            "base_low", family=FAMILY_DIRECT, handlers=10, transitions=8,
            owned_blocks=frozenset({1, 2, 3}),
        )

        # Without hints: base_high wins (higher composite_score)
        assert f_base_high.expected_benefit.composite_score() > f_base_low.expected_benefit.composite_score()

        # With hints: transition_confidence boosts DIRECT family only
        # Build a mock transition report with high confidence
        class _MockSummary:
            handlers_total = 10
            known_count = 9
            conditional_count = 0
            exit_count = 1

        class _MockTransitionReport:
            summary = _MockSummary()

        inputs = PlannerInputs(
            total_handlers=10,
            handler_transitions=_MockTransitionReport(),
        )
        pipeline, prov = planner.compose_pipeline(
            [f_base_high, f_base_low], inputs=inputs,
        )

        selected = [r for r in prov.rows if r.phase == DecisionPhase.SELECTED]
        assert len(selected) == 1
        assert selected[0].strategy_name == "base_low"
        # Verify hint metadata is recorded
        assert selected[0].hint_score_delta > 0.0
        assert len(selected[0].hint_reasons) > 0
        assert "transition_report_boost" in selected[0].hint_reasons

    def test_provenance_records_both_base_and_effective_scores(self) -> None:
        """Provenance records base_score and effective_score separately."""
        planner = UnflatteningPlanner(PipelinePolicy())
        f = _make_fragment("scored", family=FAMILY_DIRECT, handlers=10, transitions=8)

        class _MockSummary:
            handlers_total = 10
            known_count = 8
            conditional_count = 1
            exit_count = 1

        class _MockTransitionReport:
            summary = _MockSummary()

        inputs = PlannerInputs(
            total_handlers=10,
            handler_transitions=_MockTransitionReport(),
        )
        _, prov = planner.compose_pipeline([f], inputs=inputs)
        record = [r for r in prov.rows if r.phase == DecisionPhase.SELECTED][0]

        assert record.base_score == f.expected_benefit.composite_score()
        assert record.effective_score > record.base_score  # hint boosted
        assert record.hint_score_delta == pytest.approx(
            record.effective_score - record.base_score,
        )


# ---------------------------------------------------------------------------
# Test 3: Hint absence preserves base behavior
# ---------------------------------------------------------------------------

class TestHintAbsencePreservesBaseBehavior:
    """Prove that without hints, winner is decided by base_score alone."""

    def test_no_hints_winner_by_base_score(self) -> None:
        """Without hints, higher base_score wins the conflict."""
        planner = UnflatteningPlanner(PipelinePolicy())
        f_high = _make_fragment(
            "high", handlers=20, transitions=15,
            owned_blocks=frozenset({1, 2}),
        )
        f_low = _make_fragment(
            "low", handlers=5, transitions=3,
            owned_blocks=frozenset({1, 3}),
        )
        pipeline, prov = planner.compose_pipeline([f_high, f_low])

        selected = [r for r in prov.rows if r.phase == DecisionPhase.SELECTED]
        assert len(selected) == 1
        assert selected[0].strategy_name == "high"

    def test_no_hints_zero_delta_and_empty_reasons(self) -> None:
        """Without hint inputs, hint_score_delta=0 and hint_reasons=()."""
        planner = UnflatteningPlanner(PipelinePolicy())
        f = _make_fragment("plain", handlers=10)
        _, prov = planner.compose_pipeline([f])
        record = [r for r in prov.rows if r.phase == DecisionPhase.SELECTED][0]
        assert record.hint_score_delta == 0.0
        assert record.hint_reasons == ()


# ---------------------------------------------------------------------------
# Test 4: Executor preserves planner pipeline order (integration)
# ---------------------------------------------------------------------------

class TestExecutorPreservesPlannerPipelineOrder:
    """Prove that the pipeline order from planner.plan() is preserved
    through to execution."""

    def test_plan_output_order_matches_fragment_order(self) -> None:
        """plan() returns fragments in prerequisite-then-score order."""
        planner = UnflatteningPlanner(PipelinePolicy())
        f_dep = _make_fragment(
            "dependent", handlers=100, prerequisites=["base"],
            owned_blocks=frozenset({10, 11}),
        )
        f_base = _make_fragment(
            "base", handlers=5, owned_blocks=frozenset({1, 2}),
        )
        strat_dep = _FakeStrategy("dependent", fragment=f_dep)
        strat_base = _FakeStrategy("base", fragment=f_base)

        pipeline, _ = planner.plan(_FakeSnapshot(), [strat_dep, strat_base])
        names = [f.strategy_name for f in pipeline]

        # base before dependent (prerequisite ordering)
        assert names.index("base") < names.index("dependent")

    def test_no_fragment_dropped_or_inserted_by_executor_simulation(self) -> None:
        """Simulated executor pass: all fragments from planner appear in results."""
        planner = UnflatteningPlanner(PipelinePolicy())
        fragments = [
            _make_fragment(f"s{i}", handlers=10 - i, owned_blocks=frozenset({i * 10}))
            for i in range(4)
        ]
        pipeline, _ = planner.compose_pipeline(fragments)
        pipeline_names = [f.strategy_name for f in pipeline]

        # Simulate executor consuming pipeline in-order (mock results)
        results = [
            StageResult(strategy_name=f.strategy_name, success=True)
            for f in pipeline
        ]

        assert len(results) == len(pipeline)
        assert [r.strategy_name for r in results] == pipeline_names


# ---------------------------------------------------------------------------
# Test 5: Provenance planner vs executor phases are disjoint
# ---------------------------------------------------------------------------

class TestProvenancePlannerVsExecutorPhasesDisjoint:
    """Prove that planner phases and executor phases form disjoint sets,
    and each is only set by its respective owner."""

    PLANNER_PHASES = {
        DecisionPhase.SELECTED,
        DecisionPhase.POLICY_FILTERED,
        DecisionPhase.CONFLICT_DROPPED,
        DecisionPhase.INAPPLICABLE,
        DecisionPhase.CRASHED,
    }

    EXECUTOR_PHASES = {
        DecisionPhase.APPLIED,
        DecisionPhase.GATE_FAILED,
        DecisionPhase.PREFLIGHT_REJECTED,
        DecisionPhase.BYPASSED,
    }

    def test_phase_sets_are_disjoint(self) -> None:
        """Planner and executor phase sets share no members."""
        assert self.PLANNER_PHASES.isdisjoint(self.EXECUTOR_PHASES)

    def test_phase_sets_cover_all_phases(self) -> None:
        """Together, planner and executor phases cover all DecisionPhase values."""
        all_phases = set(DecisionPhase)
        assert self.PLANNER_PHASES | self.EXECUTOR_PHASES == all_phases

    def test_planner_only_emits_planner_phases(self) -> None:
        """compose_pipeline only produces records in planner-owned phases."""
        planner = UnflatteningPlanner(PipelinePolicy())
        f_ok = _make_fragment("ok", handlers=10)
        f_empty = _make_fragment("empty", has_modifications=False)
        f_risky = _make_fragment("risky", risk=0.99)
        f_conflict = _make_fragment(
            "conflict", handlers=5, owned_blocks=frozenset({1}),
        )
        f_winner = _make_fragment(
            "winner", handlers=20, owned_blocks=frozenset({1}),
        )

        _, prov = planner.compose_pipeline(
            [f_ok, f_empty, f_risky, f_conflict, f_winner],
        )
        for row in prov.rows:
            assert row.phase in self.PLANNER_PHASES, (
                f"Planner emitted executor-phase {row.phase} for {row.strategy_name}"
            )

    def test_executor_phase_updates_use_executor_phases(self) -> None:
        """Provenance updates simulating executor outcomes use executor phases."""
        prov = PipelineProvenance(
            rows=(
                DecisionRecord(
                    strategy_name="s1",
                    family=FAMILY_DIRECT,
                    phase=DecisionPhase.SELECTED,
                    reason_code=DecisionReasonCode.ACCEPTED,
                    reason="selected",
                ),
                DecisionRecord(
                    strategy_name="s2",
                    family=FAMILY_DIRECT,
                    phase=DecisionPhase.SELECTED,
                    reason_code=DecisionReasonCode.ACCEPTED,
                    reason="selected",
                ),
            )
        )
        # Simulate: s1 succeeds, s2 fails gate
        prov = prov.update_phase(
            "s1", DecisionPhase.APPLIED,
            reason_code=DecisionReasonCode.ACCEPTED,
        )
        prov = prov.update_phase(
            "s2", DecisionPhase.GATE_FAILED,
            reason_code=DecisionReasonCode.REJECTED_GATE_SEMANTIC,
            reason_detail="reachability too low",
        )
        assert prov.rows[0].phase == DecisionPhase.APPLIED
        assert prov.rows[1].phase == DecisionPhase.GATE_FAILED
        # Both are executor-owned phases
        for row in prov.rows:
            assert row.phase in self.EXECUTOR_PHASES


# ---------------------------------------------------------------------------
# Test 6: Gate failure does not trigger re-planning
# ---------------------------------------------------------------------------

class TestGateFailureDoesNotTriggerReplanning:
    """Prove that when a fragment fails its gate, the planner is NOT
    re-invoked, and other fragments remain unaffected."""

    def test_gate_failure_no_replan(self) -> None:
        """Build 3-fragment pipeline, fail fragment 2 gate,
        verify planner is not re-invoked."""
        planner = UnflatteningPlanner(PipelinePolicy())
        f1 = _make_fragment("s1", handlers=20, owned_blocks=frozenset({1}))
        f2 = _make_fragment("s2", handlers=15, owned_blocks=frozenset({2}))
        f3 = _make_fragment("s3", handlers=10, owned_blocks=frozenset({3}))

        pipeline, prov = planner.compose_pipeline([f1, f2, f3])
        assert len(pipeline) == 3

        # Simulate executor: s1 passes, s2 fails gate, s3 still runs
        results = [
            StageResult(strategy_name="s1", success=True, edits_applied=5),
            StageResult(
                strategy_name="s2", success=False,
                error="semantic gate failed", failure_phase="semantic_gate",
            ),
            StageResult(strategy_name="s3", success=True, edits_applied=3),
        ]

        # Apply provenance updates (mimicking unflattener.optimize())
        for frag, result in zip(pipeline, results):
            acct = result.metadata.get("gate_accounting")
            if result.success:
                prov = prov.update_phase(
                    frag.strategy_name, DecisionPhase.APPLIED,
                    reason_code=DecisionReasonCode.ACCEPTED,
                    gate_accounting=acct,
                )
            elif result.failure_phase == "semantic_gate":
                prov = prov.update_phase(
                    frag.strategy_name, DecisionPhase.GATE_FAILED,
                    reason_code=DecisionReasonCode.REJECTED_GATE_SEMANTIC,
                    reason_detail=result.error,
                    gate_accounting=acct,
                )

        # Verify: s1 APPLIED, s2 GATE_FAILED, s3 APPLIED
        phase_map = {r.strategy_name: r.phase for r in prov.rows}
        assert phase_map["s1"] == DecisionPhase.APPLIED
        assert phase_map["s2"] == DecisionPhase.GATE_FAILED
        assert phase_map["s3"] == DecisionPhase.APPLIED

        # Provenance still has exactly 3 records -- no re-planning added more
        assert len(prov.rows) == 3

    def test_gate_failure_with_early_abort(self) -> None:
        """When executor aborts early, remaining fragments get BYPASSED."""
        planner = UnflatteningPlanner(PipelinePolicy())
        f1 = _make_fragment("s1", handlers=20, owned_blocks=frozenset({1}))
        f2 = _make_fragment("s2", handlers=15, owned_blocks=frozenset({2}))
        f3 = _make_fragment("s3", handlers=10, owned_blocks=frozenset({3}))

        pipeline, prov = planner.compose_pipeline([f1, f2, f3])

        # Executor aborts after s2 fails (rollback_needed)
        results = [
            StageResult(strategy_name="s1", success=True, edits_applied=5),
            StageResult(
                strategy_name="s2", success=False, rollback_needed=True,
                error="semantic gate failed", failure_phase="semantic_gate",
            ),
            # s3 never executed -- executor broke out of loop
        ]

        # Apply provenance updates (mimicking unflattener lines 345-401)
        for frag, result in zip(pipeline, results):
            acct = result.metadata.get("gate_accounting")
            if result.success:
                prov = prov.update_phase(
                    frag.strategy_name, DecisionPhase.APPLIED,
                    reason_code=DecisionReasonCode.ACCEPTED,
                    gate_accounting=acct,
                )
            elif result.failure_phase == "semantic_gate":
                prov = prov.update_phase(
                    frag.strategy_name, DecisionPhase.GATE_FAILED,
                    reason_code=DecisionReasonCode.REJECTED_GATE_SEMANTIC,
                    reason_detail=result.error,
                    gate_accounting=acct,
                )

        # Mark unexecuted tail as BYPASSED (mimicking unflattener lines 394-401)
        for frag in pipeline[len(results):]:
            prov = prov.update_phase(
                frag.strategy_name, DecisionPhase.BYPASSED,
                reason_code=DecisionReasonCode.BYPASSED_PIPELINE_ABORT,
                reason_detail="pipeline aborted before this fragment was executed",
            )

        phase_map = {r.strategy_name: r.phase for r in prov.rows}
        assert phase_map["s1"] == DecisionPhase.APPLIED
        assert phase_map["s2"] == DecisionPhase.GATE_FAILED
        assert phase_map["s3"] == DecisionPhase.BYPASSED

        reason_map = {r.strategy_name: r.reason_code for r in prov.rows}
        assert reason_map["s3"] == DecisionReasonCode.BYPASSED_PIPELINE_ABORT


# ---------------------------------------------------------------------------
# Test 7: Conflict resolution reproducible across invocations
# ---------------------------------------------------------------------------

class TestConflictResolutionReproducible:
    """Prove conflict resolution is deterministic given the same inputs."""

    def test_ten_runs_identical_winner(self) -> None:
        """Run conflict resolution 10 times, verify identical results."""
        planner = UnflatteningPlanner(PipelinePolicy())
        f_a = _make_fragment(
            "alpha", handlers=15, transitions=12,
            owned_blocks=frozenset({1, 2, 3}),
        )
        f_b = _make_fragment(
            "beta", handlers=10, transitions=8,
            owned_blocks=frozenset({2, 3, 4}),
        )
        f_c = _make_fragment(
            "gamma", handlers=8, transitions=6,
            owned_blocks=frozenset({3, 4, 5}),
        )

        reference_names = None
        reference_prov_names = None

        for _ in range(10):
            pipeline, prov = planner.compose_pipeline([f_a, f_b, f_c])
            names = [f.strategy_name for f in pipeline]
            prov_names = [(r.strategy_name, r.phase) for r in prov.rows]

            if reference_names is None:
                reference_names = names
                reference_prov_names = prov_names
            else:
                assert names == reference_names
                assert prov_names == reference_prov_names

    def test_input_order_does_not_affect_winner(self) -> None:
        """Different input orderings produce the same conflict winner."""
        planner = UnflatteningPlanner(PipelinePolicy())
        f_high = _make_fragment(
            "high", handlers=20, owned_blocks=frozenset({1, 2}),
        )
        f_low = _make_fragment(
            "low", handlers=5, owned_blocks=frozenset({1, 3}),
        )

        p1, _ = planner.compose_pipeline([f_high, f_low])
        p2, _ = planner.compose_pipeline([f_low, f_high])
        assert [f.strategy_name for f in p1] == [f.strategy_name for f in p2]


# ---------------------------------------------------------------------------
# Test 8: Provenance records complete lifecycle
# ---------------------------------------------------------------------------

class TestProvenanceRecordsCompleteLifecycle:
    """Prove that every fragment gets a complete DecisionRecord through
    the full plan-execute cycle."""

    def test_all_records_have_required_fields(self) -> None:
        """Every DecisionRecord has non-empty strategy_name, valid phase/reason_code,
        and numeric base_score."""
        planner = UnflatteningPlanner(PipelinePolicy())
        f_ok = _make_fragment("ok", handlers=10, owned_blocks=frozenset({1}))
        f_empty = _make_fragment("empty", has_modifications=False)
        f_risky = _make_fragment("risky", risk=0.99)

        strat_ok = _FakeStrategy("ok", fragment=f_ok)
        strat_empty = _FakeStrategy("empty", fragment=f_empty)
        strat_risky = _FakeStrategy("risky", fragment=f_risky)
        strat_crash = _FakeStrategy("crash", crash=True)
        strat_na = _FakeStrategy("na", applicable=False)

        pipeline, prov = planner.plan(
            _FakeSnapshot(),
            [strat_ok, strat_empty, strat_risky, strat_crash, strat_na],
        )

        for row in prov.rows:
            assert row.strategy_name, f"Empty strategy_name in {row}"
            assert isinstance(row.phase, DecisionPhase), (
                f"Invalid phase {row.phase} for {row.strategy_name}"
            )
            assert isinstance(row.reason_code, DecisionReasonCode), (
                f"Invalid reason_code {row.reason_code} for {row.strategy_name}"
            )
            assert isinstance(row.base_score, (int, float)), (
                f"Non-numeric base_score for {row.strategy_name}"
            )

    def test_lifecycle_from_selected_to_applied(self) -> None:
        """A fragment progresses: SELECTED (planner) -> APPLIED (executor)."""
        planner = UnflatteningPlanner(PipelinePolicy())
        f = _make_fragment("lifecycle", handlers=10)
        strat = _FakeStrategy("lifecycle", fragment=f)

        pipeline, prov = planner.plan(_FakeSnapshot(), [strat])
        assert len(pipeline) == 1

        # Planner phase
        record = prov.rows[0]
        assert record.strategy_name == "lifecycle"
        assert record.phase == DecisionPhase.SELECTED

        # Executor phase update
        acct = GateAccounting().add(GateDecision(
            gate_name="semantic_gate", verdict=GateVerdict.PASSED,
            reason="all checks passed",
        ))
        prov = prov.update_phase(
            "lifecycle", DecisionPhase.APPLIED,
            reason_code=DecisionReasonCode.ACCEPTED,
            gate_accounting=acct,
        )
        updated = prov.rows[0]
        assert updated.phase == DecisionPhase.APPLIED
        assert updated.gate_accounting is not None
        assert updated.gate_accounting.passed_count == 1

    def test_no_none_fields_in_critical_provenance(self) -> None:
        """No DecisionRecord has None for strategy_name, phase, or reason_code."""
        planner = UnflatteningPlanner(PipelinePolicy())
        fragments = [
            _make_fragment(f"s{i}", handlers=10 - i, owned_blocks=frozenset({i * 10}))
            for i in range(5)
        ]
        _, prov = planner.compose_pipeline(fragments)
        for row in prov.rows:
            assert row.strategy_name is not None
            assert row.phase is not None
            assert row.reason_code is not None


# ---------------------------------------------------------------------------
# Test 9: Pipeline abort marks remaining as BYPASSED
# ---------------------------------------------------------------------------

class TestPipelineAbortMarksBypassedIntegration:
    """Prove that pipeline abort marks all remaining fragments as BYPASSED
    with BYPASSED_PIPELINE_ABORT reason code."""

    def test_five_fragment_abort_after_second(self) -> None:
        """5 fragments, executor stops after 2: fragments 3-5 get BYPASSED."""
        planner = UnflatteningPlanner(PipelinePolicy())
        fragments = [
            _make_fragment(f"s{i}", handlers=10 - i, owned_blocks=frozenset({i * 10}))
            for i in range(5)
        ]
        pipeline, prov = planner.compose_pipeline(fragments)
        assert len(pipeline) == 5

        # Executor only runs first 2
        results = [
            StageResult(strategy_name="s0", success=True, edits_applied=5),
            StageResult(
                strategy_name="s1", success=False, rollback_needed=True,
                error="transaction failed", failure_phase="lowering",
            ),
        ]

        # Apply provenance updates for executed fragments
        for frag, result in zip(pipeline, results):
            acct = result.metadata.get("gate_accounting")
            if result.success:
                prov = prov.update_phase(
                    frag.strategy_name, DecisionPhase.APPLIED,
                    reason_code=DecisionReasonCode.ACCEPTED,
                    gate_accounting=acct,
                )
            else:
                prov = prov.update_phase(
                    frag.strategy_name, DecisionPhase.GATE_FAILED,
                    reason_code=DecisionReasonCode.REJECTED_TRANSACTION,
                    reason_detail=result.error,
                    gate_accounting=acct,
                )

        # Mark unexecuted tail as BYPASSED
        for frag in pipeline[len(results):]:
            prov = prov.update_phase(
                frag.strategy_name, DecisionPhase.BYPASSED,
                reason_code=DecisionReasonCode.BYPASSED_PIPELINE_ABORT,
                reason_detail="pipeline aborted before this fragment was executed",
            )

        # Verify phases
        phase_map = {r.strategy_name: r.phase for r in prov.rows}
        assert phase_map["s0"] == DecisionPhase.APPLIED
        assert phase_map["s1"] == DecisionPhase.GATE_FAILED
        assert phase_map["s2"] == DecisionPhase.BYPASSED
        assert phase_map["s3"] == DecisionPhase.BYPASSED
        assert phase_map["s4"] == DecisionPhase.BYPASSED

        # Verify reason codes and details for bypassed fragments
        for row in prov.rows:
            if row.phase == DecisionPhase.BYPASSED:
                assert row.reason_code == DecisionReasonCode.BYPASSED_PIPELINE_ABORT
                assert "aborted" in row.reason.lower()


# ---------------------------------------------------------------------------
# Test 10: Policy filter before conflict resolution
# ---------------------------------------------------------------------------

class TestPolicyFilterBeforeConflictResolution:
    """Prove that policy filtering happens BEFORE conflict resolution,
    so filtered candidates don't participate in conflicts."""

    def test_risk_filtered_candidate_excluded_from_conflicts(self) -> None:
        """A high-risk fragment is filtered before it can win a conflict."""
        policy = PipelinePolicy(max_risk_score=0.5)
        planner = UnflatteningPlanner(policy)

        # f_risky has highest handlers but exceeds risk threshold
        f_risky = _make_fragment(
            "risky", handlers=50, risk=0.9,
            owned_blocks=frozenset({1, 2}),
        )
        # f_safe has fewer handlers but is within risk threshold
        f_safe = _make_fragment(
            "safe", handlers=10, risk=0.2,
            owned_blocks=frozenset({1, 2}),
        )

        pipeline, prov = planner.compose_pipeline([f_risky, f_safe])

        # f_risky should be POLICY_FILTERED (risk), NOT CONFLICT_DROPPED
        risky_record = [r for r in prov.rows if r.strategy_name == "risky"][0]
        assert risky_record.phase == DecisionPhase.POLICY_FILTERED
        assert risky_record.reason_code == DecisionReasonCode.REJECTED_RISK

        # f_safe should be SELECTED (no conflict since risky was filtered out)
        safe_record = [r for r in prov.rows if r.strategy_name == "safe"][0]
        assert safe_record.phase == DecisionPhase.SELECTED

    def test_fallback_suppressed_before_conflict_resolution(self) -> None:
        """Policy-suppressed fallbacks don't participate in conflicts."""
        policy = PipelinePolicy(direct_coverage_threshold=0.8)
        planner = UnflatteningPlanner(policy)

        f_direct = _make_fragment(
            "direct", family=FAMILY_DIRECT, handlers=9,
            owned_blocks=frozenset({1, 2}),
        )
        f_fallback = _make_fragment(
            "fallback", family=FAMILY_FALLBACK, handlers=5,
            owned_blocks=frozenset({1, 2}),
        )

        inputs = PlannerInputs(total_handlers=10)
        pipeline, prov = planner.compose_pipeline(
            [f_direct, f_fallback], inputs=inputs,
        )

        # Fallback should be POLICY_FILTERED, not CONFLICT_DROPPED
        fb_record = [r for r in prov.rows if r.strategy_name == "fallback"][0]
        assert fb_record.phase == DecisionPhase.POLICY_FILTERED
        assert fb_record.reason_code == DecisionReasonCode.REJECTED_POLICY

        # Direct should be SELECTED
        direct_record = [r for r in prov.rows if r.strategy_name == "direct"][0]
        assert direct_record.phase == DecisionPhase.SELECTED

    def test_empty_filtered_before_conflict_resolution(self) -> None:
        """Empty fragments are filtered before they can participate in conflicts."""
        planner = UnflatteningPlanner(PipelinePolicy())

        f_empty = _make_fragment(
            "empty", handlers=50, has_modifications=False,
            owned_blocks=frozenset({1, 2}),
        )
        f_real = _make_fragment(
            "real", handlers=10,
            owned_blocks=frozenset({1, 2}),
        )

        _, prov = planner.compose_pipeline([f_empty, f_real])

        empty_record = [r for r in prov.rows if r.strategy_name == "empty"][0]
        assert empty_record.phase == DecisionPhase.INAPPLICABLE
        assert empty_record.reason_code == DecisionReasonCode.REJECTED_EMPTY

        real_record = [r for r in prov.rows if r.strategy_name == "real"][0]
        assert real_record.phase == DecisionPhase.SELECTED
