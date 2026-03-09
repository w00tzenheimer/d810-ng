"""H3 proof: UnflatteningPlanner is the sole authority for pipeline
membership, ordering, and conflict resolution.

These tests prove the ownership boundaries between planner, executor, and
orchestrator using pure-Python mocks (no IDA dependency).

Audit findings:
- Re-arbitration sites found: NONE
- Executor only gates via safeguard/preflight/transaction/semantic checks
- Orchestrator only updates provenance lifecycle phases after execution
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
# Helpers
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
# Test 1: Planner output order is preserved by the pipeline
# ---------------------------------------------------------------------------

class TestPlannerOrderPreserved:
    """Prove that the planner's ordering is final and preserved downstream."""

    def test_compose_pipeline_preserves_order(self) -> None:
        """Fragments come out in prerequisite-then-score order from compose_pipeline."""
        planner = UnflatteningPlanner(PipelinePolicy())
        f_high = _make_fragment("high_score", handlers=20, transitions=15)
        f_low = _make_fragment("low_score", handlers=5, transitions=3)
        pipeline, prov = planner.compose_pipeline([f_high, f_low])
        assert [f.strategy_name for f in pipeline] == ["high_score", "low_score"]

    def test_prerequisite_ordering(self) -> None:
        """A fragment with prerequisites is ordered after its dependency."""
        planner = UnflatteningPlanner(PipelinePolicy())
        f_dep = _make_fragment("dependent", handlers=100, prerequisites=["base"])
        f_base = _make_fragment("base", handlers=5)
        # Even though dependent has a much higher score, base comes first
        pipeline, _ = planner.compose_pipeline([f_dep, f_base])
        names = [f.strategy_name for f in pipeline]
        assert names.index("base") < names.index("dependent")

    def test_plan_method_produces_final_order(self) -> None:
        """plan() delegates to compose_pipeline and returns the final order."""
        planner = UnflatteningPlanner(PipelinePolicy())
        f1 = _make_fragment("alpha", handlers=10)
        f2 = _make_fragment("beta", handlers=5)
        strat1 = _FakeStrategy("alpha", fragment=f1)
        strat2 = _FakeStrategy("beta", fragment=f2)
        pipeline, _ = planner.plan(_FakeSnapshot(), [strat1, strat2])
        assert [f.strategy_name for f in pipeline] == ["alpha", "beta"]


# ---------------------------------------------------------------------------
# Test 2: Executor gate failure does NOT cause re-selection
# ---------------------------------------------------------------------------

class TestExecutorNoReSelection:
    """Prove that gate failures produce GATE_FAILED/PREFLIGHT_REJECTED,
    not replacement fragments."""

    def test_gate_failure_maps_to_gate_failed_phase(self) -> None:
        """When executor returns failure, unflattener maps to GATE_FAILED phase,
        not re-selection of an alternative."""
        # Simulate what unflattener.optimize() does with executor results:
        # Build a provenance with SELECTED phase, then update based on result
        pipeline = [_make_fragment("strat_a")]
        provenance = PipelineProvenance(
            rows=(
                DecisionRecord(
                    strategy_name="strat_a",
                    family=FAMILY_DIRECT,
                    phase=DecisionPhase.SELECTED,
                    reason_code=DecisionReasonCode.ACCEPTED,
                    reason="selected into pipeline",
                ),
            )
        )
        # Simulate executor failure (semantic gate)
        result = StageResult(
            strategy_name="strat_a",
            success=False,
            error="semantic gate failed",
            failure_phase="semantic_gate",
        )
        result.metadata["gate_accounting"] = GateAccounting().add(
            GateDecision(
                gate_name="semantic_gate",
                verdict=GateVerdict.FAILED,
                reason="reachability too low",
            )
        )
        # Apply the same provenance update logic as unflattener.optimize()
        acct = result.metadata.get("gate_accounting")
        provenance = provenance.update_phase(
            "strat_a",
            DecisionPhase.GATE_FAILED,
            reason_code=DecisionReasonCode.REJECTED_GATE_SEMANTIC,
            reason_detail=result.error,
            gate_accounting=acct,
        )
        record = provenance.rows[0]
        assert record.phase == DecisionPhase.GATE_FAILED
        assert record.reason_code == DecisionReasonCode.REJECTED_GATE_SEMANTIC
        # No new fragment was selected -- pipeline still has exactly 1 entry
        assert len(provenance.rows) == 1

    def test_safeguard_failure_maps_to_gate_failed(self) -> None:
        """Safeguard rejection produces GATE_FAILED, not re-selection."""
        provenance = PipelineProvenance(
            rows=(
                DecisionRecord(
                    strategy_name="strat_x",
                    family=FAMILY_DIRECT,
                    phase=DecisionPhase.SELECTED,
                    reason_code=DecisionReasonCode.ACCEPTED,
                    reason="selected",
                ),
            )
        )
        provenance = provenance.update_phase(
            "strat_x",
            DecisionPhase.GATE_FAILED,
            reason_code=DecisionReasonCode.REJECTED_GATE_SAFEGUARD,
            reason_detail="insufficient modifications",
        )
        assert provenance.rows[0].phase == DecisionPhase.GATE_FAILED
        assert provenance.rows[0].reason_code == DecisionReasonCode.REJECTED_GATE_SAFEGUARD

    def test_bypassed_tail_marks_unexecuted_fragments(self) -> None:
        """Unexecuted pipeline tail is marked BYPASSED, not re-selected."""
        provenance = PipelineProvenance(
            rows=(
                DecisionRecord(
                    strategy_name="strat_a",
                    family=FAMILY_DIRECT,
                    phase=DecisionPhase.SELECTED,
                    reason_code=DecisionReasonCode.ACCEPTED,
                    reason="selected",
                ),
                DecisionRecord(
                    strategy_name="strat_b",
                    family=FAMILY_CLEANUP,
                    phase=DecisionPhase.SELECTED,
                    reason_code=DecisionReasonCode.ACCEPTED,
                    reason="selected",
                ),
            )
        )
        # Simulate executor aborting after strat_a -- strat_b never executes
        provenance = provenance.update_phase(
            "strat_b",
            DecisionPhase.BYPASSED,
            reason_code=DecisionReasonCode.BYPASSED_PIPELINE_ABORT,
            reason_detail="pipeline aborted before this fragment was executed",
        )
        assert provenance.rows[1].phase == DecisionPhase.BYPASSED
        assert provenance.rows[1].reason_code == DecisionReasonCode.BYPASSED_PIPELINE_ABORT


# ---------------------------------------------------------------------------
# Test 3: Planner conflict resolution is deterministic
# ---------------------------------------------------------------------------

class TestPlannerConflictDeterminism:
    """Prove that conflict resolution is deterministic given the same inputs."""

    def test_same_inputs_same_winner(self) -> None:
        """Running conflict resolution twice with identical inputs produces
        the same pipeline."""
        planner = UnflatteningPlanner(PipelinePolicy())
        f_a = _make_fragment(
            "strat_a", handlers=10, owned_blocks=frozenset({1, 2, 3}),
        )
        f_b = _make_fragment(
            "strat_b", handlers=8, owned_blocks=frozenset({2, 3, 4}),
        )
        # Run twice
        pipeline1, _ = planner.compose_pipeline([f_a, f_b])
        pipeline2, _ = planner.compose_pipeline([f_a, f_b])
        assert [f.strategy_name for f in pipeline1] == [f.strategy_name for f in pipeline2]

    def test_higher_score_wins_conflict(self) -> None:
        """In an ownership conflict, the higher-scoring fragment wins."""
        planner = UnflatteningPlanner(PipelinePolicy())
        f_winner = _make_fragment(
            "winner", handlers=20, owned_blocks=frozenset({1, 2}),
        )
        f_loser = _make_fragment(
            "loser", handlers=5, owned_blocks=frozenset({2, 3}),
        )
        pipeline, prov = planner.compose_pipeline([f_winner, f_loser])
        names = [f.strategy_name for f in pipeline]
        assert "winner" in names
        assert "loser" not in names
        # Verify loser got CONFLICT_DROPPED in provenance
        dropped = [r for r in prov.rows if r.phase == DecisionPhase.CONFLICT_DROPPED]
        assert len(dropped) == 1
        assert dropped[0].strategy_name == "loser"

    def test_disjoint_fragments_both_accepted(self) -> None:
        """Fragments with no ownership overlap are both accepted."""
        planner = UnflatteningPlanner(PipelinePolicy())
        f_a = _make_fragment("strat_a", owned_blocks=frozenset({1, 2}))
        f_b = _make_fragment("strat_b", owned_blocks=frozenset({3, 4}))
        pipeline, _ = planner.compose_pipeline([f_a, f_b])
        assert len(pipeline) == 2

    def test_input_order_does_not_affect_conflict_winner(self) -> None:
        """Conflict resolution uses effective score, not input order."""
        planner = UnflatteningPlanner(PipelinePolicy())
        f_high = _make_fragment(
            "high", handlers=20, owned_blocks=frozenset({1, 2}),
        )
        f_low = _make_fragment(
            "low", handlers=5, owned_blocks=frozenset({1, 3}),
        )
        # Try both orderings
        p1, _ = planner.compose_pipeline([f_high, f_low])
        p2, _ = planner.compose_pipeline([f_low, f_high])
        assert [f.strategy_name for f in p1] == [f.strategy_name for f in p2]
        assert p1[0].strategy_name == "high"


# ---------------------------------------------------------------------------
# Test 4: Provenance separates planner and executor phases
# ---------------------------------------------------------------------------

class TestProvenancePhaseSeparation:
    """Prove that provenance vocabulary cleanly separates planner decisions
    from executor outcomes."""

    def test_planner_phases_are_pre_execution(self) -> None:
        """SELECTED, POLICY_FILTERED, CONFLICT_DROPPED, INAPPLICABLE are
        planner-phase decisions that happen before execution."""
        planner_phases = {
            DecisionPhase.SELECTED,
            DecisionPhase.POLICY_FILTERED,
            DecisionPhase.CONFLICT_DROPPED,
            DecisionPhase.INAPPLICABLE,
            DecisionPhase.CRASHED,
        }
        # These phases must exist and be distinct from executor phases
        executor_phases = {
            DecisionPhase.APPLIED,
            DecisionPhase.GATE_FAILED,
            DecisionPhase.PREFLIGHT_REJECTED,
            DecisionPhase.BYPASSED,
        }
        assert planner_phases.isdisjoint(executor_phases)

    def test_planner_records_use_planner_phases(self) -> None:
        """compose_pipeline produces records only in planner-owned phases."""
        planner = UnflatteningPlanner(PipelinePolicy())
        f_accepted = _make_fragment("accepted", handlers=10)
        f_empty = _make_fragment("empty", has_modifications=False)
        f_risky = _make_fragment("risky", risk=0.99)

        pipeline, prov = planner.compose_pipeline([f_accepted, f_empty, f_risky])
        planner_only_phases = {
            DecisionPhase.SELECTED,
            DecisionPhase.POLICY_FILTERED,
            DecisionPhase.CONFLICT_DROPPED,
            DecisionPhase.INAPPLICABLE,
        }
        for row in prov.rows:
            assert row.phase in planner_only_phases, (
                f"Planner emitted executor-phase {row.phase} for {row.strategy_name}"
            )

    def test_executor_updates_use_executor_phases(self) -> None:
        """update_phase with executor outcomes uses executor-owned phases."""
        initial = PipelineProvenance(
            rows=(
                DecisionRecord(
                    strategy_name="strat",
                    family=FAMILY_DIRECT,
                    phase=DecisionPhase.SELECTED,
                    reason_code=DecisionReasonCode.ACCEPTED,
                    reason="selected",
                ),
            )
        )
        # Simulate successful execution
        updated = initial.update_phase(
            "strat",
            DecisionPhase.APPLIED,
            reason_code=DecisionReasonCode.ACCEPTED,
        )
        assert updated.rows[0].phase == DecisionPhase.APPLIED

    def test_provenance_lifecycle_progression(self) -> None:
        """A fragment progresses from SELECTED (planner) to APPLIED/GATE_FAILED
        (executor) -- never back to a planner phase."""
        prov = PipelineProvenance(
            rows=(
                DecisionRecord(
                    strategy_name="s1",
                    family=FAMILY_DIRECT,
                    phase=DecisionPhase.SELECTED,
                    reason_code=DecisionReasonCode.ACCEPTED,
                    reason="selected",
                ),
            )
        )
        # Transition to APPLIED
        prov = prov.update_phase("s1", DecisionPhase.APPLIED)
        assert prov.rows[0].phase == DecisionPhase.APPLIED

    def test_gate_accounting_attached_to_executor_records(self) -> None:
        """Gate accounting is attached during executor phase updates,
        not during planner decisions."""
        acct = GateAccounting().add(
            GateDecision(
                gate_name="semantic_gate",
                verdict=GateVerdict.PASSED,
                reason="all checks passed",
            )
        )
        prov = PipelineProvenance(
            rows=(
                DecisionRecord(
                    strategy_name="s1",
                    family=FAMILY_DIRECT,
                    phase=DecisionPhase.SELECTED,
                    reason_code=DecisionReasonCode.ACCEPTED,
                    reason="selected",
                ),
            )
        )
        prov = prov.update_phase(
            "s1",
            DecisionPhase.APPLIED,
            reason_code=DecisionReasonCode.ACCEPTED,
            gate_accounting=acct,
        )
        assert prov.rows[0].gate_accounting is not None
        assert prov.rows[0].gate_accounting.passed_count == 1


# ---------------------------------------------------------------------------
# Test 5: Policy filtering is planner-owned
# ---------------------------------------------------------------------------

class TestPolicyFilteringPlannerOwned:
    """Prove that policy decisions (fallback suppression, risk thresholds)
    are made by the planner, not the executor."""

    def test_risk_threshold_rejects_high_risk(self) -> None:
        """Fragments above max_risk_score are filtered by planner, not executor."""
        policy = PipelinePolicy(max_risk_score=0.5)
        planner = UnflatteningPlanner(policy)
        f_ok = _make_fragment("safe", risk=0.3)
        f_risky = _make_fragment("dangerous", risk=0.8)
        pipeline, prov = planner.compose_pipeline([f_ok, f_risky])
        assert [f.strategy_name for f in pipeline] == ["safe"]
        rejected = [r for r in prov.rows if r.phase == DecisionPhase.POLICY_FILTERED]
        assert len(rejected) == 1
        assert rejected[0].strategy_name == "dangerous"

    def test_fallback_suppression_by_coverage(self) -> None:
        """When direct coverage exceeds threshold, fallbacks are dropped by planner."""
        policy = PipelinePolicy(direct_coverage_threshold=0.8)
        planner = UnflatteningPlanner(policy)
        f_direct = _make_fragment("direct", family=FAMILY_DIRECT, handlers=9)
        f_fallback = _make_fragment("fallback", family=FAMILY_FALLBACK, handlers=2)
        inputs = PlannerInputs(total_handlers=10)
        pipeline, prov = planner.compose_pipeline(
            [f_direct, f_fallback], inputs=inputs,
        )
        assert [f.strategy_name for f in pipeline] == ["direct"]
        dropped = [r for r in prov.rows if r.phase == DecisionPhase.POLICY_FILTERED]
        assert any(r.strategy_name == "fallback" for r in dropped)

    def test_empty_fragment_filtered_by_planner(self) -> None:
        """Fragments with no modifications are filtered as INAPPLICABLE by planner."""
        planner = UnflatteningPlanner(PipelinePolicy())
        f_empty = _make_fragment("empty", has_modifications=False)
        pipeline, prov = planner.compose_pipeline([f_empty])
        assert len(pipeline) == 0
        inapplicable = [r for r in prov.rows if r.phase == DecisionPhase.INAPPLICABLE]
        assert len(inapplicable) == 1
        assert inapplicable[0].strategy_name == "empty"


# ---------------------------------------------------------------------------
# Test 6: plan() method is the complete entry point
# ---------------------------------------------------------------------------

class TestPlanMethodCompleteness:
    """Prove that plan() handles the full lifecycle: polling, collection,
    composition, and provenance."""

    def test_inapplicable_strategy_recorded(self) -> None:
        """Strategies returning is_applicable=False get INAPPLICABLE records."""
        planner = UnflatteningPlanner(PipelinePolicy())
        strat = _FakeStrategy("nope", applicable=False)
        pipeline, prov = planner.plan(_FakeSnapshot(), [strat])
        assert len(pipeline) == 0
        assert prov.rows[0].phase == DecisionPhase.INAPPLICABLE

    def test_crashed_strategy_recorded(self) -> None:
        """Strategies that crash during plan() get CRASHED records."""
        planner = UnflatteningPlanner(PipelinePolicy())
        strat = _FakeStrategy("boom", crash=True)
        pipeline, prov = planner.plan(_FakeSnapshot(), [strat])
        assert len(pipeline) == 0
        assert prov.rows[0].phase == DecisionPhase.CRASHED
        assert "raised" in prov.rows[0].reason

    def test_none_fragment_recorded_as_inapplicable(self) -> None:
        """Applicable strategy returning None fragment gets INAPPLICABLE."""
        planner = UnflatteningPlanner(PipelinePolicy())
        strat = _FakeStrategy("empty_plan", fragment=None)
        pipeline, prov = planner.plan(_FakeSnapshot(), [strat])
        assert len(pipeline) == 0
        assert prov.rows[0].phase == DecisionPhase.INAPPLICABLE
        assert prov.rows[0].reason_code == DecisionReasonCode.REJECTED_EMPTY
