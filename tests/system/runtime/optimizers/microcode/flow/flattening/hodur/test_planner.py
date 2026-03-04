"""Unit tests for UnflatteningPlanner.

These tests exercise pure-Python planner logic only — no IDA imports required.
"""
from __future__ import annotations

import pytest

from d810.optimizers.microcode.flow.flattening.hodur.planner import (
    PipelinePolicy,
    UnflatteningPlanner,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_DIRECT,
    FAMILY_FALLBACK,
    BenefitMetrics,
    EditType,
    OwnershipScope,
    PlanFragment,
    ProposedEdit,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_scope(blocks: set[int] | None = None) -> OwnershipScope:
    return OwnershipScope(
        blocks=frozenset(blocks or set()),
        edges=frozenset(),
        transitions=frozenset(),
    )


def _make_benefit(
    handlers: int = 1,
    transitions: int = 0,
    blocks: int = 0,
    conflict: float = 0.0,
) -> BenefitMetrics:
    return BenefitMetrics(
        handlers_resolved=handlers,
        transitions_resolved=transitions,
        blocks_freed=blocks,
        conflict_density=conflict,
    )


def _make_fragment(
    name: str,
    family: str = FAMILY_DIRECT,
    handlers: int = 1,
    blocks: set[int] | None = None,
    prerequisites: list[str] | None = None,
    risk_score: float = 0.0,
    empty: bool = False,
) -> PlanFragment:
    edits = (
        []
        if empty
        else [ProposedEdit(edit_type=EditType.GOTO_REDIRECT, source_block=0)]
    )
    return PlanFragment(
        strategy_name=name,
        family=family,
        proposed_edits=edits,
        ownership=_make_scope(blocks),
        prerequisites=prerequisites or [],
        expected_benefit=_make_benefit(handlers=handlers),
        risk_score=risk_score,
    )


# ---------------------------------------------------------------------------
# order_fragments
# ---------------------------------------------------------------------------


class TestOrderFragments:
    def test_single_fragment_returned(self) -> None:
        planner = UnflatteningPlanner()
        frag = _make_fragment("alpha")
        result = planner.order_fragments([frag])
        assert result == [frag]

    def test_ordered_by_descending_score(self) -> None:
        planner = UnflatteningPlanner()
        low = _make_fragment("low", handlers=1)
        high = _make_fragment("high", handlers=10)
        result = planner.order_fragments([low, high])
        assert result[0].strategy_name == "high"
        assert result[1].strategy_name == "low"

    def test_prerequisite_comes_first(self) -> None:
        planner = UnflatteningPlanner()
        # "dep" has a high score but "main" depends on "dep" first
        dep = _make_fragment("dep", handlers=1)
        main = _make_fragment("main", handlers=100, prerequisites=["dep"])
        result = planner.order_fragments([main, dep])
        names = [f.strategy_name for f in result]
        assert names.index("dep") < names.index("main")

    def test_empty_list_returns_empty(self) -> None:
        planner = UnflatteningPlanner()
        assert planner.order_fragments([]) == []

    def test_multiple_prerequisites_respected(self) -> None:
        planner = UnflatteningPlanner()
        a = _make_fragment("a", handlers=5)
        b = _make_fragment("b", handlers=3)
        c = _make_fragment("c", handlers=1, prerequisites=["a", "b"])
        result = planner.order_fragments([c, b, a])
        names = [f.strategy_name for f in result]
        assert names.index("a") < names.index("c")
        assert names.index("b") < names.index("c")


# ---------------------------------------------------------------------------
# find_conflicts
# ---------------------------------------------------------------------------


class TestFindConflicts:
    def test_no_overlap_returns_empty(self) -> None:
        planner = UnflatteningPlanner()
        a = _make_fragment("a", blocks={1, 2})
        b = _make_fragment("b", blocks={3, 4})
        assert planner.find_conflicts([a, b]) == []

    def test_overlap_detected(self) -> None:
        planner = UnflatteningPlanner()
        a = _make_fragment("a", blocks={1, 2})
        b = _make_fragment("b", blocks={2, 3})
        conflicts = planner.find_conflicts([a, b])
        assert len(conflicts) == 1
        name_a, name_b, overlap = conflicts[0]
        assert {name_a, name_b} == {"a", "b"}
        assert overlap == frozenset({2})

    def test_disjoint_passes_no_conflict(self) -> None:
        planner = UnflatteningPlanner()
        frags = [_make_fragment(str(i), blocks={i}) for i in range(5)]
        assert planner.find_conflicts(frags) == []

    def test_multiple_conflicts(self) -> None:
        planner = UnflatteningPlanner()
        a = _make_fragment("a", blocks={1, 2, 3})
        b = _make_fragment("b", blocks={2, 3, 4})
        c = _make_fragment("c", blocks={3, 4, 5})
        conflicts = planner.find_conflicts([a, b, c])
        # (a,b), (a,c), (b,c) all overlap
        assert len(conflicts) == 3


# ---------------------------------------------------------------------------
# apply_policy
# ---------------------------------------------------------------------------


class TestApplyPolicy:
    def test_blocks_fallback_when_coverage_above_threshold(self) -> None:
        policy = PipelinePolicy(direct_coverage_threshold=0.8)
        planner = UnflatteningPlanner(policy)
        direct = _make_fragment("direct", family=FAMILY_DIRECT, handlers=9)
        fb = _make_fragment("fallback_x", family=FAMILY_FALLBACK, handlers=1)
        result = planner.apply_policy([direct, fb], total_handlers=10)
        names = [f.strategy_name for f in result]
        assert "direct" in names
        assert "fallback_x" not in names

    def test_allows_fallback_when_coverage_below_threshold(self) -> None:
        policy = PipelinePolicy(direct_coverage_threshold=0.8)
        planner = UnflatteningPlanner(policy)
        direct = _make_fragment("direct", family=FAMILY_DIRECT, handlers=5)
        fb = _make_fragment("fallback_x", family=FAMILY_FALLBACK, handlers=2)
        result = planner.apply_policy([direct, fb], total_handlers=10)
        names = [f.strategy_name for f in result]
        assert "direct" in names
        assert "fallback_x" in names

    def test_allow_fallback_families_false_always_blocks(self) -> None:
        policy = PipelinePolicy(allow_fallback_families=False)
        planner = UnflatteningPlanner(policy)
        direct = _make_fragment("direct", family=FAMILY_DIRECT, handlers=1)
        fb = _make_fragment("fallback_x", family=FAMILY_FALLBACK, handlers=1)
        result = planner.apply_policy([direct, fb], total_handlers=100)
        names = [f.strategy_name for f in result]
        assert "direct" in names
        assert "fallback_x" not in names

    def test_zero_total_handlers_allows_all(self) -> None:
        policy = PipelinePolicy(direct_coverage_threshold=0.8)
        planner = UnflatteningPlanner(policy)
        fb = _make_fragment("fallback_x", family=FAMILY_FALLBACK, handlers=0)
        result = planner.apply_policy([fb], total_handlers=0)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# _resolve_conflicts
# ---------------------------------------------------------------------------


class TestResolveConflicts:
    def test_higher_score_wins(self) -> None:
        planner = UnflatteningPlanner()
        high = _make_fragment("high", handlers=10, blocks={1})
        low = _make_fragment("low", handlers=1, blocks={1})
        conflicts = [("high", "low", frozenset({1}))]
        result = planner._resolve_conflicts([high, low], conflicts)
        names = [f.strategy_name for f in result]
        assert "high" in names
        assert "low" not in names

    def test_lower_score_dropped(self) -> None:
        planner = UnflatteningPlanner()
        a = _make_fragment("a", handlers=5, blocks={2})
        b = _make_fragment("b", handlers=2, blocks={2})
        conflicts = [("a", "b", frozenset({2}))]
        result = planner._resolve_conflicts([a, b], conflicts)
        assert len(result) == 1
        assert result[0].strategy_name == "a"

    def test_equal_score_keeps_first(self) -> None:
        planner = UnflatteningPlanner()
        a = _make_fragment("a", handlers=3, blocks={5})
        b = _make_fragment("b", handlers=3, blocks={5})
        conflicts = [("a", "b", frozenset({5}))]
        result = planner._resolve_conflicts([a, b], conflicts)
        # a >= b so b is dropped
        names = [f.strategy_name for f in result]
        assert "a" in names
        assert "b" not in names


# ---------------------------------------------------------------------------
# compose_pipeline (integration)
# ---------------------------------------------------------------------------


class TestComposePipeline:
    def test_empty_fragments_returns_empty(self) -> None:
        planner = UnflatteningPlanner()
        result = planner.compose_pipeline([], total_handlers=10)
        assert result == []

    def test_empty_fragment_filtered_out(self) -> None:
        planner = UnflatteningPlanner()
        non_empty = _make_fragment("real", handlers=3)
        empty = _make_fragment("ghost", empty=True)
        result = planner.compose_pipeline([non_empty, empty], total_handlers=5)
        names = [f.strategy_name for f in result]
        assert "real" in names
        assert "ghost" not in names

    def test_high_risk_filtered_out(self) -> None:
        policy = PipelinePolicy(max_risk_score=0.5)
        planner = UnflatteningPlanner(policy)
        safe = _make_fragment("safe", handlers=2, risk_score=0.3)
        risky = _make_fragment("risky", handlers=2, risk_score=0.9)
        result = planner.compose_pipeline([safe, risky], total_handlers=5)
        names = [f.strategy_name for f in result]
        assert "safe" in names
        assert "risky" not in names

    def test_full_pipeline_ordered_and_conflict_free(self) -> None:
        planner = UnflatteningPlanner()
        a = _make_fragment("a", handlers=5, blocks={1})
        b = _make_fragment("b", handlers=3, blocks={2})
        result = planner.compose_pipeline([b, a], total_handlers=8)
        assert len(result) == 2
        assert result[0].strategy_name == "a"  # higher score first

    def test_conflict_resolved_in_pipeline(self) -> None:
        planner = UnflatteningPlanner()
        winner = _make_fragment("winner", handlers=10, blocks={7})
        loser = _make_fragment("loser", handlers=1, blocks={7})
        result = planner.compose_pipeline([winner, loser], total_handlers=10)
        names = [f.strategy_name for f in result]
        assert "winner" in names
        assert "loser" not in names
