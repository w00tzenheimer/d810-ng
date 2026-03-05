"""Unit tests for UnflatteningPlanner.

These tests exercise pure-Python planner logic only - no IDA imports required.
"""
from __future__ import annotations

import pytest

from d810.cfg.graph_modification import RedirectGoto
from d810.optimizers.microcode.flow.flattening.hodur.planner import (
    PipelinePolicy,
    UnflatteningPlanner,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_DIRECT,
    FAMILY_FALLBACK,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)


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
    modifications = (
        []
        if empty
        else [RedirectGoto(from_serial=0, old_target=1, new_target=2)]
    )
    return PlanFragment(
        strategy_name=name,
        family=family,
        modifications=modifications,
        ownership=_make_scope(blocks),
        prerequisites=prerequisites or [],
        expected_benefit=_make_benefit(handlers=handlers),
        risk_score=risk_score,
    )


class TestOrderFragments:
    def test_single_fragment_returned(self) -> None:
        planner = UnflatteningPlanner()
        frag = _make_fragment("alpha")
        assert planner.order_fragments([frag]) == [frag]

    def test_ordered_by_descending_score(self) -> None:
        planner = UnflatteningPlanner()
        low = _make_fragment("low", handlers=1)
        high = _make_fragment("high", handlers=10)
        result = planner.order_fragments([low, high])
        assert result[0].strategy_name == "high"
        assert result[1].strategy_name == "low"

    def test_prerequisite_comes_first(self) -> None:
        planner = UnflatteningPlanner()
        dep = _make_fragment("dep", handlers=1)
        main = _make_fragment("main", handlers=100, prerequisites=["dep"])
        result = planner.order_fragments([main, dep])
        names = [f.strategy_name for f in result]
        assert names.index("dep") < names.index("main")

    def test_empty_list_returns_empty(self) -> None:
        assert UnflatteningPlanner().order_fragments([]) == []


class TestFindConflicts:
    def test_no_overlap_returns_empty(self) -> None:
        planner = UnflatteningPlanner()
        assert planner.find_conflicts([
            _make_fragment("a", blocks={1, 2}),
            _make_fragment("b", blocks={3, 4}),
        ]) == []

    def test_overlap_detected(self) -> None:
        planner = UnflatteningPlanner()
        conflicts = planner.find_conflicts([
            _make_fragment("a", blocks={1, 2}),
            _make_fragment("b", blocks={2, 3}),
        ])
        assert len(conflicts) == 1
        name_a, name_b, overlap = conflicts[0]
        assert {name_a, name_b} == {"a", "b"}
        assert overlap == frozenset({2})


class TestApplyPolicy:
    def test_blocks_fallback_when_coverage_above_threshold(self) -> None:
        planner = UnflatteningPlanner(PipelinePolicy(direct_coverage_threshold=0.8))
        direct = _make_fragment("direct", family=FAMILY_DIRECT, handlers=9)
        fallback = _make_fragment("fallback_x", family=FAMILY_FALLBACK, handlers=1)
        names = [f.strategy_name for f in planner.apply_policy([direct, fallback], total_handlers=10)]
        assert "direct" in names
        assert "fallback_x" not in names

    def test_allows_fallback_when_coverage_below_threshold(self) -> None:
        planner = UnflatteningPlanner(PipelinePolicy(direct_coverage_threshold=0.8))
        direct = _make_fragment("direct", family=FAMILY_DIRECT, handlers=5)
        fallback = _make_fragment("fallback_x", family=FAMILY_FALLBACK, handlers=2)
        names = [f.strategy_name for f in planner.apply_policy([direct, fallback], total_handlers=10)]
        assert "direct" in names
        assert "fallback_x" in names

    def test_zero_total_handlers_allows_all(self) -> None:
        planner = UnflatteningPlanner(PipelinePolicy(direct_coverage_threshold=0.8))
        assert len(planner.apply_policy([_make_fragment("fallback_x", family=FAMILY_FALLBACK, handlers=0)], total_handlers=0)) == 1


class TestResolveConflicts:
    def test_higher_score_wins(self) -> None:
        planner = UnflatteningPlanner()
        high = _make_fragment("high", handlers=10, blocks={1})
        low = _make_fragment("low", handlers=1, blocks={1})
        result = planner._resolve_conflicts([high, low], [("high", "low", frozenset({1}))])
        names = [f.strategy_name for f in result]
        assert "high" in names
        assert "low" not in names

    def test_empty_fragment_still_reports_empty(self) -> None:
        assert _make_fragment("empty", empty=True).is_empty()
