"""Unit tests for Hodur strategy protocol types.

These tests exercise pure-Python types only - no IDA imports required.
"""
from __future__ import annotations

import pytest

from d810.cfg.graph_modification import RedirectGoto
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
    FAMILY_CLEANUP,
    FAMILY_DIRECT,
    FAMILY_FALLBACK,
)


class TestOwnershipScope:
    def _empty(self) -> OwnershipScope:
        return OwnershipScope(
            blocks=frozenset(),
            edges=frozenset(),
            transitions=frozenset(),
        )

    def _scope(
        self,
        blocks: set[int] | None = None,
        edges: set[tuple[int, int]] | None = None,
        transitions: set[tuple[int, int]] | None = None,
    ) -> OwnershipScope:
        return OwnershipScope(
            blocks=frozenset(blocks or set()),
            edges=frozenset(edges or set()),
            transitions=frozenset(transitions or set()),
        )

    def test_disjoint_true(self) -> None:
        assert self._scope(blocks={1, 2}).is_disjoint(self._scope(blocks={3, 4}))

    def test_disjoint_false_blocks(self) -> None:
        assert not self._scope(blocks={1, 2}).is_disjoint(self._scope(blocks={2, 3}))

    def test_union(self) -> None:
        union = self._scope(blocks={1}, edges={(1, 2)}, transitions={(0, 1)}).union(
            self._scope(blocks={3}, edges={(3, 4)}, transitions={(2, 3)})
        )
        assert union.blocks == frozenset({1, 3})
        assert union.edges == frozenset({(1, 2), (3, 4)})
        assert union.transitions == frozenset({(0, 1), (2, 3)})

    def test_overlap_blocks(self) -> None:
        assert self._scope(blocks={1, 2, 3}).overlap_blocks(
            self._scope(blocks={2, 3, 4})
        ) == frozenset({2, 3})

    def test_overlap_edges(self) -> None:
        assert self._scope(edges={(1, 2), (3, 4)}).overlap_edges(
            self._scope(edges={(1, 2), (5, 6)})
        ) == frozenset({(1, 2)})

    def test_frozen(self) -> None:
        scope = self._scope(blocks={1})
        with pytest.raises((AttributeError, TypeError)):
            scope.blocks = frozenset({99})  # type: ignore[misc]


class TestBenefitMetrics:
    def test_composite_score_all_zero(self) -> None:
        assert BenefitMetrics(0, 0, 0, 0.0).composite_score() == pytest.approx(0.0)

    def test_composite_score_with_conflict(self) -> None:
        assert BenefitMetrics(1, 1, 1, 1.0).composite_score() == pytest.approx(1.0)


class TestPlanFragment:
    def _empty_scope(self) -> OwnershipScope:
        return OwnershipScope(
            blocks=frozenset(),
            edges=frozenset(),
            transitions=frozenset(),
        )

    def _zero_benefit(self) -> BenefitMetrics:
        return BenefitMetrics(0, 0, 0, 0.0)

    def test_empty_fragment(self) -> None:
        frag = PlanFragment(
            strategy_name="test",
            family=FAMILY_DIRECT,
            modifications=[],
            ownership=self._empty_scope(),
            prerequisites=[],
            expected_benefit=self._zero_benefit(),
            risk_score=0.0,
        )
        assert frag.is_empty()

    def test_non_empty_fragment(self) -> None:
        frag = PlanFragment(
            strategy_name="mods_only",
            family=FAMILY_DIRECT,
            modifications=[RedirectGoto(from_serial=1, old_target=2, new_target=3)],
            ownership=self._empty_scope(),
            prerequisites=[],
            expected_benefit=self._zero_benefit(),
            risk_score=0.0,
        )
        assert not frag.is_empty()

    def test_strategy_name_preserved(self) -> None:
        frag = PlanFragment(
            strategy_name="my_strategy",
            family=FAMILY_FALLBACK,
            modifications=[],
            ownership=self._empty_scope(),
            prerequisites=["dep_a"],
            expected_benefit=self._zero_benefit(),
            risk_score=0.5,
        )
        assert frag.strategy_name == "my_strategy"
        assert frag.prerequisites == ["dep_a"]
        assert frag.risk_score == pytest.approx(0.5)


class TestFamilyConstants:
    def test_constants_are_strings(self) -> None:
        assert isinstance(FAMILY_DIRECT, str)
        assert isinstance(FAMILY_FALLBACK, str)
        assert isinstance(FAMILY_CLEANUP, str)

    def test_constants_are_distinct(self) -> None:
        assert len({FAMILY_DIRECT, FAMILY_FALLBACK, FAMILY_CLEANUP}) == 3
