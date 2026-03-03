"""Unit tests for Hodur strategy protocol types.

These tests exercise pure-Python types only — no IDA imports required.
"""
from __future__ import annotations

import pytest

from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    BenefitMetrics,
    EditType,
    OwnershipScope,
    PlanFragment,
    ProposedEdit,
    FAMILY_CLEANUP,
    FAMILY_DIRECT,
    FAMILY_FALLBACK,
)


# ---------------------------------------------------------------------------
# EditType
# ---------------------------------------------------------------------------

class TestEditType:
    def test_members_exist(self) -> None:
        assert EditType.GOTO_REDIRECT
        assert EditType.CONVERT_TO_GOTO
        assert EditType.NOP_INSN
        assert EditType.BLOCK_DUPLICATE
        assert EditType.CONDITIONAL_REDIRECT

    def test_unique_values(self) -> None:
        values = [e.value for e in EditType]
        assert len(values) == len(set(values))


# ---------------------------------------------------------------------------
# ProposedEdit
# ---------------------------------------------------------------------------

class TestProposedEdit:
    def test_required_fields(self) -> None:
        edit = ProposedEdit(edit_type=EditType.GOTO_REDIRECT, source_block=1)
        assert edit.edit_type is EditType.GOTO_REDIRECT
        assert edit.source_block == 1
        assert edit.target_block is None
        assert edit.instruction_ea is None
        assert edit.metadata == {}

    def test_optional_fields(self) -> None:
        edit = ProposedEdit(
            edit_type=EditType.NOP_INSN,
            source_block=5,
            target_block=10,
            instruction_ea=0xDEAD,
            metadata={"reason": "test"},
        )
        assert edit.target_block == 10
        assert edit.instruction_ea == 0xDEAD
        assert edit.metadata["reason"] == "test"

    def test_frozen(self) -> None:
        edit = ProposedEdit(edit_type=EditType.NOP_INSN, source_block=1)
        with pytest.raises((AttributeError, TypeError)):
            edit.source_block = 99  # type: ignore[misc]


# ---------------------------------------------------------------------------
# OwnershipScope
# ---------------------------------------------------------------------------

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

    def test_empty_scope(self) -> None:
        s = self._empty()
        assert s.blocks == frozenset()
        assert s.edges == frozenset()
        assert s.transitions == frozenset()

    def test_disjoint_true(self) -> None:
        a = self._scope(blocks={1, 2})
        b = self._scope(blocks={3, 4})
        assert a.is_disjoint(b)

    def test_disjoint_false_blocks(self) -> None:
        a = self._scope(blocks={1, 2})
        b = self._scope(blocks={2, 3})
        assert not a.is_disjoint(b)

    def test_disjoint_false_edges(self) -> None:
        a = self._scope(edges={(1, 2)})
        b = self._scope(edges={(1, 2)})
        assert not a.is_disjoint(b)

    def test_disjoint_false_transitions(self) -> None:
        a = self._scope(transitions={(0, 1)})
        b = self._scope(transitions={(0, 1)})
        assert not a.is_disjoint(b)

    def test_union(self) -> None:
        a = self._scope(blocks={1}, edges={(1, 2)}, transitions={(0, 1)})
        b = self._scope(blocks={3}, edges={(3, 4)}, transitions={(2, 3)})
        u = a.union(b)
        assert u.blocks == frozenset({1, 3})
        assert u.edges == frozenset({(1, 2), (3, 4)})
        assert u.transitions == frozenset({(0, 1), (2, 3)})

    def test_union_with_empty(self) -> None:
        a = self._scope(blocks={1, 2})
        u = a.union(self._empty())
        assert u.blocks == frozenset({1, 2})

    def test_overlap_blocks(self) -> None:
        a = self._scope(blocks={1, 2, 3})
        b = self._scope(blocks={2, 3, 4})
        assert a.overlap_blocks(b) == frozenset({2, 3})

    def test_overlap_blocks_empty(self) -> None:
        a = self._scope(blocks={1})
        b = self._scope(blocks={2})
        assert a.overlap_blocks(b) == frozenset()

    def test_overlap_edges(self) -> None:
        a = self._scope(edges={(1, 2), (3, 4)})
        b = self._scope(edges={(1, 2), (5, 6)})
        assert a.overlap_edges(b) == frozenset({(1, 2)})

    def test_frozen(self) -> None:
        s = self._scope(blocks={1})
        with pytest.raises((AttributeError, TypeError)):
            s.blocks = frozenset({99})  # type: ignore[misc]


# ---------------------------------------------------------------------------
# BenefitMetrics
# ---------------------------------------------------------------------------

class TestBenefitMetrics:
    def test_composite_score_all_zero(self) -> None:
        m = BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=0,
            blocks_freed=0,
            conflict_density=0.0,
        )
        assert m.composite_score() == pytest.approx(0.0)

    def test_composite_score_no_conflict(self) -> None:
        m = BenefitMetrics(
            handlers_resolved=2,
            transitions_resolved=3,
            blocks_freed=4,
            conflict_density=0.0,
        )
        # 2*3 + 3*2 + 4*1 - 0 = 6 + 6 + 4 = 16
        assert m.composite_score() == pytest.approx(16.0)

    def test_composite_score_with_conflict(self) -> None:
        m = BenefitMetrics(
            handlers_resolved=1,
            transitions_resolved=1,
            blocks_freed=1,
            conflict_density=1.0,
        )
        # 3 + 2 + 1 - 5 = 1
        assert m.composite_score() == pytest.approx(1.0)

    def test_composite_score_high_conflict_negative(self) -> None:
        m = BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=0,
            blocks_freed=0,
            conflict_density=2.0,
        )
        assert m.composite_score() == pytest.approx(-10.0)


# ---------------------------------------------------------------------------
# PlanFragment
# ---------------------------------------------------------------------------

class TestPlanFragment:
    def _empty_scope(self) -> OwnershipScope:
        return OwnershipScope(
            blocks=frozenset(), edges=frozenset(), transitions=frozenset()
        )

    def _zero_benefit(self) -> BenefitMetrics:
        return BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=0,
            blocks_freed=0,
            conflict_density=0.0,
        )

    def test_empty_fragment(self) -> None:
        frag = PlanFragment(
            strategy_name="test",
            proposed_edits=[],
            ownership=self._empty_scope(),
            prerequisites=[],
            expected_benefit=self._zero_benefit(),
            risk_score=0.0,
        )
        assert frag.is_empty()

    def test_non_empty_fragment(self) -> None:
        edit = ProposedEdit(edit_type=EditType.GOTO_REDIRECT, source_block=1)
        frag = PlanFragment(
            strategy_name="test",
            proposed_edits=[edit],
            ownership=self._empty_scope(),
            prerequisites=[],
            expected_benefit=self._zero_benefit(),
            risk_score=0.0,
        )
        assert not frag.is_empty()

    def test_strategy_name_preserved(self) -> None:
        frag = PlanFragment(
            strategy_name="my_strategy",
            proposed_edits=[],
            ownership=self._empty_scope(),
            prerequisites=["dep_a"],
            expected_benefit=self._zero_benefit(),
            risk_score=0.5,
        )
        assert frag.strategy_name == "my_strategy"
        assert frag.prerequisites == ["dep_a"]
        assert frag.risk_score == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# Family constants
# ---------------------------------------------------------------------------

class TestFamilyConstants:
    def test_constants_are_strings(self) -> None:
        assert isinstance(FAMILY_DIRECT, str)
        assert isinstance(FAMILY_FALLBACK, str)
        assert isinstance(FAMILY_CLEANUP, str)

    def test_constants_are_distinct(self) -> None:
        assert len({FAMILY_DIRECT, FAMILY_FALLBACK, FAMILY_CLEANUP}) == 3
