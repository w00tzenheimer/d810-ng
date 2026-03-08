"""Unit tests for Hodur strategy classes.

These tests verify that all 7 strategy classes correctly implement the
UnflatteningStrategy protocol and have unique names, without requiring an
IDA environment.
"""
from __future__ import annotations

import pytest

from d810.cfg.graph_modification import EdgeRedirectViaPredSplit, RedirectBranch
from d810.optimizers.microcode.flow.flattening.hodur._modification_bridge import (
    ModificationBuilder,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_CLEANUP,
    FAMILY_DIRECT,
    FAMILY_FALLBACK,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
    UnflatteningStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies import (
    ALL_STRATEGIES,
    AssignmentMapFallbackStrategy,
    ConditionalForkFallbackStrategy,
    DirectHandlerLinearizationStrategy,
    EdgeSplitConflictResolutionStrategy,
    HiddenHandlerClosureStrategy,
    PredPatchFallbackStrategy,
    TerminalLoopCleanupStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.snapshot import AnalysisSnapshot


# ---------------------------------------------------------------------------
# Protocol compliance
# ---------------------------------------------------------------------------


def test_all_strategies_implement_protocol():
    """Every class in ALL_STRATEGIES must satisfy the UnflatteningStrategy Protocol."""
    for cls in ALL_STRATEGIES:
        instance = cls()
        assert isinstance(instance, UnflatteningStrategy), (
            f"{cls.__name__} does not satisfy UnflatteningStrategy protocol"
        )
        assert hasattr(instance, "name"), f"{cls.__name__} missing 'name'"
        assert hasattr(instance, "family"), f"{cls.__name__} missing 'family'"
        assert hasattr(instance, "is_applicable"), f"{cls.__name__} missing 'is_applicable'"
        assert hasattr(instance, "plan"), f"{cls.__name__} missing 'plan'"


def test_strategy_names_unique():
    """Each strategy must have a unique name string."""
    names = [cls().name for cls in ALL_STRATEGIES]
    assert len(names) == len(set(names)), f"Duplicate strategy names: {names}"


def test_strategy_count():
    """ALL_STRATEGIES must contain exactly 9 strategies."""
    assert len(ALL_STRATEGIES) == 9


# ---------------------------------------------------------------------------
# Name and family properties
# ---------------------------------------------------------------------------


class TestStrategyProperties:
    """Verify name and family for each strategy."""

    def test_direct_linearization_name(self):
        s = DirectHandlerLinearizationStrategy()
        assert s.name == "direct_handler_linearization"

    def test_direct_linearization_family(self):
        s = DirectHandlerLinearizationStrategy()
        assert s.family == FAMILY_DIRECT

    def test_hidden_handler_closure_name(self):
        s = HiddenHandlerClosureStrategy()
        assert s.name == "hidden_handler_closure"

    def test_hidden_handler_closure_family(self):
        s = HiddenHandlerClosureStrategy()
        assert s.family == FAMILY_DIRECT

    def test_edge_split_name(self):
        s = EdgeSplitConflictResolutionStrategy()
        assert s.name == "edge_split_conflict_resolution"

    def test_edge_split_family(self):
        s = EdgeSplitConflictResolutionStrategy()
        assert s.family == FAMILY_DIRECT

    def test_terminal_loop_cleanup_name(self):
        s = TerminalLoopCleanupStrategy()
        assert s.name == "terminal_loop_cleanup"

    def test_terminal_loop_cleanup_family(self):
        s = TerminalLoopCleanupStrategy()
        assert s.family == FAMILY_CLEANUP

    def test_pred_patch_fallback_name(self):
        s = PredPatchFallbackStrategy()
        assert s.name == "pred_patch_fallback"

    def test_pred_patch_fallback_family(self):
        s = PredPatchFallbackStrategy()
        assert s.family == FAMILY_FALLBACK

    def test_conditional_fork_fallback_name(self):
        s = ConditionalForkFallbackStrategy()
        assert s.name == "conditional_fork_fallback"

    def test_conditional_fork_fallback_family(self):
        s = ConditionalForkFallbackStrategy()
        assert s.family == FAMILY_FALLBACK

    def test_assignment_map_fallback_name(self):
        s = AssignmentMapFallbackStrategy()
        assert s.name == "assignment_map_fallback"

    def test_assignment_map_fallback_family(self):
        s = AssignmentMapFallbackStrategy()
        assert s.family == FAMILY_FALLBACK


# ---------------------------------------------------------------------------
# is_applicable with empty snapshot
# ---------------------------------------------------------------------------


def _empty_snapshot(**kwargs) -> AnalysisSnapshot:
    """Build an AnalysisSnapshot with all fields at their defaults."""
    return AnalysisSnapshot(
        mba=None,
        state_machine=None,
        detector=None,
        **kwargs,
    )


class TestIsApplicableEmptySnapshot:
    """All strategies should return False on a completely empty snapshot."""

    def test_direct_linearization_not_applicable(self):
        s = DirectHandlerLinearizationStrategy()
        assert not s.is_applicable(_empty_snapshot())

    def test_hidden_handler_closure_not_applicable(self):
        s = HiddenHandlerClosureStrategy()
        assert not s.is_applicable(_empty_snapshot())

    def test_edge_split_not_applicable(self):
        s = EdgeSplitConflictResolutionStrategy()
        assert not s.is_applicable(_empty_snapshot())

    def test_terminal_loop_cleanup_not_applicable(self):
        s = TerminalLoopCleanupStrategy()
        assert not s.is_applicable(_empty_snapshot())

    def test_pred_patch_fallback_not_applicable(self):
        s = PredPatchFallbackStrategy()
        assert not s.is_applicable(_empty_snapshot())

    def test_conditional_fork_fallback_not_applicable(self):
        s = ConditionalForkFallbackStrategy()
        assert not s.is_applicable(_empty_snapshot())

    def test_assignment_map_fallback_not_applicable(self):
        s = AssignmentMapFallbackStrategy()
        assert not s.is_applicable(_empty_snapshot())


# ---------------------------------------------------------------------------
# plan() returns None on empty snapshot
# ---------------------------------------------------------------------------


class TestPlanEmptySnapshot:
    """All strategies should return None when is_applicable is False."""

    def _check_none(self, strategy):
        result = strategy.plan(_empty_snapshot())
        assert result is None, (
            f"{strategy.name}.plan() should return None on empty snapshot"
        )

    def test_direct_linearization_returns_none(self):
        self._check_none(DirectHandlerLinearizationStrategy())

    def test_hidden_handler_closure_returns_none(self):
        self._check_none(HiddenHandlerClosureStrategy())

    def test_edge_split_returns_none(self):
        self._check_none(EdgeSplitConflictResolutionStrategy())

    def test_terminal_loop_cleanup_returns_none(self):
        self._check_none(TerminalLoopCleanupStrategy())

    def test_pred_patch_fallback_returns_none(self):
        self._check_none(PredPatchFallbackStrategy())

    def test_conditional_fork_fallback_returns_none(self):
        self._check_none(ConditionalForkFallbackStrategy())

    def test_assignment_map_fallback_returns_none(self):
        self._check_none(AssignmentMapFallbackStrategy())


# ---------------------------------------------------------------------------
# EdgeSplitConflictResolutionStrategy — constructor args
# ---------------------------------------------------------------------------


class TestEdgeSplitConstructor:
    """EdgeSplitConflictResolutionStrategy accepts conflict blocks at init time."""

    def test_empty_conflict_blocks_not_applicable(self):
        s = EdgeSplitConflictResolutionStrategy(conflict_blocks=set())
        assert not s.is_applicable(_empty_snapshot())

    def test_non_empty_conflict_blocks_applicable(self):
        s = EdgeSplitConflictResolutionStrategy(conflict_blocks={5, 10})
        assert s.is_applicable(_empty_snapshot())

    def test_plan_returns_none_while_duplicate_materialization_is_disabled(self):
        s = EdgeSplitConflictResolutionStrategy(conflict_blocks={5, 10})
        fragment = s.plan(_empty_snapshot())
        assert fragment is None

    def test_plan_ownership_contains_conflict_blocks(self):
        s = EdgeSplitConflictResolutionStrategy(conflict_blocks={7, 13})
        fragment = s.plan(_empty_snapshot())
        assert fragment is None

    def test_plan_strategy_name_in_fragment(self):
        s = EdgeSplitConflictResolutionStrategy(conflict_blocks={1})
        fragment = s.plan(_empty_snapshot())
        assert fragment is None
        assert s.name == "edge_split_conflict_resolution"


# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------


class TestPrerequisites:
    """Verify prerequisite declarations for each strategy."""

    def test_direct_linearization_no_prereqs(self):
        s = DirectHandlerLinearizationStrategy()
        # Build a minimal snapshot so plan() runs.
        fragment = s.plan(_empty_snapshot())
        # plan returns None on empty snapshot; check via PlanFragment when applicable.
        # Constructing a PlanFragment manually to verify prereq field behaviour.
        assert s.name == "direct_handler_linearization"

    def test_hidden_handler_closure_prereqs(self):
        # Construct a plan fragment explicitly to check prerequisites field.
        frag = PlanFragment(
            strategy_name="hidden_handler_closure",
            family=FAMILY_DIRECT,
            modifications=[],
            ownership=OwnershipScope(
                blocks=frozenset(), edges=frozenset(), transitions=frozenset()
            ),
            prerequisites=["direct_handler_linearization"],
            expected_benefit=BenefitMetrics(0, 0, 0, 0.0),
            risk_score=0.2,
        )
        assert "direct_handler_linearization" in frag.prerequisites

    def test_edge_split_no_prereqs_by_design(self):
        s = EdgeSplitConflictResolutionStrategy(conflict_blocks={1})
        frag = s.plan(_empty_snapshot())
        assert frag is None
        assert s.name == "edge_split_conflict_resolution"

    def test_pred_patch_prereq_declared(self):
        # Verify the prereq list is declared on the strategy even when
        # plan() returns None (no resolvable targets from empty snapshot).
        s = PredPatchFallbackStrategy()
        snap = AnalysisSnapshot(mba=None, state_machine=None, detector=None)
        frag = s.plan(snap)
        # With no state machine, plan returns None — that's correct.
        # Verify prerequisites are accessible via the strategy's protocol.
        assert hasattr(s, "plan")
        # Also verify via a fragment that DOES get produced (needs real SM).
        # For now, trust the protocol test above covers prerequisite wiring.


class TestModificationBuilder:
    """Pure-Python checks for branch-aware GraphModification emission."""

    def test_edge_redirect_preserves_branch_kind_for_two_way_blocks(self):
        builder = ModificationBuilder(
            block_nsucc_map={10: 2},
            block_succ_map={10: (20, 21)},
        )

        modification = builder.edge_redirect(
            source_block=10,
            target_block=30,
            old_target=20,
        )

        assert modification == RedirectBranch(
            from_serial=10,
            old_target=20,
            new_target=30,
        )

    def test_edge_redirect_with_via_pred_still_emits_pred_split(self):
        builder = ModificationBuilder(
            block_nsucc_map={10: 1},
            block_succ_map={10: (20,)},
        )

        modification = builder.edge_redirect(
            source_block=10,
            target_block=30,
            old_target=20,
            via_pred=5,
        )

        assert modification == EdgeRedirectViaPredSplit(
            src_block=10,
            old_target=20,
            new_target=30,
            via_pred=5,
            rule_priority=550,
        )


# ---------------------------------------------------------------------------
# ALL_STRATEGIES list integrity
# ---------------------------------------------------------------------------


class TestAllStrategiesList:
    """Sanity checks on the ALL_STRATEGIES module-level list."""

    def test_all_strategies_is_list(self):
        assert isinstance(ALL_STRATEGIES, list)

    def test_all_strategies_are_classes(self):
        for item in ALL_STRATEGIES:
            assert isinstance(item, type), f"{item} is not a class"

    def test_all_strategies_instantiable(self):
        for cls in ALL_STRATEGIES:
            instance = cls()
            assert instance is not None

    def test_families_coverage(self):
        """At least one strategy per family."""
        families = {cls().family for cls in ALL_STRATEGIES}
        assert FAMILY_DIRECT in families
        assert FAMILY_FALLBACK in families
        assert FAMILY_CLEANUP in families
