"""Tests for EDGE_REDIRECT_VIA_PRED_SPLIT queue/coalesce logic.

These tests exercise the pure list-manipulation logic in DeferredGraphModifier:
- queue_edge_redirect() delegation and queuing
- coalesce() deduplication and conflict resolution for the new mod type
- Priority ordering

Runs in IDA environment (system/runtime); skips gracefully without IDA.
"""
from __future__ import annotations

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.hexrays.mutation.deferred_modifier import (
    DeferredGraphModifier,
    GraphModification,
    ModificationType,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_modifier() -> "DeferredGraphModifier":
    """Return a DeferredGraphModifier with mba=None (queue/coalesce are pure)."""
    return DeferredGraphModifier(mba=None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Test 1: queue_edge_redirect with via_pred=None delegates to queue_goto_change
# ---------------------------------------------------------------------------

class TestQueueEdgeRedirectDelegation:

    def test_via_pred_none_produces_goto_change_type(self):
        """When via_pred is None, queue_edge_redirect produces BLOCK_GOTO_CHANGE."""
        m = _make_modifier()
        m.queue_edge_redirect(
            src_block=10, old_target=20, new_target=30, via_pred=None,
        )
        assert len(m.modifications) == 1
        mod = m.modifications[0]
        assert mod.mod_type == ModificationType.BLOCK_GOTO_CHANGE
        assert mod.block_serial == 10
        assert mod.new_target == 30

    def test_via_pred_none_preserves_rule_priority(self):
        """Legacy delegation preserves rule_priority."""
        m = _make_modifier()
        m.queue_edge_redirect(
            src_block=5, old_target=15, new_target=25,
            via_pred=None, rule_priority=42,
        )
        assert m.modifications[0].rule_priority == 42


# ---------------------------------------------------------------------------
# Test 2: queue_edge_redirect with via_pred creates EDGE_REDIRECT_VIA_PRED_SPLIT
# ---------------------------------------------------------------------------

class TestQueueEdgeRedirectNewType:

    def test_via_pred_creates_edge_redirect_type(self):
        """With via_pred set, mod type must be EDGE_REDIRECT_VIA_PRED_SPLIT."""
        m = _make_modifier()
        m.queue_edge_redirect(
            src_block=10, old_target=20, new_target=30, via_pred=5,
        )
        assert len(m.modifications) == 1
        assert m.modifications[0].mod_type == ModificationType.EDGE_REDIRECT_VIA_PRED_SPLIT

    def test_via_pred_stores_all_fields(self):
        """All edge-redirect fields are populated correctly."""
        m = _make_modifier()
        m.queue_edge_redirect(
            src_block=10, old_target=20, new_target=30, via_pred=5,
            clone_until=99, rule_priority=7,
        )
        mod = m.modifications[0]
        assert mod.src_block == 10
        assert mod.old_target == 20
        assert mod.new_target == 30
        assert mod.via_pred == 5
        assert mod.clone_until == 99
        assert mod.rule_priority == 7
        # block_serial must equal src_block for logging/dispatch compatibility
        assert mod.block_serial == 10

    def test_via_pred_priority_is_8(self):
        """EDGE_REDIRECT_VIA_PRED_SPLIT must have priority=8."""
        m = _make_modifier()
        m.queue_edge_redirect(src_block=1, old_target=2, new_target=3, via_pred=0)
        assert m.modifications[0].priority == 8


# ---------------------------------------------------------------------------
# Test 3: coalesce deduplication --- exact duplicates are dropped
# ---------------------------------------------------------------------------

class TestCoalesceDedup:

    def test_duplicate_edge_redirect_is_removed(self):
        """Two identical EDGE_REDIRECT_VIA_PRED_SPLIT mods reduce to one."""
        m = _make_modifier()
        for _ in range(2):
            m.queue_edge_redirect(
                src_block=10, old_target=20, new_target=30, via_pred=5,
            )
        removed = m.coalesce()
        assert removed == 1
        assert len(m.modifications) == 1

    def test_distinct_via_pred_both_kept(self):
        """Two redirects with different via_pred must both survive dedup."""
        m = _make_modifier()
        m.queue_edge_redirect(src_block=10, old_target=20, new_target=30, via_pred=5)
        m.queue_edge_redirect(src_block=10, old_target=20, new_target=30, via_pred=6)
        m.coalesce()
        # Different via_pred values => different dedup keys => both kept
        assert len(m.modifications) == 2

    def test_distinct_via_pred_different_new_target_both_kept(self):
        """Two redirects sharing src_block but with different via_pred and new_target both survive.

        Regression guard for the generic same-type conflict pass: grouping by
        (mod_type, block_serial) collapsed entries that share src_block but differ
        in via_pred when new_target also differed.  The fix skips
        EDGE_REDIRECT_VIA_PRED_SPLIT in that pass so both entries survive.
        """
        m = _make_modifier()
        m.queue_edge_redirect(src_block=10, old_target=20, new_target=30, via_pred=5)
        m.queue_edge_redirect(src_block=10, old_target=20, new_target=99, via_pred=6)
        m.coalesce()
        assert len(m.modifications) == 2
        new_targets = {mod.new_target for mod in m.modifications}
        assert new_targets == {30, 99}


# ---------------------------------------------------------------------------
# Test 4: coalesce conflict resolution --- highest rule_priority wins
# ---------------------------------------------------------------------------

class TestCoalesceConflict:

    def test_highest_rule_priority_wins(self):
        """Same (src, old, via_pred) but different new_target: higher rule_priority wins."""
        m = _make_modifier()
        m.queue_edge_redirect(
            src_block=10, old_target=20, new_target=30, via_pred=5, rule_priority=10,
        )
        m.queue_edge_redirect(
            src_block=10, old_target=20, new_target=99, via_pred=5, rule_priority=50,
        )
        m.coalesce()
        assert len(m.modifications) == 1
        assert m.modifications[0].new_target == 99
        assert m.modifications[0].rule_priority == 50

    def test_lower_priority_loses(self):
        """Lower rule_priority mod is discarded."""
        m = _make_modifier()
        m.queue_edge_redirect(
            src_block=7, old_target=8, new_target=100, via_pred=3, rule_priority=100,
        )
        m.queue_edge_redirect(
            src_block=7, old_target=8, new_target=200, via_pred=3, rule_priority=1,
        )
        m.coalesce()
        assert len(m.modifications) == 1
        assert m.modifications[0].new_target == 100


# ---------------------------------------------------------------------------
# Test 5: coalesce no cross-contamination with BLOCK_GOTO_CHANGE
# ---------------------------------------------------------------------------

class TestCoalesceNoCrossContamination:

    def test_edge_redirect_survives_over_goto_change(self):
        """EDGE_REDIRECT (rank=6) beats BLOCK_GOTO_CHANGE (rank=1) in terminal conflict."""
        m = _make_modifier()
        m.queue_goto_change(block_serial=10, new_target=30, rule_priority=1)
        m.queue_edge_redirect(
            src_block=10, old_target=20, new_target=50, via_pred=5, rule_priority=5,
        )
        m.coalesce()
        surviving_types = {mod.mod_type for mod in m.modifications}
        assert ModificationType.EDGE_REDIRECT_VIA_PRED_SPLIT in surviving_types

    def test_goto_dedup_independent_of_edge_redirect(self):
        """BLOCK_GOTO_CHANGE dedup is independent of edge-redirect dedup."""
        m = _make_modifier()
        m.queue_goto_change(block_serial=1, new_target=2)
        m.queue_goto_change(block_serial=1, new_target=2)  # duplicate
        m.queue_edge_redirect(src_block=3, old_target=4, new_target=5, via_pred=6)
        removed = m.coalesce()
        assert removed >= 1
        edge_mods = [
            mod for mod in m.modifications
            if mod.mod_type == ModificationType.EDGE_REDIRECT_VIA_PRED_SPLIT
        ]
        assert len(edge_mods) == 1


# ---------------------------------------------------------------------------
# Test 6: priority ordering --- EDGE_REDIRECT (8) sorts between 5 and 10
# ---------------------------------------------------------------------------

class TestPriorityOrdering:

    def test_edge_redirect_priority_between_create_and_goto(self):
        """EDGE_REDIRECT priority=8 sorts after CREATE (5) and before GOTO (10)."""
        mods = [
            GraphModification(
                mod_type=ModificationType.BLOCK_CREATE_WITH_REDIRECT,
                block_serial=1, new_target=2, priority=5,
            ),
            GraphModification(
                mod_type=ModificationType.EDGE_REDIRECT_VIA_PRED_SPLIT,
                block_serial=3, new_target=4, priority=8,
                src_block=3, old_target=10, via_pred=0,
            ),
            GraphModification(
                mod_type=ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=5, new_target=6, priority=10,
            ),
        ]
        sorted_mods = sorted(mods, key=lambda mod: mod.priority)
        assert sorted_mods[0].mod_type == ModificationType.BLOCK_CREATE_WITH_REDIRECT
        assert sorted_mods[1].mod_type == ModificationType.EDGE_REDIRECT_VIA_PRED_SPLIT
        assert sorted_mods[2].mod_type == ModificationType.BLOCK_GOTO_CHANGE

    def test_edge_redirect_priority_value_is_8(self):
        """queue_edge_redirect assigns priority=8."""
        m = _make_modifier()
        m.queue_edge_redirect(src_block=1, old_target=2, new_target=3, via_pred=0)
        assert m.modifications[0].priority == 8
