"""Unit tests for the family-owned transition lowering invariant.

The invariant: when a 1-way feeder block has multiple predecessors and
the transition is owned by one predecessor family, a whole-block
RedirectGoto would merge all families into one target — silently
collapsing distinct semantic paths and killing returns.

The fix: use pred-scoped lowering (duplicate-and-redirect) to clone the
source block and redirect only the owning predecessor.

These tests verify the predicate ``requires_pred_scoped_lowering`` and
the helper ``derive_edge_predecessor`` that together enforce this
invariant.

Ticket: d81-3hdl (family-owned transition lowering)
"""
from __future__ import annotations

import pytest

from d810.transforms.lowering_scope import (
    LoweringScope,
    derive_edge_predecessor,
    requires_pred_scoped_lowering,
)


class TestRequiresPredScopedLowering:
    """Positive and negative cases for the lowering-scope predicate."""

    def test_shared_source_with_path_requires_pred_scoped(self):
        """Shared block (npred=2) + valid ordered_path => pred-scoped."""
        assert requires_pred_scoped_lowering(
            source_serial=156,
            pred_count=2,
            ordered_path=(154, 156),
        )

    def test_shared_source_many_preds_requires_pred_scoped(self):
        """Shared block (npred=5) + valid ordered_path => pred-scoped."""
        assert requires_pred_scoped_lowering(
            source_serial=32,
            pred_count=5,
            ordered_path=(23, 24, 32),
        )

    def test_single_pred_allows_block_scope(self):
        """Single-pred block (npred=1) => block-scope redirect is safe."""
        assert not requires_pred_scoped_lowering(
            source_serial=156,
            pred_count=1,
            ordered_path=(154, 156),
        )

    def test_zero_pred_allows_block_scope(self):
        """Zero-pred block (unreachable edge case) => block-scope."""
        assert not requires_pred_scoped_lowering(
            source_serial=10,
            pred_count=0,
            ordered_path=(8, 10),
        )

    def test_shared_source_no_path_allows_block_scope(self):
        """Shared block but no ordered_path => can't identify owner, block-scope."""
        assert not requires_pred_scoped_lowering(
            source_serial=156,
            pred_count=3,
            ordered_path=None,
        )

    def test_shared_source_empty_path_allows_block_scope(self):
        """Shared block but empty ordered_path => can't identify owner, block-scope."""
        assert not requires_pred_scoped_lowering(
            source_serial=156,
            pred_count=3,
            ordered_path=(),
        )

    def test_shared_source_empty_list_path_allows_block_scope(self):
        """Shared block but empty list path => block-scope."""
        assert not requires_pred_scoped_lowering(
            source_serial=156,
            pred_count=2,
            ordered_path=[],
        )

    def test_accepts_list_path(self):
        """ordered_path can be a list, not just a tuple."""
        assert requires_pred_scoped_lowering(
            source_serial=156,
            pred_count=2,
            ordered_path=[154, 156],
        )


class TestDeriveEdgePredecessor:
    """Extract owning predecessor from corridor path."""

    def test_two_element_path(self):
        """Path (154, 156) => predecessor is 154."""
        assert derive_edge_predecessor((154, 156)) == 154

    def test_three_element_path(self):
        """Path (23, 24, 32) => predecessor is 24 (second-to-last)."""
        assert derive_edge_predecessor((23, 24, 32)) == 24

    def test_single_element_path(self):
        """Path (156,) => predecessor is 156 itself (degenerate case)."""
        assert derive_edge_predecessor((156,)) == 156

    def test_long_path(self):
        """Path (10, 20, 30, 40, 50) => predecessor is 40."""
        assert derive_edge_predecessor((10, 20, 30, 40, 50)) == 40

    def test_empty_path_raises(self):
        """Empty path is a programming error — must raise."""
        with pytest.raises(ValueError, match="non-empty"):
            derive_edge_predecessor(())

    def test_accepts_list(self):
        """Works with list input too."""
        assert derive_edge_predecessor([100, 200, 300]) == 200


class TestLoweringScopeConstants:
    """Smoke test for LoweringScope labels."""

    def test_block_scope(self):
        assert LoweringScope.BLOCK == "block"

    def test_pred_scoped(self):
        assert LoweringScope.PRED_SCOPED == "pred_scoped"
