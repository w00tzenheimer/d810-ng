"""Unit tests for dispatcher father tracking logic.

The dispatcher father tracking mechanism prevents duplicate processing of the same
(source_block, target_block) pairs during control flow graph unflattening.

This module tests the pure set-operation logic without importing IDA modules.
The actual GenericDispatcherUnflatteningRule uses a set[tuple[int, int]] attribute
named _processed_dispatcher_fathers to track (dispatcher_father.serial, target_blk.serial) pairs.

These tests validate the mathematical properties of that tracking mechanism:
- Initialization creates empty set
- Pairs are deduplicated correctly
- Different pairs are tracked independently
- Set can be cleared for new optimization passes
"""

import pytest


@pytest.mark.pure_python
class TestDispatcherFatherTrackingLogic:
    """Tests for set-based (source, target) pair tracking logic."""

    def test_initialization_creates_empty_set(self):
        """The tracking set should start empty."""
        tracking_set: set[tuple[int, int]] = set()

        assert isinstance(tracking_set, set)
        assert len(tracking_set) == 0

    def test_duplicate_pair_is_detected(self):
        """When the same (source, target) pair is added twice, the second is ignored."""
        tracking_set: set[tuple[int, int]] = set()

        pair = (10, 20)

        # First add
        assert pair not in tracking_set
        tracking_set.add(pair)
        assert pair in tracking_set

        # Second add (duplicate) - set handles this automatically
        tracking_set.add(pair)
        assert len(tracking_set) == 1  # Still only one entry

    def test_different_pairs_are_both_tracked(self):
        """Different (source, target) pairs should all be tracked."""
        tracking_set: set[tuple[int, int]] = set()

        # Pair 1: source=10, target=20
        pair1 = (10, 20)

        # Pair 2: source=10, target=30 (same source, different target)
        pair2 = (10, 30)

        # Pair 3: source=15, target=20 (different source, same target)
        pair3 = (15, 20)

        # Add pair 1
        assert pair1 not in tracking_set
        tracking_set.add(pair1)
        assert pair1 in tracking_set

        # Pair 2 and 3 should still be untracked
        assert pair2 not in tracking_set
        assert pair3 not in tracking_set

        # Add pair 2 and 3
        tracking_set.add(pair2)
        tracking_set.add(pair3)

        # All three pairs should now be tracked
        assert pair1 in tracking_set
        assert pair2 in tracking_set
        assert pair3 in tracking_set
        assert len(tracking_set) == 3

    def test_tracking_cleared_between_passes(self):
        """The tracking set should be clearable for new optimization passes."""
        tracking_set: set[tuple[int, int]] = set()

        # Add some pairs
        tracking_set.add((10, 20))
        tracking_set.add((15, 25))
        assert len(tracking_set) == 2

        # Clear for new pass
        tracking_set.clear()

        # Verify empty
        assert len(tracking_set) == 0

    def test_tracking_persists_within_single_pass(self):
        """Within a single pass, tracking should accumulate across multiple operations."""
        tracking_set: set[tuple[int, int]] = set()

        # Simulate processing multiple dispatcher fathers within one pass
        # Dispatcher 1: fathers (5, 10), (5, 15)
        tracking_set.add((5, 10))
        tracking_set.add((5, 15))

        # Dispatcher 2: fathers (8, 20), (8, 25)
        tracking_set.add((8, 20))
        tracking_set.add((8, 25))

        # All should be tracked
        assert len(tracking_set) == 4
        assert (5, 10) in tracking_set
        assert (5, 15) in tracking_set
        assert (8, 20) in tracking_set
        assert (8, 25) in tracking_set

    def test_same_source_different_targets(self):
        """Same source block with different targets should be tracked separately."""
        tracking_set: set[tuple[int, int]] = set()

        source = 10
        target1 = 20
        target2 = 30

        # Both pairs should be trackable
        tracking_set.add((source, target1))
        tracking_set.add((source, target2))

        assert (source, target1) in tracking_set
        assert (source, target2) in tracking_set
        assert len(tracking_set) == 2

    def test_same_target_different_sources(self):
        """Same target block with different sources should be tracked separately."""
        tracking_set: set[tuple[int, int]] = set()

        source1 = 10
        source2 = 15
        target = 20

        # Both pairs should be trackable
        tracking_set.add((source1, target))
        tracking_set.add((source2, target))

        assert (source1, target) in tracking_set
        assert (source2, target) in tracking_set
        assert len(tracking_set) == 2

    def test_zero_serials_are_valid(self):
        """Block serial 0 is valid and should be tracked correctly."""
        tracking_set: set[tuple[int, int]] = set()

        # Block 0 is the entry block in IDA - it's valid
        tracking_set.add((0, 5))
        tracking_set.add((5, 0))
        tracking_set.add((0, 0))  # Self-loop edge case

        assert (0, 5) in tracking_set
        assert (5, 0) in tracking_set
        assert (0, 0) in tracking_set
        assert len(tracking_set) == 3
