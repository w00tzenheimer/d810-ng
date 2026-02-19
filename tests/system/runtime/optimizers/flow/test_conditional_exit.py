"""
Unit tests for conditional exit block detection.

These tests verify the classification logic for dispatcher exit blocks,
which is critical for proper control flow reconstruction during unflattening.
"""
import unittest
from unittest.mock import Mock

from d810.optimizers.microcode.flow.flattening.conditional_exit import (
    ExitBlockType,
    classify_exit_block,
    get_loopback_successor,
    get_exit_successor,
)


class TestClassifyExitBlock(unittest.TestCase):
    """Test cases for exit block classification."""

    def test_one_way_exit_block(self):
        """Test that a block with nsucc=1 is classified as ONE_WAY_EXIT."""
        # Create a mock block with one successor
        mock_blk = Mock()
        mock_blk.nsucc.return_value = 1
        mock_blk.succ.return_value = 10  # Single successor serial

        dispatcher_serials = {1, 2, 3, 4}

        result = classify_exit_block(mock_blk, dispatcher_serials)

        self.assertEqual(result, ExitBlockType.ONE_WAY_EXIT)

    def test_conditional_exit_with_loopback_succ0_in_dispatcher(self):
        """Test 2-way block where succ(0) is in dispatcher, succ(1) is exit."""
        mock_blk = Mock()
        mock_blk.nsucc.return_value = 2
        # succ(0) -> 2 (in dispatcher), succ(1) -> 10 (exit)
        mock_blk.succ.side_effect = lambda i: 2 if i == 0 else 10

        dispatcher_serials = {1, 2, 3, 4}

        result = classify_exit_block(mock_blk, dispatcher_serials)

        self.assertEqual(result, ExitBlockType.CONDITIONAL_EXIT_WITH_LOOPBACK)

    def test_conditional_exit_with_loopback_succ1_in_dispatcher(self):
        """Test 2-way block where succ(1) is in dispatcher, succ(0) is exit."""
        mock_blk = Mock()
        mock_blk.nsucc.return_value = 2
        # succ(0) -> 10 (exit), succ(1) -> 3 (in dispatcher)
        mock_blk.succ.side_effect = lambda i: 10 if i == 0 else 3

        dispatcher_serials = {1, 2, 3, 4}

        result = classify_exit_block(mock_blk, dispatcher_serials)

        self.assertEqual(result, ExitBlockType.CONDITIONAL_EXIT_WITH_LOOPBACK)

    def test_normal_exit_both_outside_dispatcher(self):
        """Test 2-way block where both successors are outside dispatcher."""
        mock_blk = Mock()
        mock_blk.nsucc.return_value = 2
        # Both successors outside dispatcher
        mock_blk.succ.side_effect = lambda i: 10 if i == 0 else 11

        dispatcher_serials = {1, 2, 3, 4}

        result = classify_exit_block(mock_blk, dispatcher_serials)

        self.assertEqual(result, ExitBlockType.NORMAL_EXIT)

    def test_normal_exit_both_inside_dispatcher(self):
        """Test 2-way block where both successors are inside dispatcher.

        This shouldn't happen in practice for an exit block, but we classify
        it as NORMAL_EXIT since it doesn't match the conditional-with-loopback
        pattern.
        """
        mock_blk = Mock()
        mock_blk.nsucc.return_value = 2
        # Both successors inside dispatcher
        mock_blk.succ.side_effect = lambda i: 2 if i == 0 else 3

        dispatcher_serials = {1, 2, 3, 4}

        result = classify_exit_block(mock_blk, dispatcher_serials)

        self.assertEqual(result, ExitBlockType.NORMAL_EXIT)

    def test_zero_way_block(self):
        """Test that a block with nsucc=0 is classified as ONE_WAY_EXIT."""
        mock_blk = Mock()
        mock_blk.nsucc.return_value = 0

        dispatcher_serials = {1, 2, 3}

        result = classify_exit_block(mock_blk, dispatcher_serials)

        self.assertEqual(result, ExitBlockType.ONE_WAY_EXIT)

    def test_three_way_block(self):
        """Test that a block with nsucc=3 is classified as ONE_WAY_EXIT.

        Multi-way blocks (nsucc > 2) are treated as ONE_WAY_EXIT since they
        don't match the 2-way conditional pattern.
        """
        mock_blk = Mock()
        mock_blk.nsucc.return_value = 3

        dispatcher_serials = {1, 2, 3}

        result = classify_exit_block(mock_blk, dispatcher_serials)

        self.assertEqual(result, ExitBlockType.ONE_WAY_EXIT)


class TestGetLoopbackSuccessor(unittest.TestCase):
    """Test cases for get_loopback_successor helper."""

    def test_get_loopback_successor_from_succ0(self):
        """Test retrieving loopback when it's succ(0)."""
        mock_blk = Mock()
        mock_blk.nsucc.return_value = 2
        # succ(0) -> 2 (in dispatcher), succ(1) -> 10 (exit)
        mock_blk.succ.side_effect = lambda i: 2 if i == 0 else 10

        dispatcher_serials = {1, 2, 3, 4}

        result = get_loopback_successor(mock_blk, dispatcher_serials)

        self.assertEqual(result, 2)

    def test_get_loopback_successor_from_succ1(self):
        """Test retrieving loopback when it's succ(1)."""
        mock_blk = Mock()
        mock_blk.nsucc.return_value = 2
        # succ(0) -> 10 (exit), succ(1) -> 3 (in dispatcher)
        mock_blk.succ.side_effect = lambda i: 10 if i == 0 else 3

        dispatcher_serials = {1, 2, 3, 4}

        result = get_loopback_successor(mock_blk, dispatcher_serials)

        self.assertEqual(result, 3)

    def test_get_loopback_successor_none_for_one_way(self):
        """Test that one-way blocks return None."""
        mock_blk = Mock()
        mock_blk.nsucc.return_value = 1

        dispatcher_serials = {1, 2, 3}

        result = get_loopback_successor(mock_blk, dispatcher_serials)

        self.assertIsNone(result)

    def test_get_loopback_successor_none_when_both_outside(self):
        """Test that blocks with both successors outside return None."""
        mock_blk = Mock()
        mock_blk.nsucc.return_value = 2
        # Both successors outside dispatcher
        mock_blk.succ.side_effect = lambda i: 10 if i == 0 else 11

        dispatcher_serials = {1, 2, 3}

        result = get_loopback_successor(mock_blk, dispatcher_serials)

        self.assertIsNone(result)

    def test_get_loopback_successor_succ0_when_both_inside(self):
        """Test behavior when both successors are inside dispatcher.

        In this case, we return the first one found (succ(0)).
        """
        mock_blk = Mock()
        mock_blk.nsucc.return_value = 2
        # Both successors inside dispatcher
        mock_blk.succ.side_effect = lambda i: 2 if i == 0 else 3

        dispatcher_serials = {1, 2, 3}

        result = get_loopback_successor(mock_blk, dispatcher_serials)

        # Should return succ(0) since it's checked first
        self.assertEqual(result, 2)


class TestGetExitSuccessor(unittest.TestCase):
    """Test cases for get_exit_successor helper."""

    def test_get_exit_successor_from_succ0(self):
        """Test retrieving exit when it's succ(0)."""
        mock_blk = Mock()
        mock_blk.nsucc.return_value = 2
        # succ(0) -> 10 (exit), succ(1) -> 2 (in dispatcher)
        mock_blk.succ.side_effect = lambda i: 10 if i == 0 else 2

        dispatcher_serials = {1, 2, 3, 4}

        result = get_exit_successor(mock_blk, dispatcher_serials)

        self.assertEqual(result, 10)

    def test_get_exit_successor_from_succ1(self):
        """Test retrieving exit when it's succ(1)."""
        mock_blk = Mock()
        mock_blk.nsucc.return_value = 2
        # succ(0) -> 2 (in dispatcher), succ(1) -> 10 (exit)
        mock_blk.succ.side_effect = lambda i: 2 if i == 0 else 10

        dispatcher_serials = {1, 2, 3, 4}

        result = get_exit_successor(mock_blk, dispatcher_serials)

        self.assertEqual(result, 10)

    def test_get_exit_successor_none_for_one_way(self):
        """Test that one-way blocks return None."""
        mock_blk = Mock()
        mock_blk.nsucc.return_value = 1

        dispatcher_serials = {1, 2, 3}

        result = get_exit_successor(mock_blk, dispatcher_serials)

        self.assertIsNone(result)

    def test_get_exit_successor_none_when_both_inside(self):
        """Test that blocks with both successors inside return None."""
        mock_blk = Mock()
        mock_blk.nsucc.return_value = 2
        # Both successors inside dispatcher
        mock_blk.succ.side_effect = lambda i: 2 if i == 0 else 3

        dispatcher_serials = {1, 2, 3}

        result = get_exit_successor(mock_blk, dispatcher_serials)

        self.assertIsNone(result)

    def test_get_exit_successor_succ0_when_both_outside(self):
        """Test behavior when both successors are outside dispatcher.

        In this case, we return None since there's no clear "loopback"
        to distinguish which is the "exit".
        """
        mock_blk = Mock()
        mock_blk.nsucc.return_value = 2
        # Both successors outside dispatcher
        mock_blk.succ.side_effect = lambda i: 10 if i == 0 else 11

        dispatcher_serials = {1, 2, 3}

        result = get_exit_successor(mock_blk, dispatcher_serials)

        self.assertIsNone(result)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and integration scenarios."""

    def test_empty_dispatcher_serials_set(self):
        """Test behavior with empty dispatcher set."""
        mock_blk = Mock()
        mock_blk.nsucc.return_value = 2
        mock_blk.succ.side_effect = lambda i: 2 if i == 0 else 10

        # Empty dispatcher set - all successors are "outside"
        dispatcher_serials = set()

        result = classify_exit_block(mock_blk, dispatcher_serials)

        # Both successors outside dispatcher -> NORMAL_EXIT
        self.assertEqual(result, ExitBlockType.NORMAL_EXIT)

    def test_large_dispatcher_serials_set(self):
        """Test with a large dispatcher internal blocks set."""
        mock_blk = Mock()
        mock_blk.nsucc.return_value = 2
        mock_blk.succ.side_effect = lambda i: 50 if i == 0 else 1000

        # Large set with succ(0) = 50 inside
        dispatcher_serials = set(range(1, 100))

        result = classify_exit_block(mock_blk, dispatcher_serials)

        # 50 is in dispatcher, 1000 is not -> CONDITIONAL_EXIT_WITH_LOOPBACK
        self.assertEqual(result, ExitBlockType.CONDITIONAL_EXIT_WITH_LOOPBACK)

    def test_consistency_between_functions(self):
        """Test that classify/get_loopback/get_exit are consistent."""
        mock_blk = Mock()
        mock_blk.nsucc.return_value = 2
        # succ(0) -> 3 (in dispatcher), succ(1) -> 15 (exit)
        mock_blk.succ.side_effect = lambda i: 3 if i == 0 else 15

        dispatcher_serials = {1, 2, 3, 4}

        # Classify should return CONDITIONAL_EXIT_WITH_LOOPBACK
        classification = classify_exit_block(mock_blk, dispatcher_serials)
        self.assertEqual(classification, ExitBlockType.CONDITIONAL_EXIT_WITH_LOOPBACK)

        # get_loopback_successor should return 3
        loopback = get_loopback_successor(mock_blk, dispatcher_serials)
        self.assertEqual(loopback, 3)

        # get_exit_successor should return 15
        exit_succ = get_exit_successor(mock_blk, dispatcher_serials)
        self.assertEqual(exit_succ, 15)

        # Verify loopback is in dispatcher and exit is not
        self.assertIn(loopback, dispatcher_serials)
        self.assertNotIn(exit_succ, dispatcher_serials)


if __name__ == '__main__':
    unittest.main()
