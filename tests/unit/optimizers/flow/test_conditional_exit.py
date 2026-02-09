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
    find_state_assignment_in_block,
    resolve_loopback_target,
)


class TestExitBlockClassification(unittest.TestCase):
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


class TestFindStateAssignment(unittest.TestCase):
    """Test cases for find_state_assignment_in_block."""

    def _create_mock_mop(self, mop_type, value=None):
        """Create a mock mop_t object."""
        mock_mop = Mock()
        mock_mop.t = mop_type
        if value is not None:
            mock_mop.nnn = Mock()
            mock_mop.nnn.value = value
        return mock_mop

    def _create_mock_instruction(self, opcode, dest_mop, src_mop, prev_ins=None):
        """Create a mock instruction."""
        mock_ins = Mock()
        mock_ins.opcode = opcode
        mock_ins.d = dest_mop
        mock_ins.l = src_mop
        mock_ins.prev = prev_ins
        return mock_ins

    def test_find_state_assignment_constant(self):
        """Test finding a constant state assignment."""
        try:
            import ida_hexrays
        except ImportError:
            self.skipTest("IDA not available")

        # Import the module to directly set IDA_AVAILABLE
        import d810.optimizers.microcode.flow.flattening.conditional_exit as ce_mod

        # Create mock state mop
        state_mop = self._create_mock_mop(ida_hexrays.mop_r)

        # Create mock constant mop with value 0xABCD1234
        const_mop = self._create_mock_mop(ida_hexrays.mop_n, 0xABCD1234)

        # Create mock mov instruction: mov state, 0xABCD1234
        mock_ins = self._create_mock_instruction(
            ida_hexrays.m_mov, state_mop, const_mop, prev_ins=None
        )

        # Create mock block
        mock_blk = Mock()
        mock_blk.tail = mock_ins

        # Create mock equal_mops_ignore_size function
        def mock_equal(a, b):
            return a == state_mop

        # Directly set module attributes
        original_ida_available = ce_mod.IDA_AVAILABLE

        from unittest.mock import patch

        try:
            ce_mod.IDA_AVAILABLE = True

            # Patch the actual import target, not sys.modules
            # When the function does "from d810.hexrays.hexrays_helpers import equal_mops_ignore_size",
            # we need to mock d810.hexrays.hexrays_helpers.equal_mops_ignore_size
            with patch('d810.hexrays.hexrays_helpers.equal_mops_ignore_size', mock_equal):
                result = find_state_assignment_in_block(mock_blk, state_mop)
                self.assertEqual(result, 0xABCD1234)
        finally:
            # Restore original values
            ce_mod.IDA_AVAILABLE = original_ida_available

    def test_find_state_assignment_no_assignment(self):
        """Test block without state assignment returns None."""
        try:
            import ida_hexrays
        except ImportError:
            self.skipTest("IDA not available")

        # Import the module to directly set IDA_AVAILABLE
        import d810.optimizers.microcode.flow.flattening.conditional_exit as ce_mod

        state_mop = self._create_mock_mop(ida_hexrays.mop_r)

        # Create mock instruction that doesn't write to state
        other_mop = self._create_mock_mop(ida_hexrays.mop_r)
        const_mop = self._create_mock_mop(ida_hexrays.mop_n, 42)
        mock_ins = self._create_mock_instruction(
            ida_hexrays.m_mov, other_mop, const_mop, prev_ins=None
        )

        mock_blk = Mock()
        mock_blk.tail = mock_ins

        # Create mock equal_mops_ignore_size function that returns False
        def mock_equal(a, b):
            return False

        # Directly set module attributes
        original_ida_available = ce_mod.IDA_AVAILABLE

        from unittest.mock import patch

        try:
            ce_mod.IDA_AVAILABLE = True

            # Patch the actual import target
            with patch('d810.hexrays.hexrays_helpers.equal_mops_ignore_size', mock_equal):
                result = find_state_assignment_in_block(mock_blk, state_mop)
                self.assertIsNone(result)
        finally:
            ce_mod.IDA_AVAILABLE = original_ida_available

    def test_find_state_assignment_non_constant(self):
        """Test that computed (non-constant) assignment returns None."""
        try:
            import ida_hexrays
        except ImportError:
            self.skipTest("IDA not available")

        # Import the module to directly set IDA_AVAILABLE
        import d810.optimizers.microcode.flow.flattening.conditional_exit as ce_mod

        state_mop = self._create_mock_mop(ida_hexrays.mop_r)

        # Create mock register mop (computed value, not constant)
        reg_mop = self._create_mock_mop(ida_hexrays.mop_r)

        # Create mock mov instruction: mov state, rax (not constant)
        mock_ins = self._create_mock_instruction(
            ida_hexrays.m_mov, state_mop, reg_mop, prev_ins=None
        )

        mock_blk = Mock()
        mock_blk.tail = mock_ins

        # Create mock equal_mops_ignore_size function that returns True
        def mock_equal(a, b):
            return a == state_mop

        # Directly set module attributes
        original_ida_available = ce_mod.IDA_AVAILABLE

        from unittest.mock import patch

        try:
            ce_mod.IDA_AVAILABLE = True

            # Patch the actual import target
            with patch('d810.hexrays.hexrays_helpers.equal_mops_ignore_size', mock_equal):
                result = find_state_assignment_in_block(mock_blk, state_mop)
                # Should return None because source is not a constant
                self.assertIsNone(result)
        finally:
            ce_mod.IDA_AVAILABLE = original_ida_available

    def test_find_state_assignment_none_state_mop(self):
        """Test that None state_mop returns None."""
        mock_blk = Mock()
        result = find_state_assignment_in_block(mock_blk, None)
        self.assertIsNone(result)

    def test_find_state_assignment_scans_backward(self):
        """Test that function scans backward through instructions."""
        try:
            import ida_hexrays
        except ImportError:
            self.skipTest("IDA not available")

        # Import the module to directly set IDA_AVAILABLE
        import d810.optimizers.microcode.flow.flattening.conditional_exit as ce_mod

        state_mop = self._create_mock_mop(ida_hexrays.mop_r)
        const_mop = self._create_mock_mop(ida_hexrays.mop_n, 0x1234)

        # Create chain: tail -> middle -> head
        # Only head has the state assignment
        head_ins = self._create_mock_instruction(
            ida_hexrays.m_mov, state_mop, const_mop, prev_ins=None
        )

        middle_ins = self._create_mock_instruction(
            ida_hexrays.m_add,
            self._create_mock_mop(ida_hexrays.mop_r),
            self._create_mock_mop(ida_hexrays.mop_r),
            prev_ins=head_ins
        )

        tail_ins = self._create_mock_instruction(
            ida_hexrays.m_add,
            self._create_mock_mop(ida_hexrays.mop_r),
            self._create_mock_mop(ida_hexrays.mop_r),
            prev_ins=middle_ins
        )

        mock_blk = Mock()
        mock_blk.tail = tail_ins

        # Create mock equal_mops_ignore_size function
        def mock_equal(a, b):
            return a == state_mop

        # Directly set module attributes
        original_ida_available = ce_mod.IDA_AVAILABLE

        from unittest.mock import patch

        try:
            ce_mod.IDA_AVAILABLE = True

            # Patch the actual import target
            with patch('d810.hexrays.hexrays_helpers.equal_mops_ignore_size', mock_equal):
                result = find_state_assignment_in_block(mock_blk, state_mop)
                self.assertEqual(result, 0x1234)
        finally:
            ce_mod.IDA_AVAILABLE = original_ida_available


class TestResolveLoopbackTarget(unittest.TestCase):
    """Test cases for resolve_loopback_target."""

    def test_resolve_loopback_with_known_state(self):
        """Test resolving loopback when state value is in dispatcher mapping."""
        try:
            import ida_hexrays
        except ImportError:
            self.skipTest("IDA not available")

        # Create mock exit block
        mock_exit_blk = Mock()
        mock_mba = Mock()
        mock_exit_blk.mba = mock_mba

        # Create mock loopback block with state assignment
        mock_loopback_blk = Mock()
        mock_mba.get_mblock.return_value = mock_loopback_blk

        # Create mock dispatcher info with exit blocks
        mock_dispatcher_info = Mock()

        # Create mock exit block info with comparison_value = 0xABCD1234
        mock_exit_block_info = Mock()
        mock_exit_block_info.comparison_value = 0xABCD1234
        mock_exit_block_info.serial = 5

        mock_dispatcher_info.dispatcher_exit_blocks = [mock_exit_block_info]

        state_mop = Mock()

        from unittest.mock import patch
        with patch('d810.optimizers.microcode.flow.flattening.conditional_exit.IDA_AVAILABLE', True):
            with patch('d810.optimizers.microcode.flow.flattening.conditional_exit.find_state_assignment_in_block') as mock_find:
                mock_find.return_value = 0xABCD1234
                result = resolve_loopback_target(
                    mock_exit_blk, 2, mock_dispatcher_info, state_mop
                )

        self.assertEqual(result, (5, 0xABCD1234))

    def test_resolve_loopback_unknown_state(self):
        """Test that unknown state value returns None."""
        try:
            import ida_hexrays
        except ImportError:
            self.skipTest("IDA not available")

        mock_exit_blk = Mock()
        mock_mba = Mock()
        mock_exit_blk.mba = mock_mba

        mock_loopback_blk = Mock()
        mock_mba.get_mblock.return_value = mock_loopback_blk

        mock_dispatcher_info = Mock()

        # Dispatcher has different state value (0x5678, not 0xABCD1234)
        mock_exit_block_info = Mock()
        mock_exit_block_info.comparison_value = 0x5678
        mock_exit_block_info.serial = 5

        mock_dispatcher_info.dispatcher_exit_blocks = [mock_exit_block_info]

        state_mop = Mock()

        from unittest.mock import patch
        with patch('d810.optimizers.microcode.flow.flattening.conditional_exit.IDA_AVAILABLE', True):
            with patch('d810.optimizers.microcode.flow.flattening.conditional_exit.find_state_assignment_in_block') as mock_find:
                mock_find.return_value = 0xABCD1234  # Different from dispatcher's 0x5678
                result = resolve_loopback_target(
                    mock_exit_blk, 2, mock_dispatcher_info, state_mop
                )

        self.assertIsNone(result)

    def test_resolve_loopback_no_constant_assignment(self):
        """Test that computed state assignment returns None."""
        try:
            import ida_hexrays
        except ImportError:
            self.skipTest("IDA not available")

        mock_exit_blk = Mock()
        mock_mba = Mock()
        mock_exit_blk.mba = mock_mba

        mock_loopback_blk = Mock()
        mock_mba.get_mblock.return_value = mock_loopback_blk

        mock_dispatcher_info = Mock()
        state_mop = Mock()

        from unittest.mock import patch
        with patch('d810.optimizers.microcode.flow.flattening.conditional_exit.IDA_AVAILABLE', True):
            with patch('d810.optimizers.microcode.flow.flattening.conditional_exit.find_state_assignment_in_block') as mock_find:
                mock_find.return_value = None  # No constant assignment
                result = resolve_loopback_target(
                    mock_exit_blk, 2, mock_dispatcher_info, state_mop
                )

        self.assertIsNone(result)

    def test_resolve_loopback_invalid_block_serial(self):
        """Test that invalid loopback block serial returns None."""
        try:
            import ida_hexrays
        except ImportError:
            self.skipTest("IDA not available")

        mock_exit_blk = Mock()
        mock_mba = Mock()
        mock_exit_blk.mba = mock_mba

        # get_mblock returns None (invalid serial)
        mock_mba.get_mblock.return_value = None

        mock_dispatcher_info = Mock()
        state_mop = Mock()

        from unittest.mock import patch
        with patch('d810.optimizers.microcode.flow.flattening.conditional_exit.IDA_AVAILABLE', True):
            result = resolve_loopback_target(
                mock_exit_blk, 999, mock_dispatcher_info, state_mop
            )

        self.assertIsNone(result)

    def test_resolve_loopback_multiple_exit_blocks(self):
        """Test resolving with multiple exit blocks in dispatcher."""
        try:
            import ida_hexrays
        except ImportError:
            self.skipTest("IDA not available")

        mock_exit_blk = Mock()
        mock_mba = Mock()
        mock_exit_blk.mba = mock_mba

        mock_loopback_blk = Mock()
        mock_mba.get_mblock.return_value = mock_loopback_blk

        mock_dispatcher_info = Mock()

        # Multiple exit blocks with different state values
        mock_exit_1 = Mock()
        mock_exit_1.comparison_value = 0x1111
        mock_exit_1.serial = 10

        mock_exit_2 = Mock()
        mock_exit_2.comparison_value = 0xABCD1234
        mock_exit_2.serial = 20

        mock_exit_3 = Mock()
        mock_exit_3.comparison_value = 0x3333
        mock_exit_3.serial = 30

        mock_dispatcher_info.dispatcher_exit_blocks = [mock_exit_1, mock_exit_2, mock_exit_3]

        state_mop = Mock()

        from unittest.mock import patch
        with patch('d810.optimizers.microcode.flow.flattening.conditional_exit.IDA_AVAILABLE', True):
            with patch('d810.optimizers.microcode.flow.flattening.conditional_exit.find_state_assignment_in_block') as mock_find:
                mock_find.return_value = 0xABCD1234  # Matches mock_exit_2
                result = resolve_loopback_target(
                    mock_exit_blk, 2, mock_dispatcher_info, state_mop
                )

        # Should find the matching exit block (serial 20)
        self.assertEqual(result, (20, 0xABCD1234))


if __name__ == '__main__':
    unittest.main()
