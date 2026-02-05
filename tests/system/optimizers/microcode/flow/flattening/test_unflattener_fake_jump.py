"""Tests for UnflattenerFakeJump optimizer.

This module tests the fake jump/loop removal optimization that detects
conditional jumps that are always taken or never taken from specific
predecessor blocks.

The UnflattenerFakeJump optimizer:
1. Identifies blocks with fake loop opcodes (m_jz/m_jnz)
2. Tracks comparison values backward through predecessors
3. Determines if jump is always/never taken
4. Redirects control flow to eliminate fake jumps

Test Coverage:
- Block analysis for fake jump detection
- Successor fixing based on comparison values
- Integration with optimization pipeline
- Edge cases (empty predecessors, unresolved paths, etc.)
"""

import sys
from unittest.mock import Mock, MagicMock, patch, call
import pytest


# Mock IDA before any imports
@pytest.fixture(scope="session", autouse=True)
def mock_ida_modules():
    """Mock all IDA-related modules at session level."""
    # Mock ida_hexrays with all required constants
    mock_ida_hexrays = MagicMock()
    
    # Mock opcode constants
    mock_ida_hexrays.m_jz = 0x31
    mock_ida_hexrays.m_jnz = 0x30
    mock_ida_hexrays.m_goto = 0x40
    mock_ida_hexrays.m_mov = 0x01

    # Mock mop_t types
    mock_ida_hexrays.mop_n = 2
    mock_ida_hexrays.mop_r = 1
    mock_ida_hexrays.mop_d = 4

    # Mock maturity levels (all of them to avoid sorting issues)
    mock_ida_hexrays.MMAT_ZERO = 0
    mock_ida_hexrays.MMAT_GENERATED = 10
    mock_ida_hexrays.MMAT_PREOPTIMIZED = 15
    mock_ida_hexrays.MMAT_LOCOPT = 20
    mock_ida_hexrays.MMAT_CALLS = 25
    mock_ida_hexrays.MMAT_GLBOPT1 = 30
    mock_ida_hexrays.MMAT_GLBOPT2 = 35
    mock_ida_hexrays.MMAT_GLBOPT3 = 40
    mock_ida_hexrays.MMAT_LVARS = 45

    # Mock mop_t class
    def mock_mop_t_constructor(arg=None):
        result = MagicMock()
        if arg is not None:
            result.t = getattr(arg, 't', 0)
            result.nnn = getattr(arg, 'nnn', MagicMock(value=0))
        else:
            result.t = 0
            result.nnn = MagicMock(value=0)
        return result

    mock_ida_hexrays.mop_t = mock_mop_t_constructor

    # Configure __dir__ to return all MMAT_ constants
    original_dir = lambda self=None: ['m_jz', 'm_jnz', 'm_goto', 'm_mov', 'mop_n', 'mop_r', 'mop_d', 'mop_t',
                            'MMAT_ZERO', 'MMAT_GENERATED', 'MMAT_PREOPTIMIZED', 'MMAT_LOCOPT',
                            'MMAT_CALLS', 'MMAT_GLBOPT1', 'MMAT_GLBOPT2', 'MMAT_GLBOPT3', 'MMAT_LVARS']
    mock_ida_hexrays.__dir__ = original_dir
    
    # Mock idaapi
    mock_idaapi = MagicMock()
    
    # Mock ida_kernwin  
    mock_ida_kernwin = MagicMock()

    sys.modules['ida_hexrays'] = mock_ida_hexrays
    sys.modules['idaapi'] = mock_idaapi
    sys.modules['ida_kernwin'] = mock_ida_kernwin
    yield mock_ida_hexrays


@pytest.fixture
def unflatten_rule():
    """Create UnflattenerFakeJump instance with mocked dependencies."""
    # Import after mocking is in place
    with patch('d810.core.getLogger'):
        from d810.optimizers.microcode.flow.flattening.unflattener_fake_jump import UnflattenerFakeJump
        
        rule = UnflattenerFakeJump()
        rule.dump_intermediate_microcode = False
        rule.log_dir = "/tmp/test"
        rule.cur_maturity_pass = 0
        
        return rule


def create_mock_block(serial=0, tail_opcode=None, reginsn_qty=1, predset=None):
    """Helper to create a mock mblock_t."""
    block = MagicMock()
    block.serial = serial
    block.get_reginsn_qty.return_value = reginsn_qty
    block.predset = predset if predset is not None else []
    
    if tail_opcode is not None:
        block.tail = MagicMock()
        block.tail.opcode = tail_opcode
        block.tail.l = MagicMock()
        block.tail.r = MagicMock()
        block.tail.r.t = 2  # mop_n
        block.tail.r.nnn = MagicMock(value=42)
        block.tail.d = MagicMock()
        block.tail.d.b = 10  # Jump destination
    else:
        block.tail = None
    
    block.mba = MagicMock()
    block.mba.get_mblock = MagicMock()
    
    return block


class TestUnflattenerFakeJumpInit:
    """Tests for UnflattenerFakeJump initialization and configuration."""

    def test_class_attributes(self, unflatten_rule):
        """Test class-level configuration attributes."""
        assert unflatten_rule.DESCRIPTION == "Check if a jump is always taken for each father blocks and remove them"
        assert unflatten_rule.DEFAULT_MAX_PASSES is None
        assert hasattr(unflatten_rule, 'DEFAULT_UNFLATTENING_MATURITIES')


class TestAnalyzeBlk:
    """Tests for analyze_blk method - fake jump detection logic."""

    def test_analyze_blk_no_tail_returns_zero(self, unflatten_rule, mock_ida_modules):
        """Block with no tail instruction returns 0 changes."""
        block = create_mock_block(serial=1, tail_opcode=None)
        
        result = unflatten_rule.analyze_blk(block)
        
        assert result == 0

    def test_analyze_blk_wrong_opcode_returns_zero(self, unflatten_rule, mock_ida_modules):
        """Block with non-fake-jump opcode returns 0 changes."""
        # m_goto is not in FAKE_LOOP_OPCODES
        block = create_mock_block(serial=1, tail_opcode=0x40)  # m_goto
        
        result = unflatten_rule.analyze_blk(block)
        
        assert result == 0

    def test_analyze_blk_multiple_regular_instructions_returns_zero(self, unflatten_rule, mock_ida_modules):
        """Block with multiple regular instructions returns 0 changes."""
        block = create_mock_block(
            serial=1, 
            tail_opcode=0x31,  # m_jz
            reginsn_qty=3
        )
        
        result = unflatten_rule.analyze_blk(block)
        
        assert result == 0

    def test_analyze_blk_non_numeric_operand_returns_zero(self, unflatten_rule, mock_ida_modules):
        """Block with non-numeric right operand returns 0 changes."""
        block = create_mock_block(serial=1, tail_opcode=0x31)  # m_jz
        block.tail.r.t = 1  # mop_r (register), not mop_n (numeric)
        
        result = unflatten_rule.analyze_blk(block)
        
        assert result == 0

    def test_analyze_blk_no_predecessors(self, unflatten_rule, mock_ida_modules):
        """Block with no predecessors returns 0 changes."""
        block = create_mock_block(
            serial=1, 
            tail_opcode=0x31,  # m_jz
            predset=[]
        )
        
        result = unflatten_rule.analyze_blk(block)
        
        assert result == 0

    @patch('d810.hexrays.tracker.MopTracker')
    def test_analyze_blk_unresolved_path_returns_zero(self, mock_tracker_class, unflatten_rule, mock_ida_modules):
        """Block with unresolved path returns 0 changes."""
        pred_block = create_mock_block(serial=0)
        block = create_mock_block(
            serial=1, 
            tail_opcode=0x31,  # m_jz
            predset=[0]
        )
        block.mba.get_mblock.return_value = pred_block
        
        # Mock tracker returning unresolved histories
        mock_tracker = MagicMock()
        mock_history = MagicMock()
        mock_history.is_resolved.return_value = False
        mock_tracker.search_backward.return_value = [mock_history]
        mock_tracker_class.return_value = mock_tracker
        
        result = unflatten_rule.analyze_blk(block)
        
        assert result == 0

    @patch('d810.optimizers.microcode.flow.flattening.utils.get_all_possibles_values')
    @patch('d810.hexrays.tracker.MopTracker')
    def test_analyze_blk_none_in_values_returns_zero(self, mock_tracker_class, mock_get_values, unflatten_rule, mock_ida_modules):
        """Block with None in possible values returns 0 changes."""
        pred_block = create_mock_block(serial=0)
        block = create_mock_block(
            serial=1, 
            tail_opcode=0x31,  # m_jz
            predset=[0]
        )
        block.mba.get_mblock.return_value = pred_block
        
        # Mock tracker returning resolved histories
        mock_tracker = MagicMock()
        mock_history = MagicMock()
        mock_history.is_resolved.return_value = True
        mock_tracker.search_backward.return_value = [mock_history]
        mock_tracker_class.return_value = mock_tracker
        
        # Mock get_all_possibles_values returning None
        mock_get_values.return_value = [[None]]
        
        result = unflatten_rule.analyze_blk(block)
        
        assert result == 0

    @patch('d810.optimizers.microcode.flow.flattening.utils.get_all_possibles_values')
    @patch('d810.hexrays.tracker.MopTracker')
    def test_analyze_blk_successful_single_predecessor(self, mock_tracker_class, mock_get_values, unflatten_rule, mock_ida_modules):
        """Successfully analyze block with one predecessor."""
        pred_block = create_mock_block(serial=0)
        block = create_mock_block(
            serial=1, 
            tail_opcode=0x31,  # m_jz
            predset=[0]
        )
        block.mba.get_mblock.return_value = pred_block
        
        # Mock tracker
        mock_tracker = MagicMock()
        mock_history = MagicMock()
        mock_history.is_resolved.return_value = True
        mock_tracker.search_backward.return_value = [mock_history]
        mock_tracker_class.return_value = mock_tracker
        
        # Mock get_all_possibles_values
        mock_get_values.return_value = [[42]]
        
        # Mock fix_successor
        with patch.object(unflatten_rule, 'fix_successor', return_value=True) as mock_fix:
            result = unflatten_rule.analyze_blk(block)
            
            assert result == 1
            mock_fix.assert_called_once()

    @patch('d810.optimizers.microcode.flow.flattening.utils.get_all_possibles_values')
    @patch('d810.hexrays.tracker.MopTracker')
    def test_analyze_blk_multiple_predecessors(self, mock_tracker_class, mock_get_values, unflatten_rule, mock_ida_modules):
        """Successfully analyze block with multiple predecessors."""
        pred_block_0 = create_mock_block(serial=0)
        pred_block_1 = create_mock_block(serial=1)
        block = create_mock_block(
            serial=2, 
            tail_opcode=0x30,  # m_jnz
            predset=[0, 1]
        )
        
        def get_block(serial):
            return pred_block_0 if serial == 0 else pred_block_1
        
        block.mba.get_mblock.side_effect = get_block
        
        # Mock tracker
        mock_tracker = MagicMock()
        mock_history = MagicMock()
        mock_history.is_resolved.return_value = True
        mock_tracker.search_backward.return_value = [mock_history]
        mock_tracker_class.return_value = mock_tracker
        
        # Mock get_all_possibles_values
        mock_get_values.return_value = [[100]]
        
        with patch.object(unflatten_rule, 'fix_successor', return_value=True) as mock_fix:
            result = unflatten_rule.analyze_blk(block)
            
            assert result == 2
            assert mock_fix.call_count == 2


class TestFixSuccessor:
    """Tests for fix_successor method - jump redirection logic."""

    def test_fix_successor_empty_values_returns_false(self, unflatten_rule, mock_ida_modules):
        """Empty comparison values list returns False."""
        fake_loop_block = create_mock_block(serial=1, tail_opcode=0x31)  # m_jz
        pred = create_mock_block(serial=0)
        
        result = unflatten_rule.fix_successor(fake_loop_block, pred, [])
        
        assert result is False

    @patch('d810.hexrays.cfg_utils.change_1way_block_successor')
    def test_fix_successor_jz_always_taken(self, mock_change_succ, unflatten_rule, mock_ida_modules):
        """m_jz with all values equal to compared value -> jump taken."""
        fake_loop_block = create_mock_block(serial=1, tail_opcode=0x31)  # m_jz
        fake_loop_block.tail.r.nnn.value = 42
        fake_loop_block.tail.d.b = 10
        pred = create_mock_block(serial=0)
        mock_change_succ.return_value = True
        
        result = unflatten_rule.fix_successor(fake_loop_block, pred, [42, 42, 42])
        
        assert result is True
        mock_change_succ.assert_called_once_with(pred, 10)

    @patch('d810.hexrays.cfg_utils.change_1way_block_successor')
    def test_fix_successor_jz_never_taken(self, mock_change_succ, unflatten_rule, mock_ida_modules):
        """m_jz with all values not equal to compared value -> jump not taken."""
        fake_loop_block = create_mock_block(serial=1, tail_opcode=0x31)  # m_jz
        fake_loop_block.tail.r.nnn.value = 42
        pred = create_mock_block(serial=0)
        mock_change_succ.return_value = True
        
        result = unflatten_rule.fix_successor(fake_loop_block, pred, [100, 200, 300])
        
        assert result is True
        # Jump not taken -> goto next block (serial + 1)
        mock_change_succ.assert_called_once_with(pred, 2)

    @patch('d810.hexrays.cfg_utils.change_1way_block_successor')
    def test_fix_successor_jnz_always_taken(self, mock_change_succ, unflatten_rule, mock_ida_modules):
        """m_jnz with all values not equal to compared value -> jump taken."""
        fake_loop_block = create_mock_block(serial=1, tail_opcode=0x30)  # m_jnz
        fake_loop_block.tail.r.nnn.value = 42
        fake_loop_block.tail.d.b = 15
        pred = create_mock_block(serial=0)
        mock_change_succ.return_value = True
        
        result = unflatten_rule.fix_successor(fake_loop_block, pred, [100, 200, 300])
        
        assert result is True
        mock_change_succ.assert_called_once_with(pred, 15)

    @patch('d810.hexrays.cfg_utils.change_1way_block_successor')
    def test_fix_successor_jnz_never_taken(self, mock_change_succ, unflatten_rule, mock_ida_modules):
        """m_jnz with all values equal to compared value -> jump not taken."""
        fake_loop_block = create_mock_block(serial=1, tail_opcode=0x30)  # m_jnz
        fake_loop_block.tail.r.nnn.value = 42
        pred = create_mock_block(serial=0)
        mock_change_succ.return_value = True
        
        result = unflatten_rule.fix_successor(fake_loop_block, pred, [42, 42, 42])
        
        assert result is True
        # Jump not taken -> goto next block (serial + 1)
        mock_change_succ.assert_called_once_with(pred, 2)

    @patch('d810.hexrays.cfg_utils.change_1way_block_successor')
    def test_fix_successor_mixed_values_returns_false(self, mock_change_succ, unflatten_rule, mock_ida_modules):
        """Mixed values (some match, some don't) returns False."""
        fake_loop_block = create_mock_block(serial=1, tail_opcode=0x31)  # m_jz
        fake_loop_block.tail.r.nnn.value = 42
        pred = create_mock_block(serial=0)
        
        result = unflatten_rule.fix_successor(fake_loop_block, pred, [42, 100, 42])
        
        assert result is False
        mock_change_succ.assert_not_called()

    @patch('d810.hexrays.hexrays_formatters.dump_microcode_for_debug')
    @patch('d810.hexrays.cfg_utils.change_1way_block_successor')
    def test_fix_successor_with_dump_enabled(self, mock_change_succ, mock_dump, unflatten_rule, mock_ida_modules):
        """Test that dump is called when dump_intermediate_microcode is True."""
        unflatten_rule.dump_intermediate_microcode = True
        unflatten_rule.mba = MagicMock()
        mock_change_succ.return_value = True
        
        fake_loop_block = create_mock_block(serial=1, tail_opcode=0x31)  # m_jz
        fake_loop_block.tail.r.nnn.value = 42
        pred = create_mock_block(serial=0)
        
        result = unflatten_rule.fix_successor(fake_loop_block, pred, [42, 42])
        
        assert result is True
        # Should be called twice: before and after
        assert mock_dump.call_count == 2


class TestOptimize:
    """Tests for optimize method - main entry point."""

    def test_optimize_rule_should_not_be_used(self, unflatten_rule, mock_ida_modules):
        """Optimize returns 0 when rule should not be used."""
        block = create_mock_block(serial=1)
        
        with patch.object(unflatten_rule, 'check_if_rule_should_be_used', return_value=False):
            result = unflatten_rule.optimize(block)
            
        assert result == 0
        assert unflatten_rule.mba == block.mba

    def test_optimize_no_changes_made(self, unflatten_rule, mock_ida_modules):
        """Optimize returns 0 when analyze_blk makes no changes."""
        block = create_mock_block(serial=1)
        
        with patch.object(unflatten_rule, 'check_if_rule_should_be_used', return_value=True),              patch.object(unflatten_rule, 'analyze_blk', return_value=0):
            result = unflatten_rule.optimize(block)
            
        assert result == 0
        block.mba.mark_chains_dirty.assert_not_called()

    @patch('d810.hexrays.cfg_utils.safe_verify')
    def test_optimize_successful_changes(self, mock_verify, unflatten_rule, mock_ida_modules):
        """Optimize applies changes and marks chains dirty."""
        block = create_mock_block(serial=1)
        
        with patch.object(unflatten_rule, 'check_if_rule_should_be_used', return_value=True),              patch.object(unflatten_rule, 'analyze_blk', return_value=2):
            result = unflatten_rule.optimize(block)
            
        assert result == 2
        assert unflatten_rule.last_pass_nb_patch_done == 2
        block.mba.mark_chains_dirty.assert_called_once()
        block.mba.optimize_local.assert_called_once_with(0)
        mock_verify.assert_called_once()

    @patch('d810.hexrays.cfg_utils.safe_verify')
    def test_optimize_verify_called_with_correct_args(self, mock_verify, unflatten_rule, mock_ida_modules):
        """Verify that safe_verify is called with correct arguments."""
        block = create_mock_block(serial=1)
        
        with patch.object(unflatten_rule, 'check_if_rule_should_be_used', return_value=True),              patch.object(unflatten_rule, 'analyze_blk', return_value=1):
            unflatten_rule.optimize(block)
            
        mock_verify.assert_called_once()
        call_args = mock_verify.call_args
        assert call_args[0][0] == block.mba
        assert "optimizing UnflattenerFakeJump" in call_args[0][1]


class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    @patch('d810.optimizers.microcode.flow.flattening.utils.get_all_possibles_values')
    @patch('d810.hexrays.tracker.MopTracker')
    def test_tracker_initialization(self, mock_tracker_class, mock_get_values, unflatten_rule, mock_ida_modules):
        """Test that MopTracker is initialized with correct parameters."""
        pred_block = create_mock_block(serial=0)
        block = create_mock_block(
            serial=1, 
            tail_opcode=0x31,  # m_jz
            predset=[0]
        )
        block.mba.get_mblock.return_value = pred_block
        
        mock_tracker = MagicMock()
        mock_history = MagicMock()
        mock_history.is_resolved.return_value = False
        mock_tracker.search_backward.return_value = [mock_history]
        mock_tracker_class.return_value = mock_tracker
        
        unflatten_rule.analyze_blk(block)
        
        # Verify tracker was created with max_nb_block and max_path
        mock_tracker_class.assert_called_once()
        call_args = mock_tracker_class.call_args[0]
        call_kwargs = mock_tracker_class.call_args[1]
        assert call_kwargs['max_nb_block'] == 100
        assert call_kwargs['max_path'] == 1000
        
        # Verify reset was called
        mock_tracker.reset.assert_called_once()

    @patch('d810.optimizers.microcode.flow.flattening.utils.get_all_possibles_values')
    @patch('d810.hexrays.tracker.MopTracker')
    def test_get_all_possibles_values_called_correctly(self, mock_tracker_class, mock_get_values, unflatten_rule, mock_ida_modules):
        """Test that get_all_possibles_values is called with correct args."""
        pred_block = create_mock_block(serial=0)
        block = create_mock_block(
            serial=1, 
            tail_opcode=0x31,  # m_jz
            predset=[0]
        )
        block.mba.get_mblock.return_value = pred_block
        
        mock_tracker = MagicMock()
        mock_history = MagicMock()
        mock_history.is_resolved.return_value = True
        mock_tracker.search_backward.return_value = [mock_history]
        mock_tracker_class.return_value = mock_tracker
        mock_get_values.return_value = [[None]]
        
        unflatten_rule.analyze_blk(block)
        
        # Verify get_all_possibles_values was called
        mock_get_values.assert_called_once()
        call_args = mock_get_values.call_args[0]
        assert call_args[0] == [mock_history]

    @patch('d810.optimizers.microcode.flow.flattening.utils.get_all_possibles_values')
    @patch('d810.hexrays.tracker.MopTracker')
    def test_multiple_paths_with_different_resolution_majority_resolved(
        self, mock_tracker_class, mock_get_values, unflatten_rule, mock_ida_modules
    ):
        """Test handling when resolved paths are majority - should proceed."""
        pred_block = create_mock_block(serial=0)
        block = create_mock_block(
            serial=1,
            tail_opcode=0x31,  # m_jz
            predset=[0]
        )
        block.mba.get_mblock.return_value = pred_block

        mock_tracker = MagicMock()
        # 3 resolved, 1 unresolved - resolved is majority
        mock_history_resolved = MagicMock()
        mock_history_resolved.is_resolved.return_value = True
        mock_history_unresolved = MagicMock()
        mock_history_unresolved.is_resolved.return_value = False

        mock_tracker.search_backward.return_value = [
            mock_history_resolved, mock_history_resolved,
            mock_history_resolved, mock_history_unresolved
        ]
        mock_tracker_class.return_value = mock_tracker
        mock_get_values.return_value = [[42]]

        with patch.object(unflatten_rule, 'fix_successor', return_value=True):
            result = unflatten_rule.analyze_blk(block)

        # Should proceed since resolved (3) > unresolved (1)
        assert result == 1

    @patch('d810.hexrays.tracker.MopTracker')
    def test_multiple_paths_with_different_resolution_majority_unresolved(
        self, mock_tracker_class, unflatten_rule, mock_ida_modules
    ):
        """Test handling when unresolved paths are majority - should skip for safety."""
        pred_block = create_mock_block(serial=0)
        block = create_mock_block(
            serial=1,
            tail_opcode=0x31,  # m_jz
            predset=[0]
        )
        block.mba.get_mblock.return_value = pred_block

        mock_tracker = MagicMock()
        # 1 resolved, 3 unresolved - unresolved is majority (UNSAFE)
        mock_history_resolved = MagicMock()
        mock_history_resolved.is_resolved.return_value = True
        mock_history_unresolved = MagicMock()
        mock_history_unresolved.is_resolved.return_value = False

        mock_tracker.search_backward.return_value = [
            mock_history_resolved, mock_history_unresolved,
            mock_history_unresolved, mock_history_unresolved
        ]
        mock_tracker_class.return_value = mock_tracker

        result = unflatten_rule.analyze_blk(block)

        # Should return 0 - safety check prevents proceeding when unresolved > resolved
        assert result == 0

    @patch('d810.hexrays.tracker.MopTracker')
    def test_safety_check_prevents_unsafe_redirect(self, mock_tracker_class, unflatten_rule, mock_ida_modules):
        """Test that safety check prevents potentially incorrect CFG modification.

        This test simulates the unsafe scenario identified by Z3 analysis:
        - Resolved paths show state != CONST (jump not taken)
        - Unresolved paths could have state == CONST (jump taken)
        - If we ignore unresolved and redirect based only on resolved,
          we could break control flow for the unresolved execution paths.

        The safety check should prevent this by skipping predecessors where
        unresolved paths outnumber resolved paths.
        """
        pred_block = create_mock_block(serial=0)
        block = create_mock_block(
            serial=1,
            tail_opcode=0x31,  # m_jz
            predset=[0]
        )
        block.mba.get_mblock.return_value = pred_block

        mock_tracker = MagicMock()
        # Simulate the unsafe scenario from unsafe_unflattener_test.c:
        # - 2 resolved paths (back-edges that were traced)
        # - 5 unresolved paths (loops, entry blocks, etc.)
        mock_history_resolved = MagicMock()
        mock_history_resolved.is_resolved.return_value = True
        mock_history_unresolved = MagicMock()
        mock_history_unresolved.is_resolved.return_value = False

        mock_tracker.search_backward.return_value = [
            mock_history_resolved, mock_history_resolved,  # 2 resolved
            mock_history_unresolved, mock_history_unresolved, mock_history_unresolved,  # 5 unresolved
            mock_history_unresolved, mock_history_unresolved,
        ]
        mock_tracker_class.return_value = mock_tracker

        result = unflatten_rule.analyze_blk(block)

        # CRITICAL: Safety check should prevent any modification
        # because unresolved (5) > resolved (2) - too risky to proceed
        assert result == 0


class TestConstants:
    """Tests for module constants."""

    def test_fake_loop_opcodes(self, mock_ida_modules):
        """Test that FAKE_LOOP_OPCODES contains correct opcodes."""
        from d810.optimizers.microcode.flow.flattening.unflattener_fake_jump import FAKE_LOOP_OPCODES
        
        assert 0x31 in FAKE_LOOP_OPCODES  # m_jz
        assert 0x30 in FAKE_LOOP_OPCODES  # m_jnz
        assert len(FAKE_LOOP_OPCODES) == 2
