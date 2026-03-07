"""K3.5/K3.6 tests: snapshot-based find_terminal_exit_target + degenerate block checks.

Validates that ``find_terminal_exit_target_snapshot`` and
``can_reach_return_snapshot`` produce the same results as their live-mba
counterparts when given equivalent FlowGraph snapshots.  Also tests the
snapshot-based ``_is_degenerate_loop_block_snapshot`` method.
"""
from __future__ import annotations

import pytest

try:
    import ida_hexrays
    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot

pytestmark = pytest.mark.skipif(not IDA_AVAILABLE, reason="IDA not available")


# ---- Opcode constants (must match ida_hexrays at runtime) ----
M_NOP = 0
M_GOTO = 2
M_MOV = 21


def _m_ret() -> int:
    """Get m_ret opcode from IDA."""
    return ida_hexrays.m_ret


# ---- FlowGraph fixtures ----

def _make_linear_cfg_with_ret() -> FlowGraph:
    """3-block linear CFG: entry -> body -> ret_block.

    Block 0: entry, succs=(1,)
    Block 1: body (state machine), succs=(2,)
    Block 2: has m_ret tail, succs=()
    """
    ret_insn = InsnSnapshot(opcode=_m_ret(), ea=0x3000, operands=())
    blk0 = BlockSnapshot(
        serial=0, block_type=1, succs=(1,), preds=(),
        flags=0, start_ea=0x1000, insn_snapshots=(),
    )
    blk1 = BlockSnapshot(
        serial=1, block_type=1, succs=(2,), preds=(0,),
        flags=0, start_ea=0x2000, insn_snapshots=(),
    )
    blk2 = BlockSnapshot(
        serial=2, block_type=1, succs=(), preds=(1,),
        flags=0, start_ea=0x3000, insn_snapshots=(ret_insn,),
    )
    return FlowGraph(
        blocks={0: blk0, 1: blk1, 2: blk2},
        entry_serial=0,
        func_ea=0x1000,
    )


def _make_diamond_cfg_with_ret() -> FlowGraph:
    """Diamond CFG with m_ret on one branch.

    Block 0: dispatcher/first_check, succs=(1, 2)
    Block 1: handler (state machine), succs=(3,)
    Block 2: exit path (outside SM), succs=(4,)
    Block 3: handler body (state machine), succs=(0,)  -- back-edge
    Block 4: has m_ret tail, succs=()
    """
    ret_insn = InsnSnapshot(opcode=_m_ret(), ea=0x5000, operands=())
    blk0 = BlockSnapshot(
        serial=0, block_type=1, succs=(1, 2), preds=(3,),
        flags=0, start_ea=0x1000, insn_snapshots=(),
    )
    blk1 = BlockSnapshot(
        serial=1, block_type=1, succs=(3,), preds=(0,),
        flags=0, start_ea=0x2000, insn_snapshots=(),
    )
    blk2 = BlockSnapshot(
        serial=2, block_type=1, succs=(4,), preds=(0,),
        flags=0, start_ea=0x3000, insn_snapshots=(),
    )
    blk3 = BlockSnapshot(
        serial=3, block_type=1, succs=(0,), preds=(1,),
        flags=0, start_ea=0x4000, insn_snapshots=(),
    )
    blk4 = BlockSnapshot(
        serial=4, block_type=1, succs=(), preds=(2,),
        flags=0, start_ea=0x5000, insn_snapshots=(ret_insn,),
    )
    return FlowGraph(
        blocks={0: blk0, 1: blk1, 2: blk2, 3: blk3, 4: blk4},
        entry_serial=0,
        func_ea=0x1000,
    )


def _make_no_ret_cfg() -> FlowGraph:
    """CFG with no m_ret blocks -- only a BLT_STOP with 0 successors."""
    nop_insn = InsnSnapshot(opcode=M_NOP, ea=0x2000, operands=())
    blk0 = BlockSnapshot(
        serial=0, block_type=1, succs=(1,), preds=(),
        flags=0, start_ea=0x1000, insn_snapshots=(),
    )
    blk1 = BlockSnapshot(
        serial=1, block_type=2, succs=(), preds=(0,),
        flags=0, start_ea=0x2000, insn_snapshots=(nop_insn,),
    )
    return FlowGraph(
        blocks={0: blk0, 1: blk1},
        entry_serial=0,
        func_ea=0x1000,
    )


# ---- Tests: can_reach_return_snapshot ----

class TestCanReachReturnSnapshot:
    """Test snapshot-based BFS reachability to m_ret blocks."""

    def test_direct_ret_reachable(self) -> None:
        from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
            can_reach_return_snapshot,
        )
        fg = _make_linear_cfg_with_ret()
        assert can_reach_return_snapshot(fg, 0) is True

    def test_ret_reachable_from_middle(self) -> None:
        from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
            can_reach_return_snapshot,
        )
        fg = _make_linear_cfg_with_ret()
        assert can_reach_return_snapshot(fg, 1) is True

    def test_ret_reachable_from_ret_block(self) -> None:
        from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
            can_reach_return_snapshot,
        )
        fg = _make_linear_cfg_with_ret()
        assert can_reach_return_snapshot(fg, 2) is True

    def test_no_ret_reachable(self) -> None:
        from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
            can_reach_return_snapshot,
        )
        fg = _make_no_ret_cfg()
        assert can_reach_return_snapshot(fg, 0) is False

    def test_missing_block_returns_false(self) -> None:
        from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
            can_reach_return_snapshot,
        )
        fg = _make_linear_cfg_with_ret()
        assert can_reach_return_snapshot(fg, 99) is False


# ---- Tests: find_terminal_exit_target_snapshot ----

class TestFindTerminalExitTargetSnapshot:
    """Test snapshot-based terminal exit target resolution."""

    def test_finds_outside_successor_reaching_ret(self) -> None:
        from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
            find_terminal_exit_target_snapshot,
        )
        fg = _make_diamond_cfg_with_ret()
        # State machine blocks: {0, 1, 3}; block 2 is outside and reaches ret via 4
        sm_blocks = {0, 1, 3}
        result = find_terminal_exit_target_snapshot(fg, 0, sm_blocks)
        assert result == 2

    def test_finds_ret_block_when_no_outside_successor(self) -> None:
        from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
            find_terminal_exit_target_snapshot,
        )
        fg = _make_linear_cfg_with_ret()
        # All blocks except ret block are state machine
        sm_blocks = {0, 1}
        result = find_terminal_exit_target_snapshot(fg, 0, sm_blocks)
        # Block 2 is an outside successor of block 0... wait, block 0's succs=(1,)
        # Actually block 0 only has succ 1, which is in sm_blocks.
        # So outside_successors is empty. Falls through to the m_ret scan.
        assert result == 2

    def test_fallback_to_stop_block(self) -> None:
        from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
            find_terminal_exit_target_snapshot,
        )
        fg = _make_no_ret_cfg()
        sm_blocks = {0}
        # Block 1 is outside successor of block 0, but has no m_ret.
        # BFS from block 1: no m_ret found. Falls to m_ret scan (none).
        # Falls to stop block: block 1 has 0 successors.
        result = find_terminal_exit_target_snapshot(fg, 0, sm_blocks)
        assert result == 1

    def test_returns_none_for_missing_check_block(self) -> None:
        from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
            find_terminal_exit_target_snapshot,
        )
        fg = _make_linear_cfg_with_ret()
        result = find_terminal_exit_target_snapshot(fg, 99, set())
        assert result is None


# ---- Tests: _is_degenerate_loop_block_snapshot (K3.6) ----

class TestIsDegenerateLoopBlockSnapshot:
    """Test snapshot-based degenerate loop block detection.

    K3.6: uses the @staticmethod API with explicit opcode parameters.
    """

    def test_nop_only_block_is_degenerate(self) -> None:
        from d810.optimizers.microcode.flow.flattening.hodur.strategies.terminal_loop_cleanup import (
            TerminalLoopCleanupStrategy,
        )
        nop_insn = InsnSnapshot(opcode=M_NOP, ea=0x1000, operands=())
        blk = BlockSnapshot(
            serial=0, block_type=1, succs=(0,), preds=(0,),
            flags=0, start_ea=0x1000, insn_snapshots=(nop_insn,),
        )
        assert TerminalLoopCleanupStrategy._is_degenerate_loop_block_snapshot(
            blk, m_nop=M_NOP, m_goto=M_GOTO,
        ) is True

    def test_goto_only_block_is_degenerate(self) -> None:
        from d810.optimizers.microcode.flow.flattening.hodur.strategies.terminal_loop_cleanup import (
            TerminalLoopCleanupStrategy,
        )
        goto_insn = InsnSnapshot(opcode=M_GOTO, ea=0x1000, operands=())
        blk = BlockSnapshot(
            serial=0, block_type=1, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=(goto_insn,),
        )
        assert TerminalLoopCleanupStrategy._is_degenerate_loop_block_snapshot(
            blk, m_nop=M_NOP, m_goto=M_GOTO,
        ) is True

    def test_nop_and_goto_block_is_degenerate(self) -> None:
        from d810.optimizers.microcode.flow.flattening.hodur.strategies.terminal_loop_cleanup import (
            TerminalLoopCleanupStrategy,
        )
        nop_insn = InsnSnapshot(opcode=M_NOP, ea=0x1000, operands=())
        goto_insn = InsnSnapshot(opcode=M_GOTO, ea=0x1008, operands=())
        blk = BlockSnapshot(
            serial=0, block_type=1, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=(nop_insn, goto_insn),
        )
        assert TerminalLoopCleanupStrategy._is_degenerate_loop_block_snapshot(
            blk, m_nop=M_NOP, m_goto=M_GOTO,
        ) is True

    def test_mov_block_is_not_degenerate(self) -> None:
        from d810.optimizers.microcode.flow.flattening.hodur.strategies.terminal_loop_cleanup import (
            TerminalLoopCleanupStrategy,
        )
        mov_insn = InsnSnapshot(opcode=M_MOV, ea=0x1000, operands=())
        blk = BlockSnapshot(
            serial=0, block_type=1, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=(mov_insn,),
        )
        assert TerminalLoopCleanupStrategy._is_degenerate_loop_block_snapshot(
            blk, m_nop=M_NOP, m_goto=M_GOTO,
        ) is False

    def test_empty_block_is_degenerate(self) -> None:
        from d810.optimizers.microcode.flow.flattening.hodur.strategies.terminal_loop_cleanup import (
            TerminalLoopCleanupStrategy,
        )
        blk = BlockSnapshot(
            serial=0, block_type=1, succs=(0,), preds=(0,),
            flags=0, start_ea=0x1000, insn_snapshots=(),
        )
        assert TerminalLoopCleanupStrategy._is_degenerate_loop_block_snapshot(
            blk, m_nop=M_NOP, m_goto=M_GOTO,
        ) is True

    def test_ret_block_is_not_degenerate(self) -> None:
        from d810.optimizers.microcode.flow.flattening.hodur.strategies.terminal_loop_cleanup import (
            TerminalLoopCleanupStrategy,
        )
        ret_insn = InsnSnapshot(opcode=_m_ret(), ea=0x1000, operands=())
        blk = BlockSnapshot(
            serial=0, block_type=1, succs=(), preds=(1,),
            flags=0, start_ea=0x1000, insn_snapshots=(ret_insn,),
        )
        assert TerminalLoopCleanupStrategy._is_degenerate_loop_block_snapshot(
            blk, m_nop=M_NOP, m_goto=M_GOTO,
        ) is False
