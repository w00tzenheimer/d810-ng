"""K3.4 tests: resolve_exit_via_bst_default_snapshot using FlowGraph.

Validates that the snapshot variant walks BST comparison chains identically
to the live-mba resolve_exit_via_bst_default, using InsnSnapshot + MopSnapshot.
"""
from __future__ import annotations

import pytest

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot, MopSnapshot
from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
    resolve_exit_via_bst_default_snapshot,
)

# Test-local opcode constants (avoid IDA dependency)
_TEST_M_JNZ = 0x30
_TEST_M_JZ = 0x31
_TEST_M_JBE = 0x32
_TEST_MOP_N = 2
_TEST_MOP_S = 3


def _make_bst_walk_cfg(state_var_stkoff: int = 0x10) -> FlowGraph:
    """Build a BST walk FlowGraph with rich InsnSnapshot/MopSnapshot.

    Topology (linear BST chain)::

        blk5 (BST root, jnz state_var == 0xAA)
            succs: (6, 10)   [fallthrough=6, jump=10]
        blk6 (BST node, jnz state_var == 0xBB)
            succs: (7, 11)   [fallthrough=7, jump=11]
        blk7 (default exit, 1-way) -> blk8
        blk8 (return, 0 succs)
        blk10 (handler A) -> blk8
        blk11 (handler B) -> blk8
    """
    l_mop = MopSnapshot(t=_TEST_MOP_S, size=4, stkoff=state_var_stkoff)

    blk5_tail = InsnSnapshot(
        opcode=_TEST_M_JNZ, ea=0x5010, operands=(),
        l=l_mop, r=MopSnapshot(t=_TEST_MOP_N, size=4, value=0xAA),
    )
    blk6_tail = InsnSnapshot(
        opcode=_TEST_M_JNZ, ea=0x6010, operands=(),
        l=l_mop, r=MopSnapshot(t=_TEST_MOP_N, size=4, value=0xBB),
    )

    blk5 = BlockSnapshot(
        serial=5, block_type=1, succs=(6, 10), preds=(),
        flags=0, start_ea=0x5000, insn_snapshots=(blk5_tail,),
    )
    blk6 = BlockSnapshot(
        serial=6, block_type=1, succs=(7, 11), preds=(5,),
        flags=0, start_ea=0x6000, insn_snapshots=(blk6_tail,),
    )
    blk7 = BlockSnapshot(
        serial=7, block_type=1, succs=(8,), preds=(6,),
        flags=0, start_ea=0x7000, insn_snapshots=(),
    )
    blk8 = BlockSnapshot(
        serial=8, block_type=2, succs=(), preds=(7, 10, 11),
        flags=0, start_ea=0x8000, insn_snapshots=(),
    )
    blk10 = BlockSnapshot(
        serial=10, block_type=1, succs=(8,), preds=(5,),
        flags=0, start_ea=0xA000, insn_snapshots=(),
    )
    blk11 = BlockSnapshot(
        serial=11, block_type=1, succs=(8,), preds=(6,),
        flags=0, start_ea=0xB000, insn_snapshots=(),
    )
    return FlowGraph(
        blocks={5: blk5, 6: blk6, 7: blk7, 8: blk8, 10: blk10, 11: blk11},
        entry_serial=5, func_ea=0x5000,
    )


@pytest.fixture(autouse=True)
def _patch_bst_opcodes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject test opcode set into _helpers._BST_CMP_OPCODES."""
    import d810.optimizers.microcode.flow.flattening.hodur._helpers as mod

    monkeypatch.setattr(
        mod, "_BST_CMP_OPCODES",
        frozenset({_TEST_M_JNZ, _TEST_M_JZ, _TEST_M_JBE}),
    )

    def _test_eval(opcode: int, state: int, cmp_val: int) -> bool:
        if opcode == _TEST_M_JNZ:
            return state != cmp_val
        if opcode == _TEST_M_JZ:
            return state == cmp_val
        if opcode == _TEST_M_JBE:
            return state <= cmp_val
        return False

    monkeypatch.setattr(mod, "eval_bst_condition", _test_eval)


class TestResolveExitViaBstDefaultSnapshot:
    """Verify resolve_exit_via_bst_default_snapshot walks BST via snapshots."""

    def test_resolves_through_chain(self) -> None:
        """Walk BST chain: state 0xAA -> blk5(fall) -> blk6(jump) -> blk11."""
        cfg = _make_bst_walk_cfg()
        result = resolve_exit_via_bst_default_snapshot(cfg, 5, 0xAA)
        assert result == 11

    def test_resolves_first_jump(self) -> None:
        """Walk BST chain: state 0xBB -> blk5(jump) -> blk10."""
        cfg = _make_bst_walk_cfg()
        result = resolve_exit_via_bst_default_snapshot(cfg, 5, 0xBB)
        assert result == 10

    def test_non_2way_block_returns_none_at_start(self) -> None:
        """Walk stops at 1-way block at start -> returns None."""
        cfg = _make_bst_walk_cfg()
        result = resolve_exit_via_bst_default_snapshot(cfg, 7, 0xAA)
        assert result is None

    def test_state_var_mismatch_stops(self) -> None:
        """Walk stops when left operand stkoff changes."""
        different_l = MopSnapshot(t=_TEST_MOP_S, size=4, stkoff=0x20)
        blk6_tail = InsnSnapshot(
            opcode=_TEST_M_JNZ, ea=0x6010, operands=(),
            l=different_l, r=MopSnapshot(t=_TEST_MOP_N, size=4, value=0xBB),
        )
        l_mop = MopSnapshot(t=_TEST_MOP_S, size=4, stkoff=0x10)
        blk5_tail = InsnSnapshot(
            opcode=_TEST_M_JNZ, ea=0x5010, operands=(),
            l=l_mop, r=MopSnapshot(t=_TEST_MOP_N, size=4, value=0xAA),
        )
        blk5 = BlockSnapshot(
            serial=5, block_type=1, succs=(6, 10), preds=(),
            flags=0, start_ea=0x5000, insn_snapshots=(blk5_tail,),
        )
        blk6 = BlockSnapshot(
            serial=6, block_type=1, succs=(7, 11), preds=(5,),
            flags=0, start_ea=0x6000, insn_snapshots=(blk6_tail,),
        )
        blk7 = BlockSnapshot(
            serial=7, block_type=1, succs=(), preds=(6,),
            flags=0, start_ea=0x7000, insn_snapshots=(),
        )
        blk10 = BlockSnapshot(
            serial=10, block_type=1, succs=(), preds=(5,),
            flags=0, start_ea=0xA000, insn_snapshots=(),
        )
        blk11 = BlockSnapshot(
            serial=11, block_type=1, succs=(), preds=(6,),
            flags=0, start_ea=0xB000, insn_snapshots=(),
        )
        cfg = FlowGraph(
            blocks={5: blk5, 6: blk6, 7: blk7, 10: blk10, 11: blk11},
            entry_serial=5, func_ea=0x5000,
        )
        # state 0xAA: blk5 fall -> blk6 has different stkoff -> stops at blk6
        result = resolve_exit_via_bst_default_snapshot(cfg, 5, 0xAA)
        assert result == 6
