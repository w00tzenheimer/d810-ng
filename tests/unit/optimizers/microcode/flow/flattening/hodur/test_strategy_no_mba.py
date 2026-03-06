"""K3 tests: verify FlowGraph provides mba-equivalent topology access.

These tests validate that FlowGraph exposes the properties needed to
replace live mba_t topology queries in strategy files.  Instruction-chain
access (blk.head/tail/insn.next) is NOT covered here — those remain
mba-dependent until BlockSnapshot gains instruction traversal.
"""
from __future__ import annotations

import pytest

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot


def _make_test_cfg() -> FlowGraph:
    """Build a small 3-block FlowGraph for testing."""
    blk0 = BlockSnapshot(
        serial=0, block_type=1, succs=(1,), preds=(),
        flags=0, start_ea=0x1000, insn_snapshots=(),
    )
    blk1 = BlockSnapshot(
        serial=1, block_type=1, succs=(2,), preds=(0,),
        flags=0, start_ea=0x2000, insn_snapshots=(),
    )
    blk2 = BlockSnapshot(
        serial=2, block_type=2, succs=(), preds=(1,),
        flags=0, start_ea=0x3000, insn_snapshots=(),
    )
    return FlowGraph(
        blocks={0: blk0, 1: blk1, 2: blk2},
        entry_serial=0,
        func_ea=0x1000,
    )


class TestFlowGraphMbaEquivalence:
    """Verify FlowGraph provides mba-equivalent topology queries."""

    def test_block_count_replaces_mba_qty(self) -> None:
        """FlowGraph.block_count replaces mba.qty."""
        cfg = _make_test_cfg()
        assert cfg.block_count == 3
        assert cfg.block_count == cfg.num_blocks
        assert cfg.block_count == len(cfg.blocks)

    def test_get_block_replaces_mba_get_mblock(self) -> None:
        """FlowGraph.get_block(serial) replaces mba.get_mblock(serial)."""
        cfg = _make_test_cfg()
        blk = cfg.get_block(0)
        assert blk is not None
        assert blk.serial == 0

    def test_get_block_returns_none_for_missing(self) -> None:
        """get_block returns None for non-existent serial (like mba.get_mblock)."""
        cfg = _make_test_cfg()
        assert cfg.get_block(99) is None

    def test_block_snapshot_nsucc_replaces_blk_nsucc(self) -> None:
        """BlockSnapshot.nsucc replaces blk.nsucc()."""
        cfg = _make_test_cfg()
        blk0 = cfg.get_block(0)
        blk2 = cfg.get_block(2)
        assert blk0 is not None
        assert blk0.nsucc == 1
        assert blk2 is not None
        assert blk2.nsucc == 0  # exit block

    def test_block_snapshot_npred_replaces_blk_npred(self) -> None:
        """BlockSnapshot.npred replaces blk.npred()."""
        cfg = _make_test_cfg()
        blk0 = cfg.get_block(0)
        blk1 = cfg.get_block(1)
        assert blk0 is not None
        assert blk0.npred == 0  # entry block
        assert blk1 is not None
        assert blk1.npred == 1

    def test_block_snapshot_succs_replaces_succset(self) -> None:
        """BlockSnapshot.succs replaces blk.succset."""
        cfg = _make_test_cfg()
        blk0 = cfg.get_block(0)
        assert blk0 is not None
        assert blk0.succs == (1,)

    def test_block_snapshot_preds_replaces_predset(self) -> None:
        """BlockSnapshot.preds replaces blk.predset."""
        cfg = _make_test_cfg()
        blk1 = cfg.get_block(1)
        assert blk1 is not None
        assert blk1.preds == (0,)

    def test_flow_graph_successors_method(self) -> None:
        """FlowGraph.successors(serial) replaces iteration over blk.succset."""
        cfg = _make_test_cfg()
        assert cfg.successors(0) == (1,)
        assert cfg.successors(2) == ()
        assert cfg.successors(99) == ()  # missing block

    def test_flow_graph_predecessors_method(self) -> None:
        """FlowGraph.predecessors(serial) replaces iteration over blk.predset."""
        cfg = _make_test_cfg()
        assert cfg.predecessors(1) == (0,)
        assert cfg.predecessors(0) == ()
        assert cfg.predecessors(99) == ()  # missing block

    def test_exit_blocks_via_flow_graph(self) -> None:
        """Build exit_blocks set from flow_graph (replaces mba.qty loop)."""
        cfg = _make_test_cfg()
        exit_blocks = {
            serial for serial, blk in cfg.blocks.items()
            if blk.nsucc == 0
        }
        assert exit_blocks == {2}

    def test_adjacency_dict_via_flow_graph(self) -> None:
        """Build adjacency dict from flow_graph (replaces mba.qty loop)."""
        cfg = _make_test_cfg()
        adj = {serial: list(blk.succs) for serial, blk in cfg.blocks.items()}
        assert adj == {0: [1], 1: [2], 2: []}
        # Also test the built-in method
        assert cfg.as_adjacency_dict() == adj
