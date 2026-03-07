"""K3.4 tests: find_bst_default_block_snapshot using FlowGraph.

Validates that the snapshot variant produces identical results to the
live-mba find_bst_default_block for pure-topology BST default lookups.
"""
from __future__ import annotations

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.recon.flow.bst_analysis import find_bst_default_block_snapshot


def _make_bst_cfg() -> FlowGraph:
    """Build a BST dispatcher FlowGraph.

    Topology::

        blk5 (BST root)  -> blk6, blk10 (handler)
        blk6 (BST node)  -> blk10 (handler), blk7 (default)
        blk7 (default)    -> blk8
        blk8 (exit)       -> ()
        blk10 (handler)   -> blk8
    """
    blk5 = BlockSnapshot(
        serial=5, block_type=1, succs=(6, 10), preds=(),
        flags=0, start_ea=0x5000, insn_snapshots=(),
    )
    blk6 = BlockSnapshot(
        serial=6, block_type=1, succs=(10, 7), preds=(5,),
        flags=0, start_ea=0x6000, insn_snapshots=(),
    )
    blk7 = BlockSnapshot(
        serial=7, block_type=1, succs=(8,), preds=(6,),
        flags=0, start_ea=0x7000, insn_snapshots=(),
    )
    blk8 = BlockSnapshot(
        serial=8, block_type=2, succs=(), preds=(7, 10),
        flags=0, start_ea=0x8000, insn_snapshots=(),
    )
    blk10 = BlockSnapshot(
        serial=10, block_type=1, succs=(8,), preds=(5, 6),
        flags=0, start_ea=0xA000, insn_snapshots=(),
    )
    return FlowGraph(
        blocks={5: blk5, 6: blk6, 7: blk7, 8: blk8, 10: blk10},
        entry_serial=5,
        func_ea=0x5000,
    )


class TestFindBstDefaultBlockSnapshot:
    """Verify find_bst_default_block_snapshot matches live-mba behavior."""

    def test_finds_default_block(self) -> None:
        """Default block (7) is the first succ not in BST nodes or handlers."""
        cfg = _make_bst_cfg()
        result = find_bst_default_block_snapshot(
            cfg, bst_root_serial=5,
            bst_node_blocks={5, 6}, handler_block_serials={10},
        )
        assert result == 7

    def test_returns_none_when_no_default(self) -> None:
        """Returns None when all BST-node successors are BST nodes or handlers."""
        cfg = _make_bst_cfg()
        result = find_bst_default_block_snapshot(
            cfg, bst_root_serial=5,
            bst_node_blocks={5, 6}, handler_block_serials={10, 7},
        )
        assert result is None

    def test_returns_none_for_none_flow_graph(self) -> None:
        """Returns None when flow_graph is None."""
        assert find_bst_default_block_snapshot(None, 0, set(), set()) is None

    def test_root_only_bst(self) -> None:
        """Single BST root node with a handler and default successor."""
        blk0 = BlockSnapshot(
            serial=0, block_type=1, succs=(1, 2), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=(),
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=1, succs=(), preds=(0,),
            flags=0, start_ea=0x2000, insn_snapshots=(),
        )
        blk2 = BlockSnapshot(
            serial=2, block_type=1, succs=(), preds=(0,),
            flags=0, start_ea=0x3000, insn_snapshots=(),
        )
        cfg = FlowGraph(
            blocks={0: blk0, 1: blk1, 2: blk2},
            entry_serial=0, func_ea=0x1000,
        )
        result = find_bst_default_block_snapshot(
            cfg, bst_root_serial=0,
            bst_node_blocks=set(), handler_block_serials={1},
        )
        assert result == 2
