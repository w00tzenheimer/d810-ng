"""Unit tests for CFGShapeCollector using PortableCFG (no IDA dependency)."""
from __future__ import annotations
import pytest
from d810.hexrays.portable_cfg import BlockSnapshot, PortableCFG
from d810.recon.collectors.cfg_shape import CFGShapeCollector


def _make_linear_cfg(n: int, func_ea: int = 0x401000) -> PortableCFG:
    """Build a simple linear CFG: 0->1->2->...->( n-1)."""
    blocks = {}
    for i in range(n):
        succs = (i + 1,) if i < n - 1 else ()
        preds = (i - 1,) if i > 0 else ()
        blocks[i] = BlockSnapshot(
            serial=i, block_type=1 if succs else 0,
            succs=succs, preds=preds,
            flags=0, start_ea=func_ea + i * 0x10,
            insn_snapshots=(),
        )
    return PortableCFG(blocks=blocks, entry_serial=0, func_ea=func_ea)


def _make_diamond_cfg(func_ea: int = 0x402000) -> PortableCFG:
    """Build a diamond CFG: 0->(1,2)->3."""
    blocks = {
        0: BlockSnapshot(serial=0, block_type=2, succs=(1, 2), preds=(), flags=0, start_ea=func_ea, insn_snapshots=()),
        1: BlockSnapshot(serial=1, block_type=1, succs=(3,), preds=(0,), flags=0, start_ea=func_ea + 0x10, insn_snapshots=()),
        2: BlockSnapshot(serial=2, block_type=1, succs=(3,), preds=(0,), flags=0, start_ea=func_ea + 0x20, insn_snapshots=()),
        3: BlockSnapshot(serial=3, block_type=0, succs=(), preds=(1, 2), flags=0, start_ea=func_ea + 0x30, insn_snapshots=()),
    }
    return PortableCFG(blocks=blocks, entry_serial=0, func_ea=func_ea)


def _make_flat_cfg(func_ea: int = 0x403000) -> PortableCFG:
    """Build a flattening-like CFG: dispatcher block 1 dominated by entry,
    multiple predecessors feeding back into block 1 (state machine pattern).

    Topology:
      0 (entry) -> 1 (dispatcher) -> 2, 3, 4
      2 -> 1, 3 -> 1, 4 -> 1  (back-edges)
    """
    blocks = {
        0: BlockSnapshot(serial=0, block_type=1, succs=(1,), preds=(), flags=0, start_ea=func_ea, insn_snapshots=()),
        1: BlockSnapshot(serial=1, block_type=3, succs=(2, 3, 4), preds=(0, 2, 3, 4), flags=0, start_ea=func_ea + 0x10, insn_snapshots=()),
        2: BlockSnapshot(serial=2, block_type=1, succs=(1,), preds=(1,), flags=0, start_ea=func_ea + 0x20, insn_snapshots=()),
        3: BlockSnapshot(serial=3, block_type=1, succs=(1,), preds=(1,), flags=0, start_ea=func_ea + 0x30, insn_snapshots=()),
        4: BlockSnapshot(serial=4, block_type=1, succs=(1,), preds=(1,), flags=0, start_ea=func_ea + 0x40, insn_snapshots=()),
    }
    return PortableCFG(blocks=blocks, entry_serial=0, func_ea=func_ea)


class TestCFGShapeCollector:
    def test_collector_name(self):
        c = CFGShapeCollector()
        assert c.name == "CFGShapeCollector"

    def test_maturities_include_preoptimized_and_calls(self):
        c = CFGShapeCollector()
        # MMAT_PREOPTIMIZED=5, MMAT_CALLS=3 in IDA SDK
        assert 5 in c.maturities
        assert 3 in c.maturities

    def test_level_is_microcode(self):
        assert CFGShapeCollector().level == "microcode"

    def test_linear_cfg_metrics(self):
        cfg = _make_linear_cfg(5)
        result = CFGShapeCollector().collect(cfg, func_ea=0x401000, maturity=5)
        assert result.collector_name == "CFGShapeCollector"
        assert result.func_ea == 0x401000
        assert result.maturity == 5
        assert result.metrics["block_count"] == 5
        assert result.metrics["edge_count"] == 4
        assert result.metrics["max_in_degree"] == 1

    def test_diamond_cfg_metrics(self):
        cfg = _make_diamond_cfg()
        result = CFGShapeCollector().collect(cfg, func_ea=0x402000, maturity=5)
        assert result.metrics["block_count"] == 4
        assert result.metrics["edge_count"] == 4
        assert result.metrics["max_in_degree"] == 2  # block 3 has 2 preds

    def test_flat_cfg_metrics(self):
        cfg = _make_flat_cfg()
        result = CFGShapeCollector().collect(cfg, func_ea=0x403000, maturity=5)
        # block 1 has 4 predecessors (0,2,3,4)
        assert result.metrics["max_in_degree"] == 4
        # flattening_score should be > 0 (dominant hub exists)
        assert result.metrics["flattening_score"] > 0.0

    def test_flat_cfg_flags_candidate(self):
        cfg = _make_flat_cfg()
        result = CFGShapeCollector().collect(cfg, func_ea=0x403000, maturity=5)
        # Should flag the dispatcher block as a candidate when max_in_degree >= 3
        if result.metrics["max_in_degree"] >= 3:
            assert len(result.candidates) >= 1
            kinds = {c.kind for c in result.candidates}
            assert "high_indegree_block" in kinds

    def test_result_is_frozen(self):
        cfg = _make_linear_cfg(3)
        result = CFGShapeCollector().collect(cfg, func_ea=0x401000, maturity=5)
        with pytest.raises((AttributeError, TypeError)):
            result.func_ea = 0  # type: ignore[misc]

    def test_collect_accepts_portable_cfg(self):
        """CFGShapeCollector.collect() must work on PortableCFG (no IDA needed)."""
        cfg = _make_linear_cfg(10)
        # Should not raise
        result = CFGShapeCollector().collect(cfg, func_ea=0x401000, maturity=5)
        assert result is not None
