from __future__ import annotations
import pytest
from d810.hexrays.portable_cfg import BlockSnapshot, InsnSnapshot, PortableCFG
from d810.recon.collectors.dispatch_pattern import DispatchPatternCollector


def _make_switch_cfg(func_ea: int = 0x401000) -> PortableCFG:
    """CFG with one NWAY (switch) block fanning out to 5 targets."""
    blocks = {
        0: BlockSnapshot(serial=0, block_type=3, succs=(1,), preds=(), flags=0,
                         start_ea=func_ea, insn_snapshots=()),
        1: BlockSnapshot(serial=1, block_type=5, succs=(2, 3, 4, 5, 6), preds=(0,),
                         flags=0, start_ea=func_ea + 0x10, insn_snapshots=()),
    }
    for i in range(2, 7):
        blocks[i] = BlockSnapshot(serial=i, block_type=0, succs=(), preds=(1,),
                                   flags=0, start_ea=func_ea + i * 0x10,
                                   insn_snapshots=())
    return PortableCFG(blocks=blocks, entry_serial=0, func_ea=func_ea)


def _make_linear_cfg(func_ea: int = 0x402000) -> PortableCFG:
    blocks = {}
    for i in range(4):
        succs = (i + 1,) if i < 3 else ()
        preds = (i - 1,) if i > 0 else ()
        blocks[i] = BlockSnapshot(serial=i, block_type=1 if succs else 0,
                                   succs=succs, preds=preds, flags=0,
                                   start_ea=func_ea + i * 0x10,
                                   insn_snapshots=())
    return PortableCFG(blocks=blocks, entry_serial=0, func_ea=func_ea)


class TestDispatchPatternCollector:
    def test_name_and_level(self):
        c = DispatchPatternCollector()
        assert c.name == "DispatchPatternCollector"
        assert c.level == "microcode"

    def test_maturities_include_calls_and_glbopt1(self):
        c = DispatchPatternCollector()
        assert 3 in c.maturities   # MMAT_CALLS
        assert 14 in c.maturities  # MMAT_GLBOPT1

    def test_no_dispatch_in_linear_cfg(self):
        cfg = _make_linear_cfg()
        result = DispatchPatternCollector().collect(cfg, func_ea=0x402000, maturity=3)
        assert result.metrics["nway_block_count"] == 0
        assert result.metrics["max_nway_fan_out"] == 0
        assert len(result.candidates) == 0

    def test_switch_cfg_detected(self):
        cfg = _make_switch_cfg()
        result = DispatchPatternCollector().collect(cfg, func_ea=0x401000, maturity=3)
        assert result.metrics["nway_block_count"] == 1
        assert result.metrics["max_nway_fan_out"] == 5

    def test_switch_cfg_flags_candidate(self):
        cfg = _make_switch_cfg()
        result = DispatchPatternCollector().collect(cfg, func_ea=0x401000, maturity=3)
        assert len(result.candidates) >= 1
        kinds = {c.kind for c in result.candidates}
        assert "switch_dispatcher" in kinds

    def test_back_edge_count_in_flat_cfg(self):
        """Detect back-edges (loops/flattening feedback) via DFS."""
        # flat cfg: 0->1->(2,3,4), 2->1, 3->1, 4->1
        blocks = {
            0: BlockSnapshot(serial=0, block_type=3, succs=(1,), preds=(), flags=0,
                             start_ea=0x401000, insn_snapshots=()),
            1: BlockSnapshot(serial=1, block_type=3, succs=(2, 3, 4), preds=(0, 2, 3, 4),
                             flags=0, start_ea=0x401010, insn_snapshots=()),
            2: BlockSnapshot(serial=2, block_type=1, succs=(1,), preds=(1,), flags=0,
                             start_ea=0x401020, insn_snapshots=()),
            3: BlockSnapshot(serial=3, block_type=1, succs=(1,), preds=(1,), flags=0,
                             start_ea=0x401030, insn_snapshots=()),
            4: BlockSnapshot(serial=4, block_type=1, succs=(1,), preds=(1,), flags=0,
                             start_ea=0x401040, insn_snapshots=()),
        }
        cfg = PortableCFG(blocks=blocks, entry_serial=0, func_ea=0x401000)
        result = DispatchPatternCollector().collect(cfg, func_ea=0x401000, maturity=3)
        assert result.metrics["back_edge_count"] >= 3
