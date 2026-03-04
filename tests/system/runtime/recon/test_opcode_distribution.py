"""Unit tests for OpcodeDistributionCollector using PortableCFG + InsnSnapshot."""
from __future__ import annotations
import pytest
from d810.cfg.flowgraph import BlockSnapshot, InsnSnapshot, FlowGraph
from d810.recon.collectors.opcode_distribution import OpcodeDistributionCollector


def _insn(opcode: int) -> InsnSnapshot:
    return InsnSnapshot(opcode=opcode, operands=(), ea=0)


def _make_cfg_with_opcodes(opcode_lists: list[list[int]], func_ea: int = 0x401000) -> FlowGraph:
    """Build a PortableCFG where each block has the given opcodes."""
    blocks = {}
    for i, opcodes in enumerate(opcode_lists):
        insns = tuple(_insn(op) for op in opcodes)
        succs = (i + 1,) if i < len(opcode_lists) - 1 else ()
        preds = (i - 1,) if i > 0 else ()
        blocks[i] = BlockSnapshot(
            serial=i, block_type=1 if succs else 0,
            succs=succs, preds=preds,
            flags=0, start_ea=func_ea + i * 0x10,
            insn_snapshots=insns,
        )
    return FlowGraph(blocks=blocks, entry_serial=0, func_ea=func_ea)


class TestOpcodeDistributionCollector:
    def test_name_and_level(self):
        c = OpcodeDistributionCollector()
        assert c.name == "OpcodeDistributionCollector"
        assert c.level == "microcode"

    def test_maturities_include_preoptimized(self):
        c = OpcodeDistributionCollector()
        assert 5 in c.maturities  # MMAT_PREOPTIMIZED

    def test_empty_cfg_zero_counts(self):
        cfg = FlowGraph(blocks={}, entry_serial=0, func_ea=0x401000)
        result = OpcodeDistributionCollector().collect(cfg, func_ea=0x401000, maturity=5)
        assert result.metrics["total_insns"] == 0
        assert result.metrics["unique_opcodes"] == 0
        assert result.metrics["top_opcode"] == -1

    def test_single_block_opcode_count(self):
        # opcodes: [1, 1, 2, 3]  -> total=4, unique=3, top=1 (appears twice)
        cfg = _make_cfg_with_opcodes([[1, 1, 2, 3]])
        result = OpcodeDistributionCollector().collect(cfg, func_ea=0x401000, maturity=5)
        assert result.metrics["total_insns"] == 4
        assert result.metrics["unique_opcodes"] == 3
        assert result.metrics["top_opcode"] == 1
        assert result.metrics["top_opcode_count"] == 2

    def test_multi_block_aggregation(self):
        cfg = _make_cfg_with_opcodes([[1, 2], [1, 3], [4]])
        result = OpcodeDistributionCollector().collect(cfg, func_ea=0x401000, maturity=5)
        assert result.metrics["total_insns"] == 5
        assert result.metrics["unique_opcodes"] == 4
        assert result.metrics["top_opcode"] == 1  # appears in blocks 0 and 1

    def test_high_repeat_opcode_flags_candidate(self):
        """When a single opcode makes up >50% of all instructions, flag it."""
        # opcode 7 appears 8 out of 10 times = 80%
        cfg = _make_cfg_with_opcodes([[7, 7, 7, 7, 7, 7, 7, 7, 1, 2]])
        result = OpcodeDistributionCollector().collect(cfg, func_ea=0x401000, maturity=5)
        assert result.metrics["top_opcode_ratio"] > 0.5
        # Should have a candidate flagged
        assert len(result.candidates) >= 1
        kinds = {c.kind for c in result.candidates}
        assert "high_opcode_dominance" in kinds

    def test_result_metrics_are_read_only(self):
        cfg = _make_cfg_with_opcodes([[1, 2, 3]])
        result = OpcodeDistributionCollector().collect(cfg, func_ea=0x401000, maturity=5)
        with pytest.raises(TypeError):
            result.metrics["total_insns"] = 0  # type: ignore[index]
