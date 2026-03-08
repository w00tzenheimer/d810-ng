"""Unit tests for FlowProfileClassifierCollector.

Uses SimpleNamespace mock FlowGraph objects -- no IDA dependency.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.recon.collectors.profile_classifier import (
    FlowProfileClassifierCollector,
    _portable_components,
)
from d810.recon.models import ReconResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_block(serial: int, succs: tuple[int, ...], block_type: int = 0):
    return SimpleNamespace(serial=serial, succs=succs, block_type=block_type)


def _make_flow_graph(
    blocks: dict[int, SimpleNamespace],
    entry_serial: int = 0,
    metadata: dict | None = None,
):
    return SimpleNamespace(
        blocks=blocks,
        entry_serial=entry_serial,
        metadata=metadata or {},
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestFlowProfileClassifierCollector:

    def test_name_and_level(self):
        c = FlowProfileClassifierCollector()
        assert c.name == "flow_profile_classifier"
        assert c.level == "microcode"

    def test_maturities(self):
        c = FlowProfileClassifierCollector()
        assert 3 in c.maturities   # MMAT_CALLS
        assert 14 in c.maturities  # MMAT_GLBOPT1

    def test_collect_simple_compare_chain(self):
        """Portable FlowGraph with a linear compare chain and dispatch metadata."""
        blocks = {
            0: _make_block(0, (1, 10), block_type=4),  # BLT_2WAY
            1: _make_block(1, (2, 11), block_type=4),
            2: _make_block(2, (3, 12), block_type=4),
            3: _make_block(3, (4, 13), block_type=4),
            4: _make_block(4, (5, 14), block_type=4),
            10: _make_block(10, (), block_type=0),
            11: _make_block(11, (), block_type=0),
            12: _make_block(12, (), block_type=0),
            13: _make_block(13, (), block_type=0),
            14: _make_block(14, (), block_type=0),
            5: _make_block(5, (), block_type=0),
        }
        metadata = {
            "dispatch_region": [0, 1, 2, 3, 4],
            "dispatch_table_size": 5,
            "compare_chain_length": 5,
            "has_default_target": True,
        }
        target = _make_flow_graph(blocks, entry_serial=0, metadata=metadata)

        c = FlowProfileClassifierCollector()
        result = c.collect(target, func_ea=0x1000, maturity=3)

        assert isinstance(result, ReconResult)
        assert result.collector_name == "flow_profile_classifier"
        assert result.func_ea == 0x1000
        assert result.maturity == 3
        assert result.metrics["compare_chain_length"] == 5
        assert result.metrics["dispatch_table_size"] == 5
        assert result.metrics["pattern"] == "simple_compare_chain"
        assert result.metrics["classification_confidence"] > 0.0
        assert result.metrics["recommended_strategy"] == "compare_chain_direct"

    def test_collect_unknown_pattern(self):
        """No dispatch region -> unknown pattern, no candidates."""
        blocks = {
            0: _make_block(0, (1,), block_type=0),
            1: _make_block(1, (), block_type=0),
        }
        target = _make_flow_graph(blocks, entry_serial=0)

        c = FlowProfileClassifierCollector()
        result = c.collect(target, func_ea=0x2000, maturity=14)

        assert result.metrics["pattern"] == "unknown"
        assert result.candidates == ()

    def test_collect_with_metadata_dispatch_region(self):
        """When metadata provides dispatch_region, use it directly."""
        blocks = {
            0: _make_block(0, (1, 2), block_type=4),
            1: _make_block(1, (3, 4), block_type=4),
            2: _make_block(2, (), block_type=0),
            3: _make_block(3, (), block_type=0),
            4: _make_block(4, (), block_type=0),
        }
        metadata = {
            "dispatch_region": [0, 1],
            "dispatch_table_size": 2,
            "compare_chain_length": 2,
            "state_alias_count": 1,
            "has_default_target": True,
        }
        target = _make_flow_graph(blocks, entry_serial=0, metadata=metadata)

        c = FlowProfileClassifierCollector()
        result = c.collect(target, func_ea=0x3000, maturity=3)

        assert result.metrics["dispatch_region_size"] == 2
        assert result.metrics["dispatch_table_size"] == 2
        assert result.metrics["case_block_count"] == 3

    def test_candidates_emitted_for_known_pattern(self):
        """Non-unknown pattern produces a CandidateFlag."""
        blocks = {
            0: _make_block(0, (1, 10), block_type=4),
            1: _make_block(1, (2, 11), block_type=4),
            2: _make_block(2, (12,), block_type=0),
            10: _make_block(10, (), block_type=0),
            11: _make_block(11, (), block_type=0),
            12: _make_block(12, (), block_type=0),
        }
        target = _make_flow_graph(blocks, entry_serial=0)

        c = FlowProfileClassifierCollector()
        result = c.collect(target, func_ea=0x4000, maturity=3)

        if result.metrics["pattern"] != "unknown":
            assert len(result.candidates) == 1
            flag = result.candidates[0]
            assert flag.kind.startswith("dispatch_pattern_")
            assert 0.0 <= flag.confidence <= 1.0

    def test_metrics_keys(self):
        """Verify all expected metric keys are present."""
        blocks = {
            0: _make_block(0, (1,), block_type=4),
            1: _make_block(1, (), block_type=0),
        }
        target = _make_flow_graph(blocks, entry_serial=0)

        c = FlowProfileClassifierCollector()
        result = c.collect(target, func_ea=0x5000, maturity=3)

        expected_keys = {
            "pattern",
            "classification_confidence",
            "recommended_strategy",
            "reasoning",
            "dispatch_table_size",
            "compare_chain_length",
            "dispatch_region_size",
            "case_block_count",
        }
        assert set(result.metrics.keys()) == expected_keys

    def test_result_is_frozen(self):
        """ReconResult metrics should be read-only."""
        blocks = {
            0: _make_block(0, (1,), block_type=4),
            1: _make_block(1, (), block_type=0),
        }
        target = _make_flow_graph(blocks, entry_serial=0)

        c = FlowProfileClassifierCollector()
        result = c.collect(target, func_ea=0x6000, maturity=3)

        with pytest.raises(TypeError):
            result.metrics["new_key"] = "boom"
