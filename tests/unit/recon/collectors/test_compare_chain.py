"""Unit tests for CompareChainCollector adapter."""
from __future__ import annotations

from types import MappingProxyType, SimpleNamespace

import pytest

from d810.cfg.flow.compare_chain import BlockComparison
from d810.cfg.flow.state_var_alias import VarRef
from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.recon.collectors.compare_chain import (
    CompareChainCollector,
    _count_conflicting,
    _portable_comparisons,
)
from d810.recon.models import ReconResult
from d810.recon.phase import ReconCollector


# ------------------------------------------------------------------
# Protocol / metadata tests
# ------------------------------------------------------------------


def test_collector_name():
    c = CompareChainCollector()
    assert c.name == "compare_chain"


def test_collector_level():
    c = CompareChainCollector()
    assert c.level == "microcode"


def test_collector_maturities():
    c = CompareChainCollector()
    assert 3 in c.maturities  # MMAT_CALLS
    assert 14 in c.maturities  # MMAT_GLBOPT1


def test_satisfies_protocol():
    c = CompareChainCollector()
    assert isinstance(c, ReconCollector)


# ------------------------------------------------------------------
# Pure-Python helper tests
# ------------------------------------------------------------------


def test_count_conflicting_no_conflicts():
    var = VarRef("reg", 0, 8)
    comps = [
        BlockComparison(1, var, 0x42, 10, 2),
        BlockComparison(2, var, 0x100, 20, 3),
    ]
    assert _count_conflicting(comps, frozenset({var})) == 0


def test_count_conflicting_with_conflict():
    var = VarRef("reg", 0, 8)
    comps = [
        BlockComparison(1, var, 0x42, 10, 2),
        BlockComparison(2, var, 0x42, 99, 3),  # same constant, different target
    ]
    assert _count_conflicting(comps, frozenset({var})) == 1


def test_count_conflicting_ignores_non_alias():
    var = VarRef("reg", 0, 8)
    other = VarRef("reg", 1, 8)
    comps = [
        BlockComparison(1, other, 0x42, 10, 2),
        BlockComparison(2, other, 0x42, 99, 3),
    ]
    # `other` is not in the alias set, so no conflicts counted
    assert _count_conflicting(comps, frozenset({var})) == 0


# ------------------------------------------------------------------
# FlowGraph (portable) integration
# ------------------------------------------------------------------


def _make_2way_flow_graph() -> FlowGraph:
    """FlowGraph with two BLT_2WAY blocks feeding a fallthrough."""
    return FlowGraph(
        blocks={
            0: BlockSnapshot(0, 4, (10, 1), (), 0, 0, ()),  # BLT_2WAY
            1: BlockSnapshot(1, 4, (20, 99), (0,), 0, 0, ()),  # BLT_2WAY
            10: BlockSnapshot(10, 0, (), (0,), 0, 0, ()),
            20: BlockSnapshot(20, 0, (), (1,), 0, 0, ()),
            99: BlockSnapshot(99, 0, (), (1,), 0, 0, ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )


def test_collect_portable_flowgraph():
    c = CompareChainCollector()
    fg = _make_2way_flow_graph()
    result = c.collect(fg, func_ea=0x1000, maturity=3)

    assert isinstance(result, ReconResult)
    assert result.collector_name == "compare_chain"
    assert result.func_ea == 0x1000
    assert result.maturity == 3
    assert result.metrics["compare_chain_length"] == 2  # two BLT_2WAY blocks
    assert result.metrics["dispatch_table_size"] >= 0
    assert result.metrics["unique_constants"] >= 0
    assert result.metrics["conflicting_count"] == 0
    assert "default_serial" in result.metrics


def test_collect_empty_graph():
    fg = FlowGraph(blocks={}, entry_serial=0, func_ea=0x2000)
    c = CompareChainCollector()
    result = c.collect(fg, func_ea=0x2000, maturity=14)

    assert result.metrics["compare_chain_length"] == 0
    assert result.metrics["dispatch_table_size"] == 0
    assert result.metrics["default_serial"] == -1
    assert result.candidates == ()


def test_collect_with_metadata():
    """Collector extracts comparisons from target.metadata when present."""
    var = VarRef("reg", 0, 8)
    fg = FlowGraph(
        blocks={
            0: BlockSnapshot(0, 0, (1,), (), 0, 0, ()),
            1: BlockSnapshot(1, 0, (), (0,), 0, 0, ()),
        },
        entry_serial=0,
        func_ea=0x3000,
        metadata={
            "compare_chain_comparisons": [
                {
                    "var": {"kind": "reg", "identifier": 0, "size": 8},
                    "block_serial": 0,
                    "constant": 0x42,
                    "true_target": 10,
                    "false_target": 1,
                },
                {
                    "var": {"kind": "reg", "identifier": 0, "size": 8},
                    "block_serial": 1,
                    "constant": 0x100,
                    "true_target": 20,
                    "false_target": 99,
                },
            ],
        },
    )
    c = CompareChainCollector()
    result = c.collect(fg, func_ea=0x3000, maturity=3)

    assert result.metrics["compare_chain_length"] == 2
    assert result.metrics["dispatch_table_size"] == 2
    assert result.metrics["unique_constants"] == 2
    assert result.metrics["default_serial"] == 99
    assert len(result.candidates) == 2
    assert all(cf.kind == "compare_chain_entry" for cf in result.candidates)
    assert all(cf.confidence == 0.7 for cf in result.candidates)


def test_candidates_detail_format():
    """Candidate detail strings are human-readable hex."""
    fg = FlowGraph(
        blocks={
            0: BlockSnapshot(0, 0, (), (), 0, 0, ()),
        },
        entry_serial=0,
        func_ea=0x4000,
        metadata={
            "compare_chain_comparisons": [
                {
                    "var": {"kind": "reg", "identifier": 0, "size": 4},
                    "block_serial": 0,
                    "constant": 255,
                    "true_target": 5,
                    "false_target": 6,
                },
            ],
        },
    )
    c = CompareChainCollector()
    result = c.collect(fg, func_ea=0x4000, maturity=3)
    assert "0xff" in result.candidates[0].detail
    assert "blk 5" in result.candidates[0].detail
