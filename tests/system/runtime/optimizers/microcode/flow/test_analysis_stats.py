from __future__ import annotations

from enum import IntFlag
from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.analysis_stats import (
    compute_flow_profile_stats,
    summarize_dispatcher_detection,
)
from d810.ir.flowgraph import BlockSnapshot, FlowGraph


def _fg(edges: dict[int, tuple[int, ...]]) -> FlowGraph:
    """Build a topology-only FlowGraph from ``{serial: succs}`` specs."""
    blocks = {
        serial: BlockSnapshot(
            serial=serial,
            block_type=0,
            succs=tuple(succs),
            preds=(),
            flags=0,
            start_ea=0,
            insn_snapshots=(),
        )
        for serial, succs in edges.items()
    }
    entry = min(edges) if edges else 0
    return FlowGraph(blocks=blocks, entry_serial=entry, func_ea=0)


class _Strat(IntFlag):
    NONE = 0
    A = 1
    B = 2
    C = 4


def test_compute_flow_profile_stats_reports_dispatcher_topology():
    mba = _fg(
        {
            0: (1,),
            1: (2, 4),
            2: (3,),
            3: (1,),
            4: (),
        }
    )
    analysis = SimpleNamespace(
        dispatchers=[1, 2, 3],
        blocks={1: object(), 2: object(), 3: object()},
        nested_loop_depth=2,
    )

    stats = compute_flow_profile_stats(mba, analysis)

    assert stats.total_blocks == 5
    assert stats.dispatch_region_n == 3
    assert stats.dispatch_scc_n == 3
    assert stats.dispatch_blocks_n == 3
    assert stats.dispatch_block_ratio == pytest.approx(0.6)
    assert stats.dispatch_exit_nodes_n == 1
    assert stats.dispatch_relay_nodes_n == 3
    assert stats.dispatch_glue_nodes_n == 2
    assert stats.dispatch_glue_ratio == pytest.approx(2.0 / 3.0)
    assert stats.relay_depth_estimate == 3
    assert stats.flattening_score == pytest.approx(0.8)
    assert stats.has_nested_dispatch is True


def test_compute_flow_profile_stats_handles_empty_mba():
    mba = _fg({})
    analysis = SimpleNamespace(dispatchers=[], blocks={}, nested_loop_depth=0)

    stats = compute_flow_profile_stats(mba, analysis)

    assert stats.total_blocks == 0
    assert stats.dispatch_region_n == 0
    assert stats.dispatch_scc_n == 0
    assert stats.dispatch_block_ratio == 0.0
    assert stats.flattening_score == 0.0
    assert stats.has_nested_dispatch is False


def test_summarize_dispatcher_detection_centralizes_strategy_stats():
    analysis = SimpleNamespace(
        blocks={
            0: SimpleNamespace(strategies=_Strat.A),
            1: SimpleNamespace(strategies=_Strat.A | _Strat.B),
            2: SimpleNamespace(strategies=_Strat.NONE),
        },
        dispatchers=[0, 1],
        dispatcher_type=SimpleNamespace(name="CONDITIONAL_CHAIN"),
        state_constants={0x10, 0x20},
    )

    summary = summarize_dispatcher_detection(
        analysis=analysis,
        blocks_analyzed=10,
        blocks_skipped=7,
        strategies=_Strat,
    )

    assert summary["blocks_analyzed"] == 10
    assert summary["blocks_with_strategies"] == 3
    assert summary["blocks_skipped"] == 7
    assert summary["skip_rate"] == pytest.approx(0.7)
    assert summary["dispatchers_found"] == 2
    assert summary["dispatcher_type"] == "CONDITIONAL_CHAIN"
    assert summary["state_constants_count"] == 2
    assert summary["strategies_used"] == {"A": 2, "B": 1}
