"""Integration test for the return frontier audit pipeline.

Verifies that HodurReturnSiteProvider + ReturnFrontierCollector work together
end-to-end without requiring an IDA environment.  Uses fake/mock objects for
IDA-specific types.
"""
from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

import pytest

from d810.cfg.flow.return_frontier import ReturnSite, ReturnFrontierAudit
from d810.optimizers.microcode.flow.flattening.hodur.return_sites import (
    HodurReturnSiteProvider,
)
from d810.recon.collectors.return_frontier import ReturnFrontierCollector


# ---------------------------------------------------------------------------
# Fake HandlerPathResult (no IDA dependency)
# ---------------------------------------------------------------------------


@dataclass
class _FakePath:
    """Stand-in for HandlerPathResult."""

    exit_block: int
    final_state: int | None
    state_writes: list = field(default_factory=list)
    ordered_path: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_simple_graph() -> dict[int, list[int]]:
    """
    Graph:  0 -> 1 -> 2 (exit)
                  |-> 3 (exit)
    """
    return {
        0: [1],
        1: [2, 3],
        2: [],
        3: [],
    }


def _make_modified_graph() -> dict[int, list[int]]:
    """Post-apply graph where block 3 has been redirected to a loop (no exit path).

    3 now flows to 5 which loops back to 1, so block 3 is not postdominated
    by any exit.  Block 2 is the only exit.
    """
    return {
        0: [1],
        1: [2, 3],
        2: [],
        3: [5],
        5: [1],  # back-edge loop; no path to an exit from block 3
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestProviderToCollectorPipeline:
    """Full pipeline: provider collects sites → collector audits across stages."""

    def test_pre_plan_stage_populates_audit(self) -> None:
        """After pre_plan collect(), audit is initialized with return sites."""
        provider = HodurReturnSiteProvider()
        collector = ReturnFrontierCollector()

        handler_paths = {
            10: [_FakePath(exit_block=2, final_state=None)],
            20: [_FakePath(exit_block=3, final_state=None)],
        }
        return_sites = provider.collect_return_sites(
            snapshot=None, handler_paths=handler_paths  # type: ignore[arg-type]
        )
        assert len(return_sites) == 2

        succs = _make_simple_graph()
        exits = frozenset({2, 3})
        target = SimpleNamespace(metadata={
            "return_sites": return_sites,
            "cfg_successors": succs,
            "cfg_entry": 0,
            "cfg_exits": exits,
            "stage_name": "pre_plan",
        })

        result = collector.collect(target=target, func_ea=0x1000, maturity=1)

        assert collector._audit is not None
        assert result.metrics["total_sites"] == 2

    def test_four_stage_audit_intact(self) -> None:
        """Sites that remain intact across all stages report intact in final report."""
        provider = HodurReturnSiteProvider()
        collector = ReturnFrontierCollector()

        handler_paths = {
            1: [_FakePath(exit_block=2, final_state=None)],
        }
        return_sites = provider.collect_return_sites(
            snapshot=None, handler_paths=handler_paths  # type: ignore[arg-type]
        )

        succs = _make_simple_graph()
        exits = frozenset({2, 3})

        for stage in ("pre_plan", "post_plan", "post_apply", "post_pipeline"):
            target = SimpleNamespace(metadata={
                "return_sites": return_sites,
                "cfg_successors": succs,
                "cfg_entry": 0,
                "cfg_exits": exits,
                "stage_name": stage,
            })
            collector.collect(target=target, func_ea=0x1000, maturity=1)

        report = collector._audit.report()
        assert report["total_sites"] == 1
        assert report["broken_count"] == 0
        assert report["intact_count"] == 1
        site = report["sites"][0]
        assert site["first_break_stage"] is None

    def test_broken_site_detected_at_correct_stage(self) -> None:
        """A site that becomes unreachable at post_apply is flagged with first_break_stage=post_apply.

        Scenario: block 3 is a return site. After post_apply the unflattener redirects
        block 1 to skip block 3 entirely, making block 3 unreachable from entry.
        """
        provider = HodurReturnSiteProvider()
        collector = ReturnFrontierCollector()

        # Site at exit block 3
        handler_paths = {
            20: [_FakePath(exit_block=3, final_state=None)],
        }
        return_sites = provider.collect_return_sites(
            snapshot=None, handler_paths=handler_paths  # type: ignore[arg-type]
        )

        # pre/post_plan: 0->1->{2,3}, both 2 and 3 are exits
        intact_succs = _make_simple_graph()
        intact_exits = frozenset({2, 3})

        # post_apply: 0->1->2 only; block 3 is unreachable (dropped from graph)
        # Block 3 still exists in the successor dict but entry no longer reaches it
        broken_succs = {
            0: [1],
            1: [2],       # block 1 now only goes to 2 (block 3 bypassed)
            2: [],
            3: [],        # block 3 still exists but is unreachable from entry
        }
        broken_exits = frozenset({2, 3})

        for stage, succs, exits in [
            ("pre_plan", intact_succs, intact_exits),
            ("post_plan", intact_succs, intact_exits),
            ("post_apply", broken_succs, broken_exits),
            ("post_pipeline", broken_succs, broken_exits),
        ]:
            target = SimpleNamespace(metadata={
                "return_sites": return_sites,
                "cfg_successors": succs,
                "cfg_entry": 0,
                "cfg_exits": exits,
                "stage_name": stage,
            })
            collector.collect(target=target, func_ea=0x1000, maturity=1)

        report = collector._audit.report()
        assert report["broken_count"] == 1
        site = report["sites"][0]
        assert site["first_break_stage"] == "post_apply"

    def test_json_artifact_includes_first_break_stage(self, tmp_path: Path) -> None:
        """write_artifact() produces a valid JSON file with first_break_stage field."""
        provider = HodurReturnSiteProvider()
        collector = ReturnFrontierCollector()
        collector._artifact_dir = tmp_path

        handler_paths = {
            10: [_FakePath(exit_block=2, final_state=None)],
        }
        return_sites = provider.collect_return_sites(
            snapshot=None, handler_paths=handler_paths  # type: ignore[arg-type]
        )

        succs = _make_simple_graph()
        exits = frozenset({2, 3})

        for stage in ("pre_plan", "post_plan", "post_apply", "post_pipeline"):
            target = SimpleNamespace(metadata={
                "return_sites": return_sites,
                "cfg_successors": succs,
                "cfg_entry": 0,
                "cfg_exits": exits,
                "stage_name": stage,
            })
            collector.collect(target=target, func_ea=0x1000, maturity=1)

        artifact_path = collector.write_artifact(func_ea=0x1000)
        assert artifact_path is not None
        assert artifact_path.exists()

        data = json.loads(artifact_path.read_text())
        assert "sites" in data
        assert len(data["sites"]) == 1
        assert "first_break_stage" in data["sites"][0]

    def test_metadata_return_sites_populated(self) -> None:
        """return_sites field in metadata is passed through to audit correctly."""
        provider = HodurReturnSiteProvider()
        collector = ReturnFrontierCollector()

        handler_paths = {
            5: [
                _FakePath(exit_block=10, final_state=None, state_writes=[(3, 0xABC)]),
                _FakePath(exit_block=11, final_state=None),
            ],
            6: [
                _FakePath(exit_block=12, final_state=0xDEAD),  # non-terminal, skipped
            ],
        }
        return_sites = provider.collect_return_sites(
            snapshot=None, handler_paths=handler_paths  # type: ignore[arg-type]
        )
        assert len(return_sites) == 2

        succs = {0: [1], 1: [10, 11], 10: [], 11: []}
        exits = frozenset({10, 11})

        target = SimpleNamespace(metadata={
            "return_sites": return_sites,
            "cfg_successors": succs,
            "cfg_entry": 0,
            "cfg_exits": exits,
            "stage_name": "pre_plan",
        })
        result = collector.collect(target=target, func_ea=0x2000, maturity=2)

        assert result.metrics["total_sites"] == 2
        # Both sites should be intact at pre_plan
        assert result.metrics["broken_count"] == 0

    def test_collector_reset_clears_audit(self) -> None:
        """reset() clears audit so a fresh function gets clean state."""
        provider = HodurReturnSiteProvider()
        collector = ReturnFrontierCollector()

        handler_paths = {1: [_FakePath(exit_block=5, final_state=None)]}
        return_sites = provider.collect_return_sites(
            snapshot=None, handler_paths=handler_paths  # type: ignore[arg-type]
        )
        succs = {0: [5], 5: []}
        exits = frozenset({5})

        target = SimpleNamespace(metadata={
            "return_sites": return_sites,
            "cfg_successors": succs,
            "cfg_entry": 0,
            "cfg_exits": exits,
            "stage_name": "pre_plan",
        })
        collector.collect(target=target, func_ea=0x3000, maturity=1)
        assert collector._audit is not None

        collector.reset()
        assert collector._audit is None
