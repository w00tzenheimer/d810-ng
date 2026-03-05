"""Unit tests for ReturnFrontierCollector.

Uses SimpleNamespace mock FlowGraph objects — no IDA dependency.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from d810.cfg.flow.return_frontier import ReturnSite
from d810.recon.collectors.return_frontier import ReturnFrontierCollector


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_site(site_id: str, origin_block: int) -> ReturnSite:
    return ReturnSite(
        site_id=site_id,
        origin_block=origin_block,
        guard_hash=f"hash_{site_id}",
        expected_terminal_kind="return",
        provenance="test",
    )


def _make_target(
    return_sites=(),
    successors=None,
    entry=None,
    exits=frozenset(),
    stage_name="pre_plan",
):
    """Build a fake FlowGraph-like object with a metadata dict."""
    metadata = {
        "return_sites": return_sites,
        "cfg_successors": successors,
        "cfg_entry": entry,
        "cfg_exits": exits,
        "stage_name": stage_name,
    }
    return SimpleNamespace(metadata=metadata)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestReturnFrontierCollector:

    def test_collect_with_return_sites(self):
        """Provide full metadata — verify ReconResult has correct metrics."""
        site = _make_site("s0", origin_block=1)
        # Simple linear graph: 0 -> 1 -> 2(exit)
        successors = {0: [1], 1: [2], 2: []}
        target = _make_target(
            return_sites=(site,),
            successors=successors,
            entry=0,
            exits=frozenset({2}),
            stage_name="pre_plan",
        )

        collector = ReturnFrontierCollector()
        result = collector.collect(target, func_ea=0x401000, maturity=5)

        assert result.collector_name == "return_frontier"
        assert result.func_ea == 0x401000
        assert result.maturity == 5
        assert result.metrics["total_sites"] == 1
        assert result.metrics["stages_audited"] == 1

    def test_collect_empty_metadata(self):
        """No return_sites in metadata — returns empty ReconResult."""
        target = SimpleNamespace(metadata={})

        collector = ReturnFrontierCollector()
        result = collector.collect(target, func_ea=0x402000, maturity=3)

        assert result.collector_name == "return_frontier"
        assert result.metrics == {}
        assert result.candidates == ()

    def test_collect_missing_metadata_attr(self):
        """Target with no metadata attribute — returns empty ReconResult."""
        target = SimpleNamespace()  # no metadata attr

        collector = ReturnFrontierCollector()
        result = collector.collect(target, func_ea=0x403000, maturity=3)

        assert result.candidates == ()
        assert result.metrics == {}

    def test_multi_stage_audit(self):
        """Call collect() twice with different stage_names — stages_audited == 2."""
        site = _make_site("s1", origin_block=1)
        successors = {0: [1], 1: [2], 2: []}

        collector = ReturnFrontierCollector()

        target1 = _make_target(
            return_sites=(site,),
            successors=successors,
            entry=0,
            exits=frozenset({2}),
            stage_name="pre_plan",
        )
        collector.collect(target1, func_ea=0x401000, maturity=5)

        target2 = _make_target(
            return_sites=(site,),
            successors=successors,
            entry=0,
            exits=frozenset({2}),
            stage_name="post_plan",
        )
        result2 = collector.collect(target2, func_ea=0x401000, maturity=5)

        assert result2.metrics["stages_audited"] == 2

    def test_broken_site_creates_candidate(self):
        """Site not reachable from entry — CandidateFlag created."""
        site = _make_site("s2", origin_block=5)
        # Block 5 is not reachable from entry 0
        successors = {0: [1], 1: [2], 2: [], 5: []}
        target = _make_target(
            return_sites=(site,),
            successors=successors,
            entry=0,
            exits=frozenset({2}),
            stage_name="pre_plan",
        )

        collector = ReturnFrontierCollector()
        result = collector.collect(target, func_ea=0x401000, maturity=5)

        assert len(result.candidates) == 1
        flag = result.candidates[0]
        assert "return_break_" in flag.kind
        assert flag.block_serial == 5
        assert flag.confidence == 0.9
        assert "s2" in flag.detail

    def test_intact_site_no_candidate(self):
        """Site properly postdominated — no CandidateFlag produced."""
        site = _make_site("s3", origin_block=1)
        # 0 -> 1 -> 2(exit): block 1 is postdominated by exit 2
        successors = {0: [1], 1: [2], 2: []}
        target = _make_target(
            return_sites=(site,),
            successors=successors,
            entry=0,
            exits=frozenset({2}),
            stage_name="pre_plan",
        )

        collector = ReturnFrontierCollector()
        result = collector.collect(target, func_ea=0x401000, maturity=5)

        assert result.candidates == ()
        assert result.metrics["intact_count"] == 1
        assert result.metrics["broken_count"] == 0

    def test_write_artifact(self, tmp_path):
        """Verify JSON artifact is written to _artifact_dir."""
        site = _make_site("s4", origin_block=1)
        successors = {0: [1], 1: [2], 2: []}
        target = _make_target(
            return_sites=(site,),
            successors=successors,
            entry=0,
            exits=frozenset({2}),
            stage_name="pre_plan",
        )

        collector = ReturnFrontierCollector()
        collector._artifact_dir = tmp_path  # redirect to pytest tmp
        collector.collect(target, func_ea=0x401000, maturity=5)

        artifact_path = collector.write_artifact(func_ea=0x401000)

        assert artifact_path is not None
        assert artifact_path.exists()
        data = json.loads(artifact_path.read_text())
        assert "total_sites" in data
        assert data["total_sites"] == 1
        assert "stages_audited" in data

    def test_write_artifact_before_collect_returns_none(self, tmp_path):
        """write_artifact() before any collect() returns None."""
        collector = ReturnFrontierCollector()
        collector._artifact_dir = tmp_path
        assert collector.write_artifact(func_ea=0x401000) is None

    def test_reset_clears_state(self):
        """After reset(), audit starts fresh — stages_audited resets to 1."""
        site = _make_site("s5", origin_block=1)
        successors = {0: [1], 1: [2], 2: []}

        collector = ReturnFrontierCollector()

        # First pass: two stages
        for stage in ("pre_plan", "post_plan"):
            target = _make_target(
                return_sites=(site,),
                successors=successors,
                entry=0,
                exits=frozenset({2}),
                stage_name=stage,
            )
            collector.collect(target, func_ea=0x401000, maturity=5)

        collector.reset()

        # After reset, first collect again — stages_audited should be 1
        target_fresh = _make_target(
            return_sites=(site,),
            successors=successors,
            entry=0,
            exits=frozenset({2}),
            stage_name="pre_plan",
        )
        result = collector.collect(target_fresh, func_ea=0x401000, maturity=5)
        assert result.metrics["stages_audited"] == 1
