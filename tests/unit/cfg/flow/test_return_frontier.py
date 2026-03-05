"""Unit tests for the ReturnFrontierAudit engine."""
from __future__ import annotations

import pytest

from d810.cfg.flow.return_frontier import (
    BreakKind,
    ReturnFrontierAudit,
    ReturnSite,
    ReturnSiteStatus,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _site(site_id: str, origin_block: int) -> ReturnSite:
    return ReturnSite(
        site_id=site_id,
        origin_block=origin_block,
        guard_hash="gh_" + site_id,
        expected_terminal_kind="return",
        provenance="test",
    )


def _linear_graph() -> tuple[dict[int, list[int]], int, frozenset[int]]:
    """0 -> 1 -> 2 (exit)"""
    successors = {0: [1], 1: [2], 2: []}
    return successors, 0, frozenset({2})


# ---------------------------------------------------------------------------
# Test 1: all sites intact — linear graph
# ---------------------------------------------------------------------------

def test_all_intact():
    """All sites postdominated by exit in a linear graph — 0 broken."""
    successors, entry, exits = _linear_graph()
    sites = (
        _site("s0", 0),
        _site("s1", 1),
    )
    audit = ReturnFrontierAudit(return_sites=sites)
    audit.record_stage("pre_plan", successors, entry, exits)

    report = audit.report()
    assert report["total_sites"] == 2
    assert report["intact_count"] == 2
    assert report["broken_count"] == 0
    for site in report["sites"]:
        assert site["first_break_stage"] is None
        assert site["stages"]["pre_plan"]["classification"] == BreakKind.INTACT


# ---------------------------------------------------------------------------
# Test 2: site lost at post_plan (unreachable) → coalesce_drop
# ---------------------------------------------------------------------------

def test_site_lost_at_post_plan():
    """Site reachable in pre_plan, dropped (unreachable) in post_plan → coalesce_drop."""
    # pre_plan: 0->1->2, site at block 1
    pre_succs = {0: [1], 1: [2], 2: []}
    # post_plan: 0->2, block 1 removed from graph
    post_succs = {0: [2], 2: []}
    entry = 0
    exits = frozenset({2})

    site = _site("s1", 1)
    audit = ReturnFrontierAudit(return_sites=(site,))
    audit.record_stage("pre_plan", pre_succs, entry, exits)
    audit.record_stage("post_plan", post_succs, entry, exits)

    report = audit.report()
    assert report["broken_count"] == 1
    s = report["sites"][0]
    assert s["first_break_stage"] == "post_plan"
    assert s["stages"]["post_plan"]["classification"] == BreakKind.NOT_REACHABLE


# ---------------------------------------------------------------------------
# Test 3: site loses postdomination at post_apply → apply_failure
# ---------------------------------------------------------------------------

def test_site_lost_at_post_apply():
    """Site intact through post_plan, loses postdom at post_apply → apply_failure."""
    # pre_plan and post_plan: 0->1->2 (exit)
    good_succs = {0: [1], 1: [2], 2: []}
    # post_apply: introduce branch at 1 -> 2 AND 1 -> 3 (no path to exit from 3)
    # block 3 has no successors and is not an exit — so 1 is not postdominated by 2
    bad_succs = {0: [1], 1: [2, 3], 2: [], 3: []}
    entry = 0
    exits = frozenset({2})

    site = _site("s1", 1)
    audit = ReturnFrontierAudit(return_sites=(site,))
    audit.record_stage("pre_plan", good_succs, entry, exits)
    audit.record_stage("post_plan", good_succs, entry, exits)
    audit.record_stage("post_apply", bad_succs, entry, exits)

    report = audit.report()
    assert report["broken_count"] == 1
    s = report["sites"][0]
    assert s["first_break_stage"] == "post_apply"
    assert s["stages"]["post_apply"]["classification"] == BreakKind.APPLY_FAILURE


# ---------------------------------------------------------------------------
# Test 4: site intact through post_apply, breaks at post_pipeline → later_pass_rewrite
# ---------------------------------------------------------------------------

def test_site_lost_at_post_pipeline():
    """Site intact through post_apply, broken at post_pipeline → later_pass_rewrite."""
    good_succs = {0: [1], 1: [2], 2: []}
    # post_pipeline: block 1 gains a new exit-less successor
    bad_succs = {0: [1], 1: [2, 3], 2: [], 3: []}
    entry = 0
    exits = frozenset({2})

    site = _site("s1", 1)
    audit = ReturnFrontierAudit(return_sites=(site,))
    audit.record_stage("pre_plan", good_succs, entry, exits)
    audit.record_stage("post_plan", good_succs, entry, exits)
    audit.record_stage("post_apply", good_succs, entry, exits)
    audit.record_stage("post_pipeline", bad_succs, entry, exits)

    report = audit.report()
    assert report["broken_count"] == 1
    s = report["sites"][0]
    assert s["first_break_stage"] == "post_pipeline"
    assert s["stages"]["post_pipeline"]["classification"] == BreakKind.LATER_PASS_REWRITE


# ---------------------------------------------------------------------------
# Test 5: first_break_stage returns correct stage
# ---------------------------------------------------------------------------

def test_first_break_stage():
    """first_break_stage returns the earliest stage with a break."""
    good_succs = {0: [1], 1: [2], 2: []}
    bad_succs = {0: [1], 1: [2, 3], 2: [], 3: []}
    entry = 0
    exits = frozenset({2})

    site = _site("s1", 1)
    audit = ReturnFrontierAudit(return_sites=(site,))
    audit.record_stage("pre_plan", good_succs, entry, exits)
    audit.record_stage("post_plan", bad_succs, entry, exits)
    audit.record_stage("post_apply", bad_succs, entry, exits)

    assert audit.first_break_stage("s1") == "post_plan"
    assert audit.first_break_stage("nonexistent") is None


# ---------------------------------------------------------------------------
# Test 6: report structure has expected keys
# ---------------------------------------------------------------------------

def test_report_structure():
    """Report dict has all required top-level and per-site keys."""
    successors, entry, exits = _linear_graph()
    site = _site("s0", 0)
    audit = ReturnFrontierAudit(return_sites=(site,))
    audit.record_stage("pre_plan", successors, entry, exits)

    report = audit.report()
    assert "stages_audited" in report
    assert "total_sites" in report
    assert "intact_count" in report
    assert "broken_count" in report
    assert "sites" in report

    site_entry = report["sites"][0]
    assert "site_id" in site_entry
    assert "origin_block" in site_entry
    assert "expected_terminal_kind" in site_entry
    assert "provenance" in site_entry
    assert "first_break_stage" in site_entry
    assert "stages" in site_entry
    assert "pre_plan" in site_entry["stages"]

    stage_entry = site_entry["stages"]["pre_plan"]
    assert "reachable" in stage_entry
    assert "postdominated" in stage_entry
    assert "classification" in stage_entry
    assert "detail" in stage_entry


# ---------------------------------------------------------------------------
# Test 7: diamond graph with two exits
# ---------------------------------------------------------------------------

def test_multiple_exits():
    """Diamond: 0->1(exit), 0->2->3(exit).

    Node 2 is on the only path to exit 3, so exit 3 postdominates node 2.
    Node 1 is an exit itself, so it postdominates itself.
    Node 0 branches to both exits — neither exit individually postdominates 0,
    because 0 has paths to two different exits.  The audit correctly marks 0
    as NOT postdominated by any single exit node.
    Sites at nodes 1 and 2 (each on a single path to their respective exit)
    ARE postdominated — intact.
    """
    successors = {0: [1, 2], 1: [], 2: [3], 3: []}
    entry = 0
    exits = frozenset({1, 3})

    # site_1 is at block 1 (exit itself — postdominated by exit 1 = itself)
    # site_2 is at block 2 (only successor is exit 3 — postdominated by exit 3)
    sites = (_site("s1", 1), _site("s2", 2))
    audit = ReturnFrontierAudit(return_sites=sites)
    results = audit.record_stage("pre_plan", successors, entry, exits)

    assert len(results) == 2
    # Both sites should be intact
    for status in results:
        assert status.reachable_from_entry is True, f"{status.site.site_id} not reachable"
        assert status.postdominated_by_exit is True, (
            f"{status.site.site_id} not postdominated: {status.detail}"
        )
        assert status.break_classification == BreakKind.INTACT

    report = audit.report()
    assert report["intact_count"] == 2
    assert report["broken_count"] == 0
