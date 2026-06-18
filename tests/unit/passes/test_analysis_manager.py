"""AnalysisManager — LLVM-style lazy caching + PreservedAnalyses invalidation."""
from __future__ import annotations

from d810.passes.analysis_manager import AnalysisManager
from d810.passes.pass_pipeline import PreservedAnalyses


def test_get_computes_once_and_caches():
    am = AnalysisManager(graph="G0")
    calls = []

    def compute(graph):
        calls.append(graph)
        return f"result-of-{graph}"

    assert am.get("reach", compute) == "result-of-G0"
    assert am.get("reach", compute) == "result-of-G0"
    assert calls == ["G0"]  # computed exactly once
    assert am.cached("reach")


def test_invalidate_none_drops_all_and_advances_graph():
    am = AnalysisManager(graph="G0")
    am.get("reach", lambda g: 1)
    am.get("trans", lambda g: 2)
    am.put_analysis("published", 3)
    am.invalidate_to("G1", PreservedAnalyses.none())
    assert am.graph == "G1"
    assert not am.cached("reach") and not am.cached("trans")
    assert not am.has_analysis("published")


def test_invalidate_preserving_keeps_named_results():
    am = AnalysisManager(graph="G0")
    am.get("reach", lambda g: 1)
    am.get("trans", lambda g: 2)
    am.put_analysis("published", 3)
    am.invalidate_to("G1", PreservedAnalyses.preserving({"reach"}))
    assert am.cached("reach") and not am.cached("trans")
    assert not am.has_analysis("published")


def test_has_analysis_checks_published_and_cached_results():
    am = AnalysisManager(graph="G0")
    assert not am.has_analysis("published")
    am.put_analysis("published", None)
    assert am.has_analysis("published")
    assert not am.has_analysis("cached")
    am.get("cached", lambda g: 1)
    assert am.has_analysis("cached")


def test_invalidate_all_keeps_everything():
    am = AnalysisManager(graph="G0")
    am.get("reach", lambda g: 1)
    am.invalidate_to("G1", PreservedAnalyses.all())
    assert am.cached("reach")
    # subsequent get over the new graph returns the preserved (cached) value, not recomputed
    assert am.get("reach", lambda g: 999) == 1


def test_satisfies_factstore_protocol_used_by_driver():
    am = AnalysisManager(graph="G0")
    assert am.view() is am
    assert hasattr(am, "invalidate_to")


def test_set_input_facts_replaces_active_observations():
    am = AnalysisManager(
        graph="G0",
        input_facts=type("_Facts", (), {"active_observations": ("old",)})(),
    )

    am.set_input_facts(
        type("_Facts", (), {"active_observations": ("new",)})()
    )

    assert am.active_observations == ("new",)
