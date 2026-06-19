"""AnalysisManager — LLVM-style lazy caching + PreservedAnalyses invalidation."""
from __future__ import annotations

from d810.passes.analysis_manager import AnalysisManager
from d810.analyses.value_flow.contract_evidence import contract_evidence_payload
from d810.passes.pass_pipeline import (
    PassContract,
    PassInvalidates,
    PreservedAnalyses,
)


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


def test_provider_backed_analysis_is_available_and_computed_once():
    calls: list[object] = []
    am = AnalysisManager(
        graph="G0",
        providers={"domtree": lambda graph: calls.append(graph) or f"D:{graph}"},
    )

    assert am.has_analysis("domtree")
    assert am.get_analysis("domtree") == "D:G0"
    assert am.get_analysis("domtree") == "D:G0"
    assert calls == ["G0"]


def test_register_provider_makes_analysis_available():
    am = AnalysisManager(graph="G0")
    assert not am.has_analysis("domtree")

    am.register_provider("domtree", lambda graph: f"D:{graph}")

    assert am.require_analysis("domtree") == "D:G0"


def test_require_analysis_raises_when_missing():
    am = AnalysisManager(graph="G0")

    try:
        am.require_analysis("missing")
    except KeyError as exc:
        assert exc.args == ("missing",)
    else:
        raise AssertionError("missing analysis should raise KeyError")


def test_provider_recomputes_after_invalidation_when_not_preserved():
    calls: list[object] = []
    am = AnalysisManager(
        graph="G0",
        providers={"domtree": lambda graph: calls.append(graph) or f"D:{graph}"},
    )

    assert am.get_analysis("domtree") == "D:G0"
    am.invalidate_to("G1", PreservedAnalyses.none())
    assert am.get_analysis("domtree") == "D:G1"
    assert calls == ["G0", "G1"]


def test_provider_cache_survives_invalidation_when_preserved():
    calls: list[object] = []
    am = AnalysisManager(
        graph="G0",
        providers={"domtree": lambda graph: calls.append(graph) or f"D:{graph}"},
    )

    assert am.get_analysis("domtree") == "D:G0"
    am.invalidate_to("G1", PreservedAnalyses.preserving({"domtree"}))
    assert am.get_analysis("domtree") == "D:G0"
    assert calls == ["G0"]


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


def test_set_input_facts_none_clears_active_observations():
    am = AnalysisManager(
        graph="G0",
        input_facts=type("_Facts", (), {"active_observations": ("old",)})(),
    )

    am.set_input_facts(None)

    assert am.active_observations == ()


def test_fact_store_reads_published_and_live_observation_facts():
    observation = type("_Obs", (), {"kind": "state_transition"})()
    am = AnalysisManager(
        graph="G0",
        input_facts=type("_Facts", (), {"active_observations": (observation,)})(),
    )

    assert am.has_fact("state_transition")
    assert am.get_fact("state_transition") == (observation,)

    fact = type("_Fact", (), {"kind": "state_transition"})()
    am.put_fact("state_transition", fact)

    assert am.get_fact("state_transition") == (fact, observation)


def test_evidence_store_reads_published_and_live_contract_evidence_tokens():
    observation = type(
        "_Obs",
        (),
        {
            "payload": contract_evidence_payload(
                "dispatcher_predicates",
                "branch_targets",
            ),
            "evidence": ("mov #1, %var_10.4",),
        },
    )()
    am = AnalysisManager(
        graph="G0",
        input_facts=type("_Facts", (), {"active_observations": (observation,)})(),
    )

    assert am.has_evidence("dispatcher_predicates")
    assert am.get_evidence("dispatcher_predicates") == (observation,)

    marker = object()
    am.put_evidence("dispatcher_predicates", marker)

    assert am.get_evidence("dispatcher_predicates") == (marker, observation)


def test_evidence_store_does_not_treat_raw_observation_evidence_as_contract_token():
    observation = type(
        "_Obs",
        (),
        {"evidence": ("dispatcher_predicates", "mov #1, %var_10.4")},
    )()
    am = AnalysisManager(
        graph="G0",
        input_facts=type("_Facts", (), {"active_observations": (observation,)})(),
    )

    assert not am.has_evidence("dispatcher_predicates")
    assert am.get_evidence("dispatcher_predicates") is None


def test_evidence_store_reads_state_write_contract_token_from_live_observation():
    observation = type(
        "_Obs",
        (),
        {
            "kind": "StateWriteAnchorFact",
            "payload": {
                "state_var_stkoff": 0x10,
                **contract_evidence_payload("state_variable_writes"),
            },
            "evidence": ("state_variable_writes", "mov #1, %var_10.4"),
        },
    )()
    am = AnalysisManager(
        graph="G0",
        input_facts=type("_Facts", (), {"active_observations": (observation,)})(),
    )

    assert am.has_evidence("state_variable_writes")
    assert am.get_evidence("state_variable_writes") == (observation,)
    assert not am.has_evidence("dispatcher_predicates")


def test_contract_invalidation_keeps_analysis_and_fact_validity_separate():
    am = AnalysisManager(graph="G0")
    am.put_analysis("dominators", "D")
    am.put_fact("state_transition", object())

    am.invalidate_contract(
        PassContract(invalidates=PassInvalidates(facts=frozenset({"state_transition"})))
    )

    assert am.has_analysis("dominators")
    assert not am.has_fact("state_transition")


def test_contract_invalidation_can_drop_analysis_even_when_cached():
    am = AnalysisManager(graph="G0")
    am.get("dominators", lambda graph: "D")
    am.put_analysis("value_ranges", "V")

    am.invalidate_contract(
        PassContract(
            invalidates=PassInvalidates(
                analyses=frozenset({"dominators", "value_ranges"})
            )
        )
    )

    assert not am.has_analysis("dominators")
    assert not am.has_analysis("value_ranges")
