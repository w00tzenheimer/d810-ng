"""AnalysisManager — LLVM-style lazy caching + PreservedAnalyses invalidation."""
from __future__ import annotations

from d810.analyses.control_flow.dispatcher_discovery_facts import (
    collect_state_dispatcher_discovery_fact_observations,
)
from d810.analyses.control_flow.dispatcher_resolution import (
    StateDispatcherMap,
    StateDispatcherRow,
)
from d810.analyses.control_flow.predecessor_dispatcher_target import (
    resolve_predecessor_dispatcher_target,
)
from d810.analyses.value_flow.contract_evidence import contract_evidence_payload
from d810.capabilities.dispatcher import RouterKind
from d810.passes.analysis_manager import AnalysisManager
from d810.passes.pass_pipeline import (
    PassContract,
    PassInvalidates,
    PassPreserves,
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


def test_available_analyses_includes_cache_published_and_provider_keys_without_compute():
    calls: list[object] = []
    am = AnalysisManager(
        graph="G0",
        providers={"domtree": lambda graph: calls.append(graph) or f"D:{graph}"},
    )
    am.put_analysis("published", object())
    am.get("cached", lambda graph: "C")

    assert am.available_analyses() == ("cached", "domtree", "published")
    assert calls == []


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


def test_fact_store_matches_legacy_and_canonical_contract_names():
    legacy_fact = type("_Fact", (), {"kind": "state_transition"})()
    canonical_fact = type("_Fact", (), {"kind": "recovered.state_transition"})()
    legacy_observation = type("_Obs", (), {"kind": "dispatcher_family"})()
    am = AnalysisManager(
        graph="G0",
        input_facts=type(
            "_Facts", (), {"active_observations": (legacy_observation,)}
        )(),
    )

    am.put_fact("state_transition", legacy_fact)
    am.put_fact("recovered.state_transition", canonical_fact)

    assert set(am.get_fact("recovered.state_transition")) == {
        canonical_fact,
        legacy_fact,
    }
    assert set(am.get_fact("state_transition")) == {
        canonical_fact,
        legacy_fact,
    }
    assert am.has_fact("role.dispatcher")
    assert am.get_fact("role.dispatcher") == (legacy_observation,)


def test_available_facts_respects_published_and_visible_live_observation_names():
    raw = type("_Obs", (), {"kind": "raw_instruction_addresses"})()
    stale = type("_Obs", (), {"kind": "stale_cfg_shape"})()
    am = AnalysisManager(
        graph="G0",
        input_facts=type("_Facts", (), {"active_observations": (raw, stale)})(),
    )
    am.put_fact("state_transition", object())

    assert am.available_facts() == (
        "raw_instruction_addresses",
        "stale_cfg_shape",
        "state_transition",
    )

    am.invalidate_contract(
        PassContract(
            preserves=PassPreserves(facts=frozenset({"raw_instruction_addresses"}))
        )
    )

    assert am.available_facts() == ("raw_instruction_addresses",)


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


def test_evidence_store_matches_legacy_and_canonical_contract_names():
    observation = type(
        "_Obs",
        (),
        {"payload": contract_evidence_payload("branch_targets")},
    )()
    am = AnalysisManager(
        graph="G0",
        input_facts=type("_Facts", (), {"active_observations": (observation,)})(),
    )
    marker = object()

    am.put_evidence("state_variable_writes", marker)

    assert am.get_evidence("ir.branch_target") == (observation,)
    assert am.get_evidence("ir.state_variable_write") == (marker,)
    assert am.get_evidence("state_variable_writes") == (marker,)


def test_available_evidence_respects_published_and_visible_live_tokens():
    observation = type(
        "_Obs",
        (),
        {
            "payload": contract_evidence_payload(
                "branch_targets",
                "dispatcher_predicates",
            ),
            "evidence": ("raw provenance only",),
        },
    )()
    am = AnalysisManager(
        graph="G0",
        input_facts=type("_Facts", (), {"active_observations": (observation,)})(),
    )
    am.put_evidence("state_variable_writes", object())

    assert am.available_evidence() == (
        "branch_targets",
        "dispatcher_predicates",
        "state_variable_writes",
    )

    am.invalidate_to("G1", PreservedAnalyses.all())

    assert am.available_evidence() == ()


def test_put_observation_evidence_indexes_canonical_payload_tokens():
    observation = type(
        "_Obs",
        (),
        {
            "payload": contract_evidence_payload(
                "dispatcher_predicates",
                "branch_targets",
            ),
            "evidence": ("raw provenance only",),
        },
    )()
    am = AnalysisManager(graph="G0")

    am.put_observation_evidence(observation)

    assert am.get_evidence("dispatcher_predicates") == (observation,)
    assert am.get_evidence("branch_targets") == (observation,)


def test_put_observation_evidence_ignores_raw_diagnostic_evidence():
    observation = type(
        "_Obs",
        (),
        {"evidence": ("dispatcher_predicates", "branch_targets")},
    )()
    am = AnalysisManager(graph="G0")

    am.put_observation_evidence(observation)

    assert not am.has_evidence("dispatcher_predicates")
    assert not am.has_evidence("branch_targets")


def test_evidence_store_reads_dispatcher_projection_contract_tokens():
    dispatch_map = StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=0x10,
                target_block=5,
                dispatcher_block=2,
                compare_block=2,
                branch_kind="switch_case",
                router_kind=RouterKind.TABLE,
            ),
        ),
        dispatcher_entry_block=2,
        dispatcher_blocks=frozenset({2}),
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        router_kind=RouterKind.TABLE,
    )
    predecessor_fact = resolve_predecessor_dispatcher_target(
        predecessor_block_serial=9,
        dispatcher_entry_serial=2,
        state_const=0x10,
        state_dispatcher_map=dispatch_map,
    )
    assert predecessor_fact is not None
    observations = collect_state_dispatcher_discovery_fact_observations(
        state_dispatcher_map=dispatch_map,
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
        predecessor_target_facts=(predecessor_fact,),
    )
    predecessor_observation = next(
        observation
        for observation in observations
        if observation.kind == "predecessor_dispatcher_target"
    )
    am = AnalysisManager(
        graph="G0",
        input_facts=type("_Facts", (), {"active_observations": observations})(),
    )

    assert am.has_evidence("branch_targets")
    assert am.has_evidence("dispatcher_predicates")
    assert predecessor_observation in am.get_evidence("branch_targets")
    assert predecessor_observation in am.get_evidence("dispatcher_predicates")


def test_put_observation_evidence_ignores_tokenless_dispatcher_gap_rows():
    observations = collect_state_dispatcher_discovery_fact_observations(
        state_dispatcher_map=None,
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
    )
    am = AnalysisManager(graph="G0")

    for observation in observations:
        am.put_observation_evidence(observation)

    assert not am.has_evidence("branch_targets")
    assert not am.has_evidence("dispatcher_predicates")


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


def test_invalidate_to_clears_published_evidence_for_new_epoch():
    am = AnalysisManager(graph="G0")
    am.put_evidence("branch_targets", object())

    assert am.has_evidence("branch_targets")

    am.invalidate_to("G1", PreservedAnalyses.all())

    assert not am.has_evidence("branch_targets")


def test_invalidate_to_hides_live_observation_evidence_until_fresh_input_facts():
    stale_observation = type(
        "_Obs",
        (),
        {"payload": contract_evidence_payload("branch_targets")},
    )()
    fresh_observation = type(
        "_Obs",
        (),
        {"payload": contract_evidence_payload("branch_targets")},
    )()
    am = AnalysisManager(
        graph="G0",
        input_facts=type(
            "_Facts", (), {"active_observations": (stale_observation,)}
        )(),
    )

    assert am.get_evidence("branch_targets") == (stale_observation,)

    am.invalidate_to("G1", PreservedAnalyses.all())

    assert not am.has_evidence("branch_targets")

    am.set_input_facts(
        type("_Facts", (), {"active_observations": (fresh_observation,)})()
    )

    assert am.get_evidence("branch_targets") == (fresh_observation,)


def test_put_evidence_after_epoch_invalidation_is_visible_without_stale_observations():
    stale_observation = type(
        "_Obs",
        (),
        {"payload": contract_evidence_payload("branch_targets")},
    )()
    am = AnalysisManager(
        graph="G0",
        input_facts=type(
            "_Facts", (), {"active_observations": (stale_observation,)}
        )(),
    )

    am.invalidate_to("G1", PreservedAnalyses.none())
    new_marker = object()
    am.put_evidence("branch_targets", new_marker)

    assert am.get_evidence("branch_targets") == (new_marker,)


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


def test_contract_fact_preservation_prunes_unpreserved_published_facts():
    am = AnalysisManager(graph="G0")
    raw = object()
    stale = object()
    am.put_fact("raw_instruction_addresses", raw)
    am.put_fact("stale_cfg_shape", stale)

    am.invalidate_contract(
        PassContract(
            preserves=PassPreserves(facts=frozenset({"raw_instruction_addresses"}))
        )
    )

    assert am.get_fact("raw_instruction_addresses") == (raw,)
    assert not am.has_fact("stale_cfg_shape")


def test_contract_fact_preservation_and_invalidation_match_aliases():
    am = AnalysisManager(graph="G0")
    edge = object()
    stale = object()
    am.put_fact("recovered_cfg_edge", edge)
    am.put_fact("stale_cfg_shape", stale)

    am.invalidate_contract(
        PassContract(
            preserves=PassPreserves(
                facts=frozenset({"recovered.cfg_edge", "ir.cfg_shape.stale"})
            ),
            invalidates=PassInvalidates(facts=frozenset({"ir.cfg_shape.stale"})),
        )
    )

    assert am.get_fact("recovered.cfg_edge") == (edge,)
    assert am.get_fact("recovered_cfg_edge") == (edge,)
    assert not am.has_fact("ir.cfg_shape.stale")
    assert not am.has_fact("stale_cfg_shape")


def test_contract_fact_invalidation_overrides_fact_preservation():
    am = AnalysisManager(graph="G0")
    am.put_fact("raw_instruction_addresses", object())
    am.put_fact("stale_cfg_shape", object())

    am.invalidate_contract(
        PassContract(
            preserves=PassPreserves(
                facts=frozenset({"raw_instruction_addresses", "stale_cfg_shape"})
            ),
            invalidates=PassInvalidates(facts=frozenset({"stale_cfg_shape"})),
        )
    )

    assert am.has_fact("raw_instruction_addresses")
    assert not am.has_fact("stale_cfg_shape")


def test_empty_contract_fact_preservation_keeps_legacy_fact_behavior():
    am = AnalysisManager(graph="G0")
    am.put_fact("raw_instruction_addresses", object())
    am.put_fact("stale_cfg_shape", object())

    am.invalidate_contract(PassContract())

    assert am.has_fact("raw_instruction_addresses")
    assert am.has_fact("stale_cfg_shape")


def test_contract_fact_invalidation_hides_matching_live_observation_fact():
    observation = type("_Obs", (), {"kind": "stale_cfg_shape"})()
    am = AnalysisManager(
        graph="G0",
        input_facts=type("_Facts", (), {"active_observations": (observation,)})(),
    )

    assert am.has_fact("stale_cfg_shape")

    am.invalidate_contract(
        PassContract(invalidates=PassInvalidates(facts=frozenset({"stale_cfg_shape"})))
    )

    assert not am.has_fact("stale_cfg_shape")


def test_contract_fact_preservation_hides_unpreserved_live_observation_fact():
    raw = type("_Obs", (), {"kind": "raw_instruction_addresses"})()
    stale = type("_Obs", (), {"kind": "stale_cfg_shape"})()
    am = AnalysisManager(
        graph="G0",
        input_facts=type("_Facts", (), {"active_observations": (raw, stale)})(),
    )

    am.invalidate_contract(
        PassContract(
            preserves=PassPreserves(facts=frozenset({"raw_instruction_addresses"}))
        )
    )

    assert am.has_fact("raw_instruction_addresses")
    assert not am.has_fact("stale_cfg_shape")


def test_empty_contract_fact_preservation_keeps_legacy_live_observation_behavior():
    observation = type("_Obs", (), {"kind": "stale_cfg_shape"})()
    am = AnalysisManager(
        graph="G0",
        input_facts=type("_Facts", (), {"active_observations": (observation,)})(),
    )

    am.invalidate_contract(PassContract())

    assert am.has_fact("stale_cfg_shape")


def test_new_published_fact_visible_after_live_observation_masking():
    stale_observation = type("_Obs", (), {"kind": "stale_cfg_shape"})()
    am = AnalysisManager(
        graph="G0",
        input_facts=type(
            "_Facts", (), {"active_observations": (stale_observation,)}
        )(),
    )

    am.invalidate_contract(
        PassContract(invalidates=PassInvalidates(facts=frozenset({"stale_cfg_shape"})))
    )
    new_fact = type("_Fact", (), {"kind": "stale_cfg_shape"})()
    am.put_fact("stale_cfg_shape", new_fact)

    assert am.get_fact("stale_cfg_shape") == (new_fact,)
