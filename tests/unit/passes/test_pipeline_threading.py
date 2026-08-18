"""unflatten dependency threading: pass #1's StateDispatcherMap reaches pass #2 via AnalysisManager.

The LLVM ``AnalysisManager.getResult`` edge — RecoverDispatcher publishes its map; RecoverStateTransitions
pulls it and resolves transitions through it. Without the manager edge, #2 has no map (unresolved).
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from d810.analyses.value_flow.contract_evidence import contract_evidence_payload
from d810.analyses.value_flow.observation import FactObservation
from d810.analyses.value_flow import observation as observation_module
from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidence,
    SemanticRouteDestination,
    SemanticRouteProof,
    SemanticRouteProofKind,
    SemanticRouteShape,
    SemanticStateWriteProof,
)
from d810.capabilities.resolver import CapabilitySet
from d810.capabilities.semantic_routes import CanonicalSemanticEvidenceCapability
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.ir.semantics import PredicateKind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.passes.analysis_manager import AnalysisManager
from d810.passes.pass_pipeline import FunctionPipelineContext
from d810.passes.driver import PassContractError, run_pipeline
from d810.families.state_machine_cff.pipeline import standard_state_machine_passes
from d810.ir.maturity import IRMaturity
from d810.passes.unflatten.state_machine import (
    CleanupResidualDispatcher,
    LowerStateMachine,
    PlanSemanticRegions,
    RecoverDispatcher,
    RecoverStateTransitions,
    _adopt_range_evidence_stack_identity,
    _effective_state_identity,
    _publish_observation_evidence,
    _recover_folded_constant_equality_dag,
)
from d810.passes.state_machine_spine import LOWER_ANALYSES
from d810.analyses.control_flow.dispatcher_recovery import DispatcherRecovery
from d810.analyses.control_flow.dispatcher_resolution import (
    DispatcherCandidateIdentity,
    StateDispatcherMap,
    StateDispatcherRow,
)
from d810.analyses.control_flow.condition_chain_model import (
    ConditionChainAnalysisResult,
)
from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow
from d810.analyses.control_flow.predecessor_dispatcher_target import (
    CONDITION_CHAIN_INTERVAL_ROUTE_FACT_TYPE,
    project_condition_chain_interval_route_observations,
)
from d810.analyses.control_flow.semantic_transition import StateTransitionResolution
from d810.analyses.control_flow.predecessor_dispatcher_target import (
    PREDECESSOR_DISPATCHER_TARGET_FACTS_ANALYSIS,
    PredecessorDispatcherTargetFact,
)
from d810.analyses.control_flow.dispatcher_discovery_facts import (
    predecessor_dispatcher_target_observation,
)
from d810.capabilities.dispatcher import RouterKind
from d810.passes.unflatten import state_machine as state_machine_module
from tests.native_preanalysis import make_native_key
from tests.typed_patch_authority import block_refs_by_serial

C1 = 0x10000001
STATE_OFF = 0x3C


def test_observation_publication_canonicalizes_each_immutable_payload_once(
    monkeypatch,
):
    """One publication must not repeatedly serialize earlier immutable rows."""
    observations = tuple(
        FactObservation(
            fact_id=f"fact-{index}",
            kind="StateTransitionAnchorFact",
            semantic_key=f"state-{index}",
            maturity="MMAT_GLBOPT1",
            phase="recover_state_transitions",
            confidence=1.0,
            payload={
                "source_block_serial": index,
                "successor_block_serial": index + 1,
            },
        )
        for index in range(4)
    )
    payload_index_by_identity = {
        id(observation.payload): index
        for index, observation in enumerate(observations)
    }
    canonicalizations = [0, 0, 0, 0]
    real_canonical_json = observation_module.canonical_json

    def counted_canonical_json(value):
        payload_index = payload_index_by_identity.get(id(value))
        if payload_index is not None:
            canonicalizations[payload_index] += 1
        return real_canonical_json(value)

    monkeypatch.setattr(
        observation_module,
        "canonical_json",
        counted_canonical_json,
    )
    manager = AnalysisManager(graph="G0")

    _publish_observation_evidence(
        SimpleNamespace(facts=manager),
        observations,
    )

    assert manager.session_observations == observations
    assert canonicalizations == [1, 1, 1, 1]


def test_observation_publication_preserves_per_row_fallback_order():
    calls = []

    class _FallbackFacts:
        def put_observation_evidence(self, observation):
            calls.append(observation)

    observations = (object(), object(), object())

    _publish_observation_evidence(
        SimpleNamespace(facts=_FallbackFacts()),
        observations,
    )

    assert calls == list(observations)


def test_observation_publication_propagates_batch_provider_error():
    class _FailingFacts:
        def put_observation_evidence_batch(self, _observations):
            raise RuntimeError("provider failed")

    with pytest.raises(RuntimeError, match="provider failed"):
        _publish_observation_evidence(
            SimpleNamespace(facts=_FailingFacts()),
            (object(),),
        )


def test_materialized_resolver_register_replaces_misidentified_stack_alias():
    recovery = DispatcherRecovery(
        state_var_stkoff=112,
        state_var_reg=None,
    )

    assert _effective_state_identity(
        recovery,
        materialized_computed_goto_profile=True,
        materialized_state_var_reg=20,
    ) == (None, 20)


def test_nonmaterialized_profile_keeps_recovered_stack_identity():
    recovery = DispatcherRecovery(
        state_var_stkoff=112,
        state_var_reg=None,
    )

    assert _effective_state_identity(
        recovery,
        materialized_computed_goto_profile=False,
        materialized_state_var_reg=20,
    ) == (112, None)


def test_range_evidence_replaces_spurious_register_selector_with_proven_stack_state():
    """A live range-DAG may prove the stack selector an equality scan missed."""
    dispatch_map = StateDispatcherMap(
        rows=(),
        dispatcher_entry_block=3,
        dispatcher_blocks=frozenset({3}),
        state_var_stkoff=None,
        state_var_lvar_idx=None,
        router_kind=RouterKind.CONDITION_CHAIN,
        state_var_reg=1184,
    )
    recovery = DispatcherRecovery(
        dispatcher_block_serial=3,
        state_var_stkoff=None,
        state_var_reg=1184,
        dispatch_map=dispatch_map,
    )
    range_evidence = SimpleNamespace(
        state_var_stkoff=52,
        initial_state=0x47EAC929,
        decision_dag=SimpleNamespace(nodes={3: object()}),
    )

    updated = _adopt_range_evidence_stack_identity(recovery, range_evidence)

    assert updated.state_var_stkoff == 52
    assert updated.state_var_reg is None
    assert updated.dispatch_map is not None
    assert updated.dispatch_map.state_var_stkoff == 52
    assert updated.dispatch_map.state_var_reg is None
    assert updated.dispatch_map.initial_state == 0x47EAC929


def _ne(const, target):
    left = MopSnapshot(kind=OperandKind.STACK, stkoff=STATE_OFF, size=4)
    r = MopSnapshot(kind=OperandKind.NUMBER, value=const, size=4)
    d = MopSnapshot(kind=OperandKind.BLOCK, block_ref=target)
    return InsnSnapshot(
        opcode=1,
        ea=0x1000,
        operands=(left, r, d),
        l=left,
        r=r,
        d=d,
        kind=InsnKind.EQUALITY_JUMP,
        branch_predicate=PredicateKind.NE,
        is_conditional_jump=True,
    )


def _folded_eq(left_value, right_value, target, *, predicate=PredicateKind.EQ):
    left = MopSnapshot(kind=OperandKind.NUMBER, value=left_value, size=4)
    right = MopSnapshot(kind=OperandKind.NUMBER, value=right_value, size=4)
    dest = MopSnapshot(kind=OperandKind.BLOCK, block_ref=target)
    return InsnSnapshot(
        opcode=1,
        ea=0x1000,
        operands=(left, right, dest),
        l=left,
        r=right,
        d=dest,
        kind=InsnKind.EQUALITY_JUMP,
        branch_predicate=predicate,
        is_conditional_jump=True,
    )


def test_folded_constant_equality_dag_recovers_exact_approov_routes():
    initial = 0xF6A1F
    graph = FlowGraph(
        blocks={
            3: _blk(3, (4, 15), (), _folded_eq(initial, 0xF6A25, 15)),
            4: _blk(
                4,
                (5, 8),
                (3,),
                _folded_eq(initial, 0xF6A1E, 8, predicate=PredicateKind.NE),
            ),
            5: _blk(5, (), (4,)),
            8: _blk(
                8,
                (9, 12),
                (4,),
                _folded_eq(initial, initial, 12, predicate=PredicateKind.NE),
            ),
            9: _blk(9, (), (8,)),
            12: _blk(12, (), (8,)),
            15: _blk(15, (), (3,)),
        },
        entry_serial=3,
        func_ea=0x1800019A0,
    )

    dag = _recover_folded_constant_equality_dag(
        graph,
        root_serial=3,
        initial_state=initial,
        anchored_states=frozenset({0xF6A1E, initial, 0xF6A20, 0xF6A25}),
    )

    assert dag is not None
    assert dag.route(0xF6A1E) == 5
    assert dag.route(initial) == 9
    assert dag.route(0xF6A20) == 12
    assert dag.route(0xF6A25) == 15


@pytest.mark.parametrize("mutation", ["nonreciprocal", "unknown_constant", "effectful"])
def test_folded_constant_equality_dag_rejects_malformed_observed_chain(mutation):
    initial = 0xF6A1F
    tail = _folded_eq(initial, 0xF6A1E, 5, predicate=PredicateKind.NE)
    root = _blk(3, (4, 5), (), tail)
    handler = _blk(4, (), (3,))
    target = _blk(5, (), (() if mutation == "nonreciprocal" else (3,)))
    if mutation == "unknown_constant":
        root = _blk(
            3,
            (4, 5),
            (),
            _folded_eq(initial, 0xDEADBEEF, 5, predicate=PredicateKind.NE),
        )
    elif mutation == "effectful":
        root = replace(root, insn_snapshots=(InsnSnapshot(9, 0x9999, ()), tail))
    graph = FlowGraph(
        blocks={3: root, 4: handler, 5: target},
        entry_serial=3,
        func_ea=0x1800019A0,
    )

    assert (
        _recover_folded_constant_equality_dag(
            graph,
            root_serial=3,
            initial_state=initial,
            anchored_states=frozenset({0xF6A1E, initial}),
        )
        is None
    )


def _blk(serial, succs, preds, tail=None):
    return BlockSnapshot(
        serial=serial,
        block_type=1,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x1000 + serial,
        insn_snapshots=(tail,) if tail else (),
        tail_opcode=tail.opcode if tail else None,
    )


def _chain_graph():
    # 0: jnz state,C1,2 ; state==C1 -> fall-through handler 1
    return FlowGraph(
        blocks={
            0: _blk(0, (1, 2), (), _ne(C1, 2)),
            1: _blk(1, (), (0,)),
            2: _blk(2, (), (0,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )


def _obs():
    return SimpleNamespace(
        kind="StateTransitionAnchorFact",
        fact_id="f1",
        maturity="GLBOPT1",
        phase="preanalysis",
        confidence=1.0,
        evidence=(),
        source_block=0,
        source_ea=0x1000,
        payload={
            "source_block_serial": 0,
            "source_state_const": C1,
            "successor_kind": "branch",
        },
    )


def _state_write_obs():
    return SimpleNamespace(
        kind="StateWriteAnchorFact",
        fact_id="state-write:1",
        maturity="GLBOPT1",
        phase="preanalysis",
        confidence=1.0,
        evidence=("mov #1, %var_3c.4",),
        source_block=1,
        source_ea=0x1010,
        payload={
            "state_var_stkoff": STATE_OFF,
            "state_const": C1,
            **contract_evidence_payload("state_variable_writes"),
        },
    )


def _input_facts():
    return SimpleNamespace(active_observations=(_obs(), _state_write_obs()))


def _ctx(graph, facts, capabilities=None):
    return FunctionPipelineContext(
        source=None,
        graph=graph,
        maturity=None,
        project_config=None,
        facts=facts,
        capabilities=capabilities or CapabilitySet(),
    )


def _install_current_identity_index(analyses: AnalysisManager) -> None:
    source_refs = block_refs_by_serial(*analyses.graph.blocks)
    analyses.put_analysis(
        "current_block_identity_index",
        SimpleNamespace(
            native_key=make_native_key(function_rva=0x1000),
            snapshot_id="pipeline-threading-snapshot",
            generation=0,
            maturity=4,
            plan_refs_by_serial=lambda: source_refs,
        ),
    )


class _Src:
    flow_graph = _chain_graph()
    func_ea = 0x1000
    live_source = None


class _Backend:
    def capabilities(self):
        return frozenset({"live_mba"})

    def apply(self, plan, live_source, safety_policy):
        return _chain_graph()


class _StandardFamily:
    name = "standard"

    def detect(self, graph, capabilities, context=None):
        return object()

    def pipeline_for(self, match, context):
        return standard_state_machine_passes()


class _TransitionOnlyFamily:
    name = "transition-only"

    def detect(self, graph, capabilities, context=None):
        return object()

    def pipeline_for(self, match, context):
        return (standard_state_machine_passes()[1],)


class _RegionOnlyFamily:
    name = "region-only"

    def detect(self, graph, capabilities, context=None):
        return object()

    def pipeline_for(self, match, context):
        return (standard_state_machine_passes()[2],)


def test_map_threads_from_pass1_to_pass2_and_resolves():
    am = AnalysisManager(_chain_graph(), input_facts=_input_facts())
    ctx = _ctx(am.graph, am.view())
    RecoverDispatcher().run(ctx)  # publishes the dispatcher map
    result = RecoverStateTransitions().run(ctx)  # pulls it, resolves through it
    resolutions = result.analysis_outputs["recover_state_transitions"]
    assert len(resolutions) == 1
    assert (
        resolutions[0].resolved_next_block_serial == 1
    )  # C1 -> handler 1 via #1's map
    assert resolutions[0].resolution_reason == "resolved_exact_state"


def test_recover_dispatcher_builds_exact_map_from_materialized_identities():
    graph = FlowGraph(
        blocks={
            0: _blk(0, (1,), ()),
            1: _blk(1, (), (0,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    am = AnalysisManager(graph)
    am.put_analysis("materialized_computed_goto_profile", True)
    am.put_analysis("materialized_state_var_reg", 28)
    am.put_analysis("materialized_handler_by_state", {C1: 1})
    am.put_analysis("materialized_dispatcher_entry_serial", 0)
    am.put_analysis("materialized_dispatcher_router_serials", frozenset({0}))
    ctx = _ctx(graph, am.view())

    result = RecoverDispatcher().run(ctx)
    recovery = result.analysis_outputs["recover_dispatcher"]

    assert recovery.dispatcher_block_serial == 0
    assert recovery.state_var_stkoff is None
    assert recovery.state_var_reg == 28
    assert recovery.dispatch_map is not None
    assert recovery.dispatch_map.state_to_handler() == {C1: 1}


def test_recover_dispatcher_consumes_runtime_candidate_exclusions(monkeypatch):
    identity = DispatcherCandidateIdentity(
        resolver_name="equality_chain",
        router_kind=RouterKind.EQUALITY_CHAIN,
        table_provenance=None,
        dispatcher_entry_ea=0x1000,
        state_location_kind="stack",
        state_location_value=STATE_OFF,
    )
    graph = _chain_graph()
    am = AnalysisManager(graph)
    am.put_analysis("dispatcher_candidate_exclusions", frozenset({identity}))
    seen = {}

    def _capture(graph, facts, **kwargs):
        seen["excluded"] = kwargs.get("excluded_identities")
        return DispatcherRecovery()

    monkeypatch.setattr(state_machine_module, "recover_dispatcher", _capture)

    RecoverDispatcher().run(_ctx(graph, am.view()))

    assert seen["excluded"] == frozenset({identity})


def test_recover_dispatcher_publishes_branch_target_evidence():
    am = AnalysisManager(_chain_graph(), input_facts=_input_facts())

    assert not am.has_evidence("branch_targets")
    assert not am.has_evidence("dispatcher_predicates")


def test_recover_dispatcher_publishes_exact_rows_for_snapshot_diagnostics(monkeypatch):
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        state_machine_module,
        "observe_state_dispatcher_rows",
        lambda **kwargs: calls.append(kwargs),
    )
    am = AnalysisManager(_chain_graph(), input_facts=_input_facts())
    ctx = _ctx(am.graph, am.view())

    RecoverDispatcher().run(ctx)

    assert len(calls) == 1
    assert calls[0]["func_ea"] == 0x1000
    assert calls[0]["dispatcher_entry_block"] == 0
    assert len(calls[0]["rows"]) == 1

    RecoverDispatcher().run(ctx)

    assert am.has_evidence("branch_targets")
    assert not am.has_evidence("dispatcher_predicates")


def test_recover_dispatcher_retains_native_interval_route_observation(monkeypatch):
    state = 0x16AA65E9
    entry_ea = 0x180014E20
    target_ea = 0x180030009
    graph = FlowGraph(
        blocks={
            3: replace(
                _blk(3, (), ()),
                native_start_ea=entry_ea,
            ),
            9: replace(
                _blk(9, (), ()),
                native_start_ea=target_ea,
            ),
        },
        entry_serial=3,
        func_ea=0x1000,
    )
    dispatch_map = StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=state,
                target_block=9,
                dispatcher_block=3,
                compare_block=3,
                branch_kind="dispatcher_self_loop",
                router_kind=RouterKind.CONDITION_CHAIN,
            ),
        ),
        dispatcher_entry_block=3,
        dispatcher_blocks=frozenset({3}),
        state_var_stkoff=52,
        state_var_lvar_idx=None,
        router_kind=RouterKind.CONDITION_CHAIN,
    )
    range_evidence = ConditionChainAnalysisResult(
        dispatcher=IntervalDispatcher(
            [IntervalRow(lo=state, hi=state + 1, target=9)]
        )
    )
    recovery = DispatcherRecovery(
        dispatcher_block_serial=3,
        state_var_stkoff=52,
        state_var_reg=None,
        dispatch_map=dispatch_map,
    )
    monkeypatch.setattr(
        state_machine_module,
        "recover_dispatcher",
        lambda *args, **kwargs: recovery,
    )
    monkeypatch.setattr(
        state_machine_module,
        "observe_state_dispatcher_rows",
        lambda **kwargs: None,
    )
    am = AnalysisManager(graph)
    am.put_analysis("range_evidence", range_evidence)

    RecoverDispatcher().run(_ctx(graph, am))

    retained = tuple(
        observation
        for observation in am.retained_observations
        if observation.kind == CONDITION_CHAIN_INTERVAL_ROUTE_FACT_TYPE
    )
    assert len(retained) == 1
    projected = project_condition_chain_interval_route_observations(retained)
    assert len(projected) == 1
    assert projected[0].target_native_ea == target_ea


def test_recover_dispatcher_uses_range_snapshot_topology_for_interval_leaf(
    monkeypatch,
):
    """A stale dispatcher map must not classify the range producer's leaf as topology."""
    state = 0x16AA65E9
    entry_ea = 0x180014E20
    target_ea = 0x180030009
    graph = FlowGraph(
        blocks={
            3: replace(_blk(3, (), ()), native_start_ea=entry_ea),
            9: replace(_blk(9, (), ()), native_start_ea=target_ea),
        },
        entry_serial=3,
        func_ea=0x1000,
    )
    # This map is from a different maturity and incorrectly labels the interval
    # leaf as a dispatcher block.  The range/DAG producer has only comparison
    # node 4; target 9 is a handler because it is absent from that node set.
    dispatch_map = StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=state,
                target_block=9,
                dispatcher_block=3,
                compare_block=9,
                branch_kind="dispatcher_self_loop",
                router_kind=RouterKind.CONDITION_CHAIN,
            ),
        ),
        dispatcher_entry_block=3,
        dispatcher_blocks=frozenset({3, 9, 12}),
        state_var_stkoff=52,
        state_var_lvar_idx=None,
        router_kind=RouterKind.CONDITION_CHAIN,
    )
    range_evidence = ConditionChainAnalysisResult(
        condition_chain_blocks={4},
        decision_dag=SimpleNamespace(root=4, nodes={4: object()}),
        dispatcher=IntervalDispatcher(
            [IntervalRow(lo=state, hi=state + 1, target=9)]
        ),
    )
    recovery = DispatcherRecovery(
        dispatcher_block_serial=3,
        state_var_stkoff=52,
        state_var_reg=None,
        dispatch_map=dispatch_map,
    )
    monkeypatch.setattr(
        state_machine_module,
        "recover_dispatcher",
        lambda *args, **kwargs: recovery,
    )
    monkeypatch.setattr(
        state_machine_module,
        "observe_state_dispatcher_rows",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        state_machine_module, "_build_comparison_model", lambda *args: None
    )
    am = AnalysisManager(graph)
    am.put_analysis("range_evidence", range_evidence)

    RecoverDispatcher().run(_ctx(graph, am))

    retained = tuple(
        observation
        for observation in am.retained_observations
        if observation.kind == CONDITION_CHAIN_INTERVAL_ROUTE_FACT_TYPE
    )
    projected = project_condition_chain_interval_route_observations(retained)
    assert len(projected) == 1
    assert projected[0].target_block_serial == 9
    assert projected[0].target_native_ea == target_ea


def test_recover_state_transitions_publishes_dispatcher_predicate_evidence():
    am = AnalysisManager(_chain_graph(), input_facts=_input_facts())
    ctx = _ctx(am.graph, am.view())

    RecoverDispatcher().run(ctx)
    assert not am.has_evidence("dispatcher_predicates")

    RecoverStateTransitions().run(ctx)

    assert am.has_evidence("dispatcher_predicates")


def test_full_five_pass_chain_threads_and_completes():
    am = AnalysisManager(_chain_graph(), input_facts=_input_facts())
    _install_current_identity_index(am)
    ctx = _ctx(am.graph, am.view())
    passes = [
        RecoverDispatcher(),
        RecoverStateTransitions(),
        PlanSemanticRegions(),
        LowerStateMachine(),
        CleanupResidualDispatcher(),
    ]
    results = [p.run(ctx) for p in passes]
    # every analysis dependency was published into the manager (the getResult edges)
    assert am.get_analysis("recover_dispatcher").dispatch_map is not None
    assert am.get_analysis("transition_result") is not None
    assert isinstance(
        am.get_analysis(PREDECESSOR_DISPATCHER_TARGET_FACTS_ANALYSIS), tuple
    )
    assert am.get_analysis("plan_semantic_regions") is not None
    # synthetic obs carries no next-state write -> empty transitions -> heavy DAG/lower guarded off
    assert results[3].rewrite_plan.steps == ()  # lower_state_machine
    assert results[4].rewrite_plan.steps == ()  # cleanup_residual_dispatcher


def test_lower_state_machine_merges_manager_retained_predecessor_observations(
    monkeypatch,
):
    fact = PredecessorDispatcherTargetFact(
        fact_id=(
            "predecessor_dispatcher_target:dispatcher=0:pred=0:"
            "state=0x0000000010000001:target=1:"
            "resolver=state_dispatcher_map_exact_row"
        ),
        predecessor_block_serial=0,
        dispatcher_entry_serial=0,
        state_const=C1,
        target_block_serial=1,
        resolver_kind="state_dispatcher_map_exact_row",
        row_kind="exact",
        source_instruction_ea=0x1000,
        target_native_ea=0x1010,
        state_var_stkoff=STATE_OFF,
    )
    observation = predecessor_dispatcher_target_observation(
        fact,
        maturity="GLBOPT1",
        phase="retained-test",
    )
    captured = []

    def capture(resolutions, **_kwargs):
        captured.extend(resolutions)
        return ()

    monkeypatch.setattr(
        state_machine_module,
        "bind_native_bound_transition_routes_for_current_mba",
        capture,
    )
    am = AnalysisManager(_chain_graph(), input_facts=_input_facts())
    am.put_observation_evidence(observation)
    _install_current_identity_index(am)
    ctx = _ctx(am.graph, am.view())

    RecoverDispatcher().run(ctx)
    RecoverStateTransitions().run(ctx)
    am.put_analysis(PREDECESSOR_DISPATCHER_TARGET_FACTS_ANALYSIS, ())
    PlanSemanticRegions().run(ctx)
    LowerStateMachine().run(ctx)

    assert any(
        getattr(item, "fact_id", None) == fact.fact_id
        for item in captured
    )


def test_lower_state_machine_requires_recovered_transition_analysis():
    assert "recover_state_transitions" in LOWER_ANALYSES.required
    assert PREDECESSOR_DISPATCHER_TARGET_FACTS_ANALYSIS in LOWER_ANALYSES.required


def test_fallback_lowering_requires_recovered_stack_state_identity(monkeypatch):
    calls = []

    def capture(*args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(steps=("redirect",))

    monkeypatch.setattr(state_machine_module, "lower_to_direct_graph", capture)
    common = dict(
        graph=SimpleNamespace(),
        facts=SimpleNamespace(),
        transition_result=SimpleNamespace(),
        dispatch_map=SimpleNamespace(),
        dispatcher_entry_serial=5,
        regions=None,
        use_def_safety=None,
        live_function=None,
    )

    missing = state_machine_module._lower_fallback_to_direct_graph(
        **common,
        state_var_stkoff=None,
    )

    assert missing.steps == ()
    assert calls == []

    present = state_machine_module._lower_fallback_to_direct_graph(
        **common,
        state_var_stkoff=32,
    )

    assert present.steps == ("redirect",)
    assert len(calls) == 1
    assert calls[0][1]["state_var_stkoff"] == 32


def test_exact_state_write_anchors_restore_folded_dispatcher_identity():
    rows = tuple(
        StateDispatcherRow(
            state_const=state,
            target_block=index + 10,
            dispatcher_block=3,
            compare_block=3,
            branch_kind="eq",
            router_kind=RouterKind.CONDITION_CHAIN,
        )
        for index, state in enumerate((0xF6A1E, 0xF6A1F, 0xF6A20))
    )
    recovery = DispatcherRecovery(
        dispatcher_block_serial=3,
        dispatch_map=StateDispatcherMap(
            rows=rows,
            dispatcher_entry_block=3,
            dispatcher_blocks=frozenset({3}),
            state_var_stkoff=None,
            state_var_lvar_idx=None,
            router_kind=RouterKind.CONDITION_CHAIN,
        ),
    )

    def anchor(index: int, state: int, stkoff: int) -> FactObservation:
        return FactObservation(
            fact_id=f"anchor-{index}-{state:x}-{stkoff:x}",
            kind="StateWriteAnchorFact",
            semantic_key=f"anchor-{index}-{state:x}-{stkoff:x}",
            maturity="MMAT_GLBOPT1",
            phase="pre_d810",
            confidence=0.9,
            payload={
                "block_serial": index + 4,
                "instruction_ea": 0x1800019DC + index,
                "state_const_u64": state,
                "state_var_stkoff": stkoff,
                "state_var_reg": None,
                "dest_size": 4,
            },
        )

    restored = state_machine_module._adopt_exact_state_write_anchor_identity(
        recovery,
        SimpleNamespace(
            active_observations=tuple(
                anchor(index, state, 12)
                for index, state in enumerate((0xF6A1E, 0xF6A1F, 0xF6A20))
            )
        ),
    )

    assert restored.state_var_stkoff == 12
    assert restored.state_var_reg is None
    assert restored.dispatch_map.state_var_stkoff == 12


def test_exact_state_write_anchor_identity_rejects_tied_storage_families():
    state = 0x8348BA7AD21C9415
    recovery = DispatcherRecovery(
        dispatcher_block_serial=2,
        dispatch_map=StateDispatcherMap(
            rows=(
                StateDispatcherRow(
                    state_const=state,
                    target_block=4,
                    dispatcher_block=2,
                    compare_block=2,
                    branch_kind="eq",
                    router_kind=RouterKind.CONDITION_CHAIN,
                ),
            ),
            dispatcher_entry_block=2,
            dispatcher_blocks=frozenset({2}),
            state_var_stkoff=None,
            state_var_lvar_idx=None,
            router_kind=RouterKind.CONDITION_CHAIN,
        ),
    )

    observations = tuple(
        FactObservation(
            fact_id=f"anchor-{index}",
            kind="StateWriteAnchorFact",
            semantic_key=f"anchor-{index}",
            maturity="MMAT_GLBOPT1",
            phase="pre_d810",
            confidence=0.9,
            payload={
                "block_serial": index + 1,
                "instruction_ea": 0x18001AA54 + index,
                "state_const_u64": state,
                "state_var_stkoff": stkoff,
                "state_var_reg": None,
                "dest_size": 8,
            },
        )
        for index, stkoff in enumerate((32, 40))
    )

    unchanged = state_machine_module._adopt_exact_state_write_anchor_identity(
        recovery,
        SimpleNamespace(active_observations=observations),
    )

    assert unchanged is recovery


def test_native_bound_adapter_uses_current_native_ea_rebind_only():
    calls = []

    class _Index:
        def rebind_native_ea(self, ea):
            calls.append(int(ea))
            return SimpleNamespace(block=SimpleNamespace(serial=42))

        def rebind_identity(self, _identity):
            raise AssertionError("recorded identity/serial fallback is forbidden")

    resolution = StateTransitionResolution(
        fact_id="transition:native-bound",
        source_block_serial=15,
        source_state_const_hex="0x0000000016AA65E9",
        resolved_next_block_serial=7,
        resolved_next_state_const_hex="0x00000000079323F9",
        resolved_next_state_const_u64=0x079323F9,
        resolution_kind="state_dispatcher_map",
        resolution_reason="resolved_exact_state",
        source_instruction_ea=0x7FF855576BA0,
        state_var_stkoff=STATE_OFF,
    )
    routes = state_machine_module.bind_native_bound_transition_routes_for_current_mba(
        (resolution,),
        current_block_identity_index=_Index(),
        graph=SimpleNamespace(blocks={7: object(), 42: object()}),
        dispatcher=SimpleNamespace(lookup=lambda state: 7),
        dispatcher_region_serials=frozenset({2}),
        state_var_stkoff=STATE_OFF,
        state_var_reg=None,
    )

    assert calls == [0x7FF855576BA0]
    assert len(routes) == 1
    assert routes[0].source_block_serial == 42
    assert routes[0].target_handler_serial == 7
    assert (
        state_machine_module.bind_native_bound_transition_routes_for_current_mba(
            (resolution,),
            current_block_identity_index=None,
            graph=SimpleNamespace(blocks={7: object()}),
            dispatcher=SimpleNamespace(lookup=lambda state: 7),
            dispatcher_region_serials=frozenset({2}),
            state_var_stkoff=STATE_OFF,
            state_var_reg=None,
        )
        == ()
    )


def test_native_bound_adapter_accepts_carrier_drift_with_typed_predecessor_route():
    class _Index:
        def rebind_native_ea(self, ea):
            serial = {
                0x7FF855576BA0: 42,
                0x7FF855576BB1: 7,
            }[int(ea)]
            return SimpleNamespace(block=SimpleNamespace(serial=serial))

    fact = PredecessorDispatcherTargetFact(
        fact_id="predecessor:interval-route",
        predecessor_block_serial=15,
        dispatcher_entry_serial=2,
        state_const=0x16AA65E9,
        # The old target serial is provenance only; the current router is
        # allowed to assign a different serial after the MBA is regenerated.
        target_block_serial=99,
        resolver_kind="interval_dispatcher_row",
        row_kind="interval_range",
        source_instruction_ea=0x7FF855576BA0,
        target_native_ea=0x7FF855576BB1,
        state_var_stkoff=52,
        state_var_reg=8,
    )
    routes = state_machine_module.bind_native_bound_transition_routes_for_current_mba(
        (fact,),
        current_block_identity_index=_Index(),
        graph=SimpleNamespace(blocks={7: object(), 42: object()}),
        dispatcher=SimpleNamespace(lookup=lambda state: 7),
        dispatcher_region_serials=frozenset({2, 3}),
        state_var_stkoff=52,
        state_var_reg=None,
    )

    assert len(routes) == 1
    assert routes[0].source_block_serial == 42
    assert routes[0].state_constant == 0x16AA65E9
    assert routes[0].target_handler_serial == 7


def test_native_bound_adapter_uses_unique_initial_state_carrier_family():
    source_ea = 0x7FF855576BA0
    target_ea = 0x7FF855576BB1

    class _Index:
        def rebind_native_ea(self, ea):
            serial = {source_ea: 42, target_ea: 7}[int(ea)]
            return SimpleNamespace(block=SimpleNamespace(serial=serial))

    def fact(*, fact_id: str, state: int, reg: int):
        return PredecessorDispatcherTargetFact(
            fact_id=fact_id,
            predecessor_block_serial=15,
            dispatcher_entry_serial=2,
            state_const=state,
            target_block_serial=99,
            resolver_kind="interval_dispatcher_row",
            row_kind="interval_range",
            source_instruction_ea=source_ea,
            target_native_ea=target_ea,
            state_var_stkoff=52,
            state_var_reg=reg,
        )

    routes = state_machine_module.bind_native_bound_transition_routes_for_current_mba(
        (
            fact(fact_id="shadow", state=1, reg=0),
            fact(fact_id="dispatcher", state=0x16AA65E9, reg=8),
        ),
        current_block_identity_index=_Index(),
        graph=SimpleNamespace(blocks={7: object(), 42: object()}),
        dispatcher=SimpleNamespace(lookup=lambda _state: 7),
        dispatcher_region_serials=frozenset({2}),
        state_var_stkoff=52,
        state_var_reg=None,
        initial_state=0x16AA65E9,
    )

    assert [(route.fact_id, route.state_constant) for route in routes] == [
        ("dispatcher", 0x16AA65E9)
    ]


def test_native_bound_pipeline_keeps_entry_and_later_routes_with_carrier_drift():
    class _Index:
        def rebind_native_ea(self, ea):
            serial = {
                0x180014E30: 42,
                0x180014E31: 7,
                0x180015115: 43,
                0x180015116: 8,
            }[int(ea)]
            return SimpleNamespace(block=SimpleNamespace(serial=serial))

    entry = PredecessorDispatcherTargetFact(
        fact_id="predecessor:entry-route",
        predecessor_block_serial=15,
        dispatcher_entry_serial=2,
        state_const=0x16AA65E9,
        target_block_serial=99,
        resolver_kind="interval_dispatcher_row",
        row_kind="interval_exact",
        source_instruction_ea=0x180014E30,
        target_native_ea=0x180014E31,
        state_var_stkoff=8,
        state_var_reg=8,
    )
    later = PredecessorDispatcherTargetFact(
        fact_id="predecessor:later-route",
        predecessor_block_serial=16,
        dispatcher_entry_serial=2,
        state_const=0x079323F9,
        target_block_serial=100,
        resolver_kind="interval_dispatcher_row",
        row_kind="interval_exact",
        source_instruction_ea=0x180015115,
        target_native_ea=0x180015116,
        state_var_stkoff=8,
        state_var_reg=8,
    )

    routes = state_machine_module.bind_native_bound_transition_routes_for_current_mba(
        (entry, later),
        current_block_identity_index=_Index(),
        graph=SimpleNamespace(
            blocks={7: object(), 8: object(), 42: object(), 43: object()}
        ),
        dispatcher=SimpleNamespace(
            lookup=lambda state: {0x16AA65E9: 7, 0x079323F9: 8}[int(state)]
        ),
        dispatcher_region_serials=frozenset({2, 3}),
        # The current snapshot carrier moved to stack 52; typed predecessor
        # facts remain valid because native EA + current router are authoritative.
        state_var_stkoff=52,
        state_var_reg=None,
    )

    assert [
        (route.source_block_serial, route.state_constant, route.target_handler_serial)
        for route in routes
    ] == [
        (42, 0x16AA65E9, 7),
        (43, 0x079323F9, 8),
    ]


def test_native_bound_adapter_accepts_target_serial_drift_for_same_native_identity():
    class _Index:
        def rebind_native_ea(self, ea):
            serial = {
                0x7FF855576BA0: 42,
                0x7FF855576BB1: 7,
            }[int(ea)]
            return SimpleNamespace(block=SimpleNamespace(serial=serial))

    fact = PredecessorDispatcherTargetFact(
        fact_id="predecessor:route-a",
        predecessor_block_serial=15,
        dispatcher_entry_serial=2,
        state_const=0x16AA65E9,
        target_block_serial=99,
        resolver_kind="interval_dispatcher_row",
        row_kind="interval_range",
        source_instruction_ea=0x7FF855576BA0,
        target_native_ea=0x7FF855576BB1,
        state_var_stkoff=52,
    )
    conflicting = replace(
        fact,
        fact_id="predecessor:route-b",
        target_block_serial=100,
    )

    routes = state_machine_module.bind_native_bound_transition_routes_for_current_mba(
        (fact, conflicting),
        current_block_identity_index=_Index(),
        graph=SimpleNamespace(blocks={7: object(), 42: object()}),
        dispatcher=SimpleNamespace(lookup=lambda state: 7),
        dispatcher_region_serials=frozenset({2, 3}),
        state_var_stkoff=52,
        state_var_reg=None,
    )

    assert len(routes) == 1
    assert routes[0].target_handler_serial == 7


def test_native_bound_adapter_rejects_conflicting_typed_target_native_identities():
    class _Index:
        def rebind_native_ea(self, ea):
            serial = {
                0x7FF855576BA0: 42,
                0x7FF855576BB1: 7,
                0x7FF855576BB2: 7,
            }[int(ea)]
            return SimpleNamespace(block=SimpleNamespace(serial=serial))

    fact = PredecessorDispatcherTargetFact(
        fact_id="predecessor:route-a",
        predecessor_block_serial=15,
        dispatcher_entry_serial=2,
        state_const=0x16AA65E9,
        target_block_serial=99,
        resolver_kind="interval_dispatcher_row",
        row_kind="interval_range",
        source_instruction_ea=0x7FF855576BA0,
        target_native_ea=0x7FF855576BB1,
        state_var_stkoff=52,
    )
    conflicting = replace(
        fact,
        fact_id="predecessor:route-b",
        target_block_serial=100,
        target_native_ea=0x7FF855576BB2,
    )

    routes = state_machine_module.bind_native_bound_transition_routes_for_current_mba(
        (fact, conflicting),
        current_block_identity_index=_Index(),
        graph=SimpleNamespace(blocks={7: object(), 42: object()}),
        dispatcher=SimpleNamespace(lookup=lambda state: 7),
        dispatcher_region_serials=frozenset({2, 3}),
        state_var_stkoff=52,
        state_var_reg=None,
    )

    assert routes == ()


def _dual_bound_predecessor_fact(
    *, fact_id="predecessor:dual-bound", target_ea=0x7FF855576BB1
):
    return SimpleNamespace(
        fact_id=fact_id,
        predecessor_block_serial=15,
        dispatcher_entry_serial=2,
        state_const=0x16AA65E9,
        target_block_serial=999,
        target_native_ea=target_ea,
        resolver_kind="interval_dispatcher_row",
        row_kind="interval_range",
        source_instruction_ea=0x7FF855576BA0,
        state_var_stkoff=52,
        state_var_reg=None,
    )


def test_native_bound_adapter_rebinds_unique_target_native_ea():
    source_ea = 0x7FF855576BA0
    target_ea = 0x7FF855576BB1
    calls = []

    class _Index:
        def rebind_native_ea(self, ea):
            calls.append(int(ea))
            serial = {source_ea: 42, target_ea: 77}[int(ea)]
            return SimpleNamespace(block=SimpleNamespace(serial=serial))

    routes = state_machine_module.bind_native_bound_transition_routes_for_current_mba(
        (_dual_bound_predecessor_fact(target_ea=target_ea),),
        current_block_identity_index=_Index(),
        graph=SimpleNamespace(blocks={42: object(), 77: object()}),
        dispatcher=SimpleNamespace(lookup=lambda _state: 77),
        dispatcher_region_serials=frozenset({2}),
        state_var_stkoff=52,
        state_var_reg=None,
    )

    assert calls == [source_ea, target_ea]
    assert len(routes) == 1
    assert routes[0].source_block_serial == 42
    assert routes[0].target_handler_serial == 77


def test_native_bound_adapter_rejects_missing_target_native_ea():
    source_ea = 0x7FF855576BA0

    class _Index:
        def rebind_native_ea(self, ea):
            assert int(ea) == source_ea
            return SimpleNamespace(block=SimpleNamespace(serial=42))

    routes = state_machine_module.bind_native_bound_transition_routes_for_current_mba(
        (_dual_bound_predecessor_fact(target_ea=None),),
        current_block_identity_index=_Index(),
        graph=SimpleNamespace(blocks={42: object(), 77: object()}),
        dispatcher=SimpleNamespace(lookup=lambda _state: 77),
        dispatcher_region_serials=frozenset({2}),
        state_var_stkoff=52,
        state_var_reg=None,
    )

    assert routes == ()


@pytest.mark.parametrize("target_rebind", ["missing", "ambiguous"])
def test_native_bound_adapter_rejects_missing_or_ambiguous_target_native_ea(
    target_rebind,
):
    source_ea = 0x7FF855576BA0
    target_ea = 0x7FF855576BB1

    class _Index:
        def rebind_native_ea(self, ea):
            if int(ea) == source_ea:
                return SimpleNamespace(block=SimpleNamespace(serial=42))
            assert int(ea) == target_ea
            return SimpleNamespace(block=None)

    routes = state_machine_module.bind_native_bound_transition_routes_for_current_mba(
        (_dual_bound_predecessor_fact(target_ea=target_ea),),
        current_block_identity_index=_Index(),
        graph=SimpleNamespace(blocks={42: object(), 77: object()}),
        dispatcher=SimpleNamespace(lookup=lambda _state: 77),
        dispatcher_region_serials=frozenset({2}),
        state_var_stkoff=52,
        state_var_reg=None,
    )

    assert routes == ()


def test_native_bound_adapter_rejects_router_conflict_with_dual_target_binding():
    source_ea = 0x7FF855576BA0
    target_ea = 0x7FF855576BB1

    class _Index:
        def rebind_native_ea(self, ea):
            serial = {source_ea: 42, target_ea: 77}[int(ea)]
            return SimpleNamespace(block=SimpleNamespace(serial=serial))

    routes = state_machine_module.bind_native_bound_transition_routes_for_current_mba(
        (_dual_bound_predecessor_fact(target_ea=target_ea),),
        current_block_identity_index=_Index(),
        graph=SimpleNamespace(blocks={42: object(), 77: object(), 78: object()}),
        dispatcher=SimpleNamespace(lookup=lambda _state: 78),
        dispatcher_region_serials=frozenset({2}),
        state_var_stkoff=52,
        state_var_reg=None,
    )

    assert routes == ()


@pytest.mark.parametrize("router_result", [None, 2])
def test_native_bound_adapter_uses_dual_target_when_router_is_incomplete(
    router_result,
):
    source_ea = 0x7FF855576BA0
    target_ea = 0x7FF855576BB1

    class _Index:
        def rebind_native_ea(self, ea):
            serial = {source_ea: 42, target_ea: 77}[int(ea)]
            return SimpleNamespace(block=SimpleNamespace(serial=serial))

    routes = state_machine_module.bind_native_bound_transition_routes_for_current_mba(
        (_dual_bound_predecessor_fact(target_ea=target_ea),),
        current_block_identity_index=_Index(),
        graph=SimpleNamespace(blocks={2: object(), 42: object(), 77: object()}),
        dispatcher=SimpleNamespace(lookup=lambda _state: router_result),
        dispatcher_region_serials=frozenset({2}),
        state_var_stkoff=52,
        state_var_reg=None,
    )

    assert len(routes) == 1
    assert routes[0].target_handler_serial == 77


def test_native_bound_adapter_rejects_conflicting_target_native_identities():
    source_ea = 0x7FF855576BA0
    first_target_ea = 0x7FF855576BB1
    second_target_ea = 0x7FF855576BB2

    class _Index:
        def rebind_native_ea(self, ea):
            serial = {
                source_ea: 42,
                first_target_ea: 77,
                second_target_ea: 78,
            }[int(ea)]
            return SimpleNamespace(block=SimpleNamespace(serial=serial))

    routes = state_machine_module.bind_native_bound_transition_routes_for_current_mba(
        (
            _dual_bound_predecessor_fact(
                fact_id="predecessor:dual-bound-a",
                target_ea=first_target_ea,
            ),
            _dual_bound_predecessor_fact(
                fact_id="predecessor:dual-bound-b",
                target_ea=second_target_ea,
            ),
        ),
        current_block_identity_index=_Index(),
        graph=SimpleNamespace(
            blocks={42: object(), 77: object(), 78: object()}
        ),
        dispatcher=SimpleNamespace(lookup=lambda _state: 77),
        dispatcher_region_serials=frozenset({2}),
        state_var_stkoff=52,
        state_var_reg=None,
    )

    assert routes == ()


def test_run_pipeline_publishes_state_machine_contract_facts():
    am = AnalysisManager(
        _chain_graph(),
        input_facts=_input_facts(),
    )
    _install_current_identity_index(am)

    run_pipeline(
        source=_Src(),
        family=_StandardFamily(),
        backend=_Backend(),
        facts=am,
        project_config=None,
        maturity=IRMaturity.GLOBAL_ANALYZED,
        pipeline_v2_specs=standard_state_machine_passes(),
    )

    assert am.has_fact("dispatcher_family")
    assert am.has_fact("role.dispatcher")
    assert am.has_fact("state_transition")
    assert am.has_fact("recovered.state_transition")
    assert am.has_fact("semantic_region")
    assert am.has_fact("recovered.region")
    assert am.has_fact("recovered_cfg_edge")
    assert am.has_fact("recovered.cfg_edge")
    assert am.get_fact("dispatcher_family")[0].value.dispatch_map is not None
    assert am.get_fact("state_transition")[0].kind == "state_transition"
    assert am.has_evidence("branch_targets")
    assert am.has_evidence("ir.branch_target")


def test_transition_contract_requires_published_branch_target_evidence():
    am = AnalysisManager(
        _chain_graph(),
        input_facts=_input_facts(),
    )
    am.put_analysis("recover_dispatcher", object())

    with pytest.raises(PassContractError, match="ir.branch_target"):
        run_pipeline(
            source=_Src(),
            family=_TransitionOnlyFamily(),
            backend=_Backend(),
            facts=am,
            project_config=None,
            maturity=IRMaturity.GLOBAL_ANALYZED,
            pipeline_v2_specs=(standard_state_machine_passes()[1],),
        )


def test_transition_contract_requires_dispatcher_family_fact_not_just_analysis():
    am = AnalysisManager(
        _chain_graph(),
        input_facts=_input_facts(),
    )
    am.put_analysis("recover_dispatcher", object())
    am.put_evidence("branch_targets", object())

    with pytest.raises(PassContractError, match="role.dispatcher"):
        run_pipeline(
            source=_Src(),
            family=_TransitionOnlyFamily(),
            backend=_Backend(),
            facts=am,
            project_config=None,
            maturity=IRMaturity.GLOBAL_ANALYZED,
            pipeline_v2_specs=(standard_state_machine_passes()[1],),
        )


def test_region_contract_requires_state_transition_fact_not_just_analysis():
    am = AnalysisManager(
        _chain_graph(),
        input_facts=_input_facts(),
    )
    am.put_analysis("recover_dispatcher", object())
    am.put_analysis("transition_result", object())
    am.put_fact("dispatcher_family", object())

    with pytest.raises(PassContractError, match="recovered.state_transition"):
        run_pipeline(
            source=_Src(),
            family=_RegionOnlyFamily(),
            backend=_Backend(),
            facts=am,
            project_config=None,
            maturity=IRMaturity.GLOBAL_ANALYZED,
            pipeline_v2_specs=(standard_state_machine_passes()[2],),
        )


def test_out_of_range_maturity_skips_state_machine_contract_specs():
    am = AnalysisManager(
        _chain_graph(),
        input_facts=_input_facts(),
    )

    run_pipeline(
        source=_Src(),
        family=_StandardFamily(),
        backend=_Backend(),
        facts=am,
        project_config=None,
        maturity=IRMaturity.LOCAL_OPTIMIZED,
        pipeline_v2_specs=standard_state_machine_passes(),
    )

    assert not am.has_fact("dispatcher_family")
    assert not am.has_analysis("recover_dispatcher")


def test_without_manager_edge_pass2_is_unresolved():
    # ctx.facts is a plain view (no get_analysis) -> #2 has no map
    plain = SimpleNamespace(active_observations=(_obs(),))
    result = RecoverStateTransitions().run(_ctx(_chain_graph(), plain))
    resolutions = result.analysis_outputs["recover_state_transitions"]
    assert len(resolutions) == 1
    assert resolutions[0].resolved_next_block_serial is None
    assert resolutions[0].resolution_reason == "no_dispatcher_rows_available"


def test_recover_state_transitions_binds_portable_semantic_route_group() -> None:
    native_key = make_native_key(function_rva=0x1000)

    def identity(ea: int) -> StableBlockIdentity:
        return StableBlockIdentity.from_intervals(
            (NativeEaInterval(ea, ea + 1),),
            native_key=native_key,
            exact_instruction_eas=(ea,),
        )

    source_identity = identity(0x1001)
    evidence = CanonicalSemanticEvidence(
        native_key=native_key,
        generation=2,
        atomic_group_id="canonical-semantic:g2",
        route_proofs=(
            SemanticRouteProof(
                proof_id="state-assignment@0x1001",
                atomic_group_id="canonical-semantic:g2",
                proof_kind=SemanticRouteProofKind.STATE_ASSIGNMENT,
                shape=SemanticRouteShape.DIRECT,
                source_identity=source_identity,
                source_anchor_ea=0x1001,
                delivery_region=NativeEaInterval(0x1001, 0x1002),
                destinations=(
                    SemanticRouteDestination(
                        role=SemanticEdgeRole.DIRECT,
                        state_constant=C1,
                        target_identity=identity(0x1002),
                        target_anchor_ea=0x1002,
                    ),
                ),
                state_write=SemanticStateWriteProof(
                    identity=source_identity,
                    instruction_ea=0x1001,
                    state_variable=StorageIdentity(
                        StorageIdentityKind.REGISTER,
                        20,
                    ),
                    width=4,
                    state_constant=C1,
                    corridor_instruction_eas=(0x1001,),
                    authority_transfer_ea=None,
                    preserved_call_instruction_eas=(),
                ),
            ),
        ),
    )

    class _Provider:
        def evidence_for(self, function_ea: int):
            return evidence if int(function_ea) == 0x1000 else None

    am = AnalysisManager(_chain_graph(), input_facts=_input_facts())
    ctx = _ctx(
        am.graph,
        am.view(),
        CapabilitySet().with_capability(
            CanonicalSemanticEvidenceCapability,
            _Provider(),
        ),
    )
    RecoverDispatcher().run(ctx)

    result = RecoverStateTransitions().run(ctx)

    assert result.analysis_outputs["canonical_semantic_evidence"] == evidence
    bound = result.analysis_outputs["bound_canonical_semantic_evidence"]
    assert bound.atomic_group_id == "canonical-semantic:g2"
    assert bound.routes[0].source.serial == 1
    assert bound.routes[0].source.anchor_ea == 0x1001
    assert bound.routes[0].destinations[0].block.serial == 2
    assert bound.routes[0].destinations[0].block.anchor_ea == 0x1002
