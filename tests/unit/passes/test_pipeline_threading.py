"""unflatten dependency threading: pass #1's StateDispatcherMap reaches pass #2 via AnalysisManager.

The LLVM ``AnalysisManager.getResult`` edge — RecoverDispatcher publishes its map; RecoverStateTransitions
pulls it and resolves transitions through it. Without the manager edge, #2 has no map (unresolved).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.analyses.value_flow.contract_evidence import contract_evidence_payload
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
)
from d810.analyses.control_flow.dispatcher_recovery import DispatcherRecovery
from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap
from d810.capabilities.dispatcher import RouterKind
from d810.passes.unflatten import state_machine as state_machine_module
from tests.native_preanalysis import make_native_key
from tests.typed_patch_authority import block_refs_by_serial

C1 = 0x10000001
STATE_OFF = 0x3C


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
    l = MopSnapshot(kind=OperandKind.STACK, stkoff=STATE_OFF, size=4)
    r = MopSnapshot(kind=OperandKind.NUMBER, value=const, size=4)
    d = MopSnapshot(kind=OperandKind.BLOCK, block_ref=target)
    return InsnSnapshot(
        opcode=1,
        ea=0x1000,
        operands=(l, r, d),
        l=l,
        r=r,
        d=d,
        kind=InsnKind.EQUALITY_JUMP,
        branch_predicate=PredicateKind.NE,
        is_conditional_jump=True,
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


def test_recover_dispatcher_publishes_branch_target_evidence():
    am = AnalysisManager(_chain_graph(), input_facts=_input_facts())
    ctx = _ctx(am.graph, am.view())

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
    assert am.get_analysis("plan_semantic_regions") is not None
    # synthetic obs carries no next-state write -> empty transitions -> heavy DAG/lower guarded off
    assert results[3].rewrite_plan.steps == ()  # lower_state_machine
    assert results[4].rewrite_plan.steps == ()  # cleanup_residual_dispatcher


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
