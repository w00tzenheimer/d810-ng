"""unflatten dependency threading: pass #1's StateDispatcherMap reaches pass #2 via AnalysisManager.

The LLVM ``AnalysisManager.getResult`` edge — RecoverDispatcher publishes its map; RecoverStateTransitions
pulls it and resolves transitions through it. Without the manager edge, #2 has no map (unresolved).
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.analyses.value_flow.contract_evidence import contract_evidence_payload
from d810.ir.flowgraph import (
    BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot, MopSnapshot, OperandKind,
)
from d810.ir.semantics import PredicateKind
from d810.passes.analysis_manager import AnalysisManager
from d810.passes.pass_pipeline import FunctionPipelineContext
from d810.passes.driver import PassContractError, run_pipeline
from d810.families.state_machine_cff.pipeline import standard_state_machine_passes
from d810.ir.maturity import IRMaturity
from d810.transforms.plan import PatchPlan
from d810.passes.unflatten.state_machine import (
    CleanupResidualDispatcher,
    LowerStateMachine,
    PlanSemanticRegions,
    RecoverDispatcher,
    RecoverStateTransitions,
)

C1 = 0x10000001
STATE_OFF = 0x3C


def _ne(const, target):
    l = MopSnapshot(kind=OperandKind.STACK, stkoff=STATE_OFF, size=4)
    r = MopSnapshot(kind=OperandKind.NUMBER, value=const, size=4)
    d = MopSnapshot(kind=OperandKind.BLOCK, block_ref=target)
    return InsnSnapshot(opcode=1, ea=0x1000, operands=(l, r, d), l=l, r=r, d=d,
                        kind=InsnKind.EQUALITY_JUMP, branch_predicate=PredicateKind.NE,
                        is_conditional_jump=True)


def _blk(serial, succs, preds, tail=None):
    return BlockSnapshot(serial=serial, block_type=1, succs=succs, preds=preds, flags=0,
                         start_ea=0x1000 + serial,
                         insn_snapshots=(tail,) if tail else (),
                         tail_opcode=tail.opcode if tail else None)


def _chain_graph():
    # 0: jnz state,C1,2 ; state==C1 -> fall-through handler 1
    return FlowGraph(
        blocks={0: _blk(0, (1, 2), (), _ne(C1, 2)),
                1: _blk(1, (), (0,)),
                2: _blk(2, (), (0,))},
        entry_serial=0, func_ea=0x1000)


def _obs():
    return SimpleNamespace(
        kind="StateTransitionAnchorFact", fact_id="f1",
        maturity="GLBOPT1", phase="recon", confidence=1.0, evidence=(),
        source_block=0, source_ea=0x1000,
        payload={"source_block_serial": 0, "source_state_const": C1, "successor_kind": "branch"})


def _state_write_obs():
    return SimpleNamespace(
        kind="StateWriteAnchorFact",
        fact_id="state-write:1",
        maturity="GLBOPT1",
        phase="recon",
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


def _ctx(graph, facts):
    return FunctionPipelineContext(
        source=None, graph=graph, maturity=None, project_config=None, facts=facts)


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


def test_map_threads_from_pass1_to_pass2_and_resolves():
    am = AnalysisManager(_chain_graph(), input_facts=_input_facts())
    ctx = _ctx(am.graph, am.view())
    RecoverDispatcher().run(ctx)                 # publishes the dispatcher map
    result = RecoverStateTransitions().run(ctx)  # pulls it, resolves through it
    resolutions = result.analysis_outputs["recover_state_transitions"]
    assert len(resolutions) == 1
    assert resolutions[0].resolved_next_block_serial == 1  # C1 -> handler 1 via #1's map
    assert resolutions[0].resolution_reason == "resolved_exact_state"


def test_recover_dispatcher_publishes_branch_target_evidence():
    am = AnalysisManager(_chain_graph(), input_facts=_input_facts())
    ctx = _ctx(am.graph, am.view())

    assert not am.has_evidence("branch_targets")
    assert not am.has_evidence("dispatcher_predicates")

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
    ctx = _ctx(am.graph, am.view())
    passes = [
        RecoverDispatcher(), RecoverStateTransitions(), PlanSemanticRegions(),
        LowerStateMachine(), CleanupResidualDispatcher(),
    ]
    results = [p.run(ctx) for p in passes]
    # every analysis dependency was published into the manager (the getResult edges)
    assert am.get_analysis("recover_dispatcher").dispatch_map is not None
    assert am.get_analysis("transition_result") is not None
    assert am.get_analysis("plan_semantic_regions") is not None
    # synthetic obs carries no next-state write -> empty transitions -> heavy DAG/lower guarded off
    assert results[3].rewrite_plan == PatchPlan()  # lower_state_machine
    assert results[4].rewrite_plan == PatchPlan()  # cleanup_residual_dispatcher


def test_run_pipeline_publishes_state_machine_contract_facts():
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
        maturity=IRMaturity.GLOBAL_ANALYZED,
    )

    assert am.has_fact("dispatcher_family")
    assert am.has_fact("state_transition")
    assert am.has_fact("semantic_region")
    assert am.has_fact("recovered_cfg_edge")
    assert am.get_fact("dispatcher_family")[0].value.dispatch_map is not None
    assert am.get_fact("state_transition")[0].kind == "state_transition"
    assert am.has_evidence("branch_targets")


def test_transition_contract_requires_published_branch_target_evidence():
    am = AnalysisManager(
        _chain_graph(),
        input_facts=_input_facts(),
    )
    am.put_analysis("recover_dispatcher", object())

    with pytest.raises(PassContractError, match="branch_targets"):
        run_pipeline(
            source=_Src(),
            family=_TransitionOnlyFamily(),
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
