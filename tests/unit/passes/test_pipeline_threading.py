"""unflatten dependency threading: pass #1's StateDispatcherMap reaches pass #2 via AnalysisManager.

The LLVM ``AnalysisManager.getResult`` edge — RecoverDispatcher publishes its map; RecoverStateTransitions
pulls it and resolves transitions through it. Without the manager edge, #2 has no map (unresolved).
"""
from __future__ import annotations

from types import SimpleNamespace

from d810.ir.flowgraph import (
    BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot, MopSnapshot, OperandKind,
)
from d810.ir.semantics import PredicateKind
from d810.passes.analysis_manager import AnalysisManager
from d810.passes.pass_pipeline import FunctionPipelineContext
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


def _ctx(graph, facts):
    return FunctionPipelineContext(
        source=None, graph=graph, maturity=None, project_config=None, facts=facts)


def test_map_threads_from_pass1_to_pass2_and_resolves():
    am = AnalysisManager(_chain_graph(), input_facts=SimpleNamespace(active_observations=(_obs(),)))
    ctx = _ctx(am.graph, am.view())
    RecoverDispatcher().run(ctx)                 # publishes the dispatcher map
    result = RecoverStateTransitions().run(ctx)  # pulls it, resolves through it
    resolutions = result.facts[0]
    assert len(resolutions) == 1
    assert resolutions[0].resolved_next_block_serial == 1  # C1 -> handler 1 via #1's map
    assert resolutions[0].resolution_reason == "resolved_exact_state"


def test_full_five_pass_chain_threads_and_completes():
    am = AnalysisManager(_chain_graph(), input_facts=SimpleNamespace(active_observations=(_obs(),)))
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


def test_without_manager_edge_pass2_is_unresolved():
    # ctx.facts is a plain view (no get_analysis) -> #2 has no map
    plain = SimpleNamespace(active_observations=(_obs(),))
    result = RecoverStateTransitions().run(_ctx(_chain_graph(), plain))
    resolutions = result.facts[0]
    assert len(resolutions) == 1
    assert resolutions[0].resolved_next_block_serial is None
    assert resolutions[0].resolution_reason == "no_dispatcher_rows_available"
