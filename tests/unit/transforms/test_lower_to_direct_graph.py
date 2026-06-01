"""§1a pass #4: lower_to_direct_graph builds the reconstruction spine from the DAG edges.

The portable half — walk the linearized state DAG's transition edges and redirect each handler's
exit anchor onto its successor's entry (the reachable spine, dispatcher bypassed). The DAG build
itself is the heavy live-built analysis (golden-verified at wiring); here we lock the edge-walk
helper + the analysis-dependency guards.
"""
from __future__ import annotations

from types import SimpleNamespace

from d810.analyses.control_flow.transition_builder import StateTransition, TransitionResult
from d810.analyses.control_flow.linearized_state_dag import (
    RedirectSourceKind,
    SemanticEdgeKind,
)
from d810.transforms.state_machine_unflatten import (
    _spine_redirects_from_dag,
    lower_to_direct_graph,
)
from d810.transforms.plan import PatchPlan, PatchRedirectBranch, PatchRedirectGoto


class _Map:
    def resolve_target(self, state_value):
        return None


def _edge(kind, source_block, target_entry, *, branch=False, arm=None, ordered_path=()):
    branch_arm = arm if arm is not None else (0 if branch else None)
    anchor = SimpleNamespace(
        block_serial=source_block,
        branch_arm=branch_arm,
        kind=RedirectSourceKind.CONDITIONAL_BRANCH if branch else RedirectSourceKind.UNCONDITIONAL,
    )
    return SimpleNamespace(
        kind=kind,
        target_entry_anchor=target_entry,
        source_anchor=anchor,
        ordered_path=tuple(ordered_path),
    )


def _graph(spec):
    """spec: {serial: (nsucc, (succ, ...))} -> bare FlowGraph-like stub with .blocks."""
    blocks = {
        s: SimpleNamespace(nsucc=nsucc, succs=succs) for s, (nsucc, succs) in spec.items()
    }
    return SimpleNamespace(blocks=blocks)


def test_spine_redirects_one_goto_per_transition_edge():
    # 1-way sources: old_target derived from the live block's single successor, not the dispatcher.
    dag = SimpleNamespace(edges=(
        _edge(SemanticEdgeKind.TRANSITION, 10, 20),
        _edge(SemanticEdgeKind.TRANSITION, 20, 30),
    ))
    graph = _graph({10: (1, (5,)), 20: (1, (5,))})
    steps = _spine_redirects_from_dag(dag, 5, graph)
    assert len(steps) == 2
    assert all(isinstance(s, PatchRedirectGoto) for s in steps)
    assert (steps[0].from_serial, steps[0].old_target, steps[0].new_target) == (10, 5, 20)
    assert (steps[1].from_serial, steps[1].old_target, steps[1].new_target) == (20, 5, 30)


def test_conditional_arm_anchor_becomes_branch_redirect():
    # 2-way source: old_target is the current successor of the redirected arm (succs[arm]).
    dag = SimpleNamespace(edges=(_edge(SemanticEdgeKind.CONDITIONAL_TRANSITION, 9, 44, branch=True, arm=1),))
    graph = _graph({9: (2, (16, 17))})
    steps = _spine_redirects_from_dag(dag, 5, graph)
    assert len(steps) == 1 and isinstance(steps[0], PatchRedirectBranch)
    assert (steps[0].from_serial, steps[0].old_target, steps[0].new_target) == (9, 17, 44)


def test_two_way_transition_comparator_anchor_is_skipped():
    # 2-way *TRANSITION* source -> rejected (transition_two_way_source) so the deferred apply
    # never aborts on a "not 1-way" mismatch. Matches the legacy emission planner exactly.
    dag = SimpleNamespace(edges=(_edge(SemanticEdgeKind.TRANSITION, 15, 44, arm=None),))
    graph = _graph({15: (2, (16, 17))})
    assert _spine_redirects_from_dag(dag, 5, graph) == ()


def test_two_way_conditional_transition_anchor_resolves_branch_old_target():
    # 2-way CONDITIONAL_TRANSITION source with an UNCONDITIONAL anchor (no explicit arm) now
    # routes through the shared planner like the legacy LFG path: old_target falls back to the
    # current non-target successor and a branch redirect is emitted (not skipped).
    dag = SimpleNamespace(edges=(_edge(SemanticEdgeKind.CONDITIONAL_TRANSITION, 15, 44, arm=None),))
    graph = _graph({15: (2, (16, 17))})
    steps = _spine_redirects_from_dag(dag, 5, graph)
    assert len(steps) == 1 and isinstance(steps[0], PatchRedirectBranch)
    assert (steps[0].from_serial, steps[0].old_target, steps[0].new_target) == (15, 16, 44)


def test_non_transition_edges_and_dispatcher_selfloops_skipped():
    dag = SimpleNamespace(edges=(
        _edge(SemanticEdgeKind.EXIT_ROUTINE, 10, 20),     # not a transition
        _edge(SemanticEdgeKind.TRANSITION, 10, 5),         # routes back to dispatcher (5)
        _edge(SemanticEdgeKind.TRANSITION, 11, None),      # no target
    ))
    graph = _graph({10: (1, (5,)), 11: (1, (5,))})
    assert _spine_redirects_from_dag(dag, 5, graph) == ()


def test_null_or_empty_inputs_yield_empty_plan():
    assert lower_to_direct_graph(None, None) == PatchPlan()
    # empty transitions -> heavy DAG build is guarded off
    assert lower_to_direct_graph(
        object(), None, transition_result=TransitionResult(),
        dispatch_map=_Map(), dispatcher_entry_serial=5,
    ) == PatchPlan()
    # missing dispatch_map -> empty
    assert lower_to_direct_graph(
        object(), None,
        transition_result=TransitionResult(transitions=[StateTransition(from_state=0, to_state=1, from_block=10)]),
        dispatch_map=None, dispatcher_entry_serial=5,
    ) == PatchPlan()
