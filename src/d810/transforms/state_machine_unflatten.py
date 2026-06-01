"""Lower a recovered state machine to a direct CFG — produce a PatchPlan (§1a pass #4 transform).

The "build the directed graph we want" step (LLVM-style). (B) the SWR reconstruction spine: build
the linearized state DAG (the resolved handler chain) from the recovered transitions, then for every
semantic TRANSITION edge redirect the source handler's exit anchor straight onto its successor
handler's entry — reconnecting the scattered handlers into a reachable spine with the dispatcher
bypassed. This is the piece whose absence collapses sub_7FFD (probe 1): without the spine the
handlers are unreachable and Hex-Rays DCEs the whole function.

``MutationBackend.apply`` then materializes the plan and re-lifts so the vendor optimizer recomputes
dominance. Loops are preserved as real cycles (DAG edges carry back-edges); we do NOT flatten to
acyclic. Region-fusion body materialization (the leaked-state-guard cleanup) is the separate #5 / the
deferred backend half.

``transition_result`` (#2) / ``dispatch_map`` + ``dispatcher_entry_serial`` + ``state_var_stkoff``
(#1) are the §1a analysis dependencies; while any is missing the plan is empty.
"""
from __future__ import annotations

from d810.core.typing import Protocol, runtime_checkable
from d810.ir.flowgraph import FlowGraph
from d810.analyses.value_flow.model import ValidatedFactView
from d810.analyses.control_flow.transition_builder import TransitionResult
from d810.analyses.control_flow.linearized_state_dag import (
    SemanticEdgeKind,
    build_live_linearized_state_dag_from_graph,
)
from d810.transforms.plan import PatchPlan, PatchRedirectBranch, PatchRedirectGoto
from d810.transforms.semantic_regions import SemanticRegionPlan

# Edges that advance the state machine (a back-edge to an earlier state is still a TRANSITION,
# so loops are preserved as cycles in the reconstructed graph).
_SPINE_EDGE_KINDS = frozenset(
    {SemanticEdgeKind.TRANSITION, SemanticEdgeKind.CONDITIONAL_TRANSITION}
)


@runtime_checkable
class _DispatcherMap(Protocol):
    """Minimal portable view of the recovered dispatcher map (#1)."""

    def resolve_target(self, state_value: int) -> int | None: ...


def _spine_redirects_from_dag(dag, dispatcher_entry_serial: int, graph) -> tuple[object, ...]:
    """Walk the linearized DAG's transition edges -> one redirect per edge (the reachable spine).

    Each edge's ``source_anchor`` (a handler exit) is redirected off the dispatcher onto the
    successor handler's ``target_entry_anchor``. The redirect kind is chosen from the *live*
    block's successor count, not the static anchor kind: a 1-way source emits a goto redirect,
    a 2-way source emits a branch redirect off the current arm successor. Ambiguous/comparator
    2-way sources (no resolvable arm) are skipped and left to the #3 engine / #5 cleanup so the
    deferred apply does not abort on a "not 1-way" mismatch.
    """
    blocks = getattr(graph, "blocks", {})
    nsucc_map = {s: int(b.nsucc) for s, b in blocks.items()}
    succ_map = {s: tuple(b.succs) for s, b in blocks.items()}
    steps: list[object] = []
    for edge in dag.edges:
        if edge.kind not in _SPINE_EDGE_KINDS:
            continue
        target = edge.target_entry_anchor
        anchor = edge.source_anchor
        if target is None or anchor is None:
            continue
        new_target = int(target)
        if new_target == dispatcher_entry_serial:
            continue  # state routes back to the dispatcher: leave for cleanup (#5)
        s = int(anchor.block_serial)
        succs = succ_map.get(s, ())
        nsucc = nsucc_map.get(s, len(succs))
        if nsucc == 1:
            old_target = int(succs[0]) if succs else int(dispatcher_entry_serial)
            steps.append(
                PatchRedirectGoto(
                    from_serial=s, old_target=old_target, new_target=new_target
                )
            )
        elif nsucc == 2:
            arm = anchor.branch_arm
            if arm is None or arm >= len(succs):
                continue  # ambiguous/comparator 2-way source: leave to #3 engine / #5 cleanup
            old_target = int(succs[arm])
            if old_target == new_target:
                continue
            steps.append(
                PatchRedirectBranch(
                    from_serial=s, old_target=old_target, new_target=new_target
                )
            )
        # nsucc 0 or >2 -> skip
    return tuple(steps)


def lower_to_direct_graph(
    graph: FlowGraph | None,
    facts: ValidatedFactView | None,
    *,
    transition_result: TransitionResult | None = None,
    dispatch_map: _DispatcherMap | None = None,
    dispatcher_entry_serial: int | None = None,
    state_var_stkoff: int | None = None,
    regions: SemanticRegionPlan | None = None,
) -> PatchPlan:
    """Build a ``PatchPlan`` reconnecting handlers into a direct spine (dispatcher bypassed)."""
    if (
        graph is None
        or transition_result is None
        or not transition_result.transitions
        or dispatch_map is None
        or dispatcher_entry_serial is None
    ):
        return PatchPlan()
    dag = build_live_linearized_state_dag_from_graph(
        flow_graph=graph,
        transition_result=transition_result,
        dispatcher_entry_serial=dispatcher_entry_serial,
        state_var_stkoff=state_var_stkoff,
    )
    return PatchPlan(
        steps=_spine_redirects_from_dag(dag, int(dispatcher_entry_serial), graph)
    )
