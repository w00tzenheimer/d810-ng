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
from d810.transforms.graph_modification import RedirectBranch, RedirectGoto
from d810.transforms.plan import (
    PatchConvertToGoto,
    PatchPlan,
    PatchRedirectBranch,
    PatchRedirectGoto,
)
from d810.transforms.dispatcher_backedge_disconnect_planning import (
    plan_dispatcher_backedge_disconnects,
)
from d810.transforms.semantic_regions import SemanticRegionPlan
from d810.transforms.spine_emission import emit_spine_modifications

# Edges that advance the state machine (a back-edge to an earlier state is still a TRANSITION,
# so loops are preserved as cycles in the reconstructed graph).
_SPINE_EDGE_KINDS = frozenset(
    {SemanticEdgeKind.TRANSITION, SemanticEdgeKind.CONDITIONAL_TRANSITION}
)


@runtime_checkable
class _DispatcherMap(Protocol):
    """Minimal portable view of the recovered dispatcher map (#1)."""

    def resolve_target(self, state_value: int) -> int | None: ...


def _patch_from_graph_modification(mod: object) -> object | None:
    """Wrap a neutral spine ``GraphModification`` into the §1a ``PatchPlan`` step type.

    The shared :func:`emit_spine_modifications` emits backend-neutral ``GraphModification`` values
    (the same currency the legacy LFG path appends); the §1a backend consumes a ``PatchPlan``, so
    each redirect is wrapped into its ``Patch*`` shadow. Only the two redirect shapes the spine
    emitter produces are handled; anything else is dropped (returns ``None``).
    """
    if isinstance(mod, RedirectGoto):
        return PatchRedirectGoto(
            from_serial=mod.from_serial,
            old_target=mod.old_target,
            new_target=mod.new_target,
        )
    if isinstance(mod, RedirectBranch):
        return PatchRedirectBranch(
            from_serial=mod.from_serial,
            old_target=mod.old_target,
            new_target=mod.new_target,
        )
    return None


def _spine_redirects_from_dag(dag, dispatcher_entry_serial: int, graph) -> tuple[object, ...]:
    """Walk the linearized DAG's transition edges -> one redirect per edge (the reachable spine).

    Each edge's ``source_anchor`` (a handler exit) is redirected off the dispatcher onto the
    successor handler's ``target_entry_anchor``. Emission is delegated to the portable
    :func:`emit_spine_modifications`, shared verbatim with the legacy ``LinearizedFlowGraph``
    path: the redirect kind is chosen from the *live* block's successor count, not the static
    anchor kind (a 1-way source emits a goto redirect, a 2-way conditional source emits a branch
    redirect off the live arm successor), ``old_target`` is the block's real current successor, and
    2-way *transition* comparator sources are rejected so the deferred apply never aborts on a
    "not 1-way" mismatch. The neutral mods are wrapped back into §1a ``Patch*`` steps.
    """
    blocks = getattr(graph, "blocks", {})
    nsucc_map = {s: int(b.nsucc) for s, b in blocks.items()}
    succ_map = {s: tuple(int(x) for x in b.succs) for s, b in blocks.items()}
    mods = emit_spine_modifications(
        dag=dag,
        spine_edge_kinds=_SPINE_EDGE_KINDS,
        dispatcher_entry_serial=int(dispatcher_entry_serial),
        block_nsucc_map=nsucc_map,
        block_succ_map=succ_map,
    )
    steps = tuple(
        patch
        for patch in (_patch_from_graph_modification(mod) for mod in mods)
        if patch is not None
    )
    return steps


def _spine_members_from_dag(dag) -> frozenset[int]:
    """Block serials that are reachable spine members (a source or target in ``dag.edges``).

    Used to scope the residual back-edge disconnect (#4b) so it only touches blocks that
    participate in the reconstructed spine, never unrelated 2-way blocks elsewhere in the CFG.
    """
    members: set[int] = set()
    for edge in dag.edges:
        anchor = getattr(edge, "source_anchor", None)
        if anchor is not None and getattr(anchor, "block_serial", None) is not None:
            members.add(int(anchor.block_serial))
        target = getattr(edge, "target_entry_anchor", None)
        if target is not None:
            members.add(int(target))
    return frozenset(members)


def _disconnect_residual_dispatcher_backedges(
    dag, dispatcher_entry_serial: int, graph, redirect_steps
) -> tuple[object, ...]:
    """Convert residual 2-way dispatcher back-edges among spine members to 1-way gotos (#4b).

    After the spine redirects (#4) some 2-way spine blocks still keep ``dispatcher_entry_serial``
    as one of their two successors — a spurious back-edge that the vendor structurer renders as a
    ``while`` loop. Mirroring the legacy ``_disconnect_bst_comparison_nodes`` seam, each such block
    is converted to a 1-way goto that KEEPS its non-dispatcher successor. Scoped to spine members
    (sources/targets in ``dag.edges``) so unrelated 2-way blocks are left untouched, and excluding
    any block already handled by a #4 redirect so the same source is never double-edited.
    """
    blocks = getattr(graph, "blocks", {})
    nsucc_map = {s: int(b.nsucc) for s, b in blocks.items()}
    succ_map = {s: tuple(int(x) for x in b.succs) for s, b in blocks.items()}
    # Seed ``emitted`` with the #4 redirect sources so the planner skips any block that already
    # received a goto/branch redirect (matches the legacy ``already_redirected`` guard).
    emitted = {
        (int(step.from_serial), -1)
        for step in redirect_steps
        if getattr(step, "from_serial", None) is not None
    }
    plans = plan_dispatcher_backedge_disconnects(
        block_nsucc_map=nsucc_map,
        block_succ_map=succ_map,
        dispatcher_serial=int(dispatcher_entry_serial),
        bst_node_blocks=set(),
        emitted=emitted,
    )
    spine_members = _spine_members_from_dag(dag)
    steps: list[object] = []
    for plan in plans:
        if int(plan.source_block) not in spine_members:
            continue  # only disconnect 2-way blocks that participate in the spine
        steps.append(
            PatchConvertToGoto(
                block_serial=int(plan.source_block),
                goto_target=int(plan.keep_target),
            )
        )
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
    redirect_steps = _spine_redirects_from_dag(
        dag, int(dispatcher_entry_serial), graph
    )
    backedge_steps = _disconnect_residual_dispatcher_backedges(
        dag, int(dispatcher_entry_serial), graph, redirect_steps
    )
    return PatchPlan(steps=(*redirect_steps, *backedge_steps))
