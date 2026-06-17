"""Portable per-edge spine redirect emission — shared by the legacy LFG path and unflatten #4.

The reconstruction "spine" is the chain of handler-to-handler redirects that reconnects the
scattered OLLVM handlers into a directly reachable graph with the dispatcher bypassed. Both the
legacy ``LinearizedFlowGraphStrategy`` (via ``execute_dag_redirect_fallback``) and the unflatten
``lower_to_direct_graph`` transform need exactly the same per-edge decision for the *clean spine*
case: given a semantic transition edge whose ``target_entry_anchor`` is already resolved, emit the
correct redirect modification.

This module factors that decision out of both call sites onto the single canonical, portable
emission planner (:func:`plan_dag_redirect_fallback_emission`). It is ``nsucc``-aware and resolves
``old_target`` via :func:`resolve_redirect_old_target` — the two things a naive static-anchor-kind
emitter gets wrong:

- a 2-way comparator source must emit a *branch* redirect off the **current** arm successor
  (``succs[branch_arm]``), never a goto change (which the deferred backend rejects as
  "not 1-way");
- ``old_target`` is the block's real current successor, never a hardcoded dispatcher serial.

It consumes only snapshot-bound CFG facts (``nsucc``/``succs`` maps, the condition-chain/dispatcher serial
sets) and the already-resolved ``target_entry_anchor`` carried on each edge — no live ``mba``. The
legacy strategy layers *additional* live-MBA handoff resolution (``resolve_effective_target_entry``)
and path-tail redirects on top of this base; that surface stays in the hexrays backend. Here we
emit only the portable base case that both paths share verbatim.
"""
from __future__ import annotations

from d810.core.typing import Mapping

from d810.transforms.dag_redirect_modification_planning import (
    apply_dag_redirect_emission_plan,
    plan_dag_redirect_fallback_emission,
)
from d810.transforms.graph_modification import GraphModification
from d810.transforms.lowering_selector import (
    is_live_oneway_noop,
    resolve_redirect_old_target,
)


# Edge kinds whose ``name`` marks an unconditional transition for the emission planner. A
# CONDITIONAL_TRANSITION edge is NOT an "edge_is_transition" (it carries a real 2-way arm), matching
# ``execute_dag_redirect_fallback``'s ``edge.kind.name == "TRANSITION"`` test.
_TRANSITION_KIND_NAME = "TRANSITION"
_CONDITIONAL_BRANCH_KIND_NAME = "CONDITIONAL_BRANCH"


def emit_spine_modifications(
    *,
    dag,
    spine_edge_kinds,
    dispatcher_entry_serial: int,
    block_nsucc_map: Mapping[int, int],
    block_succ_map: Mapping[int, tuple[int, ...]],
    condition_chain_blocks: frozenset[int] = frozenset(),
    dispatcher_region: frozenset[int] = frozenset(),
) -> list[GraphModification]:
    """Walk the DAG's spine edges -> one neutral redirect modification per emitted edge.

    For every edge in ``dag.edges`` whose ``kind`` is in ``spine_edge_kinds`` and whose
    ``target_entry_anchor`` is resolved (and not the dispatcher itself), resolve the current
    ``old_target`` and run the shared :func:`plan_dag_redirect_fallback_emission` planner. The
    planner is ``nsucc``-aware: a 1-way source yields a ``RedirectGoto``, a 2-way conditional
    source yields a ``RedirectBranch`` off the live arm successor, and a 2-way *transition* source
    is rejected (``transition_two_way_source``) so the deferred apply never aborts on a
    "not 1-way" mismatch. Per-source/per-arm dedup mirrors the legacy ``claimed_1way`` /
    ``claimed_2way`` bookkeeping.

    Args:
        dag: The linearized state DAG (``.edges`` of ``StateDagEdge``).
        spine_edge_kinds: Set of ``SemanticEdgeKind`` values to treat as spine transitions.
        dispatcher_entry_serial: Serial of the dispatcher entry; edges routing back to it are
            left for the dispatcher cleanup pass.
        block_nsucc_map: ``serial -> live successor count`` for the current graph.
        block_succ_map: ``serial -> tuple of live successor serials`` for the current graph.
        condition_chain_blocks: Condition-chain comparison block serials (old_target resolution hint).
        dispatcher_region: Dispatcher region block serials (old_target resolution hint).

    Returns:
        Ordered list of :class:`GraphModification` (``RedirectGoto`` / ``RedirectBranch``)
        following the same emission order the legacy strategy produces for the clean spine.
    """
    modifications: list[GraphModification] = []
    # Dedup/claim bookkeeping mirrors ``DagRedirectMutableState`` (the legacy fallback state).
    emitted: set[tuple[int, int]] = set()
    claimed_1way: dict[int, int] = {}
    claimed_2way: dict[tuple[int, int], int] = {}
    owned_blocks: set[int] = set()
    owned_edges: set[tuple[int, int]] = set()
    owned_transitions: set[tuple[int, int]] = set()

    condition_chain_set = {int(b) for b in condition_chain_blocks}
    region = {int(b) for b in dispatcher_region}

    for edge in dag.edges:
        if edge.kind not in spine_edge_kinds:
            continue
        anchor = edge.source_anchor
        target = edge.target_entry_anchor
        if anchor is None or target is None:
            continue
        new_target = int(target)
        if new_target == int(dispatcher_entry_serial):
            continue  # routes back to the dispatcher: leave for the cleanup pass

        source_block = int(anchor.block_serial)
        source_succs = tuple(int(s) for s in block_succ_map.get(source_block, ()))
        nsucc = int(block_nsucc_map.get(source_block, len(source_succs)))

        source_is_conditional_branch = (
            getattr(anchor.kind, "name", "") == _CONDITIONAL_BRANCH_KIND_NAME
        )
        source_branch_arm = (
            int(anchor.branch_arm) if anchor.branch_arm is not None else None
        )
        old_target = resolve_redirect_old_target(
            source_block,
            source_succs=source_succs,
            ordered_path=tuple(int(node) for node in edge.ordered_path),
            target_entry_anchor=new_target,
            source_branch_arm=source_branch_arm,
            source_is_conditional_branch=source_is_conditional_branch,
            condition_chain_blocks=condition_chain_set,
            dispatcher_region=region,
        )

        branch_key = (
            (source_block, int(old_target))
            if nsucc == 2 and old_target is not None
            else None
        )
        emission_plan = plan_dag_redirect_fallback_emission(
            source_block=source_block,
            target_entry=new_target,
            nsucc=nsucc,
            old_target=(int(old_target) if old_target is not None else None),
            source_succs=source_succs,
            edge_is_transition=(getattr(edge.kind, "name", "") == _TRANSITION_KIND_NAME),
            live_oneway_noop=is_live_oneway_noop(
                source_succs=source_succs,
                target_entry=new_target,
            ),
            claimed_1way_target=claimed_1way.get(source_block),
            claimed_2way_target=(
                claimed_2way.get(branch_key) if branch_key is not None else None
            ),
        )
        if (source_block, new_target) in emitted:
            continue
        if not emission_plan.accepted or emission_plan.modification is None:
            continue
        apply_dag_redirect_emission_plan(
            emission_plan,
            modifications=modifications,
            claimed_1way=claimed_1way,
            claimed_2way=claimed_2way,
            emitted=emitted,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            owned_transitions=owned_transitions,
        )

    return modifications


__all__ = ["emit_spine_modifications"]
