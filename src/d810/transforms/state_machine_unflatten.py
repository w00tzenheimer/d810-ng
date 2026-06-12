"""Lower a recovered state machine to a direct CFG — produce a PatchPlan (unflatten pass #4 transform).

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
(#1) are the unflatten analysis dependencies; while any is missing the plan is empty.
"""
from __future__ import annotations

from d810.core import logging
from d810.core.typing import Optional, Protocol, runtime_checkable
from d810.analyses.data_flow.abstract_value import Block, RouteResult
from d810.ir.flowgraph import FlowGraph
from d810.analyses.value_flow.model import ValidatedFactView
from d810.analyses.control_flow.transition_builder import TransitionResult
from d810.analyses.control_flow.linearized_state_dag import (
    SemanticEdgeKind,
    build_live_linearized_state_dag_from_graph,
)
from d810.transforms.graph_modification import (
    ConvertToGoto,
    RedirectBranch,
    RedirectGoto,
)
from d810.transforms.plan import (
    PatchConvertToGoto,
    PatchPlan,
    PatchRedirectBranch,
    PatchRedirectGoto,
    compile_patch_plan,
)
from d810.transforms.edit_simulator import project_post_state
from d810.analyses.control_flow.recovered_graph_capture import (
    record_recovered_flow_graph,
    record_recovered_state_dag,
)
from d810.transforms.dispatcher_backedge_disconnect_planning import (
    plan_dispatcher_backedge_disconnects,
)
from d810.transforms.modification_builder import ModificationBuilder
from d810.transforms.reconstruction_return_planning import (
    plan_reconstruction_return_modifications,
)
from d810.transforms.reconstruction_postprocess_planning import (
    plan_reconstruction_postprocess_modifications,
)
from d810.transforms.semantic_regions import SemanticRegionPlan
from d810.transforms.spine_emission import emit_spine_modifications
from d810.transforms.use_def_redirect_filter import filter_use_def_severing_redirects
from d810.transforms.mod_claims import collect_mod_claims
from d810.analyses.control_flow.reconstruction_discovery import (
    classify_artifact_return_blocks,
)
from d810.analyses.control_flow.return_corridor_discovery import (
    collect_common_return_corridor,
)

logger = logging.getLogger("D810.transforms.unflat_lower")

# Edges that advance the state machine (a back-edge to an earlier state is still a TRANSITION,
# so loops are preserved as cycles in the reconstructed graph).
_SPINE_EDGE_KINDS = frozenset(
    {SemanticEdgeKind.TRANSITION, SemanticEdgeKind.CONDITIONAL_TRANSITION}
)


@runtime_checkable
class DispatcherModel(Protocol):
    """Portable view of a recovered dispatcher (#1) — the consolidation seam (S1).

    One ``route`` body per dispatcher *kind* replaces the six divergent
    ``resolve_target`` routers (see ``docs/plans/dispatcher-model-consolidation.md``).
    A model knows its state variable, its entry, which blocks form the dispatcher
    region, and — the substance — how to :meth:`route` a concrete state value to a
    :class:`~d810.analyses.data_flow.abstract_value.RouteResult`
    (``Block`` | ``EntersDispatcher`` | ``RouteOneOf`` | ``Unknown``).

    ``resolve_target`` is retained as a **deprecated default** so existing exact-only
    callers keep compiling while S2 migrates them onto :meth:`route`: it calls
    ``route`` and unwraps a single :class:`Block` (anything else → ``None``).
    Concrete models inherit this default unless they override it.
    """

    def route(self, value: int) -> RouteResult:
        """Route a concrete state ``value`` to a :class:`RouteResult`."""
        ...

    def state_var(self) -> int | None:
        """The dispatcher's state variable identity (stack offset), or ``None``."""
        ...

    @property
    def entry(self) -> int | None:
        """The dispatcher entry block serial (loop head), or ``None``."""
        ...

    def is_dispatcher(self, block_serial: int) -> bool:
        """Whether ``block_serial`` belongs to the dispatcher region."""
        ...

    def region(self) -> frozenset[int]:
        """The set of block serials forming the dispatcher region."""
        ...

    def resolve_target(self, state_value: int) -> Optional[int]:
        """DEPRECATED exact-unwrap shim: ``route(value)`` then unwrap a ``Block``.

        Default body shared by every model so callers still typed against the old
        ``resolve_target`` keep working through S1/S2.  Returns the target block
        serial for a :class:`Block` route, else ``None`` (``Unknown`` /
        ``EntersDispatcher`` / ``RouteOneOf`` do not name a single exact target).
        """
        rr = self.route(int(state_value))
        return rr.serial if isinstance(rr, Block) else None


def _resolve_target_via_route(model: "DispatcherModel", state_value: int) -> int | None:
    """Free-function form of the deprecated default (for non-subclass call sites)."""
    rr = model.route(int(state_value))
    return rr.serial if isinstance(rr, Block) else None


#: Backward-compatible alias: the old minimal name still resolves to the grown
#: Protocol so existing ``dispatch_map: _DispatcherMap`` annotations keep typing.
_DispatcherMap = DispatcherModel


def _patch_from_graph_modification(mod: object) -> object | None:
    """Wrap a neutral spine ``GraphModification`` into the unflatten ``PatchPlan`` step type.

    The shared :func:`emit_spine_modifications` emits backend-neutral ``GraphModification`` values
    (the same currency the legacy LFG path appends); the unflatten backend consumes a ``PatchPlan``, so
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
    if isinstance(mod, ConvertToGoto):
        # The return planner reaches ``builder.goto_redirect`` on a 2-way anchor, which the builder
        # lowers to a ``ConvertToGoto`` (keep the live arm, drop the other). Mirror it as the unflatten
        # ``PatchConvertToGoto`` the backend already applies for the #4b back-edge disconnect.
        return PatchConvertToGoto(
            block_serial=mod.block_serial,
            goto_target=mod.goto_target,
        )
    return None


def _neutral_spine_mods(
    dag,
    dispatcher_entry_serial: int,
    graph,
    *,
    use_def_safety=None,
    live_function=None,
    state_var_stkoff=None,
) -> tuple[object, ...]:
    """The protected spine emission as neutral ``GraphModification`` values (pre ``Patch*`` wrap).

    Shared by the unflatten #4 spine step and the full-reconstruction ``modifications`` input — the legacy
    direct-reconstruction set the postprocess phases (bridge/feeder/fixpoint/return) thread their
    claims from. ``emit_spine_modifications`` chooses the redirect kind from the live successor count,
    then the use-def filter vetoes redirects that would orphan non-state uses (no-op without a
    capability / live function).
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
    return filter_use_def_severing_redirects(
        mods,
        use_def_safety=use_def_safety,
        live_function=live_function,
        pre_cfg=graph,
        state_var_stkoff=state_var_stkoff,
    )


def _spine_redirects_from_dag(
    dag,
    dispatcher_entry_serial: int,
    graph,
    *,
    use_def_safety=None,
    live_function=None,
    state_var_stkoff=None,
) -> tuple[object, ...]:
    """Walk the linearized DAG's transition edges -> one redirect per edge (the reachable spine).

    Each edge's ``source_anchor`` (a handler exit) is redirected off the dispatcher onto the
    successor handler's ``target_entry_anchor``. Emission is delegated to the portable
    :func:`emit_spine_modifications`, shared verbatim with the legacy ``LinearizedFlowGraph``
    path: the redirect kind is chosen from the *live* block's successor count, not the static
    anchor kind (a 1-way source emits a goto redirect, a 2-way conditional source emits a branch
    redirect off the live arm successor), ``old_target`` is the block's real current successor, and
    2-way *transition* comparator sources are rejected so the deferred apply never aborts on a
    "not 1-way" mismatch. The neutral mods are wrapped back into unflatten ``Patch*`` steps.
    """
    mods = _neutral_spine_mods(
        dag,
        dispatcher_entry_serial,
        graph,
        use_def_safety=use_def_safety,
        live_function=live_function,
        state_var_stkoff=state_var_stkoff,
    )
    return tuple(
        patch
        for patch in (_patch_from_graph_modification(mod) for mod in mods)
        if patch is not None
    )


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


def _return_redirects_from_dag(
    dag,
    graph,
    dispatcher_entry_serial: int,
    *,
    bst_node_blocks,
    common_return_corridor,
    artifact_return_blocks,
    claimed_sources: set[int],
) -> tuple[object, ...]:
    """Lower the DAG's CONDITIONAL_RETURN edges to terminal-return redirects (legacy return wiring).

    Translates the return phase of ``StateWriteReconstructionStrategy.plan``: construct the portable
    :class:`ModificationBuilder` over the live block successor maps, index the DAG nodes by key, and
    delegate to :func:`plan_reconstruction_return_modifications` (the shared-corridor return model,
    reused verbatim). Its neutral ``RedirectGoto`` / ``RedirectBranch`` / ``ConvertToGoto`` mods are
    wrapped into unflatten ``Patch*`` steps. ``claimed_sources`` is seeded with the spine + back-edge
    sources so the same block is never redirected twice.
    """
    blocks = getattr(graph, "blocks", {})
    nsucc_map = {s: int(b.nsucc) for s, b in blocks.items()}
    succ_map = {s: tuple(int(x) for x in b.succs) for s, b in blocks.items()}
    builder = ModificationBuilder(block_nsucc_map=nsucc_map, block_succ_map=succ_map)
    node_by_key = {node.key: node for node in getattr(dag, "nodes", ())}
    result = plan_reconstruction_return_modifications(
        dag=dag,
        flow_graph=graph,
        builder=builder,
        claimed_sources=claimed_sources,
        dispatcher_serial=int(dispatcher_entry_serial),
        bst_node_blocks=set(int(b) for b in bst_node_blocks),
        common_return_corridor=set(int(b) for b in common_return_corridor),
        artifact_return_blocks=set(int(b) for b in artifact_return_blocks),
        node_by_key=node_by_key,
    )
    return tuple(
        patch
        for patch in (
            _patch_from_graph_modification(mod) for mod in result.modifications
        )
        if patch is not None
    )


def _reconstruction_postprocess_mods(
    dag,
    graph,
    dispatcher_entry_serial: int,
    *,
    spine_mods,
    bst_node_blocks,
    dispatcher,
    common_return_corridor,
    artifact_return_blocks,
    state_var_stkoff,
    constant_result=None,
    projected_flow_graph=None,
    exact_dispatcher_map=None,
) -> tuple[tuple[object, ...], int, int]:
    """Run the portable reconstruction postprocess -> the rich neutral mod set (the returns=8 chain).

    Translates ``StateWriteReconstructionStrategy``'s postprocess: the already-portable
    :func:`plan_reconstruction_postprocess_modifications` runs preheader -> bridge -> feeder ->
    fixpoint-feeder -> return over the BST-enriched DAG, threading ``claimed_sources`` through each
    phase (so the return planner sees the post-bridge claims, not the raw spine). ``spine_mods`` is the
    neutral direct-reconstruction set; ``owned_blocks`` is its source/target span. Returns the union of
    all sub-plan modifications (InsertBlock / EdgeRedirectViaPredSplit / ZeroStateWrite /
    CreateConditionalRedirect / RedirectGoto / RedirectBranch) as neutral ``GraphModification`` values
    for the ``planner_modifications`` channel. ``constant_result`` None -> the fixpoint feeder no-ops.
    """
    blocks = getattr(graph, "blocks", {})
    nsucc_map = {s: int(b.nsucc) for s, b in blocks.items()}
    succ_map = {s: tuple(int(x) for x in b.succs) for s, b in blocks.items()}
    builder = ModificationBuilder(block_nsucc_map=nsucc_map, block_succ_map=succ_map)
    node_by_key = {node.key: node for node in getattr(dag, "nodes", ())}
    owned_blocks = {
        int(serial)
        for mod in spine_mods
        for serial in (
            getattr(mod, "from_serial", None),
            getattr(mod, "new_target", None),
        )
        if serial is not None
    }
    # Project the graph through the spine mods so the feeder phase sees the POST-spine topology — its
    # successor/predecessor checks need the reconstructed edges, not the stale dispatcher ones (the
    # legacy ``execute_reconstruction_postprocess`` projects through ``modifications`` the same way).
    # Best-effort: a projection failure falls back to the raw graph (feeder stays conservative).
    if projected_flow_graph is None:
        try:
            projected_flow_graph = project_post_state(
                graph, compile_patch_plan(list(spine_mods), graph)
            )
        except Exception:  # noqa: BLE001 — projection is best-effort diagnostics
            projected_flow_graph = graph
    # Diagnostics: stash the recovered topology for the D810_USE_STRUCTURER dump.
    record_recovered_flow_graph(projected_flow_graph)
    result = plan_reconstruction_postprocess_modifications(
        dag=dag,
        flow_graph=graph,
        projected_flow_graph=projected_flow_graph,
        builder=builder,
        dispatcher_serial=int(dispatcher_entry_serial),
        bst_node_blocks=set(int(b) for b in bst_node_blocks),
        dispatcher=dispatcher,
        modifications=list(spine_mods),
        owned_blocks=owned_blocks,
        rejected_metadata=[],
        constant_result=constant_result,
        state_var_stkoff=(
            int(state_var_stkoff) if state_var_stkoff is not None else None
        ),
        artifact_return_blocks=set(int(b) for b in artifact_return_blocks),
        common_return_corridor=set(int(b) for b in common_return_corridor),
        node_by_key=node_by_key,
        exact_dispatcher_map=exact_dispatcher_map,
    )
    mods: list = []
    if result.preheader_bridge.modification is not None:
        mods.append(result.preheader_bridge.modification)
    mods.extend(result.bridge_plan.modifications)
    mods.extend(result.feeder_plan.modifications)
    mods.extend(result.fixpoint_feeder_plan.modifications)
    mods.extend(result.return_plan.modifications)
    effective_spine_mods = tuple(spine_mods)
    return_claimed_sources, _return_claimed_targets = collect_mod_claims(
        list(result.return_plan.modifications)
    )
    if return_claimed_sources:
        effective_spine_mods = tuple(
            mod
            for mod in spine_mods
            if not (collect_mod_claims([mod])[0] & return_claimed_sources)
        )
    if logger.info_on:
        skip_reasons: dict[str, int] = {}
        for entry in result.return_plan.skipped_entries:
            skip_reasons[entry.reason] = skip_reasons.get(entry.reason, 0) + 1
        logger.info(
            "unflat #4 postprocess: preheader=%d bridge=%d feeder=%d fixpoint=%d return=%d "
            "owned=%d return_skipped=%s",
            1 if result.preheader_bridge.modification is not None else 0,
            len(result.bridge_plan.modifications),
            len(result.feeder_plan.modifications),
            len(result.fixpoint_feeder_plan.modifications),
            len(result.return_plan.modifications),
            len(owned_blocks),
            skip_reasons,
        )
    postprocess_mods = tuple(mods)
    return (
        (*effective_spine_mods, *postprocess_mods),
        len(effective_spine_mods),
        len(postprocess_mods),
    )


def lower_to_direct_graph(
    graph: FlowGraph | None,
    facts: ValidatedFactView | None,
    *,
    transition_result: TransitionResult | None = None,
    dispatch_map: _DispatcherMap | None = None,
    dispatcher_entry_serial: int | None = None,
    state_var_stkoff: int | None = None,
    regions: SemanticRegionPlan | None = None,
    use_def_safety=None,
    live_function=None,
    bst_node_blocks=None,
    dag=None,
    dispatcher=None,
    constant_result=None,
    projected_flow_graph=None,
) -> PatchPlan:
    """Build a ``PatchPlan`` reconnecting handlers into a direct spine (dispatcher bypassed).

    ``use_def_safety`` (an injected ``UseDefSafetyCapability``) + ``live_function`` (the opaque live
    backend function) enable protected emission: spine redirects that would orphan a non-state
    variable's uses are vetoed before they reach the plan. Both ``None`` on the portable/test path,
    where emission is unfiltered (byte-identical).

    ``bst_node_blocks`` is the enriched-DAG signal: when the entry threads the recovered BST node set
    in (bst evidence promoted to production), the DAG carries CONDITIONAL_RETURN edges and the legacy
    return wiring is lowered (gap3). ``None`` -> the return phase is skipped (shallow production path,
    byte-identical).

    ``dispatcher`` (the recovered ``IntervalDispatcher``) is the full-reconstruction signal: with both
    it and ``bst_node_blocks`` present, #4 runs the entire portable postprocess orchestration
    (preheader/bridge/feeder/fixpoint/return — :func:`_reconstruction_postprocess_mods`) and returns
    the rich neutral mod set via ``planner_modifications`` (the channel the backend applies for
    InsertBlock / ZeroStateWrite / …). ``None`` -> the redirect-only ``steps`` path below (the
    committed, production-byte-identical behaviour). ``constant_result`` / ``projected_flow_graph`` are
    optional postprocess inputs (``constant_result`` None -> the fixpoint feeder no-ops).
    """
    if (
        graph is None
        or transition_result is None
        or not transition_result.transitions
        or dispatch_map is None
        or dispatcher_entry_serial is None
    ):
        return PatchPlan()
    # ``dag`` lets the caller inject a pre-built (BST-enriched) DAG — the entry's diag rebuild already
    # constructs the oracle-grade DAG with the full value-range evidence. When ``None`` (production /
    # portable test) we build the shallow exact-chain DAG from ``transition_result`` here.
    if dag is None:
        dag = build_live_linearized_state_dag_from_graph(
            flow_graph=graph,
            transition_result=transition_result,
            dispatcher_entry_serial=dispatcher_entry_serial,
            state_var_stkoff=state_var_stkoff,
        )
    # Diagnostics: stash the recovered (dispatcher-free) state-DAG so the
    # D810_USE_STRUCTURER dump structures it instead of the lifted FlowGraph.
    record_recovered_state_dag(dag)
    # Full reconstruction (unflatten gap3+gap4): with the recovered IntervalDispatcher AND the BST node set,
    # run the entire portable postprocess orchestration over the enriched DAG and emit the rich neutral
    # mod set through ``planner_modifications`` (the backend's apply channel for InsertBlock /
    # ZeroStateWrite / per-pred splits / returns). Mirrors StateWriteReconstructionStrategy.plan;
    # returns are EMERGENT from the full chain, not a discrete mod. Gated on ``dispatcher`` so the
    # committed redirect-only ``steps`` path below stays byte-identical when it is absent.
    if bst_node_blocks is not None and dispatcher is not None:
        corridor = collect_common_return_corridor(
            dag,
            graph,
            bst_node_blocks=set(int(b) for b in bst_node_blocks),
            dispatcher_serial=int(dispatcher_entry_serial),
        )
        state_constants = {
            int(row.state_const)
            for row in getattr(dispatch_map, "rows", ())
            if getattr(row, "state_const", None) is not None
        }
        artifact_return_blocks = (
            classify_artifact_return_blocks(
                graph,
                state_var_stkoff=int(state_var_stkoff),
                state_constants=state_constants,
            )
            if state_var_stkoff is not None
            else set()
        )
        spine_mods = _neutral_spine_mods(
            dag,
            int(dispatcher_entry_serial),
            graph,
            use_def_safety=use_def_safety,
            live_function=live_function,
            state_var_stkoff=state_var_stkoff,
        )
        planner_mods, spine_count, postprocess_count = _reconstruction_postprocess_mods(
            dag,
            graph,
            int(dispatcher_entry_serial),
            spine_mods=spine_mods,
            bst_node_blocks=bst_node_blocks,
            dispatcher=dispatcher,
            common_return_corridor=corridor,
            artifact_return_blocks=artifact_return_blocks,
            state_var_stkoff=state_var_stkoff,
            constant_result=constant_result,
            projected_flow_graph=projected_flow_graph,
            exact_dispatcher_map=dispatch_map,
        )
        if logger.info_on:
            logger.info(
                "unflat #4 full-reconstruction: spine=%d postprocess=%d total=%d",
                spine_count,
                postprocess_count,
                len(planner_mods),
            )
        # Compile the neutral GraphModification mods into applicable PatchPlan steps
        # (same bridge the legacy executor uses) so the unflatten backend's lower() — which
        # applies ``steps``, not the ``planner_modifications`` channel — materializes
        # them. ``graph`` is the pre-mutation CFG for edge-split legality.
        return compile_patch_plan(list(planner_mods), graph)
    redirect_steps = _spine_redirects_from_dag(
        dag,
        int(dispatcher_entry_serial),
        graph,
        use_def_safety=use_def_safety,
        live_function=live_function,
        state_var_stkoff=state_var_stkoff,
    )
    backedge_steps = _disconnect_residual_dispatcher_backedges(
        dag, int(dispatcher_entry_serial), graph, redirect_steps
    )
    # Return wiring (unflatten gap3): lower the DAG's CONDITIONAL_RETURN edges to terminal returns by
    # translating StateWriteReconstructionStrategy's return phase. GATED on ``bst_node_blocks`` — the
    # enriched-DAG signal the entry threads in once bst evidence reaches production. On today's
    # shallow production path (``None``) the return phase is skipped, so the plan is byte-identical.
    return_steps: tuple[object, ...] = ()
    if bst_node_blocks is not None:
        corridor = collect_common_return_corridor(
            dag,
            graph,
            bst_node_blocks=set(int(b) for b in bst_node_blocks),
            dispatcher_serial=int(dispatcher_entry_serial),
        )
        state_constants = {
            int(row.state_const)
            for row in getattr(dispatch_map, "rows", ())
            if getattr(row, "state_const", None) is not None
        }
        artifact_return_blocks = (
            classify_artifact_return_blocks(
                graph,
                state_var_stkoff=int(state_var_stkoff),
                state_constants=state_constants,
            )
            if state_var_stkoff is not None
            else set()
        )
        # Seed claims with the spine + back-edge sources so the return phase never double-edits a
        # block already redirected by #4/#4b (mirrors the legacy claimed_sources accumulation).
        claimed_sources = {
            int(serial)
            for serial in (
                *(getattr(step, "from_serial", None) for step in redirect_steps),
                *(getattr(step, "block_serial", None) for step in backedge_steps),
            )
            if serial is not None
        }
        return_steps = _return_redirects_from_dag(
            dag,
            graph,
            int(dispatcher_entry_serial),
            bst_node_blocks=bst_node_blocks,
            common_return_corridor=corridor,
            artifact_return_blocks=artifact_return_blocks,
            claimed_sources=claimed_sources,
        )
    if logger.info_on:
        logger.info(
            "unflat #4 lowering: spine=%d backedge=%d return=%d (bst=%s)",
            len(redirect_steps),
            len(backedge_steps),
            len(return_steps),
            "on" if bst_node_blocks is not None else "off",
        )
    return PatchPlan(steps=(*redirect_steps, *backedge_steps, *return_steps))
