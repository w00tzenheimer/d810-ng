"""Per-round discovery-context publisher for the unflattening engine.

This module publishes a single read-only bundle of classification facts that
every recon-consuming strategy needs on a per-round basis. It is **classification
only**: no ``ModificationBuilder`` calls, no appends to a ``modifications`` list,
no flow-graph mutation. The resulting :class:`ReconRoundDiscoveryContext` is
built once per ``(func_ea, maturity, pass_number)`` in Hodur's family adapter
and attached to ``AnalysisSnapshot`` as the canonical round-level classification
view; the engine stays pure-Python because all recon types are imported under
``TYPE_CHECKING`` only.

Layer: ``d810.recon.flow`` (recon — above cfg, below optimizers). It composes
existing recon helpers — it does **not** re-derive anything. In particular
:func:`build_reconstruction_discovery_indexes` is wrapped verbatim; the
dispatcher region, shared-suffix sets, node maps, and structured-region data
all come straight out of the chunk-6 bundle.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from d810.core import logging
from d810.core.typing import TYPE_CHECKING

from d810.analyses.control_flow.linearized_state_dag import (
    BoundaryInlineMode,
    LabelRenderMode,
    ProgramCommentMode,
    ProgramRenderStrategy,
    RenderOrderStrategy,
    build_linearized_state_program,
    build_live_linearized_state_dag_from_graph,
)
from d810.analyses.control_flow.persisted_recon_dag import store_persisted_recon_dag
from d810.analyses.control_flow.reconstruction_discovery_indexes import (
    build_reconstruction_discovery_indexes,
)
from d810.analyses.control_flow.return_frontier_artifacts import (
    ReturnFrontierArtifactPriors,
)

if TYPE_CHECKING:
    from d810.ir.flowgraph import FlowGraph
    from d810.analyses.control_flow.linearized_state_dag import (
        LinearizedStateDag,
        RenderedProgramSnapshot,
        StateDagNode,
        StateLocalEdge,
    )
    from d810.analyses.control_flow.reconstruction_discovery_indexes import (
        ReconstructionDiscoveryIndexes,
    )
    from d810.analyses.control_flow.state_machine_analysis import (
        SnapshotConstantFixpointResult,
    )
    from d810.analyses.control_flow.transition_builder import TransitionResult


logger = logging.getLogger(
    "D810.recon.flow.round_discovery_context", logging.DEBUG
)


__all__ = (
    "DagLocalFacts",
    "ReconRoundDiscoveryContext",
    "build_round_discovery_context",
    "pass_entry_guard",
)


@dataclass(frozen=True, slots=True)
class DagLocalFacts:
    """Typed lookup indexes for one LinearizedStateDag's node-local facts.

    These are runtime planner facts, not diagnostic-rendering data. Consumers
    use them directly instead of parsing ``linearized_program`` text or querying
    the diag database.
    """

    node_by_entry: dict[int, StateDagNode]
    node_by_handler: dict[int, StateDagNode]
    node_by_owned_block: dict[int, StateDagNode]
    node_by_any_local_block: dict[int, StateDagNode]
    owned_blocks_by_entry: dict[int, frozenset[int]]
    shared_suffix_by_entry: dict[int, frozenset[int]]
    local_edges_by_entry: dict[int, tuple[StateLocalEdge, ...]]


@dataclass(frozen=True, slots=True)
class ReconRoundDiscoveryContext:
    """Canonical per-round discovery facts shared across all strategies.

    All fields are **read-only classification outputs**. No ``ModificationBuilder``
    calls, no ``modifications`` lists. Strategies query this bundle instead of
    rebuilding the DAG / indexes / fixpoint per strategy.

    **Immutability contract.** All fields are read-only after construction.
    Consumers MUST NOT mutate any field (including the nested ``structured_regions``,
    ``indexes.node_by_key``, ``indexes.structured_region_source_blocks`` defaultdict,
    or the DAG / linearized program objects). Mutation is a determinism bug —
    every strategy in the round sees the same object, so any edit bleeds.
    If a strategy needs to derive additional facts, do it in its own local
    scope; do not write back to this context.
    """

    # Live semantic DAGs (recon-layer objects, IDA-linked).
    dag: LinearizedStateDag
    corrected_dag: LinearizedStateDag

    # Dispatcher region facts (derived from the DAG).
    dispatcher_region: frozenset[int]
    dispatcher_serial: int

    # Upstream analysis results carried through the round. ``bst_result`` is
    # caller-specific (per-family BST types) so it legitimately stays ``object``.
    bst_result: object | None
    transition_result: TransitionResult
    constant_fixpoint: SnapshotConstantFixpointResult | None

    # The chunk-6 reconstruction-discovery-indexes bundle (full object, so
    # consumers can pull out ``dag_maps``, ``structured_region_edge_pairs`` etc
    # without us widening the public surface here). Declared before any
    # defaulted fields because dataclasses require non-default fields to
    # precede defaulted ones.
    indexes: ReconstructionDiscoveryIndexes

    # Structured-region overlay (may be empty).
    structured_regions: tuple = ()

    # Convenience projections of ``indexes`` — exposed explicitly because they
    # are the most-queried facts and every consumer wants them as frozensets.
    shared_suffix_blocks: frozenset[int] = field(default_factory=frozenset)
    corrected_boundary_shared_blocks: frozenset[int] = field(
        default_factory=frozenset
    )
    node_by_key: dict = field(default_factory=dict)

    # Typed node-local DAG facts for planner logic. This deliberately mirrors
    # LinearizedStateDag structure without forcing consumers to scan all nodes
    # or scrape rendered text.
    local_facts: DagLocalFacts | None = None

    # Canonical "next block / fall-through vs jump" view produced by
    # ``build_linearized_state_program(dag, ...)``. Strategies use this to
    # avoid re-rendering. ``None`` if the renderer raised during build (the
    # strategy fallback to its local setup recipes is intentional for A.1).
    linearized_program: RenderedProgramSnapshot | None = None

    # Caller/profile priors used while building return-frontier artifact facts.
    return_frontier_artifact_priors: ReturnFrontierArtifactPriors | None = None

    # Opaque round identity: ``(func_ea, maturity, pass_number, monotonic_ns)``.
    # Used by downstream consumers (probes, caches) to key per-round data.
    round_id: tuple[int, int, int, int] = (0, 0, 0, 0)


def _build_dag_local_facts(dag: LinearizedStateDag) -> DagLocalFacts:
    node_by_entry: dict[int, StateDagNode] = {}
    node_by_handler: dict[int, StateDagNode] = {}
    node_by_owned_block: dict[int, StateDagNode] = {}
    node_by_any_local_block: dict[int, StateDagNode] = {}
    owned_blocks_by_entry: dict[int, frozenset[int]] = {}
    shared_suffix_by_entry: dict[int, frozenset[int]] = {}
    local_edges_by_entry: dict[int, tuple[StateLocalEdge, ...]] = {}

    for node in dag.nodes:
        entry = int(node.entry_anchor)
        handler = int(node.handler_serial)
        node_by_entry.setdefault(entry, node)
        node_by_handler.setdefault(handler, node)

        owned_blocks = frozenset(int(block) for block in node.owned_blocks)
        shared_suffix = frozenset(int(block) for block in node.shared_suffix_blocks)
        owned_blocks_by_entry[entry] = owned_blocks
        shared_suffix_by_entry[entry] = shared_suffix
        local_edges_by_entry[entry] = tuple(node.local_edges)

        any_local_blocks = set(owned_blocks)
        any_local_blocks.update(int(block) for block in node.exclusive_blocks)
        any_local_blocks.update(shared_suffix)
        for segment in node.local_segments:
            any_local_blocks.update(int(block) for block in segment.blocks)

        for block in owned_blocks:
            node_by_owned_block.setdefault(block, node)
        for block in any_local_blocks:
            node_by_any_local_block.setdefault(block, node)

    return DagLocalFacts(
        node_by_entry=node_by_entry,
        node_by_handler=node_by_handler,
        node_by_owned_block=node_by_owned_block,
        node_by_any_local_block=node_by_any_local_block,
        owned_blocks_by_entry=owned_blocks_by_entry,
        shared_suffix_by_entry=shared_suffix_by_entry,
        local_edges_by_entry=local_edges_by_entry,
    )


def build_round_discovery_context(
    *,
    func_ea: int,
    maturity: int,
    pass_number: int,
    flow_graph: FlowGraph,
    transition_result: TransitionResult,
    dispatcher_entry_serial: int,
    state_var_stkoff: int | None,
    structured_regions: tuple = (),
    constant_fixpoint: SnapshotConstantFixpointResult | None = None,
    bst_result: object | None = None,
    initial_state: int | None = None,
    pre_header_serial: int | None = None,
    handler_range_map: object | None = None,
    bst_node_blocks: tuple[int, ...] = (),
    diagnostics: tuple[str, ...] = (),
    dispatcher: object | None = None,
    mba: object | None = None,
    prefer_local_corridors: bool = False,
    return_frontier_artifact_priors: ReturnFrontierArtifactPriors | None = None,
) -> ReconRoundDiscoveryContext:
    """Build the per-round discovery context for one unflattening pass.

    This wraps :func:`build_live_linearized_state_dag_from_graph` plus
    :func:`build_reconstruction_discovery_indexes` and returns a frozen bundle.
    The caller (Hodur's family adapter) is expected to provide exactly the
    inputs it already computes for the first-pass reconstruction strategy so
    that downstream consumers see the same DAG/indexes as the existing
    inline setup recipes.

    Callers that cannot supply a coherent input set (missing state var
    stkoff, missing BST dispatcher serial, etc.) should skip building the
    context and pass ``discovery=None`` to :class:`AnalysisSnapshot`; we do
    **not** try to half-build here.
    """
    corrected_dag_out: list = []
    dag = build_live_linearized_state_dag_from_graph(
        flow_graph,
        transition_result,
        dispatcher_entry_serial=dispatcher_entry_serial,
        state_var_stkoff=state_var_stkoff,
        pre_header_serial=pre_header_serial,
        initial_state=initial_state,
        handler_range_map=handler_range_map or {},
        bst_node_blocks=bst_node_blocks,
        diagnostics=diagnostics,
        dispatcher=dispatcher,
        mba=mba,
        prefer_local_corridors=prefer_local_corridors,
        return_frontier_artifact_priors=return_frontier_artifact_priors,
        corrected_dag_out=corrected_dag_out,
    )
    corrected_dag = corrected_dag_out[0] if corrected_dag_out else dag

    # Stash the FIRST DAG built per func_ea as the canonical recon-time
    # anchor selection. Diagnostic dumps consult this cache so they label
    # what HCC actually consumed instead of a post-mutation rebuild. Pure
    # observability — no effect on lowering. Subsequent builds in the same
    # decompilation are silently ignored (first-write wins).
    try:
        store_persisted_recon_dag(int(func_ea), dag)
    except Exception:
        pass

    indexes = build_reconstruction_discovery_indexes(
        dag=dag,
        corrected_dag=corrected_dag,
        structured_regions=structured_regions,
    )

    # Canonical linearized-program snapshot — strategies re-use this instead
    # of rendering their own. Renderer failures fall back to ``None`` so
    # strategies keep their local setup recipes as a safety net for A.1.
    linearized_program: RenderedProgramSnapshot | None = None
    try:
        linearized_program = build_linearized_state_program(
            dag,
            order_strategy=RenderOrderStrategy.CATALOG,
            program_strategy=ProgramRenderStrategy.LOCAL_SEGMENT_COLLAPSING,
            label_render_mode=LabelRenderMode.STATE_FAMILY,
            boundary_inline_mode=BoundaryInlineMode.LABELS_ONLY,
            comment_mode=ProgramCommentMode.DEBUG_METADATA,
            block_payload_by_serial={},
        )
    except Exception as exc:
        logger.debug(
            "ReconRoundDiscoveryContext: linearized_program render failed: %s",
            exc,
        )
        linearized_program = None

    # Freeze the mutable projections before handing them to the caller —
    # the indexes bundle keeps the mutable references for back-compat but the
    # context surface is strictly read-only.
    dispatcher_region = frozenset(int(s) for s in indexes.dispatcher_region)
    shared_suffix_blocks = frozenset(int(s) for s in indexes.shared_suffix_blocks)
    corrected_boundary_shared_blocks = frozenset(
        int(s) for s in indexes.corrected_boundary_shared_blocks
    )
    node_by_key = dict(indexes.node_by_key)
    local_facts = _build_dag_local_facts(dag)

    round_id = (
        int(func_ea),
        int(maturity),
        int(pass_number),
        time.monotonic_ns(),
    )

    if logger.debug_on:
        logger.debug(
            "ReconRoundDiscoveryContext: dispatcher=%d region=%d shared_suffix=%d "
            "boundary_shared=%d node_by_key=%d structured_regions=%d "
            "local_fact_entries=%d linearized_program=%s round_id=%s",
            indexes.dispatcher_serial,
            len(dispatcher_region),
            len(shared_suffix_blocks),
            len(corrected_boundary_shared_blocks),
            len(node_by_key),
            len(structured_regions),
            len(local_facts.node_by_entry),
            "ok" if linearized_program is not None else "none",
            round_id,
        )

    return ReconRoundDiscoveryContext(
        dag=dag,
        corrected_dag=corrected_dag,
        dispatcher_region=dispatcher_region,
        dispatcher_serial=int(indexes.dispatcher_serial),
        bst_result=bst_result,
        transition_result=transition_result,
        constant_fixpoint=constant_fixpoint,
        structured_regions=tuple(structured_regions),
        indexes=indexes,
        shared_suffix_blocks=shared_suffix_blocks,
        corrected_boundary_shared_blocks=corrected_boundary_shared_blocks,
        node_by_key=node_by_key,
        local_facts=local_facts,
        linearized_program=linearized_program,
        return_frontier_artifact_priors=return_frontier_artifact_priors,
        round_id=round_id,
    )



def pass_entry_guard(snapshot, *, reason: str) -> bool:
    """Log a warning when ``snapshot.discovery`` is being consulted from
    inside a round scope.

    Pass-entry state — ``snapshot.discovery.dag``, ``.corrected_dag``,
    ``.indexes`` — is frozen at the top of each Hodur pass. Once LFG starts
    its internal projected-replan rounds (``snapshot.round_context.in_round``
    flips True), the live CFG has moved and reading ``discovery`` returns the
    ORIGINAL view, not the current one. That is sometimes the desired
    semantic (SSR admissibility checks that should be stable across the
    whole pass) and sometimes a bug (strategy expected the live projected
    view).

    This helper is a VOLUNTARY guardrail: callers opt in by invoking it at
    the site where they know they want pass-entry semantics. When invoked
    outside a round (``snapshot.round_context.depth == 0`` or no round
    frame on the stack) it is silent. When invoked inside a round, it logs
    one WARNING line with the full scope trace plus the caller's stated
    reason, so log readers can audit that the access was intentional.

    Returns ``True`` when pass-entry access is safe (not in a round).
    Returns ``False`` when the access is inside a round (caller should
    double-check they actually want the frozen original view, not the
    projected one). The return value is advisory; the helper never raises.
    """
    ctx = getattr(snapshot, "round_context", None)
    if ctx is None or not getattr(ctx, "in_round", False):
        return True
    logger.warning(
        "pass_entry_guard: snapshot.discovery consulted from inside a round "
        "— reason=%r trace=%s (reading the pass-entry ORIGINAL view; if you "
        "want the current projected view, use round_summary instead)",
        reason,
        ctx.as_trace(),
    )
    return False
