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

from d810.recon.flow.linearized_state_dag import (
    BoundaryInlineMode,
    LabelRenderMode,
    ProgramCommentMode,
    ProgramRenderStrategy,
    RenderOrderStrategy,
    build_linearized_state_program,
    build_live_linearized_state_dag_from_graph,
)
from d810.recon.flow.reconstruction_discovery_indexes import (
    build_reconstruction_discovery_indexes,
)

if TYPE_CHECKING:
    from d810.cfg.flowgraph import FlowGraph
    from d810.recon.flow.linearized_state_dag import (
        LinearizedStateDag,
        RenderedProgramSnapshot,
    )
    from d810.recon.flow.reconstruction_discovery_indexes import (
        ReconstructionDiscoveryIndexes,
    )
    from d810.recon.flow.state_machine_analysis import (
        SnapshotConstantFixpointResult,
    )
    from d810.recon.flow.transition_builder import TransitionResult


logger = logging.getLogger(
    "D810.recon.flow.round_discovery_context", logging.DEBUG
)


__all__ = (
    "ReconRoundDiscoveryContext",
    "build_round_discovery_context",
)


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

    # Canonical "next block / fall-through vs jump" view produced by
    # ``build_linearized_state_program(dag, ...)``. Strategies use this to
    # avoid re-rendering. ``None`` if the renderer raised during build (the
    # strategy fallback to its local setup recipes is intentional for A.1).
    linearized_program: RenderedProgramSnapshot | None = None

    # Opaque round identity: ``(func_ea, maturity, pass_number, monotonic_ns)``.
    # Used by downstream consumers (probes, caches) to key per-round data.
    round_id: tuple[int, int, int, int] = (0, 0, 0, 0)


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
        corrected_dag_out=corrected_dag_out,
    )
    corrected_dag = corrected_dag_out[0] if corrected_dag_out else dag

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
            "linearized_program=%s round_id=%s",
            indexes.dispatcher_serial,
            len(dispatcher_region),
            len(shared_suffix_blocks),
            len(corrected_boundary_shared_blocks),
            len(node_by_key),
            len(structured_regions),
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
        linearized_program=linearized_program,
        round_id=round_id,
    )
