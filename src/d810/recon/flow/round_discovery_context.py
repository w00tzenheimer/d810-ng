"""Per-round discovery-context publisher for the unflattening engine.

This module publishes a single read-only bundle of classification facts that
every recon-consuming strategy needs on a per-round basis. It is **classification
only**: no ``ModificationBuilder`` calls, no appends to a ``modifications`` list,
no flow-graph mutation. The resulting :class:`ReconRoundDiscoveryContext` is
built once per ``(func_ea, maturity, pass_number)`` in Hodur's family adapter
and attached to ``AnalysisSnapshot`` as an opaque ``object`` field so that the
engine's pure-Python unit test surface stays IDA-free.

Layer: ``d810.recon.flow`` (recon — above cfg, below optimizers). It composes
existing recon helpers — it does **not** re-derive anything. In particular
:func:`build_reconstruction_discovery_indexes` is wrapped verbatim; the
dispatcher region, shared-suffix sets, node maps, and structured-region data
all come straight out of the chunk-6 bundle.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from d810.core import logging
from d810.core.typing import TYPE_CHECKING

from d810.recon.flow.linearized_state_dag import (
    build_live_linearized_state_dag_from_graph,
)
from d810.recon.flow.reconstruction_discovery_indexes import (
    build_reconstruction_discovery_indexes,
)

if TYPE_CHECKING:
    from d810.cfg.flowgraph import FlowGraph
    from d810.recon.flow.linearized_state_dag import LinearizedStateDag
    from d810.recon.flow.reconstruction_discovery_indexes import (
        ReconstructionDiscoveryIndexes,
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

    Typing uses ``object`` for recon-level classes so this record can live in
    the snapshot surface without leaking recon types upward into the engine's
    pure-Python layer. Callers that need the concrete types can annotate locally
    against ``d810.recon.flow.linearized_state_dag.LinearizedStateDag`` etc.
    """

    # Live semantic DAGs (recon-layer objects, IDA-linked).
    dag: object
    corrected_dag: object

    # Dispatcher region facts (derived from the DAG).
    dispatcher_region: frozenset[int]
    dispatcher_serial: int

    # Upstream analysis results carried through the round.
    bst_result: object | None
    transition_result: object | None
    constant_fixpoint: object | None

    # Structured-region overlay (may be empty).
    structured_regions: tuple = ()

    # The chunk-6 reconstruction-discovery-indexes bundle (full object, so
    # consumers can pull out ``dag_maps``, ``structured_region_edge_pairs`` etc
    # without us widening the public surface here).
    indexes: object = None

    # Convenience projections of ``indexes`` — exposed explicitly because they
    # are the most-queried facts and every consumer wants them as frozensets.
    shared_suffix_blocks: frozenset[int] = field(default_factory=frozenset)
    corrected_boundary_shared_blocks: frozenset[int] = field(
        default_factory=frozenset
    )
    node_by_key: dict = field(default_factory=dict)


def build_round_discovery_context(
    *,
    flow_graph: FlowGraph,
    transition_result: TransitionResult,
    dispatcher_entry_serial: int,
    state_var_stkoff: int | None,
    structured_regions: tuple = (),
    constant_fixpoint: object | None = None,
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

    # Freeze the mutable projections before handing them to the caller —
    # the indexes bundle keeps the mutable references for back-compat but the
    # context surface is strictly read-only.
    dispatcher_region = frozenset(int(s) for s in indexes.dispatcher_region)
    shared_suffix_blocks = frozenset(int(s) for s in indexes.shared_suffix_blocks)
    corrected_boundary_shared_blocks = frozenset(
        int(s) for s in indexes.corrected_boundary_shared_blocks
    )
    node_by_key = dict(indexes.node_by_key)

    if logger.debug_on:
        logger.debug(
            "ReconRoundDiscoveryContext: dispatcher=%d region=%d shared_suffix=%d "
            "boundary_shared=%d node_by_key=%d structured_regions=%d",
            indexes.dispatcher_serial,
            len(dispatcher_region),
            len(shared_suffix_blocks),
            len(corrected_boundary_shared_blocks),
            len(node_by_key),
            len(structured_regions),
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
    )
