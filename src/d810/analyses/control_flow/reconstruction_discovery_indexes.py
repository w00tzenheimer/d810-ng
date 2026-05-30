"""Bundled discovery-index producer for reconstruction planning.

Bundles pre-candidate-loop derivations (dispatcher region, shared-suffix
blocks, corrected boundary shared blocks, DAG node maps, structured-region
edge pairs and source blocks) into a single frozen dataclass. The producer
runs once per reconstruction round; consumers receive it as a read-only
bundle instead of rebuilding each derivation inline.

Mutability is preserved exactly as the inline code used it: ``dispatcher_region``
is a plain ``set[int]`` (read-only after construction but callees are typed
``set[int]``), ``structured_region_source_blocks`` is a ``defaultdict(set)``
keyed by ``(source_state, target_state)``, and ``structured_region_edge_pairs``
is a plain ``set[tuple[str, int, int]]``. The dataclass holds references only;
no copies are made.

Pure transform: no flow-graph access, no IDA calls.
"""
from __future__ import annotations

from d810.ir.state_edge_pair import state_edge_pair

from collections import defaultdict
from dataclasses import dataclass
from d810.core.typing import Iterable

from d810.analyses.control_flow.recon_dag_index import DagNodeMaps, build_dag_node_maps
from d810.analyses.control_flow.linearized_state_dag import LinearizedStateDag
from d810.analyses.control_flow.reconstruction_discovery import (
    collect_boundary_protected_shared_blocks,
    collect_shared_suffix_blocks,
)


__all__ = [
    "ReconstructionDiscoveryIndexes",
    "build_reconstruction_discovery_indexes",
]


# Duplicated from ``reconstruction._state_edge_pair`` to keep this producer
# independent of the hodur strategy module. Must stay in sync.


@dataclass(frozen=True, slots=True)
class ReconstructionDiscoveryIndexes:
    """Pre-candidate-loop derivations used by reconstruction planning.

    All contained collections are held by reference: the dataclass itself is
    frozen but the ``set`` / ``dict`` / ``defaultdict`` fields retain the
    mutability profile established at construction. Consumers MUST NOT mutate
    them (the inline code only read them downstream, with the exception of
    callees that type-annotate ``dispatcher_region: set[int]``).
    """

    dispatcher_region: set[int]
    dispatcher_serial: int
    shared_suffix_blocks: set[int]
    corrected_boundary_shared_blocks: set[int]
    dag_maps: DagNodeMaps
    node_by_key: dict
    structured_region_edge_pairs: set[tuple[str, int, int]]
    structured_region_source_blocks: dict[tuple[int, int], set[int]]


def build_reconstruction_discovery_indexes(
    *,
    dag: LinearizedStateDag,
    corrected_dag: LinearizedStateDag,
    structured_regions: Iterable[object],
) -> ReconstructionDiscoveryIndexes:
    """Build the pre-candidate-loop derivation bundle for one reconstruction round."""
    structured_region_edge_pairs: set[tuple[str, int, int]] = {
        (str(region.region_name), int(source), int(target))
        for region in structured_regions
        for source, target in region.internal_state_edges
    }
    structured_region_source_blocks: dict[tuple[int, int], set[int]] = defaultdict(set)
    for edge in dag.edges:
        pair = state_edge_pair(edge)
        if pair is None:
            continue
        structured_region_source_blocks[pair].add(
            int(edge.source_anchor.block_serial)
        )

    dispatcher_region: set[int] = set(dag.bst_node_blocks)
    if dag.dispatcher_entry_serial >= 0:
        dispatcher_region.add(int(dag.dispatcher_entry_serial))
    shared_suffix_blocks = collect_shared_suffix_blocks(dag)
    corrected_boundary_shared_blocks = collect_boundary_protected_shared_blocks(
        corrected_dag
    )
    dag_maps = build_dag_node_maps(dag)
    node_by_key = dag_maps.node_by_key
    dispatcher_serial = int(dag.dispatcher_entry_serial)

    return ReconstructionDiscoveryIndexes(
        dispatcher_region=dispatcher_region,
        dispatcher_serial=dispatcher_serial,
        shared_suffix_blocks=shared_suffix_blocks,
        corrected_boundary_shared_blocks=corrected_boundary_shared_blocks,
        dag_maps=dag_maps,
        node_by_key=node_by_key,
        structured_region_edge_pairs=structured_region_edge_pairs,
        structured_region_source_blocks=structured_region_source_blocks,
    )
