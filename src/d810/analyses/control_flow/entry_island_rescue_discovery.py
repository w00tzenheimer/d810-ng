from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.recon_dag_index import (
    incoming_edges_by_target_entry,
    semantic_entry_anchors,
)
from d810.analyses.control_flow.entry_island import lift_target_entry_to_island_entry
from d810.analyses.control_flow.graph_reachability import edge_reachable_frontier
from d810.analyses.control_flow.linearized_state_dag import LinearizedStateDag


@dataclass(frozen=True, slots=True)
class EntryIslandRescueSeed:
    """Discovery result for one unreachable semantic entry island."""

    source_block: int
    lifted_entry: int


@dataclass(frozen=True, slots=True)
class LateEntryIslandRescueSeed:
    """Discovery result for one unreachable non-dispatcher successor behind BST."""

    source_block: int | None
    lifted_entry: int
    passthrough_block: int
    edge_source_block: int


@dataclass(frozen=True, slots=True)
class LateEntryIslandDiagnostic:
    """Diagnostic facts for an unreachable non-dispatcher block behind BST-only preds."""

    block_serial: int
    bst_preds: tuple[int, ...]
    dispatcher_rows: tuple[str, ...]


def collect_entry_island_rescue_seeds(
    dag: LinearizedStateDag,
    *,
    reachable_blocks: set[int],
    dispatcher_region: set[int],
    claimed_targets: set[int],
) -> tuple[EntryIslandRescueSeed, ...]:
    semantic_anchors = semantic_entry_anchors(dag) - dispatcher_region
    incoming_by_target = incoming_edges_by_target_entry(dag)
    seeds: list[EntryIslandRescueSeed] = []

    for edge in dag.edges:
        if edge.target_entry_anchor is None:
            continue
        target_entry = int(edge.target_entry_anchor)
        if target_entry in dispatcher_region:
            continue

        lifted_entry = lift_target_entry_to_island_entry(
            target_entry,
            incoming_by_target_entry=incoming_by_target,
            semantic_entry_anchors=semantic_anchors,
            reachable_blocks=reachable_blocks,
            dispatcher_region=dispatcher_region,
        )
        if (
            lifted_entry in dispatcher_region
            or lifted_entry in reachable_blocks
            or lifted_entry in claimed_targets
        ):
            continue

        source_block = edge_reachable_frontier(
            ordered_path=tuple(int(serial) for serial in edge.ordered_path),
            source_block=int(edge.source_anchor.block_serial),
            reachable_blocks=reachable_blocks,
            dispatcher_region=dispatcher_region,
        )
        if source_block is None:
            continue

        seeds.append(
            EntryIslandRescueSeed(
                source_block=int(source_block),
                lifted_entry=int(lifted_entry),
            )
        )

    return tuple(seeds)


def collect_late_entry_island_rescue_seeds(
    dag: LinearizedStateDag,
    *,
    projected_flow_graph,
    reachable_blocks: set[int],
    dispatcher_region: set[int],
) -> tuple[LateEntryIslandRescueSeed, ...]:
    seeds: list[LateEntryIslandRescueSeed] = []

    for edge in dag.edges:
        if edge.target_entry_anchor is None:
            continue
        target_entry = int(edge.target_entry_anchor)
        if target_entry not in dispatcher_region:
            continue

        target_snapshot = projected_flow_graph.get_block(target_entry)
        if target_snapshot is None:
            continue

        source_block = edge_reachable_frontier(
            ordered_path=tuple(int(serial) for serial in edge.ordered_path),
            source_block=int(edge.source_anchor.block_serial),
            reachable_blocks=reachable_blocks,
            dispatcher_region=dispatcher_region,
        )

        for succ in sorted(int(s) for s in target_snapshot.succs):
            if succ in dispatcher_region or succ in reachable_blocks:
                continue
            seeds.append(
                LateEntryIslandRescueSeed(
                    source_block=(
                        int(source_block) if source_block is not None else None
                    ),
                    lifted_entry=int(succ),
                    passthrough_block=int(target_entry),
                    edge_source_block=int(edge.source_anchor.block_serial),
                )
            )

    return tuple(seeds)


def collect_late_entry_island_diagnostics(
    projected_flow_graph,
    *,
    reachable_blocks: set[int],
    dispatcher_region: set[int],
    dispatcher,
) -> tuple[LateEntryIslandDiagnostic, ...]:
    diagnostics: list[LateEntryIslandDiagnostic] = []
    for serial in sorted(int(s) for s in projected_flow_graph.blocks):
        if serial in reachable_blocks or serial in dispatcher_region:
            continue
        snap = projected_flow_graph.get_block(serial)
        if snap is None:
            continue
        preds = tuple(int(p) for p in snap.preds)
        if not preds or not all(pred in dispatcher_region for pred in preds):
            continue
        search_targets = {serial, *preds}
        rows_info = tuple(
            f"[0x{row.lo:X}..0x{row.hi:X})->blk[{row.target}]"
            for row in getattr(dispatcher, "_rows", ())
            if int(row.target) in search_targets
        )
        diagnostics.append(
            LateEntryIslandDiagnostic(
                block_serial=serial,
                bst_preds=preds,
                dispatcher_rows=rows_info,
            )
        )
    return tuple(diagnostics)


__all__ = [
    "EntryIslandRescueSeed",
    "LateEntryIslandDiagnostic",
    "LateEntryIslandRescueSeed",
    "collect_entry_island_rescue_seeds",
    "collect_late_entry_island_diagnostics",
    "collect_late_entry_island_rescue_seeds",
]
