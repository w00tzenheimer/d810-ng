"""Emitter for structured-region force-edge override plans.

Takes a ``ForceEdgeOverridePlan`` discovered by
``d810.recon.flow.force_edge_override_discovery.discover_force_edge_overrides``
and applies the multi-variant fallback emission originally inlined in
``reconstruction.plan`` at L1176-L1582.

Variant-by-variant behavior (byte-identical to the pre-extraction block):

 * ``already_accepted`` — log nothing, skip (the producer simply returns
   without calling the emitter for this case; we still accept it as a
   defensive no-op).
 * ``deferred`` — log the deferral line and skip.
 * ``no_candidates``:
    1. Log the status line.
    2. Attempt a cached direct-override replay (``cache_read``). On success
       emit modifications, append accepted metadata, return.
    3. Call ``discover_missing_via_pred_direct_overrides`` +
       ``emit_missing_via_pred_direct_overrides`` for the retry path.
 * ``override_attempt``:
    1. Log the status line.
    2. ``execute_shared_group_reconstruction`` (force_clone=True).
    3. On failure, retry with the full shared-block group. On success log +
       replace the existing shared_group_results entry.
    4. On second failure, try the mixed-group direct override path (one
       shared target + one shared horizon). On success write the cache and
       record metadata for every grouped candidate.
    5. On second failure without a mixed-group match, try single-candidate
       direct override. On success write the cache and record metadata for
       the single candidate.

All log messages and side effects match the original inline block
byte-for-byte. The class-scoped cache is accessed via callable
``cache_read`` / ``cache_write`` handles threaded from the strategy.
"""
from __future__ import annotations

from dataclasses import replace
from d810.core.typing import TYPE_CHECKING, Callable

from d810.core import logging
from d810.cfg.modification_builder import ModificationBuilder
from d810.cfg.reconstruction_execution import (
    execute_shared_group_reconstruction,
)
from d810.cfg.reconstruction_missing_via_pred_emission import (
    emit_missing_via_pred_direct_overrides,
)
from d810.cfg.reconstruction_modification_planning import (
    plan_direct_reconstruction_modifications,
    plan_passthrough_reconstruction_modifications,
)

if TYPE_CHECKING:
    from d810.recon.flow.force_edge_override_discovery import (
        ForceEdgeOverridePlan,
    )
    from d810.recon.flow.missing_via_pred_discovery import (
        MissingViaPredOverridePlan,
    )
    from d810.cfg.reconstruction_recording import RoundAcceptLedger

logger = logging.getLogger(
    "D810.hodur.strategy.state_write_reconstruction",
    logging.DEBUG,
)

__all__ = ["execute_force_edge_override"]


BlkLabelFn = Callable[[object, int], str]
EdgeMetadataFn = Callable[..., dict[str, int | str | None]]
StateEdgePairFn = Callable[[object], tuple[int, int] | None]

CacheKey = tuple[int, int, tuple[int, int]]
CacheValue = tuple[int, int, tuple[int, ...]]
CacheReadFn = Callable[[CacheKey], "CacheValue | None"]
CacheWriteFn = Callable[[CacheKey, CacheValue], None]

DiscoverMissingViaPredFn = Callable[..., "MissingViaPredOverridePlan | None"]


def execute_force_edge_override(
    plan: "ForceEdgeOverridePlan",
    *,
    # Context
    mba,
    flow_graph,
    builder: ModificationBuilder,
    dispatcher_serial: int,
    node_by_key: dict,
    cache_key: tuple[int, int],
    # Round-scoped mutable state
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    shared_group_results: list,
    ledger: "RoundAcceptLedger",
    # Region indexes
    structured_region_edge_pairs: set[tuple[str, int, int]],
    structured_region_edges_by_pair,
    corrected_region_edges_by_pair,
    shared_group_candidates_by_block,
    rejected_metadata: list[dict[str, int | str | None]],
    # Callable handles
    cache_read: CacheReadFn,
    cache_write: CacheWriteFn,
    blk_label: BlkLabelFn,
    edge_metadata_fn: EdgeMetadataFn,
    state_edge_pair_fn: StateEdgePairFn,
    discover_missing_via_pred_fn: DiscoverMissingViaPredFn,
) -> None:
    """Apply one force-edge override plan in-place.

    Mutates ``modifications``, ``owned_blocks``, ``owned_edges``,
    ``shared_group_results`` (via slice assignment), and
    ``ledger.accepted_metadata`` /
    ``ledger.structured_region_accepted_counts`` /
    ``ledger.structured_region_accepted_pairs``.
    """
    variant = plan.variant
    if variant == "already_accepted":
        return

    region_name = plan.region_name
    force_edge = plan.force_edge
    override_candidates = list(plan.override_candidates)

    if variant == "deferred":
        logger.info(
            "RECON DAG: deferring structured region force-edge %s region=%s to bridge/postprocess because live pass has no direct override candidate",
            "0x%08X->0x%08X" % force_edge,
            region_name,
        )
        return

    # Status line — identical to original (byte-for-byte).
    logger.info(
        "RECON DAG: force-edge status %s region=%s override_candidates=%d shared_blocks=%s",
        "0x%08X->0x%08X" % force_edge,
        region_name,
        len(override_candidates),
        sorted(
            {
                int(candidate.first_shared_block)
                for candidate in override_candidates
                if candidate.first_shared_block is not None
            }
        ),
    )

    if variant == "no_candidates":
        _execute_no_candidates_variant(
            plan=plan,
            mba=mba,
            flow_graph=flow_graph,
            builder=builder,
            dispatcher_serial=dispatcher_serial,
            node_by_key=node_by_key,
            cache_key=cache_key,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            ledger=ledger,
            structured_region_edge_pairs=structured_region_edge_pairs,
            structured_region_edges_by_pair=structured_region_edges_by_pair,
            corrected_region_edges_by_pair=corrected_region_edges_by_pair,
            rejected_metadata=rejected_metadata,
            cache_read=cache_read,
            blk_label=blk_label,
            edge_metadata_fn=edge_metadata_fn,
            discover_missing_via_pred_fn=discover_missing_via_pred_fn,
        )
        return

    # variant == "override_attempt"
    shared_block = plan.shared_block
    if shared_block is None:
        return

    _execute_override_attempt_variant(
        plan=plan,
        shared_block=shared_block,
        override_candidates=override_candidates,
        mba=mba,
        flow_graph=flow_graph,
        dispatcher_serial=dispatcher_serial,
        node_by_key=node_by_key,
        cache_key=cache_key,
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        shared_group_results=shared_group_results,
        ledger=ledger,
        structured_region_edge_pairs=structured_region_edge_pairs,
        shared_group_candidates_by_block=shared_group_candidates_by_block,
        cache_write=cache_write,
        blk_label=blk_label,
        edge_metadata_fn=edge_metadata_fn,
        state_edge_pair_fn=state_edge_pair_fn,
    )


def _execute_no_candidates_variant(
    *,
    plan: "ForceEdgeOverridePlan",
    mba,
    flow_graph,
    builder: ModificationBuilder,
    dispatcher_serial: int,
    node_by_key: dict,
    cache_key: tuple[int, int],
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    ledger: "RoundAcceptLedger",
    structured_region_edge_pairs: set[tuple[str, int, int]],
    structured_region_edges_by_pair,
    corrected_region_edges_by_pair,
    rejected_metadata: list[dict[str, int | str | None]],
    cache_read: CacheReadFn,
    blk_label: BlkLabelFn,
    edge_metadata_fn: EdgeMetadataFn,
    discover_missing_via_pred_fn: DiscoverMissingViaPredFn,
) -> None:
    """Handle ``no_candidates`` variant.

    First attempts the cached direct-override replay; on failure or miss,
    falls through to the ``missing_via_pred`` retry path via the already-
    extracted emitter.
    """
    region_name = plan.region_name
    force_edge = plan.force_edge

    cached_direct_override = cache_read((cache_key[0], cache_key[1], force_edge))
    if cached_direct_override is not None:
        cached_source_block, cached_target_entry, cached_ordered_path = (
            cached_direct_override
        )
        cached_direct_plan = plan_direct_reconstruction_modifications(
            flow_graph=flow_graph,
            horizon_block=int(cached_source_block),
            target_entry=int(cached_target_entry),
            ordered_path=tuple(int(serial) for serial in cached_ordered_path),
        )
        if (
            not cached_direct_plan.accepted
            and tuple(int(serial) for serial in cached_ordered_path)
            != (int(cached_source_block),)
        ):
            logger.info(
                "RECON DAG: cached force-edge direct override %s rejected for %s via %s target=%s reason=%s ordered_path=%s; retrying with horizon-only path",
                region_name,
                "0x%08X->0x%08X" % force_edge,
                blk_label(mba, cached_source_block),
                blk_label(mba, cached_target_entry),
                cached_direct_plan.rejection_reason,
                tuple(int(serial) for serial in cached_ordered_path),
            )
            cached_direct_plan = plan_direct_reconstruction_modifications(
                flow_graph=flow_graph,
                horizon_block=int(cached_source_block),
                target_entry=int(cached_target_entry),
                ordered_path=(int(cached_source_block),),
            )
        if cached_direct_plan.accepted:
            modifications.extend(cached_direct_plan.modifications)
            owned_blocks.add(int(cached_source_block))
            owned_edges.add(
                (int(cached_source_block), int(cached_target_entry))
            )
            passthrough_count = 0
            cached_matching_edges = list(
                structured_region_edges_by_pair.get(force_edge, ())
            ) or list(corrected_region_edges_by_pair.get(force_edge, ()))
            if cached_matching_edges and (
                getattr(getattr(cached_matching_edges[0], "kind", None), "name", None)
                == "CONDITIONAL_TRANSITION"
            ):
                source_key = getattr(cached_matching_edges[0], "source_key", None)
                source_node = node_by_key.get(source_key)
                pt_entry_direct: int | None = None
                if (
                    source_node is not None
                    and getattr(source_key, "state_const", None) is not None
                ):
                    pt_entry_direct = int(source_node.entry_anchor)
                pt_plan_direct = plan_passthrough_reconstruction_modifications(
                    flow_graph=flow_graph,
                    ordered_path=tuple(int(serial) for serial in cached_ordered_path),
                    horizon_block=int(cached_source_block),
                    dispatcher_serial=dispatcher_serial,
                    current_state_entry=pt_entry_direct,
                )
                modifications.extend(pt_plan_direct.modifications)
                passthrough_count = len(pt_plan_direct.modifications)
            ledger.accepted_metadata.append(
                {
                    "source_state": int(force_edge[0]),
                    "target_state": int(force_edge[1]),
                    "horizon_block": int(cached_source_block),
                    "target_entry": int(cached_target_entry),
                    "emission_mode": "cached_force_edge_direct_override",
                }
            )
            ledger.structured_region_accepted_counts[str(region_name)] += 1
            ledger.structured_region_accepted_pairs[str(region_name)].add(
                force_edge
            )
            logger.info(
                "RECON DAG: cached force-edge direct override %s forced %s via %s target=%s passthrough=%d",
                region_name,
                "0x%08X->0x%08X" % force_edge,
                blk_label(mba, cached_source_block),
                blk_label(mba, cached_target_entry),
                passthrough_count,
            )
            return
        logger.info(
            "RECON DAG: cached force-edge direct override %s failed for %s via %s target=%s reason=%s",
            region_name,
            "0x%08X->0x%08X" % force_edge,
            blk_label(mba, cached_source_block),
            blk_label(mba, cached_target_entry),
            cached_direct_plan.rejection_reason,
        )

    missing_via_pred_plan = discover_missing_via_pred_fn(
        force_edge=force_edge,
        region_name=str(region_name),
        structured_region_edges_by_pair=structured_region_edges_by_pair,
        corrected_region_edges_by_pair=corrected_region_edges_by_pair,
        rejected_metadata=rejected_metadata,
    )
    if missing_via_pred_plan is not None:
        emit_missing_via_pred_direct_overrides(
            missing_via_pred_plan,
            builder=builder,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            accepted_metadata=ledger.accepted_metadata,
            structured_region_edge_pairs=structured_region_edge_pairs,
            structured_region_accepted_counts=ledger.structured_region_accepted_counts,
            structured_region_accepted_pairs=ledger.structured_region_accepted_pairs,
            node_by_key=node_by_key,
            dispatcher_serial=dispatcher_serial,
            flow_graph=flow_graph,
            mba=mba,
            blk_label=blk_label,
            edge_metadata_fn=edge_metadata_fn,
        )


def _execute_override_attempt_variant(
    *,
    plan: "ForceEdgeOverridePlan",
    shared_block: int,
    override_candidates: list,
    mba,
    flow_graph,
    dispatcher_serial: int,
    node_by_key: dict,
    cache_key: tuple[int, int],
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    shared_group_results: list,
    ledger: "RoundAcceptLedger",
    structured_region_edge_pairs: set[tuple[str, int, int]],
    shared_group_candidates_by_block,
    cache_write: CacheWriteFn,
    blk_label: BlkLabelFn,
    edge_metadata_fn: EdgeMetadataFn,
    state_edge_pair_fn: StateEdgePairFn,
) -> None:
    """Handle ``override_attempt`` variant.

    Try shared-group reconstruction, then mixed-group direct, then single-
    candidate direct. Emits cache writes on direct-override success.
    """
    region_name = plan.region_name
    force_edge = plan.force_edge

    override_result = execute_shared_group_reconstruction(
        shared_block=int(shared_block),
        candidates=override_candidates,
        flow_graph=flow_graph,
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        force_clone=True,
    )
    if not override_result.accepted_candidates:
        logger.info(
            "RECON DAG: structured region override %s failed for %s via shared_block=%s reason=%s",
            region_name,
            "0x%08X->0x%08X" % force_edge,
            blk_label(mba, shared_block),
            override_result.rejection_reason,
        )
        group_candidates = list(
            shared_group_candidates_by_block.get(int(shared_block), ())
        )
        if len(group_candidates) != len(override_candidates):
            group_override_result = execute_shared_group_reconstruction(
                shared_block=int(shared_block),
                candidates=group_candidates,
                flow_graph=flow_graph,
                modifications=modifications,
                owned_blocks=owned_blocks,
                owned_edges=owned_edges,
                force_clone=True,
            )
            if group_override_result.accepted_candidates:
                logger.info(
                    "RECON DAG: structured region mixed-group override %s forced shared_block=%s size=%d emission=%s",
                    region_name,
                    blk_label(mba, shared_block),
                    len(group_candidates),
                    group_override_result.emission_mode,
                )
                replacement_done = False
                for idx, existing in enumerate(shared_group_results):
                    if int(existing.shared_block) == int(shared_block):
                        shared_group_results[idx] = group_override_result
                        replacement_done = True
                        break
                if not replacement_done:
                    shared_group_results.append(group_override_result)
                return
            logger.info(
                "RECON DAG: structured region direct override skipped for %s via %s because shared block has mixed group size=%d override_candidates=%d mixed_reason=%s",
                "0x%08X->0x%08X" % force_edge,
                blk_label(mba, shared_block),
                len(group_candidates),
                len(override_candidates),
                group_override_result.rejection_reason,
            )
            group_targets = {
                int(candidate.target_entry) for candidate in group_candidates
            }
            group_horizons = {
                int(candidate.horizon_block) for candidate in group_candidates
            }
            if len(group_targets) != 1 or len(group_horizons) != 1:
                return
            shared_target_entry = next(iter(group_targets))
            shared_horizon_block = next(iter(group_horizons))
            direct_plan = plan_direct_reconstruction_modifications(
                flow_graph=flow_graph,
                horizon_block=int(shared_horizon_block),
                target_entry=int(shared_target_entry),
                ordered_path=tuple(
                    int(serial) for serial in group_candidates[0].edge.ordered_path
                ),
            )
            if not direct_plan.accepted:
                logger.info(
                    "RECON DAG: structured region mixed-group direct override failed for shared_block=%s target=%s reason=%s",
                    blk_label(mba, shared_block),
                    blk_label(mba, shared_target_entry),
                    direct_plan.rejection_reason,
                )
                return
            modifications.extend(direct_plan.modifications)
            owned_blocks.add(int(shared_horizon_block))
            owned_edges.add((int(shared_horizon_block), int(shared_target_entry)))
            passthrough_specs: set[tuple[int, int, int]] = set()
            passthrough_count = 0
            for grouped_candidate in group_candidates:
                if getattr(getattr(grouped_candidate.edge, "kind", None), "name", None) != "CONDITIONAL_TRANSITION":
                    continue
                source_node = node_by_key.get(grouped_candidate.edge.source_key)
                pt_entry_direct: int | None = None
                if (
                    source_node is not None
                    and grouped_candidate.edge.source_key.state_const is not None
                ):
                    pt_entry_direct = source_node.entry_anchor
                pt_plan_direct = plan_passthrough_reconstruction_modifications(
                    flow_graph=flow_graph,
                    ordered_path=tuple(
                        int(serial) for serial in grouped_candidate.edge.ordered_path
                    ),
                    horizon_block=int(grouped_candidate.horizon_block),
                    dispatcher_serial=dispatcher_serial,
                    current_state_entry=pt_entry_direct,
                )
                for modification in pt_plan_direct.modifications:
                    spec = (
                        int(getattr(modification, "from_serial")),
                        int(getattr(modification, "old_target")),
                        int(getattr(modification, "new_target")),
                    )
                    if spec in passthrough_specs:
                        continue
                    passthrough_specs.add(spec)
                    modifications.append(modification)
                    passthrough_count += 1
            logger.info(
                "RECON DAG: structured region mixed-group direct override forced shared_block=%s target=%s size=%d passthrough=%d",
                blk_label(mba, shared_block),
                blk_label(mba, shared_target_entry),
                len(group_candidates),
                passthrough_count,
            )
            shared_group_results[:] = [
                existing
                for existing in shared_group_results
                if int(existing.shared_block) != int(shared_block)
            ]
            for grouped_candidate in group_candidates:
                ledger.record_accept(
                    replace(
                        grouped_candidate,
                        emission_mode="structured_region_mixed_group_direct_override",
                    ),
                    structured_region_edge_pairs=structured_region_edge_pairs,
                    edge_metadata_fn=edge_metadata_fn,
                    state_edge_pair_fn=state_edge_pair_fn,
                )
            cache_write(
                (cache_key[0], cache_key[1], force_edge),
                (
                    int(shared_horizon_block),
                    int(shared_target_entry),
                    tuple(
                        int(serial)
                        for serial in group_candidates[0].edge.ordered_path
                    ),
                ),
            )
            return
        direct_candidate = override_candidates[0]
        direct_plan = plan_direct_reconstruction_modifications(
            flow_graph=flow_graph,
            horizon_block=int(direct_candidate.horizon_block),
            target_entry=int(direct_candidate.target_entry),
            ordered_path=tuple(
                int(serial) for serial in direct_candidate.edge.ordered_path
            ),
        )
        if not direct_plan.accepted:
            logger.info(
                "RECON DAG: structured region direct override failed for %s via %s reason=%s",
                "0x%08X->0x%08X" % force_edge,
                blk_label(mba, direct_candidate.horizon_block),
                direct_plan.rejection_reason,
            )
            return
        modifications.extend(direct_plan.modifications)
        owned_blocks.add(int(direct_candidate.horizon_block))
        owned_edges.add(
            (
                int(direct_candidate.horizon_block),
                int(direct_candidate.target_entry),
            )
        )
        passthrough_count = 0
        if getattr(getattr(direct_candidate.edge, "kind", None), "name", None) == "CONDITIONAL_TRANSITION":
            source_node = node_by_key.get(direct_candidate.edge.source_key)
            pt_entry_direct: int | None = None
            if (
                source_node is not None
                and direct_candidate.edge.source_key.state_const is not None
            ):
                pt_entry_direct = source_node.entry_anchor
            pt_plan_direct = plan_passthrough_reconstruction_modifications(
                flow_graph=flow_graph,
                ordered_path=tuple(
                    int(serial) for serial in direct_candidate.edge.ordered_path
                ),
                horizon_block=int(direct_candidate.horizon_block),
                dispatcher_serial=dispatcher_serial,
                current_state_entry=pt_entry_direct,
            )
            modifications.extend(pt_plan_direct.modifications)
            passthrough_count = len(pt_plan_direct.modifications)
        logger.info(
            "RECON DAG: structured region direct override %s forced %s via %s (passthrough=%d)",
            region_name,
            "0x%08X->0x%08X" % force_edge,
            blk_label(mba, direct_candidate.horizon_block),
            passthrough_count,
        )
        shared_group_results[:] = [
            existing
            for existing in shared_group_results
            if int(existing.shared_block) != int(shared_block)
        ]
        ledger.record_accept(
            replace(
                direct_candidate,
                emission_mode="structured_region_direct_override",
            ),
            structured_region_edge_pairs=structured_region_edge_pairs,
            edge_metadata_fn=edge_metadata_fn,
            state_edge_pair_fn=state_edge_pair_fn,
        )
        cache_write(
            (cache_key[0], cache_key[1], force_edge),
            (
                int(direct_candidate.horizon_block),
                int(direct_candidate.target_entry),
                tuple(
                    int(serial) for serial in direct_candidate.edge.ordered_path
                ),
            ),
        )
        return

    logger.info(
        "RECON DAG: structured region override %s forced %s via %s emission=%s",
        region_name,
        "0x%08X->0x%08X" % force_edge,
        blk_label(mba, shared_block),
        override_result.emission_mode,
    )
    replacement_done = False
    for idx, existing in enumerate(shared_group_results):
        if int(existing.shared_block) == int(shared_block):
            shared_group_results[idx] = override_result
            replacement_done = True
            break
    if not replacement_done:
        shared_group_results.append(override_result)
