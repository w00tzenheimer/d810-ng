from __future__ import annotations

from dataclasses import replace

from d810.cfg.reconstruction_execution import (
    execute_primary_reconstruction_modifications as run_primary_reconstruction_execution,
    execute_shared_group_reconstruction as run_shared_group_reconstruction,
)
from d810.optimizers.microcode.flow.flattening.hodur._helpers import blk_label
from d810.recon.flow.edge_metadata import make_edge_metadata


def record_accept_metadata(
    metadata: list[dict[str, int | str | None]],
    candidate,
) -> None:
    metadata.append(
        make_edge_metadata(
            candidate.edge,
            horizon_block=candidate.horizon_block,
            site=candidate.site,
            target_entry=candidate.target_entry,
            first_shared_block=candidate.first_shared_block,
            via_pred=candidate.via_pred,
            emission_mode=candidate.emission_mode,
        )
    )


def emit_shared_group_modifications(
    logger,
    shared_block: int,
    candidates: list,
    *,
    flow_graph,
    mba,
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    accepted_metadata: list[dict[str, int | str | None]],
    rejected_metadata: list[dict[str, int | str | None]],
) -> int:
    shared_result = run_shared_group_reconstruction(
        shared_block=int(shared_block),
        candidates=candidates,
        flow_graph=flow_graph,
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
    )
    if not shared_result.accepted_candidates and not shared_result.rejected_candidates:
        return 0

    if shared_result.rejected_candidates:
        rejected_metadata.extend(
            make_edge_metadata(
                candidate.edge,
                horizon_block=candidate.horizon_block,
                site=candidate.site,
                target_entry=candidate.target_entry,
                first_shared_block=shared_block,
                via_pred=candidate.via_pred,
                rejection_reason=shared_result.rejection_reason,
            )
            for candidate in shared_result.rejected_candidates
        )
        return 0
    for candidate in shared_result.accepted_candidates:
        record_accept_metadata(
            accepted_metadata,
            replace(candidate, emission_mode="duplicate_and_redirect"),
        )
    logger.info(
        "RECON DAG: duplicate-and-redirect %s preds=%s",
        blk_label(mba, shared_block),
        [
            (blk_label(mba, pred), blk_label(mba, target))
            for pred, target in shared_result.per_pred_targets
        ],
    )
    return len(shared_result.accepted_candidates)


def emit_primary_reconstruction_modifications(
    logger,
    *,
    raw_candidates: list,
    flow_graph,
    node_by_key,
    dispatcher_serial: int,
    mba,
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    accepted_metadata: list[dict[str, int | str | None]],
    rejected_metadata: list[dict[str, int | str | None]],
) -> None:
    run = run_primary_reconstruction_execution(
        raw_candidates=raw_candidates,
        flow_graph=flow_graph,
        node_by_key=node_by_key,
        dispatcher_serial=dispatcher_serial,
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
    )

    for result in run.conditional_results:
        candidate = result.candidate
        record_accept_metadata(accepted_metadata, candidate)
        logger.info(
            "RECON DAG: conditional_arm %s state=0x%08X -> %s (arm=%d, redirects=%d, passthrough=%d)",
            blk_label(mba, candidate.horizon_block),
            candidate.site.state_value & 0xFFFFFFFF,
            blk_label(mba, candidate.target_entry),
            candidate.edge.source_anchor.branch_arm or 0,
            result.redirect_count,
            result.passthrough_count,
        )

    for result in run.direct_results:
        if result.accepted_candidate is not None:
            candidate = result.accepted_candidate
            record_accept_metadata(accepted_metadata, candidate)
            logger.info(
                "RECON DAG: direct %s state=0x%08X -> %s (nopped=%d)",
                blk_label(mba, candidate.horizon_block),
                candidate.site.state_value & 0xFFFFFFFF,
                blk_label(mba, candidate.target_entry),
                1,
            )
            continue

        rejected_metadata.extend(
            make_edge_metadata(
                candidate.edge,
                horizon_block=candidate.horizon_block,
                site=candidate.site,
                target_entry=candidate.target_entry,
                first_shared_block=candidate.first_shared_block,
                rejection_reason=result.rejection_reason,
            )
            for candidate in result.rejected_candidates
        )

    for result in run.shared_group_results:
        if result.rejected_candidates:
            rejected_metadata.extend(
                make_edge_metadata(
                    candidate.edge,
                    horizon_block=candidate.horizon_block,
                    site=candidate.site,
                    target_entry=candidate.target_entry,
                    first_shared_block=result.shared_block,
                    via_pred=candidate.via_pred,
                    rejection_reason=result.rejection_reason,
                )
                for candidate in result.rejected_candidates
            )
            continue
        if not result.accepted_candidates:
            continue
        for candidate in result.accepted_candidates:
            record_accept_metadata(
                accepted_metadata,
                replace(candidate, emission_mode="duplicate_and_redirect"),
            )
        logger.info(
            "RECON DAG: duplicate-and-redirect %s preds=%s",
            blk_label(mba, result.shared_block),
            [
                (blk_label(mba, pred), blk_label(mba, target))
                for pred, target in result.per_pred_targets
            ],
        )


__all__ = [
    "emit_shared_group_modifications",
    "emit_primary_reconstruction_modifications",
    "record_accept_metadata",
]
