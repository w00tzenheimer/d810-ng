from __future__ import annotations

from collections import defaultdict
from dataclasses import replace

from d810.cfg.reconstruction_lowering import SharedGroupEmissionCandidate
from d810.cfg.reconstruction_modification_planning import (
    plan_conditional_arm_reconstruction_modifications,
    plan_direct_reconstruction_modifications,
    plan_passthrough_reconstruction_modifications,
    plan_shared_group_reconstruction_modifications,
)
from d810.optimizers.microcode.flow.flattening.hodur._helpers import blk_label
from d810.recon.flow.edge_metadata import make_edge_metadata
from d810.recon.flow.linearized_state_dag import SemanticEdgeKind


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
    ordered_input_candidates = tuple(
        SharedGroupEmissionCandidate(
            via_pred=int(candidate.via_pred),
            target_entry=int(candidate.target_entry),
        )
        for candidate in candidates
        if candidate.via_pred is not None
    )
    if not ordered_input_candidates:
        return 0

    shared_plan = plan_shared_group_reconstruction_modifications(
        flow_graph=flow_graph,
        shared_block=int(shared_block),
        ordered_path=tuple(int(serial) for serial in candidates[0].edge.ordered_path),
        shared_candidates=ordered_input_candidates,
    )
    if not shared_plan.accepted:
        rejected_metadata.extend(
            make_edge_metadata(
                candidate.edge,
                horizon_block=candidate.horizon_block,
                site=candidate.site,
                target_entry=candidate.target_entry,
                first_shared_block=shared_block,
                via_pred=candidate.via_pred,
                rejection_reason=shared_plan.rejection_reason,
            )
            for candidate in candidates
            if candidate.via_pred is not None
        )
        return 0
    by_pred = {
        int(candidate.via_pred): candidate
        for candidate in candidates
        if candidate.via_pred is not None
    }
    ordered_candidates = [
        by_pred[int(via_pred)] for via_pred in shared_plan.ordered_via_preds
    ]
    modifications.extend(shared_plan.modifications)
    owned_blocks.add(int(shared_block))
    for _, target_entry in shared_plan.per_pred_targets:
        owned_edges.add((int(shared_block), int(target_entry)))
    for candidate in ordered_candidates:
        record_accept_metadata(
            accepted_metadata,
            replace(candidate, emission_mode="duplicate_and_redirect"),
        )
    logger.info(
        "RECON DAG: duplicate-and-redirect %s preds=%s",
        blk_label(mba, shared_block),
        [
            (blk_label(mba, pred), blk_label(mba, target))
            for pred, target in shared_plan.per_pred_targets
        ],
    )
    return len(ordered_candidates)


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
    direct_groups: defaultdict[int, list] = defaultdict(list)
    shared_groups: defaultdict[int, list] = defaultdict(list)
    conditional_arm_candidates: list = []
    for candidate in raw_candidates:
        if candidate.emission_mode == "conditional_arm":
            conditional_arm_candidates.append(candidate)
        elif candidate.emission_mode == "direct":
            direct_groups[int(candidate.horizon_block)].append(candidate)
        else:
            assert candidate.first_shared_block is not None
            shared_groups[int(candidate.first_shared_block)].append(candidate)

    for candidate in conditional_arm_candidates:
        source_node = node_by_key.get(candidate.edge.source_key)
        pt_entry: int | None = None
        if source_node is not None and candidate.edge.source_key.state_const is not None:
            pt_entry = source_node.entry_anchor

        cond_plan = plan_conditional_arm_reconstruction_modifications(
            flow_graph=flow_graph,
            horizon_block=int(candidate.horizon_block),
            target_entry=int(candidate.target_entry),
            branch_arm=int(candidate.edge.source_anchor.branch_arm or 0),
            dispatcher_serial=dispatcher_serial,
            current_entry=pt_entry,
        )
        if cond_plan.modifications:
            modifications.extend(cond_plan.modifications)
            owned_blocks.add(int(candidate.horizon_block))
            owned_edges.add((int(candidate.horizon_block), int(candidate.target_entry)))
            record_accept_metadata(accepted_metadata, candidate)

            pt_plan = plan_passthrough_reconstruction_modifications(
                flow_graph=flow_graph,
                ordered_path=tuple(int(serial) for serial in candidate.edge.ordered_path),
                horizon_block=int(candidate.horizon_block),
                dispatcher_serial=dispatcher_serial,
                current_state_entry=pt_entry,
            )
            modifications.extend(pt_plan.modifications)

            logger.info(
                "RECON DAG: conditional_arm %s state=0x%08X -> %s (arm=%d, redirects=%d, passthrough=%d)",
                blk_label(mba, candidate.horizon_block),
                candidate.site.state_value & 0xFFFFFFFF,
                blk_label(mba, candidate.target_entry),
                candidate.edge.source_anchor.branch_arm or 0,
                len(cond_plan.modifications),
                len(pt_plan.modifications),
            )

    for horizon_block in sorted(direct_groups):
        group = direct_groups[horizon_block]
        targets = {candidate.target_entry for candidate in group}
        if len(targets) > 1:
            rejected_metadata.extend(
                make_edge_metadata(
                    candidate.edge,
                    horizon_block=candidate.horizon_block,
                    site=candidate.site,
                    target_entry=candidate.target_entry,
                    first_shared_block=candidate.first_shared_block,
                    rejection_reason="direct_conflict",
                )
                for candidate in group
            )
            continue
        direct_candidate = group[0]
        direct_plan = plan_direct_reconstruction_modifications(
            flow_graph=flow_graph,
            horizon_block=int(direct_candidate.horizon_block),
            target_entry=int(direct_candidate.target_entry),
            ordered_path=tuple(int(serial) for serial in direct_candidate.edge.ordered_path),
        )
        if not direct_plan.accepted:
            rejected_metadata.append(
                make_edge_metadata(
                    direct_candidate.edge,
                    horizon_block=direct_candidate.horizon_block,
                    site=direct_candidate.site,
                    target_entry=direct_candidate.target_entry,
                    first_shared_block=direct_candidate.first_shared_block,
                    rejection_reason="noop_or_missing_old_target",
                )
            )
            continue
        modifications.extend(direct_plan.modifications)
        owned_blocks.add(int(direct_candidate.horizon_block))
        owned_edges.add((int(direct_candidate.horizon_block), int(direct_candidate.target_entry)))
        record_accept_metadata(accepted_metadata, direct_candidate)
        logger.info(
            "RECON DAG: direct %s state=0x%08X -> %s (nopped=%d)",
            blk_label(mba, direct_candidate.horizon_block),
            direct_candidate.site.state_value & 0xFFFFFFFF,
            blk_label(mba, direct_candidate.target_entry),
            1,
        )
        if direct_candidate.edge.kind == SemanticEdgeKind.CONDITIONAL_TRANSITION:
            source_node = node_by_key.get(direct_candidate.edge.source_key)
            pt_entry_d: int | None = None
            if (
                source_node is not None
                and direct_candidate.edge.source_key.state_const is not None
            ):
                pt_entry_d = source_node.entry_anchor
            pt_plan_d = plan_passthrough_reconstruction_modifications(
                flow_graph=flow_graph,
                ordered_path=tuple(int(serial) for serial in direct_candidate.edge.ordered_path),
                horizon_block=int(direct_candidate.horizon_block),
                dispatcher_serial=dispatcher_serial,
                current_state_entry=pt_entry_d,
            )
            modifications.extend(pt_plan_d.modifications)

    for shared_block in sorted(shared_groups):
        group = shared_groups[shared_block]
        emit_shared_group_modifications(
            logger,
            shared_block,
            group,
            flow_graph=flow_graph,
            mba=mba,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            accepted_metadata=accepted_metadata,
            rejected_metadata=rejected_metadata,
        )


__all__ = [
    "emit_shared_group_modifications",
    "emit_primary_reconstruction_modifications",
    "record_accept_metadata",
]
