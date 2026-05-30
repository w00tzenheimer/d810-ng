"""Emitter for missing-via-pred direct-override plans.

Takes a ``MissingViaPredOverridePlan`` discovered by
``d810.analyses.control_flow.missing_via_pred_discovery.discover_missing_via_pred_direct_overrides``
and applies the two-variant direct+passthrough emission originally encoded in
``reconstruction._emit_missing_via_pred_direct_override``.

Variant order (``raw`` then ``corrected``) and all log messages / metadata
shapes are byte-identical to the pre-extraction helper. The emitter returns
``bool``: ``True`` iff either variant (or the DOWNSTREAM_HEAD_RESCUE bypass)
emitted a successful direct override.
"""
from __future__ import annotations

from collections import Counter
from d810.core.typing import TYPE_CHECKING, Callable

from d810.core import logging
from d810.transforms.modification_builder import ModificationBuilder
from d810.transforms.reconstruction_modification_planning import (
    plan_direct_reconstruction_modifications,
    plan_passthrough_reconstruction_modifications,
)

if TYPE_CHECKING:
    from d810.analyses.control_flow.missing_via_pred_discovery import (
        DownstreamHeadRescuePlan,
        MissingViaPredOverridePlan,
    )

logger = logging.getLogger(
    "D810.hodur.strategy.state_write_reconstruction",
    logging.DEBUG,
)

__all__ = ["emit_missing_via_pred_direct_overrides"]


BlkLabelFn = Callable[[object, int], str]
EdgeMetadataFn = Callable[..., dict[str, int | str | None]]


def _try_edge_set(
    *,
    matching_edges: tuple[object, ...],
    raw_matching_edges: tuple[object, ...],
    variant: str,
    force_edge: tuple[int, int],
    region_name: str,
    flow_graph,
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    accepted_metadata: list[dict[str, int | str | None]],
    structured_region_accepted_counts: Counter,
    structured_region_accepted_pairs: dict[str, set[tuple[int, int]]],
    builder: ModificationBuilder,
    node_by_key: dict,
    dispatcher_serial: int,
    mba,
    blk_label: BlkLabelFn,
    edge_metadata_fn: EdgeMetadataFn,
    downstream_head_rescue: "DownstreamHeadRescuePlan | None",
) -> tuple[bool, int | None, int | None, tuple[int, ...] | None]:
    source_blocks = {
        int(getattr(getattr(edge, "source_anchor", None), "block_serial", -1))
        for edge in matching_edges
    }
    source_blocks.discard(-1)
    target_entries = {
        int(getattr(edge, "target_entry_anchor"))
        for edge in matching_edges
        if getattr(edge, "target_entry_anchor", None) is not None
    }
    if len(source_blocks) != 1 or len(target_entries) != 1:
        return False, None, None, None

    source_block = next(iter(source_blocks))
    target_entry = next(iter(target_entries))
    source_snapshot = flow_graph.get_block(int(source_block))
    if source_snapshot is None or int(getattr(source_snapshot, "nsucc", 0)) != 1:
        return False, None, None, None

    target_snapshot = flow_graph.get_block(int(target_entry))
    if target_snapshot is None or int(getattr(target_snapshot, "nsucc", 0)) != 1:
        logger.info(
            "RECON DAG: structured region direct-source override skipped %s for %s via %s target=%s variant=%s reason=complex_target_nsucc_%s",
            region_name,
            "0x%08X->0x%08X" % force_edge,
            blk_label(mba, int(source_block)),
            blk_label(mba, int(target_entry)),
            variant,
            (
                "missing"
                if target_snapshot is None
                else int(getattr(target_snapshot, "nsucc", 0))
            ),
        )
        return False, None, None, None

    ordered_path = tuple(int(serial) for serial in (matching_edges[0].ordered_path or ()))
    if not ordered_path:
        ordered_path = (int(source_block),)
    direct_plan = plan_direct_reconstruction_modifications(
        flow_graph=flow_graph,
        horizon_block=int(source_block),
        target_entry=int(target_entry),
        ordered_path=ordered_path,
    )
    if not direct_plan.accepted:
        logger.info(
            "RECON DAG: structured region direct-source override rejected %s for %s via %s target=%s variant=%s reason=%s",
            region_name,
            "0x%08X->0x%08X" % force_edge,
            blk_label(mba, int(source_block)),
            blk_label(mba, int(target_entry)),
            variant,
            direct_plan.rejection_reason,
        )
        return False, None, None, None

    modifications.extend(direct_plan.modifications)
    owned_blocks.add(int(source_block))
    owned_edges.add((int(source_block), int(target_entry)))
    passthrough_count = 0
    if (
        getattr(getattr(matching_edges[0], "kind", None), "name", None)
        == "CONDITIONAL_TRANSITION"
    ):
        source_key = getattr(matching_edges[0], "source_key", None)
        source_node = node_by_key.get(source_key)
        pt_entry_direct: int | None = None
        if (
            source_node is not None
            and getattr(source_key, "state_const", None) is not None
        ):
            pt_entry_direct = int(source_node.entry_anchor)
        pt_plan_direct = plan_passthrough_reconstruction_modifications(
            flow_graph=flow_graph,
            ordered_path=ordered_path,
            horizon_block=int(source_block),
            dispatcher_serial=dispatcher_serial,
            current_state_entry=pt_entry_direct,
        )
        modifications.extend(pt_plan_direct.modifications)
        passthrough_count = len(pt_plan_direct.modifications)

    # Sub_7FFD DOWNSTREAM_HEAD_RESCUE bypass: fires only inside the corrected
    # variant when source_block/target_entry match the expected anchors and the
    # raw matching edges point at the rescue target.
    if (
        downstream_head_rescue is not None
        and variant == "corrected"
        and int(source_block) == downstream_head_rescue.expected_source_block
        and int(target_entry) == downstream_head_rescue.expected_target_entry
        and raw_matching_edges
    ):
        raw_target_entries = {
            int(getattr(edge, "target_entry_anchor"))
            for edge in raw_matching_edges
            if getattr(edge, "target_entry_anchor", None) is not None
        }
        if raw_target_entries == set(downstream_head_rescue.raw_target_entries_requirement):
            rescue_mod = builder.edge_redirect(
                source_block=downstream_head_rescue.rescue_source,
                target_block=downstream_head_rescue.rescue_target,
                via_pred=int(source_block),
            )
            modifications.append(rescue_mod)
            owned_blocks.add(downstream_head_rescue.rescue_source)
            owned_edges.add(
                (
                    downstream_head_rescue.rescue_source,
                    downstream_head_rescue.rescue_target,
                )
            )
            logger.info(
                "RECON DAG: structured region corrected head rescue %s forced %s via %s rescue=%s->%s",
                region_name,
                "0x%08X->0x%08X" % force_edge,
                blk_label(mba, int(source_block)),
                blk_label(mba, downstream_head_rescue.rescue_source),
                blk_label(mba, downstream_head_rescue.rescue_target),
            )

    accepted_metadata.append(
        edge_metadata_fn(
            matching_edges[0],
            horizon_block=int(source_block),
            target_entry=int(target_entry),
            emission_mode=(
                "structured_head_direct"
                if variant == "raw"
                else "structured_head_corrected_direct"
            ),
        )
    )
    structured_region_accepted_counts[region_name] += 1
    structured_region_accepted_pairs[region_name].add(force_edge)
    logger.info(
        "RECON DAG: structured region direct-source override %s forced %s via %s target=%s variant=%s passthrough=%d",
        region_name,
        "0x%08X->0x%08X" % force_edge,
        blk_label(mba, int(source_block)),
        blk_label(mba, int(target_entry)),
        variant,
        passthrough_count,
    )
    return True, int(source_block), int(target_entry), ordered_path


def emit_missing_via_pred_direct_overrides(
    plan: "MissingViaPredOverridePlan",
    *,
    builder: ModificationBuilder,
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    accepted_metadata: list[dict[str, int | str | None]],
    structured_region_edge_pairs: set[tuple[str, int, int]],
    structured_region_accepted_counts: Counter,
    structured_region_accepted_pairs: dict[str, set[tuple[int, int]]],
    node_by_key: dict,
    dispatcher_serial: int,
    flow_graph,
    mba,
    blk_label: BlkLabelFn,
    edge_metadata_fn: EdgeMetadataFn,
) -> bool:
    """Apply a missing-via-pred override plan in raw-then-corrected order.

    Returns ``True`` iff either variant emitted a successful direct override
    (optionally followed by the DOWNSTREAM_HEAD_RESCUE bypass). Returns
    ``False`` when neither variant is eligible or both variants' inner
    classification rejects the attempt.

    ``structured_region_edge_pairs`` is accepted for call-site API stability
    (the original helper took it in its kwargs-only signature); it is not read
    by the emitter today.
    """
    del structured_region_edge_pairs  # preserved for API stability; unused

    # Raw variant always attempted first.
    accepted, _src, _tgt, _path = _try_edge_set(
        matching_edges=plan.raw_matching_edges,
        raw_matching_edges=plan.raw_matching_edges,
        variant="raw",
        force_edge=plan.force_edge,
        region_name=plan.region_name,
        flow_graph=flow_graph,
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        accepted_metadata=accepted_metadata,
        structured_region_accepted_counts=structured_region_accepted_counts,
        structured_region_accepted_pairs=structured_region_accepted_pairs,
        builder=builder,
        node_by_key=node_by_key,
        dispatcher_serial=dispatcher_serial,
        mba=mba,
        blk_label=blk_label,
        edge_metadata_fn=edge_metadata_fn,
        downstream_head_rescue=plan.downstream_head_rescue,
    )
    if accepted:
        return True

    # Corrected variant short-circuit (sub_7FFD downstream head carve-out).
    if plan.corrected_disabled_reason is not None:
        logger.info(
            "RECON DAG: structured region corrected direct-source override disabled for %s %s; leaving head edge to bridge/postprocess",
            plan.region_name,
            "0x%08X->0x%08X" % plan.force_edge,
        )
        return False

    if plan.corrected_matching_edges:
        accepted, _src, _tgt, _path = _try_edge_set(
            matching_edges=plan.corrected_matching_edges,
            raw_matching_edges=plan.raw_matching_edges,
            variant="corrected",
            force_edge=plan.force_edge,
            region_name=plan.region_name,
            flow_graph=flow_graph,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            accepted_metadata=accepted_metadata,
            structured_region_accepted_counts=structured_region_accepted_counts,
            structured_region_accepted_pairs=structured_region_accepted_pairs,
            builder=builder,
            node_by_key=node_by_key,
            dispatcher_serial=dispatcher_serial,
            mba=mba,
            blk_label=blk_label,
            downstream_head_rescue=plan.downstream_head_rescue,
        )
        if accepted:
            return True

    return False
