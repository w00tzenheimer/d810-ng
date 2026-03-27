from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EntryIslandRescueOption:
    """One projected-CFG rescue candidate for an unreachable semantic entry island."""

    source_block: int
    lifted_entry: int
    old_target: int
    via_pred: int | None = None


def build_entry_island_rescue_options(
    source_block: int,
    *,
    lifted_entry: int,
    projected_flow_graph,
    reachable_blocks: set[int],
    dispatcher_region: set[int],
    claimed_sources: set[int],
) -> tuple[EntryIslandRescueOption, ...]:
    if source_block in claimed_sources:
        return ()

    source_snapshot = projected_flow_graph.get_block(source_block)
    if source_snapshot is None or source_snapshot.nsucc != 1:
        return ()

    old_target = int(source_snapshot.succs[0])
    if old_target == lifted_entry:
        return ()

    options = [
        EntryIslandRescueOption(
            source_block=source_block,
            lifted_entry=lifted_entry,
            old_target=old_target,
        )
    ]
    for pred_serial in sorted(int(pred) for pred in source_snapshot.preds):
        if pred_serial in dispatcher_region or pred_serial in claimed_sources:
            continue
        if pred_serial not in reachable_blocks:
            continue
        options.append(
            EntryIslandRescueOption(
                source_block=source_block,
                lifted_entry=lifted_entry,
                old_target=old_target,
                via_pred=pred_serial,
            )
        )
    return tuple(options)


def build_entry_island_rescue_modification(
    option: EntryIslandRescueOption,
    *,
    builder,
):
    if option.via_pred is None:
        return builder.goto_redirect(
            source_block=option.source_block,
            target_block=option.lifted_entry,
            old_target=option.old_target,
        )
    return builder.edge_redirect(
        source_block=option.source_block,
        target_block=option.lifted_entry,
        old_target=option.old_target,
        via_pred=option.via_pred,
    )


__all__ = [
    "EntryIslandRescueOption",
    "build_entry_island_rescue_modification",
    "build_entry_island_rescue_options",
]
