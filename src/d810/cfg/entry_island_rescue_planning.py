from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.entry_island_rescue import (
    EntryIslandRescueOption,
    build_entry_island_rescue_modification,
    build_entry_island_rescue_options,
)
from d810.cfg.plan import compile_patch_plan
from d810.cfg.flow.edit_simulator import project_post_state


@dataclass(frozen=True, slots=True)
class EntryIslandRescuePlanningSeed:
    """One discovered unreachable entry-island rescue opportunity."""

    source_block: int
    lifted_entry: int


@dataclass(frozen=True, slots=True)
class EntryIslandRescueSelection:
    """Selected rescue modification for the current projected CFG."""

    accepted: bool
    option: EntryIslandRescueOption | None = None
    score: tuple[int, int, int, int, int] | None = None
    modification: object | None = None
    projected_flow_graph: object | None = None


@dataclass(frozen=True, slots=True)
class EntryIslandRescueIteration:
    raw_seeds: tuple[object, ...]
    selection: EntryIslandRescueSelection


@dataclass(frozen=True, slots=True)
class EntryIslandRescueRun:
    projected_flow_graph: object
    emitted_count: int
    iterations: tuple[EntryIslandRescueIteration, ...]


def score_entry_island_rescue_option(
    option: EntryIslandRescueOption,
    *,
    base_flow_graph,
    builder,
    modifications: list,
    baseline_reachable_count: int,
    baseline_reachable_blocks: set[int],
    compute_reachable_blocks,
) -> tuple[tuple[int, int, int, int, int], object, object] | None:
    candidate_mod = build_entry_island_rescue_modification(option, builder=builder)

    try:
        patch_plan = compile_patch_plan(modifications + [candidate_mod], base_flow_graph)
        projected_flow_graph = project_post_state(base_flow_graph, patch_plan)
    except Exception:
        return None

    reachable_blocks = compute_reachable_blocks(projected_flow_graph)
    if not reachable_blocks or option.lifted_entry not in reachable_blocks:
        return None

    reachable_count_delta = len(reachable_blocks) - baseline_reachable_count
    if reachable_count_delta < 0:
        return None

    preserved_old_target = 1 if (
        option.old_target in baseline_reachable_blocks
        and option.old_target in reachable_blocks
    ) else 0
    mode_rank = 1 if option.via_pred is None else 0
    via_rank = int(option.via_pred) if option.via_pred is not None else -1
    score = (
        reachable_count_delta,
        preserved_old_target,
        mode_rank,
        int(option.source_block),
        via_rank,
    )
    return score, candidate_mod, projected_flow_graph


def select_entry_island_rescue(
    *,
    seeds: tuple[EntryIslandRescuePlanningSeed, ...],
    current_projected_flow_graph,
    base_flow_graph,
    builder,
    modifications: list,
    reachable_blocks: set[int],
    dispatcher_region: set[int],
    claimed_sources: set[int],
    compute_reachable_blocks,
) -> EntryIslandRescueSelection:
    baseline_reachable_count = len(reachable_blocks)
    seen_options: set[tuple[int, int, int | None]] = set()
    best_score: tuple[int, int, int, int, int] | None = None
    best_option: EntryIslandRescueOption | None = None
    best_modification = None
    best_projected_flow_graph = None

    for seed in seeds:
        for option in build_entry_island_rescue_options(
            int(seed.source_block),
            lifted_entry=int(seed.lifted_entry),
            projected_flow_graph=current_projected_flow_graph,
            reachable_blocks=reachable_blocks,
            dispatcher_region=dispatcher_region,
            claimed_sources=claimed_sources,
        ):
            option_key = (
                int(option.source_block),
                int(option.lifted_entry),
                int(option.via_pred) if option.via_pred is not None else None,
            )
            if option_key in seen_options:
                continue
            seen_options.add(option_key)

            scored = score_entry_island_rescue_option(
                option,
                base_flow_graph=base_flow_graph,
                builder=builder,
                modifications=modifications,
                baseline_reachable_count=baseline_reachable_count,
                baseline_reachable_blocks=reachable_blocks,
                compute_reachable_blocks=compute_reachable_blocks,
            )
            if scored is None:
                continue

            score, candidate_mod, candidate_projected = scored
            if best_score is not None and score <= best_score:
                continue
            best_score = score
            best_option = option
            best_modification = candidate_mod
            best_projected_flow_graph = candidate_projected

    if best_option is None or best_modification is None or best_projected_flow_graph is None:
        return EntryIslandRescueSelection(accepted=False)

    return EntryIslandRescueSelection(
        accepted=True,
        option=best_option,
        score=best_score,
        modification=best_modification,
        projected_flow_graph=best_projected_flow_graph,
    )


def plan_entry_island_rescues(
    *,
    dag,
    base_flow_graph,
    projected_flow_graph,
    builder,
    modifications: list,
    dispatcher_region: set[int],
    collect_seeds,
    compute_reachable_blocks,
) -> EntryIslandRescueRun:
    current_projected_flow_graph = projected_flow_graph
    emitted = 0
    iterations: list[EntryIslandRescueIteration] = []

    while True:
        reachable_blocks = compute_reachable_blocks(current_projected_flow_graph)
        if not reachable_blocks:
            break

        raw_seeds = tuple(
            collect_seeds(
                dag,
                projected_flow_graph=current_projected_flow_graph,
                reachable_blocks=reachable_blocks,
                dispatcher_region=dispatcher_region,
            )
        )
        planning_seeds = tuple(
            EntryIslandRescuePlanningSeed(
                source_block=int(seed.source_block),
                lifted_entry=int(seed.lifted_entry),
            )
            for seed in raw_seeds
            if getattr(seed, "source_block", None) is not None
        )
        claimed_sources = {
            int(getattr(mod, "from_serial"))
            for mod in modifications
            if getattr(mod, "from_serial", None) is not None
        }
        selection = select_entry_island_rescue(
            seeds=planning_seeds,
            current_projected_flow_graph=current_projected_flow_graph,
            base_flow_graph=base_flow_graph,
            builder=builder,
            modifications=modifications,
            reachable_blocks=reachable_blocks,
            dispatcher_region=dispatcher_region,
            claimed_sources=claimed_sources,
            compute_reachable_blocks=compute_reachable_blocks,
        )
        iterations.append(
            EntryIslandRescueIteration(
                raw_seeds=raw_seeds,
                selection=selection,
            )
        )
        if (
            not selection.accepted
            or selection.modification is None
            or selection.projected_flow_graph is None
        ):
            break

        modifications.append(selection.modification)
        current_projected_flow_graph = selection.projected_flow_graph
        emitted += 1

    return EntryIslandRescueRun(
        projected_flow_graph=current_projected_flow_graph,
        emitted_count=emitted,
        iterations=tuple(iterations),
    )


__all__ = [
    "EntryIslandRescueIteration",
    "EntryIslandRescuePlanningSeed",
    "EntryIslandRescueRun",
    "plan_entry_island_rescues",
    "EntryIslandRescueSelection",
    "score_entry_island_rescue_option",
    "select_entry_island_rescue",
]
