from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.entry_island_rescue_planning import (
    EntryIslandRescueRun,
    plan_entry_island_rescues,
)


@dataclass(frozen=True, slots=True)
class LateReconstructionRescueRun:
    run: EntryIslandRescueRun
    diagnostics: tuple[object, ...]


def execute_reconstruction_entry_island_rescues(
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
    return plan_entry_island_rescues(
        dag=dag,
        base_flow_graph=base_flow_graph,
        projected_flow_graph=projected_flow_graph,
        builder=builder,
        modifications=modifications,
        dispatcher_region=dispatcher_region,
        collect_seeds=collect_seeds,
        compute_reachable_blocks=compute_reachable_blocks,
    )


def execute_reconstruction_late_island_rescues(
    *,
    dag,
    base_flow_graph,
    projected_flow_graph,
    builder,
    modifications: list,
    dispatcher_region: set[int],
    collect_seeds,
    collect_diagnostics,
    compute_reachable_blocks,
    dispatcher=None,
) -> LateReconstructionRescueRun:
    run = plan_entry_island_rescues(
        dag=dag,
        base_flow_graph=base_flow_graph,
        projected_flow_graph=projected_flow_graph,
        builder=builder,
        modifications=modifications,
        dispatcher_region=dispatcher_region,
        collect_seeds=collect_seeds,
        compute_reachable_blocks=compute_reachable_blocks,
    )

    diagnostics: tuple[object, ...] = ()
    if run.emitted_count == 0 and dispatcher is not None:
        reachable_blocks = compute_reachable_blocks(run.projected_flow_graph) or set()
        diagnostics = tuple(
            collect_diagnostics(
                run.projected_flow_graph,
                reachable_blocks=reachable_blocks,
                dispatcher_region=dispatcher_region,
                dispatcher=dispatcher,
            )
        )

    return LateReconstructionRescueRun(
        run=run,
        diagnostics=tuple(diagnostics),
    )


__all__ = [
    "LateReconstructionRescueRun",
    "execute_reconstruction_entry_island_rescues",
    "execute_reconstruction_late_island_rescues",
]
