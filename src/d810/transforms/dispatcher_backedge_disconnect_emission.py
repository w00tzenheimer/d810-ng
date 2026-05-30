from __future__ import annotations

from dataclasses import dataclass

from d810.transforms.dispatcher_backedge_disconnect_planning import (
    DispatcherBackedgeDisconnectPlan,
    plan_dispatcher_backedge_disconnects,
)


@dataclass(frozen=True, slots=True)
class DispatcherBackedgeDisconnectExecutionResult:
    plans: tuple[DispatcherBackedgeDisconnectPlan, ...]

    @property
    def count(self) -> int:
        return len(self.plans)


def execute_dispatcher_backedge_disconnects(
    *,
    block_nsucc_map: dict[int, int],
    block_succ_map: dict[int, tuple[int, ...]],
    dispatcher_serial: int,
    bst_node_blocks: set[int],
    emitted: set[tuple[int, int]],
    convert_to_goto,
    modifications: list,
) -> DispatcherBackedgeDisconnectExecutionResult:
    plans = plan_dispatcher_backedge_disconnects(
        block_nsucc_map=block_nsucc_map,
        block_succ_map=block_succ_map,
        dispatcher_serial=int(dispatcher_serial),
        bst_node_blocks={int(block) for block in bst_node_blocks},
        emitted=emitted,
    )

    for plan in plans:
        emitted.add((int(plan.source_block), int(plan.keep_target)))
        modifications.append(
            convert_to_goto(int(plan.source_block), int(plan.keep_target))
        )

    return DispatcherBackedgeDisconnectExecutionResult(plans=plans)


def disconnect_bst_comparison_nodes(
    bst_node_blocks: set[int],
    dispatcher_serial: int,
    builder: object,
    modifications: list,
    emitted: set[tuple[int, int]],
    *,
    log_plan=None,
) -> int:
    result = execute_dispatcher_backedge_disconnects(
        block_nsucc_map=builder.block_nsucc_map,
        block_succ_map=builder.block_succ_map,
        dispatcher_serial=int(dispatcher_serial),
        bst_node_blocks={int(block) for block in bst_node_blocks},
        emitted=emitted,
        convert_to_goto=builder.convert_to_goto,
        modifications=modifications,
    )
    if log_plan is not None:
        for plan in result.plans:
            log_plan(plan)
    return result.count


__all__ = [
    "disconnect_bst_comparison_nodes",
    "DispatcherBackedgeDisconnectExecutionResult",
    "execute_dispatcher_backedge_disconnects",
]
