from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DispatcherBackedgeDisconnectPlan:
    source_block: int
    keep_target: int
    is_condition_chain: bool


def plan_dispatcher_backedge_disconnects(
    *,
    block_nsucc_map: dict[int, int],
    block_succ_map: dict[int, tuple[int, ...]],
    dispatcher_serial: int,
    condition_chain_blocks: set[int],
    emitted: set[tuple[int, int]],
) -> tuple[DispatcherBackedgeDisconnectPlan, ...]:
    if dispatcher_serial < 0:
        return ()

    already_redirected: set[int] = {int(src) for src, _ in emitted}
    plans: list[DispatcherBackedgeDisconnectPlan] = []

    for serial in sorted(block_nsucc_map):
        if serial == dispatcher_serial:
            continue
        if serial in already_redirected:
            continue

        nsucc = int(block_nsucc_map.get(serial, 0))
        if nsucc != 2:
            continue

        succs = tuple(int(succ) for succ in block_succ_map.get(serial, ()))
        if len(succs) != 2:
            continue

        succ0, succ1 = succs
        if succ0 != dispatcher_serial and succ1 != dispatcher_serial:
            continue

        keep_serial = succ1 if succ0 == dispatcher_serial else succ0
        emit_key = (int(serial), int(keep_serial))
        if emit_key in emitted:
            continue

        plans.append(
            DispatcherBackedgeDisconnectPlan(
                source_block=int(serial),
                keep_target=int(keep_serial),
                is_condition_chain=(int(serial) in condition_chain_blocks),
            )
        )

    return tuple(plans)


__all__ = [
    "DispatcherBackedgeDisconnectPlan",
    "plan_dispatcher_backedge_disconnects",
]
