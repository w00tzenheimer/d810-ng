from __future__ import annotations

from d810.recon.flow.linearized_state_dag import StateDagEdge


def lift_target_entry_to_island_entry(
    target_entry: int,
    *,
    incoming_by_target_entry: dict[int, tuple[StateDagEdge, ...]],
    semantic_entry_anchors: set[int],
    reachable_blocks: set[int],
    dispatcher_region: set[int],
) -> int:
    current = int(target_entry)
    visited: set[int] = set()

    while current not in visited:
        visited.add(current)
        candidates = sorted(
            {
                int(edge.source_anchor.block_serial)
                for edge in incoming_by_target_entry.get(current, ())
                if int(edge.source_anchor.block_serial) in semantic_entry_anchors
                and int(edge.source_anchor.block_serial) not in dispatcher_region
                and int(edge.source_anchor.block_serial) not in reachable_blocks
            }
        )
        if len(candidates) != 1:
            break
        current = candidates[0]

    return current


__all__ = ["lift_target_entry_to_island_entry"]
