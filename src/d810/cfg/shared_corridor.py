"""Shared-corridor helper queries for reconstruction planning."""

from __future__ import annotations


def resolve_old_target(
    flow_graph,
    source_block: int,
    ordered_path: tuple[int, ...],
) -> int | None:
    """Resolve the source block's current semantic successor on ``ordered_path``."""
    block = flow_graph.get_block(source_block)
    if block is None:
        return None
    if source_block in ordered_path:
        idx = ordered_path.index(source_block)
        if idx + 1 < len(ordered_path):
            next_block = int(ordered_path[idx + 1])
            if next_block in tuple(block.succs):
                return next_block
    if block.nsucc == 1:
        return int(block.succs[0])
    return None


def is_shared_block(
    flow_graph,
    block_serial: int,
    *,
    shared_suffix_blocks: set[int],
) -> bool:
    """Return whether a block is shared by suffix classification or indegree."""
    if block_serial in shared_suffix_blocks:
        return True
    block = flow_graph.get_block(block_serial)
    return bool(block is not None and block.npred > 1)


def first_shared_block_index(
    flow_graph,
    ordered_path: tuple[int, ...],
    *,
    start_index: int,
    shared_suffix_blocks: set[int],
    dispatcher_region: set[int],
) -> int | None:
    """Return the first shared non-dispatcher block on ``ordered_path``."""
    for index in range(start_index, len(ordered_path)):
        block_serial = int(ordered_path[index])
        if block_serial in dispatcher_region:
            continue
        if is_shared_block(
            flow_graph,
            block_serial,
            shared_suffix_blocks=shared_suffix_blocks,
        ):
            return index
    return None


def first_boundary_index(
    flow_graph,
    ordered_path: tuple[int, ...],
    *,
    start_index: int,
    shared_suffix_blocks: set[int],
    dispatcher_region: set[int],
) -> int | None:
    """Return the first dispatcher/shared boundary block on ``ordered_path``."""
    for index in range(start_index, len(ordered_path)):
        block_serial = int(ordered_path[index])
        if block_serial in dispatcher_region or is_shared_block(
            flow_graph,
            block_serial,
            shared_suffix_blocks=shared_suffix_blocks,
        ):
            return index
    return None


__all__ = [
    "first_boundary_index",
    "first_shared_block_index",
    "is_shared_block",
    "resolve_old_target",
]
