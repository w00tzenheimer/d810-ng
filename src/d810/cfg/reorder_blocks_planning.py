"""Planning helpers for DFS-based handler block reordering."""
from __future__ import annotations

from d810.core import logging
from d810.core.typing import TYPE_CHECKING, Callable

from d810.cfg.graph_modification import ReorderBlocks

try:
    import ida_hexrays as _ida_hexrays

    _BLT_2WAY: int | None = _ida_hexrays.BLT_2WAY
except ImportError:
    _BLT_2WAY = None

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger("D810.cfg.reorder_blocks_planning")


def compute_reorder_blocks(
    snapshot: "AnalysisSnapshot",
    *,
    resolve_target_entry: Callable[[object, int], int | None],
) -> ReorderBlocks | None:
    """Compute a :class:`ReorderBlocks` modification from the snapshot."""
    sm = snapshot.state_machine
    if sm is None or not sm.handlers:
        return None
    if sm.initial_state is None:
        return None

    bst_result = snapshot.bst_result
    if bst_result is None:
        return None

    handler_state_map: dict[int, int] = getattr(
        bst_result, "handler_state_map", {}
    ) or {}
    if not handler_state_map:
        return None

    range_map: dict[int, tuple[int | None, int | None]] = getattr(
        bst_result, "handler_range_map", {}
    ) or {}

    initial_state = sm.initial_state
    assert initial_state is not None

    entry_to_state: dict[int, int] = {
        serial: state for serial, state in handler_state_map.items()
    }

    def _resolve_entry(to_state: int) -> int | None:
        target = resolve_target_entry(bst_result, to_state)
        if target is not None:
            return target
        for serial, (low, high) in range_map.items():
            lo = low if low is not None else 0
            hi = high if high is not None else 0xFFFFFFFF
            if lo <= to_state <= hi:
                return serial
        return None

    visited_states: set[int] = set()
    dfs_block_order: list[int] = []
    seen_blocks: set[int] = set()

    def _dfs(state: int) -> None:
        if state in visited_states:
            return
        if state not in sm.handlers:
            return
        visited_states.add(state)
        handler = sm.handlers[state]
        for blk_serial in handler.handler_blocks:
            if blk_serial not in seen_blocks:
                seen_blocks.add(blk_serial)
                dfs_block_order.append(blk_serial)

        handler_block_set = set(handler.handler_blocks)
        unconditional: list[int] = []
        conditional: list[int] = []

        for trans in sm.transitions:
            if trans.from_block not in handler_block_set:
                continue
            target_entry = _resolve_entry(trans.to_state)
            if target_entry is None:
                continue
            target_state = entry_to_state.get(target_entry)
            if target_state is None:
                continue
            if trans.is_conditional:
                conditional.append(target_state)
            else:
                unconditional.append(target_state)

        for target_state in unconditional:
            _dfs(target_state)

        for target_state in conditional:
            _dfs(target_state)

    _dfs(initial_state)

    for state in sm.handlers:
        if state not in visited_states:
            _dfs(state)

    if not dfs_block_order:
        return None

    non_2way_serials: tuple[int, ...] = ()
    two_way_serials: tuple[int, ...] = ()
    mba = snapshot.mba
    bst_blocks: frozenset[int] = (
        frozenset(bst_result.bst_node_blocks)
        if bst_result is not None and bst_result.bst_node_blocks
        else frozenset()
    )
    if mba is not None and _BLT_2WAY is not None:
        _non_2way: list[int] = []
        _two_way: list[int] = []
        for serial in dfs_block_order:
            blk = mba.get_mblock(serial)
            if blk is None:
                continue
            if blk.type == _BLT_2WAY and serial not in bst_blocks:
                _two_way.append(serial)
            else:
                _non_2way.append(serial)
        non_2way_serials = tuple(_non_2way)
        two_way_serials = tuple(_two_way)
    else:
        logger.warning(
            "TopologicalSort: cannot filter BLT_2WAY blocks "
            "(mba=%s, _BLT_2WAY=%s), non_2way_serials over-estimated",
            mba,
            _BLT_2WAY,
        )
        non_2way_serials = tuple(dfs_block_order)

    logger.info(
        "TopologicalSort: %d blocks in DFS order (%d non-2WAY, %d 2WAY) for %d handlers",
        len(dfs_block_order),
        len(non_2way_serials),
        len(two_way_serials),
        len(visited_states),
    )

    return ReorderBlocks(
        dfs_block_order=tuple(dfs_block_order),
        non_2way_serials=non_2way_serials,
        two_way_serials=two_way_serials,
    )


__all__ = ["compute_reorder_blocks"]
