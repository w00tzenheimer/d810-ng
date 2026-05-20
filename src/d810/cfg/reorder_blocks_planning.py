"""Planning helpers for DFS-based handler block reordering."""
from __future__ import annotations

from d810.core import logging
from d810.core.typing import (
    AbstractSet,
    Callable,
    Iterable,
    Mapping,
    Protocol,
    Sequence,
)

from d810.cfg.flowgraph import BlockKind
from d810.cfg.graph_modification import ReorderBlocks

logger = logging.getLogger("D810.cfg.reorder_blocks_planning")


class _HandlerLike(Protocol):
    check_block: int | None
    handler_blocks: Sequence[int]


class _TransitionLike(Protocol):
    from_block: int
    to_state: int
    is_conditional: bool


class _StateMachineLike(Protocol):
    initial_state: int | None
    handlers: Mapping[int, _HandlerLike]
    transitions: Iterable[_TransitionLike]


class _ReorderPlanningSnapshot(Protocol):
    state_machine: _StateMachineLike | None
    flow_graph: object | None


def compute_reorder_blocks(
    snapshot: _ReorderPlanningSnapshot,
    *,
    resolve_target_entry: Callable[[int], int | None],
    handler_entry_state_map: Mapping[int, int] | None = None,
    dispatcher_blocks: AbstractSet[int] | None = None,
) -> ReorderBlocks | None:
    """Compute a :class:`ReorderBlocks` modification from the snapshot."""
    sm = snapshot.state_machine
    if sm is None or not sm.handlers:
        return None
    if sm.initial_state is None:
        return None

    initial_state = sm.initial_state
    assert initial_state is not None

    entry_to_state: dict[int, int] = (
        {
            int(serial): int(state)
            for serial, state in handler_entry_state_map.items()
        }
        if handler_entry_state_map is not None
        else {}
    )
    if not entry_to_state:
        for state, handler in sm.handlers.items():
            check_block = handler.check_block
            if check_block is not None:
                entry_to_state[int(check_block)] = int(state)
            handler_blocks = handler.handler_blocks or ()
            if handler_blocks:
                entry_to_state.setdefault(int(handler_blocks[0]), int(state))

    def _resolve_entry(to_state: int) -> int | None:
        return resolve_target_entry(to_state)

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
            if target_state is None and trans.to_state in sm.handlers:
                target_state = trans.to_state
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
    flow_graph = snapshot.flow_graph
    dispatcher_block_set: frozenset[int] = (
        frozenset(int(block) for block in dispatcher_blocks)
        if dispatcher_blocks is not None
        else frozenset()
    )
    if flow_graph is not None:
        _non_2way: list[int] = []
        _two_way: list[int] = []
        get_block = getattr(flow_graph, "get_block", None)
        for serial in dfs_block_order:
            blk = get_block(serial) if callable(get_block) else None
            if blk is None:
                continue
            if (
                getattr(blk, "kind", BlockKind.UNKNOWN) == BlockKind.TWO_WAY
                and serial not in dispatcher_block_set
            ):
                _two_way.append(serial)
            else:
                _non_2way.append(serial)
        non_2way_serials = tuple(_non_2way)
        two_way_serials = tuple(_two_way)
    else:
        logger.warning(
            "TopologicalSort: cannot filter BLT_2WAY blocks without a FlowGraph, "
            "non_2way_serials over-estimated",
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
