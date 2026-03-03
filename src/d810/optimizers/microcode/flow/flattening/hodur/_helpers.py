"""Shared helper functions for Hodur unflattening strategies.

These are module-level functions extracted from the original HodurUnflattener
monolith.  They operate on live IDA mba_t objects but do NOT mutate the CFG —
all mutations are expressed as ProposedEdit objects by the calling strategy.
"""
from __future__ import annotations

from collections import deque
from d810.core.typing import TYPE_CHECKING

from d810.core import logging

from d810.hexrays.bst_analysis import (
    _forward_eval_insn,
    _mop_matches_stkoff,
    find_bst_default_block,
    resolve_target_via_bst,
)
from d810.optimizers.microcode.flow.flattening.hodur.datamodel import HandlerPathResult

if TYPE_CHECKING:
    pass

_helpers_logger = logging.getLogger("D810.hodur.strategy.helpers")

__all__ = [
    "collect_state_machine_blocks",
    "find_terminal_exit_target",
    "can_reach_return",
    "evaluate_handler_paths",
    "init_bst_cmp_opcodes",
    "eval_bst_condition",
    "resolve_exit_via_bst_default",
]


def collect_state_machine_blocks(state_machine: object) -> set[int]:
    """Collect all block serials that are part of the state machine.

    Args:
        state_machine: HodurStateMachine instance.

    Returns:
        Set of block serial numbers (check blocks + handler body blocks).
    """
    if state_machine is None:
        return set()
    blocks: set[int] = set()
    for handler in state_machine.handlers.values():
        blocks.add(handler.check_block)
        blocks.update(handler.handler_blocks)
    return blocks


def find_terminal_exit_target(
    mba: object,
    first_check_block: int,
    state_machine_blocks: set[int],
) -> int | None:
    """Find the first block outside the state machine that can reach a return.

    Args:
        mba: Live mba_t object.
        first_check_block: Serial of the dispatcher entry / first check block.
        state_machine_blocks: All block serials belonging to the state machine.

    Returns:
        Serial of an exit target, or None if not found.
    """
    import ida_hexrays

    first_check = mba.get_mblock(first_check_block)
    if first_check is None:
        return None

    outside_successors = [
        succ for succ in first_check.succset if succ not in state_machine_blocks
    ]
    for succ in outside_successors:
        if can_reach_return(mba, succ):
            return succ

    for blk_serial in range(mba.qty):
        blk = mba.get_mblock(blk_serial)
        if blk is None or blk.tail is None:
            continue
        if blk.tail.opcode == ida_hexrays.m_ret and (
            blk.npred() > 0 or can_reach_return(mba, blk.serial)
        ):
            return blk.serial

    stop_blk = mba.get_mblock(mba.qty - 1)
    if stop_blk is not None and stop_blk.nsucc() == 0:
        return stop_blk.serial

    return None


def can_reach_return(mba: object, start_serial: int) -> bool:
    """BFS to check if start_serial can reach an m_ret block.

    Args:
        mba: Live mba_t object.
        start_serial: Block serial to start the BFS from.

    Returns:
        True if any block reachable from start_serial has an m_ret tail.
    """
    import ida_hexrays

    visited: set[int] = set()
    to_visit = [start_serial]
    while to_visit:
        blk_serial = to_visit.pop(0)
        if blk_serial in visited:
            continue
        visited.add(blk_serial)
        blk = mba.get_mblock(blk_serial)
        if blk is None:
            continue
        if blk.tail is not None and blk.tail.opcode == ida_hexrays.m_ret:
            return True
        for succ in blk.succset:
            if succ not in visited:
                to_visit.append(succ)
    return False


def init_bst_cmp_opcodes() -> frozenset:
    """Build the set of comparison opcodes for BST walking.

    Returns:
        Frozenset of IDA opcode integers used in BST comparison blocks.
    """
    import ida_hexrays

    return frozenset({
        ida_hexrays.m_jnz,
        ida_hexrays.m_jz,
        ida_hexrays.m_jbe,
        ida_hexrays.m_ja,
        ida_hexrays.m_jb,
        ida_hexrays.m_jae,
    })


def eval_bst_condition(opcode: int, state: int, cmp_val: int) -> bool:
    """Evaluate a BST comparison: does the condition cause a jump?

    Args:
        opcode: IDA microcode opcode of the comparison instruction.
        state: Current state value.
        cmp_val: Value being compared against.

    Returns:
        True if the branch condition is taken for the given state.
    """
    import ida_hexrays

    if opcode == ida_hexrays.m_jnz:
        return state != cmp_val
    if opcode == ida_hexrays.m_jz:
        return state == cmp_val
    if opcode == ida_hexrays.m_jbe:
        return state <= cmp_val
    if opcode == ida_hexrays.m_ja:
        return state > cmp_val
    if opcode == ida_hexrays.m_jb:
        return state < cmp_val
    if opcode == ida_hexrays.m_jae:
        return state >= cmp_val
    return False


# Lazily initialised; populated on first call to resolve_exit_via_bst_default.
_BST_CMP_OPCODES: frozenset = frozenset()


def resolve_exit_via_bst_default(
    mba: object,
    bst_default_serial: int,
    exit_state: int,
) -> int | None:
    """Resolve an exit state by walking BST comparison blocks.

    Walks a chain/tree of 2WAY comparison blocks starting from
    *bst_default_serial*, following the branch dictated by *exit_state* at
    each node.  Stops at the first block that is NOT a state-variable
    comparison and returns its serial.

    Args:
        mba: Live mba_t object.
        bst_default_serial: Block serial to start the walk from.
        exit_state: The final state value for this exit path.

    Returns:
        The successor serial to redirect to, or None if unresolvable.
    """
    import ida_hexrays

    global _BST_CMP_OPCODES
    if not _BST_CMP_OPCODES:
        _BST_CMP_OPCODES = init_bst_cmp_opcodes()

    current_serial = bst_default_serial
    visited: set[int] = set()
    state_var_ref: tuple[int, int] | None = None
    state_var_stkoff: int | None = None

    while current_serial not in visited:
        visited.add(current_serial)

        blk = mba.get_mblock(current_serial)
        if blk is None or blk.nsucc() != 2:
            return current_serial if current_serial != bst_default_serial else None

        tail = blk.tail
        if tail is None or tail.opcode not in _BST_CMP_OPCODES:
            return current_serial if current_serial != bst_default_serial else None

        if tail.r is None or tail.r.t != ida_hexrays.mop_n:
            return current_serial if current_serial != bst_default_serial else None

        if state_var_ref is None:
            state_var_ref = (tail.l.t, tail.l.size)
            if tail.l.t == 3:  # mop_S (stack var)
                state_var_stkoff = tail.l.s.off
        else:
            if (tail.l.t, tail.l.size) != state_var_ref:
                _helpers_logger.info(
                    "  exit %#x: blk[%d] compares non-state-var (mop_t=%d), stopping",
                    exit_state,
                    current_serial,
                    tail.l.t,
                )
                return current_serial
            if tail.l.t == 3 and tail.l.s.off != state_var_stkoff:
                _helpers_logger.info(
                    "  exit %#x: blk[%d] compares non-state-var (mop_t=%d), stopping",
                    exit_state,
                    current_serial,
                    tail.l.t,
                )
                return current_serial

        comparison_value = int(tail.r.nnn.value)
        condition_true = eval_bst_condition(tail.opcode, exit_state, comparison_value)
        next_serial = blk.succ(1) if condition_true else blk.succ(0)

        _helpers_logger.info(
            "  exit %#x: resolved through blk[%d] -> blk[%d]",
            exit_state,
            current_serial,
            next_serial,
        )

        current_serial = next_serial

    return current_serial


def evaluate_handler_paths(
    mba: object,
    entry_serial: int,
    incoming_state: int,
    bst_node_blocks: set[int],
    state_var_stkoff: int,
) -> list[HandlerPathResult]:
    """DFS forward eval of a handler, forking state at conditional branches.

    Walks all blocks from entry_serial, forward-evaluating each instruction.
    When an exit to the dispatcher (successor in bst_node_blocks) is found,
    records the exit block and the current state variable value.  Uses
    per-path visited set to handle diamonds and prevent infinite loops.

    Args:
        mba: Live mba_t object.
        entry_serial: Block serial to start DFS from.
        incoming_state: Initial state value entering this handler.
        bst_node_blocks: Set of block serials belonging to the BST/dispatcher.
        state_var_stkoff: Stack offset of the state variable.

    Returns:
        List of HandlerPathResult, one per exit path found.
    """
    results: list[HandlerPathResult] = []

    queue: list[tuple[int, dict, dict, frozenset, list, list]] = [
        (
            entry_serial,
            {},
            {state_var_stkoff: incoming_state},
            frozenset(),
            [],
            [entry_serial],
        ),
    ]

    while queue:
        curr_serial, reg_map, stk_map, path_visited, state_writes, ordered_path = queue.pop()

        if curr_serial in path_visited:
            continue
        path_visited = path_visited | {curr_serial}

        blk = mba.get_mblock(curr_serial)

        cur_writes = list(state_writes)
        insn = blk.head
        while insn is not None:
            old_val = stk_map.get(state_var_stkoff)
            _forward_eval_insn(
                insn,
                stk_map,
                reg_map,
                state_var_stkoff,
                mba=mba,
            )
            new_val = stk_map.get(state_var_stkoff)
            if new_val != old_val:
                cur_writes.append((curr_serial, insn.ea))
            insn = insn.next

        succs = [blk.succ(i) for i in range(blk.nsucc())]

        if not succs:
            results.append(HandlerPathResult(
                exit_block=curr_serial,
                final_state=None,
                state_writes=list(cur_writes),
                ordered_path=list(ordered_path),
            ))
            continue

        for succ_serial in succs:
            if succ_serial in bst_node_blocks:
                final_val = stk_map.get(state_var_stkoff)
                if final_val is not None:
                    results.append(
                        HandlerPathResult(
                            exit_block=curr_serial,
                            final_state=final_val & 0xFFFFFFFF,
                            state_writes=cur_writes,
                            ordered_path=list(ordered_path),
                        )
                    )
            else:
                new_ordered = ordered_path + [succ_serial]
                queue.append(
                    (
                        succ_serial,
                        dict(reg_map),
                        dict(stk_map),
                        path_visited,
                        list(cur_writes),
                        new_ordered,
                    )
                )

    return results
