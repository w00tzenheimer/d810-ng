"""Dispatcher state evaluation helpers for father-history based unflattening."""
from __future__ import annotations

import ida_hexrays

from d810.core import getLogger
from d810.evaluator.hexrays_microcode.emulator import (
    MicroCodeEnvironment,
    MicroCodeInterpreter,
)
from d810.evaluator.hexrays_microcode.tracker import MopHistory, MopTracker
from d810.hexrays.utils.hexrays_formatters import format_minsn_t, format_mop_t

logger = getLogger("D810.evaluator.dispatcher_state")


class DispatcherStateEvaluationError(RuntimeError):
    """Raised when dispatcher state cannot be evaluated from a history."""


def collect_dispatcher_father_histories(
    *,
    dispatcher_father: ida_hexrays.mblock_t,
    state_mops: list[ida_hexrays.mop_t],
    dispatcher_info: object,
    dispatcher_entry_serial: int,
    max_nb_block: int,
    max_path: int,
    initialize_tracker=None,
) -> list[MopHistory]:
    """Collect MopTracker histories for one dispatcher predecessor."""
    father_tracker = MopTracker(
        state_mops,
        max_nb_block=max_nb_block,
        max_path=max_path,
        dispatcher_info=dispatcher_info,
    )
    father_tracker.reset()
    if initialize_tracker is not None:
        initialize_tracker(father_tracker)
    father_histories = father_tracker.search_backward(dispatcher_father, None)
    logger.debug(
        "Histories (dispatcher %s, predecessor %s): %s",
        dispatcher_entry_serial,
        dispatcher_father.serial,
        father_histories,
    )
    return father_histories


def histories_are_resolved(mop_histories: list[MopHistory]) -> bool:
    """Return whether all histories fully resolve their tracked mops."""
    return all(mop_history.is_resolved() for mop_history in mop_histories)


def emulate_dispatcher_with_father_history(
    *,
    entry_block: object,
    dispatcher_exit_blocks: list[object],
    father_history: MopHistory,
    should_continue=None,
    resolve_conditional_exits: bool = False,
    max_emulated_instructions: int = 10000,
) -> tuple[ida_hexrays.mblock_t, list[ida_hexrays.minsn_t]]:
    """Execute a dispatcher using concrete state values from a MopHistory."""
    microcode_interpreter = MicroCodeInterpreter(symbolic_mode=False)
    microcode_environment = MicroCodeEnvironment()
    dispatcher_input_info = []
    for initialization_mop in entry_block.use_before_def_list:
        initialization_mop_value = father_history.get_mop_constant_value(
            initialization_mop
        )
        if initialization_mop_value is None:
            raise DispatcherStateEvaluationError(
                "Can't emulate dispatcher {0} with history {1}".format(
                    entry_block.serial,
                    father_history.block_serial_path,
                )
            )
        microcode_environment.define(initialization_mop, initialization_mop_value)
        dispatcher_input_info.append(
            f"{format_mop_t(initialization_mop)} = {initialization_mop_value:x}"
        )

    logger.info(
        "Executing dispatcher %s with: %s",
        entry_block.serial,
        ", ".join(dispatcher_input_info),
    )

    exit_block_serials = {exit_block.serial for exit_block in dispatcher_exit_blocks}
    instructions_executed = []
    cur_blk = entry_block.blk
    cur_ins = cur_blk.head
    nb_emulated = 0
    while cur_blk is not None:
        if cur_ins is None:
            cur_ins = cur_blk.head
        if cur_ins is None:
            break
        keep_executing = (
            bool(should_continue(cur_blk))
            if should_continue is not None
            else cur_blk.serial not in exit_block_serials
        )
        if not keep_executing:
            can_refine_exit = (
                resolve_conditional_exits
                and cur_blk.nsucc() == 2
                and cur_blk.tail is not None
                and ida_hexrays.is_mcode_jcond(cur_blk.tail.opcode)
            )
            if not can_refine_exit:
                break
        logger.debug("  Executing: %s.%s", cur_blk.serial, format_minsn_t(cur_ins))
        is_ok = microcode_interpreter.eval_instruction(
            cur_blk, cur_ins, microcode_environment
        )
        if not is_ok:
            return cur_blk, instructions_executed
        instructions_executed.append(cur_ins)
        nb_emulated += 1
        if nb_emulated >= int(max_emulated_instructions):
            logger.warning(
                "Stopping dispatcher emulation after %d instructions "
                "(entry=%d, father=%d)",
                nb_emulated,
                entry_block.serial,
                father_history.block_serial_path[0]
                if len(father_history.block_serial_path) > 0
                else -1,
            )
            break
        cur_blk = microcode_environment.next_blk
        cur_ins = microcode_environment.next_ins
    return cur_blk, instructions_executed


__all__ = [
    "DispatcherStateEvaluationError",
    "collect_dispatcher_father_histories",
    "emulate_dispatcher_with_father_history",
    "histories_are_resolved",
]
