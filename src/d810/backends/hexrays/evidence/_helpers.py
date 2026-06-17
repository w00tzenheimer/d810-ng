"""Backward-compatible Hodur helper re-exports.

The reusable state-machine path helpers now live under
``d810.analyses.control_flow.state_machine_analysis``. This module keeps the old import
surface for Hodur strategies while the implementation remains centralized.
"""

from __future__ import annotations

from d810.core import logging
from d810.hexrays.utils.hexrays_formatters import blk_label
from d810.analyses.control_flow.state_machine_analysis import (
    ConditionalTransition,
    HandlerPathResult,
    can_reach_return_snapshot,
    detect_conditional_transitions,
    eval_condition_chain_condition,
    evaluate_handler_paths,
    find_terminal_exit_target_snapshot,
    init_condition_chain_cmp_opcodes,
    resolve_exit_via_condition_chain_default_snapshot,
)

_helpers_logger = logging.getLogger("D810.hodur.strategy.helpers")

__all__ = [
    "blk_label",
    "collect_state_machine_blocks",
    "ConditionalTransition",
    "HandlerPathResult",
    "detect_conditional_transitions",
    "find_terminal_exit_target_snapshot",
    "can_reach_return_snapshot",
    "evaluate_handler_paths",
    "init_condition_chain_cmp_opcodes",
    "eval_condition_chain_condition",
    "resolve_exit_via_condition_chain_default_snapshot",
]


def collect_state_machine_blocks(state_machine: "DispatcherStateMachine") -> set[int]:
    """Collect all block serials that are part of the state machine."""
    if state_machine is None:
        return set()
    blocks: set[int] = set()
    for handler in state_machine.handlers.values():
        blocks.add(handler.check_block)
        blocks.update(handler.handler_blocks)
    return blocks
