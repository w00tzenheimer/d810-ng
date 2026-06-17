"""State-machine evidence adapters for Hodur-compatible profiles."""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Any
from d810.backends.hexrays.evidence.datamodel import (
    DispatcherStateMachine,
)
from d810.backends.hexrays.evidence.dispatcher.switch_table import (
    analyze_switch_table_dispatcher,
)
from d810.analyses.control_flow.state_machine_analysis import evaluate_handler_paths
from d810.analyses.control_flow.transition_builder import StateHandler, StateTransition


@dataclass(frozen=True)
class SwitchTableStateMachineAdapterResult:
    """State-machine view derived from recon switch-table evidence."""

    state_machine: DispatcherStateMachine
    state_dispatcher_map: object


def detect_switch_table_state_machine(
    mba: object,
    *,
    logger: Any | None = None,
) -> SwitchTableStateMachineAdapterResult | None:
    """Build a ``DispatcherStateMachine`` from switch-table dispatcher evidence."""
    result = analyze_switch_table_dispatcher(mba)
    if result is None:
        return None

    state_dispatcher_map = result.state_dispatcher_map
    handler_map = state_dispatcher_map.to_dispatcher_handler_map()
    state_var_mop = result.state_var_mop

    if logger is not None:
        logger.info(
            "Switch-table dispatcher detected: %d handlers at blk[%d]",
            len(handler_map.handler_state_map),
            handler_map.dispatcher_serial,
        )

    state_machine = DispatcherStateMachine(mba=mba, state_var=state_var_mop)
    state_machine.state_constants = set(handler_map.handler_state_map.values())

    handler_entry_blocks = set(handler_map.handler_state_map.keys())
    dispatcher_blocks_set = set(handler_map.dispatcher_blocks)

    for handler_serial, state_const in handler_map.handler_state_map.items():
        state_machine.add_handler(
            StateHandler(
                state_value=state_const,
                check_block=handler_serial,
                handler_blocks=[handler_serial],
            )
        )

    for handler_serial, state_const in handler_map.handler_state_map.items():
        try:
            paths = evaluate_handler_paths(
                mba,
                entry_serial=handler_serial,
                incoming_state=state_const,
                condition_chain_blocks=dispatcher_blocks_set,
                state_var_stkoff=handler_map.state_var_stkoff,
                handler_entry_blocks=handler_entry_blocks,
            )
        except Exception:
            if logger is not None:
                logger.debug(
                    "Forward eval failed for switch handler blk[%d] (state=%d)",
                    handler_serial,
                    state_const,
                )
            continue

        for path_result in paths:
            if path_result.final_state is None:
                continue
            target = handler_map.resolve_target(path_result.final_state)
            if target is None:
                continue
            state_machine.add_transition(
                StateTransition(
                    from_state=state_const,
                    to_state=path_result.final_state,
                    from_block=path_result.exit_block,
                )
            )

    if logger is not None:
        logger.info(
            "Switch-table state machine: %d handlers, %d transitions",
            len(state_machine.handlers),
            len(state_machine.transitions),
        )

    return SwitchTableStateMachineAdapterResult(
        state_machine=state_machine,
        state_dispatcher_map=state_dispatcher_map,
    )
