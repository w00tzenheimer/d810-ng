"""Transition enrichment for dynamic dispatcher state carriers."""

from __future__ import annotations

from dataclasses import replace

from d810.core import logging
from d810.core.typing import Iterable
from d810.evaluator.hexrays_microcode.dynamic_state_write_backend import (
    DynamicStateWriteEvidence,
    recognize_global_or_state_write_transition,
)
from d810.recon.flow.bst_analysis import _detect_state_var_stkoff
from d810.recon.flow.transition_builder import (
    StateHandler,
    StateTransition,
    TransitionResult,
)

logger = logging.getLogger(
    "D810.recon.flow.dynamic_state_transition_recovery", logging.INFO
)


def _clone_handlers(
    transition_result: TransitionResult,
) -> dict[int, StateHandler]:
    return {
        int(state): StateHandler(
            state_value=int(handler.state_value),
            check_block=int(handler.check_block),
            handler_blocks=list(handler.handler_blocks),
            transitions=list(handler.transitions),
        )
        for state, handler in transition_result.handlers.items()
    }


def _handler_needs_dynamic_recovery(handler: StateHandler) -> bool:
    """Only enrich handlers whose normal BST walk did not prove a real edge."""

    if not handler.transitions:
        return True
    return all(
        transition.to_state == handler.state_value
        for transition in handler.transitions
        if transition.to_state is not None
    )


def _build_transition(
    *,
    from_state: int,
    handler: StateHandler,
    evidence: DynamicStateWriteEvidence,
) -> StateTransition:
    return StateTransition(
        from_state=int(from_state),
        to_state=int(evidence.target_state),
        from_block=int(handler.check_block),
        condition_block=int(evidence.state_write_block),
        is_conditional=True,
        provenance_chain=[(int(handler.check_block), int(evidence.state_write_block))],
        provenance_kind=evidence.provenance,
        provenance_ea=evidence.state_write_ea or evidence.or_insn_ea,
    )


def recover_dynamic_state_write_transitions(
    *,
    mba,
    flow_graph,
    transition_result: TransitionResult,
    dispatcher_entry_serial: int,
    state_var_stkoff: int | None,
    known_states: Iterable[int],
) -> TransitionResult:
    """Add guarded transitions recovered from global state-carrier writes.

    The BST walker can miss handlers that compute the next dispatcher state
    through writable storage.  The Approov VM sample has this form:
    ``global |= STATE; state_var = global``.  Since the previous global value
    is not proven here, the recovered edge is marked conditional/advisory and
    carries provenance back to the handler block rather than pretending to be
    an unconditional state write.
    """

    known_state_set = {int(value) & 0xFFFFFFFF for value in known_states}
    if not known_state_set or not transition_result.handlers:
        return transition_result

    state_var_lvar_idx: int | None = None
    if state_var_stkoff is None:
        try:
            state_var_stkoff, state_var_lvar_idx = _detect_state_var_stkoff(
                mba,
                int(dispatcher_entry_serial),
                diag=False,
            )
        except Exception:
            state_var_stkoff = None
            state_var_lvar_idx = None
    else:
        try:
            _detected_stkoff, detected_lvar_idx = _detect_state_var_stkoff(
                mba,
                int(dispatcher_entry_serial),
                diag=False,
            )
            if (
                _detected_stkoff is not None
                and int(_detected_stkoff) == int(state_var_stkoff)
            ):
                state_var_lvar_idx = detected_lvar_idx
        except Exception:
            state_var_lvar_idx = None

    if state_var_stkoff is None:
        return transition_result

    cloned_handlers = _clone_handlers(transition_result)
    transitions = list(transition_result.transitions)
    added = 0

    for state_value, handler in sorted(cloned_handlers.items()):
        if not _handler_needs_dynamic_recovery(handler):
            continue
        if flow_graph is not None and flow_graph.get_block(handler.check_block) is None:
            continue

        evidence = recognize_global_or_state_write_transition(
            mba=mba,
            handler_serial=handler.check_block,
            state_var_stkoff=int(state_var_stkoff),
            state_var_lvar_idx=state_var_lvar_idx,
            known_states=known_state_set,
        )
        if evidence is None:
            continue
        if evidence.target_state not in cloned_handlers:
            continue
        if (int(evidence.target_state) & 0xFFFFFFFF) == (
            int(state_value) & 0xFFFFFFFF
        ):
            continue
        if any(
            transition.is_conditional
            and (transition.to_state & 0xFFFFFFFF) == (evidence.target_state & 0xFFFFFFFF)
            for transition in handler.transitions
        ):
            continue

        transition = _build_transition(
            from_state=int(state_value),
            handler=handler,
            evidence=evidence,
        )
        handler.transitions.append(transition)
        transitions.append(transition)
        added += 1
        logger.info(
            "Recovered guarded dynamic state transition: "
            "state 0x%08X blk[%d] -> 0x%08X via global 0x%X",
            int(state_value) & 0xFFFFFFFF,
            int(handler.check_block),
            int(evidence.target_state) & 0xFFFFFFFF,
            int(evidence.global_ea),
        )

    if added == 0:
        return transition_result

    strategy_name = transition_result.strategy_name or "bst_walker"
    if "dynamic_state_write" not in strategy_name:
        strategy_name = f"{strategy_name}+dynamic_state_write"

    return replace(
        transition_result,
        transitions=transitions,
        handlers=cloned_handlers,
        strategy_name=strategy_name,
        resolved_count=len(transitions),
    )


__all__ = ["recover_dynamic_state_write_transitions"]
