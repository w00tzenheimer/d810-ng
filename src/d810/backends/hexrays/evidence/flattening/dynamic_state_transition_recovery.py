"""Transition enrichment for dynamic dispatcher state carriers."""

from __future__ import annotations

from dataclasses import replace

from d810.core import logging
from d810.core.typing import Iterable
from d810.evaluator.hexrays_microcode.dynamic_state_write_backend import (
    DynamicStateWriteEvidence,
    DerivedXorTransitionEvidence,
    derive_initial_xor_dispatch_state,
    recognize_carrier_xor_transition,
    recognize_constant_folded_state_write,
    recognize_derived_xor_dispatcher_model,
    recognize_global_or_state_write_transition,
)
from d810.backends.hexrays.evidence.bst_analysis import _detect_state_var_stkoff
from d810.analyses.control_flow.transition_builder import (
    StateHandler,
    StateTransition,
    TransitionResult,
)

logger = logging.getLogger(
    "D810.backends.hexrays.evidence.flattening.dynamic_state_transition_recovery", logging.INFO
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


def _build_derived_xor_transition(
    *,
    from_state: int,
    handler: StateHandler,
    evidence: DerivedXorTransitionEvidence,
) -> StateTransition:
    return StateTransition(
        from_state=int(from_state),
        to_state=int(evidence.target_state),
        from_block=int(handler.check_block),
        condition_block=int(evidence.state_write_block),
        is_conditional=int(evidence.state_write_block) != int(handler.check_block),
        provenance_chain=[(int(handler.check_block), int(evidence.state_write_block))],
        provenance_kind=evidence.provenance,
        provenance_ea=evidence.state_write_ea,
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
    """Add guarded transitions recovered from dynamic state-carrier writes.

    The BST walker can miss handlers that compute the next dispatcher state
    through writable storage.  The Approov VM sample has this form:
    ``global |= STATE; state_var = global``.  Since the previous global value
    is not proven here, the recovered edge is marked conditional/advisory and
    carries provenance back to the handler block rather than pretending to be
    an unconditional state write.

    Derived-XOR dispatchers use the same enrichment workflow but with a
    different state space:

    1. Recognize the dispatcher expression ``key = low8(carrier) ^ K``.
    2. Derive the initial dispatcher state from the preheader carrier write.
    3. Convert each handler-side ``carrier ^= C`` into
       ``next_key = current_key ^ (C & 0xff)``.
    4. Store those edges as ``StateTransition`` objects with
       ``provenance_kind == "derived_xor_dispatch_key"``.

    The emulated-dispatcher lowerer intentionally requires that provenance
    before it emits redirects, and generic cleanup/FCP rules use the same
    recognizer as an ownership signal.  Future dispatcher families should
    follow this pattern: recover evidence into recon first, tag the provenance,
    then make lowering consume the tagged transitions instead of rewriting
    pseudocode or teaching a generic rule to guess the derived state.
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

    cloned_handlers = _clone_handlers(transition_result)
    transitions = list(transition_result.transitions)
    added = 0

    if state_var_stkoff is not None:
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
                # General fallback: fold an MBA-over-constants next-state write
                # (the bulk of OLLVM's unresolved next-states) via the KnownBits
                # value domain. Only accepts a result that is a known state.
                evidence = recognize_constant_folded_state_write(
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
                "state 0x%08X blk[%d] -> 0x%08X via %s",
                int(state_value) & 0xFFFFFFFF,
                int(handler.check_block),
                int(evidence.target_state) & 0xFFFFFFFF,
                evidence.provenance
                if evidence.provenance != "global_or_state_write"
                else f"global 0x{int(evidence.global_ea):X}",
            )

    derived_model = recognize_derived_xor_dispatcher_model(
        mba=mba,
        dispatcher_entry_serial=dispatcher_entry_serial,
    )
    derived_initial_state = None
    if derived_model is not None:
        derived_initial_state = derive_initial_xor_dispatch_state(
            mba=mba,
            pre_header_serial=transition_result.pre_header_serial,
            model=derived_model,
        )

        def _append_derived_transition(
            *,
            state_value: int,
            handler: StateHandler,
            block_serial: int,
        ) -> bool:
            evidence = recognize_carrier_xor_transition(
                mba=mba,
                block_serial=int(block_serial),
                from_state=int(state_value),
                model=derived_model,
                known_states=known_state_set,
            )
            if evidence is None:
                return False
            if evidence.target_state not in cloned_handlers:
                return False
            if int(evidence.target_state) == int(state_value):
                return False
            if any(
                int(transition.to_state) == int(evidence.target_state)
                and getattr(transition, "provenance_kind", None) == evidence.provenance
                for transition in handler.transitions
            ):
                return False
            transition = _build_derived_xor_transition(
                from_state=int(state_value),
                handler=handler,
                evidence=evidence,
            )
            handler.transitions.append(transition)
            transitions.append(transition)
            logger.info(
                "Recovered derived-XOR dispatcher transition: "
                "state 0x%02X blk[%d] via blk[%d] xor 0x%X -> 0x%02X",
                int(state_value) & derived_model.mask,
                int(handler.check_block),
                int(block_serial),
                int(evidence.xor_constant),
                int(evidence.target_state) & derived_model.mask,
            )
            return True

        for state_value, handler in sorted(cloned_handlers.items()):
            if not _handler_needs_dynamic_recovery(handler):
                continue
            if flow_graph is not None and flow_graph.get_block(handler.check_block) is None:
                continue
            before = len(transitions)
            if _append_derived_transition(
                state_value=int(state_value),
                handler=handler,
                block_serial=int(handler.check_block),
            ):
                added += 1
                continue

            try:
                blk = mba.get_mblock(int(handler.check_block))
            except Exception:
                blk = None
            if blk is None or int(getattr(blk, "nsucc", lambda: 0)()) != 2:
                continue
            for succ_index in range(2):
                try:
                    succ_serial = int(blk.succ(succ_index))
                except Exception:
                    continue
                if _append_derived_transition(
                    state_value=int(state_value),
                    handler=handler,
                    block_serial=succ_serial,
                ):
                    added += 1
            if len(transitions) == before:
                continue

        if derived_initial_state is None:
            incoming_states = {
                int(transition.to_state)
                for transition in transitions
                if getattr(transition, "provenance_kind", None)
                == "derived_xor_dispatch_key"
            }
            derived_from_states = {
                int(transition.from_state)
                for transition in transitions
                if getattr(transition, "provenance_kind", None)
                == "derived_xor_dispatch_key"
                and transition.from_state is not None
            }
            candidate_initial_states = sorted(
                int(state) for state in derived_from_states if int(state) not in incoming_states
            )
            if len(candidate_initial_states) == 1:
                derived_initial_state = candidate_initial_states[0]

    if added == 0:
        if (
            derived_initial_state is not None
            and transition_result.initial_state is None
        ):
            return replace(
                transition_result,
                initial_state=int(derived_initial_state),
            )
        return transition_result

    strategy_name = transition_result.strategy_name or "bst_walker"
    if "dynamic_state_write" not in strategy_name:
        strategy_name = f"{strategy_name}+dynamic_state_write"
    if derived_model is not None and "derived_xor_dispatch_key" not in strategy_name:
        strategy_name = f"{strategy_name}+derived_xor_dispatch_key"

    return replace(
        transition_result,
        transitions=transitions,
        handlers=cloned_handlers,
        initial_state=(
            transition_result.initial_state
            if transition_result.initial_state is not None
            else derived_initial_state
        ),
        strategy_name=strategy_name,
        resolved_count=len(transitions),
    )


__all__ = ["recover_dynamic_state_write_transitions"]
