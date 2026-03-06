"""BST-specific adapter for canonical dispatcher transition reporting.

This module isolates direct use of BST private walker helpers so
``transition_report.py`` can focus on rendering portable analysis outputs.
"""
from __future__ import annotations

from d810.core.typing import Any, Optional

from d810.recon.flow.bst_analysis import (
    _detect_state_var_stkoff,
    _dump_dispatcher_node,
    _find_pre_header_state,
    _walk_handler_chain,
)
from d810.recon.flow.transition_analysis import (
    DispatcherTransitionAnalysis,
    HandlerTransitionObservation,
)


def analyze_bst_dispatcher(
    mba: Any,
    dispatcher_entry_serial: int,
    *,
    state_var_stkoff: Optional[int] = None,
    state_var_lvar_idx: Optional[int] = None,
    max_bst_depth: int = 20,
    max_chain_depth: int = 64,
    transitions_hint_by_handler: Optional[dict[int, int]] = None,
    capture_diagnostics: bool = False,
    max_diag_handlers: int = 3,
) -> DispatcherTransitionAnalysis:
    """Adapt BST walker data into portable transition observations."""
    diagnostics: list[str] = [] if capture_diagnostics else []

    if state_var_stkoff is None:
        if capture_diagnostics:
            (detected, detected_lvar_idx), detect_diag = _detect_state_var_stkoff(
                mba, dispatcher_entry_serial, diag=True
            )
            diagnostics.extend(detect_diag)
        else:
            detected, detected_lvar_idx = _detect_state_var_stkoff(
                mba, dispatcher_entry_serial, diag=False
            )
        if detected is not None:
            state_var_stkoff = detected
            if state_var_lvar_idx is None:
                state_var_lvar_idx = detected_lvar_idx

    pre_header_serial, initial_state = _find_pre_header_state(
        mba,
        dispatcher_entry_serial,
        state_var_stkoff,
        diag_lines=diagnostics if capture_diagnostics else None,
        state_var_lvar_idx=state_var_lvar_idx,
    )

    handler_state_map: dict[int, int] = {}
    handler_serials: set[int] = set()
    handler_range_map: dict[int, tuple[Optional[int], Optional[int]]] = {}
    bst_node_blocks: set[int] = set()
    _dump_dispatcher_node(
        mba,
        dispatcher_entry_serial,
        indent=0,
        visited=set(),
        lines=[],
        depth=0,
        max_depth=max_bst_depth,
        value_lo=0,
        value_hi=0xFFFFFFFF,
        handler_state_map=handler_state_map,
        handler_serials=handler_serials,
        handler_range_map=handler_range_map,
        bst_node_blocks=bst_node_blocks,
    )

    observations: list[HandlerTransitionObservation] = []
    diag_handlers = 0
    for handler_serial in sorted(handler_serials):
        handler_diag: list[str] | None = None
        if capture_diagnostics and diag_handlers < max_diag_handlers:
            handler_diag = []
            diagnostics.append(
                f"Handler blk[{handler_serial}] (state="
                f"{hex(handler_state_map.get(handler_serial)) if handler_state_map.get(handler_serial) is not None else '?'}):"
            )
            diag_handlers += 1

        if state_var_stkoff is not None:
            walk = _walk_handler_chain(
                mba,
                handler_serial,
                dispatcher_entry_serial,
                state_var_stkoff,
                chain_visited=set(),
                max_chain_depth=max_chain_depth,
                diag_lines=handler_diag,
                state_var_lvar_idx=state_var_lvar_idx,
            )
        else:
            walk = {"next_state": None, "back_edge": False, "exit": False, "chain": []}

        if handler_diag is not None:
            diagnostics.extend(handler_diag)

        next_state = walk.get("next_state")
        if transitions_hint_by_handler is not None and next_state is None:
            hinted = transitions_hint_by_handler.get(handler_serial)
            if hinted is not None:
                next_state = hinted

        conditional_states = tuple(sorted(walk.get("conditional_states", set())))
        state_range = handler_range_map.get(handler_serial)
        observations.append(
            HandlerTransitionObservation(
                handler_serial=handler_serial,
                state_const=handler_state_map.get(handler_serial),
                state_range_lo=state_range[0] if state_range else None,
                state_range_hi=state_range[1] if state_range else None,
                next_state=next_state,
                conditional_states=conditional_states,
                chain=tuple(walk.get("chain", ())),
                back_edge=bool(walk.get("back_edge")),
                reaches_exit_block=bool(walk.get("exit")),
                classified_exit=bool(walk.get("exit")),
                unresolved=(
                    not bool(walk.get("exit"))
                    and next_state is None
                    and not conditional_states
                ),
            )
        )

    observations.sort(
        key=lambda obs: (
            obs.state_const is None,
            obs.state_const if obs.state_const is not None else 0,
            obs.handler_serial,
        )
    )

    return DispatcherTransitionAnalysis(
        dispatcher_entry_serial=dispatcher_entry_serial,
        state_var_stkoff=state_var_stkoff,
        state_var_lvar_idx=state_var_lvar_idx,
        pre_header_serial=pre_header_serial,
        initial_state=initial_state,
        handler_state_map=handler_state_map,
        handler_range_map=handler_range_map,
        bst_node_blocks=tuple(sorted(bst_node_blocks)),
        observations=tuple(observations),
        diagnostics=tuple(diagnostics),
    )


__all__ = ["analyze_bst_dispatcher"]
