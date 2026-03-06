"""Graph-portable dispatcher transition analysis models.

This module is intentionally backend-agnostic. It consumes a lifted
``FlowGraph`` plus transition metadata and produces semantic observations that
can later be rendered into a canonical transition report.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from d810.cfg.flowgraph import FlowGraph
from d810.core.typing import Iterable, Mapping, Optional, Sequence, Tuple
from d810.recon.flow.transition_builder import TransitionResult


@dataclass(frozen=True)
class HandlerTransitionObservation:
    """Portable semantic observation for one handler entry."""

    handler_serial: int
    state_const: Optional[int]
    state_range_lo: Optional[int]
    state_range_hi: Optional[int]
    next_state: Optional[int]
    conditional_states: Tuple[int, ...]
    chain: Tuple[int, ...]
    back_edge: bool
    reaches_exit_block: bool
    classified_exit: bool
    unresolved: bool


@dataclass(frozen=True)
class DispatcherTransitionAnalysis:
    """Portable transition analysis payload, prior to report rendering."""

    dispatcher_entry_serial: int
    state_var_stkoff: Optional[int]
    state_var_lvar_idx: Optional[int]
    pre_header_serial: Optional[int]
    initial_state: Optional[int]
    handler_state_map: Mapping[int, int]
    handler_range_map: Mapping[int, Tuple[Optional[int], Optional[int]]]
    bst_node_blocks: Tuple[int, ...]
    observations: Tuple[HandlerTransitionObservation, ...]
    diagnostics: Tuple[str, ...] = ()


def _shortest_path_to_any_exit(
    flow_graph: FlowGraph,
    start_serial: int,
    exits: frozenset[int],
) -> tuple[tuple[int, ...], bool]:
    """Return the shortest path from *start_serial* to any exit block."""
    if start_serial in exits:
        return (start_serial,), True
    if not exits:
        return (start_serial,), False

    queue = deque([(start_serial, (start_serial,))])
    visited = {start_serial}
    while queue:
        serial, path = queue.popleft()
        for succ in flow_graph.successors(serial):
            if succ in visited:
                continue
            next_path = path + (succ,)
            if succ in exits:
                return next_path, True
            visited.add(succ)
            queue.append((succ, next_path))
    return (start_serial,), False


def build_transition_analysis_from_graph(
    flow_graph: FlowGraph,
    transition_result: TransitionResult,
    *,
    dispatcher_entry_serial: int,
    state_var_stkoff: Optional[int] = None,
    state_var_lvar_idx: Optional[int] = None,
    pre_header_serial: Optional[int] = None,
    initial_state: Optional[int] = None,
    handler_range_map: Mapping[int, tuple[Optional[int], Optional[int]]] | None = None,
    bst_node_blocks: Iterable[int] = (),
    diagnostics: Sequence[str] = (),
) -> DispatcherTransitionAnalysis:
    """Build portable handler transition observations from a ``FlowGraph``."""
    range_map = handler_range_map or {}
    exits = frozenset(
        serial for serial, block in flow_graph.blocks.items() if not block.succs
    )

    observations: list[HandlerTransitionObservation] = []
    for state_const, handler in sorted(transition_result.handlers.items()):
        conditional_states = tuple(
            sorted(
                {
                    transition.to_state
                    for transition in handler.transitions
                    if transition.is_conditional
                }
            )
        )
        unconditional_targets = [
            transition.to_state
            for transition in handler.transitions
            if not transition.is_conditional
        ]
        next_state = unconditional_targets[0] if unconditional_targets else None

        chain: tuple[int, ...]
        reaches_exit_block: bool
        if next_state is None and not conditional_states:
            chain, reaches_exit_block = _shortest_path_to_any_exit(
                flow_graph,
                handler.check_block,
                exits,
            )
        else:
            chain = (handler.check_block,)
            reaches_exit_block = False

        classified_exit = reaches_exit_block and next_state is None and not conditional_states
        unresolved = not classified_exit and next_state is None and not conditional_states
        state_range = range_map.get(handler.check_block)
        range_lo = state_range[0] if state_range else None
        range_hi = state_range[1] if state_range else None

        observations.append(
            HandlerTransitionObservation(
                handler_serial=handler.check_block,
                state_const=state_const,
                state_range_lo=range_lo,
                state_range_hi=range_hi,
                next_state=next_state,
                conditional_states=conditional_states,
                chain=chain,
                back_edge=bool(next_state is not None or conditional_states),
                reaches_exit_block=reaches_exit_block,
                classified_exit=classified_exit,
                unresolved=unresolved,
            )
        )

    handler_state_map = {
        handler.check_block: state_const
        for state_const, handler in transition_result.handlers.items()
    }
    return DispatcherTransitionAnalysis(
        dispatcher_entry_serial=dispatcher_entry_serial,
        state_var_stkoff=state_var_stkoff,
        state_var_lvar_idx=state_var_lvar_idx,
        pre_header_serial=(
            pre_header_serial
            if pre_header_serial is not None
            else transition_result.pre_header_serial
        ),
        initial_state=(
            initial_state
            if initial_state is not None
            else transition_result.initial_state
        ),
        handler_state_map=handler_state_map,
        handler_range_map=dict(range_map),
        bst_node_blocks=tuple(sorted(bst_node_blocks)),
        observations=tuple(observations),
        diagnostics=tuple(diagnostics),
    )


__all__ = [
    "HandlerTransitionObservation",
    "DispatcherTransitionAnalysis",
    "build_transition_analysis_from_graph",
]
