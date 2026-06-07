"""Minimal per-handler state-transition recovery (epic d81-jfg2).

The legacy recovery builds a whole state-transition graph by symbolically
DFS-walking multi-block handler paths, classifying exits, detecting corridors,
and running SCC analysis (``evaluate_handler_paths`` + the supplemental DAG
builder).  That machinery drifts across shared blocks into the wrong
handler/exit (e.g. ``0x610BB4D9`` collapsed to the exit state) and produces
diagnostic projections that disagree with the actual output.

This module replaces it with the minimal model:

    transition(handler) = route( fold(handler's next-state write) )

For each handler the dispatcher routes to, we run a **strictly handler-local**
forward scan that:

  * starts at the handler entry with an empty const env,
  * folds the state-var write per block (``_transfer_snapshot_constant_block``
    — the sound local fold, carrying the handler's own constants so shared
    ``xor``/``sub`` suffixes fold to *this* handler's value automatically), and
  * **hard-stops** at the dispatcher entry, *any other handler's entry block*,
    or a STOP/terminal block.

The last folded state-var value on a path is that path's next-state; a 2-way
branch inside the region yields one arm per branch (a conditional transition).
Each next-state is routed through the interval-set dispatcher to its target
handler.  No global graph, no SCC, no exit-classification heuristics, no
drifting walk.

Portable: consumes a :class:`d810.ir.flowgraph.FlowGraph` snapshot and an
:class:`d810.analyses.control_flow.interval_map.IntervalDispatcher`; no live
IDA / Hex-Rays imports.  The MBA fold runs through the registered
``forward_eval_insn`` seam (same as the existing snapshot path eval).
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.state_machine_analysis import (
    _is_stop_block,
    _transfer_snapshot_constant_block,
)

# Default bound on the handler-local corridor scan.  Real OLLVM handler bodies
# (entry -> work -> const-load -> shared MBA suffix -> dispatcher) are short; a
# small bound keeps the scan O(handler) and prevents runaway on malformed CFGs.
_MAX_CORRIDOR_DEPTH = 24

__all__ = [
    "TransitionArm",
    "HandlerTransition",
    "recover_handler_transitions",
]


@dataclass(frozen=True, slots=True)
class TransitionArm:
    """One outgoing edge of a handler.

    A handler with a single arm is an unconditional transition; multiple arms
    (distinct ``next_state``) are a conditional transition selected by
    ``branch_block``'s 2-way branch.
    """

    next_state: int | None       # folded next-state value (None => no write found)
    target_handler: int | None   # dispatcher route of next_state (None when unresolved)
    is_return: bool              # routes to exit/STOP, or no next-state at all
    branch_block: int | None     # the 2-way block that selected this arm (None => unconditional)
    write_block: int | None      # block whose state-var write produced next_state
    exit_block: int | None       # last block of the scanned path (the boundary)


@dataclass(frozen=True, slots=True)
class HandlerTransition:
    """All outgoing edges recovered for one handler block."""

    handler: int                 # handler entry block serial
    states: tuple[int, ...]      # representative states the dispatcher routes here
    arms: tuple[TransitionArm, ...]

    @property
    def is_conditional(self) -> bool:
        return len(self.arms) > 1


def _handler_entries(dispatcher) -> set[int]:
    """Distinct handler blocks the dispatcher routes to (excluding the default/exit)."""
    default = dispatcher.default_target
    return {
        int(row.target)
        for row in getattr(dispatcher, "_rows", ())
        if row.target is not None and int(row.target) != (int(default) if default is not None else None)
    }


def _states_by_handler(dispatcher) -> dict[int, list[int]]:
    """Map handler block -> representative state values routed to it (one per row lo)."""
    out: dict[int, list[int]] = {}
    for row in getattr(dispatcher, "_rows", ()):
        if row.target is None:
            continue
        out.setdefault(int(row.target), []).append(int(row.lo))
    return out


def _scan_handler(
    flow_graph,
    entry: int,
    *,
    state_var_stkoff: int,
    dispatcher_entry_serial: int | None,
    handler_entries: set[int],
    max_depth: int = _MAX_CORRIDOR_DEPTH,
) -> list[tuple[int | None, int | None, int]]:
    """Strictly handler-local forward scan from *entry*.

    Returns a list of ``(next_state, branch_block, exit_block)`` — one entry per
    distinct terminal path.  ``next_state`` is the last folded state-var value on
    that path (``None`` if the handler writes no next-state).  The scan stops at:
    the dispatcher entry, any *other* handler's entry block, or a STOP/terminal.
    """

    results: list[tuple[int | None, int | None, int]] = []
    # stack frames: (block_serial, stk_map, reg_map, branch_block, visited, depth)
    stack: list[tuple[int, dict, dict, int | None, frozenset[int], int]] = [
        (int(entry), {}, {}, None, frozenset({int(entry)}), 0)
    ]

    while stack:
        blk_serial, stk, reg, branch, visited, depth = stack.pop()
        block = flow_graph.get_block(blk_serial)
        if block is None:
            results.append((stk.get(state_var_stkoff), branch, blk_serial))
            continue

        # Fold this block's state-var write into the carried const env.
        nstk, nreg = _transfer_snapshot_constant_block(
            block, dict(stk), dict(reg), state_var_stkoff
        )
        running_state = nstk.get(state_var_stkoff)

        succs = tuple(int(s) for s in block.succs)

        def _is_boundary_succ(s: int) -> bool:
            if dispatcher_entry_serial is not None and s == int(dispatcher_entry_serial):
                return True
            if s in handler_entries and s != int(entry):
                return True
            succ_block = flow_graph.get_block(s)
            return _is_stop_block(succ_block)

        onward = [
            s
            for s in succs
            if s not in visited and not _is_boundary_succ(s)
        ]

        terminal = (
            not succs
            or _is_stop_block(block)
            or not onward
            or depth >= max_depth
        )
        if terminal:
            results.append((running_state, branch, blk_serial))
            continue

        # A 2-way block whose arms continue is a state-selecting branch.
        new_branch = branch if len(succs) < 2 else blk_serial
        for s in onward:
            stack.append(
                (s, nstk, nreg, new_branch, visited | {s}, depth + 1)
            )

    return results


def _classify_arm(
    next_state: int | None,
    branch_block: int | None,
    exit_block: int,
    *,
    dispatcher,
    flow_graph,
) -> TransitionArm:
    default = dispatcher.default_target
    target: int | None = None
    is_return = False
    if next_state is None:
        is_return = True
    else:
        routed = dispatcher.lookup(int(next_state) & 0xFFFFFFFF)
        if routed is None:
            is_return = True
        elif default is not None and int(routed) == int(default):
            target = int(routed)
            is_return = True
        elif _is_stop_block(flow_graph.get_block(int(routed))):
            target = int(routed)
            is_return = True
        else:
            target = int(routed)
    return TransitionArm(
        next_state=(int(next_state) & 0xFFFFFFFF) if next_state is not None else None,
        target_handler=target,
        is_return=is_return,
        branch_block=branch_block,
        write_block=exit_block,
        exit_block=exit_block,
    )


def recover_handler_transitions(
    flow_graph,
    dispatcher,
    state_var_stkoff: int,
    *,
    dispatcher_entry_serial: int | None = None,
    max_depth: int = _MAX_CORRIDOR_DEPTH,
) -> tuple[HandlerTransition, ...]:
    """Recover each handler's outgoing transition(s) via the minimal model.

    Args:
        flow_graph: a :class:`d810.ir.flowgraph.FlowGraph` snapshot.
        dispatcher: an :class:`IntervalDispatcher` (state value -> handler block).
        state_var_stkoff: the dispatcher state variable's stack offset.
        dispatcher_entry_serial: the dispatcher block the handlers loop back to;
            used as a scan boundary.  Falls back to the dispatcher's most-routed
            block when not supplied is intentionally NOT done — callers should
            pass it.
        max_depth: corridor-scan bound.

    Returns:
        One :class:`HandlerTransition` per handler block, ordered by serial.
    """

    handler_entries = _handler_entries(dispatcher)
    states_by_handler = _states_by_handler(dispatcher)
    results: list[HandlerTransition] = []

    for handler in sorted(handler_entries):
        paths = _scan_handler(
            flow_graph,
            handler,
            state_var_stkoff=int(state_var_stkoff),
            dispatcher_entry_serial=dispatcher_entry_serial,
            handler_entries=handler_entries,
            max_depth=max_depth,
        )
        # Dedup arms by next_state: identical next-states on multiple paths are
        # the same edge (a degenerate branch), not a conditional.
        seen: dict[int | None, TransitionArm] = {}
        for next_state, branch_block, exit_block in paths:
            key = (int(next_state) & 0xFFFFFFFF) if next_state is not None else None
            if key in seen:
                continue
            seen[key] = _classify_arm(
                next_state,
                branch_block,
                exit_block,
                dispatcher=dispatcher,
                flow_graph=flow_graph,
            )
        arms = tuple(seen.values())
        # A multi-path handler whose arms all fold to the same state collapses to
        # one unconditional arm with no branch attribution.
        if len(arms) == 1:
            arms = (
                TransitionArm(
                    next_state=arms[0].next_state,
                    target_handler=arms[0].target_handler,
                    is_return=arms[0].is_return,
                    branch_block=None,
                    write_block=arms[0].write_block,
                    exit_block=arms[0].exit_block,
                ),
            )
        results.append(
            HandlerTransition(
                handler=int(handler),
                states=tuple(sorted(states_by_handler.get(int(handler), ()))),
                arms=arms,
            )
        )

    return tuple(results)
