"""Portable forking-walk wrapper for the concolic engine (P2, ticket llr-8wq9).

The pure :func:`walk_emulated_state_machine` core (emulated_state_walk.py) ALREADY
forks: ``advance_states`` returns a tuple and every element is enqueued, so a
2-tuple is a conditional arm fanned out into two next states. What it does NOT do
is *record the edge*: Slice 5 kept only the ``state -> handler`` rows and threw
away the structural fact ``state -> {next_a, next_b} via handler_block`` that the
P4 reduced-product orchestrator needs (design §4).

This wrapper closes that gap WITHOUT touching the proven BFS core: it drives the
same walk but wraps the injected ``advance_states`` oracle so that, as a side
effect, each ``(state -> next_states...)`` fan-out is appended -- with its
``via_block`` / ``op`` / ``const`` provenance -- to a sink list the wrapper owns.
The result pairs the unchanged :class:`EmulatedWalkResult` with the recorded
:class:`WalkTransition` edges.

IDA-free by construction (``portable-core-no-ida``): the oracles are injected
callables; the live Hex-Rays implementation of those oracles (seed +
``MicroCodeInterpreter``) lives in the backend engine and feeds the per-fork
provenance in through :class:`ForkOutcome`. The walk itself never imports IDA.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from d810.analyses.control_flow.emulated_state_walk import (
    DEFAULT_MAX_STATES,
    EmulatedWalkResult,
    IsTerminalHandler,
    ResolveHandler,
    walk_emulated_state_machine,
)

__all__ = [
    "ForkOutcome",
    "WalkTransition",
    "ForkingAdvance",
    "ForkingWalkResult",
    "walk_forking_state_machine",
]


@dataclass(frozen=True, slots=True)
class ForkOutcome:
    """One handler's next-state fan-out, WITH the provenance that produced it.

    The forking oracle returns this instead of the bare ``tuple[int, ...]`` the
    core walk expects. ``next_states`` is 1 element for a linear handler and 2 for
    a fully-enumerated conditional arm (design §4 first-class fork). ``via_block``
    is the handler block serial the fork came from; ``op`` is the portable operator
    string (e.g. ``"^"``, or ``None`` for a ``mov #const`` arm) and ``const`` the
    transition constant. An EMPTY ``next_states`` ends that branch (terminal/exit)
    and records no transition.
    """

    next_states: tuple[int, ...]
    via_block: int | None = None
    op: str | None = None
    const: int | None = None


@dataclass(frozen=True, slots=True)
class WalkTransition:
    """A recovered forking edge: ``src_state -> next_states`` via a handler block.

    Pure-data carrier the backend lifts into the P1 ``MachineTransition`` contract.
    Kept here (not the contract type) so this module stays a leaf with no upward
    dependency on ``recovered_machine`` -- the engine does the one-line lift.
    """

    src_state: int
    next_states: tuple[int, ...]
    via_block: int | None = None
    op: str | None = None
    const: int | None = None


#: (state, handler) -> the fan-out PLUS provenance.  The forking analogue of the
#: core ``AdvanceStates`` oracle (which returns a bare tuple).
ForkingAdvance = Callable[[int, int], ForkOutcome]


@dataclass(frozen=True, slots=True)
class ForkingWalkResult:
    """The unchanged walk result paired with the recorded forking edges."""

    walk: EmulatedWalkResult
    transitions: tuple[WalkTransition, ...]


def walk_forking_state_machine(
    initial_state: int,
    resolve_handler: ResolveHandler,
    advance_states: ForkingAdvance,
    is_terminal_handler: IsTerminalHandler,
    *,
    max_states: int = DEFAULT_MAX_STATES,
) -> ForkingWalkResult:
    """Drive the core walk with a forking oracle and record every fan-out edge.

    Identical recovery to :func:`walk_emulated_state_machine` (same BFS, same
    visited-set, same abstain-never-guess, same ``max_states`` cap) -- this only
    *observes* the fan-out the core already performs and records it as a
    :class:`WalkTransition` with provenance. A handler whose ``ForkOutcome`` has an
    empty ``next_states`` produces no transition (terminal / dead branch).

    Each ``(src_state, via_block)`` pair is recorded at most once: the core walk
    resolves each distinct state once, so an oracle that re-derives facts for an
    already-recorded edge is deduped here, matching the core's row dedup.

    Examples
    --------
    A conditional handler that forks state ``0xFF`` into two arms is recorded as a
    single transition with two ``next_states`` (the first-class fork, design §4):

    >>> def resolve(s):
    ...     return {0xFF: 10, 0xAA: 11, 0xBB: 11}.get(s)
    >>> def advance(s, h):
    ...     if s == 0xFF:
    ...         return ForkOutcome((0xAA, 0xBB), via_block=10, op=None, const=None)
    ...     return ForkOutcome(())
    >>> res = walk_forking_state_machine(
    ...     0xFF, resolve, advance, is_terminal_handler=lambda h: h == 11
    ... )
    >>> res.walk.state_to_handler == {0xFF: 10, 0xAA: 11, 0xBB: 11}
    True
    >>> [t.next_states for t in res.transitions]
    [(170, 187)]

    The single recorded edge is the 2-arm fork ``0xFF -> (0xAA=170, 0xBB=187)`` via
    handler block 10; the two terminal handlers (11) record no transition.
    """
    transitions: list[WalkTransition] = []
    seen_edges: set[tuple[int, int | None]] = set()

    def _advance(state: int, handler: int) -> tuple[int, ...]:
        outcome = advance_states(state, handler)
        next_states = tuple(int(s) for s in outcome.next_states)
        if next_states:
            edge_key = (int(state), outcome.via_block)
            if edge_key not in seen_edges:
                seen_edges.add(edge_key)
                transitions.append(
                    WalkTransition(
                        src_state=int(state),
                        next_states=next_states,
                        via_block=outcome.via_block,
                        op=outcome.op,
                        const=outcome.const,
                    )
                )
        return next_states

    walk = walk_emulated_state_machine(
        initial_state,
        resolve_handler,
        _advance,
        is_terminal_handler,
        max_states=max_states,
    )
    return ForkingWalkResult(walk=walk, transitions=tuple(transitions))
