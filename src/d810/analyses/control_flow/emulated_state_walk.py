"""Shape-agnostic state-machine recovery by concrete emulation (ticket llr-a93i, Slice 5).

The static dispatcher resolvers (equality-chain, switch-table) recognize a dispatcher by
its STATIC compare shape: ``state == const`` or ``switch(state & MASK)``. They cannot
recover a dispatcher whose selector is a NON-IDENTITY function of the state -- e.g. the
XOR-masked ``switch((state ^ KEY) & MASK)`` with full-width ``state ^= magic`` transitions
(``abc_xor_dispatch``). There the compared case labels are sub-threshold *byte projections*
of the state, not the state itself, and the real state values are never compared directly,
so ``build_state_dispatcher_map_from_flow_graph`` / ``analyze_switch_table_flow_graph`` both
return ``map_rows=0``.

Such a machine is recovered the only sound way: by EXECUTING it. Seeded with the prologue's
initial state, the walk emulates the dispatcher to learn which handler a concrete state
routes to (the selector projection is *evaluated*, never pattern-matched), emulates that
handler to learn the next state(s), and repeats over the reachable state set. The result is
an exact ``state_const -> target_block`` table keyed by the REAL state values -- the same
relation the static resolvers produce, so the existing emit path consumes it unchanged.

The walk itself is pure (this module): the two oracles -- "which handler does state S route
to" and "what state(s) does handler H produce from S" -- are injected callables. The live
Hex-Rays implementation of those oracles (seed + ``MicroCodeInterpreter``) lives in the
backend adapter, keeping this core IDA-free and unit-testable (``portable-core-no-ida``).
"""
from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

__all__ = [
    "DEFAULT_MAX_STATES",
    "EmulatedWalkRow",
    "EmulatedWalkResult",
    "ResolveHandler",
    "AdvanceStates",
    "IsTerminalHandler",
    "walk_emulated_state_machine",
]

_U64 = 0xFFFFFFFFFFFFFFFF

#: Hard cap on distinct states walked, so a mis-identified machine (or a genuine state
#: explosion) can never spin: a flattened dispatcher has O(handlers) states, so a few
#: hundred is already far past any real obfuscated function.
DEFAULT_MAX_STATES = 512


@dataclass(frozen=True, slots=True)
class EmulatedWalkRow:
    """One recovered ``state_const -> target_block`` edge (dispatcher-shape neutral)."""

    state_const: int
    target_block: int


@dataclass(frozen=True, slots=True)
class EmulatedWalkResult:
    """Recovered rows plus walk diagnostics (proof-carrying observability).

    ``rows`` is the exact state->handler table.  The diagnostic tuples make the walk
    auditable: ``visited_states`` is the BFS order, ``unresolved_states`` are states whose
    handler the emulator could not prove (abstained, never guessed), ``terminal_states`` are
    states whose handler is an exit/return (the walk stops there), and ``truncated`` is set
    iff the ``max_states`` budget was hit before the frontier drained.
    """

    rows: tuple[EmulatedWalkRow, ...]
    visited_states: tuple[int, ...]
    unresolved_states: tuple[int, ...]
    terminal_states: tuple[int, ...]
    truncated: bool

    @property
    def state_to_handler(self) -> dict[int, int]:
        """Return the recovered ``state_const -> target_block`` mapping."""
        return {row.state_const: row.target_block for row in self.rows}


#: state -> handler block serial, or ``None`` when the handler cannot be proven (abstain).
ResolveHandler = Callable[[int], "int | None"]
#: (state, handler) -> the next state value(s) the handler produces (1 normally, 2 for a
#: conditional handler arm).  Returning ``()`` ends that branch without a terminal mark.
AdvanceStates = Callable[[int, int], "tuple[int, ...]"]
#: handler block serial -> whether it is an exit/return (the walk stops at it).
IsTerminalHandler = Callable[[int], bool]


def walk_emulated_state_machine(
    initial_state: int,
    resolve_handler: ResolveHandler,
    advance_states: AdvanceStates,
    is_terminal_handler: IsTerminalHandler,
    *,
    max_states: int = DEFAULT_MAX_STATES,
) -> EmulatedWalkResult:
    """Recover the exact state->handler table by concrete BFS over the state set.

    Starting from ``initial_state``: resolve the handler the dispatcher routes the state to
    (``resolve_handler`` -- the selector projection is *evaluated* here, so any dispatcher
    shape works), record the exact ``state -> handler`` row, and unless the handler is
    terminal, enqueue every next state the handler produces (``advance_states`` -- one value
    normally, two for a conditional handler arm). Each distinct state is resolved once; the
    walk terminates when the frontier drains or ``max_states`` distinct states are visited.

    NEVER fabricates an edge: a state whose handler cannot be proven (``resolve_handler``
    returns ``None``) is recorded in ``unresolved_states`` and dropped, not guessed -- so a
    partially-emulable machine yields a partial-but-sound table rather than wrong edges.

    Examples
    --------
    A two-state linear machine whose selector is ``state ^ 0xFF`` (non-identity), proving the
    walk routes by the REAL state, evaluating the projection:

    >>> handler_by_selector = {0x00: 10, 0x01: 11}
    >>> magic = {10: 0x01}  # state 0xFF -> sel 0x00 -> h10; h10 XORs to 0xFE -> sel 0x01 -> h11
    >>> res = walk_emulated_state_machine(
    ...     0xFF,
    ...     resolve_handler=lambda s: handler_by_selector.get((s ^ 0xFF) & 0xFF),
    ...     advance_states=lambda s, h: (s ^ magic[h],) if h in magic else (),
    ...     is_terminal_handler=lambda h: h == 11,
    ... )
    >>> res.state_to_handler
    {255: 10, 254: 11}
    >>> res.terminal_states
    (254,)
    >>> res.unresolved_states
    ()
    """
    rows: list[EmulatedWalkRow] = []
    visited: set[int] = set()
    order: list[int] = []
    unresolved: list[int] = []
    terminal: list[int] = []
    seen_rows: set[tuple[int, int]] = set()
    truncated = False

    queue: deque[int] = deque([int(initial_state) & _U64])
    while queue:
        state = queue.popleft()
        if state in visited:
            continue
        if len(visited) >= max_states:
            truncated = True
            break
        visited.add(state)
        order.append(state)

        handler = resolve_handler(state)
        if handler is None:
            unresolved.append(state)
            continue
        handler = int(handler)

        row_key = (state, handler)
        if row_key not in seen_rows:
            seen_rows.add(row_key)
            rows.append(EmulatedWalkRow(state_const=state, target_block=handler))

        if is_terminal_handler(handler):
            terminal.append(state)
            continue

        for next_state in advance_states(state, handler):
            next_state = int(next_state) & _U64
            if next_state not in visited:
                queue.append(next_state)

    return EmulatedWalkResult(
        rows=tuple(rows),
        visited_states=tuple(order),
        unresolved_states=tuple(unresolved),
        terminal_states=tuple(terminal),
        truncated=truncated,
    )
