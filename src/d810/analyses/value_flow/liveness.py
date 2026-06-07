"""Live-variable ``FlowDomain`` (classic backward liveness, LLVM/LiSA-style).

Backward, finite-height lattice over storage locations: a location is *live* at
a program point if some path from there uses it before redefining it.
Backend-neutral -- per-block use/def facts are injected, so the domain is
unit-testable without IDA (a Hex-Rays evidence provider builds them from live
microcode via the ``valranges`` collectors in a later slice).

Run with :data:`~d810.analyses.data_flow.configuration.Direction.BACKWARD`:
``entry_nodes`` are the exit blocks and ``entry_state`` is the set of locations
live at function exit (e.g. the return slot). Under the engine's reversed edge
relation, a node's ``in_state`` is its **live-OUT** and ``out_state`` is its
**live-IN** (``live_in = used | (live_out - defined)``).

This answers "is the dispatcher state variable dead at the aligned terminal?"
-- the liveness half of the carrier-delivery decision.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.typing import Any, Mapping

Loc = Any
#: A liveness lattice element: the set of locations live at a program point.
LivenessState = frozenset

__all__ = ["BlockLivenessFacts", "LivenessDomain"]


@dataclass(frozen=True, slots=True)
class BlockLivenessFacts:
    """Per-block use/def sets for live-variable analysis.

    ``used`` is the set of locations read before any redefinition in the block
    (upward-exposed uses); ``defined`` is the set of locations the block writes
    (the kill set for liveness).
    """

    used: frozenset[Loc] = field(default_factory=frozenset)
    defined: frozenset[Loc] = field(default_factory=frozenset)


class LivenessDomain:
    """Backward live-variable lattice (a :class:`FlowDomain`)."""

    def __init__(self, block_facts: Mapping[int, BlockLivenessFacts]) -> None:
        self._facts = block_facts

    def bottom(self) -> LivenessState:
        """Least element: nothing live."""
        return frozenset()

    def confluence(self, left: LivenessState, right: LivenessState) -> LivenessState:
        """Merge point: live if live on any successor path."""
        return left | right

    def transfer(self, node: int, in_state: LivenessState) -> LivenessState:
        """``live_in = used | (live_out - defined)`` (``in_state`` is live-OUT)."""
        facts = self._facts.get(node)
        if facts is None:
            return in_state
        return facts.used | (in_state - facts.defined)

    def equals(self, left: LivenessState, right: LivenessState) -> bool:
        """Fixpoint test: set equality."""
        return left == right

    def widen(self, previous: LivenessState, current: LivenessState) -> LivenessState:
        """Finite-height lattice: no widening required."""
        return current
