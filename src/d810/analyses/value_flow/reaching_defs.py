"""Reaching-definitions ``FlowDomain`` (angr RDA / LLVM, LiSA-style).

Forward, finite-height lattice over storage locations: for each location, the
set of *definition sites* that reach a program point. Backend-neutral -- the
per-block gen/kill facts are injected, so the domain is unit-testable without
IDA; a Hex-Rays evidence provider builds the facts from live microcode via the
``valranges`` collectors in a later slice.

State is a flat ``frozenset`` of ``(location, def_site)`` pairs, so ``meet`` is
plain set union and the lattice is immutable. Definition sites are finite, so
the lattice has finite height and ``widen`` is the identity (no acceleration
needed).

This is the LLVM ``ReachingDefinitions`` / angr ``ReachingDefinitionsAnalysis``
analog, expressed against the portable :mod:`d810.analyses.data_flow` engine.
Run it forward to answer "which definition of the return-slot carrier reaches a
terminal, and does a dominating real carrier (e.g. ``a5+0xD0``) survive there?".
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.typing import Any, Mapping

# Opaque, hashable identifiers (block serial / storage location / def site).
Loc = Any
DefSite = Any
#: A reaching-defs lattice element: the set of ``(location, def_site)`` pairs
#: that reach a program point.
ReachingState = frozenset

__all__ = ["BlockReachingFacts", "ReachingDefsDomain", "reaching_defs_of"]


@dataclass(frozen=True, slots=True)
class BlockReachingFacts:
    """Per-block gen/kill for reaching definitions.

    ``gen`` maps each location *defined* in the block to the def-site(s) it
    generates. Its keys are simultaneously the kill set: a new definition of a
    location kills every incoming definition of that location.
    """

    gen: Mapping[Loc, frozenset[DefSite]] = field(default_factory=dict)


class ReachingDefsDomain:
    """Forward reaching-definitions lattice (a :class:`FlowDomain`)."""

    def __init__(self, block_facts: Mapping[int, BlockReachingFacts]) -> None:
        self._facts = block_facts

    def bottom(self) -> ReachingState:
        """Least element: no definition reaches yet."""
        return frozenset()

    def meet(self, left: ReachingState, right: ReachingState) -> ReachingState:
        """Merge point: a definition reaches if it reaches on any path."""
        return left | right

    def transfer(self, node: int, in_state: ReachingState) -> ReachingState:
        """Apply the block's kill (defined locations) then gen (new sites)."""
        facts = self._facts.get(node)
        if facts is None or not facts.gen:
            return in_state
        killed_locs = set(facts.gen.keys())
        survived = frozenset(
            (loc, site) for (loc, site) in in_state if loc not in killed_locs
        )
        generated = frozenset(
            (loc, site) for loc, sites in facts.gen.items() for site in sites
        )
        return survived | generated

    def equals(self, left: ReachingState, right: ReachingState) -> bool:
        """Fixpoint test: set equality."""
        return left == right

    def widen(self, previous: ReachingState, current: ReachingState) -> ReachingState:
        """Finite-height lattice: no widening required."""
        return current


def reaching_defs_of(state: ReachingState, location: Loc) -> frozenset[DefSite]:
    """Return the def-sites of ``location`` in a reaching-defs lattice element."""
    return frozenset(site for (loc, site) in state if loc == location)
