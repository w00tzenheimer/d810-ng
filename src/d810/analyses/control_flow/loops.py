"""Portable loop / region analysis (LLVM-style natural loops).

Backend-neutral loop discovery over a block-successor graph
(``dict[int, tuple[int, ...]]`` keyed by block serial), so portable analyses
(recurrence, induction) can find loops without vendor CFG objects (Landing
Sequence LS8).

The Tarjan SCC routine is COPIED VERBATIM from
``d810.analyses.value_flow.loop_carrier`` rather than imported: that module
transitively pulls ``d810.ir.flowgraph`` (an upward ``analyses -> cfg`` import),
so importing it here would be layer-fatal.  ``Region`` / ``LoopRef`` /
``LoopInfo`` are net-new containers; richer natural-loop construction (header /
back-edge derivation) is added when a consumer needs it.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.ir.directed_graph import tarjan_scc as _canonical_tarjan_scc

__all__ = [
    "LoopInfo",
    "LoopRef",
    "Region",
    "loop_sccs",
    "strongly_connected_components",
]


@dataclass(frozen=True)
class Region:
    """A set of basic blocks forming a single-entry region."""

    blocks: frozenset[int]


@dataclass(frozen=True)
class LoopRef:
    """Identifies a loop by its header block serial."""

    header: int


@dataclass(frozen=True)
class LoopInfo:
    """A natural loop: header block, body blocks, and back-edges into the header."""

    header: int
    blocks: frozenset[int]
    back_edges: tuple[tuple[int, int], ...] = ()


def strongly_connected_components(
    succs_by_block: dict[int, tuple[int, ...]],
) -> tuple[tuple[int, ...], ...]:
    """Tarjan SCC over the block graph (keys-only nodes), as a tuple of
    sorted-tuple components.

    Delegates to the canonical ``d810.ir.directed_graph.tarjan_scc`` (lowest
    layer; pure — it carries none of the import baggage that originally forced
    this verbatim copy). Successors not present as keys are NOT treated as
    nodes (historical semantics), and each component is a sorted tuple.
    """
    keys = set(succs_by_block)
    adj = {
        node: tuple(s for s in succs if s in keys)
        for node, succs in succs_by_block.items()
    }
    return tuple(tuple(sorted(component)) for component in _canonical_tarjan_scc(adj))


def loop_sccs(
    succs_by_block: dict[int, tuple[int, ...]],
) -> tuple[tuple[int, ...], ...]:
    """SCCs that form loops: components with >1 block, plus single blocks that
    have a self-edge."""
    loops: list[tuple[int, ...]] = []
    for comp in strongly_connected_components(succs_by_block):
        if len(comp) > 1 or (
            len(comp) == 1 and comp[0] in succs_by_block.get(comp[0], ())
        ):
            loops.append(comp)
    return tuple(loops)
