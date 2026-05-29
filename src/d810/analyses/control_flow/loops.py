"""Portable loop / region analysis (LLVM-style natural loops).

Backend-neutral loop discovery over a block-successor graph
(``dict[int, tuple[int, ...]]`` keyed by block serial), so portable analyses
(recurrence, induction) can find loops without vendor CFG objects (Landing
Sequence LS8).

The Tarjan SCC routine is COPIED VERBATIM from
``d810.recon.facts.collectors.loop_carrier`` rather than imported: that module
transitively pulls ``d810.cfg.flowgraph`` (an upward ``analyses -> cfg`` import),
so importing it here would be layer-fatal.  ``Region`` / ``LoopRef`` /
``LoopInfo`` are net-new containers; richer natural-loop construction (header /
back-edge derivation) is added when a consumer needs it.
"""
from __future__ import annotations

from dataclasses import dataclass

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
    """Tarjan SCC over the block graph.

    Copied verbatim from ``d810.recon.facts.collectors.loop_carrier`` to keep
    ``d810.analyses`` free of the ``d810.cfg`` import that module carries.
    """
    index = 0
    stack: list[int] = []
    on_stack: set[int] = set()
    indexes: dict[int, int] = {}
    lowlinks: dict[int, int] = {}
    components: list[tuple[int, ...]] = []

    def visit(node: int) -> None:
        nonlocal index
        indexes[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)

        for succ in succs_by_block.get(node, ()):
            if succ not in succs_by_block:
                continue
            if succ not in indexes:
                visit(succ)
                lowlinks[node] = min(lowlinks[node], lowlinks[succ])
            elif succ in on_stack:
                lowlinks[node] = min(lowlinks[node], indexes[succ])

        if lowlinks[node] != indexes[node]:
            return

        component: list[int] = []
        while stack:
            popped = stack.pop()
            on_stack.remove(popped)
            component.append(popped)
            if popped == node:
                break
        components.append(tuple(sorted(component)))

    for node in sorted(succs_by_block):
        if node not in indexes:
            visit(node)
    return tuple(components)


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
