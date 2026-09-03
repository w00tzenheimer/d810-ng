"""Portable per-cell reaching definitions for aliased stack memory."""

from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Callable, Iterable, Optional


@dataclass(frozen=True, slots=True)
class AliasedStackDefSite:
    """A concrete or possible definition site for one stack cell."""

    block_serial: int
    ins_ea: int
    opcode: Optional[int] = None


@dataclass(frozen=True, slots=True)
class AliasedStackDefEvent:
    """A classified write; only exact whole-cell writes replace prior sites."""

    site: AliasedStackDefSite
    replaces_cell: bool = False


def _sorted(sites: Iterable[AliasedStackDefSite]) -> tuple[AliasedStackDefSite, ...]:
    return tuple(
        sorted(
            sites,
            key=lambda site: (
                site.block_serial,
                site.ins_ea,
                -1 if site.opcode is None else site.opcode,
            ),
        )
    )


def collect_aliased_stack_reaching_defs(
    *,
    entry_block: int,
    target_block: int,
    successors_of: Callable[[int], Iterable[int]],
    events_for_block: Callable[[int], Iterable[AliasedStackDefEvent]],
    max_iterations: int = 16384,
) -> tuple[AliasedStackDefSite, ...]:
    """Return a bounded, conservative MAY-set of defs at ``target_block``.

    The visited set limits topology discovery to the query's forward-reachable
    CFG. Exact writes replace older definitions; partial stores, pointer stores,
    and calls add a MAY site. A failed convergence returns every observed MAY
    site rather than dropping a possible definition.
    """
    visited: set[int] = set()
    pending = [entry_block]
    while pending:
        block = pending.pop()
        if block in visited:
            continue
        visited.add(block)
        pending.extend(successors_of(block))
    if target_block not in visited:
        return ()

    events = {block: tuple(events_for_block(block)) for block in visited}
    all_sites = {
        event.site for block_events in events.values() for event in block_events
    }
    in_sets: dict[int, set[AliasedStackDefSite]] = {block: set() for block in visited}
    out_sets: dict[int, set[AliasedStackDefSite]] = {block: set() for block in visited}
    # Seed every visited block: an empty entry state must still propagate to a
    # later block that contains the first definition for this cell.
    worklist = list(visited)
    iterations = 0
    while worklist and iterations < max_iterations:
        block = worklist.pop()
        iterations += 1
        current = set(in_sets[block])
        for event in events[block]:
            current = {event.site} if event.replaces_cell else current | {event.site}
        if current == out_sets[block]:
            continue
        out_sets[block] = current
        for successor in successors_of(block):
            if successor not in visited:
                continue
            merged = in_sets[successor] | current
            if merged != in_sets[successor]:
                in_sets[successor] = merged
                worklist.append(successor)
    if worklist:
        return _sorted(all_sites)
    return _sorted(in_sets[target_block])


__all__ = [
    "AliasedStackDefEvent",
    "AliasedStackDefSite",
    "collect_aliased_stack_reaching_defs",
]
