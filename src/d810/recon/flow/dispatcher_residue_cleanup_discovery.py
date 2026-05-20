"""Read-only dispatcher residue and unreachable-region cleanup discovery.

This module classifies cleanup opportunities without mutating the live MBA.
CFG planning and Hex-Rays
materialization live in their own layers.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DispatcherResidueTwoWayPredecessorFact:
    block_serial: int
    successors: tuple[int, int]
    keep_successor: int


@dataclass(frozen=True)
class DispatcherResidueCleanupFacts:
    dispatcher_serial: int
    dispatcher_region: frozenset[int]
    dispatcher_predecessors: tuple[int, ...]
    one_way_predecessors: tuple[int, ...]
    two_way_predecessors: tuple[DispatcherResidueTwoWayPredecessorFact, ...]
    dispatcher_outgoing_successors: tuple[int, ...]


@dataclass(frozen=True)
class UnreachableRegionBlockFact:
    block_serial: int
    successors: tuple[int, ...]


@dataclass(frozen=True)
class UnreachableRegionForwardRedirectFact:
    block_serial: int
    old_target: int
    new_target: int


@dataclass(frozen=True)
class UnreachableRegionCleanupFacts:
    dispatcher_serial: int
    stop_serial: int
    reachable: frozenset[int]
    protected: frozenset[int]
    corridor_seeds: frozenset[int]
    dispatcher_component: frozenset[int]
    orphaned: frozenset[int]
    cleanup_candidates: frozenset[int]
    blocks: tuple[UnreachableRegionBlockFact, ...]
    forward_redirects: tuple[UnreachableRegionForwardRedirectFact, ...]


def _block_successors(blk: object) -> tuple[int, ...]:
    nsucc = int(blk.nsucc())
    return tuple(int(blk.succ(i)) for i in range(nsucc))


def _reachable_from_entry(mba: object, qty: int) -> set[int]:
    visited: set[int] = set()
    queue: list[int] = [0]
    while queue:
        serial = queue.pop(0)
        if serial in visited or serial < 0 or serial >= qty:
            continue
        visited.add(serial)
        blk = mba.get_mblock(serial)
        if blk is None:
            continue
        for succ in _block_successors(blk):
            if succ not in visited:
                queue.append(succ)
    return visited


def _forward_reachable_within(
    mba: object,
    *,
    seeds: set[int],
    universe: set[int],
    qty: int,
) -> set[int]:
    visited: set[int] = set()
    queue = list(seeds)
    while queue:
        serial = queue.pop(0)
        if serial in visited or serial < 0 or serial >= qty:
            continue
        visited.add(serial)
        blk = mba.get_mblock(serial)
        if blk is None:
            continue
        for succ in _block_successors(blk):
            if succ in universe and succ not in visited:
                queue.append(succ)
    return visited


def _dispatcher_component(
    mba: object,
    *,
    dispatcher_serial: int,
    unreachable: set[int],
    dispatcher_region: set[int],
    qty: int,
) -> set[int]:
    component: set[int] = set()
    forward_queue = [dispatcher_serial]
    while forward_queue:
        serial = forward_queue.pop()
        if serial in component or serial not in unreachable:
            continue
        component.add(serial)
        blk = mba.get_mblock(serial)
        if blk is None:
            continue
        for succ in _block_successors(blk):
            if succ in unreachable and succ not in component:
                forward_queue.append(succ)

    backward_queue = [dispatcher_serial]
    while backward_queue:
        serial = backward_queue.pop()
        if serial < 0 or serial >= qty:
            continue
        blk = mba.get_mblock(serial)
        if blk is None:
            continue
        for i in range(int(blk.npred())):
            pred = int(blk.pred(i))
            if pred in unreachable and pred not in component:
                component.add(pred)
                backward_queue.append(pred)

    component.update(unreachable & dispatcher_region)
    return component


def discover_dispatcher_residue_cleanup_facts(
    mba: object,
    *,
    dispatcher_region: object,
    dispatcher_serial: int,
) -> DispatcherResidueCleanupFacts:
    """Classify dispatcher-residue cleanup edges without mutating MBA."""

    dispatcher_serial = int(dispatcher_serial)
    dispatcher_serials = {int(serial) for serial in (dispatcher_region or ())}
    dispatcher_serials.add(dispatcher_serial)

    disp_blk = mba.get_mblock(dispatcher_serial)
    if disp_blk is None:
        return DispatcherResidueCleanupFacts(
            dispatcher_serial=dispatcher_serial,
            dispatcher_region=frozenset(dispatcher_serials),
            dispatcher_predecessors=(),
            one_way_predecessors=(),
            two_way_predecessors=(),
            dispatcher_outgoing_successors=(),
        )

    dispatcher_predecessors = tuple(
        int(disp_blk.pred(i)) for i in range(int(disp_blk.npred()))
    )
    dispatcher_outgoing_successors = _block_successors(disp_blk)

    one_way: list[int] = []
    two_way: list[DispatcherResidueTwoWayPredecessorFact] = []
    for serial in range(int(getattr(mba, "qty", 0) or 0)):
        if serial in dispatcher_serials:
            continue
        blk = mba.get_mblock(serial)
        if blk is None:
            continue
        succs = _block_successors(blk)
        if len(succs) == 1 and succs[0] == dispatcher_serial:
            one_way.append(serial)
        elif len(succs) == 2 and dispatcher_serial in succs:
            keep = succs[1] if succs[0] == dispatcher_serial else succs[0]
            two_way.append(
                DispatcherResidueTwoWayPredecessorFact(
                    block_serial=serial,
                    successors=(succs[0], succs[1]),
                    keep_successor=int(keep),
                )
            )

    return DispatcherResidueCleanupFacts(
        dispatcher_serial=dispatcher_serial,
        dispatcher_region=frozenset(dispatcher_serials),
        dispatcher_predecessors=dispatcher_predecessors,
        one_way_predecessors=tuple(one_way),
        two_way_predecessors=tuple(two_way),
        dispatcher_outgoing_successors=dispatcher_outgoing_successors,
    )


def discover_unreachable_region_cleanup_facts(
    mba: object,
    *,
    dispatcher_serial: int,
    dispatcher_region: set[int],
    stop_serial: int,
    reconstruction_live: set[int] | None = None,
) -> UnreachableRegionCleanupFacts:
    """Classify unreachable blocks after dispatcher cleanup."""

    qty = int(getattr(mba, "qty", 0) or 0) if mba is not None else 0
    dispatcher_serial = int(dispatcher_serial)
    stop_serial = int(stop_serial)
    if qty <= 1:
        return UnreachableRegionCleanupFacts(
            dispatcher_serial=dispatcher_serial,
            stop_serial=stop_serial,
            reachable=frozenset(),
            protected=frozenset(),
            corridor_seeds=frozenset(),
            dispatcher_component=frozenset(),
            orphaned=frozenset(),
            cleanup_candidates=frozenset(),
            blocks=(),
            forward_redirects=(),
        )

    reachable = _reachable_from_entry(mba, qty)
    unreachable = {
        serial for serial in range(qty) if serial not in reachable and serial != stop_serial
    }

    protected: set[int] = set()
    corridor_seeds: set[int] = set()
    if reconstruction_live:
        corridor_seeds = set(reconstruction_live) & unreachable
        protected = _forward_reachable_within(
            mba,
            seeds=corridor_seeds,
            universe=unreachable,
            qty=qty,
        )
        unreachable -= protected

    dispatcher_component = _dispatcher_component(
        mba,
        dispatcher_serial=dispatcher_serial,
        unreachable=unreachable,
        dispatcher_region={int(serial) for serial in dispatcher_region},
        qty=qty,
    )
    orphaned = set(unreachable) - dispatcher_component
    cleanup_candidates = set(unreachable)
    cleanup_candidates.discard(stop_serial)

    blocks: list[UnreachableRegionBlockFact] = []
    for serial in sorted(cleanup_candidates):
        blk = mba.get_mblock(serial)
        if blk is None:
            continue
        succs = _block_successors(blk)
        if not succs:
            continue
        blocks.append(UnreachableRegionBlockFact(block_serial=serial, successors=succs))

    redirects: list[UnreachableRegionForwardRedirectFact] = []
    for block in blocks:
        if len(block.successors) != 1:
            continue
        old_target = int(block.successors[0])
        if old_target == stop_serial or old_target not in cleanup_candidates:
            continue
        redirects.append(
            UnreachableRegionForwardRedirectFact(
                block_serial=int(block.block_serial),
                old_target=old_target,
                new_target=stop_serial,
            )
        )

    return UnreachableRegionCleanupFacts(
        dispatcher_serial=dispatcher_serial,
        stop_serial=stop_serial,
        reachable=frozenset(reachable),
        protected=frozenset(protected),
        corridor_seeds=frozenset(corridor_seeds),
        dispatcher_component=frozenset(dispatcher_component),
        orphaned=frozenset(orphaned),
        cleanup_candidates=frozenset(cleanup_candidates),
        blocks=tuple(blocks),
        forward_redirects=tuple(redirects),
    )


__all__ = [
    "DispatcherResidueTwoWayPredecessorFact",
    "DispatcherResidueCleanupFacts",
    "UnreachableRegionBlockFact",
    "UnreachableRegionForwardRedirectFact",
    "UnreachableRegionCleanupFacts",
    "discover_dispatcher_residue_cleanup_facts",
    "discover_unreachable_region_cleanup_facts",
]
