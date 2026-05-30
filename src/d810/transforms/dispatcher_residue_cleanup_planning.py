"""CFG-owned dispatcher residue and unreachable-region cleanup plans."""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Sequence, Protocol


class DispatcherResidueTwoWayFactLike(Protocol):
    block_serial: int
    keep_successor: int
    successors: Sequence[int]


class DispatcherResidueCleanupFactsLike(Protocol):
    dispatcher_serial: int
    one_way_predecessors: Sequence[int]
    two_way_predecessors: Sequence[DispatcherResidueTwoWayFactLike]
    dispatcher_outgoing_successors: Sequence[int]


class UnreachableRegionBlockFactLike(Protocol):
    block_serial: int
    successors: Sequence[int]


class UnreachableRegionForwardRedirectFactLike(Protocol):
    block_serial: int
    old_target: int
    new_target: int


class UnreachableRegionCleanupFactsLike(Protocol):
    stop_serial: int
    cleanup_candidates: Sequence[int]
    blocks: Sequence[UnreachableRegionBlockFactLike]
    forward_redirects: Sequence[UnreachableRegionForwardRedirectFactLike]


@dataclass(frozen=True)
class DispatcherResidueTwoWayConversion:
    block_serial: int
    keep_successor: int
    old_successors: tuple[int, int]


@dataclass(frozen=True)
class DispatcherResidueCleanupPlan:
    dispatcher_serial: int
    one_way_edge_severs: tuple[int, ...]
    two_way_conversions: tuple[DispatcherResidueTwoWayConversion, ...]
    dispatcher_outgoing_successors: tuple[int, ...]

    @property
    def expected_handler_edge_changes(self) -> int:
        return len(self.one_way_edge_severs) + len(self.two_way_conversions)


@dataclass(frozen=True)
class UnreachableRegionBlockPlan:
    block_serial: int
    successors: tuple[int, ...]


@dataclass(frozen=True)
class UnreachableRegionForwardRedirect:
    block_serial: int
    old_target: int
    new_target: int


@dataclass(frozen=True)
class UnreachableRegionCleanupPlan:
    stop_serial: int
    cleanup_candidates: frozenset[int]
    blocks: tuple[UnreachableRegionBlockPlan, ...]
    forward_redirects: tuple[UnreachableRegionForwardRedirect, ...]


def plan_dispatcher_residue_cleanup(
    facts: DispatcherResidueCleanupFactsLike,
) -> DispatcherResidueCleanupPlan:
    """Build a backend-neutral dispatcher-residue plan from recon facts."""

    conversions = tuple(
        DispatcherResidueTwoWayConversion(
            block_serial=int(fact.block_serial),
            keep_successor=int(fact.keep_successor),
            old_successors=tuple(int(s) for s in fact.successors),
        )
        for fact in facts.two_way_predecessors
    )
    return DispatcherResidueCleanupPlan(
        dispatcher_serial=int(facts.dispatcher_serial),
        one_way_edge_severs=tuple(
            int(serial) for serial in facts.one_way_predecessors
        ),
        two_way_conversions=conversions,
        dispatcher_outgoing_successors=tuple(
            int(serial) for serial in facts.dispatcher_outgoing_successors
        ),
    )


def plan_unreachable_region_cleanup(
    facts: UnreachableRegionCleanupFactsLike,
) -> UnreachableRegionCleanupPlan:
    """Build a backend-neutral unreachable-region plan from recon facts."""

    return UnreachableRegionCleanupPlan(
        stop_serial=int(facts.stop_serial),
        cleanup_candidates=frozenset(
            int(serial) for serial in facts.cleanup_candidates
        ),
        blocks=tuple(
            UnreachableRegionBlockPlan(
                block_serial=int(block.block_serial),
                successors=tuple(int(s) for s in block.successors),
            )
            for block in facts.blocks
        ),
        forward_redirects=tuple(
            UnreachableRegionForwardRedirect(
                block_serial=int(redirect.block_serial),
                old_target=int(redirect.old_target),
                new_target=int(redirect.new_target),
            )
            for redirect in facts.forward_redirects
        ),
    )


__all__ = [
    "DispatcherResidueTwoWayConversion",
    "DispatcherResidueCleanupPlan",
    "UnreachableRegionBlockPlan",
    "UnreachableRegionForwardRedirect",
    "UnreachableRegionCleanupPlan",
    "plan_dispatcher_residue_cleanup",
    "plan_unreachable_region_cleanup",
]
