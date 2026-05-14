"""Live topology-walk backend for Hodur handler-chain composition."""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import AbstractSet, Protocol
from d810.optimizers.microcode.flow.flattening.hodur.handler_chain_live_topology_backend import (
    DEFAULT_HODUR_HANDLER_CHAIN_LIVE_TOPOLOGY_BACKEND,
    HandlerChainLiveTopologyBackend,
)


@dataclass(frozen=True, slots=True)
class LiveDispatcherExitOnPathProbe:
    """Candidate dispatcher exit found by walking a known path."""

    block_serial: int | None


@dataclass(frozen=True, slots=True)
class LiveReachabilityProbe:
    """Bounded live reachability result."""

    reachable: bool
    visited_count: int = 0


class HandlerChainTopologyWalkBackend(Protocol):
    """Backend boundary for HCC multi-block topology walks."""

    def deepest_dispatcher_exit_on_ordered_path(
        self,
        mba: object,
        ordered_path: tuple[int, ...],
        *,
        dispatcher_serial: int,
        excluded_blocks: AbstractSet[int],
    ) -> LiveDispatcherExitOnPathProbe:
        """Pick the deepest non-excluded 1-way block targeting dispatcher."""

    def reachable_from_entry(
        self,
        mba: object,
        target_serial: int,
        *,
        entry_serial: int = 0,
    ) -> LiveReachabilityProbe:
        """Return whether ``target_serial`` is reachable from ``entry_serial``."""


class HexRaysHandlerChainTopologyWalkBackend:
    """Default Hex-Rays live topology-walk backend for HCC planning."""

    def __init__(
        self,
        live_topology_backend: HandlerChainLiveTopologyBackend | None = None,
    ) -> None:
        self._live_topology_backend = (
            live_topology_backend
            if live_topology_backend is not None
            else DEFAULT_HODUR_HANDLER_CHAIN_LIVE_TOPOLOGY_BACKEND
        )

    def deepest_dispatcher_exit_on_ordered_path(
        self,
        mba: object,
        ordered_path: tuple[int, ...],
        *,
        dispatcher_serial: int,
        excluded_blocks: AbstractSet[int],
    ) -> LiveDispatcherExitOnPathProbe:
        excluded = {int(block) for block in excluded_blocks}
        dispatcher_serial = int(dispatcher_serial)
        for block_serial in reversed(tuple(int(block) for block in ordered_path)):
            if block_serial == dispatcher_serial or block_serial in excluded:
                continue
            probe = self._live_topology_backend.read_one_way_successor(
                mba,
                block_serial,
            )
            if (
                probe.block_exists
                and probe.nsucc == 1
                and probe.successor == dispatcher_serial
            ):
                return LiveDispatcherExitOnPathProbe(
                    block_serial=block_serial,
                )
        return LiveDispatcherExitOnPathProbe(block_serial=None)

    def reachable_from_entry(
        self,
        mba: object,
        target_serial: int,
        *,
        entry_serial: int = 0,
    ) -> LiveReachabilityProbe:
        try:
            qty = int(getattr(mba, "qty", 0))
        except Exception:
            qty = 0
        if qty <= 0:
            return LiveReachabilityProbe(reachable=False)

        target_serial = int(target_serial)
        worklist: list[int] = [int(entry_serial)]
        reached: set[int] = set()
        while worklist and len(reached) < qty + 4:
            current = worklist.pop()
            if current in reached:
                continue
            reached.add(current)
            if current == target_serial:
                return LiveReachabilityProbe(
                    reachable=True,
                    visited_count=len(reached),
                )
            topology = self._live_topology_backend.read_block_topology(
                mba,
                current,
            )
            if not topology.block_exists or topology.successors is None:
                continue
            worklist.extend(int(successor) for successor in topology.successors)
        return LiveReachabilityProbe(
            reachable=target_serial in reached,
            visited_count=len(reached),
        )


DEFAULT_HODUR_HANDLER_CHAIN_TOPOLOGY_WALK_BACKEND: HandlerChainTopologyWalkBackend = (
    HexRaysHandlerChainTopologyWalkBackend()
)


__all__ = [
    "DEFAULT_HODUR_HANDLER_CHAIN_TOPOLOGY_WALK_BACKEND",
    "HandlerChainTopologyWalkBackend",
    "HexRaysHandlerChainTopologyWalkBackend",
    "LiveDispatcherExitOnPathProbe",
    "LiveReachabilityProbe",
]
