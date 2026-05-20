"""Live topology-walk backend for Hodur handler-chain composition."""
from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

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


@dataclass(frozen=True, slots=True)
class LiveCorridorBlockProbe:
    """Live facts for one block in a corridor walk."""

    serial: int
    depth: int
    block_exists: bool
    block_type: int = -1
    predecessors: tuple[int, ...] = ()
    successors: tuple[int, ...] = ()
    tail_opcode: int = -1
    tail_target: int = -1
    entry_reachable: bool = False


@dataclass(frozen=True, slots=True)
class LiveCorridorWalkProbe:
    """Backward corridor walk facts."""

    blocks: tuple[LiveCorridorBlockProbe, ...]


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

    def walk_backward_corridor(
        self,
        mba: object,
        start_serial: int,
        *,
        max_depth: int = 8,
        entry_serial: int = 0,
    ) -> LiveCorridorWalkProbe:
        """Walk live predecessors and return raw corridor topology facts."""


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

    def _block(self, mba: object, serial: int) -> object | None:
        try:
            return mba.get_mblock(int(serial))  # type: ignore[attr-defined]
        except Exception:
            return None

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

    def walk_backward_corridor(
        self,
        mba: object,
        start_serial: int,
        *,
        max_depth: int = 8,
        entry_serial: int = 0,
    ) -> LiveCorridorWalkProbe:
        reachable_from_entry = self._reachable_set(
            mba,
            entry_serial=int(entry_serial),
        )
        blocks: list[LiveCorridorBlockProbe] = []
        seen: set[int] = set()
        frontier: list[tuple[int, int]] = [(int(start_serial), 0)]
        while frontier:
            block_serial, depth = frontier.pop(0)
            if block_serial in seen:
                continue
            seen.add(block_serial)
            probe = self._read_corridor_block(
                mba,
                block_serial,
                depth=depth,
                entry_reachable=block_serial in reachable_from_entry,
            )
            blocks.append(probe)
            if not probe.block_exists or depth >= int(max_depth):
                continue
            for predecessor in probe.predecessors:
                if predecessor not in seen:
                    frontier.append((predecessor, depth + 1))
        return LiveCorridorWalkProbe(blocks=tuple(blocks))

    def _reachable_set(self, mba: object, *, entry_serial: int = 0) -> set[int]:
        try:
            qty = int(getattr(mba, "qty", 0))
        except Exception:
            qty = 0
        reached: set[int] = set()
        worklist: list[int] = [int(entry_serial)] if qty > 0 else []
        while worklist and len(reached) < qty + 4:
            current = worklist.pop()
            if current in reached:
                continue
            reached.add(current)
            topology = self._live_topology_backend.read_block_topology(
                mba,
                current,
            )
            if not topology.block_exists or topology.successors is None:
                continue
            worklist.extend(int(successor) for successor in topology.successors)
        return reached

    def _read_corridor_block(
        self,
        mba: object,
        block_serial: int,
        *,
        depth: int,
        entry_reachable: bool,
    ) -> LiveCorridorBlockProbe:
        block = self._block(mba, int(block_serial))
        if block is None:
            return LiveCorridorBlockProbe(
                serial=int(block_serial),
                depth=int(depth),
                block_exists=False,
                entry_reachable=bool(entry_reachable),
            )
        try:
            block_type = int(block.type)  # type: ignore[attr-defined]
            pred_count = int(block.npred())  # type: ignore[attr-defined]
            succ_count = int(block.nsucc())  # type: ignore[attr-defined]
            predecessors = tuple(
                int(block.pred(index))  # type: ignore[attr-defined]
                for index in range(pred_count)
            )
            successors = tuple(
                int(block.succ(index))  # type: ignore[attr-defined]
                for index in range(succ_count)
            )
            tail = getattr(block, "tail", None)
            tail_opcode = int(tail.opcode) if tail is not None else -1
            tail_target = (
                int(tail.d.b)
                if (
                    tail is not None
                    and getattr(tail, "d", None) is not None
                    and getattr(tail.d, "t", -1) == ida_hexrays.mop_b
                )
                else -1
            )
        except Exception:
            block_type = -1
            predecessors = ()
            successors = ()
            tail_opcode = -1
            tail_target = -1
        return LiveCorridorBlockProbe(
            serial=int(block_serial),
            depth=int(depth),
            block_exists=True,
            block_type=block_type,
            predecessors=predecessors,
            successors=successors,
            tail_opcode=tail_opcode,
            tail_target=tail_target,
            entry_reachable=bool(entry_reachable),
        )


DEFAULT_HODUR_HANDLER_CHAIN_TOPOLOGY_WALK_BACKEND: HandlerChainTopologyWalkBackend = (
    HexRaysHandlerChainTopologyWalkBackend()
)


__all__ = [
    "DEFAULT_HODUR_HANDLER_CHAIN_TOPOLOGY_WALK_BACKEND",
    "HandlerChainTopologyWalkBackend",
    "HexRaysHandlerChainTopologyWalkBackend",
    "LiveCorridorBlockProbe",
    "LiveCorridorWalkProbe",
    "LiveDispatcherExitOnPathProbe",
    "LiveReachabilityProbe",
]
