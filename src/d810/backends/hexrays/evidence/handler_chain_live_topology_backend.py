"""Live-topology backend boundary for Hodur handler-chain composition."""
from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.core.typing import AbstractSet, Protocol


@dataclass(frozen=True, slots=True)
class LiveOneWaySuccessorProbe:
    """Live topology facts for a block expected to have one successor."""

    block_exists: bool
    nsucc: int | None = None
    successor: int | None = None


@dataclass(frozen=True, slots=True)
class LiveBlockTopologyProbe:
    """Live predecessor/successor facts for one block."""

    block_exists: bool
    nsucc: int | None = None
    successors: tuple[int, ...] | None = None
    npred: int | None = None
    predecessors: tuple[int, ...] | None = None
    tail_opcode: int | None = None
    conditional_target: int | None = None


class HandlerChainLiveTopologyBackend(Protocol):
    """Backend boundary for HCC live block-topology probes."""

    def block_exists(self, mba: object, serial: int) -> bool:
        """Return True when the live MBA still contains ``serial``."""

    def read_one_way_successor(
        self,
        mba: object,
        serial: int,
    ) -> LiveOneWaySuccessorProbe:
        """Read live one-way successor facts for ``serial``."""

    def read_block_topology(
        self,
        mba: object,
        serial: int,
    ) -> LiveBlockTopologyProbe:
        """Read live predecessor/successor facts for ``serial``."""

    def resolve_first_predecessor(
        self,
        mba: object,
        *,
        first_anchor: int,
        region_anchors: AbstractSet[int],
    ) -> int | None:
        """Pick the live splice predecessor for a composed region."""


class HexRaysHandlerChainLiveTopologyBackend:
    """Default Hex-Rays live-topology backend for HCC planning."""

    def _block(self, mba: object, serial: int) -> object | None:
        try:
            return mba.get_mblock(int(serial))  # type: ignore[attr-defined]
        except Exception:
            return None

    def block_exists(self, mba: object, serial: int) -> bool:
        return self._block(mba, serial) is not None

    def read_block_topology(
        self,
        mba: object,
        serial: int,
    ) -> LiveBlockTopologyProbe:
        block = self._block(mba, int(serial))
        if block is None:
            return LiveBlockTopologyProbe(block_exists=False)
        succ_count: int | None = None
        successors: tuple[int, ...] | None = None
        pred_count: int | None = None
        predecessors: tuple[int, ...] | None = None
        tail_opcode: int | None = None
        conditional_target: int | None = None
        try:
            succ_count = int(block.nsucc())  # type: ignore[attr-defined]
            successors = tuple(
                int(block.succ(index))  # type: ignore[attr-defined]
                for index in range(succ_count)
            )
        except Exception:
            pass
        try:
            pred_count = int(block.npred())  # type: ignore[attr-defined]
            predecessors = tuple(
                int(block.pred(index))  # type: ignore[attr-defined]
                for index in range(pred_count)
            )
        except Exception:
            pass
        tail = getattr(block, "tail", None)
        if tail is not None:
            try:
                tail_opcode = int(tail.opcode)
                if ida_hexrays.is_mcode_jcond(tail_opcode):
                    conditional_target = int(tail.d.b)
            except Exception:
                conditional_target = None
        return LiveBlockTopologyProbe(
            block_exists=True,
            nsucc=succ_count,
            successors=successors,
            npred=pred_count,
            predecessors=predecessors,
            tail_opcode=tail_opcode,
            conditional_target=conditional_target,
        )

    def read_one_way_successor(
        self,
        mba: object,
        serial: int,
    ) -> LiveOneWaySuccessorProbe:
        block = self._block(mba, int(serial))
        if block is None:
            return LiveOneWaySuccessorProbe(block_exists=False)
        try:
            succ_count = int(block.nsucc())  # type: ignore[attr-defined]
        except Exception:
            return LiveOneWaySuccessorProbe(block_exists=True)
        if succ_count != 1:
            return LiveOneWaySuccessorProbe(
                block_exists=True,
                nsucc=succ_count,
            )
        try:
            successor = int(block.succ(0))  # type: ignore[attr-defined]
        except Exception:
            return LiveOneWaySuccessorProbe(
                block_exists=True,
                nsucc=succ_count,
            )
        return LiveOneWaySuccessorProbe(
            block_exists=True,
            nsucc=succ_count,
            successor=successor,
        )

    def resolve_first_predecessor(
        self,
        mba: object,
        *,
        first_anchor: int,
        region_anchors: AbstractSet[int],
    ) -> int | None:
        first_block = self._block(mba, int(first_anchor))
        if first_block is None:
            return None
        try:
            pred_count = int(first_block.npred())  # type: ignore[attr-defined]
        except Exception:
            return None
        if pred_count == 0:
            return None

        eligible: list[int] = []
        try:
            for index in range(pred_count):
                pred_serial = int(first_block.pred(index))  # type: ignore[attr-defined]
                if pred_serial in region_anchors:
                    continue
                pred_block = self._block(mba, pred_serial)
                if pred_block is None:
                    continue
                try:
                    succ_count = int(pred_block.nsucc())  # type: ignore[attr-defined]
                except Exception:
                    continue
                if succ_count == 1:
                    eligible.append(pred_serial)
                    continue
                if succ_count != 2:
                    continue
                tail = getattr(pred_block, "tail", None)
                if tail is None:
                    continue
                try:
                    if not ida_hexrays.is_mcode_jcond(int(tail.opcode)):
                        continue
                    conditional_target = int(tail.d.b)
                except Exception:
                    continue
                if conditional_target != int(first_anchor):
                    continue
                eligible.append(pred_serial)
        except Exception:
            return None
        if not eligible:
            return None
        return min(eligible)


class LiveTopologyRegionEntryBlockView:
    """Region-entry resolver adapter backed by live topology probes."""

    __slots__ = ("_backend", "_mba")

    def __init__(
        self,
        mba: object,
        backend: HandlerChainLiveTopologyBackend,
    ) -> None:
        self._mba = mba
        self._backend = backend

    def block_exists(self, serial: int) -> bool:
        return self._backend.block_exists(self._mba, int(serial))

    def nsucc(self, serial: int) -> int | None:
        probe = self._backend.read_block_topology(self._mba, int(serial))
        return probe.nsucc if probe.block_exists else None

    def succ(self, serial: int, index: int = 0) -> int | None:
        probe = self._backend.read_block_topology(self._mba, int(serial))
        if not probe.block_exists or probe.successors is None:
            return None
        try:
            return int(probe.successors[int(index)])
        except Exception:
            return None


DEFAULT_HODUR_HANDLER_CHAIN_LIVE_TOPOLOGY_BACKEND: HandlerChainLiveTopologyBackend = (
    HexRaysHandlerChainLiveTopologyBackend()
)


__all__ = [
    "DEFAULT_HODUR_HANDLER_CHAIN_LIVE_TOPOLOGY_BACKEND",
    "HandlerChainLiveTopologyBackend",
    "HexRaysHandlerChainLiveTopologyBackend",
    "LiveBlockTopologyProbe",
    "LiveOneWaySuccessorProbe",
    "LiveTopologyRegionEntryBlockView",
]
