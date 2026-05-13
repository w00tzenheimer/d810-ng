"""Backend-neutral materialization boundary for CFG lowering.

The cfg layer should describe what needs to be lowered without knowing how a
backend copies, NOPs, or rewrites live instructions.  This module defines the
small contract a backend adapter can implement while Hex-Rays-specific
``mba_t``/``mblock_t``/``minsn_t`` mechanics remain outside cfg.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.graph_modification import GraphModification
from d810.core.typing import Mapping, Protocol


@dataclass(frozen=True, slots=True)
class BackendInstructionRef:
    """Stable identity for an instruction captured from a backend block."""

    block_serial: int
    ea: int
    opcode_name: str | None = None


@dataclass(frozen=True, slots=True)
class CapturedInstructionPayload:
    """Backend-neutral payload captured for later materialization."""

    source_block: int
    instructions: tuple[BackendInstructionRef, ...]

    @property
    def source_eas(self) -> frozenset[int]:
        """Instruction EAs represented by this payload."""
        return frozenset(int(insn.ea) for insn in self.instructions)

    def contains_all_source_eas(self, required_eas: frozenset[int]) -> bool:
        """Return whether every required source EA is present in the payload."""
        return all(int(ea) in self.source_eas for ea in required_eas)


class MaterializationBackend(Protocol):
    """Backend adapter for turning cfg lowering decisions into graph mods."""

    def capture_payload(
        self,
        block_serial: int,
        *,
        omit_terminal_control: bool = False,
        required_source_eas: frozenset[int] = frozenset(),
    ) -> CapturedInstructionPayload | None:
        """Capture a block payload without exposing backend instruction objects."""
        ...

    def lower_insert_block(
        self,
        *,
        source: int,
        old_target: int,
        target: int,
        payload: CapturedInstructionPayload,
        metadata: Mapping[str, object] | None = None,
    ) -> GraphModification:
        """Materialize an insert-block rewrite from a captured payload."""
        ...

    def lower_nop_instruction(
        self,
        *,
        block_serial: int,
        insn_ea: int,
        metadata: Mapping[str, object] | None = None,
    ) -> GraphModification:
        """Materialize an instruction NOP rewrite."""
        ...


__all__ = [
    "BackendInstructionRef",
    "CapturedInstructionPayload",
    "MaterializationBackend",
]
