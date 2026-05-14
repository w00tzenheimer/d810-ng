"""Backend-neutral materialization boundary for CFG lowering.

The cfg layer should describe what needs to be lowered without knowing how a
backend copies, NOPs, or rewrites live instructions.  This module defines the
small contract a backend adapter can implement while Hex-Rays-specific
``mba_t``/``mblock_t``/``minsn_t`` mechanics remain outside cfg.
"""
from __future__ import annotations

from d810.cfg.materialization_payload import (
    BackendInstructionRef,
    CapturedBlockBody,
    CapturedBlockBodySummary,
)
from d810.core.typing import TYPE_CHECKING, Mapping, Protocol

if TYPE_CHECKING:
    from d810.cfg.graph_modification import GraphModification


class MaterializationBackend(Protocol):
    """Backend adapter for turning cfg lowering decisions into graph mods."""

    def capture_payload(
        self,
        block_serial: int,
        *,
        omit_terminal_control: bool = False,
        required_source_eas: frozenset[int] = frozenset(),
    ) -> CapturedBlockBody | None:
        """Capture a block payload without exposing backend instruction objects."""
        ...

    def lower_insert_block(
        self,
        *,
        source: int,
        old_target: int,
        target: int,
        payload: CapturedBlockBody,
        metadata: Mapping[str, object] | None = None,
    ) -> "GraphModification":
        """Materialize an insert-block rewrite from a captured payload."""
        ...

    def lower_nop_instruction(
        self,
        *,
        block_serial: int,
        insn_ea: int,
        metadata: Mapping[str, object] | None = None,
    ) -> "GraphModification":
        """Materialize an instruction NOP rewrite."""
        ...


__all__ = [
    "BackendInstructionRef",
    "CapturedBlockBody",
    "CapturedBlockBodySummary",
    "MaterializationBackend",
]
