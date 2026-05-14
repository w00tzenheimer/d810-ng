"""Opaque backend-owned payloads carried by cfg lowering intents.

The cfg layer is allowed to route a captured instruction body through a
``GraphModification``/``PatchPlan``. It must not inspect or materialize the
payload itself. Only the backend adapter that produced the payload may unwrap
the backend-specific contents.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Mapping


@dataclass(frozen=True, slots=True)
class BackendInstructionRef:
    """Stable, non-live identity for an instruction represented in a capture."""

    block_serial: int
    ea: int
    opcode_name: str | None = None


@dataclass(frozen=True, slots=True)
class CapturedBlockBodySummary:
    """Backend-neutral facts cfg/Hodur may use without reading the payload."""

    source_blocks: tuple[int, ...] = ()
    instruction_count: int = 0
    source_eas: frozenset[int] = frozenset()
    contains_call: bool = False


@dataclass(frozen=True, slots=True)
class CapturedBlockBody:
    """Opaque instruction body captured by a backend adapter.

    ``payload`` is intentionally typed as ``object``. cfg may carry this object
    and compare/hash the dataclass, but the object is backend-owned and only a
    matching materialization backend should interpret it.
    """

    backend_id: str
    capture_id: str
    summary: CapturedBlockBodySummary
    payload: object
    metadata: Mapping[str, object] | None = None

    @property
    def source_blocks(self) -> tuple[int, ...]:
        return self.summary.source_blocks

    @property
    def instruction_count(self) -> int:
        return self.summary.instruction_count

    @property
    def source_eas(self) -> frozenset[int]:
        return self.summary.source_eas

    def contains_all_source_eas(self, required_eas: frozenset[int]) -> bool:
        """Return whether every required source EA is represented."""
        return all(int(ea) in self.summary.source_eas for ea in required_eas)


__all__ = [
    "BackendInstructionRef",
    "CapturedBlockBody",
    "CapturedBlockBodySummary",
]
