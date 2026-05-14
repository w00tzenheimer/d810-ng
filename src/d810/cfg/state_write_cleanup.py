"""Backend-neutral state-write cleanup requests."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.cfg.graph_modification import (
    GraphModification,
    NopInstructions,
    ZeroStateWrite,
)


class StateWriteCleanupAction(str, Enum):
    """Materialization action for a proven stale state write."""

    NOP_INSTRUCTION = "nop_instruction"
    ZERO_SOURCE = "zero_source"


@dataclass(frozen=True, slots=True)
class StateWriteCleanupRequest:
    """A backend-proven request to cleanup one state-write instruction.

    The request is backend-neutral: cfg/engine may carry it and lower it to a
    graph modification, but the proof that a native instruction matches the
    request belongs to the backend adapter that produced it.
    """

    action: StateWriteCleanupAction
    block_serial: int
    insn_ea: int
    expected_state: int | None = None
    observed_state: int | None = None
    reason: str = ""


def state_write_cleanup_to_graph_modification(
    request: StateWriteCleanupRequest,
) -> GraphModification:
    """Lower a state-write cleanup request into an existing cfg primitive."""
    if request.action == StateWriteCleanupAction.NOP_INSTRUCTION:
        return NopInstructions(
            block_serial=int(request.block_serial),
            insn_eas=(int(request.insn_ea),),
        )
    if request.action == StateWriteCleanupAction.ZERO_SOURCE:
        return ZeroStateWrite(
            block_serial=int(request.block_serial),
            insn_ea=int(request.insn_ea),
        )
    raise ValueError(f"unsupported state-write cleanup action: {request.action!r}")


__all__ = [
    "StateWriteCleanupAction",
    "StateWriteCleanupRequest",
    "state_write_cleanup_to_graph_modification",
]
