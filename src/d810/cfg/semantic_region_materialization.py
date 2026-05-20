"""Backend-neutral semantic-region materialization contracts."""
from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "InstructionCaptureDecision",
    "InstructionCaptureFacts",
    "decide_instruction_capture",
]


@dataclass(frozen=True, slots=True)
class InstructionCaptureFacts:
    """Backend-neutral facts for one instruction in a region body.

    Backends are responsible for deriving these booleans from their native IR.
    This module only owns the lowering contract: whether the instruction belongs
    in an InsertBlock body, should be skipped, records an opaque-call anchor, or
    makes the region non-materializable.
    """

    is_goto: bool = False
    is_nop: bool = False
    is_closing_forbidden: bool = False
    is_conditional_jump: bool = False
    is_call: bool = False
    is_state_write: bool = False
    is_tail: bool = False
    block_has_required_payload_evidence: bool = False


@dataclass(frozen=True, slots=True)
class InstructionCaptureDecision:
    """Decision for a single instruction during region body capture."""

    action: str
    abort_reason: str | None = None


def decide_instruction_capture(
    facts: InstructionCaptureFacts,
    *,
    opcode: int | None = None,
) -> InstructionCaptureDecision:
    """Classify one instruction for semantic-region body materialization."""
    if facts.is_goto or facts.is_nop:
        return InstructionCaptureDecision("skip")

    if facts.is_closing_forbidden:
        return InstructionCaptureDecision(
            "abort",
            abort_reason=f"closing_forbidden_opcode={opcode}",
        )

    if facts.is_conditional_jump:
        if facts.block_has_required_payload_evidence and facts.is_tail:
            return InstructionCaptureDecision("drop_control_tail")
        return InstructionCaptureDecision(
            "abort",
            abort_reason=f"jcond_opcode={opcode}",
        )

    if facts.is_call:
        return InstructionCaptureDecision("record_call")

    if facts.is_state_write:
        return InstructionCaptureDecision("skip")

    return InstructionCaptureDecision("capture")
