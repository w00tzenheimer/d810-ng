"""Backend-neutral evidence for state-variable writes."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class StateConstantWriteEvidence:
    """A backend-observed constant write to the dispatcher state variable."""

    block_serial: int
    insn_ea: int
    state_value: int

    def __post_init__(self) -> None:
        if self.block_serial < 0:
            raise ValueError("StateConstantWriteEvidence.block_serial must be non-negative")
        if self.insn_ea < 0:
            raise ValueError("StateConstantWriteEvidence.insn_ea must be non-negative")
        object.__setattr__(self, "state_value", int(self.state_value) & 0xFFFFFFFF)


__all__ = ["StateConstantWriteEvidence"]
