"""Shared types for emulation evaluators."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from d810.core import getLogger

logger = getLogger("D810.emulation")


class Architecture(Enum):
    """Supported architectures for emulation."""

    X86 = "x86"
    X86_64 = "x86_64"
    ARM64 = "arm64"


@dataclass
class EmulationState:
    """State snapshot from emulation."""

    registers: dict[str, int] = field(default_factory=dict)
    memory: dict[int, bytes] = field(default_factory=dict)
    flags: int = 0
    pc: int = 0
    stopped: bool = False
    stop_reason: str = ""


@dataclass
class StateTransition:
    """Represents a state machine transition discovered through emulation."""

    from_value: int
    to_value: int
    from_block: int | None = None
    to_block: int | None = None
    condition: str | None = None
    is_proven: bool = False

