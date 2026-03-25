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


class BoundaryKind(Enum):
    """Classification for a handler-entry boundary."""

    STABLE_HANDOFF = "stable_handoff"
    TRANSIENT_CORRIDOR = "transient_corridor"
    TERMINAL = "terminal"
    BST_REENTRY = "bst_reentry"
    UNSAFE_SIDE_EFFECT = "unsafe_side_effect"


class CorridorEventKind(Enum):
    """Low-level events emitted while tracing a corridor."""

    INSN = "insn"
    STATE_WRITE = "state_write"
    WATCHED_STACK_WRITE = "watched_stack_write"
    BRANCH = "branch"
    CALL = "call"
    TERMINAL = "terminal"
    ERROR = "error"


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


@dataclass(frozen=True, slots=True)
class CorridorEvent:
    """One observed event in a bounded corridor trace."""

    kind: CorridorEventKind
    address: int
    detail: str = ""
    value: int | None = None


@dataclass(frozen=True, slots=True)
class CorridorTraceResult:
    """Trace result for a bounded straight-line corridor probe."""

    events: tuple[CorridorEvent, ...] = ()
    stopped: bool = False
    stop_reason: str = ""
    state_write_seen: bool = False
