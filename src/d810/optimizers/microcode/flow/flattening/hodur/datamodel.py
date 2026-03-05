"""Hodur state machine data model — pure dataclass definitions.

These types describe the detected Hodur while-loop state machine and the
records produced during pass-0 linearization.  They are separated from the
detection logic so that unit tests can construct them without an IDA
environment.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    import ida_hexrays

from d810.recon.flow.transition_builder import (
    StateHandler,
    StateTransition,
    StateUpdateSite,
)

__all__ = [
    # Re-exported from transition_builder for convenience
    "StateHandler",
    "StateTransition",
    "StateUpdateSite",
    # Defined here
    "HodurStateMachine",
    "HandlerPathResult",
    "Pass0RedirectRecord",
]


@dataclass
class HodurStateMachine:
    """Represents the complete Hodur state machine structure."""

    mba: "ida_hexrays.mba_t"
    state_var: "ida_hexrays.mop_t | None" = None
    initial_state: int | None = None
    state_constants: set[int] = field(default_factory=set)
    handlers: dict[int, StateHandler] = field(
        default_factory=dict
    )  # state_value -> handler
    transitions: list[StateTransition] = field(default_factory=list)
    assignment_map: dict[int, list] = field(default_factory=dict)

    def add_state_constant(self, const: int) -> None:
        self.state_constants.add(const)

    def add_handler(self, handler: StateHandler) -> None:
        self.handlers[handler.state_value] = handler

    def add_transition(self, transition: StateTransition) -> None:
        self.transitions.append(transition)
        if transition.from_state in self.handlers:
            self.handlers[transition.from_state].transitions.append(transition)


@dataclass
class HandlerPathResult:
    """Result of evaluating one exit path from a handler."""

    exit_block: int  # block serial where handler exits to dispatcher
    final_state: Optional[int]  # concrete state value at exit; None for terminal (m_ret) paths
    state_writes: list  # [(block_serial, insn_ea), ...] of state var writes
    ordered_path: list = field(default_factory=list)  # ordered sequence of block serials visited during DFS


@dataclass
class Pass0RedirectRecord:
    """Compact redirect ledger row for pass-0 linearization diagnostics."""

    category: str
    handler_entry: int
    incoming_state: int | None
    exit_block: int
    final_state: int | None
    source_block: int
    via_pred: int | None
    target_block: int
    reason: str
