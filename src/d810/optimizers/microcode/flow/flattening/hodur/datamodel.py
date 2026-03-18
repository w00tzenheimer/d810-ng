"""Dispatcher state machine data model — pure dataclass definitions.

These types describe the detected dispatcher-driven state machine and the
records produced during pass-0 linearization. They are separated from the
detection logic so that unit tests can construct them without an IDA
environment. The canonical model name is ``DispatcherStateMachine``; the
historical ``HodurStateMachine`` name remains as a compatibility alias.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from d810.core.typing import TYPE_CHECKING

if TYPE_CHECKING:
    import ida_hexrays

from d810.recon.flow.transition_builder import (
    StateHandler,
    StateTransition,
    StateUpdateSite,
)
from d810.recon.flow.state_machine_analysis import (
    CarrierResolutionResult,
    ConditionalTransition,
    HandlerPathResult,
    ResolutionMethod,
)

__all__ = [
    # Re-exported from transition_builder for convenience
    "StateHandler",
    "StateTransition",
    "StateUpdateSite",
    # Re-exported from recon state-machine analysis
    "CarrierResolutionResult",
    "DispatcherStateMachine",
    "HodurStateMachine",
    "HandlerPathResult",
    "ConditionalTransition",
    "Pass0RedirectRecord",
    "ResolutionMethod",
]


@dataclass
class DispatcherStateMachine:
    """Represents a recovered dispatcher-driven state machine."""

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
        if transition.from_state is not None and transition.from_state in self.handlers:
            self.handlers[transition.from_state].transitions.append(transition)


# Backward-compatible alias for older Hodur-specific imports.
HodurStateMachine = DispatcherStateMachine


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
