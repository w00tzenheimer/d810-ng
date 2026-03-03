"""Immutable analysis snapshot types for the Hodur strategy pipeline.

These types are pure Python — no IDA imports — so they can be fully exercised
by unit tests without an IDA environment.

``ReachabilityInfo`` captures reachability from the function entry block.
``AnalysisSnapshot`` is the read-only context passed to every strategy's
``plan()`` method.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.datamodel import (
        HodurStateMachine,
    )
    from d810.optimizers.microcode.flow.flattening.hodur.analysis import (
        HodurStateMachineDetector,
    )


__all__ = [
    "ReachabilityInfo",
    "AnalysisSnapshot",
]


@dataclass(frozen=True)
class ReachabilityInfo:
    """Reachability baseline from function entry."""

    entry_serial: int
    reachable_blocks: frozenset[int]
    total_blocks: int

    @property
    def coverage(self) -> float:
        if self.total_blocks == 0:
            return 0.0
        return len(self.reachable_blocks) / self.total_blocks


@dataclass(frozen=True)
class AnalysisSnapshot:
    """Immutable analysis result for one maturity pass.

    Built once by HodurUnflattener at the start of optimize().
    Passed to every strategy's plan() method as read-only context.
    """

    mba: object  # ida_hexrays.mba_t — keep as object (IDA type, not importable in unit tests)
    state_machine: HodurStateMachine | None = None
    detector: HodurStateMachineDetector | None = None
    dispatcher_cache: object | None = None  # keep as object (IDA type)
    bst_result: object | None = None
    bst_dispatcher_serial: int = -1
    handler_graph: dict = field(default_factory=dict)
    reachability: ReachabilityInfo | None = None
    state_write_provenance: dict = field(default_factory=dict)
    maturity: int = 0
    pass_number: int = 0
    resolved_transitions: frozenset = field(default_factory=frozenset)
    initial_transitions: tuple = ()

    @property
    def state_constants(self) -> set:
        if self.state_machine is not None:
            return self.state_machine.state_constants
        return set()

    @property
    def handler_count(self) -> int:
        if self.state_machine is not None:
            return len(self.state_machine.handlers)
        return 0

    @property
    def transition_count(self) -> int:
        if self.state_machine is not None:
            return len(self.state_machine.transitions)
        return 0

    @property
    def unresolved_transition_count(self) -> int:
        return self.transition_count - len(self.resolved_transitions)
