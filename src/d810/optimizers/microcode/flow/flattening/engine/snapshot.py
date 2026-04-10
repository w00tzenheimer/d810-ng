"""Immutable analysis snapshot types for the shared unflattening engine.

These types are pure Python — no IDA imports — so they can be fully exercised
by unit tests without an IDA environment.

``ReachabilityInfo`` captures reachability from the function entry block.
``AnalysisSnapshot`` is the read-only context passed to every strategy's
``plan()`` method, with Hodur as the current primary producer.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from d810.core.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from d810.cfg.flowgraph import FlowGraph


__all__ = [
    "ReachabilityInfo",
    "StateModelSummary",
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
class StateModelSummary:
    """Family-agnostic summary of state-model facts for one analysis pass.

    Families that do not expose a Hodur-like ``state_machine`` object can
    populate this summary directly and still use the shared snapshot contract.
    """

    state_constants: frozenset[int] = field(default_factory=frozenset)
    handler_count: int = 0
    transition_count: int = 0


def _coerce_state_constants(value: object | None) -> set[int]:
    if value is None:
        return set()
    try:
        return {int(item) for item in value}  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return set()


def _safe_len(value: object | None) -> int:
    if value is None:
        return 0
    try:
        return len(value)  # type: ignore[arg-type]
    except TypeError:
        try:
            return sum(1 for _ in value)  # type: ignore[arg-type]
        except TypeError:
            return 0


@dataclass(frozen=True)
class AnalysisSnapshot:
    """Immutable analysis result for one maturity pass.

    Built once by HodurUnflattener at the start of optimize().
    Passed to every strategy's plan() method as read-only context.
    """

    mba: object  # ida_hexrays.mba_t — keep as object (IDA type, not importable in unit tests)
    state_machine: object | None = None
    detector: object | None = None
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
    flow_graph: FlowGraph | None = None
    nop_state_values: dict[int, int] = field(default_factory=dict)
    lfg_redirected_blocks: frozenset[int] = field(default_factory=frozenset)
    state_summary: StateModelSummary | None = None

    @property
    def state_constants(self) -> set:
        if self.state_summary is not None:
            return set(self.state_summary.state_constants)
        return _coerce_state_constants(
            getattr(self.state_machine, "state_constants", None)
        )

    @property
    def handler_count(self) -> int:
        if self.state_summary is not None:
            return max(0, int(self.state_summary.handler_count))
        return _safe_len(getattr(self.state_machine, "handlers", None))

    @property
    def transition_count(self) -> int:
        if self.state_summary is not None:
            return max(0, int(self.state_summary.transition_count))
        return _safe_len(getattr(self.state_machine, "transitions", None))

    @property
    def unresolved_transition_count(self) -> int:
        return self.transition_count - len(self.resolved_transitions)
