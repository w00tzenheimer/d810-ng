"""Immutable analysis snapshot types for the shared unflattening engine.

Types are narrowed via :pep:`563` postponed annotations (``from __future__ import
annotations``) plus :data:`d810.core.typing.TYPE_CHECKING` — runtime imports
stay engine-local so recon types never leak into this module's runtime graph,
while callers still get proper narrow types (``ReconRoundDiscoveryContext``,
``FlowGraph``, …) for static analysis.

``ReachabilityInfo`` captures reachability from the function entry block.
``AnalysisSnapshot`` is the read-only context passed to every strategy's
``plan()`` method, with Hodur as the current primary producer. The optional
``discovery`` field carries the canonical per-round classification bundle —
live DAG, corrected DAG, dispatcher region, shared-suffix blocks, structured
regions, the reconstruction-discovery-indexes bundle, and the rendered
linearized program — built once per ``(func_ea, maturity, pass)`` and shared
by every strategy. **Consumers MUST NOT mutate ``discovery`` or any of its
fields.**
"""
from __future__ import annotations

from dataclasses import dataclass, field
from d810.core.typing import TYPE_CHECKING

from d810.core.round_context import (
    RoundContext,
)
from d810.transforms.planner_context import (
    CumulativePlannerView,
)

if TYPE_CHECKING:
    from d810.ir.flowgraph import FlowGraph
    from d810.analyses.control_flow.round_discovery_context import (
        ReconRoundDiscoveryContext,
    )


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

    mba: object  # ida_hexrays.mba_t — opaque object because the concrete type is caller-specific
    state_machine: object | None = None
    detector: object | None = None
    dispatcher_analysis: object | None = None  # opaque; family-specific DispatcherAnalysis
    bst_result: object | None = None
    bst_dispatcher_serial: int = -1
    dispatcher_blocks: frozenset[int] = field(default_factory=frozenset)
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
    # Canonical per-round classification bundle. Types are narrowed via
    # ``TYPE_CHECKING``; runtime imports remain engine-only so recon types
    # never leak into the engine's pure-Python import graph. Defaults to
    # ``None`` until a family adapter opts in to building it; strategies MUST
    # tolerate ``None`` during the Phase A scaffolding rollout.
    discovery: ReconRoundDiscoveryContext | None = None

    # Validated maturity fact view. Most strategy uses are diagnostic, but
    # narrow consumers may use validated facts as semantic safety gates when
    # the behavior is explicitly fact-backed and does not rediscover intent.
    diagnostic_fact_view: object | None = None

    # Cumulative planner-context view built from prior fragments' metadata
    # entries under the "planner_ctx" key. The engine rebuilds this before
    # each strategy's plan() call, aggregating every LinearizationDecision /
    # StateWriteNeutralization / claimed_sources contribution made earlier
    # in the same pipeline run. Strategies read from it to avoid re-routing
    # blocks that prior strategies have already committed to.
    # Defaults to None; strategies MUST tolerate None (fall back to "no
    # prior context known").
    cumulative_planner_view: CumulativePlannerView | None = None

    # Hierarchical execution-scope stack. Empty ``RoundContext`` means
    # "pass-entry, pre-strategy". Strategies that have internal
    # projected-replan rounds push ``RoundFrame(scope="round", index=N,
    # name=...)`` frames and pass the updated snapshot down to sub-callbacks
    # via ``dataclasses.replace``. Strategies reading ``discovery.dag`` MUST
    # be aware that ``discovery`` is pass-entry frozen — when
    # ``round_context.in_round`` is True the live CFG has already moved, so
    # consulting ``discovery`` returns the ORIGINAL pass-entry view, not the
    # current projected view. Use ``round_summary`` (LFG-local) for the
    # current projected DAG. The ``round_context.as_trace()`` breadcrumb is
    # suitable for guardrail / debug log correlation.
    round_context: RoundContext = field(default_factory=RoundContext)

    @property
    def state_constants(self) -> set:
        if self.state_summary is not None:
            return set(self.state_summary.state_constants)
        return _coerce_state_constants(
            getattr(self.state_machine, "state_constants", None)
        )

    @property
    def dispatcher_serial(self) -> int:
        return int(self.bst_dispatcher_serial)

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
