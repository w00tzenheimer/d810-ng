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
from d810.ir.maturity import (
    MaturityEnvelope,
)
from d810.transforms.planner_context import (
    CumulativePlannerView,
)

if TYPE_CHECKING:
    from d810.ir.flowgraph import FlowGraph
    from d810.analyses.control_flow.round_discovery_context import (
        PreanalysisRoundDiscoveryContext,
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


@dataclass(frozen=True, init=False)
class AnalysisSnapshot:
    """Immutable analysis result for one maturity pass.

    Built once by the state-machine CFF unflattener at the start of optimize().
    Passed to every strategy's plan() method as read-only context.
    """

    mba: object  # ida_hexrays.mba_t — opaque object because the concrete type is caller-specific
    state_machine: object | None
    detector: object | None
    dispatcher_analysis: object | None  # opaque; family-specific DispatcherAnalysis
    range_evidence: object | None
    dispatcher_root_serial: int
    dispatcher_blocks: frozenset[int]
    handler_graph: dict
    reachability: ReachabilityInfo | None
    state_write_provenance: dict
    provider_level: int
    maturity_envelope: MaturityEnvelope | None
    pass_number: int
    resolved_transitions: frozenset
    initial_transitions: tuple
    flow_graph: FlowGraph | None
    nop_state_values: dict[int, int]
    lfg_redirected_blocks: frozenset[int]
    state_summary: StateModelSummary | None
    # Canonical per-round classification bundle. Types are narrowed via
    # ``TYPE_CHECKING``; runtime imports remain engine-only so recon types
    # never leak into the engine's pure-Python import graph. Defaults to
    # ``None`` until a family adapter opts in to building it; strategies MUST
    # tolerate ``None`` during the Phase A scaffolding rollout.
    discovery: PreanalysisRoundDiscoveryContext | None

    # Validated maturity fact view. Most strategy uses are diagnostic, but
    # narrow consumers may use validated facts as semantic safety gates when
    # the behavior is explicitly fact-backed and does not rediscover intent.
    diagnostic_fact_view: object | None

    # Cumulative planner-context view built from prior fragments' metadata
    # entries under the "planner_ctx" key. The engine rebuilds this before
    # each strategy's plan() call, aggregating every LinearizationDecision /
    # StateWriteNeutralization / claimed_sources contribution made earlier
    # in the same pipeline run. Strategies read from it to avoid re-routing
    # blocks that prior strategies have already committed to.
    # Defaults to None; strategies MUST tolerate None (fall back to "no
    # prior context known").
    cumulative_planner_view: CumulativePlannerView | None

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
    round_context: RoundContext

    def __init__(
        self,
        *,
        mba: object,
        state_machine: object | None = None,
        detector: object | None = None,
        dispatcher_analysis: object | None = None,
        range_evidence: object | None = None,
        dispatcher_root_serial: int = -1,
        dispatcher_blocks: frozenset[int] | None = None,
        handler_graph: dict | None = None,
        reachability: ReachabilityInfo | None = None,
        state_write_provenance: dict | None = None,
        provider_level: int = 0,
        maturity_envelope: MaturityEnvelope | None = None,
        pass_number: int = 0,
        resolved_transitions: frozenset | None = None,
        initial_transitions: tuple = (),
        flow_graph: FlowGraph | None = None,
        nop_state_values: dict[int, int] | None = None,
        lfg_redirected_blocks: frozenset[int] | None = None,
        state_summary: StateModelSummary | None = None,
        discovery: PreanalysisRoundDiscoveryContext | None = None,
        diagnostic_fact_view: object | None = None,
        cumulative_planner_view: CumulativePlannerView | None = None,
        round_context: RoundContext | None = None,
        **legacy_fields: object,
    ) -> None:
        legacy_provider_level = legacy_fields.pop("maturity", None)
        if legacy_fields:
            names = ", ".join(sorted(legacy_fields))
            raise TypeError(f"Unexpected AnalysisSnapshot field(s): {names}")
        if legacy_provider_level is not None:
            provider_level = int(legacy_provider_level)
        object.__setattr__(self, "mba", mba)
        object.__setattr__(self, "state_machine", state_machine)
        object.__setattr__(self, "detector", detector)
        object.__setattr__(self, "dispatcher_analysis", dispatcher_analysis)
        object.__setattr__(self, "range_evidence", range_evidence)
        object.__setattr__(
            self, "dispatcher_root_serial", int(dispatcher_root_serial)
        )
        object.__setattr__(
            self, "dispatcher_blocks", dispatcher_blocks or frozenset()
        )
        object.__setattr__(self, "handler_graph", handler_graph or {})
        object.__setattr__(self, "reachability", reachability)
        object.__setattr__(
            self, "state_write_provenance", state_write_provenance or {}
        )
        object.__setattr__(self, "provider_level", int(provider_level))
        object.__setattr__(self, "maturity_envelope", maturity_envelope)
        object.__setattr__(self, "pass_number", int(pass_number))
        object.__setattr__(
            self, "resolved_transitions", resolved_transitions or frozenset()
        )
        object.__setattr__(self, "initial_transitions", initial_transitions)
        object.__setattr__(self, "flow_graph", flow_graph)
        object.__setattr__(self, "nop_state_values", nop_state_values or {})
        object.__setattr__(
            self, "lfg_redirected_blocks", lfg_redirected_blocks or frozenset()
        )
        object.__setattr__(self, "state_summary", state_summary)
        object.__setattr__(self, "discovery", discovery)
        object.__setattr__(self, "diagnostic_fact_view", diagnostic_fact_view)
        object.__setattr__(
            self, "cumulative_planner_view", cumulative_planner_view
        )
        object.__setattr__(
            self, "round_context", round_context or RoundContext()
        )

    @property
    def maturity(self) -> int:
        if (
            self.maturity_envelope is not None
            and self.maturity_envelope.provider_id is not None
        ):
            return int(self.maturity_envelope.provider_id)
        return int(self.provider_level)

    @property
    def state_constants(self) -> set:
        if self.state_summary is not None:
            return set(self.state_summary.state_constants)
        return _coerce_state_constants(
            getattr(self.state_machine, "state_constants", None)
        )

    @property
    def dispatcher_serial(self) -> int:
        return int(self.dispatcher_root_serial)

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
