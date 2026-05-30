"""Core protocol types for the shared unflattening engine.

All types in this module are pure Python, so they can be exercised by unit
tests without an IDA environment.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.typing import (
    TYPE_CHECKING,
    NotRequired,
    TypedDict,
)
from d810.transforms.lowering import LoweringMode
# Canonical home for ``UnflatteningStrategy`` is
# ``d810.families.state_machine_cff.protocols`` per the
# llvm-lisa-restructure plan.  This module re-exports it for
# back-compat with the dozen existing import sites under
# ``optimizers.microcode.flow.flattening.engine`` and ``hodur/``.
# New code should import from the canonical location.
from d810.families.state_machine_cff.protocols import UnflatteningStrategy
from d810.optimizers.microcode.flow.flattening.engine.planner_context import (
    PlannerContextContribution,
)

if TYPE_CHECKING:
    from d810.cfg.flowgraph import FlowGraph
    from d810.transforms.graph_modification import GraphModification

__all__ = [
    "FAMILY_CLEANUP",
    "FAMILY_DIRECT",
    "FAMILY_FALLBACK",
    "BenefitMetrics",
    "OwnershipScope",
    "PlanFragment",
    "PlanFragmentMetadata",
    "StageResult",
    "UnflatteningStrategy",
    "VerificationGate",
]


class PlanFragmentMetadata(TypedDict, total=False):
    """Typed schema for :attr:`PlanFragment.metadata`.

    ``total=False`` so strategies only declare the keys they actually set.
    Only a handful of keys are typed here today — the rest remain untyped
    `dict` access at runtime. Add keys as they're audited; the TypedDict
    shape is advisory for type checkers, not enforced at runtime.

    Currently typed:
        planner_ctx: A :class:`PlannerContextContribution` recording the
            linearization decisions, state-write neutralizations, and
            claimed sources this fragment's strategy made. The engine
            aggregates these across fragments via
            :meth:`CumulativePlannerView.compile` and injects the result
            onto :class:`AnalysisSnapshot.cumulative_planner_view` for
            subsequent strategies.
    """

    planner_ctx: NotRequired[PlannerContextContribution]
    #: LS12: target CFG-shape provenance, stamped by the planner from the
    #: producing strategy's ``lowering_mode``.  PROVENANCE-ONLY -- never read by
    #: planner scoring / fragment arbitration / executor (which key on
    #: ``fragment.family``); recorded only for diagnostics and future slices.
    lowering_mode: NotRequired[LoweringMode]


FAMILY_DIRECT: str = "direct"
FAMILY_FALLBACK: str = "fallback"
FAMILY_CLEANUP: str = "cleanup"


@dataclass(frozen=True)
class OwnershipScope:
    """Declares the microcode resources a strategy claims exclusive ownership of.

    Used by the plan-merger to detect and resolve conflicts between strategies
    that want to modify the same blocks, edges, or state transitions.

    Args:
        blocks: Set of block serial numbers owned by the strategy.
        edges: Set of (src_serial, dst_serial) CFG edges owned by the strategy.
        transitions: Set of (src_state, dst_state) pairs owned by the strategy.
    """

    blocks: frozenset[int]
    edges: frozenset[tuple[int, int]]
    transitions: frozenset[tuple[int, int]]

    def is_disjoint(self, other: OwnershipScope) -> bool:
        """Return True iff this scope and *other* share no owned resources."""
        return (
            self.blocks.isdisjoint(other.blocks)
            and self.edges.isdisjoint(other.edges)
            and self.transitions.isdisjoint(other.transitions)
        )

    def union(self, other: OwnershipScope) -> OwnershipScope:
        """Return a new scope that is the union of this scope and *other*."""
        return OwnershipScope(
            blocks=self.blocks | other.blocks,
            edges=self.edges | other.edges,
            transitions=self.transitions | other.transitions,
        )

    def overlap_blocks(self, other: OwnershipScope) -> frozenset[int]:
        """Return the intersection of block sets."""
        return self.blocks & other.blocks

    def overlap_edges(self, other: OwnershipScope) -> frozenset[tuple[int, int]]:
        """Return the intersection of edge sets."""
        return self.edges & other.edges


@dataclass
class BenefitMetrics:
    """Quantitative estimate of the benefit a :class:`PlanFragment` provides."""

    handlers_resolved: int
    transitions_resolved: int
    blocks_freed: int
    conflict_density: float

    def composite_score(self) -> float:
        """Compute a weighted scalar benefit estimate."""
        return (
            self.handlers_resolved * 3.0
            + self.transitions_resolved * 2.0
            + self.blocks_freed * 1.0
            - self.conflict_density * 5.0
        )


@dataclass
class PlanFragment:
    """A concrete unflattening plan produced by a single strategy for one pass."""

    strategy_name: str
    family: str
    ownership: OwnershipScope
    prerequisites: list[str]
    expected_benefit: BenefitMetrics
    risk_score: float
    # Runtime type is plain ``dict``; :class:`PlanFragmentMetadata` documents
    # the typed schema (specifically the ``planner_ctx`` key) for human
    # readers and type-checker narrowing at call sites that know to cast.
    # We can't use ``PlanFragmentMetadata`` directly as the annotation
    # here because Python 3.13's ``dataclass`` decorator introspects
    # ``cls.__mro__`` of annotated types, and TypedDict classes don't
    # expose a stable MRO — doing so raises ``AttributeError: 'function'
    # object has no attribute '__mro__'`` at import time.
    metadata: dict = field(default_factory=dict)  # type: ignore[type-arg]
    modifications: list[GraphModification] = field(default_factory=list)

    def is_empty(self) -> bool:
        """Return True when this fragment proposes no graph-affecting actions."""
        return len(self.modifications) == 0


# ``UnflatteningStrategy`` is re-exported from
# ``d810.families.state_machine_cff.protocols`` at the module top.
# Slice 2 of the llvm-lisa-restructure migration moved the canonical
# home; this module keeps the symbol importable from the old path for
# back-compat.


@dataclass
class StageResult:
    """Outcome of executing one plan fragment."""

    strategy_name: str
    edits_applied: int = 0
    reachability_after: float = 1.0
    handler_reachability: float = 1.0
    conflict_count_after: int = 0
    terminal_cycles: list = field(default_factory=list)
    success: bool = True
    rollback_needed: bool = False
    quarantine: bool = False
    error: str | None = None
    failure_phase: str | None = None
    metadata: dict = field(default_factory=dict)  # type: ignore[type-arg]


@dataclass
class VerificationGate:
    """Post-stage verification thresholds."""

    min_reachability: float = 0.7
    min_handler_reachability: float = 0.9
    max_conflict_count: int = 10

    def check(self, result: StageResult) -> bool:
        """Return True iff the result passes all verification thresholds."""
        if result.reachability_after < self.min_reachability:
            return False
        if result.handler_reachability < self.min_handler_reachability:
            return False
        if result.conflict_count_after > self.max_conflict_count:
            return False
        return True

    def check_flow_graph(
        self,
        cfg: FlowGraph,
        handler_entry_serials: set[int] | None = None,
        conflict_count_after: int = 0,
    ) -> bool:
        """Evaluate gate thresholds directly from a virtual FlowGraph snapshot."""
        if not cfg.blocks:
            return False

        visited: set[int] = set()
        queue: list[int] = [cfg.entry_serial]
        while queue:
            serial = queue.pop()
            if serial in visited or serial not in cfg.blocks:
                continue
            visited.add(serial)
            queue.extend(cfg.successors(serial))

        block_reachability = len(visited) / len(cfg.blocks)

        if handler_entry_serials:
            reachable_handlers = visited & handler_entry_serials
            handler_reachability = len(reachable_handlers) / len(handler_entry_serials)
        else:
            handler_reachability = block_reachability

        return self.check(
            StageResult(
                strategy_name="flow_graph_gate",
                reachability_after=block_reachability,
                handler_reachability=handler_reachability,
                conflict_count_after=conflict_count_after,
            )
        )


def __getattr__(name: str):
    if name == "SemanticGate":
        try:
            from d810.analyses.control_flow.graph_checks import SemanticGate
        except ModuleNotFoundError as exc:
            if exc.name and exc.name.startswith("ida_"):
                raise AttributeError(
                    "SemanticGate is unavailable without IDA dependencies"
                ) from exc
            raise

        return SemanticGate
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
