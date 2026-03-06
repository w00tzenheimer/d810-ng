"""Core protocol types for the Hodur strategy-based unflattening pipeline.

All types in this module are pure Python - no IDA imports - so they can be
fully exercised by unit tests without an IDA environment.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from d810.core.typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from d810.cfg.graph_modification import GraphModification
    from d810.cfg.flowgraph import FlowGraph
    # AnalysisSnapshot lives in an IDA-dependent module; import only for type
    # checking so this module remains importable in unit-test environments.
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
        AnalysisSnapshot,
    )

# ---------------------------------------------------------------------------
# Family constants
# ---------------------------------------------------------------------------

FAMILY_DIRECT: str = "direct"
FAMILY_FALLBACK: str = "fallback"
FAMILY_CLEANUP: str = "cleanup"


# ---------------------------------------------------------------------------
# OwnershipScope
# ---------------------------------------------------------------------------


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
        """Return True iff this scope and *other* share no owned resources.

        Args:
            other: The scope to compare against.

        Returns:
            True when blocks, edges, and transitions are all pairwise disjoint.
        """
        return (
            self.blocks.isdisjoint(other.blocks)
            and self.edges.isdisjoint(other.edges)
            and self.transitions.isdisjoint(other.transitions)
        )

    def union(self, other: OwnershipScope) -> OwnershipScope:
        """Return a new scope that is the union of this scope and *other*.

        Args:
            other: The scope to merge with.

        Returns:
            A new :class:`OwnershipScope` whose sets are the unions of both.
        """
        return OwnershipScope(
            blocks=self.blocks | other.blocks,
            edges=self.edges | other.edges,
            transitions=self.transitions | other.transitions,
        )

    def overlap_blocks(self, other: OwnershipScope) -> frozenset[int]:
        """Return the intersection of block sets.

        Args:
            other: The scope to intersect with.

        Returns:
            Frozenset of block serials present in both scopes.
        """
        return self.blocks & other.blocks

    def overlap_edges(self, other: OwnershipScope) -> frozenset[tuple[int, int]]:
        """Return the intersection of edge sets.

        Args:
            other: The scope to intersect with.

        Returns:
            Frozenset of edges present in both scopes.
        """
        return self.edges & other.edges


# ---------------------------------------------------------------------------
# BenefitMetrics
# ---------------------------------------------------------------------------


@dataclass
class BenefitMetrics:
    """Quantitative estimate of the benefit a :class:`PlanFragment` provides.

    Args:
        handlers_resolved: Number of flattened handlers the plan linearises.
        transitions_resolved: Number of state transitions that become explicit gotos.
        blocks_freed: Number of dispatcher or BST blocks that become dead code.
        conflict_density: Estimated proportion of owned resources that conflict
            with other concurrently-active strategies (0.0-1.0+).
    """

    handlers_resolved: int
    transitions_resolved: int
    blocks_freed: int
    conflict_density: float

    def composite_score(self) -> float:
        """Compute a weighted scalar benefit estimate.

        Weights: handlers * 3, transitions * 2, blocks * 1, conflict * -5.

        Returns:
            Weighted float; higher is better.
        """
        return (
            self.handlers_resolved * 3.0
            + self.transitions_resolved * 2.0
            + self.blocks_freed * 1.0
            - self.conflict_density * 5.0
        )


# ---------------------------------------------------------------------------
# PlanFragment
# ---------------------------------------------------------------------------


@dataclass
class PlanFragment:
    """A concrete unflattening plan produced by a single strategy for one pass.

    Args:
        strategy_name: Identifier of the strategy that produced this fragment.
        family: Strategy family - one of :data:`FAMILY_DIRECT`,
            :data:`FAMILY_FALLBACK`, or :data:`FAMILY_CLEANUP`.
        ownership: Microcode resources claimed by this plan.
        prerequisites: Names of other strategies whose fragments must be applied
            before this one.
        expected_benefit: Estimated benefit of applying this plan.
        risk_score: Estimated probability (0.0-1.0) that applying this plan
            introduces a correctness error.
        modifications: Ordered list of backend-agnostic graph modifications.
    """

    strategy_name: str
    family: str
    ownership: OwnershipScope
    prerequisites: list[str]
    expected_benefit: BenefitMetrics
    risk_score: float
    metadata: dict = field(default_factory=dict)  # type: ignore[type-arg]
    """Arbitrary strategy-specific metadata (e.g. pass0 ledger, bookkeeping for G2)."""
    modifications: list[GraphModification] = field(default_factory=list)

    def is_empty(self) -> bool:
        """Return True when this fragment proposes no graph-affecting actions."""
        return len(self.modifications) == 0


# ---------------------------------------------------------------------------
# UnflatteningStrategy Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class UnflatteningStrategy(Protocol):
    """Interface that every concrete unflattening strategy must satisfy.

    Strategies are stateless objects; all mutable context is passed through
    the ``snapshot`` argument so strategies can be instantiated once and
    reused across multiple functions.
    """

    @property
    def name(self) -> str:
        """Short, unique identifier for this strategy (e.g. ``"direct_linearize"``)."""
        ...

    @property
    def family(self) -> str:
        """Strategy family - one of :data:`FAMILY_DIRECT`, :data:`FAMILY_FALLBACK`,
        or :data:`FAMILY_CLEANUP`."""
        ...

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when this strategy can produce a non-empty plan.

        Args:
            snapshot: Read-only view of the current function's analysis state.

        Returns:
            True if the strategy has actionable work to do.
        """
        ...

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Produce a :class:`PlanFragment` describing desired modifications.

        Args:
            snapshot: Read-only view of the current function's analysis state.

        Returns:
            A :class:`PlanFragment` with at least one modification, or ``None``
            when the strategy has nothing to contribute.
        """
        ...


# ---------------------------------------------------------------------------
# StageResult
# ---------------------------------------------------------------------------


@dataclass
class StageResult:
    """Outcome of executing one plan fragment."""

    strategy_name: str
    edits_applied: int = 0
    reachability_after: float = 1.0          # DIAGNOSTIC ONLY
    handler_reachability: float = 1.0        # DIAGNOSTIC ONLY
    conflict_count_after: int = 0
    terminal_cycles: list = field(default_factory=list)  # gate-critical
    success: bool = True
    rollback_needed: bool = False
    quarantine: bool = False
    error: str | None = None
    failure_phase: str | None = None
    metadata: dict = field(default_factory=dict)  # type: ignore[type-arg]
    """Arbitrary diagnostic metadata (e.g. terminal return audit/proof results)."""


# ---------------------------------------------------------------------------
# VerificationGate
# ---------------------------------------------------------------------------


@dataclass
class VerificationGate:
    """Post-stage verification thresholds.

    After direct linearization, dispatcher and BST blocks become dead code,
    so block-level reachability drops significantly (e.g. to ~0.66). This is
    *expected*. The primary correctness metric is **handler reachability** -
    the fraction of handler entry blocks that remain reachable from the
    function entry. Block-level reachability is kept only as a catastrophic-
    failure floor.

    Attributes:
        min_reachability: Catastrophic floor for block-level reachability.
        min_handler_reachability: Primary gate - fraction of handler entries
            that must be reachable after the stage.
        max_conflict_count: Upper bound on conflict count.
    """

    min_reachability: float = 0.7
    min_handler_reachability: float = 0.9
    max_conflict_count: int = 10

    def check(self, result: StageResult) -> bool:
        """Return True iff the result passes all verification thresholds.

        Args:
            result: The stage result to check.

        Returns:
            True when handler reachability is above the minimum, block-level
            reachability is above the catastrophic floor, and conflict count
            is at or below the maximum.
        """
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


# ---------------------------------------------------------------------------
# SemanticGate (re-exported from cfg layer for convenience)
# ---------------------------------------------------------------------------

from d810.cfg.flow.graph_checks import SemanticGate  # noqa: E402
