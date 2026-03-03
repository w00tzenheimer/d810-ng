"""Core protocol types for the Hodur strategy-based unflattening pipeline.

All types in this module are pure Python — no IDA imports — so they can be
fully exercised by unit tests without an IDA environment.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
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
# EditType
# ---------------------------------------------------------------------------


class EditType(Enum):
    """Describes the kind of microcode mutation a strategy wants to apply."""

    GOTO_REDIRECT = auto()
    CONVERT_TO_GOTO = auto()
    NOP_INSN = auto()
    BLOCK_DUPLICATE = auto()
    CONDITIONAL_REDIRECT = auto()


# ---------------------------------------------------------------------------
# ProposedEdit
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProposedEdit:
    """An atomic microcode edit proposed by a strategy.

    Args:
        edit_type: The kind of mutation to perform.
        source_block: Serial number of the block containing the edit site.
        target_block: Serial number of the destination block, if applicable.
        instruction_ea: Effective address of the instruction to mutate, if applicable.
        metadata: Arbitrary key/value pairs for debugging and logging.
    """

    edit_type: EditType
    source_block: int
    target_block: int | None = None
    instruction_ea: int | None = None
    metadata: dict = field(default_factory=dict)  # type: ignore[type-arg]
    """Mutable metadata dict. Contents can change despite frozen dataclass.
    Strategies should treat as write-once after construction."""


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
            with other concurrently-active strategies (0.0–1.0+).
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
        family: Strategy family — one of :data:`FAMILY_DIRECT`,
            :data:`FAMILY_FALLBACK`, or :data:`FAMILY_CLEANUP`.
        proposed_edits: Ordered list of atomic edits to apply.
        ownership: Microcode resources claimed by this plan.
        prerequisites: Names of other strategies whose fragments must be applied
            before this one.
        expected_benefit: Estimated benefit of applying this plan.
        risk_score: Estimated probability (0.0–1.0) that applying this plan
            introduces a correctness error.
    """

    strategy_name: str
    family: str
    proposed_edits: list[ProposedEdit]
    ownership: OwnershipScope
    prerequisites: list[str]
    expected_benefit: BenefitMetrics
    risk_score: float

    def is_empty(self) -> bool:
        """Return True when this fragment proposes no edits.

        Returns:
            True iff ``proposed_edits`` is empty.
        """
        return len(self.proposed_edits) == 0


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
        """Strategy family — one of :data:`FAMILY_DIRECT`, :data:`FAMILY_FALLBACK`,
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
        """Produce a :class:`PlanFragment` describing all desired edits.

        Args:
            snapshot: Read-only view of the current function's analysis state.

        Returns:
            A :class:`PlanFragment` with at least one edit, or ``None`` when
            the strategy has nothing to contribute.
        """
        ...
