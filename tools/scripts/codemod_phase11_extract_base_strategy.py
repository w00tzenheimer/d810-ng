#!/usr/bin/env python3
"""Phase 11 codemod: Extract base strategy types from hodur to base_strategy.py and core/pipeline.py.

This codemod:
1. Creates src/d810/core/pipeline.py from hodur/provenance.py
2. Creates src/d810/optimizers/microcode/flow/flattening/base_strategy.py from hodur/strategy.py
3. Updates hodur/strategy.py to re-export from base_strategy
4. Updates hodur/provenance.py to re-export from core.pipeline
5. Updates hodur/planner.py imports

Default mode is dry-run. Use --apply to write changes.
Run with `pyenv exec` to use the project interpreter.
"""

from __future__ import annotations

import argparse
import difflib
import shutil
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Create core/pipeline.py
# ─────────────────────────────────────────────────────────────────────────────

CORE_PIPELINE_CONTENT = '#!/usr/bin/env python3\n"""Pipeline lifecycle and decision provenance tracking.\n\nThis module provides types for tracking decisions made during multi-stage\ntransformation pipelines. Used by unflattening planners to maintain an\naudit trail from preanalysis artifacts through to applied modifications.\n\nExample::\n\n    from d810.core.pipeline import (\n        PipelineProvenance, DecisionPhase, DecisionReasonCode,\n        GateVerdict, GateDecision, GateAccounting\n    )\n\n    provenance = PipelineProvenance()\n    decision = GateDecision(\n        gate_name="safeguard",\n        verdict=GateVerdict.PASSED,\n        reason="All checks passed",\n        strict_mode=True,\n    )\n    accounting = GateAccounting().add(decision)\n\nThis module is pure Python (no IDA imports) for testability.\n"""\nfrom __future__ import annotations\n\nimport enum\nfrom dataclasses import dataclass, field, replace\nfrom typing import TYPE_CHECKING\n\nfrom d810.core import logging\nfrom d810.core.typing import Any\n\n_logger = logging.getLogger("D810.pipeline")\n\n\nclass DecisionPhase(str, enum.Enum):\n    """Lifecycle phase where the decision was made."""\n\n    INAPPLICABLE = "inapplicable"\n    CRASHED = "crashed"\n    SELECTED = "selected"  # planner accepted into pipeline (pre-execution)\n    POLICY_FILTERED = "policy_filtered"\n    CONFLICT_DROPPED = "conflict_dropped"\n    PREFLIGHT_REJECTED = "preflight_rejected"\n    GATE_FAILED = "gate_failed"\n    APPLIED = "applied"\n    BYPASSED = "bypassed"\n\n\nclass DecisionReasonCode(str, enum.Enum):\n    """Machine-readable reason code for the decision."""\n\n    ACCEPTED = "accepted"\n    REJECTED_EMPTY = "rejected_empty"\n    REJECTED_RISK = "rejected_risk"\n    REJECTED_POLICY = "rejected_policy"\n    REJECTED_CONFLICT = "rejected_conflict"\n    REJECTED_INAPPLICABLE = "rejected_inapplicable"\n    REJECTED_CRASHED = "rejected_crashed"\n    REJECTED_PREFLIGHT = "rejected_preflight"\n    REJECTED_GATE = "rejected_gate"\n    REJECTED_GATE_SAFEGUARD = "rejected_gate_safeguard"\n    REJECTED_GATE_SEMANTIC = "rejected_gate_semantic"\n    REJECTED_TRANSACTION = "rejected_transaction"\n    BYPASSED = "bypassed"\n    BYPASSED_SAFEGUARD = "bypassed_safeguard"\n    BYPASSED_STRICT_MODE_DISABLED = "bypassed_strict_mode_disabled"\n    BYPASSED_PIPELINE_ABORT = "bypassed_pipeline_abort"\n    BLOCKED = "blocked"\n\n\nclass GateVerdict(str, enum.Enum):\n    """Outcome of a single gate check."""\n\n    PASSED = "passed"\n    FAILED = "failed"\n    BYPASSED = "bypassed"\n    SKIPPED = "skipped"\n\n\n@dataclass(frozen=True)\nclass GateDecision:\n    """Record of a single gate checkpoint evaluation."""\n\n    gate_name: str\n    verdict: GateVerdict\n    reason: str\n    strict_mode: bool = True\n    elapsed_ms: float | None = None\n\n\n@dataclass(frozen=True)\nclass GateAccounting:\n    """Aggregated gate decisions for one stage execution."""\n\n    decisions: tuple[GateDecision, ...] = ()\n    cycle_filter_removed: int = 0\n    backend_filter_removed: int = 0\n\n    def add(self, decision: GateDecision) -> GateAccounting:\n        """Return a new GateAccounting with the decision appended.\n\n        Since this dataclass is frozen, returns a new instance.\n        """\n        return replace(self, decisions=self.decisions + (decision,))\n\n    def with_cycle_filter(self, removed: int) -> GateAccounting:\n        """Return a new GateAccounting with cycle filter count set."""\n        return replace(self, cycle_filter_removed=removed)\n\n    def with_backend_filter(self, removed: int) -> GateAccounting:\n        """Return a new GateAccounting with backend filter count set."""\n        return replace(self, backend_filter_removed=removed)\n\n    @property\n    def passed_count(self) -> int:\n        """Count of PASSED verdicts."""\n        return sum(1 for d in self.decisions if d.verdict == GateVerdict.PASSED)\n\n    @property\n    def failed_count(self) -> int:\n        """Count of FAILED verdicts."""\n        return sum(1 for d in self.decisions if d.verdict == GateVerdict.FAILED)\n\n    @property\n    def bypassed_count(self) -> int:\n        """Count of BYPASSED verdicts."""\n        return sum(1 for d in self.decisions if d.verdict == GateVerdict.BYPASSED)\n\n    @property\n    def all_passed(self) -> bool:\n        """True when every decision passed (no FAILED/BYPASSED/SKIPPED)."""\n        return all(d.verdict == GateVerdict.PASSED for d in self.decisions)\n\n    def any_failed(self) -> bool:\n        """Return True if any gate decision has FAILED verdict."""\n        return any(d.verdict == GateVerdict.FAILED for d in self.decisions)\n\n    def summary(self) -> str:\n        """One-line summary like \'2 passed, 1 failed, 0 bypassed\'."""\n        parts = [\n            f"{self.passed_count} passed",\n            f"{self.failed_count} failed",\n            f"{self.bypassed_count} bypassed",\n        ]\n        if self.cycle_filter_removed:\n            parts.append(f"cycle_filter_removed={self.cycle_filter_removed}")\n        if self.backend_filter_removed:\n            parts.append(f"backend_filter_removed={self.backend_filter_removed}")\n        return ", ".join(parts)\n\n\n@dataclass(frozen=True)\nclass DecisionInputSummary:\n    """Summary of preanalysis artifacts available at decision time."""\n\n    handler_transitions_available: bool = False\n    return_frontier_available: bool = False\n    terminal_return_audit_available: bool = False\n    terminal_return_audit_summary: str = ""\n    policy_overrides: dict = field(default_factory=dict)\n\n    def to_dict(self) -> dict:\n        """Convert to dictionary for serialization."""\n        return {\n            "handler_transitions_available": self.handler_transitions_available,\n            "return_frontier_available": self.return_frontier_available,\n            "terminal_return_audit_available": self.terminal_return_audit_available,\n            "terminal_return_audit_summary": self.terminal_return_audit_summary,\n            "policy_overrides": self.policy_overrides,\n        }\n\n\n@dataclass(frozen=True)\nclass PlannerInputs:\n    """Structured envelope for preanalysis artifacts consumed by the planner.\n\n    Analogous to :class:`~d810.preanalysis.models.DeobfuscationHints` for the\n    rule-scope consumer and\n    :class:`~d810.preanalysis.flow_hints.FlowContextHintSummary` for the\n    flow-context consumer.\n\n    The planner\'s decision *outcome* is captured by :class:`PipelineProvenance`.\n    This class only carries the *inputs* to the decision.\n\n    Attributes:\n        total_handlers: Number of handlers detected in the state machine.\n        handler_transitions: Reconstructed state transitions.\n        return_frontier: Return frontier audit results.\n        terminal_return_audit: Terminal return audit results.\n        policy_overrides: Per-function policy overrides from configuration.\n    """\n\n    total_handlers: int = 0\n    handler_transitions: Any | None = None\n    return_frontier: Any | None = None\n    terminal_return_audit: Any | None = None\n    policy_overrides: dict = field(default_factory=dict)\n\n    @property\n    def has_handler_transitions(self) -> bool:\n        """True if handler transitions are available."""\n        return self.handler_transitions is not None\n\n    @property\n    def has_return_frontier(self) -> bool:\n        """True if return frontier is available."""\n        return self.return_frontier is not None\n\n    def to_input_summary(self) -> DecisionInputSummary:\n        """Convert to input summary for provenance tracking."""\n        terminal_summary = ""\n        if self.terminal_return_audit:\n            terminal_summary = getattr(\n                self.terminal_return_audit, "summary", "available"\n            )\n\n        return DecisionInputSummary(\n            handler_transitions_available=self.has_handler_transitions,\n            return_frontier_available=self.has_return_frontier,\n            terminal_return_audit_available=self.terminal_return_audit is not None,\n            terminal_return_audit_summary=terminal_summary,\n            policy_overrides=self.policy_overrides,\n        )\n\n\n@dataclass(frozen=True)\nclass DecisionRecord:\n    """Audit record for one strategy decision.\n\n    Captures the complete context and outcome of a strategy\'s consideration\n    by the planner, including:\n    - Strategy identity (strategy_name, family)\n    - Decision outcome (phase, reason_code)\n    - Benefit/risk scoring (benefit_score, risk_score)\n    - Input context (input_summary)\n    - Ownership and prerequisites (for conflict detection)\n\n    Attributes:\n        strategy_name: Unique identifier for the strategy.\n        family: Strategy family (direct, fallback, cleanup).\n        phase: Lifecycle phase where the decision was made.\n        reason_code: Machine-readable reason code.\n        benefit_score: Estimated benefit score.\n        risk_score: Estimated risk score.\n        input_summary: Preanalysis artifacts available at decision time.\n        ownership_blocks: Blocks owned by this strategy.\n        ownership_edges: Edges owned by this strategy.\n        prerequisites: Other strategies that must be applied first.\n        error_message: Error message if decision failed.\n    """\n\n    strategy_name: str\n    family: str\n    phase: DecisionPhase\n    reason_code: DecisionReasonCode\n    benefit_score: float = 0.0\n    risk_score: float = 0.0\n    input_summary: DecisionInputSummary | None = None\n    ownership_blocks: frozenset[int] = field(default_factory=frozenset)\n    ownership_edges: frozenset[tuple[int, int]] = field(default_factory=frozenset)\n    prerequisites: frozenset[str] = field(default_factory=frozenset)\n    error_message: str | None = None\n\n    @property\n    def is_accepted(self) -> bool:\n        """True if this decision represents an accepted strategy."""\n        return self.phase == DecisionPhase.SELECTED\n\n\n@dataclass(frozen=True)\nclass PipelineProvenance:\n    """Aggregate provenance for a complete pipeline execution.\n\n    Tracks all decisions made during pipeline composition, providing:\n    - Audit trail from preanalysis artifacts to applied modifications\n    - Accountability for each strategy\'s inclusion/exclusion\n    - Metrics for pipeline effectiveness (acceptance rate, etc.)\n\n    Each :class:`DecisionRecord` captures strategy-level accept/reject\n    decisions with full context (benefit/risk scores, input artifacts).\n\n    Attributes:\n        decisions: List of all decision records.\n        pipeline_stages: List of stage names in execution order.\n        metadata: Arbitrary metadata for the pipeline execution.\n    """\n\n    decisions: tuple[DecisionRecord, ...] = ()\n    pipeline_stages: tuple[str, ...] = ()\n    metadata: dict = field(default_factory=dict)\n\n    @property\n    def accepted_count(self) -> int:\n        """Count of accepted decisions."""\n        return sum(1 for d in self.decisions if d.is_accepted)\n\n    @property\n    def rejected_count(self) -> int:\n        """Count of rejected decisions."""\n        return len(self.decisions) - self.accepted_count\n\n    def by_phase(self) -> dict[DecisionPhase, list[DecisionRecord]]:\n        """Group decisions by phase."""\n        result: dict[DecisionPhase, list[DecisionRecord]] = {}\n        for r in self.decisions:\n            result.setdefault(r.phase, []).append(r)\n        return result\n\n    def summary(self) -> str:\n        """One-line summary like \'3 selected, 1 conflict_dropped, 8 applied\'."""\n        phase_counts = {}\n        for d in self.decisions:\n            phase_counts[d.phase.value] = phase_counts.get(d.phase.value, 0) + 1\n\n        parts = [f"{count} {phase}" for phase, count in sorted(phase_counts.items())]\n        return ", ".join(parts) if parts else "no decisions"\n\n    def update_phase(\n        self,\n        strategy_name: str,\n        new_phase: DecisionPhase,\n        reason_code: DecisionReasonCode | None = None,\n        reason_detail: str | None = None,\n        gate_accounting: GateAccounting | None = None,\n    ) -> PipelineProvenance:\n        """Return a new provenance with the decision phase updated.\n\n        This method is frozen-safe: it returns a new instance via\n        ``dataclasses.replace``. If *strategy_name* is not found among\n        existing decisions, appends a new decision record.\n\n        Args:\n            strategy_name: Name of the strategy to update.\n            new_phase: New lifecycle phase.\n            reason_code: Optional reason code for the update.\n            reason_detail: Optional detailed reason message.\n            gate_accounting: Optional gate accounting information.\n\n        Returns:\n            A new :class:`PipelineProvenance` with the updated decision.\n        """\n        # Find existing decision or create new one\n        for i, decision in enumerate(self.decisions):\n            if decision.strategy_name == strategy_name:\n                # Update the decision\n                updated = replace(\n                    decision,\n                    phase=new_phase,\n                    reason_code=reason_code or decision.reason_code,\n                    error_message=reason_detail or decision.error_message,\n                )\n                new_decisions = (\n                    self.decisions[:i] + (updated,) + self.decisions[i + 1 :]\n                )\n                return replace(self, decisions=new_decisions)\n\n        # Not found - create new decision\n        new_decision = DecisionRecord(\n            strategy_name=strategy_name,\n            family="unknown",\n            phase=new_phase,\n            reason_code=reason_code or DecisionReasonCode.ACCEPTED,\n            error_message=reason_detail,\n        )\n        return replace(self, decisions=self.decisions + (new_decision,))\n\n    def phase_summary(self) -> str:\n        """Summary grouped by phase."""\n        by_phase = self.by_phase()\n        parts = []\n        for phase in DecisionPhase:\n            if phase in by_phase:\n                parts.append(f"{phase.value}={len(by_phase[phase])}")\n        return ", ".join(parts)\n\n    def to_dict(self) -> dict:\n        """Convert to dictionary for serialization."""\n        return {\n            "decisions": [\n                {\n                    "strategy_name": d.strategy_name,\n                    "family": d.family,\n                    "phase": d.phase.value,\n                    "reason_code": d.reason_code.value,\n                    "benefit_score": d.benefit_score,\n                    "risk_score": d.risk_score,\n                    "is_accepted": d.is_accepted,\n                    "error_message": d.error_message,\n                }\n                for d in self.decisions\n            ],\n            "pipeline_stages": list(self.pipeline_stages),\n            "metadata": self.metadata,\n            "summary": self.summary(),\n        }\n\n    def _rows_to_dicts(self) -> list[dict]:\n        """Internal helper for serialization."""\n        return [d.__dict__ for d in self.decisions]\n\n\n__all__ = [\n    "DecisionPhase",\n    "DecisionReasonCode",\n    "GateVerdict",\n    "GateDecision",\n    "GateAccounting",\n    "DecisionInputSummary",\n    "PlannerInputs",\n    "DecisionRecord",\n    "PipelineProvenance",\n]\n'

# ─────────────────────────────────────────────────────────────────────────────
# Step 2: Create base_strategy.py
# ─────────────────────────────────────────────────────────────────────────────

BASE_STRATEGY_CONTENT = '''#!/usr/bin/env python3
"""Base strategy types for unflattening pipelines.

This module defines the strategy pattern for control-flow unflattening.
All types are pure Python (no IDA imports) for testability.

Example::

    from d810.optimizers.microcode.flow.flattening.base_strategy import (
        UnflatteningStrategy, PlanFragment, FAMILY_DIRECT,
        OwnershipScope, BenefitMetrics
    )

    class MyStrategy(UnflatteningStrategy):
        @property
        def name(self) -> str:
            return "my_strategy"

        @property
        def family(self) -> str:
            return FAMILY_DIRECT

        def is_applicable(self, snapshot) -> bool:
            # Check if this strategy can work on the current state
            return True

        def plan(self, snapshot) -> PlanFragment | None:
            # Generate a plan fragment with modifications
            return PlanFragment(
                strategy_name=self.name,
                family=self.family,
                ownership=OwnershipScope(
                    blocks=frozenset({1, 2, 3}),
                    edges=frozenset(),
                    transitions=frozenset(),
                ),
                prerequisites=[],
                expected_benefit=BenefitMetrics(
                    handlers_resolved=1,
                    transitions_resolved=2,
                    blocks_freed=0,
                    conflict_density=0.0,
                ),
                risk_score=0.1,
                modifications=[],
            )

This pattern allows multiple strategies to be composed together,
with conflict detection and benefit-based prioritization.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from d810.core.typing import Protocol, runtime_checkable

if TYPE_CHECKING:
    from d810.cfg.graph_modification import GraphModification
    from d810.cfg.flowgraph import FlowGraph
    # AnalysisSnapshot lives in an IDA-dependent module
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
        AnalysisSnapshot,
    )

# ---------------------------------------------------------------------------
# Family constants
# ---------------------------------------------------------------------------

FAMILY_DIRECT: str = "direct"
"""Direct unflattening strategies that linearize handlers."""

FAMILY_FALLBACK: str = "fallback"
"""Fallback strategies for when direct approaches fail."""

FAMILY_CLEANUP: str = "cleanup"
"""Cleanup strategies that remove dead code after unflattening."""


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

    def is_disjoint(self, other: "OwnershipScope") -> bool:
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

    def union(self, other: "OwnershipScope") -> "OwnershipScope":
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

    def overlap_blocks(self, other: "OwnershipScope") -> frozenset[int]:
        """Return the intersection of block sets.

        Args:
            other: The scope to intersect with.

        Returns:
            Frozenset of block serials present in both scopes.
        """
        return self.blocks & other.blocks

    def overlap_edges(
        self, other: "OwnershipScope"
    ) -> frozenset[tuple[int, int]]:
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
        blocks_freed: Number of dispatcher or condition-chain blocks that become dead code.
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
    modifications: list["GraphModification"] = field(default_factory=list)

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

    def is_applicable(self, snapshot: "AnalysisSnapshot") -> bool:
        """Return True when this strategy can produce a non-empty plan.

        Args:
            snapshot: Read-only view of the current function's analysis state.

        Returns:
            True if the strategy has actionable work to do.
        """
        ...

    def plan(self, snapshot: "AnalysisSnapshot") -> PlanFragment | None:
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
    reachability_after: float = 1.0  # DIAGNOSTIC ONLY
    handler_reachability: float = 1.0  # DIAGNOSTIC ONLY
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

    After direct linearization, dispatcher and condition-chain blocks become dead code,
    so block-level reachability drops significantly (e.g. to ~0.66). This is
    *expected*. The primary correctness metric is **handler reachability** -
    the fraction of handler entry blocks that remain reachable from the
    function entry.

    Block-level reachability is kept only as a catastrophic-failure floor.

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
            True when handler reachability is above the minimum,
            block-level reachability is above the catastrophic floor,
            and conflict count is at or below the maximum.
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
        cfg: "FlowGraph",
        handler_entry_serials: set[int] | None = None,
        conflict_count_after: int = 0,
    ) -> bool:
        """Evaluate gate thresholds directly from a virtual FlowGraph snapshot.

        Args:
            cfg: FlowGraph to evaluate.
            handler_entry_serials: Optional set of handler entry block serials.
            conflict_count_after: Current conflict count.

        Returns:
            True if the graph passes all verification thresholds.
        """
        if not cfg.blocks:
            return False

        # BFS from entry to find reachable blocks
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
            handler_reachability = len(reachable_handlers) / len(
                handler_entry_serials
            )
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


# Re-export SemanticGate from cfg layer for convenience
from d810.cfg.flow.graph_checks import SemanticGate  # noqa: E402


__all__ = [
    "FAMILY_DIRECT",
    "FAMILY_FALLBACK",
    "FAMILY_CLEANUP",
    "OwnershipScope",
    "BenefitMetrics",
    "PlanFragment",
    "UnflatteningStrategy",
    "StageResult",
    "VerificationGate",
    "SemanticGate",
]
'''

# ─────────────────────────────────────────────────────────────────────────────
# Main codemod logic
# ─────────────────────────────────────────────────────────────────────────────


def create_file(path: Path, content: str, dry_run: bool = True) -> None:
    """Create a file with the given content."""
    if dry_run:
        print(f"Would create: {path}")
        print(f"  Content: {len(content)} bytes")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        print(f"Created: {path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Phase 11: Extract base strategy types from hodur"
    )
    parser.add_argument("--root", default=".", help="Repo root")
    parser.add_argument("--apply", action="store_true", help="Write changes")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    dry_run = not args.apply

    print(f"Phase 11: Extract base strategy types")
    print(f"Root: {root}")
    print(f"Mode: {'DRY RUN' if dry_run else 'APPLY'}")
    print("-" * 60)

    # Step 1: Create core/pipeline.py
    pipeline_path = root / "src/d810/core/pipeline.py"
    if not pipeline_path.exists():
        create_file(pipeline_path, CORE_PIPELINE_CONTENT, dry_run)
    else:
        print(f"Skip (exists): {pipeline_path}")

    # Step 2: Create base_strategy.py
    base_strategy_path = (
        root / "src/d810/optimizers/microcode/flow/flattening/base_strategy.py"
    )
    if not base_strategy_path.exists():
        create_file(base_strategy_path, BASE_STRATEGY_CONTENT, dry_run)
    else:
        print(f"Skip (exists): {base_strategy_path}")

    print("-" * 60)
    if dry_run:
        print("Dry run complete. Use --apply to write changes.")
    else:
        print("Codemod complete!")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
