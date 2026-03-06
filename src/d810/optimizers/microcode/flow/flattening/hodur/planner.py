"""Central planner for Hodur unflattening pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from d810.core.typing import TYPE_CHECKING

from d810.core.logging import getLogger
from d810.optimizers.microcode.flow.flattening.hodur.provenance import (
    DecisionPhase,
    DecisionReasonCode,
    DecisionRecord,
    PipelineProvenance,
    PlannerInputs,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_FALLBACK,
    OwnershipScope,
    PlanFragment,
    UnflatteningStrategy,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
        AnalysisSnapshot,
    )

logger = getLogger(__name__)


@dataclass
class PipelinePolicy:
    """Policy for strategy selection and ordering."""

    direct_coverage_threshold: float = 0.8  # block fallbacks if direct covers this fraction
    max_risk_score: float = 0.7  # reject fragments above this risk
    allow_fallback_families: bool = True


class UnflatteningPlanner:
    """Selects, orders, and arbitrates strategy fragments."""

    def __init__(self, policy: PipelinePolicy | None = None):
        self.policy = policy or PipelinePolicy()

    def plan(
        self,
        snapshot: AnalysisSnapshot,
        strategies: list[UnflatteningStrategy],
        inputs: PlannerInputs | None = None,
    ) -> tuple[list[PlanFragment], PipelineProvenance]:
        """Poll strategies, collect fragments, and compose the pipeline.

        This is the primary public API. It owns:
        1. Strategy polling (``is_applicable`` + ``plan``).
        2. Fragment collection.
        3. Pipeline composition via :meth:`compose_pipeline`.
        4. Provenance generation (including INAPPLICABLE/CRASHED records).

        Args:
            snapshot: Read-only view of the current function's analysis state.
            strategies: Ordered list of strategy instances to poll.
            inputs: Structured envelope with recon artifacts and handler count.

        Returns:
            A tuple of (ordered pipeline, complete provenance ledger).
        """
        fragments: list[PlanFragment] = []
        pre_planner_records: list[DecisionRecord] = []

        for strategy in strategies:
            if not strategy.is_applicable(snapshot):
                pre_planner_records.append(DecisionRecord(
                    strategy_name=strategy.name,
                    family=strategy.family,
                    phase=DecisionPhase.INAPPLICABLE,
                    reason_code=DecisionReasonCode.REJECTED_INAPPLICABLE,
                    reason="is_applicable returned False",
                ))
                continue
            try:
                fragment = strategy.plan(snapshot)
            except Exception as e:
                logger.warning(
                    "Strategy %s crashed: %s", strategy.name, e,
                )
                pre_planner_records.append(DecisionRecord(
                    strategy_name=strategy.name,
                    family=strategy.family,
                    phase=DecisionPhase.CRASHED,
                    reason_code=DecisionReasonCode.REJECTED_CRASHED,
                    reason=f"plan() raised: {e}",
                    notes=str(e),
                ))
                continue
            if fragment is not None:
                fragments.append(fragment)

        # Compose pipeline from collected fragments
        pipeline, provenance = self.compose_pipeline(
            fragments,
            inputs=inputs,
        )

        # Prepend strategy-level INAPPLICABLE/CRASHED records to planner provenance
        if pre_planner_records:
            provenance = PipelineProvenance(
                rows=tuple(pre_planner_records) + provenance.rows,
                input_summary=provenance.input_summary,
            )

        return pipeline, provenance

    def compose_pipeline(
        self,
        fragments: list[PlanFragment],
        total_handlers: int | None = None,
        *,
        inputs: PlannerInputs | None = None,
    ) -> tuple[list[PlanFragment], PipelineProvenance]:
        """Full pipeline: filter -> policy -> resolve conflicts -> order.

        Args:
            fragments: Candidate plan fragments from strategies.
            total_handlers: Handler count (deprecated, prefer inputs.total_handlers).
            inputs: Structured envelope with recon artifacts and handler count.

        Returns:
            A tuple of (ordered pipeline, provenance ledger).
        """
        # Resolve total_handlers from inputs envelope or legacy parameter
        if inputs is not None:
            effective_total_handlers = inputs.total_handlers
            input_summary = inputs.to_input_summary()
        elif total_handlers is not None:
            effective_total_handlers = total_handlers
            input_summary = None
        else:
            effective_total_handlers = 0
            input_summary = None

        rows: list[DecisionRecord] = []

        # --- Gate 1: Empty filter (fragments with no actions) ---
        filtered: list[PlanFragment] = []
        for f in fragments:
            if f.is_empty():
                rows.append(self._record(
                    f,
                    phase=DecisionPhase.INAPPLICABLE,
                    reason_code=DecisionReasonCode.REJECTED_EMPTY,
                    reason="fragment has no modifications",
                ))
            else:
                filtered.append(f)

        # --- Gate 2: Risk filter (risk_score > threshold) ---
        risk_passed: list[PlanFragment] = []
        for f in filtered:
            if f.risk_score > self.policy.max_risk_score:
                rows.append(self._record(
                    f,
                    phase=DecisionPhase.POLICY_FILTERED,
                    reason_code=DecisionReasonCode.REJECTED_RISK,
                    reason=(
                        f"risk_score={f.risk_score:.2f} > "
                        f"threshold={self.policy.max_risk_score:.2f}"
                    ),
                ))
            else:
                risk_passed.append(f)

        # --- Gate 3: Policy gate (coverage threshold drops fallbacks) ---
        accepted = self._apply_policy_with_provenance(
            risk_passed, effective_total_handlers, rows
        )

        # --- Gate 4: Conflict resolution (greedy independent set) ---
        conflicts = self.find_conflicts(accepted)
        if conflicts:
            accepted = self._resolve_conflicts_with_provenance(
                accepted, conflicts, rows
            )

        # --- Gate 5: Selection (surviving fragments) ---
        ordered = self.order_fragments(accepted)
        for f in ordered:
            rows.append(self._record(
                f,
                phase=DecisionPhase.SELECTED,
                reason_code=DecisionReasonCode.ACCEPTED,
                reason=(
                    f"composite_score={f.expected_benefit.composite_score():.1f}, "
                    f"selected into pipeline"
                ),
            ))

        provenance = PipelineProvenance(
            rows=tuple(rows),
            input_summary=input_summary,
        )
        logger.info("Pipeline provenance: %s", provenance.summary())
        return ordered, provenance

    def order_fragments(self, fragments: list[PlanFragment]) -> list[PlanFragment]:
        """Order by prerequisites first, then by descending composite score."""
        ordered: list[PlanFragment] = []
        remaining = list(fragments)
        resolved_names: set[str] = set()
        while remaining:
            ready = [
                f for f in remaining if all(p in resolved_names for p in f.prerequisites)
            ]
            if not ready:
                ready = remaining  # cycle or unmet prereqs — add by score
            ready.sort(key=lambda f: f.expected_benefit.composite_score(), reverse=True)
            chosen = ready[0]
            ordered.append(chosen)
            resolved_names.add(chosen.strategy_name)
            remaining.remove(chosen)
        return ordered

    def find_conflicts(
        self, fragments: list[PlanFragment]
    ) -> list[tuple[str, str, frozenset[int]]]:
        """Find pairs of fragments with overlapping block, edge, or transition ownership."""
        conflicts = []
        for i, a in enumerate(fragments):
            for b in fragments[i + 1 :]:
                block_overlap = a.ownership.overlap_blocks(b.ownership)
                edge_overlap = a.ownership.overlap_edges(b.ownership)
                trans_overlap = a.ownership.transitions & b.ownership.transitions
                if block_overlap or edge_overlap or trans_overlap:
                    conflicts.append((a.strategy_name, b.strategy_name, block_overlap))
        return conflicts

    def apply_policy(
        self, fragments: list[PlanFragment], total_handlers: int
    ) -> list[PlanFragment]:
        """Apply policy to filter/block strategies."""
        if not self.policy.allow_fallback_families:
            return [f for f in fragments if f.family != FAMILY_FALLBACK]
        direct_handlers = sum(
            f.expected_benefit.handlers_resolved
            for f in fragments
            if f.family != FAMILY_FALLBACK
        )
        if total_handlers > 0:
            coverage = direct_handlers / total_handlers
            if coverage >= self.policy.direct_coverage_threshold:
                return [f for f in fragments if f.family != FAMILY_FALLBACK]
        return fragments

    def _apply_policy_with_provenance(
        self,
        fragments: list[PlanFragment],
        total_handlers: int,
        rows: list[DecisionRecord],
    ) -> list[PlanFragment]:
        """Apply policy gate and record provenance for dropped fallbacks."""
        if not self.policy.allow_fallback_families:
            accepted: list[PlanFragment] = []
            for f in fragments:
                if f.family == FAMILY_FALLBACK:
                    rows.append(self._record(
                        f,
                        phase=DecisionPhase.POLICY_FILTERED,
                        reason_code=DecisionReasonCode.REJECTED_POLICY,
                        reason="fallback families disallowed by policy",
                    ))
                else:
                    accepted.append(f)
            return accepted

        direct_handlers = sum(
            f.expected_benefit.handlers_resolved
            for f in fragments
            if f.family != FAMILY_FALLBACK
        )
        if total_handlers > 0:
            coverage = direct_handlers / total_handlers
            if coverage >= self.policy.direct_coverage_threshold:
                accepted = []
                for f in fragments:
                    if f.family == FAMILY_FALLBACK:
                        rows.append(self._record(
                            f,
                            phase=DecisionPhase.POLICY_FILTERED,
                            reason_code=DecisionReasonCode.REJECTED_POLICY,
                            reason=(
                                f"direct coverage {coverage:.0%} >= "
                                f"{self.policy.direct_coverage_threshold:.0%} threshold"
                            ),
                        ))
                    else:
                        accepted.append(f)
                return accepted
        return fragments

    def _resolve_conflicts_with_provenance(
        self,
        fragments: list[PlanFragment],
        conflicts: list[tuple[str, str, frozenset[int]]],
        rows: list[DecisionRecord],
    ) -> list[PlanFragment]:
        """Greedy independent set with provenance for dropped fragments."""
        scored = sorted(
            fragments,
            key=lambda f: f.expected_benefit.composite_score(),
            reverse=True,
        )
        accepted: list[PlanFragment] = []
        claimed = OwnershipScope(
            blocks=frozenset(),
            edges=frozenset(),
            transitions=frozenset(),
        )
        for frag in scored:
            if frag.ownership.is_disjoint(claimed):
                accepted.append(frag)
                claimed = claimed.union(frag.ownership)
            else:
                overlap_blocks = frag.ownership.blocks & claimed.blocks
                rows.append(self._record(
                    frag,
                    phase=DecisionPhase.CONFLICT_DROPPED,
                    reason_code=DecisionReasonCode.REJECTED_CONFLICT,
                    reason=(
                        f"ownership conflict: {len(overlap_blocks)} shared blocks"
                    ),
                    ownership_blocks=frozenset(frag.ownership.blocks),
                ))
        return accepted

    def _resolve_conflicts(
        self,
        fragments: list[PlanFragment],
        conflicts: list[tuple[str, str, frozenset[int]]],
    ) -> list[PlanFragment]:
        """Greedy independent set: iterate by score, skip conflicting fragments.

        Fragments are sorted by descending composite score.  Each fragment is
        accepted only when its ownership scope is fully disjoint from all
        already-accepted fragments.  This avoids the cascade problem where the
        naive pairwise approach can drop a high-scoring fragment because it
        conflicted with a low-scoring one that was itself later dropped.
        """
        scored = sorted(
            fragments,
            key=lambda f: f.expected_benefit.composite_score(),
            reverse=True,
        )
        accepted: list[PlanFragment] = []
        claimed = OwnershipScope(
            blocks=frozenset(),
            edges=frozenset(),
            transitions=frozenset(),
        )
        for frag in scored:
            if frag.ownership.is_disjoint(claimed):
                accepted.append(frag)
                claimed = claimed.union(frag.ownership)
        return accepted

    @staticmethod
    def _record(
        frag: PlanFragment,
        *,
        phase: DecisionPhase,
        reason_code: DecisionReasonCode,
        reason: str,
        ownership_blocks: frozenset[int] | None = None,
    ) -> DecisionRecord:
        """Build a DecisionRecord from a PlanFragment."""
        return DecisionRecord(
            strategy_name=frag.strategy_name,
            family=frag.family,
            phase=phase,
            reason_code=reason_code,
            reason=reason,
            composite_score=frag.expected_benefit.composite_score(),
            risk_score=frag.risk_score,
            handler_count=frag.expected_benefit.handlers_resolved,
            transition_count=frag.expected_benefit.transitions_resolved,
            ownership_blocks=ownership_blocks or frozenset(frag.ownership.blocks),
            prerequisites=frozenset(frag.prerequisites),
        )
