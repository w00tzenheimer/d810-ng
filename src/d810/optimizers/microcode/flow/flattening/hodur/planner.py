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
    FAMILY_CLEANUP,
    FAMILY_DIRECT,
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


# ---------------------------------------------------------------------------
# Hint signals: normalized recon data for scoring adjustments
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PlannerHintSignals:
    """Normalized signals derived from raw recon artifacts.

    Each field is a 0.0-1.0 float indicating confidence or risk level
    for a specific recon dimension. Used by :func:`compute_hint_adjustment`
    to bias fragment scoring before conflict resolution and ordering.
    """

    transition_confidence: float = 0.0
    return_frontier_risk: float = 0.0
    terminal_return_risk: float = 0.0


def derive_hint_signals(inputs: PlannerInputs | None) -> PlannerHintSignals:
    """Map raw recon artifacts to normalized hint signals.

    Uses simple presence-based heuristics; values can be refined later
    as recon fidelity improves.

    Args:
        inputs: Structured envelope with recon artifacts, or None.

    Returns:
        A :class:`PlannerHintSignals` with all fields populated.
    """
    if inputs is None:
        return PlannerHintSignals()
    return PlannerHintSignals(
        transition_confidence=0.8 if inputs.has_handler_transitions else 0.0,
        return_frontier_risk=0.5 if inputs.has_return_frontier else 0.0,
        terminal_return_risk=0.5 if inputs.terminal_return_audit is not None else 0.0,
    )


@dataclass(frozen=True)
class HintAdjustment:
    """Score adjustment produced by recon hint analysis.

    Attributes:
        score_delta: Additive adjustment to the fragment's composite score.
        reasons: Human-readable reasons for the adjustment.
    """

    score_delta: float = 0.0
    reasons: tuple[str, ...] = ()


def compute_hint_adjustment(
    fragment: PlanFragment, signals: PlannerHintSignals
) -> HintAdjustment:
    """Compute a score adjustment for *fragment* based on recon *signals*.

    This is a pure function with no side effects.

    Args:
        fragment: The plan fragment to evaluate.
        signals: Normalized recon signals.

    Returns:
        A :class:`HintAdjustment` with the cumulative score delta and reasons.
    """
    delta = 0.0
    reasons: list[str] = []

    # Boost direct-family fragments when transition data is confident
    if fragment.family == FAMILY_DIRECT and signals.transition_confidence > 0.5:
        bonus = 2.0 * signals.transition_confidence
        delta += bonus
        reasons.append("transition_report_boost")

    # Penalize all fragments when return frontier risk is elevated
    if signals.return_frontier_risk > 0.3:
        penalty = -1.5 * signals.return_frontier_risk
        delta += penalty
        reasons.append("return_frontier_penalty")

    # Penalize cleanup-family fragments when terminal return risk is elevated
    if fragment.family == FAMILY_CLEANUP and signals.terminal_return_risk > 0.3:
        penalty = -1.0 * signals.terminal_return_risk
        delta += penalty
        reasons.append("terminal_return_penalty")

    return HintAdjustment(score_delta=delta, reasons=tuple(reasons))


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
            else:
                pre_planner_records.append(DecisionRecord(
                    strategy_name=strategy.name,
                    family=strategy.family,
                    phase=DecisionPhase.INAPPLICABLE,
                    reason_code=DecisionReasonCode.REJECTED_EMPTY,
                    reason="applicable but produced no fragment",
                ))

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

        # --- Hint signal scoring (between Gate 2 and Gate 3) ---
        signals = derive_hint_signals(inputs)
        hint_adjustments: dict[str, HintAdjustment] = {}
        effective_scores: dict[str, float] = {}
        for f in risk_passed:
            adj = compute_hint_adjustment(f, signals)
            hint_adjustments[f.strategy_name] = adj
            effective_scores[f.strategy_name] = (
                f.expected_benefit.composite_score() + adj.score_delta
            )

        # --- Gate 3: Policy gate (coverage threshold drops fallbacks) ---
        accepted = self._apply_policy_with_provenance(
            risk_passed, effective_total_handlers, rows,
            hint_adjustments=hint_adjustments,
            effective_scores=effective_scores,
        )

        # --- Gate 4: Conflict resolution (greedy independent set) ---
        conflicts = self.find_conflicts(accepted)
        if conflicts:
            accepted = self._resolve_conflicts_with_provenance(
                accepted, conflicts, rows,
                effective_scores=effective_scores,
                hint_adjustments=hint_adjustments,
            )

        # --- Gate 5: Selection (surviving fragments) ---
        ordered = self.order_fragments(
            accepted, effective_scores=effective_scores,
        )
        for f in ordered:
            adj = hint_adjustments.get(f.strategy_name, HintAdjustment())
            eff = effective_scores.get(
                f.strategy_name, f.expected_benefit.composite_score(),
            )
            rows.append(self._record(
                f,
                phase=DecisionPhase.SELECTED,
                reason_code=DecisionReasonCode.ACCEPTED,
                reason=(
                    f"composite_score={f.expected_benefit.composite_score():.1f}, "
                    f"selected into pipeline"
                ),
                base_score=f.expected_benefit.composite_score(),
                hint_score_delta=adj.score_delta,
                effective_score=eff,
                hint_reasons=adj.reasons,
            ))

        provenance = PipelineProvenance(
            rows=tuple(rows),
            input_summary=input_summary,
        )
        logger.info("Pipeline provenance: %s", provenance.summary())
        return ordered, provenance

    def order_fragments(
        self,
        fragments: list[PlanFragment],
        *,
        effective_scores: dict[str, float] | None = None,
    ) -> list[PlanFragment]:
        """Order by prerequisites first, then by descending effective score.

        Args:
            fragments: Fragments to order.
            effective_scores: Optional mapping of strategy_name to effective score
                (composite + hint delta). Falls back to composite_score() when absent.
        """
        ordered: list[PlanFragment] = []
        remaining = list(fragments)
        resolved_names: set[str] = set()

        def _score(f: PlanFragment) -> float:
            if effective_scores is not None and f.strategy_name in effective_scores:
                return effective_scores[f.strategy_name]
            return f.expected_benefit.composite_score()

        while remaining:
            ready = [
                f for f in remaining if all(p in resolved_names for p in f.prerequisites)
            ]
            if not ready:
                ready = remaining  # cycle or unmet prereqs — add by score
            ready.sort(key=_score, reverse=True)
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
        *,
        hint_adjustments: dict[str, HintAdjustment] | None = None,
        effective_scores: dict[str, float] | None = None,
    ) -> list[PlanFragment]:
        """Apply policy gate and record provenance for dropped fallbacks."""
        ha = hint_adjustments or {}
        es = effective_scores or {}

        def _hint_kwargs(f: PlanFragment) -> dict:
            adj = ha.get(f.strategy_name, HintAdjustment())
            return {
                "base_score": f.expected_benefit.composite_score(),
                "hint_score_delta": adj.score_delta,
                "effective_score": es.get(f.strategy_name, f.expected_benefit.composite_score()),
                "hint_reasons": adj.reasons,
            }

        if not self.policy.allow_fallback_families:
            accepted: list[PlanFragment] = []
            for f in fragments:
                if f.family == FAMILY_FALLBACK:
                    rows.append(self._record(
                        f,
                        phase=DecisionPhase.POLICY_FILTERED,
                        reason_code=DecisionReasonCode.REJECTED_POLICY,
                        reason="fallback families disallowed by policy",
                        **_hint_kwargs(f),
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
                            **_hint_kwargs(f),
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
        *,
        effective_scores: dict[str, float] | None = None,
        hint_adjustments: dict[str, HintAdjustment] | None = None,
    ) -> list[PlanFragment]:
        """Greedy independent set with provenance for dropped fragments."""
        ha = hint_adjustments or {}
        es = effective_scores or {}

        def _score(f: PlanFragment) -> float:
            if f.strategy_name in es:
                return es[f.strategy_name]
            return f.expected_benefit.composite_score()

        scored = sorted(
            fragments,
            key=_score,
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
                adj = ha.get(frag.strategy_name, HintAdjustment())
                rows.append(self._record(
                    frag,
                    phase=DecisionPhase.CONFLICT_DROPPED,
                    reason_code=DecisionReasonCode.REJECTED_CONFLICT,
                    reason=(
                        f"ownership conflict: {len(overlap_blocks)} shared blocks"
                    ),
                    ownership_blocks=frozenset(frag.ownership.blocks),
                    base_score=frag.expected_benefit.composite_score(),
                    hint_score_delta=adj.score_delta,
                    effective_score=_score(frag),
                    hint_reasons=adj.reasons,
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
        base_score: float = 0.0,
        hint_score_delta: float = 0.0,
        effective_score: float = 0.0,
        hint_reasons: tuple[str, ...] = (),
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
            base_score=base_score,
            hint_score_delta=hint_score_delta,
            effective_score=effective_score,
            hint_reasons=hint_reasons,
        )
