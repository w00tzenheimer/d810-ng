"""Central planner for Hodur unflattening pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_FALLBACK,
    PlanFragment,
)


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

    def compose_pipeline(
        self, fragments: list[PlanFragment], total_handlers: int
    ) -> list[PlanFragment]:
        """Full pipeline: filter -> policy -> resolve conflicts -> order."""
        filtered = [f for f in fragments if not f.is_empty()]
        filtered = [f for f in filtered if f.risk_score <= self.policy.max_risk_score]
        accepted = self.apply_policy(filtered, total_handlers)
        conflicts = self.find_conflicts(accepted)
        if conflicts:
            accepted = self._resolve_conflicts(accepted, conflicts)
        return self.order_fragments(accepted)

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
        """Find pairs of fragments with overlapping block ownership."""
        conflicts = []
        for i, a in enumerate(fragments):
            for b in fragments[i + 1 :]:
                overlap = a.ownership.overlap_blocks(b.ownership)
                if overlap:
                    conflicts.append((a.strategy_name, b.strategy_name, overlap))
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
            if "fallback" not in f.strategy_name
        )
        if total_handlers > 0:
            coverage = direct_handlers / total_handlers
            if coverage >= self.policy.direct_coverage_threshold:
                return [f for f in fragments if f.family != FAMILY_FALLBACK]
        return fragments

    def _resolve_conflicts(
        self,
        fragments: list[PlanFragment],
        conflicts: list[tuple[str, str, frozenset[int]]],
    ) -> list[PlanFragment]:
        """Resolve ownership conflicts by keeping higher-score fragment."""
        dropped: set[str] = set()
        for name_a, name_b, _overlap in conflicts:
            frag_a = next(f for f in fragments if f.strategy_name == name_a)
            frag_b = next(f for f in fragments if f.strategy_name == name_b)
            loser = (
                name_b
                if frag_a.expected_benefit.composite_score()
                >= frag_b.expected_benefit.composite_score()
                else name_a
            )
            dropped.add(loser)
        return [f for f in fragments if f.strategy_name not in dropped]
