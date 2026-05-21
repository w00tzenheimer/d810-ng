"""Cleanup-family engine strategy for the predecessor branch-arm shape.

This strategy owns the ``two_way_predecessor_arm_known`` shape — see
corpus-evidence rationale in ticket d81-4zm8.  It emits the typed
:class:`CloneConditionalAsGotoFromBranchArm` primitive when (and only when)
the dedicated branch-arm planner admits each candidate fix:

* 2-way predecessor with the conditional source on a known arm
  (``pred_arm == 1`` for the explicit conditional branch, ``pred_arm == 0``
  for the implicit fallthrough).
* 2-way conditional source with an unambiguous explicit branch arm.
* Selected target has at most one predecessor in the snapshot.
* Conditional source has no non-tail side effects.

Live mba collection is intentionally a stub today.  The collection function is
wired into the cleanup backend so the integration point is in place; populating
it with a full dispatcher-aware analysis lives behind ticket d81-4zm8.

Until then, callers can seed FlowGraph metadata directly (e.g. from tests
or future strategies) and the :class:`FixPredecessorBranchArmStrategy` will
verify each candidate against the planner before emitting.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from d810.cfg.fix_predecessor_planning import (
    FixPredecessorOutcome,
    plan_fix_predecessor_clone_from_branch_arm,
)
from d810.cfg.flowgraph import FlowGraph
from d810.cfg.graph_modification import (
    CloneConditionalAsGotoFromBranchArm,
    GraphModification,
)
from d810.core.typing import TYPE_CHECKING
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_CLEANUP,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
        AnalysisSnapshot,
    )

FIX_PREDECESSOR_BRANCH_ARM_FIXES_METADATA_KEY = "fix_predecessor_branch_arm_fixes"


@dataclass(frozen=True)
class FixPredecessorBranchArmFix:
    """Validated FixPredecessor branch-arm candidate for one (pred, cond) pair.

    Captures the planner-required context (resolved arm, outcome, side-effect
    awareness) so the strategy can drive the typed primitive without
    re-deriving topology at apply time.
    """

    cond_block: int
    pred_block: int
    target: int
    pred_arm: int
    outcome: FixPredecessorOutcome
    has_body_side_effects: bool = False
    description: str = ""


def serialize_fix_predecessor_branch_arm_fixes(
    fixes: Sequence[FixPredecessorBranchArmFix],
) -> tuple[FixPredecessorBranchArmFix, ...]:
    """Stable canonical ordering for FlowGraph metadata storage."""
    return tuple(
        sorted(
            fixes,
            key=lambda fix: (
                int(fix.cond_block),
                int(fix.pred_block),
                int(fix.target),
                int(fix.pred_arm),
                fix.outcome.value,
            ),
        )
    )


def extract_fix_predecessor_branch_arm_fixes(
    flow_graph: FlowGraph,
) -> tuple[FixPredecessorBranchArmFix, ...]:
    """Pull candidate fixes out of FlowGraph metadata, if any are present."""
    payload = flow_graph.metadata.get(FIX_PREDECESSOR_BRANCH_ARM_FIXES_METADATA_KEY)
    if not payload:
        return ()
    return tuple(payload)


def build_fix_predecessor_branch_arm_modifications(
    fixes: Sequence[FixPredecessorBranchArmFix],
    flow_graph: FlowGraph,
    *,
    side_effect_blocks: frozenset[int] | None = None,
) -> list[CloneConditionalAsGotoFromBranchArm]:
    """Return the subset of fixes the branch-arm planner admits, as primitives.

    Every candidate is re-validated through
    :func:`plan_fix_predecessor_clone_from_branch_arm` against the snapshot
    ``flow_graph``.  Rejections fall back to legacy (the caller does not
    receive a primitive for them), preserving the strict acceptance gate for
    ambiguous or side-effect-bearing records while allowing either proven
    predecessor arm.
    """
    if side_effect_blocks is None:
        side_effect_blocks = frozenset()
    modifications: list[CloneConditionalAsGotoFromBranchArm] = []
    for fix in fixes:
        per_candidate_side_effects = (
            side_effect_blocks | {int(fix.cond_block)}
            if fix.has_body_side_effects
            else side_effect_blocks
        )
        decision = plan_fix_predecessor_clone_from_branch_arm(
            flow_graph,
            pred_serial=int(fix.pred_block),
            conditional_serial=int(fix.cond_block),
            selected_target_serial=int(fix.target),
            outcome=fix.outcome,
            side_effect_blocks=per_candidate_side_effects,
            description=fix.description,
        )
        if not decision.accepted:
            continue
        candidate = decision.candidate
        if candidate is None:
            continue
        modifications.append(candidate.to_graph_modification())
    return modifications


def collect_live_fix_predecessor_branch_arm_fixes(
    mba: object,
    *,
    logger: object | None = None,
    allowed_maturities: Sequence[int] | None = None,
) -> tuple[FixPredecessorBranchArmFix, ...]:
    """Live mba collector — stub today (d81-4zm8 follow-up).

    Wiring this collector to a full live analysis is still deferred.  Until
    that producer lands, the cleanup-family strategy sees zero candidates in
    production and is exercised only by tests that seed FlowGraph metadata
    directly.
    """
    if mba is None:
        return ()
    if allowed_maturities is not None:
        maturity = getattr(mba, "maturity", None)
        if maturity not in set(int(m) for m in allowed_maturities):
            return ()
    if logger is not None and hasattr(logger, "debug"):
        try:
            logger.debug(
                "collect_live_fix_predecessor_branch_arm_fixes is a stub; "
                "live mba candidates remain owned by the legacy FixPredecessor rule"
            )
        except Exception:
            pass
    return ()


def _build_ownership(
    modifications: Sequence[GraphModification],
) -> OwnershipScope:
    blocks: set[int] = set()
    edges: set[tuple[int, int]] = set()
    for mod in modifications:
        if isinstance(mod, CloneConditionalAsGotoFromBranchArm):
            # The clone is owned by source_block; the rewired edge is the
            # explicit branch arm of pred_serial -> source_block.
            blocks.add(int(mod.source_block))
            edges.add((int(mod.pred_serial), int(mod.source_block)))
    return OwnershipScope(
        blocks=frozenset(blocks),
        edges=frozenset(edges),
        transitions=frozenset(),
    )


class FixPredecessorBranchArmStrategy:
    """Engine strategy wrapper for FixPredecessor arm=1 clone-as-goto edits."""

    name = "fix_predecessor_branch_arm"
    family = FAMILY_CLEANUP

    def is_applicable(self, snapshot: "AnalysisSnapshot") -> bool:
        return bool(
            extract_fix_predecessor_branch_arm_fixes(snapshot.flow_graph)
        )

    def plan(self, snapshot: "AnalysisSnapshot") -> PlanFragment | None:
        fixes = extract_fix_predecessor_branch_arm_fixes(snapshot.flow_graph)
        if not fixes:
            return None
        side_effect_serials = _side_effect_serials(snapshot)
        modifications = build_fix_predecessor_branch_arm_modifications(
            fixes,
            snapshot.flow_graph,
            side_effect_blocks=side_effect_serials,
        )
        if not modifications:
            return None
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            ownership=_build_ownership(modifications),
            prerequisites=[],
            expected_benefit=BenefitMetrics(
                handlers_resolved=0,
                transitions_resolved=0,
                blocks_freed=len(modifications),
                conflict_density=0.0,
            ),
            risk_score=0.15,
            metadata={
                FIX_PREDECESSOR_BRANCH_ARM_FIXES_METADATA_KEY: (
                    serialize_fix_predecessor_branch_arm_fixes(fixes)
                ),
                "safeguard_min_required": 1,
            },
            modifications=list(modifications),
        )


def _side_effect_serials(snapshot: "AnalysisSnapshot") -> frozenset[int]:
    """Best-effort recovery of side-effect block serials from the snapshot.

    The cleanup family currently does not surface side-effect membership in
    a stable metadata field.  Returning the empty set here matches the
    branch-arm planner's other call sites in unit tests; once the cleanup
    family carries a side-effect set we will read it from
    ``snapshot.flow_graph.metadata`` here.
    """
    payload = snapshot.flow_graph.metadata.get("side_effect_block_serials")
    if not payload:
        return frozenset()
    try:
        return frozenset(int(serial) for serial in payload)
    except Exception:
        return frozenset()


__all__ = [
    "FIX_PREDECESSOR_BRANCH_ARM_FIXES_METADATA_KEY",
    "FixPredecessorBranchArmFix",
    "FixPredecessorBranchArmStrategy",
    "build_fix_predecessor_branch_arm_modifications",
    "collect_live_fix_predecessor_branch_arm_fixes",
    "extract_fix_predecessor_branch_arm_fixes",
    "serialize_fix_predecessor_branch_arm_fixes",
]
