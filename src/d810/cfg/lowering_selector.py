"""Generic lowering-shape selection for shared feeder transitions.

This module lives in :mod:`d810.cfg` because it chooses between *virtual*
graph-edit shapes before any Hex-Rays lowering occurs.

The current first slice handles the shared 1-way feeder case:

- block-scope goto redirect
- predecessor-scoped clone

The selector is intentionally generic and consumes only projected CFG facts
plus corridor ownership hints.  Callers in Hodur provide those facts from
``d810.recon`` outputs.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Protocol
from d810.cfg.lowering_scope import derive_edge_predecessor, requires_pred_scoped_lowering


class SharedFeederLoweringKind:
    """Labels for shared-feeder lowering decisions."""

    BLOCK_GOTO = "block_goto"
    PRED_EDGE_PEEL = "pred_edge_peel"
    PRED_SCOPED_CLONE = "pred_scoped_clone"


@dataclass(frozen=True, slots=True)
class SharedFeederLoweringDecision:
    """Decision returned by :func:`select_shared_feeder_lowering`."""

    kind: str
    via_pred: int | None = None
    reason: str = ""


@dataclass(frozen=True, slots=True)
class SharedGroupCandidate:
    """One predecessor-owned target inside a shared-group rewrite."""

    via_pred: int
    target_entry: int


@dataclass(frozen=True, slots=True)
class SharedGroupContext:
    """Structured planning input for shared-group duplicate-and-redirect."""

    shared_block: int
    old_target: int
    shared_preds: tuple[int, ...]
    candidates: tuple[SharedGroupCandidate, ...]


@dataclass(frozen=True, slots=True)
class SharedGroupDuplicationPlan:
    """Planned duplicate-and-redirect layout for a shared group."""

    accepted: bool
    per_pred_targets: tuple[tuple[int, int], ...] = ()
    rejection_reason: str = ""


@dataclass(frozen=True, slots=True)
class ResidualBranchAnchorContext:
    """Structured planning input for residual branch-anchor handoff rewrites."""

    is_conditional_branch_source: bool
    branch_source: int | None
    source_block: int
    via_pred: int
    prefix_target: int
    branch_succs: tuple[int, ...]
    old_target: int | None
    ordered_path: tuple[int, ...]
    dispatcher_serial: int
    bst_node_blocks: frozenset[int]
    target_reaches_branch: bool


@dataclass(frozen=True, slots=True)
class ResidualBranchAnchorPlan:
    """Planner result for a residual branch-anchor handoff."""

    accepted: bool
    branch_source: int | None = None
    old_target: int | None = None
    rejection_reason: str = ""


@dataclass(frozen=True, slots=True)
class SharedFeederLoweringCandidate:
    """One possible lowering shape for a shared-feeder redirect."""

    kind: str
    via_pred: int | None = None
    reason: str = ""


@dataclass(frozen=True, slots=True)
class SharedFeederCandidateScore:
    """Score attached to a lowering candidate.

    Lower scores are preferred. ``accepted=False`` vetoes the candidate.
    """

    accepted: bool
    score: int
    reason: str = ""


class SharedFeederCandidateScorerProtocol(Protocol):
    """Optional scorer hook implemented by higher-level validation layers."""

    def score(
        self,
        context: "SharedFeederContext",
        candidate: SharedFeederLoweringCandidate,
    ) -> SharedFeederCandidateScore:
        """Return an additive score or veto for ``candidate``."""


@dataclass(frozen=True, slots=True)
class PredecessorPeelContext:
    """Projected CFG facts needed to evaluate predecessor-edge peeling."""

    via_pred: int | None
    via_pred_succs: tuple[int, ...]
    source_block: int
    target_entry: int
    dispatcher_serial: int
    bst_node_blocks: frozenset[int]
    target_reaches_pred: bool


@dataclass(frozen=True, slots=True)
class SharedFeederContext:
    """Structured recon -> cfg handoff for shared-feeder lowering selection."""

    source_serial: int
    source_pred_count: int
    ordered_path: tuple[int, ...]
    via_pred_succs: tuple[int, ...]
    target_entry: int
    dispatcher_serial: int
    bst_node_blocks: frozenset[int]
    target_reaches_pred: bool

    @property
    def via_pred(self) -> int | None:
        if not self.ordered_path:
            return None
        try:
            return derive_edge_predecessor(self.ordered_path)
        except ValueError:
            return None

    @property
    def peel_context(self) -> PredecessorPeelContext:
        return PredecessorPeelContext(
            via_pred=self.via_pred,
            via_pred_succs=self.via_pred_succs,
            source_block=self.source_serial,
            target_entry=self.target_entry,
            dispatcher_serial=self.dispatcher_serial,
            bst_node_blocks=self.bst_node_blocks,
            target_reaches_pred=self.target_reaches_pred,
        )


def target_reaches_source_ignoring_blocks(
    flow_graph: object,
    *,
    target_entry: int,
    source_block: int,
    ignored_blocks: set[int],
    limit: int = 256,
) -> bool:
    """Return True if ``target_entry`` can reach ``source_block``.

    Used to reject lowering shapes that would immediately introduce a cycle
    when redirecting to ``target_entry``.
    """
    if target_entry == source_block:
        return True
    worklist: list[int] = [target_entry]
    seen: set[int] = set()
    while worklist and len(seen) < limit:
        current = worklist.pop()
        if current in seen:
            continue
        seen.add(current)
        if current == source_block:
            return True
        try:
            succs = tuple(flow_graph.successors(current))
        except Exception:
            block = flow_graph.get_block(current)
            succs = tuple(getattr(block, "succs", ())) if block is not None else ()
        for succ in succs:
            succ = int(succ)
            if succ in ignored_blocks or succ in seen:
                continue
            worklist.append(succ)
    return False


def can_peel_predecessor_edge(context: PredecessorPeelContext) -> bool:
    """Return True when a predecessor edge can be peeled instead of cloning."""
    if context.via_pred is None:
        return False
    if len(context.via_pred_succs) != 2:
        return False
    if context.source_block not in context.via_pred_succs:
        return False
    if context.target_entry in {
        context.dispatcher_serial,
        context.source_block,
        context.via_pred,
    }:
        return False
    if context.target_entry in context.bst_node_blocks:
        return False
    other_succs = {
        int(succ)
        for succ in context.via_pred_succs
        if int(succ) != context.source_block
    }
    if context.target_entry in other_succs:
        return False
    if context.target_reaches_pred:
        return False
    return True


def enumerate_shared_feeder_candidates(
    context: SharedFeederContext,
) -> tuple[SharedFeederLoweringCandidate, ...]:
    """Enumerate legal lowering candidates for a shared-feeder rewrite."""
    if not requires_pred_scoped_lowering(
        context.source_serial,
        context.source_pred_count,
        context.ordered_path,
    ):
        return (
            SharedFeederLoweringCandidate(
                kind=SharedFeederLoweringKind.BLOCK_GOTO,
                reason="source_not_shared",
            ),
        )

    candidates: list[SharedFeederLoweringCandidate] = []
    if can_peel_predecessor_edge(context.peel_context):
        candidates.append(
            SharedFeederLoweringCandidate(
                kind=SharedFeederLoweringKind.PRED_EDGE_PEEL,
                via_pred=context.via_pred,
                reason="shared_source_peel_available",
            )
        )
    candidates.append(
        SharedFeederLoweringCandidate(
            kind=SharedFeederLoweringKind.PRED_SCOPED_CLONE,
            via_pred=context.via_pred,
            reason="shared_source_requires_clone",
        )
    )
    return tuple(candidates)


def plan_shared_group_duplication(
    context: SharedGroupContext,
) -> SharedGroupDuplicationPlan:
    """Plan the duplicate-and-redirect layout for a shared group.

    This is a pure cfg-layer rewrite planner. Callers are responsible for
    translating candidate-specific metadata and logging.
    """
    ordered_candidates = tuple(sorted(context.candidates, key=lambda c: c.via_pred))
    old_target = int(context.old_target)
    if all(int(candidate.target_entry) == old_target for candidate in ordered_candidates):
        return SharedGroupDuplicationPlan(
            accepted=False,
            rejection_reason="noop_or_missing_old_target",
        )

    candidate_preds = {int(candidate.via_pred) for candidate in ordered_candidates}
    non_candidate_preds = [
        int(pred) for pred in context.shared_preds if int(pred) not in candidate_preds
    ]

    per_pred_targets: tuple[tuple[int, int], ...]
    if len(ordered_candidates) == 1:
        candidate = ordered_candidates[0]
        if int(candidate.target_entry) == old_target:
            return SharedGroupDuplicationPlan(
                accepted=False,
                rejection_reason="noop_or_missing_old_target",
            )
        if not non_candidate_preds:
            return SharedGroupDuplicationPlan(
                accepted=False,
                rejection_reason="missing_keep_pred",
            )
        per_pred_targets = (
            (int(non_candidate_preds[0]), old_target),
            (int(candidate.via_pred), int(candidate.target_entry)),
        )
        return SharedGroupDuplicationPlan(
            accepted=True,
            per_pred_targets=per_pred_targets,
        )

    if non_candidate_preds:
        return SharedGroupDuplicationPlan(
            accepted=False,
            rejection_reason="shared_group_requires_multi_clone",
        )

    if len(ordered_candidates) == 2:
        keep_indices = [
            index
            for index, candidate in enumerate(ordered_candidates)
            if int(candidate.target_entry) == old_target
        ]
        if len(keep_indices) == 1:
            keep_index = keep_indices[0]
            first = ordered_candidates[keep_index]
            second = ordered_candidates[1 - keep_index]
        else:
            first, second = ordered_candidates
        per_pred_targets = (
            (int(first.via_pred), int(first.target_entry)),
            (int(second.via_pred), int(second.target_entry)),
        )
        return SharedGroupDuplicationPlan(
            accepted=True,
            per_pred_targets=per_pred_targets,
        )

    return SharedGroupDuplicationPlan(
        accepted=False,
        rejection_reason="shared_group_too_wide",
    )


def plan_residual_branch_anchor_handoff(
    context: ResidualBranchAnchorContext,
) -> ResidualBranchAnchorPlan:
    """Plan a residual branch-anchor handoff without touching live MBA state."""
    if (
        not context.is_conditional_branch_source
        or context.branch_source is None
        or context.branch_source in {context.source_block, context.via_pred}
    ):
        return ResidualBranchAnchorPlan(
            accepted=False,
            rejection_reason="anchor_not_conditional_branch",
        )

    if len(context.branch_succs) != 2:
        return ResidualBranchAnchorPlan(
            accepted=False,
            rejection_reason="branch_not_two_way",
        )

    if (
        context.old_target is None
        or context.old_target == context.prefix_target
        or context.old_target not in context.ordered_path
        or context.prefix_target in {context.dispatcher_serial, context.branch_source}
        or context.prefix_target in context.bst_node_blocks
    ):
        return ResidualBranchAnchorPlan(
            accepted=False,
            rejection_reason="invalid_branch_target",
        )

    other_succs = {
        int(succ) for succ in context.branch_succs if int(succ) != context.old_target
    }
    if context.prefix_target in other_succs:
        return ResidualBranchAnchorPlan(
            accepted=False,
            rejection_reason="other_arm_collision",
        )

    if context.target_reaches_branch:
        return ResidualBranchAnchorPlan(
            accepted=False,
            rejection_reason="cycle_risk",
        )

    return ResidualBranchAnchorPlan(
        accepted=True,
        branch_source=context.branch_source,
        old_target=context.old_target,
    )


def _default_candidate_score(
    candidate: SharedFeederLoweringCandidate,
) -> SharedFeederCandidateScore:
    """Behavior-preserving default policy for shared-feeder lowering.

    This refactor branch keeps predecessor-edge peel disabled by default even
    when it is legal. That preserves the trusted ``sub_7FFD`` output while the
    selector grows evaluator-backed proof hooks in later commits.
    """
    if candidate.kind == SharedFeederLoweringKind.BLOCK_GOTO:
        return SharedFeederCandidateScore(accepted=True, score=0, reason="direct")
    if candidate.kind == SharedFeederLoweringKind.PRED_SCOPED_CLONE:
        return SharedFeederCandidateScore(accepted=True, score=100, reason="clone")
    if candidate.kind == SharedFeederLoweringKind.PRED_EDGE_PEEL:
        return SharedFeederCandidateScore(
            accepted=True,
            score=1000,
            reason="policy_disabled_pending_evaluator",
        )
    return SharedFeederCandidateScore(
        accepted=False,
        score=10_000,
        reason="unknown_candidate_kind",
    )


def select_shared_feeder_lowering(
    context: SharedFeederContext,
    *,
    scorer: SharedFeederCandidateScorerProtocol | None = None,
) -> SharedFeederLoweringDecision:
    """Choose a lowering shape for a shared 1-way feeder redirect.

    Current behavior-preserving order:

    1. block-scope goto redirect when pred-scoping is unnecessary
    2. predecessor-scoped clone as the conservative fallback

    A predecessor-edge peel helper is extracted in this module, but the
    selector does not choose it by default on the refactor branch. That keeps
    shared-feeder lowering observationally aligned with the pre-extraction
    Hodur behavior for ``sub_7FFD`` while preserving the extracted seam for a
    future, separately-validated peel policy.
    """
    best_candidate: SharedFeederLoweringCandidate | None = None
    best_score: tuple[int, str] | None = None
    for candidate in enumerate_shared_feeder_candidates(context):
        base_score = _default_candidate_score(candidate)
        if not base_score.accepted:
            continue
        total_score = base_score.score
        final_reason = candidate.reason
        if scorer is not None:
            extra_score = scorer.score(context, candidate)
            if not extra_score.accepted:
                continue
            total_score += extra_score.score
            if extra_score.reason:
                final_reason = extra_score.reason
        rank = (total_score, candidate.kind)
        if best_score is None or rank < best_score:
            best_score = rank
            best_candidate = SharedFeederLoweringCandidate(
                kind=candidate.kind,
                via_pred=candidate.via_pred,
                reason=final_reason,
            )

    if best_candidate is None:
        return SharedFeederLoweringDecision(
            kind=SharedFeederLoweringKind.PRED_SCOPED_CLONE,
            via_pred=context.via_pred,
            reason="shared_source_requires_clone",
        )

    return SharedFeederLoweringDecision(
        kind=best_candidate.kind,
        via_pred=best_candidate.via_pred,
        reason=best_candidate.reason,
    )


__all__ = [
    "PredecessorPeelContext",
    "SharedFeederCandidateScore",
    "SharedFeederCandidateScorerProtocol",
    "SharedFeederLoweringCandidate",
    "SharedFeederContext",
    "SharedFeederLoweringDecision",
    "SharedFeederLoweringKind",
    "SharedGroupCandidate",
    "SharedGroupContext",
    "SharedGroupDuplicationPlan",
    "ResidualBranchAnchorContext",
    "ResidualBranchAnchorPlan",
    "can_peel_predecessor_edge",
    "enumerate_shared_feeder_candidates",
    "plan_shared_group_duplication",
    "plan_residual_branch_anchor_handoff",
    "select_shared_feeder_lowering",
    "target_reaches_source_ignoring_blocks",
]
