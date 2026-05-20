"""Diagnostic classification of predecessor-repair opportunities.

This module is intentionally read-only. It bucketizes predecessor/conditional
topologies against existing planner shapes so corpus evidence can drive which
typed CFG primitive is worth adding next.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.cfg.fix_predecessor_planning import (
    FixPredecessorCloneAsGotoDecision,
    FixPredecessorCloneAsGotoFromBranchArmDecision,
    FixPredecessorOutcome,
    FixPredecessorRejectReason,
    infer_conditional_target,
    infer_fallthrough_target,
    plan_fix_predecessor_clone_as_goto,
    plan_fix_predecessor_clone_from_branch_arm,
)
from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.core.typing import Optional


class PredecessorTopology(str, Enum):
    """Topology of the predecessor block at the source of a redirect."""

    ONE_WAY = "one_way"
    TWO_WAY = "two_way"
    UNKNOWN = "unknown"


class FixPredecessorBucket(str, Enum):
    """Classification bucket for a single FixPredecessor repair opportunity.

    The buckets are mutually exclusive — each classification reports exactly
    one.  See :func:`classify_predecessor_modification` for assignment rules.
    """

    ALREADY_SUPPORTED_ONE_WAY = "already_supported_one_way"
    TWO_WAY_PREDECESSOR_ARM_KNOWN = "two_way_predecessor_arm_known"
    TWO_WAY_PREDECESSOR_ARM_AMBIGUOUS = "two_way_predecessor_arm_ambiguous"
    SHARED_SUCCESSOR = "shared_successor"
    MULTI_PRED_TARGET = "multi_pred_target"
    MULTI_SUCC_PREDECESSOR_UNSUPPORTED = "multi_succ_predecessor_unsupported"
    COPIED_SIDE_EFFECTS_REQUIRED = "copied_side_effects_required"
    UNSUPPORTED_SHAPE = "unsupported_shape"


@dataclass(frozen=True)
class FixPredecessorClassification:
    """Read-only metadata describing one queued predecessor repair opportunity.

    Fields mirror the diagnostic schema required by the next-slice plan:

    * ``source_block`` / ``selected_predecessor`` — the predecessor block
      whose successor would be rewritten.
    * ``target_conditional_block`` — the 2-way conditional block being
      patched.
    * ``selected_target`` — the arm (taken or fallthrough) the legacy rule
      believes the predecessor always reaches.
    * ``predecessor_topology`` / ``predecessor_arm`` — shape of the
      predecessor edge that points to the conditional.  Arm convention:
      ``1`` = explicit branch target arm of the predecessor's tail, ``0`` =
      fallthrough arm.  ``None`` when the topology cannot resolve a unique
      arm.
    * ``conditional_target_*`` counts — succ/pred counts of the conditional
      block.
    * ``selected_target_predecessor_count`` — pred count of the redirected
      target (useful for future ``multi_pred_target`` primitives).
    * ``clone_required`` / ``direct_redirect_equivalent`` — orthogonal
      structural axes describing whether the cond block must be cloned or
      whether a direct redirect would preserve semantics.
    * ``conditional_has_body_side_effects`` — whether the cond block
      contains non-tail side effects (calls, stores).
    * ``matches_clone_conditional_as_goto`` — ``True`` iff the existing
      one-way ``CloneConditionalAsGoto`` planner admits this shape.
    * ``matches_clone_conditional_as_goto_from_branch_arm`` — ``True`` iff
      the sibling 2-way branch-arm planner admits this shape.  Mutually
      exclusive with the one-way flag because the two planners require
      disjoint predecessor topologies.
    * ``planner_rejection`` — the rejection reason from the structural
      planner for the predecessor shape (one-way planner for one-way preds,
      branch-arm planner for two-way preds).  ``None`` when admitted by
      whichever planner is appropriate.
    * ``bucket`` — the assigned classification bucket.
    """

    source_block: int
    target_conditional_block: int
    selected_predecessor: int
    selected_target: int
    outcome: FixPredecessorOutcome
    predecessor_topology: PredecessorTopology
    predecessor_arm: Optional[int]
    conditional_target_successor_count: int
    conditional_target_predecessor_count: int
    selected_target_predecessor_count: int
    clone_required: bool
    direct_redirect_equivalent: bool
    conditional_has_body_side_effects: bool
    matches_clone_conditional_as_goto: bool
    matches_clone_conditional_as_goto_from_branch_arm: bool
    planner_rejection: Optional[FixPredecessorRejectReason]
    bucket: FixPredecessorBucket
    description: str = ""


def _infer_predecessor_topology(
    pred_block: BlockSnapshot | None,
) -> PredecessorTopology:
    if pred_block is None:
        return PredecessorTopology.UNKNOWN
    if pred_block.nsucc == 1:
        return PredecessorTopology.ONE_WAY
    if pred_block.nsucc == 2:
        return PredecessorTopology.TWO_WAY
    return PredecessorTopology.UNKNOWN


def _resolve_predecessor_arm(
    pred_block: BlockSnapshot | None,
    target_serial: int,
) -> Optional[int]:
    """Return ``0`` or ``1`` for the 2-way predecessor arm that targets ``target_serial``.

    Returns ``None`` when:

    * ``pred_block`` is missing or not a 2-way block, or
    * ``target_serial`` is not among the predecessor's successors, or
    * the explicit branch arm cannot be inferred from the tail.
    """
    if pred_block is None or pred_block.nsucc != 2:
        return None
    if target_serial not in pred_block.succs:
        return None
    explicit_arm = infer_conditional_target(pred_block)
    if explicit_arm is None:
        return None
    fallthrough = infer_fallthrough_target(
        pred_block, conditional_target=explicit_arm
    )
    if fallthrough is None:
        return None
    if target_serial == explicit_arm:
        return 1
    if target_serial == fallthrough:
        return 0
    return None


def _select_bucket(
    *,
    decision: FixPredecessorCloneAsGotoDecision,
    predecessor_topology: PredecessorTopology,
    predecessor_arm: Optional[int],
    cond_block: BlockSnapshot | None,
    cond_serial: int,
    pred_block: BlockSnapshot | None,
    target_npred: int,
    conditional_has_body_side_effects: bool,
) -> FixPredecessorBucket:
    """First-match-wins bucket assignment.

    Order of precedence:

    1. Planner admits the shape -> ``already_supported_one_way``.
    2. Predecessor topology issues:

       * ``nsucc > 2`` or unknown shape -> ``multi_succ_predecessor_unsupported``
         / ``unsupported_shape``.
       * ``nsucc == 2`` but cond not among its succs -> ``unsupported_shape``.
       * ``nsucc == 2`` and cond in succs:

         * arm resolvable -> ``two_way_predecessor_arm_known``.
         * arm ambiguous  -> ``two_way_predecessor_arm_ambiguous``.

    3. One-way predecessor — diagnose by conditional/target topology:

       * Degenerate cond (both arms point at the same target)
         -> ``shared_successor``.
       * Non-tail side effects in cond -> ``copied_side_effects_required``.
       * Redirected target has multiple predecessors -> ``multi_pred_target``.
       * Otherwise -> ``unsupported_shape``.
    """
    if decision.accepted:
        return FixPredecessorBucket.ALREADY_SUPPORTED_ONE_WAY

    if predecessor_topology == PredecessorTopology.UNKNOWN:
        if pred_block is not None and pred_block.nsucc > 2:
            return FixPredecessorBucket.MULTI_SUCC_PREDECESSOR_UNSUPPORTED
        return FixPredecessorBucket.UNSUPPORTED_SHAPE

    if predecessor_topology == PredecessorTopology.TWO_WAY:
        if pred_block is None or cond_serial not in pred_block.succs:
            return FixPredecessorBucket.UNSUPPORTED_SHAPE
        if predecessor_arm is not None:
            return FixPredecessorBucket.TWO_WAY_PREDECESSOR_ARM_KNOWN
        return FixPredecessorBucket.TWO_WAY_PREDECESSOR_ARM_AMBIGUOUS

    # One-way predecessor — planner already rejected it.
    if (
        cond_block is not None
        and cond_block.nsucc == 2
        and len(set(cond_block.succs)) == 1
    ):
        return FixPredecessorBucket.SHARED_SUCCESSOR

    if conditional_has_body_side_effects:
        return FixPredecessorBucket.COPIED_SIDE_EFFECTS_REQUIRED

    if target_npred > 1:
        return FixPredecessorBucket.MULTI_PRED_TARGET

    return FixPredecessorBucket.UNSUPPORTED_SHAPE


def classify_predecessor_modification(
    cfg: FlowGraph,
    *,
    pred_serial: int,
    conditional_serial: int,
    selected_target_serial: int,
    outcome: FixPredecessorOutcome,
    side_effect_blocks: frozenset[int] = frozenset(),
    description: str = "",
) -> FixPredecessorClassification:
    """Classify a single queued FixPredecessor modification.

    The function is pure: no graph state is mutated and no IDA APIs are
    invoked.  It runs the existing :func:`plan_fix_predecessor_clone_as_goto`
    planner under the hood, then assigns a structural bucket regardless of
    whether the planner accepted the candidate.
    """
    pred_block = cfg.get_block(pred_serial)
    conditional_block = cfg.get_block(conditional_serial)
    selected_target_block = cfg.get_block(selected_target_serial)

    decision = plan_fix_predecessor_clone_as_goto(
        cfg,
        pred_serial=pred_serial,
        conditional_serial=conditional_serial,
        selected_target_serial=selected_target_serial,
        outcome=outcome,
        description=description,
    )
    branch_arm_decision = plan_fix_predecessor_clone_from_branch_arm(
        cfg,
        pred_serial=pred_serial,
        conditional_serial=conditional_serial,
        selected_target_serial=selected_target_serial,
        outcome=outcome,
        side_effect_blocks=side_effect_blocks,
        description=description,
    )

    predecessor_topology = _infer_predecessor_topology(pred_block)
    predecessor_arm = _resolve_predecessor_arm(pred_block, conditional_serial)

    cond_nsucc = conditional_block.nsucc if conditional_block is not None else 0
    cond_npred = conditional_block.npred if conditional_block is not None else 0
    target_npred = (
        selected_target_block.npred if selected_target_block is not None else 0
    )

    clone_required = cond_npred > 1
    direct_redirect_equivalent = (
        cond_npred == 1
        and predecessor_topology == PredecessorTopology.ONE_WAY
    )
    conditional_has_body_side_effects = conditional_serial in side_effect_blocks

    # ``planner_rejection`` reports the structural planner that's
    # appropriate for the predecessor topology — the one-way planner for
    # one-way preds and the 2-way branch-arm planner for 2-way preds.  This
    # keeps the field useful as a "why was this not admitted" signal
    # regardless of which sibling primitive is the natural fit.
    if predecessor_topology == PredecessorTopology.TWO_WAY:
        active_decision: FixPredecessorCloneAsGotoDecision | FixPredecessorCloneAsGotoFromBranchArmDecision = (
            branch_arm_decision
        )
    else:
        active_decision = decision
    planner_rejection: Optional[FixPredecessorRejectReason] = (
        None if active_decision.accepted else active_decision.rejection_reason
    )

    bucket = _select_bucket(
        decision=decision,
        predecessor_topology=predecessor_topology,
        predecessor_arm=predecessor_arm,
        cond_block=conditional_block,
        cond_serial=conditional_serial,
        pred_block=pred_block,
        target_npred=target_npred,
        conditional_has_body_side_effects=conditional_has_body_side_effects,
    )

    return FixPredecessorClassification(
        source_block=pred_serial,
        target_conditional_block=conditional_serial,
        selected_predecessor=pred_serial,
        selected_target=selected_target_serial,
        outcome=outcome,
        predecessor_topology=predecessor_topology,
        predecessor_arm=predecessor_arm,
        conditional_target_successor_count=cond_nsucc,
        conditional_target_predecessor_count=cond_npred,
        selected_target_predecessor_count=target_npred,
        clone_required=clone_required,
        direct_redirect_equivalent=direct_redirect_equivalent,
        conditional_has_body_side_effects=conditional_has_body_side_effects,
        matches_clone_conditional_as_goto=decision.accepted,
        matches_clone_conditional_as_goto_from_branch_arm=branch_arm_decision.accepted,
        planner_rejection=planner_rejection,
        bucket=bucket,
        description=description,
    )


def summarize_classifications(
    classifications: tuple[FixPredecessorClassification, ...]
    | list[FixPredecessorClassification],
) -> dict[FixPredecessorBucket, int]:
    """Return a deterministic ``bucket -> count`` map across all buckets.

    Buckets with zero occurrences are still present in the result so that
    corpus reports show a stable column ordering.
    """
    counts: dict[FixPredecessorBucket, int] = {b: 0 for b in FixPredecessorBucket}
    for classification in classifications:
        counts[classification.bucket] = counts[classification.bucket] + 1
    return counts


def format_classification_report(
    classifications: tuple[FixPredecessorClassification, ...]
    | list[FixPredecessorClassification],
    *,
    examples_per_bucket: int = 3,
    title: str = "FixPredecessor classification report",
) -> str:
    """Render a human-readable corpus inventory grouped by bucket.

    The report lists every bucket with its observed count and up to
    ``examples_per_bucket`` concrete (pred, cond, target) examples per bucket.
    Buckets with zero observations are emitted as well, so the output is
    stable across runs and easy to diff.
    """
    counts = summarize_classifications(classifications)
    by_bucket: dict[FixPredecessorBucket, list[FixPredecessorClassification]] = {
        b: [] for b in FixPredecessorBucket
    }
    for classification in classifications:
        by_bucket[classification.bucket].append(classification)

    lines: list[str] = [
        f"{title} ({len(classifications)} record(s))",
    ]
    for bucket in FixPredecessorBucket:
        lines.append(f"  [{bucket.value}] count={counts[bucket]}")
        for example in by_bucket[bucket][:examples_per_bucket]:
            arm = (
                "none"
                if example.predecessor_arm is None
                else str(example.predecessor_arm)
            )
            rejection = (
                example.planner_rejection.value
                if example.planner_rejection is not None
                else "accepted"
            )
            lines.append(
                "    "
                f"pred={example.selected_predecessor} "
                f"cond={example.target_conditional_block} "
                f"target={example.selected_target} "
                f"outcome={example.outcome.value} "
                f"topology={example.predecessor_topology.value} "
                f"arm={arm} "
                f"cond_succs={example.conditional_target_successor_count} "
                f"cond_preds={example.conditional_target_predecessor_count} "
                f"target_preds={example.selected_target_predecessor_count} "
                f"clone_required={example.clone_required} "
                f"direct_eq={example.direct_redirect_equivalent} "
                f"side_effects={example.conditional_has_body_side_effects} "
                f"matches_one_way={example.matches_clone_conditional_as_goto} "
                f"matches_arm={example.matches_clone_conditional_as_goto_from_branch_arm} "
                f"planner={rejection}"
            )
    return "\n".join(lines)


__all__ = [
    "FixPredecessorBucket",
    "FixPredecessorClassification",
    "PredecessorTopology",
    "classify_predecessor_modification",
    "format_classification_report",
    "summarize_classifications",
]
