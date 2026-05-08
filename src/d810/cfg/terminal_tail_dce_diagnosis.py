"""Per-byte DCE cause diagnosis for snap17 → snap18 (read-only).

For each byte_emit[k] lost between the last D810-controlled snapshot
(typically ``post_bundle_stabilize``, snap 17 for sub_7FFD) and the
GLBOPT1 post_d810 capture (snap 18), classify why IDA's
``mba_t.optimize_global()`` finalization removed the block.

Strictly read-only. Pure-algorithm consumer of pre-extracted snapshot
evidence; the CLI assembles inputs from the diag DB.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.core.logging import getLogger
from d810.core.typing import Iterable

logger = getLogger(__name__)


class DceCause(str, Enum):
    """Classification of why a byte_emit block disappears at IDA finalization."""

    UNREACHABLE_AT_SNAP17 = "unreachable_at_snap17"
    REDIRECTED_AROUND_BEFORE_FINALIZATION = "redirected_around_before_finalization"
    MERGED_INTO_SHARED_FOLDED_BODY = "merged_into_shared_folded_body"
    DCE_DEAD_WRITE = "dce_dead_write"
    FOLDED_INTO_SURVIVING_BYTE_EMIT = "folded_into_surviving_byte_emit"
    IDA_NATIVE_UNKNOWN = "ida_native_unknown"
    SURVIVES = "survives"
    COLLECTOR_GAP = "collector_gap"


class RecommendedAction(str, Enum):
    """Highest-level next-step action implied by the DCE cause."""

    PRESERVATION = "preservation"
    RECONSTRUCTION = "reconstruction"
    STRUCTURER_SHAPING = "structurer_shaping"
    COLLECTOR_FIX = "collector_fix"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class ByteEmitSnapshotEvidence:
    """Per-byte snapshot evidence — input to DceCause classifier."""

    byte_index: int
    snap17_block_serial: int | None
    snap17_block_ea: str | None
    snap17_npred: int | None
    snap17_nsucc: int | None
    snap17_in_scc: bool
    snap17_in_giant_scc: bool
    snap17_unique_pred: bool
    snap17_shares_succ_with_other_byte: bool
    snap17_dominated_by_prior_return: bool
    snap17_memory_write_appears_dead: bool
    snap18_block_present: bool
    snap18_fact_detected: bool
    snap18_surviving_byte_absorbs: bool


@dataclass(frozen=True, slots=True)
class ByteEmitDceClassification:
    """One byte's classified cause + recommended action."""

    byte_index: int
    cause: DceCause
    recommended_action: RecommendedAction
    rationale: str
    evidence: ByteEmitSnapshotEvidence


def classify_byte_emit_dce(
    evidence: ByteEmitSnapshotEvidence,
) -> ByteEmitDceClassification:
    """Pure-algorithm classification of a single byte_emit's DCE cause."""
    e = evidence

    # Block survives → fact-detection is the only remaining question.
    if e.snap18_block_present:
        if e.snap18_fact_detected:
            return ByteEmitDceClassification(
                byte_index=e.byte_index,
                cause=DceCause.SURVIVES,
                recommended_action=RecommendedAction.NONE,
                rationale=(
                    "Block present at snap17 and snap18; byte_emit fact "
                    "fires at snap18. No work needed."
                ),
                evidence=e,
            )
        return ByteEmitDceClassification(
            byte_index=e.byte_index,
            cause=DceCause.COLLECTOR_GAP,
            recommended_action=RecommendedAction.COLLECTOR_FIX,
            rationale=(
                "Block survives snap17→snap18 but the byte_emit FACT "
                "no longer matches. Collector heuristic should be "
                "tightened to recognize the post-D810 IR shape."
            ),
            evidence=e,
        )

    # Block gone — work through the snap17 evidence in priority order.
    if e.snap17_block_serial is None:
        return ByteEmitDceClassification(
            byte_index=e.byte_index,
            cause=DceCause.IDA_NATIVE_UNKNOWN,
            recommended_action=RecommendedAction.RECONSTRUCTION,
            rationale="No snap17 evidence; cannot classify further.",
            evidence=e,
        )

    if e.snap18_surviving_byte_absorbs:
        return ByteEmitDceClassification(
            byte_index=e.byte_index,
            cause=DceCause.FOLDED_INTO_SURVIVING_BYTE_EMIT,
            recommended_action=RecommendedAction.STRUCTURER_SHAPING,
            rationale=(
                "Another byte_emit survives at snap18 holding the "
                "collapsed body. IDA fused this byte's logic into the "
                "surviving emitter; structurer rendering reflects the "
                "fusion."
            ),
            evidence=e,
        )

    if e.snap17_npred is not None and e.snap17_npred == 0:
        return ByteEmitDceClassification(
            byte_index=e.byte_index,
            cause=DceCause.UNREACHABLE_AT_SNAP17,
            recommended_action=RecommendedAction.PRESERVATION,
            rationale=(
                "Block already had 0 predecessors at snap17. Some D810 "
                "redirect severed its only entry; IDA correctly DCE'd."
            ),
            evidence=e,
        )

    if e.snap17_unique_pred and e.snap17_dominated_by_prior_return:
        return ByteEmitDceClassification(
            byte_index=e.byte_index,
            cause=DceCause.REDIRECTED_AROUND_BEFORE_FINALIZATION,
            recommended_action=RecommendedAction.PRESERVATION,
            rationale=(
                "Unique pred dominated by an earlier return; IDA proves "
                "this block unreachable post-redirect and folds it."
            ),
            evidence=e,
        )

    if e.snap17_shares_succ_with_other_byte:
        return ByteEmitDceClassification(
            byte_index=e.byte_index,
            cause=DceCause.MERGED_INTO_SHARED_FOLDED_BODY,
            recommended_action=RecommendedAction.STRUCTURER_SHAPING,
            rationale=(
                "Block shares a successor with another byte_emit. IDA "
                "merges them via tail-equivalence; the merged body "
                "absorbs this emit."
            ),
            evidence=e,
        )

    if e.snap17_memory_write_appears_dead:
        return ByteEmitDceClassification(
            byte_index=e.byte_index,
            cause=DceCause.DCE_DEAD_WRITE,
            recommended_action=RecommendedAction.PRESERVATION,
            rationale=(
                "Memory store target is overwritten by a downstream "
                "block before any read. IDA's dataflow optimizer "
                "DCE's the write."
            ),
            evidence=e,
        )

    return ByteEmitDceClassification(
        byte_index=e.byte_index,
        cause=DceCause.IDA_NATIVE_UNKNOWN,
        recommended_action=RecommendedAction.RECONSTRUCTION,
        rationale=(
            "Block had reachable preds at snap17, no shared-succ "
            "absorption, no dead-write signal — but is gone at snap18. "
            "IDA's finalization made an undocumented choice; needs "
            "deeper trace before a behavior fix."
        ),
        evidence=e,
    )


def classify_all(
    evidences: Iterable[ByteEmitSnapshotEvidence],
) -> tuple[ByteEmitDceClassification, ...]:
    return tuple(
        sorted(
            (classify_byte_emit_dce(e) for e in evidences),
            key=lambda c: c.byte_index,
        )
    )


def recommend_overall_action(
    classifications: Iterable[ByteEmitDceClassification],
) -> tuple[RecommendedAction, str]:
    """Aggregate per-byte recommendations into a single overall recommendation.

    Priority: PRESERVATION > RECONSTRUCTION > STRUCTURER_SHAPING > COLLECTOR_FIX > NONE.
    The first non-NONE action that applies to at least one missing byte
    becomes the overall recommendation.
    """
    counts: dict[RecommendedAction, int] = {}
    for c in classifications:
        if c.cause is DceCause.SURVIVES:
            continue
        counts[c.recommended_action] = counts.get(c.recommended_action, 0) + 1
    priority = [
        RecommendedAction.PRESERVATION,
        RecommendedAction.RECONSTRUCTION,
        RecommendedAction.STRUCTURER_SHAPING,
        RecommendedAction.COLLECTOR_FIX,
    ]
    for action in priority:
        if counts.get(action, 0) > 0:
            n = counts[action]
            return action, (
                f"{action.value} is recommended because {n} byte_emit(s) "
                f"have that classification (highest-priority action present)."
            )
    return RecommendedAction.NONE, "all byte emits survive — no work needed"


def format_dce_table(
    classifications: tuple[ByteEmitDceClassification, ...],
) -> str:
    lines = [
        "| byte | cause | action | rationale |",
        "|-|-|-|-|",
    ]
    for c in classifications:
        rationale_short = c.rationale[:120].replace("\n", " ")
        lines.append(
            f"| {c.byte_index} | {c.cause.value} | "
            f"{c.recommended_action.value} | {rationale_short} |"
        )
    return "\n".join(lines)


__all__ = [
    "ByteEmitDceClassification",
    "ByteEmitSnapshotEvidence",
    "DceCause",
    "RecommendedAction",
    "classify_all",
    "classify_byte_emit_dce",
    "format_dce_table",
    "recommend_overall_action",
]
