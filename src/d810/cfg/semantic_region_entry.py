"""Semantic-region entry resolution.

This module classifies the CFG splice point for a semantic DAG region without
depending on a live Hex-Rays ``mba_t``.  Strategy code supplies a small block
view; the resolver stays backend-neutral and only reasons about DAG edges plus
projected block successor shape.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass

from d810.core.typing import Protocol

__all__ = [
    "EntryEligibility",
    "RegionEntryBlockView",
    "SemanticEntryCandidate",
    "resolve_semantic_entry_candidate",
]


class EntryEligibility(str, enum.Enum):
    """Why a region head's semantic incoming edge is/isn't usable as a splice."""

    NO_TRANSITION_INCOMING = "NO_TRANSITION_INCOMING"
    MULTIPLE_DISTINCT_SPLICE_SOURCES = "MULTIPLE_DISTINCT_SPLICE_SOURCES"
    SOURCE_DEAD = "SOURCE_DEAD"
    SOURCE_INSIDE_REGION = "SOURCE_INSIDE_REGION"
    SOURCE_NOT_1WAY = "SOURCE_NOT_1WAY"
    SOURCE_OLD_TARGET_UNREADABLE = "SOURCE_OLD_TARGET_UNREADABLE"
    UNCONDITIONAL_1WAY = "UNCONDITIONAL_1WAY"


class RegionEntryBlockView(Protocol):
    """Backend-neutral successor view for semantic-region entry resolution."""

    def block_exists(self, serial: int) -> bool:
        """Return whether ``serial`` resolves to a live/projected block."""
        ...

    def nsucc(self, serial: int) -> int | None:
        """Return successor count, or ``None`` when unreadable."""
        ...

    def succ(self, serial: int, index: int = 0) -> int | None:
        """Return successor at ``index``, or ``None`` when unreadable."""
        ...


@dataclass(frozen=True, slots=True)
class SemanticEntryCandidate:
    """Candidate for splicing a region through its DAG TRANSITION edge.

    Fields:
        head_state: ``state_const`` of the region head node (or 0 if absent).
        head_entry: Entry anchor block serial of the region head node.
        splice_source_block: The unique TRANSITION source block when
            classification reaches the per-source check, else ``None``.
        splice_old_target: Existing single successor of ``splice_source_block``
            when readable, else ``None``.
        transition_source_blocks: All distinct TRANSITION source blocks for
            edges incoming to the region head, ordered ascending.
        nontransition_source_blocks: All distinct non-TRANSITION source blocks
            for edges incoming to the region head, ordered ascending.
            Informational only; these never block ``UNCONDITIONAL_1WAY``.
        eligibility: The classification.
        reason: Human-readable explanation of the classification.
    """

    head_state: int
    head_entry: int
    splice_source_block: int | None
    splice_old_target: int | None
    transition_source_blocks: tuple[int, ...]
    nontransition_source_blocks: tuple[int, ...]
    eligibility: EntryEligibility
    reason: str


def resolve_semantic_entry_candidate(
    *,
    dag: object,
    region_head_node: object,
    region_anchors: frozenset[int],
    block_view: RegionEntryBlockView,
    transition_kind: object,
) -> SemanticEntryCandidate:
    """Classify the semantic incoming edge of a DAG region head.

    The resolver answers whether exactly one admissible TRANSITION source
    reaches ``region_head_node`` and whether the corresponding source block is
    a readable 1-way CFG block.  Non-TRANSITION incoming edges are preserved in
    the result for diagnostics but never block a valid TRANSITION source.
    """
    head_key = getattr(region_head_node, "key")
    head_state = int(getattr(head_key, "state_const", 0) or 0)
    head_entry = int(getattr(region_head_node, "entry_anchor"))

    transition_sources: list[int] = []
    nontransition_sources: list[int] = []
    for edge in getattr(dag, "edges", ()):
        if getattr(edge, "target_key", None) != head_key:
            continue
        try:
            src = int(edge.source_anchor.block_serial)
        except Exception:
            continue
        if getattr(edge, "kind", None) is transition_kind:
            transition_sources.append(src)
        else:
            nontransition_sources.append(src)

    transition_unique = tuple(sorted(set(transition_sources)))
    nontransition_unique = tuple(sorted(set(nontransition_sources)))

    if not transition_unique:
        return SemanticEntryCandidate(
            head_state=head_state,
            head_entry=head_entry,
            splice_source_block=None,
            splice_old_target=None,
            transition_source_blocks=(),
            nontransition_source_blocks=nontransition_unique,
            eligibility=EntryEligibility.NO_TRANSITION_INCOMING,
            reason="no TRANSITION edges target region head",
        )

    if len(transition_unique) > 1:
        return SemanticEntryCandidate(
            head_state=head_state,
            head_entry=head_entry,
            splice_source_block=None,
            splice_old_target=None,
            transition_source_blocks=transition_unique,
            nontransition_source_blocks=nontransition_unique,
            eligibility=EntryEligibility.MULTIPLE_DISTINCT_SPLICE_SOURCES,
            reason=(
                "TRANSITION edges to region head originate from "
                f"{len(transition_unique)} distinct source blocks"
            ),
        )

    splice_source = int(transition_unique[0])

    if not block_view.block_exists(splice_source):
        return SemanticEntryCandidate(
            head_state=head_state,
            head_entry=head_entry,
            splice_source_block=splice_source,
            splice_old_target=None,
            transition_source_blocks=transition_unique,
            nontransition_source_blocks=nontransition_unique,
            eligibility=EntryEligibility.SOURCE_DEAD,
            reason=f"block view could not resolve blk[{splice_source}]",
        )

    if splice_source in region_anchors:
        return SemanticEntryCandidate(
            head_state=head_state,
            head_entry=head_entry,
            splice_source_block=splice_source,
            splice_old_target=None,
            transition_source_blocks=transition_unique,
            nontransition_source_blocks=nontransition_unique,
            eligibility=EntryEligibility.SOURCE_INSIDE_REGION,
            reason=f"source block blk[{splice_source}] is itself a region anchor",
        )

    nsucc = block_view.nsucc(splice_source)
    if nsucc is None:
        return SemanticEntryCandidate(
            head_state=head_state,
            head_entry=head_entry,
            splice_source_block=splice_source,
            splice_old_target=None,
            transition_source_blocks=transition_unique,
            nontransition_source_blocks=nontransition_unique,
            eligibility=EntryEligibility.SOURCE_NOT_1WAY,
            reason=f"blk[{splice_source}].nsucc() unreadable",
        )

    if nsucc != 1:
        return SemanticEntryCandidate(
            head_state=head_state,
            head_entry=head_entry,
            splice_source_block=splice_source,
            splice_old_target=None,
            transition_source_blocks=transition_unique,
            nontransition_source_blocks=nontransition_unique,
            eligibility=EntryEligibility.SOURCE_NOT_1WAY,
            reason=f"blk[{splice_source}].nsucc()={nsucc}, expected 1",
        )

    old_target = block_view.succ(splice_source, 0)
    if old_target is None:
        return SemanticEntryCandidate(
            head_state=head_state,
            head_entry=head_entry,
            splice_source_block=splice_source,
            splice_old_target=None,
            transition_source_blocks=transition_unique,
            nontransition_source_blocks=nontransition_unique,
            eligibility=EntryEligibility.SOURCE_OLD_TARGET_UNREADABLE,
            reason=f"blk[{splice_source}].succ(0) unreadable",
        )

    return SemanticEntryCandidate(
        head_state=head_state,
        head_entry=head_entry,
        splice_source_block=splice_source,
        splice_old_target=int(old_target),
        transition_source_blocks=transition_unique,
        nontransition_source_blocks=nontransition_unique,
        eligibility=EntryEligibility.UNCONDITIONAL_1WAY,
        reason="single TRANSITION source is a 1-way block; semantic splice eligible",
    )
