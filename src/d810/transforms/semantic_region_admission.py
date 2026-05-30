"""Semantic-region raw admission helpers.

These helpers classify backend-neutral relationships between raw semantic
regions before a strategy decides how to lower them.  They do not inspect
Hex-Rays microblocks and they do not own HCC log formatting or emission policy.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.transforms.semantic_region_entry import SemanticEntryCandidate

__all__ = [
    "RawRegionInfo",
    "classify_source_covered_by_other_region",
    "classify_yes_handlers_subclass",
    "find_cover_regions",
]


@dataclass(frozen=True, slots=True)
class RawRegionInfo:
    """Best-effort observation about one raw semantic region.

    The concrete DAG node and composed-candidate types intentionally remain
    structural: ``cfg`` owns the admission decision, while concrete semantic
    DAG dataclasses live in ``recon`` and concrete materialization candidates
    are produced by strategy/backend code.
    """

    region_nodes: tuple[object, ...]
    head_node: object
    tail_node: object
    head_anchor: int
    tail_anchor: int
    region_anchors: frozenset[int]
    old_physical_pred: int | None
    proposed_exit: int | None
    candidate: SemanticEntryCandidate
    composed_candidate: object | None = None
    opaque_call_anchor: tuple[int, int, bool] | None = None
    opaque_call_pre_count: int | None = None
    opaque_call_post_count: int | None = None
    opaque_call_shape: str | None = None


def classify_source_covered_by_other_region(
    *,
    self_info: RawRegionInfo,
    raw_region_table: tuple[RawRegionInfo, ...],
) -> tuple[str, tuple[str, ...]]:
    """Return ``(label, all_reasons)`` for source coverage by other regions.

    The returned ``label`` is the highest-priority reason using
    ``COLLISION > HANDLERS > PHYSICAL_PRED``.  ``all_reasons`` contains every
    matching reason in that same priority order.
    """
    src = self_info.candidate.splice_source_block
    if src is None:
        return ("NO", ())
    src_int = int(src)
    self_id = id(self_info)

    has_collision = False
    has_handlers = False
    has_physical_pred = False
    for other in raw_region_table:
        if id(other) == self_id:
            continue
        other_src = other.candidate.splice_source_block
        if other_src is not None and int(other_src) == src_int:
            has_collision = True
        if src_int in other.region_anchors:
            has_handlers = True
        if (
            other.old_physical_pred is not None
            and src_int == int(other.old_physical_pred)
        ):
            has_physical_pred = True

    reasons: list[str] = []
    if has_collision:
        reasons.append("YES_COLLISION")
    if has_handlers:
        reasons.append("YES_HANDLERS")
    if has_physical_pred:
        reasons.append("YES_PHYSICAL_PRED")
    if not reasons:
        return ("NO", ())
    return (reasons[0], tuple(reasons))


def find_cover_regions(
    *,
    self_info: RawRegionInfo,
    raw_region_table: tuple[RawRegionInfo, ...],
) -> tuple[RawRegionInfo, ...]:
    """Return raw regions whose anchors contain ``self_info``'s splice source."""
    src = self_info.candidate.splice_source_block
    if src is None:
        return ()
    src_int = int(src)
    self_id = id(self_info)
    covers: list[RawRegionInfo] = []
    for other in raw_region_table:
        if id(other) == self_id:
            continue
        if src_int in other.region_anchors:
            covers.append(other)
    return tuple(covers)


def classify_yes_handlers_subclass(
    *,
    self_info: RawRegionInfo,
    raw_region_table: tuple[RawRegionInfo, ...],
) -> str | None:
    """Classify a YES_HANDLERS region into fusion sub-categories.

    Returns one of ``FUSABLE_LINEAR``, ``NOT_FUSABLE_BRANCH``, or
    ``CONFLICT``.  Returns ``None`` only when ``self_info`` is not actually a
    YES_HANDLERS candidate.
    """
    covers = find_cover_regions(
        self_info=self_info, raw_region_table=raw_region_table,
    )
    if not covers:
        return "CONFLICT"

    if len(covers) > 1:
        return "CONFLICT"

    cover = covers[0]

    if cover.composed_candidate is None:
        return "CONFLICT"

    cover_src = cover.candidate.splice_source_block
    if cover_src is not None:
        cover_src_int = int(cover_src)
        for other in raw_region_table:
            if id(other) == id(cover) or id(other) == id(self_info):
                continue
            other_src = other.candidate.splice_source_block
            if other_src is not None and int(other_src) == cover_src_int:
                return "CONFLICT"

    if not self_info.region_anchors.isdisjoint(cover.region_anchors):
        return "CONFLICT"

    cover_exit = cover.proposed_exit
    self_head = self_info.head_anchor
    if cover_exit is not None and int(cover_exit) == int(self_head):
        return "FUSABLE_LINEAR"

    return "NOT_FUSABLE_BRANCH"
