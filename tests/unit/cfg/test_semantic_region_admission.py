from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.semantic_region_admission import (
    RawRegionInfo,
    classify_source_covered_by_other_region,
    classify_yes_handlers_subclass,
    find_cover_regions,
)
from d810.cfg.semantic_region_entry import (
    EntryEligibility,
    SemanticEntryCandidate,
)


@dataclass(frozen=True, slots=True)
class _ComposedCandidate:
    handler_serials: tuple[int, ...] = ()


def _candidate(source: int | None) -> SemanticEntryCandidate:
    return SemanticEntryCandidate(
        head_state=0,
        head_entry=0,
        splice_source_block=source,
        splice_old_target=None,
        transition_source_blocks=(() if source is None else (source,)),
        nontransition_source_blocks=(),
        eligibility=EntryEligibility.UNCONDITIONAL_1WAY,
        reason="test",
    )


def _info(
    *,
    head: int,
    anchors: tuple[int, ...],
    source: int | None = None,
    old_pred: int | None = None,
    proposed_exit: int | None = None,
    composed: bool = False,
) -> RawRegionInfo:
    head_node = object()
    tail_node = object()
    region_nodes = tuple(object() for _ in anchors) or (head_node,)
    return RawRegionInfo(
        region_nodes=region_nodes,
        head_node=head_node,
        tail_node=tail_node,
        head_anchor=head,
        tail_anchor=head,
        region_anchors=frozenset(anchors),
        old_physical_pred=old_pred,
        proposed_exit=proposed_exit,
        candidate=_candidate(source),
        composed_candidate=(_ComposedCandidate(anchors) if composed else None),
    )


def test_source_coverage_no_source():
    info = _info(head=10, anchors=(10,), source=None)

    assert classify_source_covered_by_other_region(
        self_info=info,
        raw_region_table=(info,),
    ) == ("NO", ())


def test_source_coverage_reports_all_reasons_in_priority_order():
    info = _info(head=10, anchors=(10,), source=50)
    collision = _info(head=20, anchors=(20,), source=50)
    handler_cover = _info(head=30, anchors=(50, 30))
    physical_pred_cover = _info(head=40, anchors=(40,), old_pred=50)

    assert classify_source_covered_by_other_region(
        self_info=info,
        raw_region_table=(info, physical_pred_cover, handler_cover, collision),
    ) == (
        "YES_COLLISION",
        ("YES_COLLISION", "YES_HANDLERS", "YES_PHYSICAL_PRED"),
    )


def test_source_coverage_prefers_handlers_over_physical_pred_without_collision():
    info = _info(head=10, anchors=(10,), source=50)
    handler_cover = _info(head=30, anchors=(50, 30))
    physical_pred_cover = _info(head=40, anchors=(40,), old_pred=50)

    assert classify_source_covered_by_other_region(
        self_info=info,
        raw_region_table=(info, physical_pred_cover, handler_cover),
    ) == ("YES_HANDLERS", ("YES_HANDLERS", "YES_PHYSICAL_PRED"))


def test_find_cover_regions_excludes_self_and_matches_source_in_region_anchors():
    info = _info(head=10, anchors=(10, 50), source=50)
    cover = _info(head=20, anchors=(20, 50))
    other = _info(head=30, anchors=(30,))

    assert find_cover_regions(
        self_info=info,
        raw_region_table=(info, other, cover),
    ) == (cover,)


def test_yes_handlers_subclass_conflict_without_cover():
    info = _info(head=10, anchors=(10,), source=50)

    assert classify_yes_handlers_subclass(
        self_info=info,
        raw_region_table=(info,),
    ) == "CONFLICT"


def test_yes_handlers_subclass_conflict_with_multiple_covers():
    info = _info(head=10, anchors=(10,), source=50)
    cover_a = _info(head=20, anchors=(20, 50), composed=True)
    cover_b = _info(head=30, anchors=(30, 50), composed=True)

    assert classify_yes_handlers_subclass(
        self_info=info,
        raw_region_table=(info, cover_a, cover_b),
    ) == "CONFLICT"


def test_yes_handlers_subclass_conflict_when_cover_not_composed():
    info = _info(head=10, anchors=(10,), source=50)
    cover = _info(head=20, anchors=(20, 50), composed=False)

    assert classify_yes_handlers_subclass(
        self_info=info,
        raw_region_table=(info, cover),
    ) == "CONFLICT"


def test_yes_handlers_subclass_conflict_on_cover_splice_source_collision():
    info = _info(head=10, anchors=(10,), source=50)
    cover = _info(head=20, anchors=(20, 50), source=70, composed=True)
    collision = _info(head=30, anchors=(30,), source=70)

    assert classify_yes_handlers_subclass(
        self_info=info,
        raw_region_table=(info, cover, collision),
    ) == "CONFLICT"


def test_yes_handlers_subclass_conflict_on_handler_overlap():
    info = _info(head=10, anchors=(10, 20), source=50)
    cover = _info(head=20, anchors=(20, 50), composed=True)

    assert classify_yes_handlers_subclass(
        self_info=info,
        raw_region_table=(info, cover),
    ) == "CONFLICT"


def test_yes_handlers_subclass_fusable_linear_when_cover_exits_to_self_head():
    info = _info(head=10, anchors=(10,), source=50)
    cover = _info(
        head=20,
        anchors=(20, 50),
        proposed_exit=10,
        composed=True,
    )

    assert classify_yes_handlers_subclass(
        self_info=info,
        raw_region_table=(info, cover),
    ) == "FUSABLE_LINEAR"


def test_yes_handlers_subclass_not_fusable_branch_when_cover_exits_elsewhere():
    info = _info(head=10, anchors=(10,), source=50)
    cover = _info(
        head=20,
        anchors=(20, 50),
        proposed_exit=99,
        composed=True,
    )

    assert classify_yes_handlers_subclass(
        self_info=info,
        raw_region_table=(info, cover),
    ) == "NOT_FUSABLE_BRANCH"
